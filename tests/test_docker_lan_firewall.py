"""Execute the PowerShell policy with mocked firewall cmdlets, never host rules."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

MOCKS = r'''
param([string]$Target, [string]$Python, [string]$Scenario, [string]$Lan, [string]$Subnet)
$ErrorActionPreference = 'Stop'
$global:MockCreated = @()
$global:MockRules = @{}
$global:MockAdminChecks = 0
function Get-NetIPAddress { param($AddressFamily, $IPAddress, $ErrorAction)
    if ($Scenario -ne 'nonlocal') { [pscustomobject]@{IPAddress=$IPAddress} }
}
function Get-NetFirewallProfile { param($PolicyStore)
    1..3 | ForEach-Object { [pscustomobject]@{Enabled=($Scenario -ne 'disabled')} }
}
function Make-Rule($Name, $Action, $Remote) {
    [pscustomobject]@{
        Name=$Name; Enabled='True'; Direction='Inbound'; Action=$Action; Profile='Any';
        EdgeTraversalPolicy='Block'; PolicyStoreSourceType='Local'; Program='Any'; Package='';
        Service='Any'; InterfaceAlias='Any'; InterfaceType=0; Authentication='NotRequired';
        OverrideBlockRules='False'; Protocol='TCP'; LocalPort='8765'; RemotePort='Any';
        LocalAddress=$Lan; RemoteAddress=@($Remote | ForEach-Object { "$_".Replace('/24', '/255.255.255.0') })
    }
}
function Get-NetFirewallRule { param($PolicyStore, $Name, $ErrorAction)
    if ($global:MockRules.ContainsKey($Name)) { return $global:MockRules[$Name] }
    if ($Scenario -in @('existing','conflict','verify_existing_nonadmin') -or ($Scenario -eq 'partial' -and $Name.EndsWith('BlockOutsideSubnet'))) {
        $action = if ($Name.EndsWith('-Allow')) { 'Allow' } else { 'Block' }
        $remote = if ($action -eq 'Allow') { @($policy.subnet) } else { @($policy.excluded) }
        $rule = Make-Rule $Name $action $remote
        if ($Scenario -eq 'conflict' -and $action -eq 'Allow') { $rule.Program='C:\wrong.exe' }
        return $rule
    }
}
# Every filter is replaced locally. A missing mock must fail before any mutation.
function Get-NetFirewallAddressFilter { param([Parameter(ValueFromPipeline)]$InputObject) process { $InputObject } }
function Get-NetFirewallPortFilter { param([Parameter(ValueFromPipeline)]$InputObject) process { $InputObject } }
function Get-NetFirewallApplicationFilter { param([Parameter(ValueFromPipeline)]$InputObject) process { $InputObject } }
function Get-NetFirewallServiceFilter { param([Parameter(ValueFromPipeline)]$InputObject) process { $InputObject } }
function Get-NetFirewallInterfaceFilter { param([Parameter(ValueFromPipeline)]$InputObject) process { $InputObject } }
function Get-NetFirewallInterfaceTypeFilter { param([Parameter(ValueFromPipeline)]$InputObject) process { $InputObject } }
function Get-NetFirewallSecurityFilter { param([Parameter(ValueFromPipeline)]$InputObject) process { $InputObject } }
function New-NetFirewallRule {
    param($PolicyStore,$Direction,$Enabled,$Program,$Protocol,$LocalAddress,$LocalPort,$EdgeTraversalPolicy,
          $Profile,$Name,$DisplayName,$Action,$RemoteAddress)
    $global:MockCreated += @{ name=$Name; action=$Action; remote=@($RemoteAddress); local=$LocalAddress; program=$Program; port=$LocalPort }
    $global:MockRules[$Name] = Make-Rule $Name $Action $RemoteAddress
}
$options = @{ LanIP=$Lan; Subnet=$Subnet; PythonPath=$Python; Port=8765 }
if ($Scenario -eq 'preview') { $options.WhatIf=$true }
if ($Scenario -in @('verify_missing','verify_existing_nonadmin')) { $options.VerifyOnly=$true }
try { $messages = @(& $Target @options); $failure=$null }
catch { $messages=@(); $failure=$_.Exception.Message }
@{ created=@($global:MockCreated); failure=$failure; messages=$messages; admin_checks=$global:MockAdminChecks } | ConvertTo-Json -Depth 8 -Compress
'''


def run_policy(tmp_path: Path, scenario: str, lan="192.168.50.10", subnet="192.168.50.0/24"):
    shell = shutil.which("pwsh")
    if shell is None:
        pytest.skip("PowerShell is required for mocked firewall execution")
    source = (ROOT / "scripts/configure-docker-lan.ps1").read_text(encoding="utf-8")
    assert "#Requires -RunAsAdministrator" not in source
    # Substitute only the Windows principal query, never the mutation guard.
    # This explicitly exercises both normal-token and elevated-token branches.
    principal = "$isAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
    assert source.count(principal) == 1
    source = source.replace(principal, "$global:MockAdminChecks += 1; $isAdministrator = $Scenario -ne 'nonadmin_new'", 1)
    escaped = str(ROOT).replace("'", "''")
    source = source.replace("$projectRoot = Split-Path -Parent $PSScriptRoot", f"$projectRoot = '{escaped}'", 1)
    target = tmp_path / "policy.ps1"
    target.write_text(source, encoding="utf-8")
    harness = tmp_path / "harness.ps1"
    harness.write_text(MOCKS, encoding="utf-8")
    result = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-File", str(harness), str(target), sys.executable,
         scenario, lan, subnet], capture_output=True, text=True, timeout=20, check=True,
    )
    return json.loads(result.stdout.splitlines()[-1])


def test_new_rules_block_first_and_only_cover_selected_port(tmp_path):
    value = run_policy(tmp_path, "new")
    assert value["failure"] is None
    assert [row["action"] for row in value["created"]] == ["Block", "Allow"]
    assert all(row["local"] == "192.168.50.10" and row["port"] == 8765 and row["program"] == "Any"
               for row in value["created"])
    assert value["created"][1]["remote"] == ["192.168.50.0/24"]
    import ipaddress
    excluded = [ipaddress.ip_network(item) for item in value["created"][0]["remote"]]
    assert all(ipaddress.ip_address("192.168.50.20") not in network for network in excluded)
    assert all(any(ipaddress.ip_address(address) in network for network in excluded)
               for address in ("8.8.8.8", "127.0.0.1", "192.168.51.10", "10.0.0.10"))


@pytest.mark.parametrize("scenario", ["preview", "existing", "verify_existing_nonadmin"])
def test_preview_and_matching_existing_rules_do_not_mutate(tmp_path, scenario):
    value = run_policy(tmp_path, scenario)
    assert value["failure"] is None and not value["created"]
    assert value["admin_checks"] == 0
    if scenario == "preview":
        assert any("readiness is not asserted" in line for line in value["messages"])


@pytest.mark.parametrize("scenario", ["conflict", "disabled", "nonlocal", "verify_missing"])
def test_unsafe_or_missing_policy_fails_without_mutation(tmp_path, scenario):
    value = run_policy(tmp_path, scenario)
    assert value["failure"] and not value["created"]


@pytest.mark.parametrize("lan,subnet", [
    ("0.0.0.0", "192.168.50.0/24"), ("8.8.8.8", "8.8.8.0/24"),
    ("192.168.50.10", "192.168.51.0/24"), ("192.168.50.255", "192.168.50.0/24"),
    ("::1", "::1/128"),
])
def test_invalid_address_policy_rejected_before_firewall_mutation(tmp_path, lan, subnet):
    value = run_policy(tmp_path, "new", lan, subnet)
    assert value["failure"] and not value["created"]


def test_matching_block_can_be_completed_without_replacing_it(tmp_path):
    value = run_policy(tmp_path, "partial")
    assert value["failure"] is None
    assert [row["action"] for row in value["created"]] == ["Allow"]


def test_normal_token_cannot_create_missing_rules(tmp_path):
    value = run_policy(tmp_path, "nonadmin_new")
    assert value["admin_checks"] == 1
    assert "requires administrator" in value["failure"]
    assert not value["created"]

