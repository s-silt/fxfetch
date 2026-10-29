[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$LanIP,
    [Parameter(Mandatory = $true)][string]$Subnet,
    [ValidateRange(1024, 65535)][int]$Port = 8765,
    [Parameter(Mandatory = $true)][string]$PythonPath,
    [switch]$VerifyOnly
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$python = (Resolve-Path -LiteralPath $PythonPath).Path
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'PythonPath must be a file.' }
$validator = @'
import ipaddress, json, sys
sys.path.insert(0, sys.argv[1])
from fxfetch.core.lan import validate_bind, validate_lan_networks, excluded_ipv4_networks
ip = validate_bind(sys.argv[2])
subnet = validate_lan_networks((sys.argv[3],))[0]
address, network = ipaddress.IPv4Address(ip), ipaddress.IPv4Network(subnet)
if address.is_loopback or address not in network or address in (network.network_address, network.broadcast_address):
    raise ValueError('LanIP must be a usable RFC1918 interface inside Subnet')
# This LAN publication permits exactly one subnet, not remote loopback ranges.
print(json.dumps({'ip': ip, 'subnet': subnet, 'excluded': excluded_ipv4_networks((subnet,))}))
'@
$validatedOutput = & $python -c $validator (Join-Path $projectRoot 'src') $LanIP $Subnet
if ($LASTEXITCODE -ne 0) { throw 'LAN address/subnet validation failed.' }
$policy = $validatedOutput | ConvertFrom-Json
if (@(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $policy.ip -ErrorAction SilentlyContinue).Count -eq 0) {
    throw 'LanIP is not assigned to a local IPv4 interface.'
}
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
if ($profiles.Count -ne 3 -or @($profiles | Where-Object { -not $_.Enabled }).Count -gt 0) {
    throw 'All three firewall profiles must already be enabled. Global policy will not be changed.'
}

function Test-SameValues($Actual, $Expected) {
    $left = @($Actual | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object -Unique)
    $right = @($Expected | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object -Unique)
    return (@(Compare-Object $left $right).Count -eq 0)
}

function Convert-FirewallAddresses($Values) {
    foreach ($value in $Values) {
        $parts = "$value".Split('/')
        # Windows returns subnet masks even when rules were created using CIDR.
        if ($parts.Count -eq 2 -and $parts[1].Contains('.')) {
            $mask = [System.Net.IPAddress]::Parse($parts[1])
            if ($mask.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
                throw 'Unexpected firewall address mask family.'
            }
            $bits = ($mask.GetAddressBytes() | ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0') }) -join ''
            if ($bits -notmatch '^1*0*$') { throw 'Non-contiguous firewall subnet mask.' }
            "$($parts[0])/$($bits.TrimEnd('0').Length)"
        } else { "$value" }
    }
}

function Assert-ExactRule($Rule, [string]$Action, $RemoteAddress) {
    $address = $Rule | Get-NetFirewallAddressFilter
    $portFilter = $Rule | Get-NetFirewallPortFilter
    $application = $Rule | Get-NetFirewallApplicationFilter
    $service = $Rule | Get-NetFirewallServiceFilter
    $interface = $Rule | Get-NetFirewallInterfaceFilter
    $interfaceType = $Rule | Get-NetFirewallInterfaceTypeFilter
    $security = $Rule | Get-NetFirewallSecurityFilter
    $same = (
        "$($Rule.Enabled)" -eq 'True' -and "$($Rule.Direction)" -eq 'Inbound' -and
        "$($Rule.Action)" -eq $Action -and "$($Rule.Profile)" -eq 'Any' -and
        "$($Rule.EdgeTraversalPolicy)" -eq 'Block' -and
        "$($Rule.PolicyStoreSourceType)" -eq 'Local' -and
        "$($application.Program)" -eq 'Any' -and "$($application.Package)" -in @('', 'Any') -and
        "$($service.Service)" -eq 'Any' -and
        (Test-SameValues $interface.InterfaceAlias @('Any')) -and
        "$($interfaceType.InterfaceType)" -in @('Any', '0') -and
        "$($security.Authentication)" -eq 'NotRequired' -and
        "$($security.OverrideBlockRules)" -eq 'False' -and
        "$($portFilter.Protocol)" -in @('TCP', '6') -and
        (Test-SameValues $portFilter.LocalPort @("$Port")) -and
        (Test-SameValues $portFilter.RemotePort @('Any')) -and
        (Test-SameValues $address.LocalAddress @($policy.ip)) -and
        (Test-SameValues @(Convert-FirewallAddresses $address.RemoteAddress) $RemoteAddress)
    )
    if (-not $same) { throw "Existing rule $($Rule.Name) differs from the requested narrow policy; nothing was replaced." }
}

$prefix = "fxfetch-Docker-LAN-$Port-$($policy.ip)"
# Validate BOTH rules before changing anything. A partially created matching
# block is safe to complete; a conflicting rule is never overwritten.
$plans = @(
    @{ Name = "$prefix-BlockOutsideSubnet"; Action = 'Block'; RemoteAddress = @($policy.excluded) },
    @{ Name = "$prefix-Allow"; Action = 'Allow'; RemoteAddress = @($policy.subnet) }
)
$missing = @()
foreach ($plan in $plans) {
    $existing = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $plan.Name -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 1) { throw "Duplicate rule identity: $($plan.Name)" }
    if ($existing.Count -eq 1) { Assert-ExactRule $existing[0] $plan.Action $plan.RemoteAddress }
    else { $missing += $plan }
}
if ($VerifyOnly -and $missing.Count -gt 0) { throw 'Required Docker LAN firewall rules are missing.' }
$verified = $missing.Count -eq 0
if (-not $VerifyOnly -and $missing.Count -gt 0 -and $PSCmdlet.ShouldProcess("$($policy.ip):$Port TCP", 'Create Docker LAN rules, outside-subnet block first')) {
    # Read-only verification and previews work with the normal user token.
    # Elevation is required immediately before the first actual mutation.
    $isAdministrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdministrator) { throw 'Creating missing Docker LAN firewall rules requires administrator PowerShell. No rules were changed.' }
    $common = @{
        PolicyStore = 'PersistentStore'; Direction = 'Inbound'; Enabled = 'True';
        Program = 'Any'; Protocol = 'TCP'; LocalAddress = $policy.ip; LocalPort = $Port;
        EdgeTraversalPolicy = 'Block'; Profile = 'Any'
    }
    foreach ($plan in $missing) {
        New-NetFirewallRule @common -Name $plan.Name -DisplayName $plan.Name -Action $plan.Action -RemoteAddress $plan.RemoteAddress | Out-Null
    }
    foreach ($plan in $plans) {
        $active = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $plan.Name -ErrorAction Stop)
        if ($active.Count -ne 1) { throw 'Created rule is not uniquely effective in ActiveStore; do not publish the port.' }
        Assert-ExactRule $active[0] $plan.Action $plan.RemoteAddress
    }
    $verified = $true
}
if (-not $verified) {
    Write-Output 'Preview only: no firewall changes were made and readiness is not asserted.'
} else {
    Write-Output "Verified Docker LAN firewall policy for $($policy.ip):$Port, allowed source $($policy.subnet)."
}
Write-Output 'Publish only this literal IPv4 address and port. Never publish SSH, CDP or the internal gateway. No IPv6 or wildcard publication is covered.'
Write-Output 'Docker NAT may hide the original source from the API. Host firewall restrictions are mandatory; forwarded headers are not trusted. Upstream NAT/router forwarding can hide an external source behind a permitted LAN peer and is outside this verification.'
