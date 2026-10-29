#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$LanIP,
    [Parameter(Mandatory = $true)][string]$Subnet,
    [ValidateRange(1, 65535)][int]$Port = 8765,
    [Parameter(Mandatory = $true)][string]$PythonPath
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$python = (Resolve-Path -LiteralPath $PythonPath).Path
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'PythonPath must be a file.' }
# Only literal arguments reach the Python validation module; no evaluated shell text.
$validator = @'
import ctypes, json, sys
sys.path.insert(0, sys.argv[1])
from fxfetch.core.lan import validate_bind, validate_lan_networks, client_allowed, excluded_ipv4_networks
ip = validate_bind(sys.argv[2])
nets = validate_lan_networks((sys.argv[3],))
if ip.startswith('127.') or not client_allowed(ip, nets):
    raise ValueError('LanIP must be an RFC1918 interface inside Subnet')
buffer = ctypes.create_unicode_buffer(32768)
length = ctypes.windll.kernel32.GetModuleFileNameW(None, buffer, len(buffer))
if not length or length >= len(buffer):
    raise OSError('Cannot resolve actual Python process image')
print(json.dumps({'ip': ip, 'subnet': nets[0], 'excluded': excluded_ipv4_networks((nets[0], '127.0.0.0/8')), 'program': buffer.value}))
'@
$validatorArgs = @('-c', $validator, (Join-Path $projectRoot 'src'), $LanIP, $Subnet)
$validatedOutput = & $python @validatorArgs
if ($LASTEXITCODE -ne 0) { throw 'LAN address/subnet validation failed.' }
$policy = $validatedOutput | ConvertFrom-Json
$program = (Resolve-Path -LiteralPath $policy.program).Path
if (-not (Test-Path -LiteralPath $program -PathType Leaf)) { throw 'Actual Python process image is not a file.' }
$boundAddress = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress $policy.ip -ErrorAction SilentlyContinue)
if ($boundAddress.Count -eq 0) { throw 'LanIP is not assigned to a local IPv4 interface.' }
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
if (@($profiles | Where-Object { -not $_.Enabled }).Count -gt 0) {
    throw 'All firewall profiles must already be enabled. Global policy will not be changed.'
}
# Audit pre-existing enabled inbound allows for the interpreter or the service port.
# Report them for review; never delete third-party firewall rules.
$existing = @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -Action Allow)
foreach ($rule in $existing) {
    $app = $rule | Get-NetFirewallApplicationFilter
    $ports = $rule | Get-NetFirewallPortFilter
    if ($app.Program -eq $program -or @($ports.LocalPort) -contains "$Port" -or ($app.Program -eq 'Any' -and @($ports.LocalPort) -contains 'Any')) {
        $remote = $rule | Get-NetFirewallAddressFilter
        Write-Warning ("Review existing allow: {0}; Program={1}; Port={2}; Remote={3}; Profile={4}" -f $rule.DisplayName, $app.Program, ($ports.LocalPort -join ','), ($remote.RemoteAddress -join ','), $rule.Profile)
    }
}
$rulePrefix = "fxfetch-LAN-$Port-$($policy.ip)"
$allowName = "$rulePrefix-Allow"
$blockName = "$rulePrefix-BlockOutsideSubnet"
foreach ($name in @($allowName, $blockName)) {
    if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) {
        throw "Rule $name already exists. Review it explicitly before replacement; nothing was deleted."
    }
}
if ($PSCmdlet.ShouldProcess("$program on $($policy.ip):$Port", 'Create narrow LAN allow and explicit outside-subnet block')) {
    $common = @{ Direction = 'Inbound'; Enabled = 'True'; Program = $program; Protocol = 'TCP'; LocalAddress = $policy.ip; LocalPort = $Port; EdgeTraversalPolicy = 'Block' }
    # Block first, so interruption cannot leave a broader exposure than the final rules.
    New-NetFirewallRule @common -Name $blockName -DisplayName $blockName -Action Block -Profile Any -RemoteAddress @($policy.excluded) | Out-Null
    New-NetFirewallRule @common -Name $allowName -DisplayName $allowName -Action Allow -Profile Any -RemoteAddress $policy.subnet | Out-Null
}
Write-Output "Bind the application to $($policy.ip):$Port and configure allowed networks as $($policy.subnet),127.0.0.0/8."
Write-Output 'Application socket-peer checks remain mandatory. Forwarded headers are untrusted. Source NAT can hide a remote client behind a permitted LAN peer; the application cannot identify that original client. No router, UPnP, global firewall policy, or third-party rules were changed.'
