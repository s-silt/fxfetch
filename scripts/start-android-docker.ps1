[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$EnvFile,
    [string[]]$OverrideFile = @(),
    [string]$LanSubnet,
    [string]$PythonPath
)
$ErrorActionPreference = 'Stop'
if (-not $PythonPath) { $PythonPath = Join-Path $PSScriptRoot '../.venv/Scripts/python.exe' }
$python = (Resolve-Path -LiteralPath $PythonPath).Path
$launcher = Join-Path $PSScriptRoot 'android-worker/start_docker.py'
$arguments = @($launcher, '--env-file', (Resolve-Path -LiteralPath $EnvFile).Path)
foreach ($path in $OverrideFile) { $arguments += @('--override', (Resolve-Path -LiteralPath $path).Path) }
if ($LanSubnet) { $arguments += @('--lan-subnet', $LanSubnet) }
& $python @arguments
if ($LASTEXITCODE -ne 0) { throw 'Docker Android startup failed; no fallback was attempted. Inspect the bounded reason above.' }
