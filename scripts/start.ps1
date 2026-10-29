param(
    [string]$BindAddress,
    [int]$Port,
    [string]$OutputRoot = '.runtime/service',
    [string[]]$AllowedHost = @(),
    [switch]$SkipAndroid
)
$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$PythonPath = Join-Path $ProjectRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $PythonPath)) { throw 'Create the project virtual environment first.' }
Push-Location $ProjectRoot
try {
    if (-not $SkipAndroid -and (Test-Path -LiteralPath (Join-Path $OutputRoot 'android-worker.json'))) {
        & $PythonPath (Join-Path $PSScriptRoot 'android-worker/resume_worker.py') --service-root $OutputRoot
        if ($LASTEXITCODE -ne 0) {
            Write-Warning 'Android Chrome recovery did not pass. The API will start and report the worker as unavailable.'
        }
    }
    $LaunchArguments = @('-m', 'fxfetch', 'serve', '--out', $OutputRoot)
    if ($PSBoundParameters.ContainsKey('BindAddress')) { $LaunchArguments += @('--host', $BindAddress) }
    if ($PSBoundParameters.ContainsKey('Port')) { $LaunchArguments += @('--port', "$Port") }
    foreach ($Entry in $AllowedHost) { $LaunchArguments += @('--allowed-host', $Entry) }
    & $PythonPath @LaunchArguments
    if ($LASTEXITCODE -ne 0) { throw "Server exited with code $LASTEXITCODE" }
} finally {
    Pop-Location
}
