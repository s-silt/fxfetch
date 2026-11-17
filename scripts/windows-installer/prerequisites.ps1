#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InstallRoot,
    [switch]$CheckOnly,
    [switch]$DryRun,
    [switch]$AcceptDockerLicense,
    [string]$AssetsDirectory
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$utf8 = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $utf8
$OutputEncoding = $utf8
$result = [ordered]@{ schema = 'fxfetch.prerequisites.v1'; status = 'checking'; reboot_required = $false; docker_installed = $false; wsl_ready = $false; steps = @(); diagnostics_relative_path = $null }
$script:privateDir = $null
$script:diagnosticsProtected = $false
function Finish([string]$Status, [int]$Code) {
    $result.status = $Status
    [Console]::WriteLine(($result | ConvertTo-Json -Depth 8 -Compress))
    exit $Code
}
function Step([string]$Name, [string]$State) {
    $result.steps += [ordered]@{ name = $Name; state = $State }
}
function Assert-Publisher([string]$Path, [string]$Publisher) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) { throw 'signature_invalid' }
    $simpleName = $signature.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    if ($simpleName -ne $Publisher) { throw 'publisher_invalid' }
}
function Run-Bounded([string]$Path, [string]$Arguments, [string]$Name, [int]$Seconds = 900) {
    # Native stdout/stderr may contain local paths: never return them through public JSON.
    $stdout = Join-Path $script:privateDir ($Name + '.stdout.log')
    $stderr = Join-Path $script:privateDir ($Name + '.stderr.log')
    $process = Start-Process -FilePath $Path -ArgumentList $Arguments -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if (-not $process.WaitForExit($Seconds * 1000)) {
        # Terminate only this installer command and its descendants, never existing Docker workloads.
        & "$env:SystemRoot\System32\taskkill.exe" /PID $process.Id /T /F 2>&1 | Out-Null
        throw 'command_timeout'
    }
    $process.Refresh()
    return [int]$process.ExitCode
}
function Get-WslVersion([string]$WslPath) {
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $WslPath
    $startInfo.Arguments = '--version'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    # wsl.exe writes UTF-16 when redirected, independently of console code page.
    $startInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
    $startInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $startInfo
    try {
        [void]$p.Start()
        $readOut = $p.StandardOutput.ReadToEndAsync()
        $readErr = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit(15000)) { $p.Kill(); return $null }
        $text = $readOut.GetAwaiter().GetResult() -replace "`0", ''
        [void]$readErr.GetAwaiter().GetResult()
        if ($p.ExitCode -eq 0 -and $text -match '(?m)^\s*WSL\s*[^\d\r\n]*([0-9]+\.[0-9]+\.[0-9]+)') { return [version]$Matches[1] }
        return $null
    } finally { $p.Dispose() }
}
function Test-WslFeatures {
    $features = @(Get-CimInstance Win32_OptionalFeature -Filter "Name='Microsoft-Windows-Subsystem-Linux' OR Name='VirtualMachinePlatform'")
    return $features.Count -eq 2 -and @($features | Where-Object { $_.InstallState -ne 1 }).Count -eq 0
}
function Assert-LocalAsset([string]$Path, [string]$Publisher) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'offline_asset_missing' }
    $item = Get-Item -LiteralPath $Path
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'offline_asset_link_rejected' }
    Assert-Publisher $Path $Publisher
}

try {
    if (-not [System.IO.Path]::IsPathRooted($InstallRoot) -or $InstallRoot.StartsWith('\\')) { Finish 'invalid_install_root' 30 }
    if ($DryRun) {
        Step 'check_windows_virtualization_wsl_docker' 'planned'
        Step 'require_administrator_if_install_needed' 'planned'
        Step 'install_bundled_microsoft_wsl_msi_without_distribution' 'planned'
        Step 'require_explicit_docker_license_acceptance' 'planned'
        Step 'verify_bundled_official_installers_authenticode' 'planned'
        Step 'install_docker_wsl2_backend_without_reboot' 'planned'
        Finish 'planned' 0
    }
    if (-not [Environment]::Is64BitOperatingSystem -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64' -or [Environment]::OSVersion.Version.Build -lt 22631) { Finish 'unsupported_windows' 30 }
    $computer = Get-CimInstance Win32_ComputerSystem
    $processors = @(Get-CimInstance Win32_Processor)
    if ($computer.TotalPhysicalMemory -lt 8GB) { Finish 'insufficient_memory' 30 }
    if (-not $computer.HypervisorPresent -and @($processors | Where-Object { -not $_.VirtualizationFirmwareEnabled -or -not $_.SecondLevelAddressTranslationExtensions }).Count -gt 0) { Finish 'virtualization_required' 30 }
    $dockerPaths = @((Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'), (Join-Path $env:LOCALAPPDATA 'Programs\DockerDesktop\Docker Desktop.exe'))
    $result.docker_installed = @($dockerPaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }).Count -gt 0
    $wsl = Join-Path $env:SystemRoot 'System32\wsl.exe'
    $version = if (Test-Path -LiteralPath $wsl) { Get-WslVersion $wsl } else { $null }
    $featuresReady = Test-WslFeatures
    $result.wsl_ready = $null -ne $version -and $version -ge [version]'2.1.5' -and $featuresReady
    Step 'check_prerequisites' 'complete'
    if ($result.docker_installed -and $result.wsl_ready) { Finish 'ready' 0 }
    if ($CheckOnly) { Finish 'needs_install' 0 }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Finish 'admin_required' 10 }
    if (-not $result.docker_installed -and -not $AcceptDockerLicense) { Finish 'license_required' 11 }
    $relative = 'private\prerequisites-' + [guid]::NewGuid().ToString('N')
    $script:privateDir = Join-Path ([System.IO.Path]::GetFullPath($InstallRoot)) $relative
    [void][System.IO.Directory]::CreateDirectory($script:privateDir)
    # Remove inherited access; diagnostics are readable only by this account, SYSTEM and administrators.
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($identity.User, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')), (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $script:privateDir -AclObject $acl
    $script:diagnosticsProtected = $true
    $result.diagnostics_relative_path = $relative
    if ([string]::IsNullOrWhiteSpace($AssetsDirectory) -or -not [System.IO.Path]::IsPathRooted($AssetsDirectory)) { Finish 'offline_assets_required' 30 }
    $assets = [System.IO.Path]::GetFullPath($AssetsDirectory)
    if (-not $result.wsl_ready) {
        $msi = Join-Path $assets 'wsl.msi'
        Assert-LocalAsset $msi 'Microsoft Corporation'
        $msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
        $dism = Join-Path $env:SystemRoot 'System32\dism.exe'
        Assert-Publisher $msiexec 'Microsoft Windows'
        Assert-Publisher $dism 'Microsoft Windows'
        $code = Run-Bounded $msiexec ('/i "' + $msi + '" /qn /norestart') 'wsl-msi'
        if ($code -notin @(0, 3010, 1641)) { Step 'install_wsl' 'failed'; Finish 'wsl_install_failed' 30 }
        $needsReboot = $code -in @(3010, 1641)
        foreach ($feature in @('Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform')) {
            $code = Run-Bounded $dism ('/Online /Enable-Feature /FeatureName:' + $feature + ' /All /NoRestart /LimitAccess') ('feature-' + $feature)
            if ($code -notin @(0, 3010, 1641)) { Finish 'offline_windows_feature_install_failed' 30 }
            if ($code -in @(3010, 1641)) { $needsReboot = $true }
        }
        Step 'install_wsl_offline' 'complete'
        if ($needsReboot -or -not $featuresReady) { $result.reboot_required = $true; Finish 'reboot_required' 20 }
        $updatedVersion = Get-WslVersion $wsl
        $result.wsl_ready = $null -ne $updatedVersion -and $updatedVersion -ge [version]'2.1.5' -and (Test-WslFeatures)
        if (-not $result.wsl_ready) { Finish 'wsl_version_insufficient' 30 }
    }
    if (-not $result.docker_installed) {
        $installer = Join-Path $assets 'docker-desktop-installer.exe'
        Assert-LocalAsset $installer 'Docker Inc'
        Step 'verify_docker_installer' 'complete'
        $code = Run-Bounded $installer 'install --quiet --accept-license --backend=wsl-2' 'docker' 1200
        if ($code -in @(3010, 1641)) { $result.reboot_required = $true; Finish 'reboot_required' 20 }
        if ($code -ne 0) { Finish 'docker_install_failed' 30 }
        $result.docker_installed = @($dockerPaths | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }).Count -gt 0
        if (-not $result.docker_installed) { Finish 'docker_install_unverified' 30 }
        Step 'install_docker' 'complete'
    }
    Finish 'ready' 0
} catch {
    # No exception text, native output or environment values escape the private diagnostic boundary.
    if ($script:diagnosticsProtected) { [System.IO.File]::WriteAllText((Join-Path $script:privateDir 'failure.log'), $_.Exception.GetType().FullName + ': ' + $_.Exception.Message, $utf8) }
    Step 'prerequisites' 'failed'
    Finish 'failed' 30
}
