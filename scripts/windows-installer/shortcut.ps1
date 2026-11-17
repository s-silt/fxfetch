#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$InstallRoot, [ValidateSet('Setup','Launch')][string]$Mode = 'Launch')
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$root = [IO.Path]::GetFullPath($InstallRoot)
$filename = if ($Mode -eq 'Setup') { 'fxfetch-setup.exe' } else { 'fxfetch.exe' }
$executable = Join-Path $root $filename
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'launcher_missing' }
$desktop = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
$shell = New-Object -ComObject WScript.Shell
$linkname = if ($Mode -eq 'Setup') { 'fxfetch Setup.lnk' } else { 'fxfetch.lnk' }
$name = Join-Path $desktop $linkname
if (Test-Path -LiteralPath $name) {
    $existing = $shell.CreateShortcut($name)
    if ($existing.TargetPath -ne $executable) { throw 'unrelated_shortcut_preserved' }
}
$shortcut = $shell.CreateShortcut($name)
$shortcut.TargetPath = $executable
$shortcut.WorkingDirectory = $root
$shortcut.Description = 'fxfetch LAN service'
$shortcut.Save()
if ($Mode -eq 'Launch') {
    $pendingLink = Join-Path $desktop 'fxfetch Setup.lnk'
    if (Test-Path -LiteralPath $pendingLink) {
        $pending = $shell.CreateShortcut($pendingLink)
        if ($pending.TargetPath -eq (Join-Path $root 'fxfetch-setup.exe')) {
            Remove-Item -LiteralPath $pendingLink
        }
    }
}
[Console]::WriteLine('{"shortcut_created":true}')
