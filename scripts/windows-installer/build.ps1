#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$out = [IO.Path]::GetFullPath($OutputDirectory)
[IO.Directory]::CreateDirectory($out) | Out-Null
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw 'NET_Framework_compiler_missing' }
$common = @('/nologo','/target:winexe','/platform:x64','/codepage:65001','/r:System.Windows.Forms.dll','/r:System.Drawing.dll','/r:System.Web.Extensions.dll')
& $compiler @common ('/out:' + (Join-Path $out 'fxfetch-setup.exe')) ('/win32manifest:' + (Join-Path $PSScriptRoot 'setup.manifest')) (Join-Path $PSScriptRoot 'Setup.cs')
if ($LASTEXITCODE -ne 0) { throw 'installer_compile_failed' }
& $compiler @common ('/out:' + (Join-Path $out 'fxfetch.exe')) (Join-Path $PSScriptRoot 'Setup.cs')
if ($LASTEXITCODE -ne 0) { throw 'launcher_compile_failed' }
