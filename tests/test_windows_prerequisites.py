"""Offline installer contract tests; never execute a prerequisite installation."""

import ast
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/windows-installer/prerequisites.ps1"
POWERSHELL = shutil.which("powershell.exe")


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell required")
@pytest.mark.parametrize("accept_license", [False, True])
def test_dry_run_utf8_has_no_files_or_installation(tmp_path: Path, accept_license: bool) -> None:
    install_root = tmp_path / "中文 安装目录"
    command = [
        str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(SCRIPT),
        "-InstallRoot", str(install_root), "-DryRun",
    ]
    if accept_license:
        command.append("-AcceptDockerLicense")
    completed = subprocess.run(command, capture_output=True, timeout=30, check=False)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    result = json.loads(completed.stdout.decode("utf-8-sig"))
    assert result["schema"] == "fxfetch.prerequisites.v1"
    assert result["status"] == "planned"
    assert result["reboot_required"] is False
    assert result["docker_installed"] is False
    assert result["diagnostics_relative_path"] is None
    assert all(step["state"] == "planned" for step in result["steps"])
    assert not install_root.exists()


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell required")
def test_powershell_parses_without_execution() -> None:
    escaped = str(SCRIPT).replace("'", "''")
    command = (
        "$tokens=$null; $errors=$null; "
        f"[void][System.Management.Automation.Language.Parser]::ParseFile('{escaped}',"
        "[ref]$tokens,[ref]$errors); if($errors.Count){$errors | Out-String; exit 1}"
    )
    completed = subprocess.run(
        [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, timeout=30, check=False,
    )
    assert completed.returncode == 0, completed.stdout.decode(errors="replace")


def test_fixed_download_and_explicit_acceptance_contract() -> None:
    source = SCRIPT.read_text(encoding="utf-8-sig")
    assert "docker-desktop-installer.exe" in source
    assert "wsl.msi" in source
    assert "$signature.Status -ne 'Valid'" in source
    assert "Assert-LocalAsset $installer 'Docker Inc'" in source
    assert "Assert-LocalAsset $msi 'Microsoft Corporation'" in source
    assert "-not $AcceptDockerLicense" in source
    assert "/NoRestart /LimitAccess" in source
    assert "--install" not in source
    assert "--update" not in source
    assert "HttpClient" not in source
    assert "Invoke-WebRequest" not in source
    assert "https://" not in source
    assert "WaitForExit($Seconds * 1000)" in source
    assert "ServerCertificateValidationCallback" not in source
    assert "Set-ExecutionPolicy" not in source
    assert "Restart-Computer" not in source


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell required")
@pytest.mark.parametrize("installed", [False, True])
def test_check_only_mocked_host(tmp_path: Path, installed: bool) -> None:
    source = SCRIPT.read_text(encoding="utf-8-sig")
    guard = next(line for line in source.splitlines() if "Finish 'unsupported_windows'" in line)
    source = source.replace(guard, "    # Synthetic Windows platform for offline test.")
    value = "$true" if installed else "$false"
    mocks = """
function Get-CimInstance([string]$ClassName) {
    if ($ClassName -eq 'Win32_ComputerSystem') {
        return [pscustomobject]@{ TotalPhysicalMemory = 16GB; HypervisorPresent = $true }
    }
    return [pscustomobject]@{ VirtualizationFirmwareEnabled = $true; SecondLevelAddressTranslationExtensions = $true }
}
function Test-Path { return MOCK_INSTALLED }
function Get-WslVersion { return [version]'2.6.0' }
function Test-WslFeatures { return $true }
function Start-Process { throw 'Native process must never run during check-only' }
""".replace("MOCK_INSTALLED", value)
    marker = "\ntry {\n    if (-not [System.IO.Path]::IsPathRooted"
    assert marker in source
    source = source.replace(marker, "\n" + mocks + marker, 1)
    mocked_script = tmp_path / "mocked.ps1"
    mocked_script.write_text(source, encoding="utf-8-sig")
    install_root = tmp_path / "另一个独立目录"
    completed = subprocess.run(
        [str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(mocked_script),
         "-InstallRoot", str(install_root), "-CheckOnly"],
        capture_output=True, timeout=30, check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    result = json.loads(completed.stdout.decode("utf-8-sig"))
    assert result["status"] == ("ready" if installed else "needs_install")
    assert result["docker_installed"] is installed
    assert result["wsl_ready"] is installed
    assert not install_root.exists()


@pytest.mark.skipif(POWERSHELL is None, reason="Windows PowerShell required")
@pytest.mark.parametrize("entrypoint", ["windows-installer/install.py", "android-worker/start_docker.py"])
def test_bundled_scripts_work_with_restricted_parent_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entrypoint: str,
) -> None:
    # Exercise the actual launch prefixes against a harmless offline dry run.
    # The inherited process policy must not prevent fresh Windows setup.
    monkeypatch.setenv("PSExecutionPolicyPreference", "Restricted")
    tree = ast.parse((SCRIPT.parents[1] / entrypoint).read_text(encoding="utf-8"))
    prefixes: set[tuple[str, ...]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.List):
            values = [item.value if isinstance(item, ast.Constant) else None for item in node.elts]
            if "-File" in values:
                prefix = tuple(values[1:values.index("-File") + 1])
                assert all(isinstance(value, str) for value in prefix)
                prefixes.add(prefix)
    assert prefixes
    install_root = tmp_path / "中文 空格"
    for prefix in prefixes:
        completed = subprocess.run(
            [str(POWERSHELL), *prefix, str(SCRIPT), "-InstallRoot", str(install_root), "-DryRun"],
            capture_output=True, timeout=30, check=False,
        )
        assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
        assert json.loads(completed.stdout.decode("utf-8-sig"))["status"] == "planned"
    assert os.environ["PSExecutionPolicyPreference"] == "Restricted"
    assert not install_root.exists()
