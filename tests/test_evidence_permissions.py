import json
import os
import stat
import subprocess
from pathlib import Path

import pytest
from test_web_evidence import _make_capture

from fxfetch import build_setup
from fxfetch.core import web_capture
from fxfetch.core.limits import Limits
from fxfetch.core.web_evidence import export_web
from fxfetch.core.web_evidence_io import create_private_evidence_directory
from fxfetch.core.web_evidence_schema import EvidenceError


def test_new_evidence_root_has_private_permissions(tmp_path):
    target = tmp_path / "private"
    create_private_evidence_directory(target)
    if os.name != "nt":
        assert stat.S_IMODE(target.stat().st_mode) == 0o700
    else:
        powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        command = (
            "$ErrorActionPreference='Stop';"
            "$acl=Get-Acl -LiteralPath $env:FXFETCH_TEST_ACL_PATH;"
            "$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value;"
            "$rules=@($acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]));"
            "$trusted=@($sid,'S-1-5-18','S-1-5-32-544','S-1-3-4');"
            "@{protected=$acl.AreAccessRulesProtected;unexpected=(@($rules|Where-Object "
            "{$_.IdentityReference.Value -notin $trusted -or $_.IsInherited}).Count);"
            "own=(@($rules|Where-Object {$_.IdentityReference.Value -eq $sid -and "
            "$_.AccessControlType -eq 'Allow' -and $_.FileSystemRights -eq 'FullControl'}).Count)}|ConvertTo-Json -Compress"
        )
        result = subprocess.run(
            [str(powershell), "-NoProfile", "-NonInteractive", "-Command", command],
            env={**{key: value for key, value in os.environ.items() if key.casefold() != "psmodulepath"},
                 "FXFETCH_TEST_ACL_PATH": str(target)},
            capture_output=True, text=True, check=False, timeout=15,
        )
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"protected": True, "unexpected": 0, "own": 1}, result.stderr


def test_capture_permissions_fail_before_collector_or_evidence_write(tmp_path, monkeypatch):
    monkeypatch.setattr(build_setup, "_private_directory", lambda _: False)
    monkeypatch.setattr(web_capture, "collect_http", lambda *_: pytest.fail("collector must not run"))
    output = tmp_path / "capture"
    with pytest.raises(EvidenceError, match="private_permissions_unavailable"):
        web_capture.capture_web("https://capture.synthetic.test/", output, authorized_active=True, service_root=tmp_path)
    assert not output.exists()


def test_export_permissions_fail_before_private_material_copy(tmp_path, monkeypatch):
    capture = _make_capture(tmp_path / "source")
    before = (capture / "http/response.body").read_bytes()
    monkeypatch.setattr(build_setup, "_private_directory", lambda _: False)
    output = tmp_path / "export"
    with pytest.raises(EvidenceError, match="private_permissions_unavailable"):
        export_web(capture, output, Limits())
    assert not output.exists()
    assert (capture / "http/response.body").read_bytes() == before


def test_private_directory_does_not_modify_existing_directory(tmp_path):
    target = tmp_path / "existing"
    target.mkdir()
    (target / "preserve").write_bytes(b"original")
    with pytest.raises(FileExistsError):
        create_private_evidence_directory(target)
    assert (target / "preserve").read_bytes() == b"original"
