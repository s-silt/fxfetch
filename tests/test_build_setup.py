from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from fxfetch import build_setup
from fxfetch.core.process_limits import ProcessResult


def test_optional_font_config_is_local_pinned_and_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    font = tmp_path / "font.otf"
    license_path = tmp_path / "license.txt"
    raw = b"OTTOsynthetic-font"
    license_data = b"SIL OPEN FONT LICENSE Version 1.1"
    font.write_bytes(raw)
    license_path.write_bytes(license_data)
    pins = {
        "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        "git_blob_sha1": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
        "license_sha256": hashlib.sha256(license_data).hexdigest(),
    }
    monkeypatch.setattr(build_setup, "_FONT_PINS", pins)
    config = {"path": str(font), "license_path": str(license_path), **pins}
    path = tmp_path / "offline-font.json"
    path.write_text(json.dumps(config))
    settings = build_setup.load_builder(tmp_path).settings
    assert settings.offline_font_path == font
    assert settings.offline_font_size == len(raw)
    license_path.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="local content"):
        build_setup.load_builder(tmp_path)
    config["size"] = len(raw) + 1
    path.write_text(json.dumps(config))
    with pytest.raises(ValueError, match="metadata"):
        build_setup.load_builder(tmp_path)


@pytest.mark.parametrize("change", [{"path": "relative.otf"}, {"extra": True}])
def test_optional_font_config_rejects_untrusted_shape(tmp_path: Path, change: dict) -> None:
    config = {"path": str(tmp_path / "font.otf"), "license_path": str(tmp_path / "license.txt"),
              **build_setup._FONT_PINS, **change}
    (tmp_path / "offline-font.json").write_text(json.dumps(config))
    with pytest.raises(ValueError):
        build_setup.load_builder(tmp_path)


def test_local_setup_preserves_identity_and_limits_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[list[str]] = []

    def private(path: Path) -> bool:
        path.mkdir(parents=True, exist_ok=True)
        return True

    def run(command: list[str], **_: object) -> ProcessResult:
        commands.append(command)
        if "-genkeypair" in command:
            Path(command[command.index("-keystore") + 1]).write_bytes(b"synthetic signing key")
        return ProcessResult(0)

    monkeypatch.setattr(build_setup, "_private_directory", private)
    monkeypatch.setattr(build_setup, "run_limited", run)
    jdk = tmp_path / "jdk"
    keytool = jdk / "bin" / ("keytool.exe" if os.name == "nt" else "keytool")
    keytool.parent.mkdir(parents=True)
    keytool.touch()
    root = tmp_path / "service"
    first = build_setup.setup_build(root, tmp_path / "sdk", tmp_path / "tools", jdk)
    assert first.state == "disabled"  # Synthetic tool files are not a usable SDK.
    original_key = (root / ".build-private/application.p12").read_bytes()
    original_password = (root / ".build-private/password").read_bytes()
    second = build_setup.setup_build(root, tmp_path / "sdk", tmp_path / "tools", jdk)
    assert second.state == "disabled"
    assert (root / ".build-private/application.p12").read_bytes() == original_key
    assert (root / ".build-private/password").read_bytes() == original_password
    assert sum("-genkeypair" in command for command in commands) == 1
    assert all(
        original_password.strip().decode() not in argument for command in commands for argument in command
    )
    config = json.loads((root / "build.json").read_text())
    assert set(config) == {"sdk_root", "build_tools_root", "java_home"}
    builder = build_setup.load_builder(root)
    assert builder.settings.signing_keystore == root / ".build-private/application.p12"
    assert builder.settings.signing_password_file == root / ".build-private/password"


def test_setup_rejects_incomplete_existing_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def private(path: Path) -> bool:
        path.mkdir(parents=True, exist_ok=True)
        (path / "password").write_bytes(b"synthetic existing password")
        return True

    monkeypatch.setattr(build_setup, "_private_directory", private)
    result = build_setup.setup_build(tmp_path, tmp_path, tmp_path, tmp_path)
    assert result.reason_codes == ("incomplete_signing_identity",)
    assert not (tmp_path / "build.json").exists()


@pytest.mark.parametrize(
    "config", [{"unknown": "value"}, {"sdk_root": "relative", "build_tools_root": ".", "java_home": "."}, []]
)
def test_build_config_is_fixed_local_schema(tmp_path: Path, config: object) -> None:
    (tmp_path / "build.json").write_text(json.dumps(config))
    with pytest.raises(ValueError):
        build_setup.load_builder(tmp_path)


def test_setup_fail_closed_if_private_permissions_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(build_setup, "_private_directory", lambda _: False)
    result = build_setup.setup_build(tmp_path, tmp_path, tmp_path, tmp_path)
    assert result.reason_codes == ("private_permissions_unavailable",)
    assert not (tmp_path / "build.json").exists()
