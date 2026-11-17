"""Service installer tests use synthetic assets and a mocked Docker CLI only."""
from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/windows-installer/service_setup.py"
SPEC = importlib.util.spec_from_file_location("windows_service_setup", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup)


def assets(root: Path) -> None:
    (root / "assets/android-sdk-linux").mkdir(parents=True)
    (root / "assets/fonts").mkdir(parents=True)
    (root / "private/api-worker").mkdir(parents=True)


@pytest.mark.parametrize("use_hash", [False, True])
def test_fresh_volume_stdin_only_and_utf8(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, use_hash: bool) -> None:
    root = tmp_path / "中文 独立安装"
    assets(root)
    calls: list[tuple[list[str], dict]] = []
    password = "合成口令-only-for-test-12345"
    synthetic_hash = "pbkdf2_sha256$600000$" + "ab" * 16 + "$" + "cd" * 32

    def docker(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((arguments, dict(kwargs)))
        identity = json.loads((root / "private/service-install.json").read_text(encoding="utf-8"))
        output = ""
        if arguments[1:3] == ["volume", "inspect"]:
            output = json.dumps([{"Labels": {setup.LABEL: identity["install_id"]}}])
        if arguments[1] == "run":
            output = json.dumps({"state": "ready", "build": "ready", "fresh_identity": True})
        return subprocess.CompletedProcess(arguments, 0, output, "")

    monkeypatch.setattr(setup.subprocess, "run", docker)
    result = (setup.initialise("synthetic-docker", root, password_hash=synthetic_hash) if use_hash
              else setup.initialise("synthetic-docker", root, password))
    assert result["state"] == "ready"
    assert password not in json.dumps(result)
    assert len(calls) == 4
    command, options = calls[-1]
    assert password not in str(command)
    payload = json.loads(options["input"])
    assert payload["password_hash" if use_hash else "password"] == (synthetic_hash if use_hash else password)
    assert synthetic_hash not in str(command)
    assert options["encoding"] == "utf-8"
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--pull") + 1] == "never"
    assert setup.IMAGE in command
    assert not (root / "private/auth.json").exists()


@pytest.mark.parametrize("encoded", ["", "pbkdf2_sha256$1$ab$cd", "plain-password", "pbkdf2_sha256$600000$" + "aa" * 16 + "$" + "bb" * 31])
def test_invalid_preconfigured_hash_before_any_commands(tmp_path: Path, encoded: str) -> None:
    with pytest.raises(ValueError, match="invalid_auth_configuration"):
        setup.initialise("must-never-execute", tmp_path, password_hash=encoded)
    assert list(tmp_path.iterdir()) == []


def test_unknown_existing_volume_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assets(tmp_path)
    _, identity = setup._marker(tmp_path)
    commands: list[list[str]] = []

    def docker(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(arguments)
        output = identity["volume"] if arguments[1:3] == ["volume", "ls"] else '[{"Labels": {}}]'
        return subprocess.CompletedProcess(arguments, 0, output, "")

    monkeypatch.setattr(setup.subprocess, "run", docker)
    with pytest.raises(ValueError, match="unowned"):
        setup.initialise("synthetic-docker", tmp_path, "synthetic-password-12345")
    assert all(command[1] != "run" for command in commands)
    assert all(command[1:3] != ["volume", "create"] for command in commands)


def test_runtime_is_independent_and_only_one_lan_publication(tmp_path: Path) -> None:
    first = setup.write_runtime_config(tmp_path / "甲 安装", "192.168.44.10", "192.168.44.0/24")
    second = setup.write_runtime_config(tmp_path / "乙 安装", "192.168.44.11", "192.168.44.0/24")
    assert first["volume"] != second["volume"]
    assert setup.write_runtime_config(tmp_path / "甲 安装", "192.168.44.10", "192.168.44.0/24")["volume"] == first["volume"]
    text = Path(first["override"]).read_text(encoding="utf-8")
    assert "ports: !override" in text
    assert text.count('"published"') == 1
    assert "external: true" in text
    assert "subpath: worker-config" in text
    assert "volumes: !override" in text
    assert '"FXFETCH_PORT": "8765"' in text
    environment = Path(first["env_file"]).read_text(encoding="utf-8")
    assert "甲 安装" in environment
    assert "android-sdk-linux" in environment
    assert "FXFETCH_FXAPK='/opt/fxapk-venv/bin/fxapk'" in environment
    assert "FXFETCH_DNS_PROVIDERS='cloudflare,google'" in environment
    assert "password" not in environment.lower()


@pytest.mark.parametrize("ip,subnet,port", [
    ("0.0.0.0", "192.168.0.0/24", 8765),
    ("192.168.0.2", "0.0.0.0/0", 8765),
    ("192.168.0.2", "192.168.0.0/24", 12222),
    ("192.168.0.255", "192.168.0.0/24", 8765),
])
def test_invalid_network_rejected_before_writes(tmp_path: Path, ip: str, subnet: str, port: int) -> None:
    with pytest.raises(ValueError):
        setup.write_runtime_config(tmp_path / "not-created", ip, subnet, port)
    assert not (tmp_path / "not-created").exists()


def test_embedded_initializer_compiles_and_never_uses_network() -> None:
    compile(setup.INITIALIZER, "<synthetic-installer-initializer>", "exec")
    assert "password_hash(p['password'])" in setup.INITIALIZER
    assert "os.chown(path, 10001, 10001)" in setup.INITIALIZER
    assert "setup_build(r, Path('/opt/android-sdk')" in setup.INITIALIZER
