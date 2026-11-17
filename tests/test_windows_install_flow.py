"""Installer gate ordering with synthetic local state; never launch Docker."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/windows-installer/install.py"
SPEC = importlib.util.spec_from_file_location("synthetic_install_flow", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


@pytest.mark.skipif(os.name != "nt", reason="Windows installation path contract")
@pytest.mark.parametrize("failure", ["bootstrap", "shutdown", "initialize", "firewall"])
def test_failed_gate_never_publishes_or_emits_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    root, bundle = tmp_path / "installation", tmp_path / "bundle"
    monkeypatch.syspath_prepend(str(SCRIPT.parents[2] / "src"))
    events: list[str] = []
    statuses: list[str] = []
    monkeypatch.setattr(installer, "verify_bundle", lambda _: {"images": {"synthetic:local": "sha256:test"}})
    monkeypatch.setattr(installer.shutil, "disk_usage", lambda _: SimpleNamespace(free=100 * 1024**3))
    monkeypatch.setattr(installer, "docker_path", lambda: "synthetic-docker")
    monkeypatch.setattr(installer, "emit", lambda status, *a, **kw: statuses.append(status))

    def copy(*_: object) -> None:
        (root / "private").mkdir(parents=True)
        (root / "private/installation.json").write_text(json.dumps({"install_id": "a" * 32}), encoding="utf-8")

    def gate(name: str) -> None:
        events.append(name)
        if failure == name:
            raise ValueError("synthetic_gate_failed")

    def run(arguments: list[str], *a: object, **kw: object) -> subprocess.CompletedProcess[str]:
        output, code = "", 0
        if arguments[1:3] in (["network", "inspect"], ["container", "inspect"]):
            code = 1
        elif arguments[1:3] == ["image", "inspect"]:
            output = "sha256:test"
        elif arguments[1] == "inspect":
            output = json.dumps([{"State": {"Running": False, "ExitCode": 137 if failure == "shutdown" else 0}}])
        if any(str(value).endswith("configure-docker-lan.ps1") for value in arguments):
            gate("firewall")
        return subprocess.CompletedProcess(arguments, code, output, "")

    starter = SimpleNamespace(ensure_engine=lambda _: None, ensure_kvm=lambda _: None)
    guest = SimpleNamespace(prepare=lambda *a: None, bootstrap=lambda *a: gate("bootstrap"))
    service = SimpleNamespace(initialise=lambda *a, **kw: gate("initialize"),
                              write_runtime_config=lambda *a: gate("config"))
    monkeypatch.setattr(installer, "copy_payload", copy)
    monkeypatch.setattr(installer, "run", run)
    monkeypatch.setattr(installer, "load", lambda name, _: {
        "installer_docker_start": starter, "provision_guest": guest, "service_setup": service,
    }[name])
    monkeypatch.setattr(installer, "launch", lambda _: pytest.fail("LAN startup must follow every gate"))
    args = argparse.Namespace(bundle=bundle, root=root, lan_ip="192.168.7.10", subnet="192.168.7.0/24",
                              accept_licenses=True)
    with pytest.raises(ValueError, match="guest_shutdown_not_clean|synthetic_gate_failed"):
        installer.install(args, {"use_default": False, "password": "synthetic-password"})
    assert "ready" not in statuses
    assert not (root / "private/launcher.json").exists()
    if failure in {"bootstrap", "shutdown", "initialize"}:
        assert "firewall" not in events


@pytest.mark.parametrize("chrome,web_apk", [(True, True), (False, True), (True, False)])
def test_healthy_containers_require_live_features_before_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, chrome: bool, web_apk: bool,
) -> None:
    private = tmp_path / "private"
    private.mkdir()
    (private / "launcher.json").write_text('{"subnet":"192.168.7.0/24"}', encoding="utf-8")
    (private / "service-install.json").write_text('{"volume":"synthetic-api"}', encoding="utf-8")
    seen: list[str] = []
    monkeypatch.setattr(installer, "docker_path", lambda: "synthetic-docker")

    def run(arguments: list[str], *a: object, **kw: object) -> subprocess.CompletedProcess[str]:
        if any(str(value).endswith("start_docker.py") for value in arguments):
            output = '\n'.join(json.dumps(row) for row in (
                {"phase": "configuration_verified", "publication": "192.168.7.10:8765"},
                {"phase": "containers_healthy"},
            ))
        elif arguments[1] == "ps":
            output = "api-id" if arguments[-1].endswith("=api") else "worker-id"
        elif arguments[1] == "inspect":
            mount = {"Destination": "/var/lib/fxfetch", "Name": "synthetic-api"} if arguments[2] == "api-id" else {
                "Destination": "/state", "Source": str(private / "guest"),
            }
            output = json.dumps([{"Mounts": [mount]}])
        elif arguments[1] == "exec":
            assert arguments[2] == "api-id"
            assert arguments[-1] == installer.READINESS
            seen.append("live_features")
            output = json.dumps({"chrome": chrome, "web_apk": web_apk})
        else:
            pytest.fail("unexpected synthetic subprocess")
        return subprocess.CompletedProcess(arguments, 0, output, "")

    monkeypatch.setattr(installer, "run", run)
    if chrome and web_apk:
        assert installer.launch(tmp_path) == "http://192.168.7.10:8765/"
    else:
        with pytest.raises(ValueError, match="installed_features_not_ready"):
            installer.launch(tmp_path)
    assert seen == ["live_features"]
