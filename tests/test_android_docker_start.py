"""Startup policy/control tests using mocks; never start Docker or change WSL."""

import copy
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "docker_start", Path(__file__).resolve().parents[1] / "scripts/android-worker/start_docker.py",
)
assert SPEC is not None and SPEC.loader is not None
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


def test_localized_wsl_style_stderr_cannot_abort_successful_control_probe():
    result = launcher.run([
        sys.executable, "-c",
        "import sys; sys.stdout.write('linux\\n'); sys.stderr.buffer.write('本地诊断'.encode('utf-16-le'))",
    ], 5)
    assert result.returncode == 0 and result.stdout.strip() == "linux"
    assert result.stderr


def model():
    return {"name": "fxfetch-android-docker", "services": {
        "android-worker": {"image": "fxfetch-android-qemu:local", "ports": [
            {"host_ip": "127.0.0.1", "published": "18765", "target": 18765, "protocol": "tcp"},
        ]},
        "api": {"image": "fxfetch-android-api:local", "network_mode": "service:android-worker",
                "environment": {"FXFETCH_PUBLIC_IP": "127.0.0.1", "FXFETCH_PORT": "18765"}},
    }}


def test_default_and_lan_same_port_publication():
    value = model()
    assert launcher.publication(value)[:2] == ("127.0.0.1", 18765)
    value["services"]["android-worker"]["ports"] = [
        {"host_ip": "192.168.50.10", "published": "8765", "target": 8765, "protocol": "tcp"},
    ]
    value["services"]["api"]["environment"] = {"FXFETCH_PUBLIC_IP": "192.168.50.10", "FXFETCH_PORT": "8765"}
    assert launcher.publication(value)[:2] == ("192.168.50.10", 8765)


@pytest.mark.parametrize("address", ["0.0.0.0", "::", "::1", "8.8.8.8", "localhost", "127.0.0.2"])
def test_wildcard_public_ipv6_and_hostnames_fail(address):
    value = model()
    value["services"]["android-worker"]["ports"][0]["host_ip"] = address
    with pytest.raises(ValueError):
        launcher.publication(value)


def test_merged_extra_port_or_mismatched_origin_fails():
    value = model()
    value["services"]["android-worker"]["ports"].append(copy.deepcopy(value["services"]["android-worker"]["ports"][0]))
    with pytest.raises(ValueError, match="exactly_one"):
        launcher.publication(value)
    value = model()
    value["services"]["api"]["environment"]["FXFETCH_PORT"] = "8765"
    with pytest.raises(ValueError, match="origin"):
        launcher.publication(value)


def test_control_port_or_registry_image_never_started():
    value = model()
    port = value["services"]["android-worker"]["ports"][0]
    port.update(target=19222, published="19222")
    with pytest.raises(ValueError, match="control_port"):
        launcher.publication(value)
    value = model()
    value["services"]["api"]["image"] = "untrusted.example/api:latest"
    with pytest.raises(ValueError, match="prebuilt"):
        launcher.publication(value)


def test_existing_kvm_is_not_modified(monkeypatch):
    calls = []
    def fake(args, timeout, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")
    monkeypatch.setattr(launcher, "run", fake)
    launcher.ensure_kvm("wsl")
    assert calls == [["wsl", "--distribution", "docker-desktop", "--user", "root", "--", "test", "-c", "/dev/kvm"]]


@pytest.mark.parametrize("vendor,module", [("GenuineIntel", "kvm_intel"), ("AuthenticAMD", "kvm_amd")])
def test_only_known_existing_cpu_module_is_loaded(monkeypatch, vendor, module):
    calls = []
    def fake(args, timeout, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 1 if len(calls) == 1 else 0,
                                           f"vendor_id\t: {vendor}\n" if "cat" in args else "", "")
    monkeypatch.setattr(launcher, "run", fake)
    launcher.ensure_kvm("wsl")
    assert len(calls) == 4
    assert calls[2][-2:] == ["modprobe", module]
    assert all(call[1:5] == ["--distribution", "docker-desktop", "--user", "root"] for call in calls)


def test_unavailable_kvm_fails_without_tcg(monkeypatch):
    calls = []
    def fake(args, timeout, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 1 if "test" in args else 0,
                                           "vendor_id : GenuineIntel\n" if "cat" in args else "", "")
    monkeypatch.setattr(launcher, "run", fake)
    with pytest.raises(ValueError, match="no_software_fallback"):
        launcher.ensure_kvm("wsl")
    assert len(calls) == 4


def test_healthy_engine_does_not_restart_desktop(monkeypatch):
    calls = []
    def fake(args, timeout, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "linux\n", "")
    monkeypatch.setattr(launcher, "run", fake)
    launcher.ensure_engine("docker")
    assert len(calls) == 1 and calls[0][1] == "info"


def test_engine_wait_has_one_ninety_second_budget(monkeypatch):
    clock = [0.0]
    calls = []
    def fake(args, timeout, **kwargs):
        calls.append((args, timeout))
        clock[0] += min(1, timeout)
        return subprocess.CompletedProcess(args, 0 if "desktop" in args else 1, "", "")
    monkeypatch.setattr(launcher, "run", fake)
    monkeypatch.setattr(launcher.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(launcher.time, "sleep", lambda duration: clock.__setitem__(0, clock[0] + duration))
    with pytest.raises(ValueError, match="within_90_seconds"):
        launcher.ensure_engine("docker")
    assert clock[0] <= 90
    assert sum("desktop" in args for args, _timeout in calls) == 1
    assert all(timeout <= 18 for _args, timeout in calls)


def test_stale_live_container_cannot_be_reported_as_current():
    worker = {"Image": "sha256:worker", "HostConfig": {"PortBindings": {
        "18765/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18765"}],
    }}}
    api = {"Image": "sha256:api", "HostConfig": {}, "Config": {"Env": [
        "FXFETCH_PUBLIC_IP=127.0.0.1", "FXFETCH_PORT=18765",
    ]}}
    launcher.verify_running(worker, api, "127.0.0.1", 18765, ["sha256:worker", "sha256:api"])
    with pytest.raises(ValueError, match="image_differs"):
        launcher.verify_running(worker, api, "127.0.0.1", 18765, ["sha256:worker", "sha256:new"])
    with pytest.raises(ValueError, match="publication_differs"):
        launcher.verify_running(worker, api, "192.168.50.10", 8765, ["sha256:worker", "sha256:api"])
