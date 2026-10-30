import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_ENTRY = Path(__file__).resolve().parents[1] / "deploy" / "docker" / "entrypoint.py"
_SPEC = importlib.util.spec_from_file_location("fxfetch_container_entrypoint", _ENTRY)
assert _SPEC is not None and _SPEC.loader is not None
entrypoint = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = entrypoint
_SPEC.loader.exec_module(entrypoint)


def config(**extra):
    return entrypoint.deployment({"FXFETCH_ROOT": str(_ENTRY.parent.resolve()), **extra})


def test_container_has_explicit_bind_and_exact_default_peers():
    value = config()
    assert value.bind == "172.30.246.2"
    assert value.public_ip == "127.0.0.1"
    assert value.allowed_networks == ("172.30.246.1/32", "172.30.246.2/32")
    assert value.allowed_hosts == ("127.0.0.1:18765", "172.30.246.2:18765", "localhost:18765")
    assert value.fxapk_executable is None


@pytest.mark.parametrize("values", [
    {"FXFETCH_PUBLIC_IP": "0.0.0.0"},
    {"FXFETCH_PUBLIC_IP": "8.8.8.8"},
    {"FXFETCH_PUBLIC_IP": "example.test"},
    {"FXFETCH_CONTAINER_IP": "127.0.0.1"},
    {"FXFETCH_CONTAINER_IP": "172.30.246.0"},
    {"FXFETCH_CONTAINER_IP": "172.30.247.2"},
    {"FXFETCH_TRUSTED_PEERS": "0.0.0.0/0"},
    {"FXFETCH_TRUSTED_PEERS": ""},
    {"FXFETCH_PORT": "80"},
    {"FXFETCH_PORT": "65536"},
    {"FXFETCH_ROOT": "relative"},
    {"FXFETCH_FXAPK": "fxapk"},
    {"FXFETCH_FXAPK": "C:/Tools/fxapk.exe"},
    {"FXFETCH_FXAPK": "//host/share/fxapk"},
    {"FXFETCH_FXAPK": "/opt/../fxapk"},
    {"FXFETCH_FXAPK": "/opt/fxapk\\bin"},
    {"FXFETCH_FXAPK": "/opt/fxapk\0"},
    {"FXFETCH_FXAPK": "/opt/fxapk\n"},
])
def test_container_rejects_unsafe_or_ambiguous_configuration(values):
    with pytest.raises(ValueError):
        config(**values)


def test_container_clears_mixed_case_proxy_environment(monkeypatch):
    for key in ("HTTP_PROXY", "https_proxy", "All_Proxy"):
        monkeypatch.setenv(key, "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", "example.test")
    monkeypatch.setenv("no_proxy", "example.test")
    entrypoint.clear_proxy_environment()
    assert not any(key.lower() in {"http_proxy", "https_proxy", "all_proxy"} for key in os.environ)
    assert os.environ["NO_PROXY"] == os.environ["no_proxy"] == "*"


def test_container_configuration_never_resolves_targets(monkeypatch):
    import socket

    def forbid(*args, **kwargs):
        raise AssertionError("configuration must not resolve or connect")

    monkeypatch.setattr(socket, "getaddrinfo", forbid)
    monkeypatch.setattr(socket, "create_connection", forbid)
    monkeypatch.setattr(subprocess, "Popen", forbid)
    value = config(
        FXFETCH_PUBLIC_IP="192.168.50.20", FXFETCH_TRUSTED_PEERS="192.168.50.0/24",
        FXFETCH_FXAPK="/opt/offline tools/bin/fxapk",
    )
    assert value.fxapk_executable == "/opt/offline tools/bin/fxapk"


@pytest.mark.parametrize("executable", ["", "/opt/fxapk/venv/bin/fxapk"])
def test_container_serve_uses_only_deployment_analysis_configuration(tmp_path, monkeypatch, executable):
    import uvicorn

    from fxfetch import build_setup, cli, service
    from fxfetch.web import api

    # Migrated host configuration must not enable analysis or change container networking.
    (tmp_path / "server.json").write_text(json.dumps({
        "fxapk_executable": "C:/host/fxapk.exe", "host": "0.0.0.0", "proxy_host": "host.test",
    }), encoding="utf-8")
    monkeypatch.setattr(os, "environ", {"FXFETCH_ROOT": str(tmp_path), "FXFETCH_FXAPK": executable})
    monkeypatch.setattr(cli, "_load_auth", lambda root: "synthetic-hash")
    monkeypatch.setattr(build_setup, "load_builder", lambda root: None)
    captured = {}

    def make_service(settings, **kwargs):
        captured["settings"] = settings
        return object()

    app = object()
    monkeypatch.setattr(service, "JobService", make_service)
    monkeypatch.setattr(api, "create_app", lambda settings, **kwargs: app)
    monkeypatch.setattr(uvicorn, "run", lambda application, **kwargs: captured.update(app=application, **kwargs))
    assert entrypoint.main(["serve"]) == 0
    settings = captured["settings"]
    assert settings.fxapk_executable == (executable or None)
    assert settings.proxy_host is None
    assert settings.host == captured["host"] == "172.30.246.2"
    assert captured["app"] is app
    assert captured["proxy_headers"] is False


@pytest.mark.parametrize("deployment", ["docker", "android-docker"])
@pytest.mark.parametrize("executable", ["", "/opt/fxapk/venv/bin/fxapk"])
def test_compose_passes_optional_analysis_path(tmp_path, deployment, executable):
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker Compose CLI is not installed; no daemon is required")
    environ = {
        **os.environ, "FXFETCH_FXAPK": executable,
        "FXFETCH_ANDROID_STATE": str(tmp_path / "vm"),
        "FXFETCH_ANDROID_CONFIG_DIR": str(tmp_path / "config"),
    }
    result = subprocess.run(
        [docker, "compose", "-f", str(_ENTRY.parents[1] / deployment / "compose.yaml"),
         "config", "--format", "json"],
        env=environ, check=True, capture_output=True, text=True, timeout=20,
    )
    api = json.loads(result.stdout)["services"]["api"]
    assert api["environment"]["FXFETCH_FXAPK"] == executable
    assert api["user"] == "10001:10001" and api["read_only"]
    assert api["cap_drop"] == ["ALL"]
