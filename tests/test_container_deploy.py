import importlib.util
import os
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
    config(FXFETCH_PUBLIC_IP="192.168.50.20", FXFETCH_TRUSTED_PEERS="192.168.50.0/24")
