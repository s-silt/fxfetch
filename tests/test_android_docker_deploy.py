"""Inspect the Compose model without starting Docker, a guest, or a service."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def model(tmp_path_factory):
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker Compose CLI is not installed; no daemon is required")
    private = tmp_path_factory.mktemp("synthetic-compose-paths")
    environ = {
        **os.environ,
        "FXFETCH_ANDROID_STATE": str(private / "vm"),
        "FXFETCH_ANDROID_CONFIG_DIR": str(private / "config"),
    }
    result = subprocess.run(
        [docker, "compose", "-f", str(ROOT / "deploy/android-docker/compose.yaml"),
         "config", "--format", "json"],
        env=environ, check=True, capture_output=True, text=True, timeout=20,
    )
    return json.loads(result.stdout)


def test_only_loopback_api_is_published_and_control_shares_namespace(model):
    api, worker = model["services"]["api"], model["services"]["android-worker"]
    assert api["network_mode"] == "service:android-worker"
    assert not api.get("ports") and not api.get("networks")
    assert len(worker["ports"]) == 1
    published = worker["ports"][0]
    assert (published["host_ip"], published["target"], published["published"]) == (
        "127.0.0.1", 18765, "18765",
    )
    assert api["environment"]["FXFETCH_CONTAINER_IP"] == worker["networks"]["private"]["ipv4_address"]
    assert api["environment"]["FXFETCH_PUBLIC_IP"] == published["host_ip"]


def test_api_has_no_hypervisor_device_or_privileged_host_access(model):
    api, worker = model["services"]["api"], model["services"]["android-worker"]
    assert api["user"] == "10001:10001" and not api.get("devices")
    assert worker["devices"] == [{"source": "/dev/kvm", "target": "/dev/kvm", "permissions": "rw"}]
    for service in (api, worker):
        assert not service.get("privileged") and service["read_only"]
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
        assert int(service["mem_limit"]) == int(service["memswap_limit"])
        assert service["restart"] == "no"
        assert not service.get("pid") and not service.get("ipc")
        assert all("docker.sock" not in str(mount) for mount in service["volumes"])
    credentials = [mount for mount in api["volumes"] if mount["type"] == "bind"]
    assert len(credentials) == 1
    assert all(mount["read_only"] and not mount["bind"]["create_host_path"] for mount in credentials)
    assert {mount["target"] for mount in worker["volumes"]} == {"/state"}


def test_api_has_direct_environment_and_explicit_nonpublic_bind(model):
    environ = model["services"]["api"]["environment"]
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        assert environ[key] == ""
    assert environ["NO_PROXY"] == environ["no_proxy"] == "*"
    assert environ["FXFETCH_TRUSTED_PEERS"] == "172.30.247.1/32"
    assert environ["FXFETCH_CONTAINER_SUBNET"] == "172.30.247.0/28"
