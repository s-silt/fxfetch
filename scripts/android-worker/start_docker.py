"""Bounded Windows Docker startup; no builds, pulls, browser installs or VM fallback."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
COMPOSE = PROJECT / "deploy/android-docker/compose.yaml"


def run(arguments: list[str], timeout: float, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        # WSL can emit localized UTF-16 diagnostics on stderr even when its
        # Linux stdout is UTF-8. Diagnostics are never used as readiness proof
        # or echoed; do not let a decoder thread abort a successful probe.
        arguments, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if len(result.stdout) > 2 * 1024**2 or len(result.stderr) > 2 * 1024**2:
        raise ValueError("local_command_output_limit")
    if check and result.returncode:
        # Compose output can contain private paths or config; do not echo it.
        raise ValueError("local_control_command_failed")
    return result


def publication(model: dict) -> tuple[str, int, tuple[str, str]]:
    if model.get("name") != "fxfetch-android-docker":
        raise ValueError("unexpected_compose_project")
    services = model.get("services", {})
    if set(services) != {"android-worker", "api"}:
        raise ValueError("unexpected_compose_services")
    worker, api = services["android-worker"], services["api"]
    if api.get("ports") or api.get("network_mode") != "service:android-worker":
        raise ValueError("unexpected_api_network")
    if worker.get("network_mode") or any(item.get("privileged") for item in services.values()):
        raise ValueError("unexpected_host_access")
    ports = worker.get("ports", [])
    if len(ports) != 1:
        raise ValueError("exactly_one_api_publication_required")
    port = ports[0]
    address = ipaddress.ip_address(port.get("host_ip", ""))
    private = tuple(ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    if not isinstance(address, ipaddress.IPv4Address) or not (
        str(address) == "127.0.0.1" or any(address in network for network in private)
    ):
        raise ValueError("publication_must_be_explicit_loopback_or_lan_ipv4")
    published = int(port["published"])
    if not 1024 <= published <= 65535 or int(port["target"]) != published or port.get("protocol") != "tcp":
        raise ValueError("api_host_and_container_tcp_ports_must_match")
    if published in {12222, 19222, 18767}:
        raise ValueError("control_port_must_not_be_published")
    environment = api.get("environment", {})
    if environment.get("FXFETCH_PUBLIC_IP") != str(address) or str(environment.get("FXFETCH_PORT")) != str(published):
        raise ValueError("api_origin_must_match_publication")
    images = (worker.get("image"), api.get("image"))
    if images[0] != "fxfetch-android-qemu:local" or images[1] not in {
        "fxfetch-android-api:local", "fxfetch-android-api-builder:local",
    }:
        raise ValueError("prebuilt_local_images_required")
    return str(address), published, images


def ensure_engine(docker: str) -> None:
    deadline = time.monotonic() + 90
    try:
        initial = run([docker, "info", "--format", "{{.OSType}}"], 8, check=False)
        if initial.returncode == 0 and initial.stdout.strip() == "linux":
            return
    except subprocess.TimeoutExpired:
        pass  # Still within the one overall engine-start deadline.
    run([docker, "desktop", "start", "--detach", "--timeout", "15"], min(18, deadline - time.monotonic()))
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        try:
            result = run([docker, "info", "--format", "{{.OSType}}"], min(5, remaining), check=False)
            if result.returncode == 0 and result.stdout.strip() == "linux":
                return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(min(2, max(0, deadline - time.monotonic())))
    raise ValueError("docker_linux_engine_not_ready_within_90_seconds")


def verify_running(worker: dict, api: dict, address: str, port: int, images: list[str]) -> None:
    expected = {f"{port}/tcp": [{"HostIp": address, "HostPort": str(port)}]}
    if worker.get("HostConfig", {}).get("PortBindings") != expected:
        raise ValueError("running_publication_differs_review_idle_cutover")
    if api.get("HostConfig", {}).get("PortBindings"):
        raise ValueError("running_api_has_unexpected_publication")
    if [worker.get("Image"), api.get("Image")] != images:
        raise ValueError("running_image_differs_review_idle_cutover")
    environment = dict(item.split("=", 1) for item in api.get("Config", {}).get("Env", []) if "=" in item)
    if environment.get("FXFETCH_PUBLIC_IP") != address or environment.get("FXFETCH_PORT") != str(port):
        raise ValueError("running_origin_differs_review_idle_cutover")


def ensure_kvm(wsl: str) -> None:
    prefix = [wsl, "--distribution", "docker-desktop", "--user", "root", "--"]
    if run([*prefix, "test", "-c", "/dev/kvm"], 10, check=False).returncode == 0:
        return
    cpu = run([*prefix, "cat", "/proc/cpuinfo"], 10).stdout
    vendors = {line.split(":", 1)[1].strip() for line in cpu.splitlines() if line.startswith("vendor_id")}
    module = {frozenset({"GenuineIntel"}): "kvm_intel", frozenset({"AuthenticAMD"}): "kvm_amd"}.get(frozenset(vendors))
    if module is None:
        raise ValueError("unsupported_or_ambiguous_cpu_vendor")
    run([*prefix, "modprobe", module], 15)
    if run([*prefix, "test", "-c", "/dev/kvm"], 10, check=False).returncode != 0:
        raise ValueError("kvm_unavailable_no_software_fallback")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--override", type=Path, action="append", default=[])
    parser.add_argument("--lan-subnet")
    args = parser.parse_args()
    if os.name != "nt":
        raise ValueError("windows_docker_launcher_only")
    docker, wsl = shutil.which("docker"), shutil.which("wsl")
    if docker is None or wsl is None:
        raise ValueError("docker_and_wsl_must_already_be_installed")
    for path in (args.env_file, *args.override):
        if path.is_symlink() or not path.is_file():
            raise ValueError("configuration_must_be_existing_regular_file")
    compose = [docker, "compose", "--env-file", str(args.env_file.resolve()), "-f", str(COMPOSE)]
    for path in args.override:
        compose.extend(["-f", str(path.resolve())])
    model = json.loads(run([*compose, "config", "--format", "json"], 20).stdout)
    address, port, images = publication(model)
    if address != "127.0.0.1":
        if not args.lan_subnet:
            raise ValueError("lan_publication_requires_explicit_subnet")
        shell = shutil.which("powershell.exe")
        if shell is None:
            raise ValueError("windows_powershell_required_for_firewall_verification")
        # VerifyOnly refuses missing/conflicting policy; never creates/relaxes rules.
        run([shell, "-NoProfile", "-NonInteractive", "-File", str(PROJECT / "scripts/configure-docker-lan.ps1"),
             "-LanIP", address, "-Subnet", args.lan_subnet, "-Port", str(port),
             "-PythonPath", sys.executable, "-VerifyOnly"], 45)
    print(json.dumps({"phase": "configuration_verified", "publication": f"{address}:{port}"}), flush=True)
    ensure_engine(docker)
    ensure_kvm(wsl)
    image_ids = [run([docker, "image", "inspect", image, "--format", "{{.Id}}"], 10).stdout.strip() for image in images]
    # Existing services are never recreated by this startup helper. Explicit
    # upgrades/cutovers require a separate idle check and reviewed compose action.
    run([*compose, "up", "-d", "--no-build", "--pull", "never", "--no-recreate",
         "--wait", "--wait-timeout", "300"], 320)
    identifiers = [run([*compose, "ps", "-q", service], 10).stdout.strip() for service in ("android-worker", "api")]
    if any(not identifier or "\n" in identifier for identifier in identifiers):
        raise ValueError("one_container_per_service_required")
    live = json.loads(run([docker, "inspect", *identifiers], 10).stdout)
    if not isinstance(live, list) or len(live) != 2:
        raise ValueError("unexpected_container_inspection")
    verify_running(live[0], live[1], address, port, image_ids)
    print(json.dumps({"phase": "containers_healthy", "android_download_verified": False,
                      "target_requests": 0, "note": "Health does not replace a live Android lease/download acceptance"}))


if __name__ == "__main__":
    try:
        main()
    except subprocess.TimeoutExpired:
        print(json.dumps({"phase": "failed", "reason": "bounded_local_command_timeout"}))
        raise SystemExit(1) from None
    except (OSError, ValueError, KeyError, TypeError) as error:
        reason = str(error)
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,100}", reason):
            reason = "local_startup_precondition_or_command_failed"
        print(json.dumps({"phase": "failed", "reason": reason}))
        raise SystemExit(1) from None
