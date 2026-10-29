"""Run only inside the dedicated fxfetch Ubuntu VM, as root.

This deployment helper installs an offline Android environment. It cannot issue
a production browser lease and has no arbitrary target navigation operation.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import socket
import struct
import subprocess
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path

ROOT = Path("/var/lib/fxfetch-worker")
IMAGE = "redroid/redroid@sha256:11d58a64bfbde2253d1cce81bff409ff58174980222d1bada232d9ef59181191"
NAME = "fxfetch-android"
NETWORK = "fxfetch-android-net"
BRIDGE = "fxfetch-and"
DATA_BYTES = 2 * 1024 * 1024 * 1024


def run(*args: str, timeout: int = 90, stdin: str | None = None) -> str:
    result = subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {result.stderr[-2000:]}")
    return result.stdout.strip()


def validate_vm() -> None:
    if socket.gethostname() != "fxfetch-android-worker" or not Path("/etc/fxfetch-worker-status").is_file():
        raise RuntimeError("This helper is restricted to the dedicated project VM")
    if not ROOT.is_dir() or ROOT.is_symlink():
        raise RuntimeError("Missing dedicated worker state directory")


def wait_for_boot(timeout: float = 90, container_id: str | None = None) -> None:
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        probe = subprocess.run(["docker", "exec", container_id or NAME, "getprop", "sys.boot_completed"], text=True, capture_output=True, timeout=10)
        if probe.returncode == 0 and probe.stdout.strip() == "1":
            return
        time.sleep(1)
    raise RuntimeError("Android boot did not complete within its fixed budget")


def wait_for_cdp(container_id: str, *, timeout: float = 60, expected_version: str | None = None,
                 check: Callable[[], None] | None = None) -> dict[str, object]:
    """Wait for this Chrome's local blank target without navigating/restarting it."""
    if not re.fullmatch(r"[a-f0-9]{64}", container_id) or not 0 < timeout <= 60:
        raise RuntimeError("Invalid bounded CDP readiness request")
    deadline = time.monotonic() + timeout
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    error = "no_response"
    started = time.monotonic()
    while time.monotonic() < deadline:
        if check:
            check()
        if run("docker", "inspect", "--format", "{{.State.Running}}", container_id, timeout=2) != "true":
            raise RuntimeError("Android container stopped during CDP preparation")
        try:
            documents = []
            for path, limit in (("version", 16384), ("list", 65536)):
                if check:
                    check()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("Chrome CDP readiness budget exhausted")
                with opener.open("http://127.0.0.1:9222/json/" + path, timeout=min(2, remaining)) as response:
                    payload = response.read(limit + 1)
                    if len(payload) > limit:
                        raise ValueError("CDP readiness response exceeded its limit")
                    documents.append(json.loads(payload))
                if check:
                    check()
            version, targets = documents
            if not isinstance(version, dict) or not isinstance(targets, list):
                raise ValueError("Unexpected CDP readiness response")
            if expected_version and version.get("Browser") != "Chrome/" + expected_version:
                raise ValueError("CDP browser does not match the accepted version")
            pages = [target for target in targets if isinstance(target, dict) and target.get("type") == "page"]
            if len(pages) != 1 or pages[0].get("url") != "about:blank":
                raise ValueError("CDP requires one blank page before navigation")
            if check:
                check()
            return {"cdp": version, "targets": targets, "ready_seconds": round(time.monotonic() - started, 3)}
        except (OSError, ValueError) as failure:
            error = str(failure)
        if check:
            check()
        time.sleep(min(0.5, max(0, deadline - time.monotonic())))
    raise RuntimeError(f"Chrome CDP unavailable within its budget: {error}")


def firewall(allow_broker: bool = False, deny_established: bool = False) -> None:
    # No global flush: this is a new table scoped to this VM's exact bridge.
    existing = run("nft", "list", "tables")
    replace = "delete table inet fxfetch_android\n" if "table inet fxfetch_android" in existing else ""
    broker = 'iifname "fxfetch-and" ip daddr 10.0.2.2 tcp dport 18767 counter accept;' if allow_broker else ""
    established = '' if deny_established else 'iifname "fxfetch-and" ct direction reply ct state established,related counter accept;'
    rules = f"""table inet fxfetch_android {{
      chain input {{
        type filter hook input priority -200; policy accept;
        {established}
        iifname "fxfetch-and" counter drop;
      }}
      chain forward {{
        type filter hook forward priority -200; policy accept;
        {established}
        {broker}
        iifname "fxfetch-and" counter drop;
      }}
    }}
    """
    run("nft", "-f", "-", stdin=replace + rules)


def namespace_firewall(allow_broker: bool = False, expected_container_id: str | None = None) -> dict[str, str | int]:
    if expected_container_id is not None and not re.fullmatch(r"[a-f0-9]{64}", expected_container_id):
        raise RuntimeError("Invalid immutable container identity")
    container = json.loads(run("docker", "inspect", expected_container_id or NAME, timeout=5))[0]
    container_id = container["Id"]
    if expected_container_id is not None and container_id != expected_container_id:
        raise RuntimeError("Android container identity changed")
    if container["State"]["Running"] is not True:
        raise RuntimeError("Android network namespace is not running")
    pid = int(container["State"]["Pid"])
    if pid <= 1:
        raise RuntimeError("Invalid Android container PID")
    # Keep the original namespace alive even if expiry removes the container.
    # A reused PID must never redirect this operation into a successor lease.
    descriptor = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
    try:
        namespace_path = f"/proc/{os.getpid()}/fd/{descriptor}"
        namespace = str(Path(namespace_path).readlink())
        current = json.loads(run("docker", "inspect", container_id, timeout=5))[0]
        if current["State"]["Running"] is not True or int(current["State"]["Pid"]) != pid:
            raise RuntimeError("Android container exited during namespace setup")
        prefix = ("nsenter", f"--net={namespace_path}", "nft")
        existing = run(*prefix, "list", "tables", timeout=5)
        replace = "delete table inet fxfetch_browser_output\n" if "table inet fxfetch_browser_output" in existing else ""
        broker = 'ip daddr 10.0.2.2 tcp dport 18767 counter accept;' if allow_broker else ""
        rules = f"""table inet fxfetch_browser_output {{
      chain output {{
        type filter hook output priority -150; policy drop;
        ct direction reply ct state established,related counter accept;
        {broker}
        counter drop;
      }}
    }}
    """
        run(*prefix, "-f", "-", stdin=replace + rules, timeout=5)
        return {"container_pid": pid, "network_namespace": namespace, "rules": run(*prefix, "-s", "list", "table", "inet", "fxfetch_browser_output", timeout=5)}
    finally:
        os.close(descriptor)


def prepare(announce: bool = True, require_existing_data: bool = False) -> None:
    if run("docker", "ps", "-aq", "--filter", f"name=^/{NAME}$"):
        raise RuntimeError("Stop and inspect the existing Android container first")
    run("modprobe", "binder_linux")
    binder = Path("/dev/binderfs")
    binder.mkdir(exist_ok=True)
    if not (binder / "binder-control").exists():
        run("mount", "-t", "binder", "binder", str(binder))
    with (binder / "binder-control").open("rb+", buffering=0) as control:
        for name in ("binder", "hwbinder", "vndbinder"):
            if not (binder / name).exists():
                fcntl.ioctl(control, 0xC1086201, struct.pack("=256sII", name.encode(), 0, 0))
    data = ROOT / "data"
    data.mkdir(exist_ok=True)
    disk = ROOT / "android-data.ext4"
    if require_existing_data and (not disk.is_file() or disk.is_symlink()):
        raise RuntimeError("Recovery requires the existing dedicated data image")
    if not disk.exists():
        with disk.open("xb") as output:
            output.truncate(DATA_BYTES)
        run("mkfs.ext4", "-F", "-m", "0", "-L", "fxfetch-android", str(disk), timeout=120)
    if disk.stat().st_size != DATA_BYTES:
        raise RuntimeError("Android data partition has unexpected capacity")
    mounted = subprocess.run(["mountpoint", "-q", str(data)], check=False).returncode == 0
    if not mounted:
        run("mount", "-o", "loop,nodev,nosuid", str(disk), str(data))
    networks = run("docker", "network", "ls", "--format", "{{.Name}}")
    if NETWORK not in networks.splitlines():
        run("docker", "network", "create", "--driver", "bridge", "--subnet", "172.30.0.0/24", "--gateway", "172.30.0.1", "--opt", f"com.docker.network.bridge.name={BRIDGE}", NETWORK)
    firewall(deny_established=True)
    if announce:
        print(json.dumps({"state": "prepared_offline", "data_bytes": DATA_BYTES, "production_enabled": False}))


def start_offline(announce: bool = True, deadline: bool = True, lease_id: str = "offline") -> str:
    if run("docker", "ps", "-aq", "--filter", f"name=^/{NAME}$"):
        raise RuntimeError("Refusing to replace an existing Android container")
    # Guard first; there is no unguarded Android boot interval.
    firewall()
    run("docker", "image", "inspect", IMAGE)
    run("mountpoint", "-q", str(ROOT / "data"))
    container = run("docker", "run", "-d", "--name", NAME, "--label", f"io.fxfetch.lease={lease_id}", "--privileged", "--pull", "never", "--restart", "no", "--cpus", "2", "--memory", "2560m", "--memory-swap", "2560m", "--pids-limit", "4096", "--network", NETWORK, "--ip", "172.30.0.2", "--dns", "127.0.0.1", "--dns-search", ".", "-p", "127.0.0.1:15600:5555", "-v", "/dev/binderfs:/dev/binderfs", "-v", f"{ROOT / 'data'}:/data", IMAGE, "androidboot.use_memfd=true", "androidboot.redroid_gpu_mode=guest", "androidboot.redroid_width=1080", "androidboot.redroid_height=1920", "androidboot.redroid_dpi=420", "androidboot.redroid_net_ndns=1", "androidboot.redroid_net_dns1=127.0.0.1", "ro.setupwizard.mode=DISABLED", timeout=120)
    namespace_firewall(expected_container_id=container)
    # Separate systemd unit survives the SSH connection and host worker.
    if deadline:
        run("systemd-run", "--unit=fxfetch-android-offline-stop", "--on-active=600", "--timer-property=AccuracySec=1", "/usr/bin/docker", "stop", "--time", "5", container)
    if announce:
        print(json.dumps({"state": "booting_offline", "container_id": container, "max_seconds": 600, "production_enabled": False}))
    return container


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "start-offline", "stop", "status"])
    args = parser.parse_args()
    validate_vm()
    if args.action == "prepare":
        prepare()
    elif args.action == "start-offline":
        start_offline()
    elif args.action == "stop":
        run("docker", "stop", "--time", "5", NAME)
        firewall()
    else:
        print(json.dumps({"containers": run("docker", "ps", "-a", "--filter", f"name=^/{NAME}$", "--format", "{{json .}}"), "rules": run("nft", "list", "table", "inet", "fxfetch_android"), "production_enabled": False}))


if __name__ == "__main__":
    main()
