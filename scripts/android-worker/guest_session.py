"""Root-owned Android session control; JSON stdin never contains a target URL."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import guest_environment as env

STATE = env.ROOT / "session.json"
BASE = env.ROOT / "accepted-base.ext4"
ACCEPTANCE = env.ROOT / "acceptance.json"
SCRIPT = Path("/opt/fxfetch/guest_session.py")
ZERO = "0" * 32
PACKAGE = "com.android.chrome"
LIBRARY = "com.google.android.trichromelibrary"


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text()) if path.is_file() else {}


@contextlib.contextmanager
def lock_state() -> Iterator[None]:
    lock = env.ROOT / "session.lock"
    with lock.open("a+") as stream:
        lock.chmod(0o600)
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def save_state(value: dict[str, object]) -> None:
    """Caller holds lock_state; unique scratch also avoids concurrent replace."""
    temporary = STATE.with_name(f"session.{os.getpid()}.{uuid.uuid4().hex}.new")
    temporary.write_text(json.dumps(value, sort_keys=True) + "\n")
    temporary.chmod(0o600)
    temporary.replace(STATE)


def mark_phase(lease_id: str, phase: str, event: str, started: float) -> None:
    """Bounded private control metadata only: no URL, headers or exception text."""
    directory = env.ROOT / "diagnostics"
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink():
        raise RuntimeError("Unsafe diagnostics directory")
    destination = directory / f"begin-{lease_id}.jsonl"
    if destination.is_symlink() or (destination.exists() and destination.stat().st_size > 32768):
        raise RuntimeError("Unsafe or oversized phase receipt")
    entry = {"phase": phase, "event": event, "elapsed_seconds": round(time.monotonic() - started, 3),
             "utc": datetime.now(UTC).isoformat(), "pid": os.getpid()}
    with destination.open("a") as output:
        destination.chmod(0o600)
        output.write(json.dumps(entry, sort_keys=True) + "\n")


def acceptance() -> dict[str, object]:
    if not ACCEPTANCE.is_file() or not BASE.is_file():
        return {}
    if ACCEPTANCE.is_symlink() or BASE.is_symlink():
        raise RuntimeError("Symlink acceptance/baseline is forbidden")
    info = ACCEPTANCE.stat()
    base_info = BASE.stat()
    if info.st_uid != 0 or info.st_mode & 0o022 or base_info.st_uid != 0 or base_info.st_mode & 0o022:
        raise RuntimeError("Unsafe acceptance receipt ownership/permissions")
    value = read_json(ACCEPTANCE)
    if value.get("accepted") is not True or value.get("image_digest") != env.IMAGE:
        return {}
    if not re.fullmatch(r"[a-f0-9]{64}", str(value.get("chrome_sha256", ""))):
        return {}
    if not re.fullmatch(r"[a-f0-9]{64}", str(value.get("trichrome_sha256", ""))):
        return {}
    if BASE.stat().st_size != env.DATA_BYTES:
        return {}
    environment = Path(env.__file__).resolve()
    if value.get("environment_sha256") != hashlib.sha256(environment.read_bytes()).hexdigest():
        return {}
    return value


def verified_base(receipt: dict[str, object]) -> bool:
    expected = str(receipt.get("base_sha256", ""))
    if not re.fullmatch(r"[a-f0-9]{64}", expected):
        return False
    with BASE.open("rb") as base:
        return hashlib.file_digest(base, "sha256").hexdigest() == expected


def package_section(description: str, heading: str) -> list[str]:
    lines = description.splitlines()
    for index, line in enumerate(lines):
        if line.strip() != heading + ":":
            continue
        indentation = len(line) - len(line.lstrip())
        values = []
        for child in lines[index + 1:]:
            if not child.strip():
                break
            if len(child) - len(child.lstrip()) <= indentation:
                break
            values.append(child.strip())
        return values
    return []


def installed_trichrome(description: str, container_id: str) -> dict[str, object]:
    """Verify the versioned installed provider Chrome actually resolves."""
    result: dict[str, object] = {"trichrome_dependency_present": False}
    declared = [match.group(1) for value in package_section(description, "usesStaticLibraries")
                if (match := re.fullmatch(re.escape(LIBRARY) + r" version:(\d{1,20})", value))]
    if len(declared) != 1:
        return result
    version = declared[0]
    package = LIBRARY + "_" + version
    registered = env.run("docker", "exec", container_id, "dumpsys", "package", package)
    if package_section(registered, "static library") != [f"name:{LIBRARY} version:{version}"]:
        return result
    directories = set(re.findall(r"(?m)^\s*codePath=(/data/app/[^\s]+)$", registered))
    if len(directories) != 1:
        return result
    directory = directories.pop()
    if any(part in {".", ".."} for part in directory.split("/")):
        return result
    actual_path = directory + "/base.apk"
    if actual_path not in package_section(description, "usesLibraryFiles"):
        return result
    installed_hash = env.run("docker", "exec", container_id, "sha256sum", actual_path).split()[0]
    if not re.fullmatch(r"[a-f0-9]{64}", installed_hash):
        raise RuntimeError("Invalid installed library hash response")
    result.update({"trichrome_dependency_present": True, "trichrome_package": package,
                   "trichrome_library_version": version, "trichrome_installed_sha256": installed_hash})
    return result


def inspect_status(lease_id: str) -> dict[str, object]:
    state = read_json(STATE)
    active_id = str(state.get("lease_id", ""))
    if lease_id != ZERO and active_id and active_id != lease_id:
        raise RuntimeError("lease_id_mismatch")
    receipt = acceptance()
    result: dict[str, object] = {
        "state": "idle", "lease_id": active_id or None,
        "expires_at": state.get("expires_at"), "guard_ready": False,
        "deployment_ready": False, "deployment_verified": False, "cdp_endpoint": "http://127.0.0.1:9222",
        "data_capacity_bytes": None, "mount_source": None,
        "image_digest": env.IMAGE, "chrome_package": PACKAGE,
        "chrome_version": receipt.get("chrome_version"), "chrome_source_sha256": receipt.get("chrome_sha256"),
        "trichrome_source_sha256": receipt.get("trichrome_sha256"),
        "helper_sha256": hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
        "environment_sha256": hashlib.sha256(Path(env.__file__).read_bytes()).hexdigest(),
    }
    rules = env.run("nft", "-s", "list", "table", "inet", "fxfetch_android")
    result["firewall_sha256"] = hashlib.sha256(rules.encode()).hexdigest()
    mount = json.loads(env.run("findmnt", "--json", "--target", str(env.ROOT / "data")))
    filesystems = mount.get("filesystems", [])
    mount_ok = bool(filesystems and filesystems[0].get("target") == str(env.ROOT / "data"))
    if mount_ok:
        source = str(filesystems[0]["source"])
        result["mount_source"] = source
        result["data_capacity_bytes"] = int(env.run("blockdev", "--getsize64", source))
    inspected = subprocess.run(["docker", "inspect", env.NAME], text=True, capture_output=True, timeout=20)
    running = False
    if inspected.returncode == 0:
        container = json.loads(inspected.stdout)[0]
        running = container["State"]["Running"] is True
        result["container_id"] = container["Id"]
        result["container_image_id"] = container["Image"]
        if running:
            result["state"] = "running"
            pid = int(container["State"]["Pid"])
            result["container_pid"] = pid
            result["network_namespace"] = str(Path(f"/proc/{pid}/ns/net").readlink())
            inner_rules = env.run("nsenter", "-t", str(pid), "-n", "nft", "-s", "list", "table", "inet", "fxfetch_browser_output")
            result["namespace_firewall_sha256"] = hashlib.sha256(inner_rules.encode()).hexdigest()
            package_result = subprocess.run(["docker", "exec", env.NAME, "pm", "path", PACKAGE], text=True, capture_output=True, timeout=30)
            paths = package_result.stdout.splitlines() if package_result.returncode == 0 else []
            if len(paths) == 1 and paths[0].startswith("package:/data/app/") and paths[0].endswith("/base.apk"):
                actual_sha = env.run("docker", "exec", env.NAME, "sha256sum", paths[0][8:]).split()[0]
                result["chrome_installed_sha256"] = actual_sha
            description = env.run("docker", "exec", env.NAME, "dumpsys", "package", PACKAGE)
            match = re.search(r"versionName=([^\s]+)", description)
            result["chrome_version"] = match.group(1) if match else None
            version = re.search(r"versionCode=(\d+)", description)
            result["chrome_version_code"] = version.group(1) if version else None
            result.update(installed_trichrome(description, container["Id"]))
    unexpired = isinstance(state.get("expires_at"), (int, float)) and float(state["expires_at"]) > time.time()
    expected_firewall = state.get("firewall_sha256")
    timer = subprocess.run(["systemctl", "is-active", f"fxfetch-session-{active_id}.timer"], text=True, capture_output=True, timeout=10) if active_id else None
    result["deadline_active"] = bool(timer and timer.returncode == 0 and timer.stdout.strip() == "active")
    image_info = json.loads(env.run("docker", "image", "inspect", env.IMAGE))[0] if receipt else {}
    checks = {
        "accepted_receipt": bool(receipt), "running": running, "mount": mount_ok,
        "unexpired": unexpired, "lease_present": bool(active_id), "deadline_active": bool(result["deadline_active"]),
        "capacity": result["data_capacity_bytes"] == env.DATA_BYTES,
        "chrome_hash": result.get("chrome_installed_sha256") == receipt.get("chrome_sha256"),
        "trichrome_hash": result.get("trichrome_installed_sha256") == receipt.get("trichrome_sha256"),
        "trichrome_dependency": result.get("trichrome_dependency_present") is True,
        "outer_firewall": result["firewall_sha256"] == expected_firewall,
        "namespace_firewall": result.get("namespace_firewall_sha256") == state.get("namespace_firewall_sha256"),
        "network_namespace": result.get("network_namespace") == state.get("network_namespace"),
        "image_identity": result.get("container_image_id") == image_info.get("Id"),
        "container_identity": result.get("container_id") == state.get("container_id"),
    }
    result["guard_checks"] = checks
    result["guard_ready"] = all(checks.values())
    if inspected.returncode == 0 and not running:
        result["state"] = "stopped_unreleased"
    if inspected.returncode != 0 and active_id:
        result["state"] = str(state.get("state", "unreleased"))
    if receipt and inspected.returncode != 0 and not active_id:
        base_valid = verified_base(receipt)
        asset = env.ROOT / "assets/Chrome.apk"
        with asset.open("rb") as chrome:
            source_valid = hashlib.file_digest(chrome, "sha256").hexdigest() == receipt.get("chrome_sha256")
        with (env.ROOT / "assets/TrichromeLibrary.apk").open("rb") as library:
            library_valid = hashlib.file_digest(library, "sha256").hexdigest() == receipt.get("trichrome_sha256")
        result["base_sha256_verified"] = base_valid
        result["chrome_asset_verified"] = source_valid
        result["trichrome_asset_verified"] = library_valid
        result["image_id"] = image_info["Id"]
        verified = bool(base_valid and source_valid and library_valid and mount_ok and result["data_capacity_bytes"] == env.DATA_BYTES
                        and result["firewall_sha256"] == receipt.get("deny_firewall_sha256")
                        and image_info["Id"] == receipt.get("image_id"))
        result["deployment_verified"] = verified
        result["deployment_ready"] = verified
    return result


def end(lease_id: str) -> dict[str, object]:
    if not re.fullmatch(r"[a-f0-9]{32}", lease_id) or lease_id == ZERO:
        raise RuntimeError("invalid_lease_id")
    staging = env.ROOT / f"session-{lease_id}.ext4"
    guard_error: Exception | None = None
    with lock_state():
        state = read_json(STATE)
        container_id = env.run("docker", "ps", "-aq", "--no-trunc", "--filter", f"name=^/{env.NAME}$", "--filter", f"label=io.fxfetch.lease={lease_id}")
        if state.get("lease_id") != lease_id and not container_id:
            staging.unlink(missing_ok=True)
            return {"state": "ended", "lease_id": lease_id, "already_ended": True, "guard_ready": False}
        if state.get("lease_id") == lease_id:
            try:
                env.firewall(deny_established=True)
            except (OSError, RuntimeError, subprocess.SubprocessError) as failure:
                guard_error = failure
            save_state({**state, "state": "ending"})
    # Use the immutable captured ID. Concurrent expiry must never stop a later
    # container that happens to reuse NAME, or overwrite the later lease state.
    if container_id:
        for args in (("docker", "stop", "--time", "5", container_id), ("docker", "rm", container_id)):
            action = subprocess.run(args, text=True, capture_output=True, timeout=30)
            if action.returncode:
                still_present = subprocess.run(["docker", "inspect", container_id], capture_output=True, timeout=10)
                if still_present.returncode == 0:
                    raise RuntimeError(action.stderr[-2000:])
    with lock_state():
        # Exact lease pathname only; unlink never follows a symlink target.
        # An old copying process retains its own inode until its next check.
        staging.unlink(missing_ok=True)
        if read_json(STATE).get("lease_id") == lease_id:
            save_state({"state": "ended", "previous_lease_id": lease_id, "ended_at": time.time()})
    if guard_error is not None:
        raise RuntimeError(f"Container stopped, but firewall close failed: {guard_error}")
    return {"state": "ended", "lease_id": lease_id, "guard_ready": False}


def begin(lease_id: str, duration: int) -> dict[str, object]:
    started = time.monotonic()
    expires = time.time() + duration
    mark_phase(lease_id, "base_metadata", "start", started)
    receipt = acceptance()
    expected_base = str(receipt.get("base_sha256", ""))
    if not receipt or not re.fullmatch(r"[a-f0-9]{64}", expected_base):
        raise RuntimeError("guard_not_accepted")
    mark_phase(lease_id, "base_metadata", "complete", started)
    with lock_state():
        previous = read_json(STATE)
        if previous.get("lease_id") or env.run("docker", "ps", "-aq", "--filter", f"name=^/{env.NAME}$"):
            raise RuntimeError("Existing Android session/container requires an explicit end")
        env.firewall(deny_established=True)
        save_state({"lease_id": lease_id, "state": "starting", "expires_at": expires})
    remaining = max(1, int(expires - time.time()))
    env.run("systemd-run", f"--unit=fxfetch-session-{lease_id}", f"--on-active={remaining}", "--timer-property=AccuracySec=1", "/usr/bin/python3", str(SCRIPT), "expire", "--lease-id", lease_id)

    def ensure_current() -> None:
        current = read_json(STATE)
        if time.time() >= expires or current.get("lease_id") != lease_id or current.get("state") != "starting":
            raise RuntimeError("session_expired_during_preparation")

    def control_step(*args: str, timeout: int = 5) -> str:
        # A fixed ADB endpoint is shared by sequential leases. Serialize only
        # bounded commands, checking ownership on both sides of every wait.
        with lock_state():
            ensure_current()
            result = env.run(*args, timeout=timeout)
            ensure_current()
            return result

    staging = env.ROOT / f"session-{lease_id}.ext4"
    try:
        active = env.ROOT / "android-data.ext4"
        mark_phase(lease_id, "copy", "start", started)
        copied = 0
        base_hash = hashlib.sha256()
        with BASE.open("rb") as source, staging.open("xb") as destination:
            staging.chmod(0o600)
            while chunk := source.read(1024 * 1024):
                ensure_current()
                copied += len(chunk)
                if copied > env.DATA_BYTES:
                    raise RuntimeError("baseline_copy_capacity_mismatch")
                base_hash.update(chunk)
                destination.write(chunk)
            if copied != env.DATA_BYTES or base_hash.hexdigest() != expected_base:
                raise RuntimeError("baseline_copy_verification_failed")
            destination.flush()
            os.fsync(destination.fileno())
        mark_phase(lease_id, "copy", "complete", started)
        # Expired preparation can only affect its own staging file. A later
        # lease cannot inherit a partial copy or be overwritten by an old one.
        with lock_state():
            ensure_current()
            mark_phase(lease_id, "mount", "start", started)
            env.run("umount", str(env.ROOT / "data"))
            staging.replace(active)
            env.run("mount", "-o", "loop,nodev,nosuid", str(active), str(env.ROOT / "data"))
            mark_phase(lease_id, "mount", "complete", started)
            ensure_current()
            mark_phase(lease_id, "start", "start", started)
            container_id = env.start_offline(announce=False, deadline=False, lease_id=lease_id)
            if not isinstance(container_id, str) or not re.fullmatch(r"[a-f0-9]{64}", container_id):
                raise RuntimeError("Invalid immutable container identity")
            ensure_current()
            mark_phase(lease_id, "start", "complete", started)
        mark_phase(lease_id, "boot", "start", started)
        env.wait_for_boot(min(120, max(1, expires - time.time())), container_id=container_id)
        mark_phase(lease_id, "boot", "complete", started)
        mark_phase(lease_id, "adb", "start", started)
        control_step("adb", "connect", "127.0.0.1:15600")
        control_step("adb", "-s", "127.0.0.1:15600", "forward", "tcp:9222", "localabstract:chrome_devtools_remote")
        control_step("docker", "exec", container_id, "am", "force-stop", PACKAGE)
        with lock_state():
            ensure_current()
            namespace = env.namespace_firewall(allow_broker=True, expected_container_id=container_id)
            ensure_current()
        control_step("docker", "exec", container_id, "am", "start", "-a", "android.intent.action.VIEW", "-d", "about:blank", "-p", PACKAGE, timeout=15)
        mark_phase(lease_id, "adb", "complete", started)
        ensure_current()
        mark_phase(lease_id, "cdp", "start", started)
        env.wait_for_cdp(container_id, timeout=min(60, expires - time.time()),
                         expected_version=str(receipt.get("chrome_version", "")), check=ensure_current)
        mark_phase(lease_id, "cdp", "complete", started)
        with lock_state():
            ensure_current()
            env.firewall(allow_broker=True)
            rules = env.run("nft", "-s", "list", "table", "inet", "fxfetch_android")
            ensure_current()
            save_state({"lease_id": lease_id, "state": "running", "expires_at": expires, "container_id": container_id, "firewall_sha256": hashlib.sha256(rules.encode()).hexdigest(), "namespace_firewall_sha256": hashlib.sha256(str(namespace["rules"]).encode()).hexdigest(), "network_namespace": namespace["network_namespace"]})
        mark_phase(lease_id, "liveproof", "start", started)
        value = inspect_status(lease_id)
        if value["guard_ready"] is not True:
            diagnostic = env.ROOT / "diagnostics" / f"guard-{lease_id}.json"
            if diagnostic.is_symlink():
                raise RuntimeError("Unsafe guard diagnostic path")
            diagnostic.write_text(json.dumps(value, sort_keys=True) + "\n")
            diagnostic.chmod(0o600)
            failed = ",".join(key for key, passed in value.get("guard_checks", {}).items() if not passed)
            raise RuntimeError("live_guard_verification_failed:" + failed)
        mark_phase(lease_id, "liveproof", "complete", started)
        mark_phase(lease_id, "ready", "complete", started)
        return value
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        try:
            mark_phase(lease_id, "begin", "failed", started)
        finally:
            end(lease_id)
        raise
    finally:
        if staging.exists():
            staging.unlink()


def recover_idle() -> dict[str, object]:
    """Restore ephemeral VM guards without booting Android or ending live work."""
    with lock_state():
        state = read_json(STATE)
        active = state.get("lease_id")
        if active:
            expiry = state.get("expires_at")
            if not isinstance(expiry, (int, float)) or expiry > time.time():
                raise RuntimeError("Recovery refuses an active or unbounded session")
            if not isinstance(active, str) or not re.fullmatch(r"[a-f0-9]{32}", active) or active == ZERO:
                raise RuntimeError("Invalid expired session identity")
    # end captures its own labelled immutable ID; it cannot remove a later lease.
    if active:
        end(active)
    with lock_state():
        if read_json(STATE).get("lease_id"):
            raise RuntimeError("Session changed during recovery")
        if env.run("docker", "ps", "-aq", "--filter", f"name=^/{env.NAME}$"):
            raise RuntimeError("Unreleased Android container requires explicit inspection")
        env.prepare(announce=False, require_existing_data=True)
        return inspect_status(ZERO)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["begin", "status", "end", "expire", "recover-idle"])
    parser.add_argument("--lease-id", help=argparse.SUPPRESS)
    args = parser.parse_args()
    env.validate_vm()
    request = {"lease_id": args.lease_id} if args.action == "expire" else json.loads(sys.stdin.buffer.read(4097))
    if not isinstance(request, dict) or set(request) - {"lease_id", "timeout_seconds"}:
        raise RuntimeError("invalid_control_request")
    lease_id = request.get("lease_id")
    if not isinstance(lease_id, str) or not re.fullmatch(r"[a-f0-9]{32}", lease_id):
        raise RuntimeError("invalid_lease_id")
    if args.action not in {"status", "recover-idle"} and lease_id == ZERO:
        raise RuntimeError("zero_id_only_allowed_for_readiness")
    if args.action == "begin":
        duration = request.get("timeout_seconds")
        if type(duration) is not int or not 1 <= duration <= 600:
            raise RuntimeError("invalid_timeout")
        result = begin(lease_id, duration)
    elif args.action == "status":
        result = inspect_status(lease_id)
    elif args.action == "recover-idle":
        if lease_id != ZERO or set(request) != {"lease_id"}:
            raise RuntimeError("invalid_recovery_request")
        result = recover_idle()
    else:
        if args.action == "expire":
            # Kill the exact lease before waiting for state cleanup locks.
            own = env.run("docker", "ps", "-q", "--no-trunc", "--filter", f"name=^/{env.NAME}$", "--filter", f"label=io.fxfetch.lease={lease_id}")
            if own:
                subprocess.run(["docker", "kill", own], check=False, capture_output=True, timeout=10)
        result = end(lease_id)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(json.dumps({"state": "failed", "guard_ready": False, "reason": str(error)}))
        sys.exit(1)
