"""Resume only the registered project VM and restore its idle browser guards."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from pathlib import Path

from fxfetch.core.android_worker import PROBE_ID, AndroidWorker, load_worker_config
from fxfetch.core.errors import FxfetchError

PROJECT = Path(__file__).resolve().parents[2]
STATE = PROJECT / ".runtime" / "android-worker"
VBOX = Path(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")
NAME = "fxfetch-android-worker"


def fields(text: str) -> dict[str, str]:
    return dict(re.findall(r'^([A-Za-z][A-Za-z0-9_]*)="([^"\r\n]*)"$', text, re.MULTILINE))


def expected_identity(state: Path) -> tuple[str, Path]:
    receipt = json.loads((state / "vm-prepared.json").read_text(encoding="utf-8"))
    saved = fields(receipt["vm_uuid"])
    identifier = saved.get("UUID", "")
    if receipt.get("vm_name") != NAME or not re.fullmatch(r"[0-9a-fA-F-]{36}", identifier):
        raise ValueError("untrusted_vm_receipt")
    config = Path(saved["CfgFile"])
    # VBox machine-readable strings escape Windows path separators.
    config = Path(str(config).replace("\\\\", "\\")).resolve()
    if config != (state / NAME / (NAME + ".vbox")).resolve():
        raise ValueError("vm_receipt_path_outside_project")
    return identifier, config


def verify_live_identity(saved: tuple[str, Path], output: str) -> str:
    current = fields(output)
    if current.get("UUID", "").lower() != saved[0].lower() or current.get("name") != NAME:
        raise ValueError("registered_vm_identity_changed")
    current_path = Path(current.get("CfgFile", "").replace("\\\\", "\\")).resolve()
    if current_path != saved[1]:
        raise ValueError("registered_vm_path_changed")
    state = current.get("VMState", "unknown")
    if state not in {"running", "poweroff", "aborted", "saved"}:
        raise ValueError("vm_state_requires_attention")
    return state


def run(arguments: list[str], timeout: float) -> str:
    completed = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if completed.returncode:
        raise RuntimeError("local_control_command_failed")
    return completed.stdout


def resume(service_root: Path) -> dict[str, object]:
    config = load_worker_config(service_root)
    if config is None:
        return {"enabled": False, "reason_code": "browser_worker_not_configured"}
    if not VBOX.is_file():
        raise FxfetchError("browser_worker_unavailable", "VirtualBox is unavailable")
    identity = expected_identity(STATE)
    state = verify_live_identity(
        identity, run([str(VBOX), "showvminfo", identity[0], "--machinereadable"], 10)
    )
    if state != "running":
        print(json.dumps({"phase": "starting_project_vm", "previous_state": state}), flush=True)
        run([str(VBOX), "startvm", identity[0], "--type", "headless"], 45)
    worker = AndroidWorker(config)
    deadline = time.monotonic() + 90
    while True:
        try:
            run([*worker._ssh(), "worker@127.0.0.1", "true"], 8)
            break
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            if time.monotonic() >= deadline:
                raise FxfetchError(
                    "browser_worker_unavailable", "Project VM SSH did not become ready"
                ) from None
            time.sleep(0.5)
    print(json.dumps({"phase": "restoring_idle_guards"}), flush=True)
    status = worker.call("recover-idle", PROBE_ID)
    worker.validate(status, readiness=True)
    return {
        "enabled": True,
        "mode": "android_chrome",
        "version": status.get("chrome_version"),
        "vm_uuid": identity[0],
        "navigation_started": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service-root", type=Path, default=PROJECT / ".runtime/service")
    arguments = parser.parse_args()
    try:
        print(json.dumps(resume(arguments.service_root.resolve())))
        return 0
    except (FxfetchError, OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(
            json.dumps(
                {
                    "enabled": False,
                    "reason_code": error.code
                    if isinstance(error, FxfetchError)
                    else "browser_recovery_failed",
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
