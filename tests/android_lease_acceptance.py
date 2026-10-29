"""Explicit real Android lease confinement, cancellation and recovery acceptance.

Only the test gateway maps capture.test/frame.test to localhost. No target
URL, firewall bypass, package installation or real upstream is accepted.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import shlex
import subprocess
import threading
import time
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from android_browser_acceptance import APK, origin, test_gate

from fxfetch.core.android_worker import PROBE_ID, AndroidLease, AndroidWorker, load_worker_config
from fxfetch.core.browser_capture import capture_browser
from fxfetch.core.limits import Limits


class RecordedWorker(AndroidWorker):
    """Observe the unchanged control call's result; never retry or bypass it."""

    def __init__(self, config, records: list[dict]):
        super().__init__(config)
        self.records = records

    def call(self, action: str, lease_id: str, timeout_seconds: int | None = None) -> dict:
        original = subprocess.run
        started = time.monotonic()

        def recorded(*args, **kwargs):
            try:
                completed = original(*args, **kwargs)
            except subprocess.TimeoutExpired as error:
                self.records.append({
                    "action": action, "timed_out": True,
                    "seconds": round(time.monotonic() - started, 3),
                    "stdout": (error.stdout.decode("utf-8", errors="replace")
                               if isinstance(error.stdout, bytes) else error.stdout or "")[:32768],
                    "stderr": (error.stderr.decode("utf-8", errors="replace")
                               if isinstance(error.stderr, bytes) else error.stderr or "")[-4000:],
                })
                raise
            row = {"action": action, "returncode": completed.returncode,
                   "seconds": round(time.monotonic() - started, 3)}
            if completed.returncode:
                row["stdout"] = completed.stdout[:32768]
                row["stderr"] = completed.stderr[-4000:]
            self.records.append(row)
            return completed

        with patch("fxfetch.core.android_worker.subprocess.run", recorded):
            return super().call(action, lease_id, timeout_seconds)


def guest(worker: AndroidWorker, code: str) -> dict:
    result = subprocess.run(
        [*worker._ssh(), "worker@127.0.0.1", "sudo -n python3 -u -c " + shlex.quote(code)],
        text=True, capture_output=True, timeout=45,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise RuntimeError(f"Synthetic guest probe failed: {result.stderr[-2000:]}")
    return json.loads(result.stdout)


def control_closed() -> bool:
    import socket

    with socket.socket() as control:
        control.settimeout(0.3)
        return control.connect_ex(("127.0.0.1", 19222)) != 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-config-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    config = load_worker_config(args.worker_config_root)
    if config is None:
        raise SystemExit("An independently accepted worker configuration is required")
    control_calls: list[dict] = []
    worker = RecordedWorker(config, control_calls)
    receipt: dict = {"status": "failed", "real_targets": 0, "apk_installed": False, "cases": [],
                     "helper_sha256": config.helper_sha256, "environment_sha256": config.environment_sha256,
                     "control_calls": control_calls}
    all_started = time.monotonic()

    def save() -> None:
        (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")

    try:
        with origin() as server:
            previous_container = None
            for name in ("cancel", "recovery_cookie"):
                started = time.monotonic()
                cancel = threading.Event()
                server.counts.clear()
                server.package_started.clear()
                events = []
                row: dict = {"case": name, "gateway_errors": []}
                receipt["cases"].append(row)
                gate = test_gate(server.server_port, cancel)
                gate.timeout = 240

                def observe_gateway(event: dict, current: dict = row) -> None:
                    current["gateway_errors"].append({
                        "reason_code": event.get("reason_code"),
                        "host": event.get("host") or urlsplit(event.get("url", "")).hostname,
                    })

                gate.on_event = observe_gateway
                with gate as gateway:
                    assert gateway.active and not gateway.armed
                    with AndroidLease(worker, gateway, cancel, 240) as lease:
                        row["lease_id"] = lease.lease_id
                        row["prepare_seconds"] = round(time.monotonic() - started, 3)
                        row["container_id"] = lease.status["container_id"]
                        if previous_container is not None:
                            assert row["container_id"] != previous_container
                        previous_container = row["container_id"]
                        lease.verify_before_launch()
                        assert gateway.armed
                        save()
                        print(json.dumps({"phase": "lease_ready", **row}), flush=True)
                        if name == "cancel":
                            inner = Path(__file__).with_name("android_namespace_probe.py").read_text("utf-8")
                            code = (
                                "import json,subprocess; "
                                "item=json.loads(subprocess.check_output(['docker','inspect','fxfetch-android']))[0]; "
                                f"assert item['Id']=={row['container_id']!r} and item['State']['Running']; "
                                "subprocess.run(['nsenter','-t',str(item['State']['Pid']),'-n','python3','-u','-c',"
                                + repr(inner) + "],check=True,timeout=25)"
                            )
                            receipt["inner_matrix"] = guest(worker, code)
                            outer = Path(__file__).with_name("android_outer_probe.py").read_text("utf-8")
                            gateway.permit_request(lease.lease_id, "http://capture.test/empty", "GET")
                            receipt["outer_matrix"] = guest(worker, outer)
                            assert receipt["inner_matrix"]["status"] == "passed"
                            assert receipt["outer_matrix"]["status"] == "passed"
                            # Added/removed test interfaces and counter changes
                            # must not invalidate the live production proof.
                            lease.verify_before_launch()
                            save()
                            print(json.dumps({"phase": "guards", "inner": receipt["inner_matrix"],
                                              "outer": receipt["outer_matrix"]}), flush=True)
                            server.counts.clear()

                            def stop_stream(current: dict = row, signal: threading.Event = cancel) -> None:
                                if server.package_started.wait(20):
                                    time.sleep(0.15)
                                    current["cancel_at"] = time.monotonic()
                                    signal.set()

                            stopper = threading.Thread(target=stop_stream, daemon=True)
                            stopper.start()
                        capture_started = time.monotonic()
                        result = asyncio.run(capture_browser(
                            "http://capture.test" + ("/stall.apk" if name == "cancel" else "/api-page"),
                            args.output / name, cancel, lease=lease,
                            limits=Limits(chain_timeout=45, read_timeout=10), on_event=events.append,
                        ))
                        row.update(outcome=result.outcome, reason_code=result.reason_code,
                                   capture_seconds=round(time.monotonic() - capture_started, 3),
                                   origin_requests=dict(server.counts),
                                   gateway_connections=gateway.connections,
                                   gateway_errors=[{"reason_code": event.get("reason_code"),
                                                    "host": event.get("host") or urlsplit(event.get("url", "")).hostname}
                                                   for event in gateway.errors])
                        if name == "cancel":
                            stopper.join(1)
                            row["cancel_response_seconds"] = round(time.monotonic() - row.pop("cancel_at"), 3)
                            assert result.reason_code == "cancelled" and not result.artifacts
                            assert row["cancel_response_seconds"] < 5
                        else:
                            assert result.outcome == "downloaded"
                            assert result.artifacts[0].sha256 == hashlib.sha256(APK).hexdigest()
                            assert all(server.counts[path] == 1 for path in ("/api-page", "/api", "/single"))
                        (args.output / f"{name}.json").write_text(
                            json.dumps({"result": asdict(result), "events": events}, indent=2, default=str),
                            encoding="utf-8",
                        )
                    assert not gateway.active and not gateway.armed and control_closed()
                state = worker.call("status", PROBE_ID)
                row["closed_state"] = {key: state.get(key) for key in ("state", "lease_id", "guard_ready", "deployment_verified")}
                assert not state.get("lease_id") and state.get("state") == "idle"
                row["total_seconds"] = round(time.monotonic() - started, 3)
                row["passed"] = True
                save()
                print(json.dumps(row), flush=True)
        receipt["status"] = "passed"
    finally:
        receipt["elapsed_seconds"] = round(time.monotonic() - all_started, 3)
        save()
        print(json.dumps({"status": receipt["status"], "receipt": str(args.output / "receipt.json")}), flush=True)


if __name__ == "__main__":
    main()
