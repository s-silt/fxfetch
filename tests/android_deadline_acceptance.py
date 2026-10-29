"""Opt-in real guest deadline acceptance on about:blank, with no navigation."""

from __future__ import annotations

import argparse
import json
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from android_browser_acceptance import origin, test_gate
from android_lease_acceptance import RecordedWorker, control_closed, guest

from fxfetch.core.android_worker import PROBE_ID, AndroidLease, load_worker_config
from fxfetch.core.errors import FxfetchError


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-config-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration", type=int, choices=(90, 120, 150, 210, 240), default=210)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    config = load_worker_config(args.worker_config_root)
    if config is None:
        raise SystemExit("An independently accepted worker configuration is required")
    control_calls: list[dict] = []
    worker = RecordedWorker(config, control_calls)
    receipt: dict = {"status": "failed", "navigation_count": 0, "duration": args.duration,
                     "helper_sha256": config.helper_sha256, "environment_sha256": config.environment_sha256,
                     "control_calls": control_calls}
    started = time.monotonic()
    try:
        with origin() as server:
            cancel = threading.Event()
            gate = test_gate(server.server_port, cancel)
            gate.timeout = args.duration + 90
            with gate as gateway:
                prepared = AndroidLease(worker, gateway, cancel, args.duration)
                receipt["lease_id"] = prepared.lease_id
                print(json.dumps({"phase": "begin_requested", "lease_id": prepared.lease_id}), flush=True)
                with prepared as lease:
                    lease.verify_before_launch()
                    receipt.update(lease_id=lease.lease_id, container_id=lease.status["container_id"],
                                   expires_at=lease.status["expires_at"],
                                   preparation_seconds=round(time.monotonic() - started, 3))
                    print(json.dumps({"phase": "waiting_for_native_expiry", **receipt}), flush=True)
                    # The host does not cancel, close or send end while waiting.
                    # Only the independent guest systemd deadline can stop it.
                    while time.time() <= receipt["expires_at"] + 1:
                        time.sleep(min(2, max(0.1, receipt["expires_at"] + 1 - time.time())))
                    end = time.monotonic() + 45
                    errors = []
                    while True:
                        try:
                            status = worker.call("status", PROBE_ID)
                            if not status.get("lease_id") and status.get("state") == "idle":
                                break
                        except FxfetchError as error:
                            errors.append(error.code)
                        if time.monotonic() >= end:
                            raise AssertionError("Independent guest deadline did not end the lease")
                        time.sleep(1)
                    assert status.get("guard_ready") is False
                    assert not status.get("container_id")
                    receipt["post_expiry_status"] = {
                        key: status.get(key) for key in ("state", "lease_id", "container_id", "guard_ready")
                    }
                    # Capture guest evidence before the host sends any end.
                    # Only this lease's timer/unit and immutable CID are read.
                    observation = guest(worker, f'''import json, subprocess
from pathlib import Path
state=json.loads(Path('/var/lib/fxfetch-worker/session.json').read_text())
journal=subprocess.run(['journalctl','-u','fxfetch-session-{lease.lease_id}.service','--no-pager','-o','cat'],text=True,capture_output=True,timeout=10)
container=subprocess.run(['docker','ps','-aq','--no-trunc','--filter','id={receipt["container_id"]}'],text=True,capture_output=True,timeout=10)
print(json.dumps({{'state':state,'journal_returncode':journal.returncode,'journal':journal.stdout[-16000:],'container_query_returncode':container.returncode,'container_ids':container.stdout.strip()}}))
''')
                    receipt["native_expiry_evidence"] = observation
                    assert observation["state"].get("previous_lease_id") == lease.lease_id
                    assert observation["state"].get("ended_at", 0) >= receipt["expires_at"] - 2
                    assert observation["container_query_returncode"] == 0 and not observation["container_ids"]
                    assert observation["journal_returncode"] == 0
                    assert lease.lease_id in observation["journal"] and '"state": "ended"' in observation["journal"]
                    receipt["control_actions_before_expired_proof"] = [row["action"] for row in control_calls]
                    assert "end" not in receipt["control_actions_before_expired_proof"]
                    receipt["transient_status_errors"] = errors
                    try:
                        lease.verify_before_launch()
                    except FxfetchError as error:
                        receipt["expired_lease_rejected"] = error.code
                    else:
                        raise AssertionError("An expired lease still passed its live proof")
                    assert not gateway.active and not gateway.armed
                    assert not server.counts
                    receipt["gateway_connections"] = gateway.connections
                    receipt["gateway_errors"] = [
                        {"reason_code": event.get("reason_code"),
                         "host": event.get("host") or urlsplit(event.get("url", "")).hostname}
                        for event in gateway.errors
                    ]
                    receipt["status"] = "passed"
                assert control_closed() and not gateway.active and not gateway.armed
                receipt["host_cleanup"] = {"cdp_tunnel_closed": True, "gateway_active": False, "gateway_armed": False}
    finally:
        receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        print(json.dumps(receipt), flush=True)


if __name__ == "__main__":
    main()
