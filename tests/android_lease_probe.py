"""One actual production begin/end diagnostic, with no browser navigation."""

from __future__ import annotations

import argparse
import json
import threading
import time
from pathlib import Path

from android_browser_acceptance import origin, test_gate
from android_lease_acceptance import RecordedWorker

from fxfetch.core.android_worker import AndroidLease, load_worker_config


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-config-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    config = load_worker_config(args.worker_config_root)
    if config is None:
        raise SystemExit("Accepted test worker configuration is required")
    calls: list[dict] = []
    worker = RecordedWorker(config, calls)
    receipt: dict = {"status": "failed", "navigation_count": 0, "control_calls": calls,
                     "helper_sha256": config.helper_sha256, "environment_sha256": config.environment_sha256}
    started = time.monotonic()
    try:
        with origin() as server:
            cancel = threading.Event()
            gate = test_gate(server.server_port, cancel)
            gate.timeout = 240
            with gate as gateway:
                lease = AndroidLease(worker, gateway, cancel, 240)
                receipt["lease_id"] = lease.lease_id
                print(json.dumps({"phase": "begin_requested", "lease_id": lease.lease_id}), flush=True)
                with lease:
                    receipt["prepare_seconds"] = round(time.monotonic() - started, 3)
                    receipt["live_status"] = {key: lease.status.get(key) for key in (
                        "state", "container_id", "guard_ready", "chrome_version", "data_capacity_bytes"
                    )}
                    # Deliberately do not arm: this diagnostic needs only the
                    # control plane. The synthetic gateway remains dormant.
                    assert not gateway.armed and not server.counts
                    print(json.dumps({"phase": "begin_returned", **receipt}), flush=True)
                assert not gateway.active
                receipt["status"] = "passed"
    finally:
        receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        print(json.dumps(receipt), flush=True)


if __name__ == "__main__":
    main()
