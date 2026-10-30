"""Test-only bootstrap for the real task_worker inside its process limits.

The transport substitution is a fixed synthetic origin; HTTP preflight returns
an explicit synthetic browser-required result without resolving a target. Production code
never imports this module. Android control calls execute unchanged and are only
observed so a failed cold start retains its original control error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import runpy
import sys
import time
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from android_lease_acceptance import RecordedWorker

from fxfetch.core.browser_gateway import BrowserGateway
from fxfetch.core.errors import FxfetchError
from fxfetch.core.workflow import WorkflowResult


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin-port", type=int, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("request", type=Path)
    parser.add_argument("result", type=Path)
    args = parser.parse_args()
    if os.name not in {"nt", "posix"} or not 1 <= args.origin_port <= 65535:
        raise SystemExit("This acceptance requires a supported host and a local synthetic origin")
    request = json.loads(args.request.read_text(encoding="utf-8"))
    if (
        request.get("operation") != "collect"
        or request.get("url") != "http://capture.test/api-page"
        or request.get("proxy_host")
        or request.get("limits", {}).get("chain_timeout") != 600
        or not re.fullmatch(r"[a-f0-9]{32}", str(request.get("android_lease_id", "")))
    ):
        raise SystemExit("Only the fixed supervisor-owned synthetic collection is allowed")
    state: dict = {
        "status": "running", "pid": os.getpid(), "lease_id": request["android_lease_id"],
        "worker_module": "fxfetch.task_worker", "control_calls": [],
        "gateway_errors": [], "gateway_closed": False, "transport": "synthetic_loopback_only",
    }
    gates: list[BrowserGateway] = []

    def save() -> None:
        pending = args.receipt.with_suffix(".pending")
        pending.write_text(json.dumps(state, indent=2), encoding="utf-8")
        pending.replace(args.receipt)

    class ObservedWorker(RecordedWorker):
        def __init__(self, config):
            super().__init__(config, state["control_calls"])

        def call(self, action, lease_id, timeout_seconds=None):
            state["current_action"] = action
            state["current_action_at"] = time.time()
            save()
            try:
                value = super().call(action, lease_id, timeout_seconds)
                state["last_control_state"] = value.get("state")
                return value
            except FxfetchError as error:
                state.setdefault("control_errors", []).append({
                    "action": action, "reason_code": error.code,
                    "cause_type": type(error.__cause__).__name__ if error.__cause__ else None,
                    "cause": str(error.__cause__)[:2000] if error.__cause__ else None,
                })
                raise
            finally:
                state["current_action"] = None
                save()

    class SyntheticGateway(BrowserGateway):
        def _destination(self, url: str) -> tuple[str, int]:
            parsed = urlsplit(url)
            if (
                parsed.scheme != "http" or parsed.hostname not in {"capture.test", "frame.test"}
                or parsed.port not in {None, 80}
            ):
                raise FxfetchError("synthetic_destination_denied", "No upstream connection is allowed")
            self._check()
            return "127.0.0.1", args.origin_port

    def gateway(**kwargs):
        # Preserve every production budget and the central permit enforcement.
        value = SyntheticGateway(**kwargs)
        gates.append(value)
        return value

    def synthetic_preflight(self, url, output_dir, cancel, on_event=None):
        assert url == "http://capture.test/api-page"
        state["synthetic_http_preflight_calls"] = state.get("synthetic_http_preflight_calls", 0) + 1
        save()
        return WorkflowResult("failed", "browser_required", "partial")

    save()
    sys.argv = ["fxfetch.task_worker", str(args.request), str(args.result)]
    try:
        with (
            patch("fxfetch.core.browser_workflow.BrowserGateway", gateway),
            patch("fxfetch.core.browser_workflow.AndroidWorker", ObservedWorker),
            patch("fxfetch.core.workflow.Workflow.run", synthetic_preflight),
        ):
            try:
                runpy.run_module("fxfetch.task_worker", run_name="__main__")
            except SystemExit as exit_status:
                if exit_status.code not in (None, 0):
                    raise
        state["status"] = "worker_returned"
    finally:
        state["gateway_errors"] = [
            {"reason_code": row.get("reason_code"),
             "host": row.get("host") or urlsplit(row.get("url", "")).hostname}
            for value in gates for row in value.errors
        ]
        state["gateway_connections"] = sum(value.connections for value in gates)
        state["gateway_count"] = len(gates)
        state["gateway_closed"] = bool(gates) and all(not value.active and not value.armed for value in gates)
        save()


if __name__ == "__main__":
    main()
