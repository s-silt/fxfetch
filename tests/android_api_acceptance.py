"""Opt-in real Android -> service/API -> original file acceptance on local fixtures.

Only the test gateway maps capture.test/frame.test to an in-process server.
No public DNS, real target, APK installation or production service is involved.
Process-tree supervision is covered separately by test_task_supervision.py.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from android_browser_acceptance import origin, test_gate
from fastapi.testclient import TestClient

from fxfetch.config import Settings
from fxfetch.core.android_worker import load_worker_config
from fxfetch.core.browser_workflow import BrowserWorkflow
from fxfetch.core.limits import Limits
from fxfetch.security import password_hash
from fxfetch.service import JobService
from fxfetch.web.api import create_app


class RejectStatic:
    def run(self, *args, **kwargs):
        raise AssertionError("Generic page must enter Android before the first request")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-config-root", type=Path, required=True)
    parser.add_argument("--synthetic-apk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # Unique directory prevents reuse of cookies, records or a partial receipt.
    args.output.mkdir(parents=True, exist_ok=False)
    config = load_worker_config(args.worker_config_root)
    if config is None:
        raise SystemExit("A separately accepted Android worker is required")
    payload = args.synthetic_apk.read_bytes()
    expected_hash = hashlib.sha256(payload).hexdigest()
    assert 10 * 1024**2 <= len(payload) <= 30 * 1024**2
    password = "local-synthetic-api-test"
    limits = replace(Limits(), chain_timeout=240)
    settings = Settings(
        args.output / "service",
        password_hash(password),
        allowed_hosts=("testserver",),
        limits=limits,
    )
    workflow = BrowserWorkflow(RejectStatic(), config, limits)
    service = JobService(settings, workflow=workflow)
    receipt = {"status": "failed", "real_targets": 0, "apk_installed": False}
    gates = []
    started = time.monotonic()
    try:
        with origin() as server:
            server.payload = payload

            def gateway(**kwargs):
                gate = test_gate(server.server_port, kwargs["cancel"])
                gate.timeout = kwargs["timeout"]
                gate.on_event = kwargs.get("on_event")
                gates.append(gate)
                return gate

            with patch("fxfetch.core.browser_workflow.BrowserGateway", gateway):
                with TestClient(create_app(settings, service=service), client=("127.0.0.1", 50000)) as client:
                    headers = {"Origin": "http://testserver"}
                    response = client.post("/api/login", json={"password": password}, headers=headers)
                    assert response.status_code == 200
                    headers["X-CSRF-Token"] = response.json()["csrf_token"]
                    response = client.post(
                        "/api/jobs",
                        json={"url": "http://capture.test/api-page"},
                        headers={**headers, "Idempotency-Key": "android-api-synthetic"},
                    )
                    assert response.status_code == 202, response.text
                    identifier = response.json()["id"]
                    observed_events: set[str] = set()
                    deadline = time.monotonic() + 260
                    while time.monotonic() < deadline:
                        response = client.get(f"/api/jobs/{identifier}")
                        assert response.status_code == 200
                        job = response.json()
                        observed_events.update(
                            row.get("event", "") for row in (job.get("progress") or {}).get("events", [])
                        )
                        if job["state"] == "completed":
                            break
                        time.sleep(0.15)
                    else:
                        raise AssertionError("API synthetic task exceeded its wall-clock budget")
                    receipt.update(
                        outcome=job["outcome"],
                        reason_code=job["result"].get("reason_code"),
                        collector_mode=job["result"].get("collector_mode"),
                        events=sorted(observed_events),
                        request_counts=dict(server.counts),
                    )
                    assert job["outcome"] == "downloaded", receipt
                    assert job["result"]["collector_mode"] == "android_chrome", job
                    assert len(job["artifacts"]) == 1
                    artifact = job["artifacts"][0]
                    response = client.get(f"/api/jobs/{identifier}/artifacts/{artifact['id']}")
                    assert response.status_code == 200
                    assert len(response.content) == len(payload)
                    assert hashlib.sha256(response.content).hexdigest() == expected_hash
                    assert all(server.counts[path] == 1 for path in ("/api-page", "/api", "/single"))
                    assert {"browser_started", "download_started", "file_verified"} <= observed_events
                    request_counts = dict(server.counts)
                    response = client.delete("/api/jobs", headers=headers)
                    assert response.status_code == 200, response.text
                    assert client.get("/api/jobs").json()["jobs"] == []
                    assert dict(server.counts) == request_counts
                    receipt.update(
                        status="passed",
                        sha256=expected_hash,
                        size=len(payload),
                        cleared_without_target_request=True,
                        attachment_downloaded=True,
                        scope="real_android_service_api_injected_test_gateway",
                    )
    finally:
        receipt["gateway_errors"] = [
            {"reason_code": row.get("reason_code"), "host": row.get("host") or urlsplit(row.get("url", "")).hostname}
            for gate in gates for row in gate.errors
        ]
        receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        print(json.dumps(receipt))


if __name__ == "__main__":
    main()
