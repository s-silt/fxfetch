"""Explicit bounded process -> real task_worker -> Android -> API acceptance.

This does not inject a Workflow. The child executes the production task_worker
module with a test-only gateway mapping capture.test/frame.test to localhost.
No real target, public DNS, APK installation or production service is involved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import sys
import time
from pathlib import Path
from unittest.mock import patch

from android_browser_acceptance import origin
from fastapi.testclient import TestClient

from fxfetch.config import Settings
from fxfetch.core.android_worker import PROBE_ID, AndroidWorker, load_worker_config
from fxfetch.core.errors import FxfetchError
from fxfetch.core.limits import Limits
from fxfetch.core.process_limits import run_limited
from fxfetch.core.task_evidence_verify import verify_task_archive
from fxfetch.security import password_hash
from fxfetch.service import JobService
from fxfetch.web.api import create_app


def port_closed(port: int) -> bool:
    with socket.socket() as connection:
        connection.settimeout(0.3)
        return connection.connect_ex(("127.0.0.1", port)) != 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-config-root", type=Path, required=True)
    parser.add_argument("--synthetic-apk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.name not in {"nt", "posix"}:
        raise SystemExit("A supported process-limit implementation is required")
    expected_limit = "windows_job_memory" if os.name == "nt" else "posix_rlimit_as"
    config = load_worker_config(args.worker_config_root)
    if config is None:
        raise SystemExit("An independently accepted Android worker configuration is required")
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    payload = args.synthetic_apk.read_bytes()
    assert 10 * 1024**2 <= len(payload) <= 30 * 1024**2
    expected_hash = hashlib.sha256(payload).hexdigest()
    settings = Settings(args.output / "service", password_hash("isolated-synthetic-api"),
                        allowed_hosts=("testserver",), limits=Limits())
    service = JobService(settings)
    assert service._isolated_collect
    # References the existing private key; it does not duplicate key material.
    (settings.root / "android-worker.json").write_bytes(
        (args.worker_config_root / "android-worker.json").read_bytes()
    )
    child_receipt = args.output / "child-receipt.json"
    receipt: dict = {
        "status": "failed", "real_targets": 0, "apk_installed": False,
        "scope": expected_limit + "_real_task_worker_android_api_synthetic_transport",
        "workflow_injected": False, "chain_timeout": 600, "memory_bytes": 2 * 1024**3,
        "expected_size": len(payload), "expected_sha256": expected_hash,
        "process_runs": [], "helper_sha256": config.helper_sha256,
        "environment_sha256": config.environment_sha256,
    }
    started = time.monotonic()

    def save() -> None:
        receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")

    try:
        assert port_closed(18767) and port_closed(19222), "Another session owns the fixed worker ports"
        with origin() as server:
            server.payload = payload

            def observed_runner(command, **options):
                assert command[:3] == [sys.executable, "-m", "fxfetch.task_worker"]
                assert len(command) == 5 and not receipt["process_runs"]
                assert options["memory_bytes"] == 2 * 1024**3
                assert 590 < options["timeout"] <= 600
                request_path, result_path = map(Path, command[3:])
                request = json.loads(request_path.read_text(encoding="utf-8"))
                lease_id = request.get("android_lease_id", "")
                assert re.fullmatch(r"[a-f0-9]{32}", lease_id) and lease_id != PROBE_ID
                assert request["url"] == "http://capture.test/api-page"
                assert request["limits"]["chain_timeout"] == 600
                receipt["lease_id"] = lease_id
                receipt["worker_request"] = str(request_path.relative_to(args.output))
                row = {"limit_method": "pending", "timeout": options["timeout"]}
                receipt["process_runs"].append(row)
                save()
                print(json.dumps({"phase": "isolated_worker_started", "lease_id": lease_id}), flush=True)
                # Only the bootstrap/fixture changes: the real runner, budgets,
                # supervisor lease, request and task_worker code are retained.
                execution = run_limited([
                    sys.executable, str(Path(__file__).with_name("android_isolated_worker_fixture.py")),
                    "--origin-port", str(server.server_port), "--receipt", str(child_receipt),
                    str(request_path), str(result_path),
                ], **options)
                row.update(
                    limit_method=execution.limit_method, memory_limited=execution.memory_limited,
                    returncode=execution.returncode, reason_code=execution.reason_code,
                    timed_out=execution.timed_out, cancelled=execution.cancelled,
                    output_truncated=execution.output_truncated,
                    stderr=execution.stderr.decode("utf-8", errors="replace")[-16000:],
                )
                if result_path.is_file():
                    value = json.loads(result_path.read_text(encoding="utf-8"))
                    receipt["worker_result"] = {
                        key: value.get(key) for key in ("outcome", "reason_code", "coverage", "collector_mode")
                    }
                save()
                return execution

            with patch("fxfetch.service.run_limited", observed_runner):
                with TestClient(create_app(settings, service=service), client=("127.0.0.1", 50000)) as client:
                    headers = {"Origin": "http://testserver"}
                    response = client.post("/api/login", json={"password": "isolated-synthetic-api"}, headers=headers)
                    assert response.status_code == 200
                    headers["X-CSRF-Token"] = response.json()["csrf_token"]
                    response = client.post("/api/jobs", json={"url": "http://capture.test/api-page"},
                                           headers={**headers, "Idempotency-Key": "isolated-android-synthetic"})
                    assert response.status_code == 202, response.text
                    identifier = response.json()["id"]
                    observed_events: set[str] = set()
                    deadline = time.monotonic() + 640
                    while time.monotonic() < deadline:
                        response = client.get(f"/api/jobs/{identifier}")
                        assert response.status_code == 200
                        job = response.json()
                        observed_events.update(row.get("event", "") for row in (job.get("progress") or {}).get("events", []))
                        if job["state"] in {"completed", "cancelled"}:
                            break
                        time.sleep(0.2)
                    else:
                        raise AssertionError("Isolated API task exceeded its bounded deadline")
                    receipt.update(
                        outcome=job["outcome"], reason_code=job["result"].get("reason_code"),
                        collector_mode=job["result"].get("collector_mode"), events=sorted(observed_events),
                        request_counts=dict(server.counts),
                        execution_limit_method=job["progress"].get("execution_limit_method"),
                    )
                    save()
                    assert job["outcome"] == "downloaded", receipt
                    assert receipt["execution_limit_method"] == "isolated_process_tree"
                    assert receipt["worker_result"]["collector_mode"] == "android_chrome"
                    execution = receipt["process_runs"][0]
                    assert execution["limit_method"] == expected_limit and execution["memory_limited"]
                    assert execution["returncode"] == 0 and execution["reason_code"] is None
                    assert not execution["timed_out"] and not execution["output_truncated"]
                    assert len(job["artifacts"]) == 1
                    artifact = job["artifacts"][0]
                    response = client.get(f"/api/jobs/{identifier}/artifacts/{artifact['id']}")
                    assert response.status_code == 200 and len(response.content) == len(payload)
                    assert hashlib.sha256(response.content).hexdigest() == expected_hash
                    assert all(server.counts[path] == 1 for path in ("/api-page", "/api", "/single"))
                    assert {"browser_started", "download_started", "file_verified"} <= observed_events
                    child = json.loads(child_receipt.read_text(encoding="utf-8"))
                    receipt["child"] = child
                    assert child["lease_id"] == receipt["lease_id"]
                    assert child["status"] == "worker_returned" and child["gateway_closed"]
                    assert child["gateway_count"] == 1
                    assert any(row["action"] == "begin" and row.get("returncode") == 0 for row in child["control_calls"])
                    assert any(row["action"] == "end" and row.get("returncode") == 0 for row in child["control_calls"])
                    assert child["synthetic_http_preflight_calls"] == 1
                    bundle_deadline = time.monotonic() + 30
                    while job["data_package"]["state"] in {"pending", "building"}:
                        assert time.monotonic() < bundle_deadline, "Data package seal exceeded deadline"
                        time.sleep(0.1)
                        job = client.get(f"/api/jobs/{identifier}").json()
                    assert job["data_package"]["state"] == "ready", job["data_package"]
                    response = client.get(f"/api/jobs/{identifier}/data-package")
                    assert response.status_code == 200
                    bundle_path = args.output / "task-data.zip"
                    bundle_path.write_bytes(response.content)
                    manifest, bundle_sha = verify_task_archive(bundle_path, max_bytes=32 * 1024**2)
                    assert manifest["package_result"]["outcome"] == "downloaded"
                    assert manifest["web_materials"]["count"] > 0
                    assert all(row["sha256"] != expected_hash for row in manifest["files"])
                    receipt.update(data_package_downloaded=True, data_package_sha256=bundle_sha,
                                   data_package_material_count=manifest["web_materials"]["count"])
                    counts = dict(server.counts)
                    response = client.delete("/api/jobs", headers=headers)
                    assert response.status_code == 200 and client.get("/api/jobs").json()["jobs"] == []
                    assert dict(server.counts) == counts
                    receipt.update(sha256=expected_hash, size=len(payload), attachment_downloaded=True,
                                   cleared_without_target_request=True)
            receipt["capture_assertions_passed"] = True
    finally:
        original_failure = sys.exc_info()[0] is not None
        # Observe cleanup even when begin/download assertions failed. Rescue is
        # scoped to the supervisor's exact lease and can never make a run pass.
        cleanup_ok = False
        if receipt.get("lease_id"):
            worker = AndroidWorker(config)
            status = None
            cleanup_errors = []
            try:
                status = worker.call("status", PROBE_ID)
            except FxfetchError as error:
                cleanup_errors.append({"action": "status", "reason_code": error.code})
            rescue = status is None or status.get("lease_id") == receipt["lease_id"]
            receipt["cleanup_rescue_required"] = rescue
            if rescue:
                try:
                    worker.call("end", receipt["lease_id"])
                    status = worker.call("status", PROBE_ID)
                except FxfetchError as error:
                    cleanup_errors.append({"action": "exact_lease_rescue", "reason_code": error.code})
            if status is not None:
                receipt["post_task_status"] = {
                    key: status.get(key)
                    for key in ("state", "lease_id", "container_id", "guard_ready", "deployment_verified")
                }
                cleanup_ok = bool(
                    status.get("state") == "idle" and not status.get("lease_id")
                    and not status.get("container_id") and not status.get("guard_ready")
                    and status.get("deployment_verified") is True and not rescue
                )
            receipt["cleanup_errors"] = cleanup_errors
        receipt["host_ports_closed"] = {str(port): port_closed(port) for port in (18767, 19222)}
        cleanup_ok = cleanup_ok and all(receipt["host_ports_closed"].values())
        if not original_failure and receipt.get("capture_assertions_passed") and cleanup_ok:
            receipt["status"] = "passed"
        if child_receipt.is_file():
            receipt["child"] = json.loads(child_receipt.read_text(encoding="utf-8"))
        save()
        print(json.dumps(receipt), flush=True)
        if not original_failure and receipt["status"] != "passed":
            raise AssertionError("Isolated task did not pass normal cleanup; inspect the private receipt")


if __name__ == "__main__":
    main()
