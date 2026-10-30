"""Explicit synthetic Android certificate-error fallback/DER probe; never install trust.

Run only after the operator confirms jobs/builds/analyses are idle and gives this
process exclusive ownership of the worker. By default this script only prints
its scope; --execute is required for the production lease. No worker deployment,
recovery, image installation, or target APK execution is performed. The optional
--ignore-tls-errors applies only to this capture; omit it for the default refusal.
For a three-task acceptance run this script three times with separate outputs:
default, --ignore-tls-errors, default. Each uses a fresh production AndroidLease.

When staged in a container, the directory containing tests/ must have a writable
.runtime/temp/ sibling. All synthetic keys and output stay there; the private
leaf key is deleted by the server context. Config is read, never printed.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import threading
import time
import zipfile
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

from browser_tls_profile import RUNTIME_TEMP, trusted_tls_server

from fxfetch.core.android_worker import PROBE_ID, AndroidLease, AndroidWorker, load_worker_config
from fxfetch.core.browser_capture import capture_browser
from fxfetch.core.browser_gateway import BrowserGateway
from fxfetch.core.browser_workflow import project_capture
from fxfetch.core.errors import FxfetchError
from fxfetch.core.limits import Limits
from fxfetch.core.task_evidence_io import build_task_archive
from fxfetch.core.task_evidence_recorder import TaskEvidenceRecorder
from fxfetch.core.task_evidence_verify import verify_task_archive

ENTRY = "https://capture.test/download"


def synthetic_gateway(origin_port: int, cancel: threading.Event) -> BrowserGateway:
    class LocalTLSGateway(BrowserGateway):
        def _destination(self, url: str) -> tuple[str, int]:
            parsed = urlsplit(url)
            if (parsed.scheme, parsed.hostname, parsed.port) not in {
                ("https", "capture.test", None), ("https", "capture.test", 443),
            }:
                raise FxfetchError("synthetic_destination_denied", "Only the fixed synthetic TLS origin is allowed")
            self._check()
            return "127.0.0.1", origin_port

    return LocalTLSGateway(port=18767, timeout=240, max_connections=64,
                           max_wire_bytes=8 * 1024 * 1024, cancel=cancel)


def run(config_root: Path, output: Path, *, tls_policy: str = "strict") -> int:
    output = output.resolve()
    output.relative_to(RUNTIME_TEMP.resolve())
    if output.exists():
        raise ValueError("output_must_be_new")
    output.mkdir(parents=True)
    started = time.monotonic()
    receipt: dict = {"scope": "synthetic_android_tls_only", "tls_policy": tls_policy,
                     "trust_installed": False, "worker_rebuilt": False, "raw_trace_persisted": False,
                     "capture_timeout_seconds": 45, "lease_seconds": 240, "status": "started"}
    worker = None
    try:
        config = load_worker_config(config_root)
        if config is None:
            raise ValueError("worker_config_missing")
        worker = AndroidWorker(config)
        status = worker.call("status", PROBE_ID)
        worker.validate(status, readiness=True)
        if status.get("state") != "idle" or status.get("lease_id") is not None:
            raise ValueError("worker_must_be_idle")
        receipt["chrome_version"] = status.get("chrome_version")
        cancel = threading.Event()
        task_root = output / "task"
        recorder = TaskEvidenceRecorder(task_root)
        recorder.append("task_tls_policy", {"tls_policy": tls_policy})
        try:
            with trusted_tls_server(output / "server") as server:
                expected = {hashlib.sha256(der).hexdigest(): der for der in server.certificates[:2]}
                receipt["expected_server_chain_sha256"] = list(expected)
                gateway = synthetic_gateway(urlsplit(server.origin).port, cancel)
                with gateway:
                    with AndroidLease(worker, gateway, cancel, timeout=240) as lease:
                        receipt["lease_ready_seconds"] = round(time.monotonic() - started, 3)
                        capture = asyncio.run(asyncio.wait_for(capture_browser(
                            ENTRY, task_root / "browser", cancel, lease=lease, journal=recorder.journal,
                            observation_context={"collector_id": "browser", "attempt_id": "synthetic-android-tls"},
                            limits=Limits(chain_timeout=30, read_timeout=3),
                            tls_policy=tls_policy,
                        ), 45))
                receipt.update(outcome=capture.outcome, reason_code=capture.reason_code,
                               http_requests_received=sum(server.counts.values()), capture_gaps=capture.gaps)
                if tls_policy == "auto":
                    if (capture.outcome != "downloaded" or len(capture.artifacts) != 1
                            or capture.artifacts[0].path.read_bytes() != server.apk
                            or server.counts["/download"] != 1 or server.counts["/app.apk"] != 1):
                        raise AssertionError("observed_certificate_fallback_must_preserve_package_download")
                    receipt["original_package_sha256"] = hashlib.sha256(server.apk).hexdigest()
                elif capture.outcome != "failed" or capture.artifacts or server.counts:
                    raise AssertionError("untrusted_tls_must_fail_before_http")
                recorder.close()
                result = asdict(project_capture(capture, ENTRY))
                archive_path = task_root / "evidence.zip"
                manifest, _ = build_task_archive(
                    task_root, archive_path, job_id="synthetic-android-tls", entry_url=ENTRY,
                    package_result=result, result=result, observation_path=recorder.path,
                    max_bytes=16 * 1024 * 1024, max_seconds=5,
                    tls_policy=tls_policy,
                )
                verified, _ = verify_task_archive(archive_path, max_bytes=16 * 1024 * 1024)
                if verified != manifest or manifest["tls_policy"] != tls_policy:
                    raise AssertionError("archive_manifest_mismatch")
                receipt["tls_fallback"] = manifest["tls_fallback"]
                if (manifest["tls_fallback"]["observed"] is not (tls_policy == "auto")
                        or manifest["tls_fallback"]["state"] != "recorded"):
                    raise AssertionError("archive_actual_fallback_mismatch")
                observations = [json.loads(line) for line in recorder.path.read_bytes().splitlines()]
                failures = [row for row in observations if row["kind"] == "tls_certificate_error"]
                continued = [row for row in observations if row["kind"] == "tls_verification_fallback"]
                if tls_policy == "auto":
                    if not failures or len(continued) != manifest["tls_fallback"]["count"]:
                        raise AssertionError("missing_actual_certificate_error_proof")
                elif continued:
                    raise AssertionError("strict_task_cannot_continue_certificate_errors")
                receipt["certificate_errors_recorded"] = len(failures)
                receipt["confirmed_fallbacks"] = len(continued)
                certificates = [item for item in manifest["attachments"] if item["kind"] == "certificate"]
                if certificates:
                    with zipfile.ZipFile(archive_path) as archive:
                        packages = [item for item in manifest["attachments"] if item["kind"] == "package"]
                        if tls_policy == "auto":
                            if len(packages) != 1 or archive.read(packages[0]["path"]) != server.apk:
                                raise AssertionError("archive_original_apk_mismatch")
                            receipt["zip_original_apk_match"] = True
                        for item in certificates:
                            if (item["capture_source"] != "chrome_netlog_ssl_certificates_received"
                                    or item["association"] != "browser_network_event"
                                    or item["request_association"] != "unknown"
                                    or item["tls_verification"] != ("unknown" if tls_policy == "auto" else "required")
                                    or item.get("source_url") or item.get("request_ref") or item.get("origin")
                                    or archive.read(item["path"]) != expected.get(item["sha256"])):
                                raise AssertionError("passive_der_provenance_or_bytes_mismatch")
                    if {item["sha256"] for item in certificates} != set(expected):
                        raise AssertionError("observed_server_chain_incomplete")
                    receipt.update(status="passed_der", zip_original_der_match=True,
                                   saved_certificate_records=len(certificates))
                else:
                    if "tls_certificate_not_captured" not in manifest["gaps"]:
                        raise AssertionError("missing_certificate_gap")
                    receipt.update(status="tls_rejected_certificate_gap", saved_certificate_records=0)
        finally:
            recorder.close()
        final = worker.call("status", PROBE_ID)
        worker.validate(final, readiness=True)
        if final.get("state") != "idle" or final.get("lease_id") is not None:
            raise AssertionError("worker_not_idle_after_cleanup")
        receipt["worker_idle_after_cleanup"] = True
        return 0 if receipt["status"] == "passed_der" else 2
    except (FxfetchError, OSError, ValueError, AssertionError, TimeoutError) as error:
        receipt.update(status="failed", reason_code=error.code if isinstance(error, FxfetchError) else type(error).__name__)
        if isinstance(error, AssertionError):
            receipt["synthetic_assertion"] = str(error)[:160]
        return 1
    finally:
        receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": receipt["status"], "receipt": str(output / "receipt.json")}))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker-config-root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--execute", action="store_true", help="Run only after exclusive idle-worker authorization")
    parser.add_argument("--tls-policy", choices=("strict", "auto"), default="strict")
    args = parser.parse_args()
    if not args.execute:
        print("Prepared only. Requires exclusive idle worker, valid pinned config, and writable .runtime/temp; no connection made.")
        return 0
    if args.worker_config_root is None or args.output is None:
        parser.error("--worker-config-root and --output are required for execution")
    return run(args.worker_config_root, args.output, tls_policy=args.tls_policy)


if __name__ == "__main__":
    raise SystemExit(main())
