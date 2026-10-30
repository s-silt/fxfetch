"""Real installed Chrome: task-scoped TLS override, original DER and guards."""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
import zipfile
from dataclasses import asdict
from urllib.parse import urlsplit

from browser_tls_originals_acceptance import _chrome, _workspace
from browser_tls_profile import CHROME_ARGS, trusted_tls_server
from playwright.async_api import async_playwright

from fxfetch.core.browser_capture import BrowserLaunchProof, capture_browser
from fxfetch.core.browser_workflow import project_capture
from fxfetch.core.errors import FxfetchError
from fxfetch.core.limits import Limits
from fxfetch.core.task_evidence_io import build_task_archive
from fxfetch.core.task_evidence_recorder import TaskEvidenceRecorder
from fxfetch.core.task_evidence_verify import verify_task_archive


def test_tls_override_is_one_capture_and_preserves_originals():
    """Same Chrome process makes leakage visible across three independent tasks."""
    chrome = _chrome()
    workspace = _workspace("chrome-tls-override")
    started = time.monotonic()
    receipt = {"system_trust_modified": False, "profile_trust_modified": False,
               "same_chrome_process": True, "raw_trace_persisted": False, "tasks": []}
    with trusted_tls_server(workspace / "server") as server:
        expected = {hashlib.sha256(der).hexdigest(): der for der in server.certificates[:2]}
        profile = workspace / "profile"
        entry = server.origin + "/download"

        def permit(url, method):
            actual, allowed = urlsplit(url), urlsplit(server.origin)
            if (actual.scheme, actual.hostname, actual.port) != ("https", "localhost", allowed.port):
                raise FxfetchError("synthetic_destination_denied", "Destination outside the local TLS test")
            if method not in {"GET", "HEAD"}:
                raise FxfetchError("synthetic_method_denied", "Only synthetic reads are allowed")

        async def run():
            async with async_playwright() as driver:
                context = await driver.chromium.launch_persistent_context(
                    str(profile), executable_path=str(chrome), headless=True, timeout=15000,
                    accept_downloads=False, service_workers="block", args=CHROME_ARGS,
                )
                try:
                    control = await context.new_cdp_session(context.pages[0])
                    receipt["chrome"] = (await control.send("Browser.getVersion"))["product"]
                    await control.detach()
                    port = (profile / "DevToolsActivePort").read_text().splitlines()[0]

                    class SyntheticLease:
                        def verify_before_launch(self):
                            return BrowserLaunchProof(chrome, profile, "unused-with-local-cdp",
                                                      cdp_endpoint=f"http://127.0.0.1:{port}", permit_request=permit)

                    for label, ignored in [("default_before", False), ("ignored_once", True), ("default_after", False)]:
                        # The production remote worker also supplies one blank
                        # target. Reset only the visible page between tasks;
                        # never change TLS settings in this test harness.
                        pages = context.pages
                        assert len(pages) == 1
                        await pages[0].goto("about:blank", timeout=5000)
                        before = dict(server.counts)
                        task_root = workspace / label
                        recorder = TaskEvidenceRecorder(task_root)
                        policy = "auto" if ignored else "strict"
                        recorder.append("task_tls_policy", {"tls_policy": policy})
                        options = {"tls_policy": "auto"} if ignored else {}
                        try:
                            capture = await capture_browser(
                                entry, task_root / "browser", threading.Event(), lease=SyntheticLease(),
                                journal=recorder.journal,
                                observation_context={"collector_id": "browser", "attempt_id": label},
                                limits=Limits(chain_timeout=12, read_timeout=3), **options,
                            )
                        finally:
                            recorder.close()
                        task_receipt = {"task": label, "tls_policy": policy, "outcome": capture.outcome,
                                        "reason_code": capture.reason_code, "capture_gaps": capture.gaps,
                                        "http_requests_delta": sum(server.counts.values()) - sum(before.values())}
                        receipt["tasks"].append(task_receipt)
                        if ignored:
                            assert capture.outcome == "downloaded" and len(capture.artifacts) == 1, task_receipt
                            assert capture.artifacts[0].path.read_bytes() == server.apk
                            assert server.counts["/download"] - before.get("/download", 0) == 1
                            assert server.counts["/app.apk"] - before.get("/app.apk", 0) == 1
                        else:
                            assert capture.outcome == "failed" and not capture.artifacts, task_receipt
                            assert dict(server.counts) == before, "Default TLS must reject before HTTP"
                        assert capture.tls_verification == ("unknown" if ignored else "required")
                        assert capture.tls_fallback_used is ignored
                        rows = [json.loads(line) for line in recorder.path.read_text().splitlines()]
                        saved = [row["fields"] for row in rows if row["kind"] == "tls_certificate_saved"]
                        assert saved
                        expected_verification = "unknown" if ignored else "required"
                        assert all(item["tls_verification"] == expected_verification for item in saved)
                        result = asdict(project_capture(capture, entry))
                        archive_path = task_root / "evidence.zip"
                        manifest, _ = build_task_archive(
                            task_root, archive_path, job_id=label, entry_url=entry, package_result=result,
                            result=result, observation_path=recorder.path, max_bytes=16 * 1024 * 1024,
                            max_seconds=5, tls_policy=policy,
                        )
                        verified, _ = verify_task_archive(archive_path, max_bytes=16 * 1024 * 1024)
                        assert verified == manifest and manifest["tls_policy"] == policy
                        assert manifest["tls_fallback"]["observed"] is ignored
                        fallback = [row["fields"] for row in rows if row["kind"] == "tls_verification_fallback"]
                        assert bool(fallback) is ignored
                        if ignored:
                            assert all(item["chrome_error_type"] == "ERR_CERT_AUTHORITY_INVALID" for item in fallback)
                        certificates = [item for item in manifest["attachments"] if item["kind"] == "certificate"]
                        assert {item["sha256"] for item in certificates} == set(expected)
                        with zipfile.ZipFile(archive_path) as archive:
                            for item in certificates:
                                assert archive.read(item["path"]) == expected[item["sha256"]]
                                assert item["tls_verification"] == expected_verification
                                assert item["association"] == "browser_network_event"
                                assert item["request_association"] == "unknown"
                                assert not item.get("source_url") and not item.get("request_ref")
                        task_receipt.update(zip_original_der_match=True, saved_certificate_records=len(saved),
                                            archive_risk_marked=manifest["tls_fallback"]["observed"], passed=True)
                    receipt["passed"] = True
                finally:
                    await asyncio.wait_for(context.close(), 5)

        try:
            asyncio.run(asyncio.wait_for(run(), 55))
        finally:
            receipt["http_counts"] = dict(server.counts)
            receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
            (workspace / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
            print(f"TLS override receipt: {workspace / 'receipt.json'}")


def test_tls_override_keeps_redirect_request_guard():
    chrome = _chrome()
    workspace = _workspace("chrome-tls-override-guard")
    started = time.monotonic()
    receipt = {"ignore_tls_errors": True, "system_trust_modified": False, "blocked_requests": []}
    with trusted_tls_server(workspace / "canary") as canary:
        denied = canary.origin + "/download"
        with trusted_tls_server(workspace / "server", blocked_redirect=denied) as server:
            profile = workspace / "profile"

            def permit(url, method):
                destination, allowed = urlsplit(url), urlsplit(server.origin)
                if (destination.scheme, destination.hostname, destination.port) != ("https", "localhost", allowed.port):
                    receipt["blocked_requests"].append(url)
                    raise FxfetchError("synthetic_destination_denied", "Blocked synthetic redirect")
                assert method in {"GET", "HEAD"}

            async def run():
                async with async_playwright() as driver:
                    context = await driver.chromium.launch_persistent_context(
                        str(profile), executable_path=str(chrome), headless=True, timeout=15000,
                        accept_downloads=False, service_workers="block", args=CHROME_ARGS,
                    )
                    try:
                        port = (profile / "DevToolsActivePort").read_text().splitlines()[0]

                        class SyntheticLease:
                            def verify_before_launch(self):
                                return BrowserLaunchProof(chrome, profile, "unused-with-local-cdp",
                                                          cdp_endpoint=f"http://127.0.0.1:{port}", permit_request=permit)

                        result = await capture_browser(
                            server.origin + "/redirect-blocked", workspace / "capture", threading.Event(),
                            lease=SyntheticLease(), limits=Limits(chain_timeout=12, read_timeout=3),
                            ignore_tls_errors=True,
                        )
                        receipt.update(outcome=result.outcome, reason_code=result.reason_code)
                        assert result.outcome == "failed" and not result.artifacts
                        assert denied in receipt["blocked_requests"]
                        assert server.counts["/redirect-blocked"] == 1 and not canary.counts
                        receipt["passed"] = True
                    finally:
                        await asyncio.wait_for(context.close(), 5)

            try:
                asyncio.run(asyncio.wait_for(run(), 30))
            finally:
                receipt.update(canary_http_requests=sum(canary.counts.values()), http_counts=dict(server.counts),
                               elapsed_seconds=round(time.monotonic() - started, 3))
                (workspace / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
                print(f"TLS override guard receipt: {workspace / 'receipt.json'}")
