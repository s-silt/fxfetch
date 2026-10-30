"""Installed Chrome certificate-error events; no global TLS-ignore switch."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from urllib.parse import urlsplit

from browser_tls_originals_acceptance import _chrome, _workspace
from browser_tls_profile import CHROME_ARGS, create_trusted_profile, trusted_tls_server
from playwright.async_api import async_playwright

from fxfetch.core.browser_capture import BrowserLaunchProof, capture_browser
from fxfetch.core.limits import Limits
from fxfetch.core.task_evidence_recorder import TaskEvidenceRecorder


def test_certificate_error_override_protocol():
    chrome = _chrome()
    workspace = _workspace("chrome-tls-event-protocol")
    receipt = {"global_ignore": False, "system_trust_modified": False, "events": []}
    start = time.monotonic()
    with trusted_tls_server(workspace / "server") as server:
        async def run():
            async with async_playwright() as driver:
                context = await driver.chromium.launch_persistent_context(
                    str(workspace / "profile"), executable_path=str(chrome), headless=True,
                    timeout=10000, args=CHROME_ARGS,
                )
                try:
                    page = context.pages[0]
                    cdp = await context.new_cdp_session(page)
                    receipt["chrome"] = (await cdp.send("Browser.getVersion"))["product"]
                    await cdp.send("Security.setIgnoreCertificateErrors", {"ignore": False})
                    await cdp.send("Security.enable")
                    await cdp.send("Security.setOverrideCertificateErrors", {"override": True})
                    allowed = set()
                    handlers = set()

                    async def request(event):
                        assert event["request"]["url"] == server.origin + "/download"
                        allowed.add(event["request"]["url"])
                        await cdp.send("Fetch.continueRequest", {"requestId": event["requestId"]})

                    async def certificate(event):
                        assert event["requestURL"] in allowed
                        receipt["events"].append({key: event[key] for key in ("eventId", "errorType", "requestURL")})
                        await cdp.send("Security.handleCertificateError", {"eventId": event["eventId"], "action": "continue"})

                    def dispatch(coro):
                        task = asyncio.create_task(coro)
                        handlers.add(task)

                    cdp.on("Security.certificateError", lambda event: dispatch(certificate(event)))
                    cdp.on("Fetch.requestPaused", lambda event: dispatch(request(event)))
                    await cdp.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]})
                    response = await page.goto(server.origin + "/download", timeout=10000, wait_until="domcontentloaded")
                    await asyncio.gather(*handlers)
                    assert response is not None and response.status == 200
                    assert receipt["events"] and server.counts["/download"] == 1
                    receipt["passed"] = True
                finally:
                    try:
                        await asyncio.wait_for(cdp.send("Security.setOverrideCertificateErrors", {"override": False}), 1)
                        await asyncio.wait_for(cdp.send("Security.setIgnoreCertificateErrors", {"ignore": False}), 1)
                    finally:
                        await asyncio.wait_for(context.close(), 3)

        try:
            asyncio.run(asyncio.wait_for(run(), 20))
        finally:
            receipt["http_counts"] = dict(server.counts)
            receipt["elapsed_seconds"] = round(time.monotonic() - start, 3)
            (workspace / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
            print(f"TLS event protocol receipt: {workspace / 'receipt.json'}")


def test_auto_keeps_trusted_cross_origin_iframe_strict_and_available():
    chrome = _chrome()
    workspace = _workspace("chrome-tls-auto-trusted-iframe")
    receipt = {"tls_policy": "auto", "system_trust_modified": False, "global_ignore": False,
               "local_network_access_checks": "disabled_in_this_loopback_fixture_only"}
    start = time.monotonic()
    with trusted_tls_server(workspace / "child-server") as child:
        child_origin = child.origin.replace("localhost", "127.0.0.1")
        with trusted_tls_server(workspace / "parent-server", embedded_origin=child_origin) as parent:
            profile = workspace / "profile"
            create_trusted_profile(profile, parent.certificates[-1], additional_roots=(child.certificates[-1],))
            allowed = {urlsplit(origin).netloc for origin in (parent.origin, child_origin)}
            recorder = TaskEvidenceRecorder(workspace / "task")
            recorder.append("task_tls_policy", {"tls_policy": "auto"})

            def permit(url, method):
                value = urlsplit(url)
                assert value.scheme == "https" and value.netloc in allowed and method in {"GET", "HEAD"}

            async def run():
                async with async_playwright() as driver:
                    context = await driver.chromium.launch_persistent_context(
                        str(profile), executable_path=str(chrome), headless=True, timeout=10000,
                        # This synthetic loopback fixture tests OOPIF Security
                        # initialization, not Chrome's independent LNA policy.
                        args=[*CHROME_ARGS, "--site-per-process", "--disable-features=LocalNetworkAccessChecks"],
                        accept_downloads=False,
                    )
                    try:
                        receipt["failed_requests"] = []
                        context.on("requestfailed", lambda request: receipt["failed_requests"].append(
                            {"url": request.url, "failure": request.failure}))
                        port = (profile / "DevToolsActivePort").read_text().splitlines()[0]

                        class Lease:
                            def verify_before_launch(self):
                                return BrowserLaunchProof(chrome, profile, "unused-with-local-cdp",
                                                          cdp_endpoint=f"http://127.0.0.1:{port}", permit_request=permit)

                        return await capture_browser(parent.origin + "/iframe-download", workspace / "task" / "browser",
                                                     threading.Event(), lease=Lease(), journal=recorder.journal,
                                                     observation_context={"collector_id": "browser", "attempt_id": "trusted-iframe"},
                                                     tls_policy="auto", limits=Limits(chain_timeout=18, read_timeout=3))
                    finally:
                        await asyncio.wait_for(context.close(), 3)

            try:
                capture = asyncio.run(asyncio.wait_for(run(), 30))
                recorder.close()
                receipt.update(outcome=capture.outcome, reason_code=capture.reason_code,
                               tls_fallback_used=capture.tls_fallback_used, tls_verification=capture.tls_verification)
                assert capture.outcome == "downloaded" and capture.artifacts[0].path.read_bytes() == parent.apk, receipt
                assert child.counts["/frame"] == 1 and parent.counts["/app.apk"] == 1
                rows = [json.loads(line) for line in recorder.path.read_text().splitlines()]
                assert not capture.tls_fallback_used and capture.tls_verification == "required"
                assert not any(row["kind"] in {"tls_certificate_error", "tls_verification_fallback"} for row in rows)
                iframe_targets = [row for row in rows if row["kind"] == "target_attached" and row["fields"].get("target_type") == "iframe"]
                assert iframe_targets, "The test must exercise a real out-of-process iframe"
                receipt.update(passed=True, out_of_process_iframe_targets=len(iframe_targets))
            finally:
                recorder.close()
                receipt.update(parent_http_counts=dict(parent.counts), child_http_counts=dict(child.counts),
                               elapsed_seconds=round(time.monotonic() - start, 3))
                (workspace / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
                print(f"TLS trusted iframe receipt: {workspace / 'receipt.json'}")
