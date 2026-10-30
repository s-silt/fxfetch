"""Installed Chrome trusted local TLS originals; profile trust only, no TLS bypass."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import tempfile
import threading
import time
import zipfile
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from browser_tls_profile import CHROME_ARGS, RUNTIME_TEMP, create_trusted_profile, trusted_tls_server
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright

from fxfetch.core.browser_capture import BrowserLaunchProof, capture_browser
from fxfetch.core.browser_workflow import project_capture
from fxfetch.core.limits import Limits
from fxfetch.core.task_evidence_io import build_task_archive
from fxfetch.core.task_evidence_recorder import TaskEvidenceRecorder
from fxfetch.core.task_evidence_verify import verify_task_archive


def _workspace(label: str) -> Path:
    RUNTIME_TEMP.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=label + "-", dir=RUNTIME_TEMP))


def _chrome() -> Path:
    path = Path(os.environ.get("FXFETCH_TEST_CHROME", r"C:\Program Files\Google\Chrome\Application\chrome.exe"))
    if not path.is_file():
        pytest.skip("Installed Chrome required; no browser download")
    return path


@pytest.mark.parametrize("response_mode", ["continue", "stream_fulfill"])
def test_get_certificate_timing(response_mode):
    chrome = _chrome()
    workspace = _workspace("chrome-tls-timing")
    receipt: dict = {"tls_errors_ignored": False, "system_trust_modified": False,
                     "trust_scope": "new_temporary_profile_only", "response_mode": response_mode, "snapshots": []}
    started = time.monotonic()
    with trusted_tls_server(workspace / "server") as server:
        profile = workspace / "profile"
        create_trusted_profile(profile, server.certificates[-1])
        expected = [hashlib.sha256(der).hexdigest() for der in server.certificates]
        receipt["expected_chain_sha256"] = expected

        async def run():
            async with async_playwright() as driver:
                # The same generated CA must remain untrusted in another fresh
                # profile: this rules out reliance on system/global trust.
                isolated = await driver.chromium.launch_persistent_context(
                    str(workspace / "untrusted-profile"), executable_path=str(chrome),
                    headless=True, timeout=15000, args=CHROME_ARGS,
                )
                try:
                    with pytest.raises(PlaywrightError, match="ERR_CERT_AUTHORITY_INVALID"):
                        await isolated.pages[0].goto(server.origin + "/timing", timeout=10000)
                    assert not server.counts
                    receipt["same_ca_rejected_by_separate_profile"] = True
                finally:
                    await asyncio.wait_for(isolated.close(), 5)
                context = await driver.chromium.launch_persistent_context(
                    str(profile), executable_path=str(chrome), headless=True, timeout=15000,
                    accept_downloads=False, service_workers="block", args=CHROME_ARGS,
                )
                try:
                    page = context.pages[0]
                    cdp = await context.new_cdp_session(page)
                    await cdp.send("Network.enable")
                    receipt["chrome"] = (await cdp.send("Browser.getVersion"))["product"]

                    async def snapshot(stage):
                        begin = time.monotonic()
                        try:
                            reply = await asyncio.wait_for(cdp.send("Network.getCertificate", {"origin": server.origin}), 2)
                        except TimeoutError:
                            receipt["snapshots"].append({"stage": stage, "status": "timed_out",
                                                         "elapsed_seconds": round(time.monotonic() - begin, 4)})
                            return []
                        chain = [base64.b64decode(value, validate=True) for value in reply.get("tableNames", [])]
                        receipt["snapshots"].append({"stage": stage, "chain_count": len(chain),
                                                     "sha256": [hashlib.sha256(der).hexdigest() for der in chain],
                                                     "elapsed_seconds": round(time.monotonic() - begin, 4)})
                        return chain

                    await snapshot("before_navigation")
                    await cdp.send("Fetch.enable", {"patterns": [{"urlPattern": server.origin + "/timing", "requestStage": "Response"}]})
                    paused_done = asyncio.Event()
                    errors = []

                    async def paused(event):
                        try:
                            await snapshot("fetch_response_paused")
                        except Exception as error:
                            errors.append(type(error).__name__)
                        finally:
                            if response_mode == "continue":
                                await cdp.send("Fetch.continueRequest", {"requestId": event["requestId"]})
                            else:
                                handle = (await cdp.send("Fetch.takeResponseBodyAsStream", {"requestId": event["requestId"]}))["stream"]
                                body = bytearray()
                                while True:
                                    chunk = await cdp.send("IO.read", {"handle": handle, "size": 65536})
                                    body.extend(base64.b64decode(chunk["data"]) if chunk.get("base64Encoded") else chunk["data"].encode())
                                    assert len(body) <= 65536
                                    if chunk.get("eof"):
                                        break
                                await cdp.send("IO.close", {"handle": handle})
                                await cdp.send("Fetch.fulfillRequest", {"requestId": event["requestId"],
                                               "responseCode": event["responseStatusCode"],
                                               "responseHeaders": event["responseHeaders"],
                                               "body": base64.b64encode(body).decode()})
                            paused_done.set()

                    cdp.on("Fetch.requestPaused", lambda event: asyncio.create_task(paused(event)))
                    response = await page.goto(server.origin + "/timing", wait_until="domcontentloaded", timeout=15000)
                    await asyncio.wait_for(paused_done.wait(), 3)
                    assert not errors, errors
                    assert response is not None and response.status == 200
                    assert "Local TLS body." in await page.inner_text("body")
                    receipt["tls_verified_navigation"] = True
                    receipt["http_status"] = response.status
                    chain = await snapshot("after_continue_and_domcontentloaded")
                    if response_mode == "continue":
                        assert chain and chain[0] == server.certificates[0]
                        assert chain[:2] == list(server.certificates[:2])
                    else:
                        assert not chain, "Recheck current Chrome stream-fulfill certificate retention"
                    receipt["passed"] = True
                finally:
                    await asyncio.wait_for(context.close(), 5)

        try:
            asyncio.run(asyncio.wait_for(run(), 45))
        finally:
            receipt["http_counts"] = dict(server.counts)
            receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
            (workspace / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
            print(f"TLS timing receipt: {workspace / 'receipt.json'}")


@pytest.mark.parametrize("trust_profile,block_certificate_directory", [(True, False), (True, True), (False, False)],
                         ids=["original_chain_zip", "certificate_io_gap", "untrusted_tls_observed_only"])
def test_capture_original_chain_and_download_survives_certificate_gap(trust_profile, block_certificate_directory):
    chrome = _chrome()
    workspace = _workspace("chrome-tls-originals")
    task_root = workspace / "task"
    output_dir = task_root / "browser"
    output_dir.mkdir(parents=True)
    if block_certificate_directory:
        (output_dir / "tls").write_bytes(b"synthetic certificate-directory conflict")
    receipt: dict = {"tls_errors_ignored": False, "system_trust_modified": False,
                     "trust_scope": "new_temporary_profile_only" if trust_profile else "no_trust_installed",
                     "certificate_directory_blocked": block_certificate_directory}
    started = time.monotonic()
    with trusted_tls_server(workspace / "server") as server:
        profile = workspace / "profile"
        if trust_profile:
            create_trusted_profile(profile, server.certificates[-1])
        entry = server.origin + "/download"
        # The passive trace contains the chain actually sent by the server,
        # not the local trust anchor used to validate it.
        expected = {hashlib.sha256(der).hexdigest(): der for der in server.certificates[:2]}
        receipt["expected_chain_sha256"] = list(expected)
        recorder = TaskEvidenceRecorder(task_root)
        requested = []

        def permit(url, method):
            value, allowed = urlsplit(url), urlsplit(server.origin)
            assert (value.scheme, value.hostname, value.port) == ("https", "localhost", allowed.port)
            assert method in {"GET", "HEAD"}
            requested.append(url)

        async def run():
            async with async_playwright() as driver:
                context = await driver.chromium.launch_persistent_context(
                    str(profile), executable_path=str(chrome), headless=True, timeout=15000,
                    accept_downloads=False, service_workers="block", args=CHROME_ARGS,
                )
                try:
                    cdp = await context.new_cdp_session(context.pages[0])
                    receipt["chrome"] = (await cdp.send("Browser.getVersion"))["product"]
                    await cdp.detach()
                    port = (profile / "DevToolsActivePort").read_text().splitlines()[0]

                    class SyntheticLease:
                        def verify_before_launch(self):
                            return BrowserLaunchProof(chrome, profile, "unused-with-local-cdp",
                                                      cdp_endpoint=f"http://127.0.0.1:{port}", permit_request=permit)

                    return await capture_browser(
                        entry, output_dir, threading.Event(), lease=SyntheticLease(), journal=recorder.journal,
                        observation_context={"collector_id": "browser", "attempt_id": "synthetic-trusted-tls"},
                        limits=Limits(chain_timeout=18, read_timeout=3),
                    )
                finally:
                    await asyncio.wait_for(context.close(), 5)

        try:
            capture = asyncio.run(asyncio.wait_for(run(), 45))
            recorder.close()
            receipt.update({"outcome": capture.outcome, "reason_code": capture.reason_code,
                            "capture_gaps": capture.gaps, "http_counts": dict(server.counts),
                            "permitted_requests": len(requested)})
            if trust_profile:
                assert capture.outcome == "downloaded", receipt
                assert len(capture.artifacts) == 1 and capture.artifacts[0].path.read_bytes() == server.apk
                assert capture.artifacts[0].sha256 == hashlib.sha256(server.apk).hexdigest()
                assert server.counts["/download"] == server.counts["/app.apk"] == 1
            else:
                assert capture.outcome == "failed" and not capture.artifacts, receipt
                assert not server.counts, "Untrusted TLS must fail before any HTTP request reaches the origin"
                receipt["untrusted_tls_rejected_before_http"] = True
            rows = [json.loads(line) for line in recorder.path.read_text().splitlines()]
            saved = [row["fields"] for row in rows if row["kind"] == "tls_certificate_saved"]
            result = asdict(project_capture(capture, entry))
            archive_path = task_root / "evidence.zip"
            manifest, _ = build_task_archive(
                task_root, archive_path, job_id="synthetic-trusted-tls", entry_url=entry,
                package_result=result, result=result, observation_path=recorder.path,
                max_bytes=16 * 1024 * 1024, max_seconds=5,
            )
            verified, _ = verify_task_archive(archive_path, max_bytes=16 * 1024 * 1024)
            assert verified == manifest
            attachments = [item for item in manifest["attachments"] if item["kind"] == "certificate"]
            if block_certificate_directory:
                assert not saved and not attachments and not list(output_dir.rglob("*.der"))
                assert "tls_certificate_not_captured" in capture.gaps
                assert "tls_certificate_not_captured" in manifest["gaps"]
                assert any(row["kind"] == "gap" and row["fields"].get("reason_code") ==
                           "browser_tls_certificate_storage_failed" for row in rows), rows
                assert any(row["kind"] == "tls_certificate_observed" for row in rows)
                receipt["certificate_gap_preserved"] = True
            else:
                assert saved and attachments, receipt
                assert {item["sha256"] for item in saved} == set(expected)
                assert {item["sha256"] for item in attachments} == set(expected)
                with zipfile.ZipFile(archive_path) as archive:
                    for item in attachments:
                        assert archive.read(item["path"]) == expected[item["sha256"]]
                        assert item["capture_source"] == "chrome_netlog_ssl_certificates_received"
                        assert item["association"] == "browser_network_event"
                        assert item["request_association"] == "unknown"
                        assert item["chain_complete"] is True and item["chain_length"] == 2
                        assert item["chain_index"] in {0, 1}
                        assert not item.get("origin") and not item.get("source_url") and not item.get("request_ref")
                for item in saved:
                    assert (task_root / item["path"]).read_bytes() == expected[item["sha256"]]
                receipt["zip_original_der_match"] = True
            receipt.update({"saved_certificate_records": len(saved), "zip_certificate_records": len(attachments),
                            "original_package_sha256": capture.artifacts[0].sha256 if capture.artifacts else None,
                            "passed": True})
        finally:
            recorder.close()
            receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
            (workspace / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
            print(f"TLS original receipt: {workspace / 'receipt.json'}")


def test_passive_netlog_during_stream_capture():
    """Probe only: retain selected certificate metadata, never the raw trace."""
    chrome = _chrome()
    workspace = _workspace("chrome-tls-netlog")
    receipt: dict = {"tls_errors_ignored": False, "system_trust_modified": False,
                     "trace_buffer_kib": 4096, "trace_categories": ["netlog"],
                     "raw_trace_persisted": False, "certificate_events": []}
    started = time.monotonic()
    with trusted_tls_server(workspace / "server") as server:
        profile = workspace / "profile"
        create_trusted_profile(profile, server.certificates[-1])

        def permit(url, method):
            value = urlsplit(url)
            assert (value.scheme, value.hostname, value.port) == ("https", "localhost", urlsplit(server.origin).port)
            assert method in {"GET", "HEAD"}

        async def run():
            async with async_playwright() as driver:
                context = await driver.chromium.launch_persistent_context(
                    str(profile), executable_path=str(chrome), headless=True, timeout=15000,
                    accept_downloads=False, service_workers="block", args=CHROME_ARGS,
                )
                trace_started = False
                try:
                    browser = context.browser
                    assert browser is not None
                    control = await browser.new_browser_cdp_session()
                    receipt["chrome"] = (await control.send("Browser.getVersion"))["product"]
                    complete = asyncio.get_running_loop().create_future()
                    control.on("Tracing.tracingComplete", lambda value: complete.set_result(value) if not complete.done() else None)
                    await asyncio.wait_for(control.send("Tracing.start", {
                        "transferMode": "ReturnAsStream", "streamFormat": "json", "streamCompression": "none",
                        "traceConfig": {"recordMode": "recordContinuously", "traceBufferSizeInKb": 4096,
                                        "includedCategories": ["netlog"], "excludedCategories": ["*"]},
                    }), 3)
                    trace_started = True
                    # Do not nest production capture's own trace inside this
                    # low-level probe. Keep identical stream takeover semantics.
                    page = context.pages[0]
                    page_cdp = await context.new_cdp_session(page)
                    await control.send("Browser.setDownloadBehavior", {"behavior": "deny", "eventsEnabled": True})
                    await page_cdp.send("Network.enable")
                    await page_cdp.send("Fetch.enable", {"patterns": [{"urlPattern": server.origin + "/*",
                                                                       "requestStage": "Response"}]})
                    package_done = asyncio.Event()
                    failures = []
                    handlers = set()

                    async def take_stream(event):
                        try:
                            request = event["request"]
                            permit(request["url"], request["method"])
                            handle = (await page_cdp.send("Fetch.takeResponseBodyAsStream", {"requestId": event["requestId"]}))["stream"]
                            body = bytearray()
                            try:
                                while True:
                                    part = await page_cdp.send("IO.read", {"handle": handle, "size": 65536})
                                    body.extend(base64.b64decode(part["data"]) if part.get("base64Encoded") else part["data"].encode())
                                    assert len(body) <= 65536
                                    if part.get("eof"):
                                        break
                            finally:
                                await page_cdp.send("IO.close", {"handle": handle})
                            package = urlsplit(request["url"]).path == "/app.apk"
                            if package:
                                assert bytes(body) == server.apk
                                receipt["original_package_sha256"] = hashlib.sha256(body).hexdigest()
                            await page_cdp.send("Fetch.fulfillRequest", {"requestId": event["requestId"],
                                                "responseCode": 204 if package else event["responseStatusCode"],
                                                "responseHeaders": [] if package else event["responseHeaders"],
                                                "body": "" if package else base64.b64encode(body).decode()})
                            if package:
                                package_done.set()
                        except Exception as error:
                            failures.append(repr(error))
                            package_done.set()

                    def schedule(event):
                        task = asyncio.create_task(take_stream(event))
                        handlers.add(task)
                        task.add_done_callback(handlers.discard)

                    page_cdp.on("Fetch.requestPaused", schedule)
                    await page.goto(server.origin + "/download", wait_until="domcontentloaded", timeout=10000)
                    await page.locator("a").click(no_wait_after=True, timeout=5000)
                    await asyncio.wait_for(package_done.wait(), 5)
                    assert not failures, failures
                    assert server.counts["/download"] == server.counts["/app.apk"] == 1
                    receipt["outcome"] = "downloaded"
                    await asyncio.wait_for(control.send("Tracing.end"), 3)
                    trace_started = False
                    finished = await asyncio.wait_for(complete, 5)
                    handle = finished["stream"]
                    raw = bytearray()
                    try:
                        while True:
                            part = await asyncio.wait_for(control.send("IO.read", {"handle": handle, "size": 65536}), 2)
                            raw.extend(base64.b64decode(part["data"]) if part.get("base64Encoded") else part["data"].encode())
                            assert len(raw) <= 4 * 1024 * 1024, "Bounded trace read exceeded"
                            if part.get("eof"):
                                break
                    finally:
                        await asyncio.wait_for(control.send("IO.close", {"handle": handle}), 2)
                    receipt["trace_bytes"] = len(raw)
                    events = json.loads(raw)["traceEvents"]
                    receipt["trace_event_count"] = len(events)
                    receipt["connection_metadata"] = []
                    for event in events:
                        args = event.get("args", {})
                        params = args.get("params", {})
                        if event.get("cat") != "netlog" or not isinstance(params, dict):
                            continue
                        selected = {key: params[key] for key in (
                            "source_dependency", "host", "host_and_port", "hostname", "address",
                            "address_list", "remote_address", "local_address", "group_id",
                        ) if key in params}
                        url = params.get("url")
                        if isinstance(url, str) and urlsplit(url).hostname == "localhost":
                            selected["synthetic_url"] = url
                        if selected or "SSL_CONNECT" in str(event.get("name")) or "TCP_CONNECT" in str(event.get("name")):
                            receipt["connection_metadata"].append({
                                "name": event.get("name"), "source_type": args.get("source_type"),
                                "id2": event.get("id2"), "pid": event.get("pid"), "phase": event.get("ph"),
                                "parameter_keys": sorted(params), "selected_parameters": selected,
                            })
                            if len(receipt["connection_metadata"]) >= 80:
                                break
                    for event in events:
                        if event.get("name") != "SSL_CERTIFICATES_RECEIVED":
                            continue
                        args = event.get("args", {})
                        params = args.get("params", {})
                        chain = [x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)
                                 for pem in params.get("certificates", [])]
                        receipt["certificate_events"].append({
                            "source_type": args.get("source_type"), "id": event.get("id"), "id2": event.get("id2"),
                            "pid": event.get("pid"), "ts": event.get("ts"),
                            "chain_sha256": [hashlib.sha256(der).hexdigest() for der in chain],
                            "matches_sent_leaf_intermediate": chain == list(server.certificates[:2]),
                        })
                    receipt["passed"] = any(item["matches_sent_leaf_intermediate"] for item in receipt["certificate_events"])
                    assert receipt["passed"], receipt
                finally:
                    if trace_started:
                        await asyncio.wait_for(control.send("Tracing.end"), 3)
                    await asyncio.wait_for(context.close(), 5)

        try:
            asyncio.run(asyncio.wait_for(run(), 45))
        finally:
            receipt["http_counts"] = dict(server.counts)
            receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
            (workspace / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
            print(f"TLS netlog receipt: {workspace / 'receipt.json'}")
