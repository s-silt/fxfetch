"""Actual installed desktop Chrome, synthetic proxy only, no real targets."""

import asyncio
import base64
import json
import threading
import time
from urllib.parse import urlsplit

import pytest
from browser_capture_acceptance import (
    APK,
    Handler,
    SyntheticProxy,
    assert_package_journal,
    synthetic_sdk_payload,
)
from browser_capture_acceptance import run_capture as capture_fixture

from fxfetch.core import browser_capture
from fxfetch.core.cdp_transport import CDPCommandError, CDPMux
from fxfetch.core.limits import Limits
from fxfetch.core.web_journal import EvidenceJournal

run_capture = capture_fixture


class ResourceHandler(Handler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.hostname not in {"capture.test", "frame.test"}:
            return super().do_GET()
        path = parsed.path
        pages = {
            "/expired-dispatch": '<img src="/cancelled-side.png">',
            "/expired-package-dispatch": '<img src="/cancelled.apk">',
            "/stale-image-page": '<link rel="icon" href="data:,"><img src="/stale-image.png"><script>setTimeout(()=>location.href="/stale-image-next",300)</script>',
            "/stale-image-next": '<link rel="icon" href="data:,"><a href="/app.apk">Download APK</a>',
            "/optional-image": '<img src="/missing-image.png">',
            "/optional-image-denied": '<img src="/denied-image.png">',
            "/optional-css": '<link rel="stylesheet" href="/missing-style.css">',
            "/optional-media": '<video src="/missing-video.mp4" autoplay muted></video>',
            "/optional-connection": '<img src="/closed-image.png">',
            "/closed-no-package": '<link rel="icon" href="data:,"><img src="/closed-image.png">',
            "/package-network-failure": '<img src="/closed.apk">',
            "/download-side-script": '<link rel="icon" href="data:,"><script>setTimeout(()=>location.href="/slow-package.apk",100);setTimeout(()=>{const s=document.createElement("script");s.src="/side-script.js";document.body.append(s)},500)</script>',
            "/download-side-xhr": '<link rel="icon" href="data:,"><script>setTimeout(()=>location.href="/slow-package.apk",100);setTimeout(()=>fetch("/side-api").catch(()=>{}),500)</script>',
            "/required-script": '<script src="/missing-script.js"></script>',
            "/required-api": '<script>fetch("/denied-api")</script>',
            "/api-fallback": '<script>fetch("/missing-api").then(async r=>{if(r.status===404 && await r.text()==="Synthetic missing resource")location.href="/app.apk"})</script>',
            "/api-no-download": '<script>fetch("/missing-api")</script>',
            "/api-blocked-no-download": '<script>fetch("/denied-api")</script>',
            "/script-no-download": '<script src="/missing-script.js"></script>',
            "/package-as-image": '<img src="/denied.apk">',
            "/package-mime-as-image": '<img src="/package-mime.png">',
            "/no-package-optional": '<p>Plain synthetic page</p><img src="/missing-image.png">',
            "/runtime-error": '<script>setTimeout(()=>{throw new Error("WebGL unavailable private-secret")},20)</script>',
            "/slow-script-page": '<link rel="icon" href="data:,"><p>Loading</p><script async src="/slow-script.js"></script>',
            "/heartbeat-page": '<link rel="icon" href="data:,"><p>Waiting</p><script>setInterval(()=>fetch("/heartbeat"),500)</script>',
            "/heartbeat-http-error": '<link rel="icon" href="data:,"><p>Waiting</p><script>fetch("/missing-api");setInterval(()=>fetch("/heartbeat"),500)</script>',
        }
        if path in pages:
            self.server.counts[path] += 1
            content = pages[path]
            if path not in {
                "/no-package-optional", "/slow-script-page", "/api-fallback",
                "/api-no-download", "/api-blocked-no-download", "/script-no-download",
                "/heartbeat-page", "/heartbeat-http-error",
                "/closed-no-package", "/download-side-script", "/download-side-xhr",
                "/stale-image-page", "/stale-image-next",
            }:
                content += "<script>setTimeout(()=>location.href='/app.apk',1200)</script>"
            self.respond(200, content.encode())
        elif path == "/stale-image.png":
            self.server.counts[path] += 1
            self.respond(200, b"synthetic-stale-image", "image/png")
        elif path in {"/missing-image.png", "/missing-style.css", "/missing-video.mp4", "/missing-script.js", "/missing-api"}:
            self.server.counts[path] += 1
            self.respond(404, b"Synthetic missing resource", "text/plain")
        elif path in {"/denied-image.png", "/denied-api", "/denied.apk", "/package-mime.png"}:
            self.server.counts[path] += 1
            mime = "application/octet-stream" if path == "/package-mime.png" else "text/plain"
            self.respond(403, b"Synthetic access control", mime)
        elif path == "/heartbeat":
            self.server.counts[path] += 1
            self.respond(200, b'{"alive":true}', "application/json")
        elif path == "/slow-script.js":
            self.server.counts[path] += 1
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                for _ in range(6):
                    block = b" " * 65536
                    self.wfile.write(f"{len(block):X}\r\n".encode() + block + b"\r\n")
                    self.wfile.flush()
                    if self.server.stopped.wait(1):
                        return
                block = b"setTimeout(()=>location.href='/app.apk',500)"
                self.wfile.write(f"{len(block):X}\r\n".encode() + block + b"\r\n0\r\n\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                self.close_connection = True
        elif path == "/slow-package.apk":
            self.server.counts[path] += 1
            self.server.package_started.set()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(APK)))
            self.end_headers()
            try:
                for start in range(0, len(APK), 65536):
                    self.wfile.write(APK[start:start + 65536])
                    self.wfile.flush()
                    if self.server.stopped.wait(0.4):
                        return
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                self.close_connection = True
        elif path in {"/side-script.js", "/side-api"}:
            self.server.counts[path] += 1
            self.connection.shutdown(2)
            self.close_connection = True
        elif path in {"/closed-image.png", "/closed.apk"}:
            self.server.counts[path] += 1
            self.connection.shutdown(2)
            self.close_connection = True
        else:
            return super().do_GET()


@pytest.fixture
def proxy():
    server = SyntheticProxy()
    server.RequestHandlerClass = ResourceHandler
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.stopped.set()
        server.shutdown()
        server.server_close()
        thread.join(2)


@pytest.mark.parametrize("path", ["/optional-image", "/optional-image-denied", "/optional-css", "/optional-media"])
def test_optional_failure_does_not_stop_normal_apk_navigation(run_capture, proxy, path):
    result, _events = run_capture(path)
    assert result.outcome == "downloaded", result.responses
    assert result.artifacts[0].path.read_bytes() == APK
    assert proxy.counts["/app.apk"] == 1
    assert any(row.get("optional_resource_failure") for row in result.responses), result.responses


@pytest.mark.parametrize("path,reason", [
    ("/package-as-image", "http_access_control"), ("/package-mime-as-image", "http_access_control"),
    ("/package-network-failure", "browser_network_error"),
])
def test_required_or_package_failure_still_stops_before_download(run_capture, proxy, path, reason):
    result, _events = run_capture(path)
    assert result.reason_code == reason and not result.artifacts, result
    assert proxy.counts["/app.apk"] == 0


def test_failed_side_resource_does_not_block_later_valid_download(run_capture, proxy):
    result, _events = run_capture("/optional-connection")
    assert result.outcome == "downloaded" and result.artifacts[0].path.read_bytes() == APK
    assert proxy.counts["/app.apk"] == 1
    assert "browser_subresource_network_error" in result.gaps


def test_failed_side_resource_without_package_stays_failed(run_capture):
    result, _events = run_capture("/closed-no-package")
    assert result.outcome == "failed" and result.reason_code == "browser_network_error"
    assert result.coverage == "partial" and not result.artifacts


@pytest.mark.parametrize("path,side", [("/download-side-script", "/side-script.js"), ("/download-side-xhr", "/side-api")])
def test_failed_side_resource_during_package_stream_does_not_cancel_or_retry(run_capture, proxy, path, side):
    result, events = run_capture(path)
    assert result.outcome == "downloaded", result
    assert result.artifacts[0].path.read_bytes() == APK
    # Chrome may retry a connection closed without headers internally. The
    # capturer must issue only the original browser request and never replay it.
    assert 1 <= proxy.counts[side] <= 2 and proxy.counts["/slow-package.apk"] == 1
    assert sum(event["event"] == "request" and event["url"].endswith(side) for event in events) == 1
    assert "browser_subresource_network_error" in result.gaps
    assert any(row.get("deferred_network_error") for row in result.responses)


@pytest.mark.parametrize("path", ["/required-script", "/required-api", "/api-fallback"])
def test_http_subresource_error_allows_page_download_fallback(run_capture, proxy, path):
    result, _events = run_capture(path)
    assert result.outcome == "downloaded", result
    assert result.artifacts[0].path.read_bytes() == APK and proxy.counts["/app.apk"] == 1
    assert "browser_subresource_http_error" in result.gaps
    assert any(row.get("deferred_http_error") for row in result.responses)


@pytest.mark.parametrize("path,outcome,reason", [
    ("/api-no-download", "failed", "browser_http_error"),
    ("/script-no-download", "failed", "browser_http_error"),
    ("/api-blocked-no-download", "blocked", "http_access_control"),
])
def test_http_subresource_without_download_preserves_error(run_capture, proxy, path, outcome, reason):
    result, _events = run_capture(path)
    assert (result.outcome, result.reason_code, result.coverage) == (outcome, reason, "partial"), result
    assert not result.artifacts and proxy.counts["/app.apk"] == 0


def test_optional_failure_without_package_remains_unknown(run_capture):
    result, _events = run_capture("/no-package-optional")
    assert result.outcome == "failed" and result.coverage == "partial"
    assert "browser_optional_resource_http_error" in result.gaps


def test_runtime_exception_is_private_observation_and_download_continues(run_capture, tmp_path):
    result, events = run_capture("/runtime-error")
    assert result.outcome == "downloaded" and result.artifacts[0].path.read_bytes() == APK
    content = (tmp_path / "capture" / "runtime-diagnostic.json").read_text()
    assert json.loads(content)["exceptions"][0]["category"] == "webgl_unavailable"
    assert "private-secret" not in content
    assert not any("runtime" in event.get("event", "") for event in events)


def test_slow_script_gets_render_time_after_body_is_fulfilled(run_capture, proxy, monkeypatch):
    monkeypatch.setattr(browser_capture, "MAX_NO_PROGRESS_SECONDS", 2.0)
    result, _events = run_capture("/slow-script-page", limits=Limits(chain_timeout=20, read_timeout=10))
    assert result.outcome == "downloaded", result
    assert result.artifacts[0].path.read_bytes() == APK
    assert proxy.counts["/slow-script.js"] == 1 and proxy.counts["/app.apk"] == 1


@pytest.mark.parametrize("path,reason", [
    ("/heartbeat-page", "browser_dynamic_incomplete"),
    ("/heartbeat-http-error", "browser_http_error"),
])
def test_repeated_heartbeat_stops_without_waiting_for_task_timeout(run_capture, proxy, monkeypatch, path, reason):
    monkeypatch.setattr(browser_capture, "MAX_NO_PROGRESS_SECONDS", 2.0)
    start = time.monotonic()
    result, _events = run_capture(path, limits=Limits(chain_timeout=20, read_timeout=3))
    assert time.monotonic() - start < 10
    assert result.outcome == "failed" and result.reason_code == reason
    assert "browser_no_progress" in result.gaps and not result.artifacts
    assert proxy.counts["/heartbeat"] >= 3


@pytest.mark.parametrize("with_journal", [False, True], ids=["plain", "package-journal-sdk"])
def test_navigation_discards_old_image_without_failing_new_download(run_capture, proxy, monkeypatch, tmp_path, with_journal):
    original = CDPMux.send
    discarded = []

    async def delayed(self, session, method, params=None):
        old_image = method == "Fetch.fulfillRequest" and (params or {}).get("body") == base64.b64encode(b"synthetic-stale-image").decode()
        if old_image:
            await asyncio.sleep(1)
            # Deterministically end the synthetic image interception while a
            # navigation is pending; Chrome then rejects fulfillment itself.
            await original(self, session, "Fetch.failRequest", {
                "requestId": params["requestId"], "errorReason": "Aborted",
            })
        try:
            return await original(self, session, method, params)
        except CDPCommandError as error:
            if old_image:
                discarded.append(error.category)
            raise

    monkeypatch.setattr(CDPMux, "send", delayed)
    payload = synthetic_sdk_payload() if with_journal else APK
    proxy.payload = payload
    journal = EvidenceJournal(tmp_path / "package-observations.jsonl", "browser", "package-resource-sdk") if with_journal else None
    try:
        result, _events = run_capture("/stale-image-page", purpose="package", journal=journal)
    finally:
        if journal is not None:
            journal.close()
    assert discarded == ["interception_gone"]
    assert result.outcome == "downloaded" and result.artifacts[0].path.read_bytes() == payload, result
    assert proxy.counts["/stale-image.png"] == proxy.counts["/app.apk"] == 1
    assert "browser_resource_interception_expired" in result.gaps
    assert any(row.get("delivered_to_browser") is False for row in result.bodies)
    if journal is not None:
        assert_package_journal(journal, ("/stale-image-page", "/stale-image.png", "/stale-image-next", "/app.apk"))


@pytest.mark.parametrize("path,outcome", [("/expired-dispatch", "downloaded"), ("/expired-package-dispatch", "failed")])
def test_already_cancelled_interception_skips_only_decorative_requests(run_capture, proxy, monkeypatch, path, outcome):
    original = CDPMux.__init__
    cancelled = []

    def init(self, process, handler, check, command_timeout):
        def observe(session, method, data):
            url = data.get("request", {}).get("url", "")
            if method == "Fetch.requestPaused" and urlsplit(url).path in {"/cancelled-side.png", "/cancelled.apk"} and "responseStatusCode" not in data:
                async def discard():
                    await self.send(session, "Fetch.failRequest", {"requestId": data["requestId"], "errorReason": "Aborted"})
                    cancelled.append(url)
                    handler(session, method, data)
                asyncio.create_task(discard())
            else:
                handler(session, method, data)
        original(self, process, observe, check, command_timeout)

    monkeypatch.setattr(CDPMux, "__init__", init)
    result, _events = run_capture(path)
    assert result.outcome == outcome and len(cancelled) == 1, result
    assert proxy.counts["/cancelled-side.png"] == proxy.counts["/cancelled.apk"] == 0
    if outcome == "downloaded":
        assert result.artifacts[0].path.read_bytes() == APK and proxy.counts["/app.apk"] == 1
        assert any(row.get("request_cancelled") for row in result.responses)
    else:
        assert result.reason_code == "browser_cdp_failed" and not result.artifacts
