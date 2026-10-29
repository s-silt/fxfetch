"""Explicit real-Chrome acceptance using a synthetic loopback-only proxy.

Run: python -m pytest -q tests/browser_capture_acceptance.py
Never contacts an external target, installs a browser or executes an APK.
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import io
import json
import os
import threading
import time
import zipfile
from collections import Counter
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import qrcode
from PIL import Image
from playwright.async_api import async_playwright

from fxfetch.core.browser_capture import BrowserLaunchProof, capture_browser
from fxfetch.core.limits import Limits


def package() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("AndroidManifest.xml", b"synthetic-manifest")
        archive.writestr("classes.dex", b"dex\n035\0" + bytes(range(256)) * 1024)
    return output.getvalue()


APK = package()


def permit_synthetic_request(url: str, method: str) -> None:
    # This fixture's proxy has no upstream; explicitly bind the callback to
    # its two fixed synthetic origins instead of adding a production bypass.
    if urlsplit(url).hostname not in {"capture.test", "frame.test"} or method not in {"GET", "HEAD", "POST", "OPTIONS"}:
        raise AssertionError("Request left the fixed synthetic fixture")


def png_bytes(image):
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


PNG = png_bytes(Image.new("RGB", (32, 24), "blue"))
QR = png_bytes(qrcode.make("http://capture.test/single?ticket=once"))
QR_A = png_bytes(qrcode.make("http://capture.test/a.apk"))
QR_B = png_bytes(qrcode.make("http://capture.test/b.apk"))


class SyntheticProxy(ThreadingHTTPServer):
    daemon_threads = True
    counts: Counter[str]
    stopped: threading.Event
    package_started: threading.Event
    payload: bytes

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.counts = Counter()
        self.stopped = threading.Event()
        self.package_started = threading.Event()
        self.payload = APK


class Handler(BaseHTTPRequestHandler):
    server: SyntheticProxy
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        return

    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, ConnectionAbortedError):
            # Chrome teardown closes idle synthetic keep-alive connections.
            self.server.counts["expected_teardown_disconnect"] += 1

    def do_CONNECT(self):
        self.respond(403, b"Synthetic proxy never connects upstream", "text/plain")

    def respond(self, status, body, content_type="text/html", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.hostname not in {"capture.test", "frame.test"}:
            self.respond(403, b"No upstream permitted", "text/plain")
            return
        path = parsed.path
        self.server.counts[path] += 1
        pages = {
            "/js": b'<script>location.href="/app.apk"</script>',
            "/api-page": b'<script>fetch("/api").then(r=>r.json()).then(d=>location.href=d.url)</script>',
            "/click": b"<button onclick=\"location.href='/app.apk'\">Download Android</button>",
            "/popup": b"<button onclick=\"window.open('/child')\">Download Android</button>",
            "/child": b'<script>location.href="/app.apk"</script>',
            "/iframe": b'<iframe src="http://frame.test/frame"></iframe>',
            "/frame": b"<button onclick=\"location.href='/app.apk'\">Download Android</button>",
            "/empty": b"<p>Static synthetic content</p>",
            "/dom-hang": b"<p>Observed page</p><script>Object.defineProperty(document.documentElement,'outerHTML',{get(){while(true){}}});</script>",
            "/script-hang": b"<script>while(true){}</script>",
            "/element-hang": b"<button id='stuck'>Download</button><script>Object.defineProperty(document.querySelector('#stuck'),'innerText',{get(){while(true){}}});</script>",
            "/blob-worker": b"<script>new Worker(URL.createObjectURL(new Blob([\"fetch('/worker-body')\"],{type:'text/javascript'})))</script>",
            "/normal-worker": b"<script>new Worker('/worker.js')</script>",
            "/shared-worker": b"<script>new SharedWorker('/worker.js')</script>",
            "/budget-race": b"<p>" + b"x" * 8000 + b"</p><script>setTimeout(()=>fetch('/chunked.apk'),750)</script>",
            "/offline": b'<link rel="stylesheet" href="/style.css"><h1 id="title">Initial content</h1><img src="/image.png"><script src="/render.js"></script>',
            "/gzip-page": b'<script src="/gzip.js"></script>',
            "/large-script-page": b'<script src="/large.js"></script>',
            "/qr-page": b'<h1>Scan to download</h1><img src="/qr.png">',
            "/qr-multiple": b'<h1>Choose QR</h1><img src="/qr-a.png"><img src="/qr-b.png">',
            "/web-budget": b'<img src="/image.png"><img src="/image-two.png">',
            "/multiple": b'<a href="/a.apk">Download A</a><a href="/b.apk">Download B</a>',
            "/download-noise": b'<a href="/article.html">How to download the app?</a><a href="/category/">Download tutorials</a><a href="/download-noise">Download</a><a href="/app.apk" class="download-btn">Download</a>',
            "/duplicate-links": b'<a href="/app.apk">Download APK</a><a href="http://capture.test/app.apk">Android package</a><a href="/app.apk">Mirror</a>',
            "/base-links": b'<base href="http://frame.test/packages/"><a href="a.apk">Download A</a><a href="b.apk">Download B</a>',
            "/dom-shrinks": b'''<div id="mount"><button id="initial">Loading</button><button>Placeholder</button><button>Placeholder</button></div>
                <script>Object.defineProperty(document.querySelector('#initial'),'innerText',{get(){
                  document.querySelector('#mount').innerHTML='<a href="/app.apk">Download APK</a>';
                  return 'Loading';
                }});</script>''',
            "/form": b'<form action="/business"><button>Download and register</button></form>',
            "/blob": b"<button onclick=\"let a=document.createElement('a');a.href=URL.createObjectURL(new Blob(['x']));a.download='x.apk';a.click()\">Download Android</button>",
        }
        if path in {"/div-download", "/span-download", "/onclick-download"}:
            control = {
                "/div-download": '<div class="button_install">下载安装</div>',
                "/span-download": '<span class="download-btn">下载并安装</span>',
                "/onclick-download": '<div onclick="location.href=\'/app.apk\'">立即下载</div>',
            }[path]
            pages[path] = ('''<meta charset="utf-8"><div class="download-area">CONTROL
                <div class="android_install_ques noise">安卓安装说明</div>
                <span class="install_ques_button noise">安装说明</span>
                <div class="download-link noise">http://capture.test/a.apk</div>
                <div class="download-btn noise">下载帮助</div>
                <div class="button noise">下载安装教程</div>
                <span class="btn noise">联系客服</span>
                <div class="button_install noise">下载并注册</div>
                <a class="source" href="/unused" style="display:none"></a>
                </div><script>
                document.querySelectorAll('.noise').forEach(e=>e.onclick=()=>fetch('/unexpected-action'));
                const control=document.querySelector('.download-area').firstElementChild;
                if(!control.hasAttribute('onclick'))control.addEventListener('click',()=>location.href='/app.apk');
                </script>'''.replace("CONTROL", control)).encode()
        elif path == "/div-dom-shrinks":
            pages[path] = '''<meta charset="utf-8"><div id="mount"><button id="initial">Loading</button><button>Placeholder</button></div>
                <script>Object.defineProperty(document.querySelector('#initial'),'innerText',{get(){
                document.querySelector('#mount').innerHTML='<div class="button_install">下载安装</div>';
                document.querySelector('.button_install').onclick=()=>location.href='/app.apk';return 'Loading';
                }});</script>'''.encode()
        elif path == "/div-candidate-limit":
            pages[path] = b'<div class="button_install">Download</div>' * 30
        elif path in {"/temporary-overlay", "/persistent-overlay"}:
            pages[path] = b'''<button onclick="location.href='/app.apk'">Download APK</button>
                <div id="cover" style="position:fixed;inset:0;z-index:100;background:white">Loading</div>'''
            if path == "/temporary-overlay":
                pages[path] += b"<script>setTimeout(()=>document.querySelector('#cover').remove(),4000)</script>"
        if path in {"/device-denied", "/device-passed", "/device-hidden-denial", "/device-denied-link"}:
            rejected = "true" if path != "/device-passed" else "false"
            hidden = ' style="display:none"' if path == "/device-hidden-denial" else ""
            pages[path] = (f'<p id="status"{hidden}></p><script>'
                "const probes=['navigator.webdriver','WEBGL_debug_renderer_info','UNMASKED_RENDERER_WEBGL'];"
                f"function rejected(){{return {rejected};}}"
                "function grade(){return 100;}const threshold=60;"
                "function allowed(){if(rejected()) return false;return grade()>=threshold;}"
                "async function content(){await fetch('/device-content');location.href='/app.apk';}"
                "window.onload=function(){if(allowed()){content();return;}"
                "document.querySelector('#status').textContent='Synthetic device denied';};"
                "</script>").encode()
            if path == "/device-denied-link":
                pages[path] += b'<a href="/app.apk" hidden></a>'
        if path == "/hidden-file-link":
            pages[path] = b'''<script>window.onload=()=>{
                document.body.innerHTML='<a href="/single.apk?ticket=once" hidden></a><a href="http://capture.test/single.apk?ticket=once" hidden></a>';
                };</script><body></body>'''
        elif path == "/hidden-file-multiple":
            pages[path] = b'<a href="/a.apk" hidden></a><a href="/b.apk" hidden></a>'
        elif path in {"/hidden-file-challenge", "/hidden-file-challenge-403", "/challenge-only", "/hidden-file-challenge-multiple"}:
            pages[path] = b'<p>Please verify you are human</p><div class="captcha"><button>Verify</button></div>'
            if path == "/hidden-file-challenge":
                pages[path] += b'<a href="/app.apk" hidden></a>'
            elif path == "/hidden-file-challenge-403":
                pages[path] += b'<a href="/blocked.apk" hidden></a>'
            elif path == "/hidden-file-challenge-multiple":
                pages[path] += b'<a href="/a.apk" hidden></a><a href="/b.apk" hidden></a>'
        elif path == "/hidden-only-ipa":
            pages[path] = b'<a href="/app.ipa" hidden></a><p>Other platform</p>'
        if path in pages:
            headers = (
                {"Set-Cookie": "synthetic=session; Path=/; SameSite=Lax"}
                if path in {"/api-page", "/qr-page", "/hidden-file-link"}
                else None
            )
            if path == "/gzip-page":
                self.respond(200, gzip.compress(pages[path]), extra={"Content-Encoding": "gzip"})
            else:
                self.respond(200, pages[path], extra=headers)
        elif path == "/large.js":
            self.respond(
                200,
                b"/*" + b"x" * (9 * 1024 * 1024) + b"*/location.href='/app.apk';",
                "application/javascript",
            )
        elif path in {"/style.css", "/render.js", "/gzip.js"}:
            content = {
                "/style.css": b"h1{color:#123456}",
                "/render.js": b"document.querySelector('#title').textContent='Rendered synthetic offline content';",
                "/gzip.js": b"location.href='/app.apk';",
            }[path]
            self.respond(
                200,
                gzip.compress(content),
                "text/css" if path.endswith(".css") else "application/javascript",
                {"Content-Encoding": "gzip"},
            )
        elif path in {"/image.png", "/image-two.png", "/qr.png", "/qr-a.png", "/qr-b.png"}:
            content = {"/qr.png": QR, "/qr-a.png": QR_A, "/qr-b.png": QR_B}.get(path, PNG)
            self.respond(200, content, "image/png")
        elif path == "/worker.js":
            self.respond(200, b"fetch('/worker-body')", "application/javascript")
        elif path == "/worker-body":
            self.respond(200, b"Worker network must not be allowed", "application/octet-stream")
        elif path == "/device-content":
            self.respond(200, b"{}", "application/json")
        elif path == "/api":
            if self.headers.get("Cookie") != "synthetic=session":
                self.respond(403, b"Missing session")
            else:
                self.respond(200, json.dumps({"url": "/single?ticket=once"}).encode(), "application/json")
        elif path in {"/single", "/single.apk"}:
            if (
                self.headers.get("Cookie") != "synthetic=session"
                or parsed.query != "ticket=once"
                or self.server.counts[path] != 1
            ):
                self.respond(403, b"Missing session or consumed ticket")
            else:
                self.respond(200, self.server.payload, "application/octet-stream")
        elif path in {"/app.apk", "/a.apk", "/b.apk", "/declared.apk"}:
            self.server.package_started.set()
            self.respond(200, APK, "application/octet-stream")
        elif path == "/truncated.apk":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(APK) + 500))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(APK[:200])
            self.wfile.flush()
            self.close_connection = True
        elif path in {"/chunked.apk", "/stall.apk", "/chunked.html"}:
            self.send_response(200)
            self.send_header(
                "Content-Type", "text/html" if path.endswith(".html") else "application/octet-stream"
            )
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.server.package_started.set()
            if path == "/stall.apk":
                self.server.stopped.wait(10)
                self.close_connection = True
                return
            try:
                for start in range(0, len(APK), 8192):
                    block = APK[start : start + 8192]
                    self.wfile.write(f"{len(block):X}\r\n".encode() + block + b"\r\n")
                    self.wfile.flush()
                    time.sleep(0.005)
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                self.close_connection = True
        elif path == "/redirect":
            self.respond(302, b"", extra={"Location": "/app.apk"})
        elif path in {"/blocked", "/blocked.apk"}:
            self.respond(403, b"Synthetic access control")
        elif path == "/favicon.ico":
            self.respond(204, b"", "image/x-icon")
        else:
            self.respond(404, b"Missing synthetic route")


@pytest.fixture
def proxy():
    server = SyntheticProxy()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.stopped.set()
        server.shutdown()
        server.server_close()
        thread.join(2)


@pytest.fixture
def run_capture(proxy, tmp_path):
    chrome = Path(
        os.environ.get("FXFETCH_TEST_CHROME", r"C:\Program Files\Google\Chrome\Application\chrome.exe")
    )
    if not chrome.is_file():
        pytest.skip("Installed Chrome required; no browser is downloaded")

    class LocalSyntheticLease:
        def verify_before_launch(self):
            return BrowserLaunchProof(
                chrome,
                tmp_path / "profile",
                f"http://127.0.0.1:{proxy.server_port}",
                ("--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",),
                permit_request=permit_synthetic_request,
            )

    def run(path, *, limits=None, cancel=None):
        events = []
        result = asyncio.run(
            capture_browser(
                f"http://capture.test{path}",
                tmp_path / "capture",
                cancel or threading.Event(),
                lease=LocalSyntheticLease(),
                limits=limits or Limits(chain_timeout=12, read_timeout=3),
                on_event=events.append,
            )
        )
        assert not list((tmp_path / "profile").rglob("*.crdownload"))
        assert not list((tmp_path / "profile").rglob("*.apk"))
        return result, events

    return run


@pytest.mark.parametrize("path", ["/js", "/click", "/popup", "/iframe", "/redirect"])
def test_browser_acquires_original_package(run_capture, proxy, path):
    result, events = run_capture(path)
    assert result.outcome == "downloaded", (result, events)
    assert result.coverage == "complete" and not result.gaps
    assert result.artifacts[0].path.read_bytes() == APK
    assert result.artifacts[0].sha256 == hashlib.sha256(APK).hexdigest()
    assert proxy.counts["/app.apk"] == 1
    assert any(row["event"] == "file_verified" for row in events)


def test_js_api_cookie_and_one_time_ticket_are_not_replayed(run_capture, proxy):
    result, events = run_capture("/api-page")
    assert result.outcome == "downloaded", (result, events)
    assert result.artifacts[0].path.read_bytes() == APK
    assert proxy.counts["/api-page"] == proxy.counts["/api"] == proxy.counts["/single"] == 1


@pytest.mark.parametrize("path", ["/declared.apk", "/chunked.apk"])
def test_byte_limit_is_applied_before_native_disk_download(run_capture, path):
    result, events = run_capture(path, limits=replace(Limits(), max_package_bytes=32_768, chain_timeout=12))
    assert result.outcome == "failed" and result.reason_code == "download_limit", (result, events)
    assert not result.artifacts
    assert all(item["size"] <= 32_768 for item in result.partials)
    assert all(Path(str(item["path"])).stat().st_size <= 32_768 for item in result.partials)


def test_cancel_stalled_stream_is_prompt_and_not_success(run_capture, proxy):
    cancel = threading.Event()

    def stop():
        if proxy.package_started.wait(5):
            time.sleep(0.15)
            cancel.set()

    worker = threading.Thread(target=stop, daemon=True)
    worker.start()
    started = time.monotonic()
    result, _ = run_capture("/stall.apk", cancel=cancel)
    worker.join(1)
    assert result.reason_code == "cancelled", result
    assert not result.artifacts and time.monotonic() - started < 6


def test_stalled_response_has_a_read_timeout(run_capture):
    result, _ = run_capture("/stall.apk", limits=replace(Limits(), chain_timeout=12, read_timeout=0.7))
    assert result.reason_code == "browser_read_timeout", result
    assert not result.artifacts


@pytest.mark.parametrize("path", ["/dom-hang", "/script-hang", "/element-hang"])
def test_hostile_page_execution_obeys_read_deadline(run_capture, path):
    started = time.monotonic()
    result, _ = run_capture(path, limits=replace(Limits(), chain_timeout=8, read_timeout=0.7))
    assert result.reason_code == "browser_read_timeout", result
    assert not result.artifacts and time.monotonic() - started < 6


def test_hostile_dom_snapshot_remains_cancellable(run_capture, proxy):
    cancel = threading.Event()

    def stop():
        end = time.monotonic() + 5
        while not proxy.counts["/dom-hang"] and time.monotonic() < end:
            time.sleep(0.02)
        time.sleep(1.2)
        cancel.set()

    stopper = threading.Thread(target=stop, daemon=True)
    stopper.start()
    started = time.monotonic()
    result, _ = run_capture("/dom-hang", cancel=cancel, limits=replace(Limits(), chain_timeout=8, read_timeout=5))
    stopper.join(1)
    assert result.reason_code == "cancelled" and not result.artifacts, result
    assert time.monotonic() - started < 6


@pytest.mark.parametrize("path", ["/blob-worker", "/normal-worker", "/shared-worker"])
def test_uncovered_workers_are_rejected_before_their_fetch(run_capture, proxy, path):
    result, _ = run_capture(path)
    assert result.reason_code == "browser_worker_scope_unsupported", result
    assert result.outcome == "failed" and result.coverage == "partial" and not result.artifacts
    assert proxy.counts["/worker-body"] == 0


def test_dom_save_during_pending_stream_read_cannot_overrun_task_budget(run_capture, monkeypatch):
    from playwright.async_api import Page

    from fxfetch.core.cdp_transport import CDPMux

    original_send = CDPMux.send
    original_evaluate = Page.evaluate
    read_ready = asyncio.Event()
    reads = 0
    suspended = False

    async def delayed_read(self, session, method, params=None):
        nonlocal reads, suspended
        response = await original_send(self, session, method, params)
        if method == "IO.read":
            reads += 1
            if reads == 2:
                suspended = True
                read_ready.set()
                # Deterministically expose a response already in transit while
                # the independently requested DOM snapshot consumes its budget.
                await asyncio.sleep(0.1)
        return response

    async def snapshot_after_read(self, expression, arg=None):
        text = await original_evaluate(self, expression, arg)
        if "TextEncoder" in expression:
            await asyncio.wait_for(read_ready.wait(), timeout=4)
        return text

    monkeypatch.setattr(CDPMux, "send", delayed_read)
    monkeypatch.setattr(Page, "evaluate", snapshot_after_read)
    maximum = 17_300
    result, _ = run_capture("/budget-race", limits=replace(
        Limits(), max_task_bytes=maximum, chain_timeout=12, read_timeout=5,
    ))
    assert suspended and any(body["purpose"] == "browser_rendered_dom" for body in result.bodies)
    assert result.reason_code == "download_limit" and not result.artifacts, result
    observed = sum(item["size"] for item in result.bodies) + sum(item["size"] for item in result.partials)
    assert observed <= maximum


def test_real_gateway_accepts_only_observed_browser_request_permits(tmp_path):
    from android_browser_acceptance import origin, test_gate

    chrome = Path(os.environ.get("FXFETCH_TEST_CHROME", r"C:\Program Files\Google\Chrome\Application\chrome.exe"))
    if not chrome.is_file():
        pytest.skip("Installed Chrome required; no browser is downloaded")
    cancel = threading.Event()
    permitted = []
    identity = "d" * 32
    with origin() as server:
        gate = test_gate(server.server_port, cancel)
        gate.port = 0
        with gate as gateway:
            class GuardedSyntheticLease:
                def verify_before_launch(self):
                    gateway.arm(identity)

                    def permit(url, method):
                        gateway.permit_request(identity, url, method)
                        permitted.append((url, method))

                    return BrowserLaunchProof(
                        chrome, tmp_path / "profile", f"http://127.0.0.1:{gateway.port}",
                        ("--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",),
                        permit_request=permit,
                    )

            result = asyncio.run(capture_browser(
                "http://capture.test/api-page", tmp_path / "capture", cancel,
                lease=GuardedSyntheticLease(), limits=replace(Limits(), chain_timeout=20, read_timeout=5),
            ))
            assert result.outcome == "downloaded", (result, gateway.errors)
            assert result.artifacts[0].sha256 == hashlib.sha256(APK).hexdigest()
            assert all(server.counts[path] == 1 for path in ("/api-page", "/api", "/single"))
            assert all((url, "GET") in permitted for url in (
                "http://capture.test/api-page", "http://capture.test/api", "http://capture.test/single?ticket=once"
            ))


def test_missing_request_permit_issuer_fails_before_browser_launch(tmp_path):
    from fxfetch.core.errors import FxfetchError

    class NoPermitLease:
        def verify_before_launch(self):
            return BrowserLaunchProof(tmp_path / "not-a-browser", tmp_path / "profile", "http://127.0.0.1:9")

    with pytest.raises(FxfetchError, match="permission callback") as error:
        asyncio.run(capture_browser(
            "http://capture.test/empty", tmp_path / "capture", threading.Event(), lease=NoPermitLease()
        ))
    assert error.value.code == "browser_guard_unavailable"


def test_chain_deadline_is_distinct(run_capture):
    result, _ = run_capture("/stall.apk", limits=replace(Limits(), chain_timeout=2.5, read_timeout=10))
    assert result.reason_code == "chain_timeout", result
    assert not result.artifacts


def test_truncated_body_is_never_downloaded(run_capture):
    result, _ = run_capture("/truncated.apk")
    assert result.outcome == "failed" and not result.artifacts
    assert result.reason_code in {"browser_cdp_failed", "length_mismatch", "browser_network_error"}


@pytest.mark.parametrize(
    "path,reason",
    [
        ("/blocked", "http_access_control"),
        ("/multiple", "candidate_selection_required"),
        ("/empty", "browser_dynamic_incomplete"),
        ("/form", "browser_dynamic_incomplete"),
        # With behavior=deny Chrome 156 can suppress download events entirely.
        # This is an unresolved scope, never evidence of no package.
        ("/blob", "browser_dynamic_incomplete"),
    ],
)
def test_unresolved_scope_never_becomes_no_package(run_capture, proxy, path, reason):
    result, _ = run_capture(path)
    assert result.reason_code == reason, result
    assert result.outcome in {"failed", "blocked"} and result.coverage == "partial"
    assert not result.artifacts and proxy.counts["/business"] == 0
    assert proxy.counts["/a.apk"] == proxy.counts["/b.apk"] == 0


def test_request_budget_denies_the_next_request_before_dispatch(run_capture, proxy):
    result, _ = run_capture("/js", limits=replace(Limits(), max_requests=1, chain_timeout=12))
    assert result.reason_code == "request_limit", result
    assert proxy.counts["/app.apk"] == 0


def test_existing_loopback_cdp_endpoint_preserves_cookie_request(proxy, tmp_path):
    chrome = Path(
        os.environ.get("FXFETCH_TEST_CHROME", r"C:\Program Files\Google\Chrome\Application\chrome.exe")
    )
    if not chrome.is_file():
        pytest.skip("Installed Chrome required")

    async def run():
        profile = tmp_path / "remote-profile"
        async with async_playwright() as driver:
            original = await driver.chromium.launch_persistent_context(
                str(profile),
                executable_path=str(chrome),
                headless=True,
                accept_downloads=False,
                service_workers="block",
                proxy={"server": f"http://127.0.0.1:{proxy.server_port}"},
                args=[
                    "--remote-debugging-port=0",
                    "--remote-debugging-address=127.0.0.1",
                    "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
                ],
            )
            port = (profile / "DevToolsActivePort").read_text().splitlines()[0]

            class RemoteSyntheticLease:
                def verify_before_launch(self):
                    return BrowserLaunchProof(
                        chrome, profile, "unused-for-remote", cdp_endpoint=f"http://127.0.0.1:{port}",
                        permit_request=permit_synthetic_request,
                    )

            try:
                return await capture_browser(
                    "http://capture.test/api-page",
                    tmp_path / "capture",
                    threading.Event(),
                    lease=RemoteSyntheticLease(),
                    limits=Limits(chain_timeout=12, read_timeout=3),
                )
            finally:
                await original.close()

    result = asyncio.run(run())
    assert result.outcome == "downloaded", result
    assert result.artifacts[0].path.read_bytes() == APK
    assert proxy.counts["/single"] == 1


@pytest.mark.parametrize("run_number", range(3))
def test_popup_capture_is_ready_before_autonavigation(run_capture, proxy, run_number):
    result, events = run_capture("/popup")
    assert result.outcome == "downloaded", (run_number, result, events)
    assert proxy.counts["/app.apk"] == 1
    assert result.artifacts[0].path.read_bytes() == APK


def test_real_sdk_generated_synthetic_apk_uses_the_original_request(run_capture, proxy):
    value = os.environ.get("FXFETCH_SYNTHETIC_SDK_APK")
    if not value:
        pytest.skip("Optional independently built synthetic SDK package is not configured")
    payload = Path(value).read_bytes()
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        assert archive.read("AndroidManifest.xml").startswith(b"\x03\x00\x08\x00")
        assert archive.read("classes.dex").startswith(b"dex\n")
        assert any(
            b"entry.synthetic.test" in archive.read(name)
            for name in archive.namelist()
            if name.startswith("assets/") and not name.endswith("/")
        )
    proxy.payload = payload
    result, events = run_capture("/api-page")
    assert result.outcome == "downloaded", (result, events)
    assert result.artifacts[0].path.read_bytes() == payload
    assert result.artifacts[0].sha256 == hashlib.sha256(payload).hexdigest()
    assert proxy.counts["/api-page"] == proxy.counts["/api"] == proxy.counts["/single"] == 1


def test_gzip_html_and_script_are_fulfilled_as_decoded_bytes(run_capture, proxy):
    result, events = run_capture("/gzip-page")
    assert result.outcome == "downloaded", (result, events)
    assert proxy.counts["/gzip-page"] == proxy.counts["/gzip.js"] == proxy.counts["/app.apk"] == 1
    script = next(item for item in result.bodies if str(item["url"]).endswith("/gzip.js"))
    assert Path(str(script["path"])).read_bytes() == b"location.href='/app.apk';"
    assert script["hash_scope"] == "browser_response_decoded"


def test_rendered_dom_and_loaded_resources_build_offline_without_refetch(run_capture, proxy):
    result, events = run_capture("/offline")
    assert result.outcome == "failed" and result.coverage == "partial", (result, events)
    assert result.offline["available"], result
    markup = Path(result.offline["entry"]).read_text("utf-8")
    assert "Rendered synthetic offline content" in markup
    assert "<script" not in markup
    assert any(
        "#123456" in Path(path).read_text("utf-8")
        for path in result.offline["files"]
        if Path(path).suffix == ".css"
    )
    assert any(Path(path).suffix == ".png" for path in result.offline["files"])
    assert (
        proxy.counts["/offline"]
        == proxy.counts["/style.css"]
        == proxy.counts["/render.js"]
        == proxy.counts["/image.png"]
        == 1
    )
    assert any(item["purpose"] == "browser_rendered_dom" for item in result.bodies)


def test_actual_loaded_qr_image_continues_in_original_cookie_session(run_capture, proxy):
    result, events = run_capture("/qr-page")
    assert result.outcome == "downloaded", (result, events)
    assert proxy.counts["/qr-page"] == proxy.counts["/qr.png"] == proxy.counts["/single"] == 1
    assert result.page_qr["status"] == "decoded"
    assert len(result.page_qr["sources"]) == 1
    assert result.candidates[0].url == "http://capture.test/single?ticket=once"
    assert any(item["event"] == "redirect" and item.get("mechanism") == "page_qr" for item in events)


def test_multiple_qr_links_are_returned_without_target_requests(run_capture, proxy):
    result, _ = run_capture("/qr-multiple")
    assert result.reason_code == "candidate_selection_required", result
    assert len(result.selection_candidates) == 2
    assert proxy.counts["/a.apk"] == proxy.counts["/b.apk"] == 0
    assert proxy.counts["/qr-a.png"] == proxy.counts["/qr-b.png"] == 1


def test_multiple_download_hrefs_are_returned_for_selection(run_capture, proxy):
    result, _ = run_capture("/multiple")
    assert result.reason_code == "candidate_selection_required"
    assert {candidate.url for candidate in result.selection_candidates} == {
        "http://capture.test/a.apk",
        "http://capture.test/b.apk",
    }
    assert proxy.counts["/a.apk"] == proxy.counts["/b.apk"] == 0


def test_rendered_hidden_file_href_preserves_session_and_is_not_replayed(run_capture, proxy):
    result, events = run_capture("/hidden-file-link")
    assert result.outcome == "downloaded", (result, events)
    assert proxy.counts["/single.apk"] == 1
    assert result.artifacts[0].path.read_bytes() == APK


def test_multiple_hidden_file_hrefs_require_selection_without_requests(run_capture, proxy):
    result, _ = run_capture("/hidden-file-multiple")
    assert result.reason_code == "candidate_selection_required", result
    assert len(result.selection_candidates) == 2
    assert proxy.counts["/a.apk"] == proxy.counts["/b.apk"] == 0


@pytest.mark.parametrize("path,code", [
    ("/hidden-file-challenge", "page_challenge_observed"),
    ("/device-denied-link", "page_device_verification_observed"),
])
def test_observed_gate_keeps_evidence_while_explicit_file_is_obtained(run_capture, proxy, path, code):
    result, events = run_capture(path)
    assert result.outcome == "downloaded", (result, events)
    assert proxy.counts["/app.apk"] == 1 and proxy.counts["/device-content"] == 0
    assert code in result.gaps
    assert any(row.get("page_observation") == code and row.get("verification") == "not_established"
               for row in result.responses)
    assert any(row["event"] == "challenge_detected" and row.get("verification_passed") is False
               for row in events)


def test_observed_challenge_without_file_href_remains_blocked(run_capture, proxy):
    result, _ = run_capture("/challenge-only")
    assert (result.outcome, result.reason_code) == ("blocked", "challenge_detected"), result
    assert "page_challenge_observed" in result.gaps
    assert proxy.counts["/app.apk"] == 0


def test_explicit_file_access_control_is_not_bypassed(run_capture, proxy):
    result, _ = run_capture("/hidden-file-challenge-403")
    assert (result.outcome, result.reason_code) == ("blocked", "http_access_control"), result
    assert not result.artifacts and proxy.counts["/blocked.apk"] == 1
    assert "page_challenge_observed" in result.gaps


def test_challenge_with_multiple_file_hrefs_still_requires_selection(run_capture, proxy):
    result, _ = run_capture("/hidden-file-challenge-multiple")
    assert result.reason_code == "candidate_selection_required", result
    assert len(result.selection_candidates) == 2 and "page_challenge_observed" in result.gaps
    assert proxy.counts["/a.apk"] == proxy.counts["/b.apk"] == 0


def test_android_explicit_href_priority_does_not_fall_back_to_ipa(run_capture, proxy):
    result, _ = run_capture("/hidden-only-ipa")
    assert not result.artifacts
    assert proxy.counts["/app.ipa"] == 0


@pytest.mark.parametrize("path", ["/download-noise", "/duplicate-links"])
def test_download_action_filtering_and_destination_deduplication(run_capture, proxy, path):
    result, events = run_capture(path)
    assert result.outcome == "downloaded", (result, events)
    assert proxy.counts["/app.apk"] == 1
    assert proxy.counts["/article.html"] == proxy.counts["/category/"] == 0
    assert sum(row["event"] == "download_action" for row in events) == 1


@pytest.mark.parametrize("path", ["/dom-shrinks", "/div-dom-shrinks"])
def test_dom_remount_during_interactive_scan_keeps_collecting(run_capture, proxy, path):
    result, events = run_capture(path)
    assert result.outcome == "downloaded", (result, events)
    assert proxy.counts["/app.apk"] == 1
    assert result.artifacts[0].path.read_bytes() == APK


@pytest.mark.parametrize("path", ["/div-download", "/span-download", "/onclick-download"])
def test_nonsemantic_download_control_uses_normal_handler_without_clicking_noise(run_capture, proxy, path):
    result, events = run_capture(path)
    assert result.outcome == "downloaded", (result, events)
    assert proxy.counts["/app.apk"] == 1
    assert proxy.counts["/unexpected-action"] == proxy.counts["/a.apk"] == 0
    assert sum(row["event"] == "download_action" for row in events) == 1


def test_nonsemantic_controls_share_candidate_budget(run_capture, proxy):
    result, _ = run_capture("/div-candidate-limit", limits=replace(Limits(), max_candidates=20))
    assert result.reason_code == "candidate_limit", result
    assert proxy.counts["/app.apk"] == 0


def test_normal_click_waits_for_temporary_overlay_to_disappear(run_capture, proxy):
    result, events = run_capture("/temporary-overlay", limits=replace(Limits(), chain_timeout=12, read_timeout=6))
    assert result.outcome == "downloaded", (result, events)
    assert proxy.counts["/app.apk"] == 1


def test_persistent_overlay_is_not_removed_or_force_clicked(run_capture, proxy):
    started = time.monotonic()
    result, _ = run_capture("/persistent-overlay", limits=replace(Limits(), chain_timeout=6, read_timeout=2))
    assert result.outcome == "failed"
    assert result.reason_code in {"browser_capture_failed", "browser_read_timeout"}
    assert proxy.counts["/app.apk"] == 0
    assert time.monotonic() - started < 8


def test_selection_resolves_links_using_document_base(run_capture, proxy):
    result, _ = run_capture("/base-links")
    assert result.reason_code == "candidate_selection_required", result
    assert {item.url for item in result.selection_candidates} == {
        "http://frame.test/packages/a.apk", "http://frame.test/packages/b.apk",
    }
    assert proxy.counts["/a.apk"] == proxy.counts["/b.apk"] == 0


def test_observed_device_rejection_does_not_invoke_protected_content(run_capture, proxy):
    result, _ = run_capture("/device-denied")
    assert (result.outcome, result.reason_code) == ("blocked", "device_verification_required"), result
    assert not result.artifacts
    assert proxy.counts["/device-content"] == proxy.counts["/app.apk"] == 0


def test_passed_device_gate_continues_normal_page_execution(run_capture, proxy):
    result, _ = run_capture("/device-passed")
    assert result.outcome == "downloaded", result
    assert proxy.counts["/device-content"] == proxy.counts["/app.apk"] == 1


def test_hidden_device_denial_is_not_claimed_as_observed_rejection(run_capture, proxy):
    result, _ = run_capture("/device-hidden-denial")
    assert result.reason_code == "browser_dynamic_incomplete", result
    assert result.outcome != "blocked"
    assert proxy.counts["/device-content"] == 0


@pytest.mark.parametrize(
    "path,limits,maximum",
    [
        ("/chunked.html", replace(Limits(), max_body_bytes=4096, chain_timeout=12), 4096),
        ("/web-budget", replace(Limits(), max_web_bytes=180, chain_timeout=12), 180),
    ],
)
def test_web_response_and_total_web_budgets_apply_to_streams(run_capture, path, limits, maximum):
    result, _ = run_capture(path, limits=limits)
    assert result.outcome == "failed" and result.reason_code == "browser_web_limit", result
    assert not result.artifacts
    written = sum(item["size"] for item in result.bodies if item["purpose"] == "browser_response")
    written += sum(item["size"] for item in result.partials)
    assert written <= maximum


def test_large_script_fulfillment_uses_separate_bounded_script_budget(run_capture, proxy):
    result, events = run_capture(
        "/large-script-page", limits=replace(Limits(), chain_timeout=25, read_timeout=3)
    )
    assert result.outcome == "downloaded", (result, events)
    script = next(item for item in result.bodies if str(item["url"]).endswith("/large.js"))
    assert 9 * 1024 * 1024 < script["size"] < 10 * 1024 * 1024
    assert proxy.counts["/large.js"] == proxy.counts["/app.apk"] == 1


def test_redirect_limit_rejects_the_next_hop_before_dispatch(run_capture, proxy):
    result, _ = run_capture("/redirect", limits=replace(Limits(), max_redirects=0, chain_timeout=12))
    assert result.reason_code == "redirect_limit", result
    assert proxy.counts["/app.apk"] == 0
