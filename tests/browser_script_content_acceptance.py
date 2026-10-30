"""Real Chrome against a local synthetic proxy; no external targets."""

import base64
import threading
from urllib.parse import urlsplit

import pytest
from browser_capture_acceptance import (
    APK,
    PNG,
    Handler,
    SyntheticProxy,
    assert_package_journal,
    synthetic_sdk_payload,
)
from browser_capture_acceptance import run_capture as capture_fixture

from fxfetch.core.web_journal import EvidenceJournal

run_capture = capture_fixture


class ContentHandler(Handler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.hostname != "capture.test":
            return super().do_GET()
        path = parsed.path
        entries = {
            "/script-gate": "fetch('/content.html',{method:'GET',headers:{Accept:'text/html'}})",
            "/script-denied": "fetch('/denied.html')",
            "/script-loop": "fetch('/loop.html')",
            "/script-multiple": "fetch('/one.html');fetch('/two.html')",
            "/script-post": "fetch('/content.html',{method:'POST'})",
            "/script-private": "fetch('http://127.0.0.1/private.html')",
        }
        if path in entries:
            self.server.counts[path] += 1
            page = ('<link rel="icon" href="data:,"><p>Please verify you are human</p>'
                    '<div class="captcha"><button>Verify</button></div>'
                    '<script>async function gated(){fetch("/function-called");await ' + entries[path] + ';}</script>')
            self.respond(200, page.encode(), extra={"Set-Cookie": "fx_gate=1; Path=/"})
        elif path == "/content.html":
            self.server.counts[path] += 1
            if "fx_gate=1" not in self.headers.get("Cookie", ""):
                return self.respond(403, b"Cookie required")
            page = (b'<link rel="icon" href="data:,"><img src="data:image/png;base64,' +
                    base64.b64encode(PNG + b"\0" * 70_000) +
                    b'"><a hidden href="/content-package.apk?ticket=once">APK</a>')
            self.respond(200, page,
                         extra={"Content-Disposition": 'attachment; filename="content.html"'})
        elif path == "/content-package.apk":
            self.server.counts[path] += 1
            allowed = "fx_gate=1" in self.headers.get("Cookie", "") and self.server.counts[path] == 1
            self.respond(200 if allowed else 403, self.server.payload if allowed else b"Ticket invalid", "application/vnd.android.package-archive")
        elif path == "/denied.html":
            self.server.counts[path] += 1
            self.respond(403, b"Verification required")
        elif path == "/loop.html":
            self.server.counts[path] += 1
            self.respond(200, b'<link rel="icon" href="data:,"><script>function more(){fetch("/loop.html")}</script>')
        else:
            return super().do_GET()


@pytest.fixture
def proxy():
    server = SyntheticProxy()
    server.RequestHandlerClass = ContentHandler
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.stopped.set()
        server.shutdown()
        server.server_close()
        thread.join(2)


@pytest.mark.parametrize("with_journal", [False, True], ids=["plain", "package-journal-sdk"])
def test_disclosed_content_chain_preserves_cookie_and_single_use_package(run_capture, proxy, tmp_path, with_journal):
    payload = synthetic_sdk_payload() if with_journal else APK
    proxy.payload = payload
    journal = EvidenceJournal(tmp_path / "package-observations.jsonl", "browser", "package-content-sdk") if with_journal else None
    try:
        result, events = run_capture("/script-gate", purpose="package", journal=journal)
    finally:
        if journal is not None:
            journal.close()
    assert result.outcome == "downloaded" and result.artifacts[0].path.read_bytes() == payload, result
    assert proxy.counts["/content.html"] == proxy.counts["/content-package.apk"] == 1
    assert proxy.counts["/function-called"] == 0
    assert "page_challenge_observed" in result.gaps
    assert any(row.get("disposition_handling") == "inline_disclosed_html" for row in result.bodies)
    assert any(row.get("continuation") == "explicit_script_content_link" and row.get("verification_passed") is False
               for row in events)
    assert any(row.get("mechanism") == "script_content_link" and row.get("same_browser_session") for row in events)
    if journal is not None:
        assert_package_journal(journal, ("/script-gate", "/content.html", "/content-package.apk"),
                               allow_inline_url_omission=True)


@pytest.mark.parametrize("path,reason", [
    ("/script-denied", "http_access_control"),
    ("/script-loop", "browser_content_loop"),
    ("/script-multiple", "candidate_selection_required"),
    ("/script-post", "challenge_detected"),
    ("/script-private", "challenge_detected"),
])
def test_disclosed_content_does_not_override_guards_or_ambiguity(run_capture, proxy, path, reason):
    result, _events = run_capture(path)
    assert result.reason_code == reason and not result.artifacts, result
    assert proxy.counts["/function-called"] == proxy.counts["/content-package.apk"] == 0
    assert proxy.counts["/one.html"] == proxy.counts["/two.html"] == 0
    if path == "/script-loop":
        assert proxy.counts["/loop.html"] == 1
