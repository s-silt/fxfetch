"""Real Chrome, synthetic no-upstream proxy: accessible button semantics."""

from __future__ import annotations

import json
import threading
from urllib.parse import urlsplit

import browser_capture_acceptance as synthetic
import pytest
from browser_capture_acceptance import APK
from browser_capture_acceptance import run_capture as run_capture

from fxfetch.core.limits import Limits

CONTROLS = {
    "/labels-get-apk": '<button onclick="location.href=\'/app.apk\'">Get APK</button>',
    "/labels-aria": '<button aria-label="Download APK" onclick="location.href=\'/app.apk\'">Android</button>',
    "/labels-value-aria": '<input type="button" value="Android" aria-label="Download APK" onclick="location.href=\'/app.apk\'">',
    "/labels-extra-aria": '<div class="download-btn" aria-label="Download APK" onclick="location.href=\'/app.apk\'">Android</div>',
    "/labels-two-downloads": '<button aria-label="Download APK" onclick="location.href=\'/app.apk\'">Download Android</button>',
}
BUSINESS_NOISE = """
<button aria-label="Download APK" onclick="fetch('/business')">登录</button>
<button aria-label="Download APK" onclick="fetch('/business')">注册</button>
<button aria-label="Download APK" onclick="fetch('/business')">付款</button>
<button aria-label="Download APK" onclick="fetch('/business')">Pay</button>
<button aria-label="Login" onclick="fetch('/business')">Download APK</button>
<form><button aria-label="Download APK" onclick="fetch('/business')">Android</button></form>
<div class="download-btn" aria-label="Download APK" onclick="fetch('/business')">下载帮助</div>
<div class="download-btn"><button aria-label="Download APK" onclick="fetch('/business')">登录</button></div>
<button aria-label="Download IPA" onclick="fetch('/business')">iPhone</button>
"""


class LabelHandler(synthetic.Handler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.hostname != "capture.test" or parsed.path not in {*CONTROLS, "/labels-business-only", "/labels-overlong"}:
            return super().do_GET()
        self.server.counts[parsed.path] += 1
        if parsed.path == "/labels-overlong":
            control = '<button aria-label="Download APK" onclick="fetch(\'/business\')">' + "x" * 256 + "登录</button>"
        else:
            control = CONTROLS.get(parsed.path, "")
        self.respond(200, ('<meta charset="utf-8"><link rel="icon" href="data:,">' + control + BUSINESS_NOISE).encode())


@pytest.fixture
def proxy(monkeypatch):
    monkeypatch.setattr(synthetic, "Handler", LabelHandler)
    server = synthetic.SyntheticProxy()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.stopped.set()
        server.shutdown()
        server.server_close()
        thread.join(2)


@pytest.mark.parametrize("path", list(CONTROLS))
def test_accessible_download_text_does_not_mask_business_controls(run_capture, proxy, tmp_path, path):
    result, events = run_capture(path, limits=Limits(chain_timeout=10, read_timeout=3))
    assert result.outcome == "downloaded", (result.reason_code, result.gaps)
    assert len(result.artifacts) == 1 and result.artifacts[0].path.read_bytes() == APK
    assert proxy.counts[path] == proxy.counts["/app.apk"] == 1
    assert proxy.counts["/business"] == 0
    assert sum(event["event"] == "download_action" and event.get("action") == "click" for event in events) == 1
    (tmp_path / "label-receipt.json").write_text(json.dumps({
        "passed": True, "case": path, "outcome": result.outcome,
        "package_sha256": result.artifacts[0].sha256, "counts": dict(proxy.counts),
    }, indent=2) + "\n")


@pytest.mark.parametrize("path", ["/labels-business-only", "/labels-overlong"])
def test_business_or_unbounded_label_never_becomes_a_download_click(run_capture, proxy, tmp_path, path):
    result, events = run_capture(path, limits=Limits(chain_timeout=3, read_timeout=1))
    assert result.outcome == "failed" and not result.artifacts
    assert proxy.counts[path] == 1 and proxy.counts["/business"] == proxy.counts["/app.apk"] == 0
    assert not any(event["event"] == "download_action" for event in events)
    (tmp_path / "label-receipt.json").write_text(json.dumps({
        "passed": True, "case": path, "outcome": result.outcome,
        "reason_code": result.reason_code, "counts": dict(proxy.counts),
    }, indent=2) + "\n")
