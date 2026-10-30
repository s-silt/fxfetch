"""Real installed Chrome; delayed synthetic document, no upstream connection."""
import threading
import time
from urllib.parse import urlsplit

import browser_capture_acceptance as synthetic
import pytest
from browser_capture_acceptance import APK
from browser_capture_acceptance import run_capture as run_capture

from fxfetch.core.limits import Limits


class DelayedHandler(synthetic.Handler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.hostname != "capture.test" or parsed.path not in {"/slow-entry", "/stalled-entry"}:
            return super().do_GET()
        self.server.counts[parsed.path] += 1
        delay = 6.5 if parsed.path == "/slow-entry" else 15
        if not self.server.stopped.wait(delay):
            self.respond(200, b'<link rel="icon" href="data:,"><script>location.href="/app.apk"</script>')


@pytest.fixture
def proxy(monkeypatch):
    monkeypatch.setattr(synthetic, "Handler", DelayedHandler)
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


def test_pending_entry_navigation_waits_past_idle_window(run_capture, proxy):
    result, _ = run_capture('/slow-entry', limits=Limits(chain_timeout=25, read_timeout=12))
    assert result.outcome == 'downloaded', result.reason_code
    assert result.artifacts[0].path.read_bytes() == APK
    assert proxy.counts['/slow-entry'] == proxy.counts['/app.apk'] == 1


def test_pending_navigation_still_has_read_deadline(run_capture, proxy):
    started = time.monotonic()
    result, _ = run_capture('/stalled-entry', limits=Limits(chain_timeout=12, read_timeout=2))
    assert result.outcome == 'failed'
    assert result.reason_code != 'browser_dynamic_incomplete'
    assert not result.artifacts and proxy.counts['/app.apk'] == 0
    assert time.monotonic() - started < 10
