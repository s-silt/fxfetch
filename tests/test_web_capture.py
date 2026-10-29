from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from fxfetch import cli
from fxfetch.core.http_client import HttpClient
from fxfetch.core.limits import Limits
from fxfetch.core.web_capture import capture_web
from fxfetch.core.web_journal import EvidenceJournal


class _LocalClient(HttpClient):
    def _resolve(self, host: str, port: int) -> tuple[str, ...]:
        return ("127.0.0.1",)


@pytest.fixture
def local_site():
    counts: Counter[str] = Counter()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_: object) -> None:
            return

        def send_body(self, status: int, body: bytes, content_type: str = "text/html") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            counts[self.path] += 1
            if self.path == "/plain":
                self.send_body(200, b'<p>synthetic page</p><a href="/app.apk">download</a>')
            elif self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "dir/step")
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif self.path == "/dir/step":
                self.send_response(302)
                self.send_header("Location", "../repeat")
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif self.path == "/repeat":
                self.send_response(302)
                self.send_header("Location", "/repeat")
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif self.path == "/blocked-entry":
                self.send_response(302)
                self.send_header("Location", "/blocked")
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif self.path == "/blocked":
                self.send_body(403, b"synthetic access control", "text/plain")
            elif self.path == "/blocked-short":
                self.send_response(403)
                self.send_header("Content-Length", "100")
                self.end_headers()
                self.wfile.write(b"denied")
                self.close_connection = True
            elif self.path == "/short":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", "100")
                self.end_headers()
                self.wfile.write(b"partial")
                self.close_connection = True
            elif self.path == "/apk-limit":
                body = b"PK\x03\x04" + b"x" * 100
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self.wfile.write(f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
            else:
                self.send_body(404, b"missing", "text/plain")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://synthetic.test:{server.server_port}", counts
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def _capture(
    url: str,
    output: Path,
    *,
    client: HttpClient,
    limits: Limits | None = None,
):
    return capture_web(
        url,
        output,
        collector="http",
        authorized_active=True,
        service_root=output.parent,
        client=client,
        limits=limits,
    )


def _journal_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_offline_capture_preview_is_socket_free_and_does_not_create_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def forbidden(*_: object, **__: object) -> None:
        pytest.fail("offline web preview attempted networking")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    output = tmp_path / "not-created"
    assert cli.main(
        ["capture-web", "https://synthetic.invalid/page?secret=private", "--out", str(output)]
    ) == 0
    state = json.loads(capsys.readouterr().out)
    assert state["mode"] == "offline" and state["network_requests"] == 0
    assert "secret" not in json.dumps(state)
    assert not output.exists()


def test_http_capture_fresh_process_does_not_import_playwright(local_site, tmp_path: Path) -> None:
    base, _ = local_site
    offline_output = tmp_path / "offline"
    active_output = tmp_path / "active"
    script = r"""
import importlib.abc
import json
import sys

blocked = []


class RejectPlaywright(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "playwright" or fullname.startswith("playwright."):
            blocked.append(fullname)
            raise ModuleNotFoundError("playwright blocked by regression", name=fullname)
        return None


sys.meta_path.insert(0, RejectPlaywright())
from fxfetch import cli
from fxfetch.core.http_client import HttpClient


def local_resolve(self, host, port):
    return ("127.0.0.1",)


HttpClient._resolve = local_resolve
base, offline_output, active_output = sys.argv[1:]
if cli.main(["capture-web", base + "/plain", "--out", offline_output, "--collector", "http"]) != 0:
    raise AssertionError("offline capture preview failed")
if cli.main(
    [
        "capture-web",
        base + "/plain",
        "--out",
        active_output,
        "--collector",
        "http",
        "--authorized-active",
    ]
) != 0:
    raise AssertionError("authorized HTTP capture failed")
if blocked:
    raise AssertionError(f"unexpected Playwright imports: {blocked}")
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, base, str(offline_output), str(active_output)],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    states = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
    assert states[0]["mode"] == "offline"
    assert states[0]["network_requests"] == 0
    assert states[1]["state"] == "web_capture"
    assert states[1]["collector"] == "http"
    assert states[1]["outcome"] == "captured"


def test_capture_rejects_non_http_scheme_offline(tmp_path: Path) -> None:
    assert cli.main(["capture-web", "ftp://synthetic.invalid/file", "--out", str(tmp_path / "out")]) == 1
    assert not (tmp_path / "out").exists()


def test_http_plain_page_is_saved_without_following_links(local_site, tmp_path: Path) -> None:
    base, counts = local_site
    output = tmp_path / "capture"
    result = _capture(base + "/plain", output, client=_LocalClient())
    assert result is not None
    assert (result.outcome, result.coverage) == ("captured", "partial")
    assert result.gaps == ["js_not_executed", "subresources_not_collected", "interaction_not_performed"]
    body = output / result.materials[0]["path"]
    assert body.read_bytes().startswith(b"<p>synthetic page")
    assert counts["/plain"] == 1 and counts["/app.apk"] == 0


def test_http_relative_redirects_and_repeated_url_remain_distinct(local_site, tmp_path: Path) -> None:
    base, counts = local_site
    output = tmp_path / "capture"
    result = _capture(base + "/start", output, client=_LocalClient())
    assert result is not None and result.outcome == "failed"
    rows = _journal_rows(output / "capture.jsonl")
    attempts = [row["fields"]["url"] for row in rows if row["kind"] == "request_attempted"]
    redirects = [row["fields"] for row in rows if row["kind"] == "redirect_observed"]
    assert attempts == [base + "/start", base + "/dir/step", base + "/repeat"]
    assert redirects[0]["location_raw"] == "dir/step"
    assert redirects[0]["resolved_target"] == base + "/dir/step"
    assert redirects[1]["resolved_target"] == base + "/repeat"
    assert redirects[2]["resolved_target"] == base + "/repeat"
    assert counts["/repeat"] == 1


def test_http_blocked_response_and_partial_prefix_are_preserved(local_site, tmp_path: Path) -> None:
    base, _ = local_site
    blocked_dir = tmp_path / "blocked-capture"
    blocked = _capture(base + "/blocked-entry", blocked_dir, client=_LocalClient())
    assert blocked is not None and (blocked.outcome, blocked.reason_code) == ("blocked", "http_access_control")
    blocked_file = blocked_dir / blocked.materials[0]["path"]
    assert blocked.materials[0]["complete"] is True
    assert blocked_file.read_bytes() == b"synthetic access control"
    assert any(
        row["kind"] == "response_observed" and row["fields"]["status"] == 403
        for row in _journal_rows(blocked_dir / "capture.jsonl")
    )

    partial_dir = tmp_path / "partial-capture"
    partial = _capture(base + "/short", partial_dir, client=_LocalClient())
    assert partial is not None and partial.outcome == "failed"
    assert partial.materials[0]["complete"] is False
    assert (partial_dir / partial.materials[0]["path"]).read_bytes() == b"partial"


def test_http_zip_prefix_obeys_web_body_limit(local_site, tmp_path: Path) -> None:
    base, _ = local_site
    result = _capture(
        base + "/apk-limit",
        tmp_path / "limited",
        client=_LocalClient(Limits(max_body_bytes=32, max_package_bytes=500)),
        limits=Limits(max_body_bytes=32, max_package_bytes=500),
    )
    assert result is not None and result.outcome == "failed"
    assert result.materials[0]["complete"] is False
    saved = (tmp_path / "limited" / result.materials[0]["path"]).read_bytes()
    assert len(saved) == 32 and saved.startswith(b"PK\x03\x04")


def test_journal_is_not_limited_to_store_ring_and_marks_saturation(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "events.jsonl"
    journal = EvidenceJournal(path, "http", "attempt-1")
    for index in range(140):
        assert journal.append("event", {"index": index})
    journal.close()
    rows = _journal_rows(path)
    assert len(rows) == 140 and rows[-1]["seq"] == 140

    import fxfetch.core.web_journal as web_journal

    monkeypatch.setattr(web_journal, "MAX_RECORDS", 5)
    limited_path = tmp_path / "limited.jsonl"
    limited = EvidenceJournal(limited_path, "http", "attempt-2")
    for index in range(10):
        limited.append("event", {"index": index})
    limited.close()
    limited_rows = _journal_rows(limited_path)
    assert limited_rows[-1]["kind"] == "journal_truncated"
    assert [row["seq"] for row in limited_rows] == list(range(1, len(limited_rows) + 1))
    assert len(limited_rows) == 5


def test_web_capture_retains_but_does_not_accept_binary_download(local_site, tmp_path: Path) -> None:
    base, _ = local_site
    result = _capture(base + "/apk-limit", tmp_path / "binary", client=_LocalClient())
    assert result is not None
    assert (result.outcome, result.reason_code) == ("failed", "unsupported_download_response")
    assert result.materials[0]["role"] == "unsupported_download"
    assert result.materials[0]["complete"] is True


def test_access_control_survives_truncated_response(local_site, tmp_path: Path) -> None:
    base, _ = local_site
    result = _capture(base + "/blocked-short", tmp_path / "blocked-short", client=_LocalClient())
    assert result is not None
    assert (result.outcome, result.reason_code) == ("blocked", "http_access_control")
    assert result.materials[0]["complete"] is False
    assert "length_mismatch" in result.gaps


def test_capture_fails_when_journal_writes_fail(local_site, tmp_path: Path, monkeypatch) -> None:
    base, _ = local_site

    def fail_write(self, row):
        self.failed = True
        self.gaps.append("journal_write_failed")
        return False

    monkeypatch.setattr(EvidenceJournal, "_write", fail_write)
    result = _capture(base + "/plain", tmp_path / "journal-failure", client=_LocalClient())
    assert result is not None
    assert (result.outcome, result.reason_code) == ("failed", "journal_write_failed")
    assert result.materials and result.journal_state == "failed"


def test_journal_omits_nonfinite_values_without_losing_valid_fields(tmp_path: Path) -> None:
    journal = EvidenceJournal(tmp_path / "events.jsonl", "http", "attempt-1")
    assert journal.append("diagnostic", {"invalid": float("nan"), "valid": 3})
    journal.close()
    fields = _journal_rows(journal.path)[0]["fields"]
    assert fields["valid"] == 3 and "invalid" not in fields
    assert fields["omitted_fields"] == ["invalid"]
