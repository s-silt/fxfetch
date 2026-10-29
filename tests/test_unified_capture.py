from __future__ import annotations

import hashlib
import json
import threading
import zipfile
from dataclasses import asdict
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from fxfetch.core.browser_web_evidence import record_saved_material
from fxfetch.core.http_client import HttpClient
from fxfetch.core.network import AcquisitionPolicy
from fxfetch.core.task_evidence import finalize_package
from fxfetch.core.task_evidence_recorder import TaskEvidenceRecorder
from fxfetch.core.web_journal import EvidenceJournal
from fxfetch.core.workflow import Workflow


def _apk_bytes() -> bytes:
    import io

    value = io.BytesIO()
    with zipfile.ZipFile(value, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex\n035\0")
    return value.getvalue()


def _capture_policy(tmp_path: Path, routes: dict[str, tuple[int, dict[str, str], bytes]]):
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_: object) -> None:
            pass

        def do_GET(self) -> None:
            requests.append(self.path)
            status, headers, body = routes[self.path]
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    class LocalClient(HttpClient):
        def __init__(self, limits, observer):
            super().__init__(limits, transport_observer=observer)

        def _resolve(self, _host: str, _port: int) -> tuple[str, ...]:
            return ("127.0.0.1",)

    recorder = TaskEvidenceRecorder(tmp_path)
    policy = AcquisitionPolicy(
        collector_factory=lambda limits, _proxy: Workflow(
            LocalClient(limits, recorder), limits
        ),
        transport_observer=recorder,
    )
    base = f"http://capture.synthetic.test:{server.server_port}"
    try:
        result = policy.run(base + next(iter(routes)), tmp_path, threading.Event())
    finally:
        recorder.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    terminal = asdict(result)
    metadata = finalize_package(
        tmp_path,
        job_id="synthetic-unified",
        entry_url=base + next(iter(routes)),
        terminal_result=terminal,
        observation_path=tmp_path / "task-observations.jsonl",
        max_bytes=32 * 1024 * 1024,
    )
    return terminal, metadata, requests


def test_http_instance_observer_records_saved_body_once_after_write(tmp_path: Path) -> None:
    body = b"<html>synthetic</html>"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_: object) -> None:
            pass

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    events: list[dict[str, object]] = []

    def observe(event: dict[str, object]) -> None:
        if event.get("kind") == "response_body_saved":
            path = Path(str(event["path"]))
            assert path.is_file()
            assert hashlib.sha256(path.read_bytes()).hexdigest() == event["sha256"]
        events.append(event)

    class LocalClient(HttpClient):
        def _resolve(self, host: str, port: int) -> tuple[str, ...]:
            return ("127.0.0.1",)

    try:
        client = LocalClient(transport_observer=observe)
        destination = tmp_path / "response.html"
        response = client.fetch(
            f"http://capture.synthetic.test:{server.server_port}/",
            destination,
            user_agent="synthetic",
            cookie_jar=CookieJar(),
            cancel=threading.Event(),
            on_transport_event=observe,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert response.request_ref
    saved = [event for event in events if event.get("kind") == "response_body_saved"]
    assert len(saved) == 1
    assert saved[0]["request_ref"] == response.request_ref
    assert saved[0]["source_url"] == response.url
    assert saved[0]["complete"] is True


def test_package_mode_browser_save_records_unknown_request_association(tmp_path: Path) -> None:
    journal = EvidenceJournal(tmp_path / "observations.jsonl", "task", "synthetic")
    record_saved_material(
        journal,
        source_url="https://capture.synthetic.test/",
        path="browser/web/dom.html",
        size=4,
        sha256=hashlib.sha256(b"dom!").hexdigest(),
        representation="browser_rendered_dom",
        complete=True,
    )
    journal.close()

    record = json.loads((tmp_path / "observations.jsonl").read_text(encoding="utf-8"))
    assert record["kind"] == "response_body_saved"
    assert record["fields"]["source_url"] == "https://capture.synthetic.test/"
    assert "request_ref" not in record["fields"]


def test_instance_observer_failure_does_not_fail_http_fetch(tmp_path: Path) -> None:
    body = b"ok"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_: object) -> None:
            pass

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class BrokenObserver:
        def __call__(self, _: dict[str, object]) -> None:
            raise OSError("synthetic observer failure")

        def mark_failed(self, _: str) -> None:
            pass

    class LocalClient(HttpClient):
        def _resolve(self, host: str, port: int) -> tuple[str, ...]:
            return ("127.0.0.1",)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = LocalClient(transport_observer=BrokenObserver()).fetch(
            f"http://capture.synthetic.test:{server.server_port}/",
            tmp_path / "response",
            user_agent="synthetic",
            cookie_jar=CookieJar(),
            cancel=threading.Event(),
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert response.path.read_bytes() == body


def test_workflow_html_is_archived_with_redirect_without_replay(tmp_path: Path) -> None:
    html = b"<html><title>synthetic</title></html>"
    terminal, metadata, requests = _capture_policy(
        tmp_path,
        {
            "/start": (302, {"Location": "/page"}, b""),
            "/page": (200, {"Content-Type": "text/html"}, html),
        },
    )
    assert terminal["outcome"] != "downloaded"
    assert terminal["collector_mode"] == "http"
    assert metadata["state"] == "ready"
    archive_path = tmp_path / "data-package" / metadata["filename"]
    with zipfile.ZipFile(archive_path) as bundle:
        manifest = json.loads(bundle.read("manifest.json"))
        assert manifest["web_materials"]["state"] == "saved"
        assert {
            "http_subresource_coverage_limited",
            "http_javascript_not_executed",
        }.issubset(manifest["web_materials"]["gaps"])
        assert any(bundle.read(item["path"]) == html for item in manifest["files"])
        observations = [
            json.loads(line)
            for line in bundle.read("observations.jsonl").decode("utf-8").splitlines()
        ]
        assert any(row["kind"] == "redirect_observed" for row in observations)
        request_rows = [row for row in observations if row["kind"] == "request_attempted"]
        saved_rows = [row for row in observations if row["kind"] == "response_body_saved"]
        assert len(requests) == len(request_rows) >= 2
        assert len({row["fields"]["request_ref"] for row in request_rows}) == len(request_rows)
        assert saved_rows
        for row in request_rows + saved_rows:
            assert row["collector"] == "task"
            assert row["fields"]["collector_id"] == "http"
            assert row["fields"]["attempt_id"] == "network-1-direct"
        for saved in saved_rows:
            assert any(
                request["fields"]["request_ref"] == saved["fields"]["request_ref"]
                and request["fields"]["url"] == saved["fields"]["source_url"]
                for request in request_rows
            )


def test_workflow_direct_apk_is_referenced_but_not_archived(tmp_path: Path) -> None:
    package = _apk_bytes()
    terminal, metadata, _ = _capture_policy(
        tmp_path,
        {
            "/original.apk": (
                200,
                {"Content-Type": "application/vnd.android.package-archive"},
                package,
            ),
        },
    )
    assert terminal["outcome"] == "downloaded"
    assert metadata["state"] == "ready"
    archive_path = tmp_path / "data-package" / metadata["filename"]
    with zipfile.ZipFile(archive_path) as bundle:
        manifest = json.loads(bundle.read("manifest.json"))
        assert manifest["files"] == []
        assert len(manifest["external_packages"]) == 1
        assert manifest["external_packages"][0]["sha256"] == hashlib.sha256(package).hexdigest()
        assert manifest["external_packages"][0]["request_ref"]
        observations = [
            json.loads(line)
            for line in bundle.read("observations.jsonl").decode("utf-8").splitlines()
        ]
        package_request = next(
            row for row in observations
            if row["kind"] == "request_attempted"
            and row["fields"]["request_ref"] == manifest["external_packages"][0]["request_ref"]
        )
        assert package_request["fields"]["url"] == manifest["external_packages"][0]["source_url"]
        assert package_request["fields"]["collector_id"] == "http"
        assert package_request["fields"]["attempt_id"] == "network-1-direct"
        assert all(package not in bundle.read(name) for name in bundle.namelist())
