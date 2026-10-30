"""Synthetic browser observations, never a claim that a browser was executed."""

from __future__ import annotations

import hashlib
from pathlib import Path

from fxfetch.core.task_evidence import finalize_package
from fxfetch.core.task_evidence_recorder import TaskEvidenceRecorder


def browser_archive(root: Path, *, scenario: str) -> Path:
    root.mkdir(parents=True)
    recorder = TaskEvidenceRecorder(root)
    recorder.set_context("browser", "browser-one")
    context = {"session_id": "session-one", "target_id": "page-one", "frame_id": "main"}

    def emit(kind, **fields):
        recorder.observe_transport({"event": kind, **context, **fields})

    def response(ref, url, mime, body, *, resource="Document", complete=True, package=False):
        identity = {"request_ref": ref, "url": url, "method": "GET", "resource_type": resource}
        emit("request_attempted", **identity, permitted=False, stage="Fetch.request")
        emit("request_permitted", request_ref=ref, permitted=True)
        emit("response_observed", **identity, status=200, headers={"content-type": mime})
        if body is not None:
            path = root / f"{ref}.body"
            path.write_bytes(body)
            emit("response_body_saved" if complete else "response_prefix_saved", **identity,
                 path=path, size=len(body), sha256=hashlib.sha256(body).hexdigest(), complete=complete,
                 representation="browser_response_body" if complete else "browser_response_prefix",
                 package_stream=package)
            return path
        return None

    entry = "https://entry.example.test/"
    response("main", entry, "text/html", b"<html>captcha required</html>" if scenario == "blocked"
             else b"<html>ordinary page without package links</html>")
    response("script", "https://assets.example.test/bootstrap", "application/javascript; charset=utf-8",
             b'window.location.href="https://static-next.example.test/landing";', resource="Script")
    response("api", "https://api.example.test/config", "application/json",
             b'{"service":"https://service.example.test/v2"}', resource="Fetch")
    response("third-party", "https://metrics.example.test/collect", "text/plain", None, resource="XHR")
    response("partial", "https://partial.example.test/data", "text/plain",
             b"https://partial-api.example.test/v1", complete=False, resource="XHR")
    emit("request_attempted", request_ref="failed", url="https://failed.example.test/no-response", method="GET")
    emit("request_attempted", request_ref="denied", url="https://denied.example.test/", method="GET", permitted=False)
    emit("request_denied", request_ref="denied", reason_code="synthetic_denied")
    emit("network_request_observed", request_ref=None, association="unknown", url="https://unassociated.example.test/")
    emit("acquisition_event", url="https://candidate-only.example.test/")
    child_url = "https://frame.example.test/challenge"
    emit("frame_navigated", frame_id="child-frame", url=child_url, parent_id="main")
    emit("challenge_detected", url=entry if scenario == "blocked" else child_url,
         target_id="page-one" if scenario == "blocked" else "child-page", reason_code="captcha_required")
    snapshot = root / "rendered.body"
    raw = b"<html>rendered challenge snapshot</html>"
    snapshot.write_bytes(raw)
    emit("terminal_snapshot", url=child_url, request_ref=None, frame_id="child-frame", path=snapshot,
         size=len(raw), sha256=hashlib.sha256(raw).hexdigest(), complete=True, representation="browser_rendered_dom")
    artifacts = []
    if scenario == "package":
        raw = b"PK\x03\x04synthetic-package-bytes-not-a-real-apk"
        url = "https://download.example.test/raw"
        path = response("package", url, "application/octet-stream", raw, package=True)
        artifacts = [{"kind": "apk", "path": str(path), "size": len(raw),
                      "sha256": hashlib.sha256(raw).hexdigest(), "url": url, "request_ref": "package"}]
    recorder.close()
    outcome = {"ordinary": "not_found", "blocked": "blocked", "package": "downloaded"}[scenario]
    metadata = finalize_package(
        root, job_id="synthetic-browser", entry_url=entry,
        terminal_result={"outcome": outcome, "reason_code": "synthetic", "coverage": "partial",
                         "artifacts": artifacts, "attempts": []},
        observation_path=recorder.path, max_bytes=16 * 1024 * 1024,
    )
    assert metadata["state"] == "ready", metadata
    return root / "data-package" / metadata["filename"]
