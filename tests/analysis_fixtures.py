from __future__ import annotations

import hashlib
from pathlib import Path

from fxfetch.core.task_evidence import finalize_package
from fxfetch.core.task_evidence_recorder import TaskEvidenceRecorder


def analysis_archive(root: Path, *, empty: bool = False) -> Path:
    root.mkdir(parents=True)
    recorder = TaskEvidenceRecorder(root)
    recorder.set_context("http", "first")
    if not empty:
        start = "https://entry.example.test/start"
        end = "https://content.example.test/page"
        for event in (
            {"event": "request_attempted", "request_ref": "one", "url": start, "method": "GET"},
            {"event": "response_observed", "request_ref": "one", "url": start, "status": 302,
             "location_raw": end},
            {"event": "redirect_observed", "request_ref": "one", "from_url": start, "resolved_target": end},
            {"event": "request_attempted", "request_ref": "two", "url": end, "method": "GET"},
            {"event": "response_observed", "request_ref": "two", "url": end, "status": 200},
            {"event": "acquisition_event", "url": "https://unvisited.example.test/metadata-only"},
        ):
            recorder.observe_transport(event)
        raw = b'<html><script>var api="https://api.example.test/v1";</script></html>'
        body = root / "page.html"
        body.write_bytes(raw)
        recorder.observe_transport({
            "event": "response_body_saved", "request_ref": "two", "source_url": end,
            "path": body, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "representation": "http_response_decoded", "complete": True,
        })
    recorder.close()
    metadata = finalize_package(
        root, job_id="synthetic-task", entry_url="https://entry.example.test/start",
        terminal_result={"outcome": "failed" if empty else "not_found", "reason_code": "synthetic",
                         "coverage": "partial", "artifacts": [], "attempts": []},
        observation_path=recorder.path, max_bytes=16 * 1024 * 1024,
    )
    assert metadata["state"] == "ready", metadata
    return root / "data-package" / metadata["filename"]
