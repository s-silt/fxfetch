from __future__ import annotations

import io
import json
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from browser_evidence_fixtures import run_browser_capture

from fxfetch.core.browser_web_evidence import BrowserWebEvidence
from fxfetch.core.limits import Limits
from fxfetch.core.task_evidence import finalize_package
from fxfetch.core.task_evidence_recorder import TaskEvidenceRecorder
from fxfetch.core.task_evidence_verify import verify_task_archive


class _Journal:
    def __init__(self) -> None:
        self.rows: list[tuple[str, dict[str, object]]] = []

    def append(self, kind: str, fields: dict[str, object]) -> bool:
        self.rows.append((kind, fields))
        return True


def test_main_attribution_requires_entry_session_document_and_root_frame() -> None:
    observer = BrowserWebEvidence(journal=None)
    observer.set_entry_identity("entry-session", "root-frame")

    root_document = {"resourceType": "Document", "frameId": "root-frame"}
    xhr = {"resourceType": "XHR", "frameId": "root-frame"}
    iframe_document = {"resourceType": "Document", "frameId": "child-frame"}
    popup_document = {"resourceType": "Document", "frameId": "root-frame"}

    assert observer.is_main_request("entry-session", root_document)
    assert not observer.is_main_request("entry-session", xhr)
    assert not observer.is_main_request("entry-session", iframe_document)
    assert not observer.is_main_request("popup-session", popup_document)


def test_network_event_keeps_unknown_association_and_projects_safe_fields() -> None:
    journal = _Journal()
    observer = BrowserWebEvidence(journal=journal)  # type: ignore[arg-type]
    observer.target_attached("session-1", {"targetId": "target-1", "type": "page"})
    data: dict[str, Any] = {
        "requestId": "network-1",
        "request": {
            "url": "https://capture.test/resource",
            "method": "GET",
            "headers": {"Authorization": "secret", "Cookie": "private"},
            "postData": "private body",
        },
        "documentURL": "https://capture.test/",
        "frameId": "frame-1",
        "loaderId": "loader-1",
        "type": "XHR",
        "initiator": {
            "type": "script",
            "stack": {
                "callFrames": [
                    {"url": "https://capture.test/app.js", "lineNumber": 12},
                    {"url": "https://capture.test/ignored.js", "lineNumber": 13},
                ]
            },
        },
        "redirectResponse": {
            "url": "https://capture.test/old",
            "status": 302,
            "headers": {
                "Location": "/resource",
                "Set-Cookie": "private",
                "Authorization": "secret",
            },
        },
    }

    observer.network_request("session-1", data)

    kind, fields = journal.rows[-1]
    assert kind == "network_request_observed"
    assert fields["request_ref"] is None
    assert fields["association"] == "unknown"
    assert fields["network_id"] == "network-1"
    assert fields["initiator"] == {
        "type": "script",
        "stack": [{"url": "https://capture.test/app.js", "line_number": 12},
                  {"url": "https://capture.test/ignored.js", "line_number": 13}],
    }
    redirect = fields["redirect"]
    assert isinstance(redirect, dict)
    assert redirect["headers"] == {"location": "/resource"}
    assert "Authorization" not in str(fields)
    assert "Cookie" not in str(fields)
    assert "postData" not in str(fields)


def test_response_header_projection_omits_credentials() -> None:
    journal = _Journal()
    observer = BrowserWebEvidence(journal=journal)  # type: ignore[arg-type]
    observer.set_entry_identity("session-1", "frame-1")
    observer.begin_request(
        "session-1",
        {
            "requestId": "fetch-1",
            "request": {"url": "https://capture.test/", "method": "GET"},
            "resourceType": "Document",
            "frameId": "frame-1",
        },
    )
    _, _, safe_headers = observer.response_observed(
        "session-1",
        {
            "requestId": "fetch-1",
            "request": {"url": "https://capture.test/", "method": "GET"},
            "resourceType": "Document",
            "frameId": "frame-1",
            "networkId": "network-1",
        },
        {
            "content-type": "text/html",
            "location": "/next",
            "authorization": "secret",
            "cookie": "private",
            "set-cookie": "private",
        },
        200,
        1,
    )

    assert safe_headers == {"content-type": "text/html", "location": "/next"}
    response_fields = journal.rows[-1][1]
    assert response_fields["headers"] == safe_headers


def test_body_and_subresource_observations_do_not_confuse_main_outcome() -> None:
    journal = _Journal()
    observer = BrowserWebEvidence(journal=journal)  # type: ignore[arg-type]
    observer.set_entry_identity("entry-session", "root-frame")

    main = {
        "requestId": "main-200",
        "request": {"url": "https://capture.test/", "method": "GET"},
        "resourceType": "Document",
        "frameId": "root-frame",
    }
    observer.begin_request("entry-session", main)
    _, is_main, _ = observer.response_observed("entry-session", main, {}, 200, 1)
    assert is_main
    observer.body_saved(
        "entry-session",
        main,
        path="web/main.html",
        size=4,
        sha256="a" * 64,
        representation="browser_response_decoded",
        complete=True,
        body_text="<html>",
    )
    assert journal.rows[-1][1]["resource_type"] == "Document"

    for request_id, resource_type, frame_id in (
        ("xhr-403", "XHR", "root-frame"),
        ("iframe-403", "Document", "child-frame"),
    ):
        event = {
            "requestId": request_id,
            "request": {"url": f"https://capture.test/{request_id}", "method": "GET"},
            "resourceType": resource_type,
            "frameId": frame_id,
        }
        observer.begin_request("entry-session", event)
        _, is_main, _ = observer.response_observed("entry-session", event, {}, 403, 2)
        assert not is_main
        observer.subresource_http_error("entry-session", event, 403)

    assert observer.main_status == 200
    assert observer.final_outcome("captured", "passive_visit_material_captured") == (
        "captured",
        "passive_visit_material_captured",
    )

    main_error = {
        "requestId": "main-403",
        "request": {"url": "https://capture.test/", "method": "GET"},
        "resourceType": "Document",
        "frameId": "root-frame",
    }
    observer.begin_request("entry-session", main_error)
    _, is_main, _ = observer.response_observed("entry-session", main_error, {}, 403, 3)
    assert is_main
    assert observer.final_outcome("captured", "passive_visit_material_captured") == (
        "blocked",
        "http_access_control",
    )


def test_main_challenge_preserves_device_verification_reason() -> None:
    observer = BrowserWebEvidence(journal=None)
    observer.main_challenge = True

    assert observer.final_outcome("blocked", "device_verification_required") == (
        "blocked",
        "device_verification_required",
    )
    assert observer.final_outcome("blocked", "challenge_detected") == (
        "blocked",
        "challenge_detected",
    )


def test_package_capture_records_cdp_facts_without_web_policy(tmp_path, monkeypatch) -> None:
    result, rows, _, _ = run_browser_capture(tmp_path, monkeypatch)

    kinds = [kind for kind, _ in rows]
    assert {"request_attempted", "response_observed", "redirect_observed", "network_request_observed",
            "frame_navigated", "response_body_saved", "terminal_snapshot"}.issubset(kinds)
    requests = [fields for kind, fields in rows if kind == "request_attempted"]
    assert len({fields["request_ref"] for fields in requests}) == len(requests)
    assert all(fields["collector_id"] == "browser" for fields in requests)
    assert all(fields["attempt_id"] == "browser-attempt-1" for fields in requests)
    assert result.outcome == "failed"
    assert result.reason_code == "browser_dynamic_incomplete"
    assert "single_passive_visit" not in result.gaps


def test_browser_capture_modes_consume_redirect_and_response_once(tmp_path, monkeypatch) -> None:
    package_root = tmp_path / "package"
    package_recorder = TaskEvidenceRecorder(package_root)
    previous = package_recorder.set_context("browser", "browser-package-redirect")
    package_result, _, package_counts, _ = run_browser_capture(
        package_root,
        monkeypatch,
        purpose="package",
        journal=package_recorder.journal,
        observation_context={
            "collector_id": package_recorder.context[0],
            "attempt_id": package_recorder.context[1],
        },
    )
    package_recorder.restore_context(previous)
    package_recorder.close()
    assert (package_result.outcome, package_result.reason_code) == (
        "failed",
        "browser_dynamic_incomplete",
    )
    assert "single_passive_visit" not in package_result.gaps
    assert package_counts["stream"] == {"request-2": 1}
    assert package_counts["response_continue"] == {"request-1": 1}
    package_metadata = finalize_package(
        package_root,
        job_id="browser-package-redirect",
        entry_url="https://capture.synthetic.test/old",
        terminal_result={
            "outcome": package_result.outcome,
            "reason_code": package_result.reason_code,
            "coverage": package_result.coverage,
            "artifacts": [],
            "attempts": [],
            "gaps": package_result.gaps,
        },
        observation_path=package_recorder.path,
        max_bytes=32 * 1024 * 1024,
    )
    assert package_metadata["state"] == "ready"
    package_archive = package_root / "data-package" / package_metadata["filename"]
    package_manifest, _ = verify_task_archive(package_archive, max_bytes=32 * 1024 * 1024)
    package_material_paths = {item["path"] for item in package_manifest["files"]}
    with zipfile.ZipFile(package_archive) as archive:
        package_observations = [
            json.loads(line)
            for line in archive.read("observations.jsonl").decode("utf-8").splitlines()
        ]
        package_redirects = [
            row for row in package_observations if row["kind"] == "redirect_observed"
        ]
        package_saved = [
            row["fields"]
            for row in package_observations
            if row["kind"] == "response_body_saved"
        ]
        assert len(package_saved) == 1
        assert package_saved[0]["url"] == "https://capture.synthetic.test/page"
        assert package_saved[0]["path"] in package_material_paths
        assert archive.read(package_saved[0]["path"]) == b"<html>synthetic</html>"
    assert package_redirects
    assert package_manifest["external_packages"] == []

    web_result, web_rows, web_counts, _ = run_browser_capture(
        tmp_path / "web",
        monkeypatch,
        purpose="web",
    )
    assert (web_result.outcome, web_result.reason_code) == (
        "captured",
        "passive_visit_material_captured",
    )
    assert web_counts["stream"] == {"request-2": 1}
    assert web_counts["response_continue"] == {"request-1": 1}
    assert any(kind == "redirect_observed" for kind, _ in web_rows)
    web_saved = [fields for kind, fields in web_rows if kind == "response_body_saved"]
    assert len(web_saved) == 1
    assert web_saved[0]["url"] == "https://capture.synthetic.test/page"


def _synthetic_apk() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("AndroidManifest.xml", b"synthetic-manifest")
        archive.writestr("classes.dex", b"dex\n035\0" + bytes(range(64)))
    return output.getvalue()


@pytest.mark.parametrize(
    ("case", "chunk_sizes", "failure_after", "max_body_bytes"),
    [
        ("complete", (1, 1, 1, 1), None, None),
        ("midstream_failure", (2, 2), 2, None),
        ("limit_prefix", (2, 2), None, 4),
        ("short_prefix_failure", (1,), 1, None),
    ],
)
def test_package_prefix_streams_are_recorded_and_excluded(
    tmp_path,
    monkeypatch,
    case: str,
    chunk_sizes: tuple[int, ...],
    failure_after: int | None,
    max_body_bytes: int | None,
) -> None:
    package = _synthetic_apk()
    if case == "short_prefix_failure":
        package = b"PK"
    recorder = TaskEvidenceRecorder(tmp_path)
    previous = recorder.set_context("browser", f"browser-{case}")
    limits = (
        replace(Limits(), max_body_bytes=max_body_bytes, chain_timeout=4, read_timeout=1)
        if max_body_bytes is not None
        else Limits(chain_timeout=4, read_timeout=1)
    )
    result, _, _, output_dir = run_browser_capture(
        tmp_path,
        monkeypatch,
        body=package,
        headers={"Content-Type": "text/plain"},
        redirect=False,
        chunk_sizes=chunk_sizes,
        stream_failure_after=failure_after,
        include_content_length=max_body_bytes is None,
        limits=limits,
        journal=recorder.journal,
        observation_context={
            "collector_id": recorder.context[0],
            "attempt_id": recorder.context[1],
        },
    )
    recorder.restore_context(previous)
    recorder.close()

    assert not result.artifacts
    saved = result.bodies + result.partials
    assert saved
    package_body = saved[0]
    assert package_body["package_stream"] is True
    package_path = Path(str(package_body["path"]))
    assert package_path.is_file()
    package_record_path = package_path.relative_to(tmp_path).as_posix()

    metadata = finalize_package(
        tmp_path,
        job_id=f"browser-package-{case}",
        entry_url="https://capture.synthetic.test/page",
        terminal_result={
            "outcome": result.outcome,
            "reason_code": result.reason_code,
            "coverage": result.coverage,
            "artifacts": [],
            "attempts": [],
            "gaps": result.gaps,
        },
        observation_path=recorder.path,
        max_bytes=32 * 1024 * 1024,
    )
    assert metadata["state"] == "ready"
    archive_path = tmp_path / "data-package" / metadata["filename"]
    manifest, _ = verify_task_archive(archive_path, max_bytes=32 * 1024 * 1024)
    material_paths = {item["path"] for item in manifest["files"]}
    assert package_record_path not in material_paths
    assert manifest["package_result"]["outcome"] == "failed"
    assert manifest["package_result"]["reason_code"] == result.reason_code
    assert manifest["external_packages"] == []
    assert not result.artifacts
    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
        assert package_record_path not in names
        assert package not in b"".join(archive.read(name) for name in names)
        observations = [
            json.loads(line)
            for line in archive.read("observations.jsonl").decode("utf-8").splitlines()
        ]
    package_rows = [
        row for row in observations
        if row["kind"] in {"response_body_saved", "response_prefix_saved"}
        and row["fields"].get("package_stream") is True
    ]
    assert package_rows
    assert "package_body_not_included" in manifest["gaps"]
    assert all(row["fields"]["path"] not in material_paths for row in package_rows)
    assert output_dir.is_dir()
