from __future__ import annotations

import hashlib
import json
import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest

from fxfetch.core.limits import Limits
from fxfetch.core.web_evidence import EvidenceError, export_web, verify_web
from fxfetch.core.web_evidence_schema import portable_path
from fxfetch.core.web_journal import EvidenceJournal


def _make_capture(root: Path, *, material_path: str = "http/response.body") -> Path:
    root.mkdir()
    body = root / material_path
    body.parent.mkdir(parents=True)
    body.write_bytes(b"synthetic private response")
    journal = EvidenceJournal(root / "capture.jsonl", "http", "attempt-1")
    journal.append("capture_started", {"url": "https://example.invalid/?token=private"})
    journal.append(
        "request_attempted",
        {"request_ref": "http-1", "url": "https://example.invalid/?token=private"},
    )
    journal.append(
        "response_body_saved",
        {
            "request_ref": "http-1",
            "url": "https://example.invalid/?token=private",
            "path": material_path,
            "size": len(body.read_bytes()),
            "sha256": hashlib.sha256(body.read_bytes()).hexdigest(),
            "representation": "http_response_body",
            "complete": True,
        },
    )
    journal.append(
        "request_attempted",
        {"request_ref": "http-2", "url": "https://other.invalid/path"},
    )
    journal.close()
    stamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    summary = {
        "schema_version": "fxfetch.web-capture.v1",
        "capture_id": "capture-1",
        "entry_url": "https://example.invalid/?token=private",
        "collector": "http",
        "started_at": stamp,
        "finished_at": stamp,
        "outcome": "captured",
        "reason_code": "web_material_captured",
        "coverage": "partial",
        "gaps": ["subresources_not_collected"],
        "journal_state": "healthy",
        "materials": [
            {
                "path": material_path,
                "size": len(body.read_bytes()),
                "sha256": hashlib.sha256(body.read_bytes()).hexdigest(),
                "role": "response_body",
                "representation": "http_response_body",
                "complete": True,
                "source_url": "https://example.invalid/?token=private",
                "request_ref": "http-1",
            }
        ],
    }
    (root / "capture.json").write_text(json.dumps(summary), encoding="utf-8")
    return root


@pytest.mark.parametrize("material_path", ["http/response.body", "browser/web/response.body"])
def test_export_roundtrip_is_private_and_socket_free(tmp_path: Path, monkeypatch, material_path: str) -> None:
    def forbidden(*_: object, **__: object) -> None:
        pytest.fail("offline evidence operation attempted networking")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    capture = _make_capture(tmp_path / "capture", material_path=material_path)
    bundle_dir = tmp_path / "bundle"
    manifest, external_digest = export_web(capture, bundle_dir, Limits())
    verified, verified_digest = verify_web(bundle_dir, Limits())
    assert manifest["schema_version"] == "fxfetch.web-evidence.v1"
    assert manifest["entry_url"].endswith("?token=private")
    assert manifest["files"][0]["path"] == "capture.jsonl"
    assert manifest["files"][1]["complete"] is True
    assert verified["capture_id"] == "capture-1"
    assert external_digest == verified_digest
    assert len(external_digest) == 64
    assert not (bundle_dir / "capture.json").exists()


def test_export_rejects_traversal_unknown_schema_and_output_overlap(tmp_path: Path) -> None:
    capture = _make_capture(tmp_path / "capture")
    summary_path = capture / "capture.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["materials"][0]["path"] = "../outside"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    with pytest.raises(EvidenceError):
        export_web(capture, tmp_path / "escaped", Limits())
    assert not (tmp_path / "escaped").exists()

    summary["materials"][0]["path"] = "http/response.body"
    summary["schema_version"] = "fxfetch.web-capture.v99"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    with pytest.raises(EvidenceError, match="unsupported"):
        export_web(capture, tmp_path / "unknown", Limits())
    assert not (tmp_path / "unknown").exists()

    with pytest.raises(EvidenceError, match="overlap"):
        export_web(capture, capture / "bundle", Limits())


def test_export_rejects_unsupported_material_reference(tmp_path: Path) -> None:
    capture = _make_capture(tmp_path / "capture")
    summary_path = capture / "capture.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["materials"][0]["request_ref"] = "not-in-journal"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    with pytest.raises(EvidenceError, match="reference_unsupported"):
        export_web(capture, tmp_path / "bundle", Limits())


def test_export_rejects_swapped_request_reference(tmp_path: Path) -> None:
    capture = _make_capture(tmp_path / "capture")
    summary_path = capture / "capture.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["materials"][0]["request_ref"] = "http-2"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    with pytest.raises(EvidenceError, match="reference_mismatch"):
        export_web(capture, tmp_path / "bundle", Limits())


@pytest.mark.parametrize("path", ["CON.txt", "bad. ", "bad ", "nul\x00name", "ctl\x1fname"])
def test_portable_paths_reject_windows_aliases(path: str) -> None:
    with pytest.raises(EvidenceError, match="path_invalid"):
        portable_path(path)


def test_truncated_journal_allows_missing_saved_event_with_gap(tmp_path: Path) -> None:
    capture = _make_capture(tmp_path / "capture")
    journal_path = capture / "capture.jsonl"
    rows = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines()]
    rows = [row for row in rows if row["kind"] != "response_body_saved"]
    for index, row in enumerate(rows, 1):
        row["seq"] = index
    journal_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    summary_path = capture / "capture.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["journal_state"] = "truncated"
    summary["gaps"].append("material_provenance_incomplete")
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    export_web(capture, tmp_path / "bundle", Limits())
    _, digest = verify_web(tmp_path / "bundle", Limits())
    assert len(digest) == 64


def test_truncated_journal_rejects_contradictory_saved_event(tmp_path: Path) -> None:
    capture = _make_capture(tmp_path / "capture")
    journal_path = capture / "capture.jsonl"
    rows = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines()]
    saved = next(row for row in rows if row["kind"] == "response_body_saved")
    saved["fields"]["sha256"] = "0" * 64
    journal_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    summary_path = capture / "capture.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["journal_state"] = "truncated"
    summary["gaps"].append("material_provenance_incomplete")
    summary_path.write_text(json.dumps(summary), encoding="utf-8")

    with pytest.raises(EvidenceError, match="material_provenance_invalid"):
        export_web(capture, tmp_path / "bundle", Limits())


def test_verify_rejects_deep_json(tmp_path: Path) -> None:
    capture = _make_capture(tmp_path / "capture")
    bundle = tmp_path / "bundle"
    export_web(capture, bundle, Limits())
    manifest_path = bundle / "manifest.json"
    manifest = manifest_path.read_text(encoding="utf-8")
    manifest_path.write_text(manifest[:-1] + ',"deep":' + "[" * 10000 + "0" + "]" * 10000 + "}")

    with pytest.raises(EvidenceError, match="manifest_invalid"):
        verify_web(bundle, Limits())


def test_verify_rejects_unlisted_directory_budget(tmp_path: Path) -> None:
    capture = _make_capture(tmp_path / "capture")
    bundle = tmp_path / "bundle"
    export_web(capture, bundle, Limits())
    for index in range(2001):
        (bundle / f"unlisted-{index:04d}").mkdir()
    with pytest.raises(EvidenceError, match="file_count_invalid|unlisted_directory"):
        verify_web(bundle, Limits())


def test_verify_rejects_tamper_unknown_version_and_case_collision(tmp_path: Path) -> None:
    capture = _make_capture(tmp_path / "capture")
    bundle = tmp_path / "bundle"
    export_web(capture, bundle, Limits())
    body = bundle / "http" / "response.body"
    body.write_bytes(b"tampered")
    with pytest.raises(EvidenceError, match="integrity"):
        verify_web(bundle, Limits())

    export_web(capture, tmp_path / "clean-bundle", Limits())
    clean = tmp_path / "clean-bundle"
    manifest_path = clean / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema_version"] = "fxfetch.web-evidence.v99"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(EvidenceError, match="unsupported"):
        verify_web(clean, Limits())

    export_web(capture, tmp_path / "collision-bundle", Limits())
    collision = tmp_path / "collision-bundle"
    manifest_path = collision / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"].append({**manifest["files"][0], "path": "CAPTURE.JSONL"})
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(EvidenceError, match="collision"):
        verify_web(collision, Limits())


def test_export_refuses_existing_output_and_partial_records_remain_incomplete(tmp_path: Path) -> None:
    capture = _make_capture(tmp_path / "capture")
    with pytest.raises(EvidenceError, match="exists"):
        export_web(capture, capture, Limits())


@pytest.mark.parametrize("field", ["collector", "outcome", "journal_state"])
@pytest.mark.parametrize("value", [[], {}])
def test_invalid_enum_types_return_validation_error(tmp_path: Path, field: str, value: object) -> None:
    capture = _make_capture(tmp_path / "capture")
    path = capture / "capture.json"
    summary = json.loads(path.read_text())
    summary[field] = value
    path.write_text(json.dumps(summary))
    with pytest.raises(EvidenceError):
        export_web(capture, tmp_path / "bundle", Limits())


@pytest.mark.parametrize("mutation", ["identity", "truncation"])
def test_journal_rejects_conflicting_identity_or_hidden_truncation(tmp_path: Path, mutation: str) -> None:
    capture = _make_capture(tmp_path / "capture")
    path = capture / "capture.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    if mutation == "identity":
        rows[-1]["fields"]["request_ref"] = "http-1"
    else:
        rows[-1]["kind"] = "journal_truncated"
        rows[-1]["fields"] = {"reason": "record_limit"}
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    with pytest.raises(EvidenceError, match="identity_conflict|completeness_mismatch"):
        export_web(capture, tmp_path / "bundle", Limits())
