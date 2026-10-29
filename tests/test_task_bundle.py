from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from fxfetch.cli import main
from fxfetch.core.task_evidence import finalize_package, package_filename
from fxfetch.core.task_evidence_io import build_task_archive, verify_task_archive
from fxfetch.core.task_evidence_recorder import TaskEvidenceRecorder
from fxfetch.core.web_evidence_schema import EvidenceError


def _archive(
    tmp_path: Path,
    *,
    outcome: str = "downloaded",
    mutate_source: bool = False,
    collector_mode: str | None = None,
) -> Path:
    html = b"<html>synthetic</html>"
    package = b"synthetic-original-package"
    html_path = tmp_path / "web" / "index.html"
    package_path = tmp_path / "artifacts" / "original.apk"
    html_path.parent.mkdir(parents=True)
    package_path.parent.mkdir(parents=True)
    html_path.write_bytes(html)
    package_prefix = package[:12]
    package_path.write_bytes(package if outcome == "downloaded" else package_prefix)
    recorder = TaskEvidenceRecorder(tmp_path)
    context = recorder.set_context("http", "network-http-1")
    recorder.observe_transport(
        {
            "event": "request_attempted",
            "request_ref": "http-web-request",
            "url": "https://capture.synthetic.test/",
            "method": "GET",
        }
    )
    recorder.restore_context(context)
    context = recorder.set_context("http", "network-http-2")
    recorder.observe_transport(
        {
            "event": "request_attempted",
            "request_ref": "http-package-request",
            "url": "https://capture.synthetic.test/original.apk",
            "method": "GET",
        }
    )
    recorder.restore_context(context)
    context = recorder.set_context("http", "network-http-1")
    recorder(
        {
                "kind": "response_prefix_saved",
            "request_ref": "http-web-request",
            "source_url": "https://capture.synthetic.test/",
            "path": html_path,
            "size": len(html),
            "sha256": hashlib.sha256(html).hexdigest(),
                "representation": "http_saved_prefix",
                "complete": False,
        }
    )
    recorder.restore_context(context)
    context = recorder.set_context("http", "network-http-2")
    recorder(
        {
            "kind": (
                "response_body_saved" if outcome == "downloaded" else "response_prefix_saved"
            ),
            "request_ref": "http-package-request",
            "source_url": "https://capture.synthetic.test/original.apk",
            "path": package_path,
            "size": len(package if outcome == "downloaded" else package_prefix),
            "sha256": hashlib.sha256(
                package if outcome == "downloaded" else package_prefix
            ).hexdigest(),
            "representation": (
                "http_response_decoded" if outcome == "downloaded" else "http_response_prefix"
            ),
            "complete": outcome == "downloaded",
            "package_stream": True,
        }
    )
    recorder.restore_context(context)
    recorder.close()
    if mutate_source:
        html_path.write_bytes(b"<html>mutated</html>")
    artifact = {
        "kind": "apk",
        "path": str(package_path),
        "size": len(package),
        "sha256": hashlib.sha256(package).hexdigest(),
        "url": "https://capture.synthetic.test/original.apk",
        "request_ref": "http-package-request",
    }
    result = {
        "outcome": outcome,
        "reason_code": "package_verified" if outcome == "downloaded" else "synthetic_failure",
        "coverage": "complete" if outcome == "downloaded" else "partial",
        "artifacts": [artifact] if outcome == "downloaded" else [],
        "attempts": [],
    }
    if collector_mode is not None:
        result["collector_mode"] = collector_mode
    metadata = finalize_package(
        tmp_path,
        job_id="task-synthetic",
        entry_url="https://capture.synthetic.test/",
        terminal_result=result,
        observation_path=tmp_path / "task-observations.jsonl",
        max_bytes=32 * 1024 * 1024,
    )
    if mutate_source:
        assert metadata["state"] == "failed"
        assert metadata["reason_code"] == "task_evidence_material_mismatch"
        return tmp_path / "data-package" / "captu.synth.test.zip"
    assert metadata["state"] == "ready"
    return tmp_path / "data-package" / metadata["filename"]


def test_archive_keeps_web_material_separate_from_external_package(tmp_path: Path) -> None:
    archive = _archive(tmp_path)
    manifest, _ = verify_task_archive(archive, max_bytes=32 * 1024 * 1024)

    assert manifest["package_result"]["outcome"] == "downloaded"
    assert manifest["web_materials"] == {
        "state": "saved",
        "count": 1,
        "coverage": "partial",
        "gaps": [],
    }
    assert manifest["files"][0]["request_association"] == "known"
    assert manifest["files"][0]["request_ref"] == "http-web-request"
    assert manifest["external_packages"][0]["request_ref"] == "http-package-request"
    with zipfile.ZipFile(archive) as bundle:
        assert "web/index.html" in bundle.namelist()
        assert all("original.apk" not in name for name in bundle.namelist())
        assert b"synthetic-original-package" not in b"".join(
            bundle.read(name) for name in bundle.namelist()
        )


def test_http_and_browser_coverage_gaps_are_retained(tmp_path: Path) -> None:
    archive = _archive(tmp_path, collector_mode="http")
    manifest, _ = verify_task_archive(archive, max_bytes=32 * 1024 * 1024)
    assert {
        "http_subresource_coverage_limited",
        "http_javascript_not_executed",
    }.issubset(manifest["web_materials"]["gaps"])

    browser = tmp_path / "browser"
    browser.mkdir()
    metadata = finalize_package(
        browser,
        job_id="browser-gaps",
        entry_url="https://capture.synthetic.test/",
        terminal_result={
            "outcome": "failed",
            "reason_code": "browser_network_error",
            "coverage": "partial",
            "collector_mode": "browser",
            "network_attempts": [
                {
                    "result": {
                        "gaps": ["browser_subresource_http_error"],
                        "landing": {"gaps": ["browser_snapshot_missing"]},
                    }
                }
            ],
        },
        observation_path=browser / "missing-observations.jsonl",
        max_bytes=32 * 1024 * 1024,
    )
    assert metadata["state"] == "ready"
    assert {
        "browser_subresource_http_error",
        "browser_snapshot_missing",
    }.issubset(metadata["web_materials"]["gaps"])


def test_failed_task_still_has_verifiable_failure_archive(tmp_path: Path) -> None:
    archive = _archive(tmp_path, outcome="failed")
    manifest, _ = verify_task_archive(archive, max_bytes=32 * 1024 * 1024)
    assert manifest["package_result"]["outcome"] == "failed"
    assert manifest["web_materials"]["state"] == "saved"
    with zipfile.ZipFile(archive) as bundle:
        assert all("original.apk" not in name for name in bundle.namelist())
        assert b"synthetic-original-package" not in bundle.read("observations.jsonl")


def test_source_mutation_before_seal_is_rejected(tmp_path: Path) -> None:
    assert not _archive(tmp_path, mutate_source=True).exists()


def test_manifest_request_association_tampering_is_rejected(tmp_path: Path) -> None:
    original = _archive(tmp_path)
    with zipfile.ZipFile(original) as source:
        members = {item.filename: source.read(item) for item in source.infolist()}
    manifest = json.loads(members["manifest.json"])
    manifest["files"][0]["request_ref"] = "http-unobserved-request"
    members[manifest["files"][0]["path"]] = b"substituted synthetic page"
    manifest["files"][0]["size"] = len(members[manifest["files"][0]["path"]])
    manifest["files"][0]["sha256"] = hashlib.sha256(
        members[manifest["files"][0]["path"]]
    ).hexdigest()
    members["manifest.json"] = json.dumps(manifest, separators=(",", ":")).encode()
    tampered = tmp_path / "association-tampered.zip"
    with zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_DEFLATED) as target:
        for name, value in members.items():
            target.writestr(name, value)
    with pytest.raises(EvidenceError):
        verify_task_archive(tampered, max_bytes=32 * 1024 * 1024)


def test_partial_package_prefix_is_not_archived(tmp_path: Path) -> None:
    archive = _archive(tmp_path, outcome="failed")
    with zipfile.ZipFile(archive) as bundle:
        manifest = json.loads(bundle.read("manifest.json"))
        assert "package_body_not_included" in manifest["gaps"]
        assert b"synthetic-original" not in b"".join(
            bundle.read(name) for name in bundle.namelist()
        )
        observations = bundle.read("observations.jsonl").decode("utf-8")
        assert '"kind":"response_prefix_saved"' in observations
        assert all("original.apk" not in name for name in bundle.namelist())


def test_observation_parser_preserves_prefix_and_rejects_invalid_interior() -> None:
    from fxfetch.core.task_evidence_provenance import parse_observations

    start = (
        b'{"seq":1,"observed_at":"2026-10-29T00:00:00Z","collector":"task",'
        b'"attempt_id":"job","kind":"task_observation_started","fields":{}}\n'
    )
    rows, _, state, gaps, *_ = parse_observations(start + b'{"seq":2')
    assert len(rows) == 1
    assert state == "truncated"
    assert "observations_trailing_record_truncated" in gaps
    rows, _, state, gaps, *_ = parse_observations(start + b'not-json\n' + start)
    assert len(rows) == 1
    assert state == "failed"
    assert "observations_invalid" in gaps


def test_truncation_marker_cannot_be_sealed_as_healthy() -> None:
    from fxfetch.core.task_evidence_provenance import parse_observations

    values = [
        ("task_observation_started", {}),
        ("journal_truncated", {}),
        (
            "task_observation_finished",
            {"state": "healthy", "gaps": [], "records_before_close": 2},
        ),
    ]
    raw = b"".join(
        (
            json.dumps(
                {
                    "seq": sequence,
                    "observed_at": f"2026-10-29T00:00:0{sequence}Z",
                    "collector": "task",
                    "attempt_id": "job",
                    "kind": kind,
                    "fields": fields,
                },
                separators=(",", ":"),
            ).encode()
            + b"\n"
        )
        for sequence, (kind, fields) in enumerate(values, start=1)
    )
    _, _, state, gaps, *_ = parse_observations(raw)
    assert state == "failed"
    assert "observations_lifecycle_invalid" in gaps


def test_interrupted_journal_archive_preserves_truncated_raw_tail(tmp_path: Path) -> None:
    recorder = TaskEvidenceRecorder(tmp_path)
    recorder.close()
    journal = tmp_path / "task-observations.jsonl"
    rows = journal.read_bytes().splitlines(keepends=True)
    raw = b"".join(rows[:-1]) + b'{"seq":3'
    journal.write_bytes(raw)
    metadata = finalize_package(
        tmp_path,
        job_id="interrupted-task",
        entry_url="https://capture.synthetic.test/",
        terminal_result={
            "outcome": "failed",
            "reason_code": "worker_interrupted",
            "coverage": "partial",
            "artifacts": [],
            "attempts": [],
            "gaps": [],
        },
        observation_path=journal,
        max_bytes=32 * 1024 * 1024,
    )
    assert metadata["state"] == "ready"
    archive = tmp_path / "data-package" / metadata["filename"]
    manifest, _ = verify_task_archive(archive, max_bytes=32 * 1024 * 1024)
    assert manifest["observations"]["state"] == "failed"
    assert "observation_receipt_mismatch" in manifest["observations"]["gaps"]
    with zipfile.ZipFile(archive) as bundle:
        assert bundle.read("observations.jsonl") == raw


@pytest.mark.parametrize("corruption", ["invalid_receipt", "invalid_interior_record"])
def test_degraded_journal_keeps_raw_bytes_and_valid_prefix(
    tmp_path: Path, corruption: str
) -> None:
    recorder = TaskEvidenceRecorder(tmp_path)
    recorder.observe_transport(
        {
            "event": "request_attempted",
            "request_ref": "synthetic-request",
            "url": "https://capture.synthetic.test/",
            "method": "GET",
        }
    )
    recorder.close()
    journal = tmp_path / "task-observations.jsonl"
    raw = journal.read_bytes()
    if corruption == "invalid_receipt":
        journal.with_suffix(".jsonl.status.json").write_text("{", encoding="utf-8")
    else:
        lines = raw.splitlines(keepends=True)
        raw = b"".join(lines[:2]) + b"not-json\n" + b"".join(lines[2:])
        journal.write_bytes(raw)
    metadata = finalize_package(
        tmp_path,
        job_id=f"degraded-{corruption}",
        entry_url="https://capture.synthetic.test/",
        terminal_result={
            "outcome": "failed",
            "reason_code": "synthetic_failure",
            "coverage": "partial",
            "artifacts": [],
            "attempts": [],
        },
        observation_path=journal,
        max_bytes=32 * 1024 * 1024,
    )
    assert metadata["state"] == "ready"
    archive = tmp_path / "data-package" / metadata["filename"]
    manifest, _ = verify_task_archive(archive, max_bytes=32 * 1024 * 1024)
    assert manifest["observations"]["state"] == "failed"
    assert manifest["observations"]["records"] >= 2
    if corruption == "invalid_receipt":
        assert "observation_receipt_invalid" in manifest["observations"]["gaps"]
    else:
        assert "observations_invalid" in manifest["observations"]["gaps"]
    with zipfile.ZipFile(archive) as bundle:
        assert bundle.read("observations.jsonl") == raw


def test_recorder_failure_is_persisted_in_receipt(tmp_path: Path) -> None:
    recorder = TaskEvidenceRecorder(tmp_path)
    recorder.mark_failed("synthetic_observer_failure")
    recorder.close()
    receipt = json.loads(
        (tmp_path / "task-observations.jsonl.status.json").read_text(encoding="utf-8")
    )
    assert receipt["state"] == "failed"
    assert "synthetic_observer_failure" in receipt["gaps"]


def test_missing_observation_receipt_is_interrupted_not_invalid(tmp_path: Path) -> None:
    from fxfetch.core.task_evidence_observations import read_observations

    journal = tmp_path / "task-observations.jsonl"
    assert read_observations(journal)[1] == "unavailable"
    recorder = TaskEvidenceRecorder(tmp_path)
    recorder.close()
    journal.with_suffix(".jsonl.status.json").unlink()
    observation = read_observations(journal)
    assert observation[1] == "interrupted"
    assert "observations_receipt_missing" in observation[3]
    assert "observation_receipt_invalid" not in observation[3]


def test_verify_data_cli_is_offline_and_reports_external_bytes_unverified(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = _archive(tmp_path)
    assert main(["verify-data", str(archive)]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["state"] == "verified"
    assert value["external_packages_verified"] is False


@pytest.mark.parametrize(
    ("member_name", "changed_name", "reason_code"),
    [
        ("manifest.json", "MANIFEST.JSON", "task_evidence_manifest_missing"),
        ("observations.jsonl", "OBSERVATIONS.JSONL", "task_evidence_unlisted_file"),
        ("web/index.html", "WEB/index.html", "task_evidence_unlisted_file"),
    ],
)
def test_case_changed_archive_members_fail_verifier_and_cli(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    member_name: str,
    changed_name: str,
    reason_code: str,
) -> None:
    original = _archive(tmp_path)
    with zipfile.ZipFile(original) as source:
        members = {item.filename: source.read(item) for item in source.infolist()}
    damaged = tmp_path / "case-changed.zip"
    with zipfile.ZipFile(damaged, "w", compression=zipfile.ZIP_DEFLATED) as target:
        for name, value in members.items():
            target.writestr(changed_name if name == member_name else name, value)

    with pytest.raises(EvidenceError, match=reason_code):
        verify_task_archive(damaged, max_bytes=32 * 1024 * 1024)

    assert main(["verify-data", str(damaged)]) == 1
    value = json.loads(capsys.readouterr().out)
    assert value == {"state": "failed", "reason_code": reason_code}


@pytest.mark.parametrize("damage", ["truncated", "tampered", "unsafe"])
def test_verifier_rejects_truncated_tampered_and_unsafe_archives(
    tmp_path: Path, damage: str
) -> None:
    original = _archive(tmp_path)
    damaged = tmp_path / "damaged.zip"
    if damage == "truncated":
        damaged.write_bytes(original.read_bytes()[:32])
    else:
        with zipfile.ZipFile(original) as source:
            members = {item.filename: source.read(item) for item in source.infolist()}
        if damage == "tampered":
            members["web/index.html"] = b"tampered"
        else:
            members["../unsafe"] = b"unsafe"
        with zipfile.ZipFile(damaged, "w", compression=zipfile.ZIP_DEFLATED) as target:
            for name, value in members.items():
                target.writestr(name, value)

    with pytest.raises(EvidenceError):
        verify_task_archive(damaged, max_bytes=32 * 1024 * 1024)


def test_package_filename_reuses_offline_apk_naming() -> None:
    assert package_filename("https://abcdef.example.test/") == "abcde.examp.test.zip"


def test_same_archive_name_isolated_in_per_job_directories(tmp_path: Path) -> None:
    first_root, second_root = tmp_path / "job-a", tmp_path / "job-b"
    first_root.mkdir()
    second_root.mkdir()
    first = _archive(first_root)
    second = _archive(second_root)

    assert first.name == second.name
    assert first != second
    assert first.is_file() and second.is_file()


def test_archive_read_rejects_symlink_ancestor(tmp_path: Path) -> None:
    archive = _archive(tmp_path / "real")
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(archive.parent, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"directory symlinks unavailable: {error}")
    with pytest.raises(EvidenceError, match="evidence_link_rejected"):
        verify_task_archive(alias / archive.name, max_bytes=32 * 1024 * 1024)


def test_metadata_and_observation_reads_reject_symlink_ancestor(tmp_path: Path) -> None:
    from fxfetch.core.task_evidence import package_metadata
    from fxfetch.core.task_evidence_observations import read_observations

    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except (NotImplementedError, OSError) as error:
        pytest.skip(f"directory symlinks unavailable: {error}")

    metadata = package_metadata(alias, "completed")
    assert metadata["state"] == "failed"
    assert metadata["reason_code"] == "data_package_storage_path_invalid"
    observation = read_observations(alias / "task-observations.jsonl")
    assert observation[1] == "failed"
    assert "observations_invalid" in observation[3]


def test_archive_sealing_deadline_is_enforced(tmp_path: Path) -> None:
    with pytest.raises(EvidenceError, match="task_evidence_seal_timeout"):
        build_task_archive(
            tmp_path,
            tmp_path / "data-package" / "synthetic.zip",
            job_id="deadline-test",
            entry_url="https://capture.synthetic.test/",
            package_result={"outcome": "failed", "reason_code": "synthetic", "coverage": "partial"},
            result={"artifacts": [], "attempts": [], "gaps": []},
            observation_path=None,
            max_bytes=1024 * 1024,
            max_seconds=0,
        )


def test_sealing_failure_does_not_change_original_package_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from fxfetch.core import task_evidence

    original = tmp_path / "artifacts" / "original.apk"
    original.parent.mkdir()
    original.write_bytes(b"original package")
    result = {
        "outcome": "downloaded",
        "reason_code": "package_verified",
        "coverage": "complete",
        "artifacts": [
            {
                "kind": "apk",
                "path": str(original),
                "size": original.stat().st_size,
                "sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
            }
        ],
    }

    def fail_archive(*_: object, **__: object) -> None:
        raise EvidenceError("synthetic_storage_failure")

    monkeypatch.setattr(task_evidence, "build_task_archive", fail_archive)
    metadata = finalize_package(
        tmp_path,
        job_id="task-synthetic",
        entry_url="https://capture.synthetic.test/",
        terminal_result=result,
        observation_path=tmp_path / "missing-observations.jsonl",
        max_bytes=32 * 1024 * 1024,
    )

    assert metadata["state"] == "failed"
    assert result["outcome"] == "downloaded"
    assert original.read_bytes() == b"original package"
