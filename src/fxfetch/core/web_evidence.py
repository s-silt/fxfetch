"""Offline export and verification orchestration for web evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any

from .. import __version__
from .limits import Limits
from .web_evidence_io import (
    check_ancestors,
    contained,
    digest,
    directory_inventory,
    is_reparse,
    read_json_object,
    source_path,
)
from .web_evidence_schema import (
    BUNDLE_SCHEMA,
    MAX_FILES,
    MAX_MANIFEST_BYTES,
    EvidenceError,
    strict_json,
    validate_common,
    validate_file_record,
)
from .web_provenance import JournalFacts, validate_journal, validate_material_provenance


def _read_summary(root: Path) -> dict[str, Any]:
    summary = read_json_object(source_path(root, "capture.json"), MAX_MANIFEST_BYTES)
    validate_common(summary, summary=True)
    return summary


def _capture_files(
    root: Path, summary: dict[str, Any], limits: Limits
) -> list[dict[str, Any]]:
    materials = summary.get("materials")
    if not isinstance(materials, list) or len(materials) > MAX_FILES - 1:
        raise EvidenceError("evidence_file_count_invalid")
    used_paths = {"capture.jsonl"}
    component_spellings = {"capture.jsonl": "capture.jsonl"}
    journal_path = source_path(root, "capture.jsonl")
    journal_size, journal_hash, facts = validate_journal(
        journal_path,
        summary["collector"],
        min(limits.max_task_bytes, 8 * 1024 * 1024),
        complete=summary["journal_state"] == "healthy",
    )
    records = [
        {
            "path": "capture.jsonl",
            "size": journal_size,
            "sha256": journal_hash,
            "role": "provenance_journal",
            "representation": "append_only_jsonl",
            "complete": summary["journal_state"] == "healthy",
            "source_url": None,
            "request_ref": None,
        }
    ]
    total = journal_size
    for material in materials:
        record = validate_file_record(material, used_paths, component_spellings)
        source_path(root, record["path"])
        total += record["size"]
        if total > limits.max_task_bytes:
            raise EvidenceError("evidence_budget_exceeded")
        records.append(record)
    if len(records) > MAX_FILES:
        raise EvidenceError("evidence_file_count_invalid")
    validate_material_provenance(
        records,
        facts,
        allow_missing=summary["journal_state"] != "healthy"
        and "material_provenance_incomplete" in summary["gaps"],
    )
    return records


def _remove_created(files: list[Path], directories: list[Path]) -> None:
    for path in reversed(files):
        try:
            path.unlink()
        except OSError:
            pass
    for path in reversed(directories):
        try:
            path.rmdir()
        except OSError:
            pass


def _manifest_from_summary(summary: dict[str, Any], records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": BUNDLE_SCHEMA,
        "producer_version": __version__,
        "capture_id": summary["capture_id"],
        "entry_url": summary["entry_url"],
        "collector": summary["collector"],
        "started_at": summary["started_at"],
        "finished_at": summary["finished_at"],
        "outcome": summary["outcome"],
        "reason_code": summary["reason_code"],
        "coverage": summary["coverage"],
        "gaps": summary["gaps"],
        "files": records,
    }


def _copy_record(
    source_root: Path,
    destination_root: Path,
    record: dict[str, Any],
    limits: Limits,
    created_files: list[Path],
    created_dirs: list[Path],
) -> None:
    source = source_path(source_root, record["path"])
    target = destination_root.joinpath(*PurePosixPath(record["path"]).parts)
    if not contained(destination_root, target):
        raise EvidenceError("evidence_path_escape")
    parent = destination_root
    for component in PurePosixPath(record["path"]).parts[:-1]:
        parent /= component
        if not parent.exists():
            parent.mkdir()
            created_dirs.append(parent)
        elif is_reparse(parent) or not parent.is_dir():
            raise EvidenceError("evidence_path_invalid")
    copied = 0
    value = hashlib.sha256()
    try:
        with source.open("rb") as reader, target.open("xb") as writer:
            created_files.append(target)
            while block := reader.read(64 * 1024):
                copied += len(block)
                if copied > record["size"] or copied > limits.max_task_bytes:
                    raise EvidenceError("evidence_source_changed")
                value.update(block)
                writer.write(block)
    except OSError as error:
        raise EvidenceError("evidence_file_unavailable") from error
    if copied != record["size"] or value.hexdigest() != record["sha256"]:
        raise EvidenceError("evidence_source_changed")


def export_web(capture_dir: Path, output_dir: Path, limits: Limits) -> tuple[dict[str, Any], str]:
    source = Path(os.path.abspath(capture_dir))
    destination = Path(os.path.abspath(output_dir))
    if not source.is_dir() or is_reparse(source):
        raise EvidenceError("capture_directory_invalid")
    check_ancestors(source)
    check_ancestors(destination.parent)
    if destination.exists():
        raise EvidenceError("bundle_output_exists")
    resolved_source = source.resolve()
    resolved_destination = destination.resolve(strict=False)
    if contained(resolved_source, resolved_destination) or contained(resolved_destination, resolved_source):
        raise EvidenceError("bundle_output_overlap")
    if not destination.parent.is_dir():
        raise EvidenceError("bundle_parent_missing")
    summary = _read_summary(source)
    records = _capture_files(source, summary, limits)
    manifest = _manifest_from_summary(summary, records)
    validate_common(manifest, summary=False)
    encoded_manifest = json.dumps(
        manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    if len(encoded_manifest) > MAX_MANIFEST_BYTES:
        raise EvidenceError("evidence_manifest_too_large")
    created_files: list[Path] = []
    created_dirs: list[Path] = []
    try:
        destination.mkdir()
        created_dirs.append(destination)
        for record in records:
            _copy_record(source, destination, record, limits, created_files, created_dirs)
        manifest_path = destination / "manifest.json"
        with manifest_path.open("xb") as stream:
            created_files.append(manifest_path)
            stream.write(encoded_manifest)
        directory_inventory(destination, {"manifest.json", *(record["path"] for record in records)})
        _manifest_file(destination / "manifest.json", limits)
        return manifest, hashlib.sha256(encoded_manifest).hexdigest()
    except Exception:
        _remove_created(created_files, created_dirs)
        raise


def _manifest_file(path: Path, limits: Limits) -> tuple[dict[str, Any], bytes]:
    if is_reparse(path):
        raise EvidenceError("evidence_link_rejected")
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_MANIFEST_BYTES + 1)
            if len(raw) > MAX_MANIFEST_BYTES:
                raise EvidenceError("evidence_manifest_too_large")
            manifest = strict_json(raw)
    except EvidenceError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        raise EvidenceError("evidence_manifest_invalid") from error
    if not isinstance(manifest, dict):
        raise EvidenceError("evidence_manifest_invalid")
    validate_common(manifest, summary=False)
    files = manifest.get("files")
    if not isinstance(files, list) or not files or len(files) > MAX_FILES:
        raise EvidenceError("evidence_file_count_invalid")
    used_paths: set[str] = set()
    component_spellings: dict[str, str] = {}
    validated = [validate_file_record(record, used_paths, component_spellings) for record in files]
    if "capture.jsonl" not in used_paths:
        raise EvidenceError("evidence_journal_missing")
    manifest["files"] = validated
    total = 0
    for record in validated:
        total += record["size"]
        if total > limits.max_task_bytes:
            raise EvidenceError("evidence_budget_exceeded")
    return manifest, raw


def _verify_journal_metadata(
    manifest: dict[str, Any],
    journal: Path,
    journal_record: dict[str, Any],
    limits: Limits,
) -> JournalFacts:
    if (
        journal_record["role"] != "provenance_journal"
        or journal_record["representation"] != "append_only_jsonl"
        or journal_record["source_url"] is not None
        or journal_record["request_ref"] is not None
    ):
        raise EvidenceError("evidence_journal_metadata_invalid")
    _, _, facts = validate_journal(
        journal,
        manifest["collector"],
        min(limits.max_task_bytes, 8 * 1024 * 1024),
        complete=journal_record["complete"],
    )
    return facts


def verify_web(bundle_dir: Path, limits: Limits) -> tuple[dict[str, Any], str]:
    root = Path(os.path.abspath(bundle_dir))
    if not root.is_dir() or is_reparse(root):
        raise EvidenceError("bundle_directory_invalid")
    check_ancestors(root)
    manifest, raw_manifest = _manifest_file(root / "manifest.json", limits)
    expected_files = {"manifest.json", *(record["path"] for record in manifest["files"])}
    directory_inventory(root, expected_files)
    total = 0
    for record in manifest["files"]:
        source = source_path(root, record["path"])
        size, file_hash = digest(source, limits.max_task_bytes)
        total += size
        if size != record["size"] or file_hash != record["sha256"]:
            raise EvidenceError("evidence_integrity_failed")
        if total > limits.max_task_bytes:
            raise EvidenceError("evidence_budget_exceeded")
    journal = source_path(root, "capture.jsonl")
    journal_record = next(item for item in manifest["files"] if item["path"] == "capture.jsonl")
    facts = _verify_journal_metadata(manifest, journal, journal_record, limits)
    validate_material_provenance(
        manifest["files"],
        facts,
        allow_missing=not journal_record["complete"]
        and "material_provenance_incomplete" in manifest["gaps"],
    )
    if len(raw_manifest) > MAX_MANIFEST_BYTES:
        raise EvidenceError("evidence_manifest_too_large")
    return manifest, hashlib.sha256(raw_manifest).hexdigest()


__all__ = ["EvidenceError", "export_web", "verify_web"]
