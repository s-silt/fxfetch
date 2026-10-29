"""Bounded ZIP creation and verification for task evidence."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from fxfetch import __version__

from .task_evidence_observations import read_observations
from .task_evidence_provenance import validate_material_provenance, validate_saved_bytes
from .task_evidence_schema import (
    MAX_TASK_FILES,
    TASK_EVIDENCE_SCHEMA,
    EvidenceError,
    validate_task_manifest,
)
from .task_evidence_verify import _bounded_digest, _check_deadline, verify_task_archive
from .web_evidence_io import check_ancestors, is_reparse, source_path


def build_task_archive(
    root: Path,
    archive_path: Path,
    *,
    job_id: str,
    entry_url: str,
    package_result: dict[str, Any],
    result: dict[str, Any],
    observation_path: Path | None,
    max_bytes: int,
    max_seconds: float = 15.0,
) -> tuple[dict[str, Any], str]:
    root = root.absolute()
    deadline = time.monotonic() + max_seconds
    check_ancestors(root)
    check_ancestors(archive_path.parent)
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    check_ancestors(archive_path.parent)
    for directory in (root, archive_path.parent):
        if is_reparse(directory):
            raise EvidenceError("task_evidence_link_rejected")
    (
        observation_bytes,
        observation_state,
        observation_records,
        gaps,
        rows,
        started_at,
        finished_at,
    ) = read_observations(observation_path)
    gaps.extend(_result_gaps(result))
    external = _external_packages(root, result, deadline)
    request_refs = {
        item["fields"].get("request_ref")
        for item in rows
        if item["kind"] == "request_attempted"
    }
    for package in external:
        if package.get("request_ref") not in request_refs:
            package.pop("request_ref", None)
            gaps.append("package_request_association_incomplete")
    package_refs = {item["request_ref"] for item in external if item.get("request_ref")}
    files: list[dict[str, Any]] = []
    sources: list[tuple[str, Path]] = []
    used_paths = {"manifest.json", "observations.jsonl"}
    file_paths: set[str] = set()
    seen_materials: set[tuple[str, str]] = set()
    package_paths, package_hashes = _package_source_facts(root, result)
    for row in rows:
        fields = row.get("fields")
        if not isinstance(fields, dict) or row.get("kind") not in {
            "response_body_saved",
            "response_prefix_saved",
            "terminal_snapshot",
        }:
            continue
        request_ref = fields.get("request_ref")
        if isinstance(request_ref, str) and request_ref in package_refs:
            continue
        if fields.get("package_stream") is True:
            gaps.append("package_body_not_included")
            continue
        relative = fields.get("path")
        if not isinstance(relative, str):
            gaps.append("material_path_unknown")
            continue
        if relative.casefold() in package_paths:
            gaps.append("original_package_excluded")
            continue
        recorded_size, recorded_hash = fields.get("size"), fields.get("sha256")
        if (
            isinstance(recorded_size, bool)
            or not isinstance(recorded_size, int)
            or recorded_size < 0
            or not isinstance(recorded_hash, str)
            or len(recorded_hash) != 64
        ):
            gaps.append("material_provenance_incomplete")
            continue
        key = relative.casefold(), str(request_ref or "")
        if key in seen_materials:
            continue
        seen_materials.add(key)
        try:
            source = source_path(root, relative)
            validate_saved_bytes(source, recorded_size, recorded_hash, max_bytes, deadline)
            size, sha256 = recorded_size, recorded_hash
        except EvidenceError:
            raise
        except OSError as error:
            raise EvidenceError("task_evidence_material_unavailable") from error
        if (size, sha256) in package_hashes:
            gaps.append("original_package_excluded")
            continue
        if size == 0:
            continue
        if len(files) >= MAX_TASK_FILES or sum(item["size"] for item in files) + size > max_bytes:
            gaps.append("material_byte_budget")
            break
        member = relative.replace("\\", "/")
        if member.casefold() in used_paths:
            gaps.append("material_path_collision")
            continue
        folded_parts = {
            "/".join(PurePosixPath(member).parts[:index]).casefold()
            for index in range(1, len(PurePosixPath(member).parts) + 1)
        }
        if folded_parts.intersection(file_paths) or any(
            existing.startswith(member.casefold() + "/") for existing in file_paths
        ):
            gaps.append("material_path_collision")
            continue
        used_paths.add(member.casefold())
        file_paths.add(member.casefold())
        source_url = fields.get("source_url", fields.get("url"))
        record: dict[str, Any] = {
            "path": member,
            "size": size,
            "sha256": sha256,
            "representation": str(fields.get("representation") or "http_response_body")[:128],
            "complete": fields.get("complete") is True,
            "source_url": source_url if isinstance(source_url, str) else None,
            "request_association": (
                "known"
                if isinstance(request_ref, str)
                and request_ref
                and any(
                    item["kind"] == "request_attempted"
                    and item["fields"].get("request_ref") == request_ref
                    for item in rows
                )
                else "unknown"
            ),
        }
        if record["request_association"] == "known":
            record["request_ref"] = request_ref
        elif isinstance(request_ref, str) and request_ref:
            gaps.append("material_request_association_incomplete")
        files.append(record)
        sources.append((member, source))
    validate_material_provenance(
        rows,
        files,
        external,
        allow_incomplete=observation_state != "healthy",
    )
    state = "saved" if files else "empty"
    manifest: dict[str, Any] = {
        "schema_version": TASK_EVIDENCE_SCHEMA,
        "producer_version": __version__,
        "job_id": job_id,
        "entry_url": entry_url,
        "package_result": {
            "outcome": package_result.get("outcome", "failed"),
            "reason_code": package_result.get("reason_code"),
            "coverage": package_result.get("coverage", "partial"),
        },
        "web_materials": {
            "state": state,
            "count": len(files),
            "coverage": "partial",
            "gaps": list(dict.fromkeys(gaps))[:256],
        },
        "observations": {
            "state": observation_state,
            "records": observation_records,
            "path": "observations.jsonl" if observation_bytes is not None else None,
            "size": len(observation_bytes or b""),
            "sha256": hashlib.sha256(observation_bytes).hexdigest() if observation_bytes is not None else None,
            "started_at": started_at,
            "finished_at": finished_at,
            "gaps": list(dict.fromkeys(gaps))[:256],
        },
        "attempts": _attempts(result),
        "files": files,
        "external_packages": external,
        "gaps": list(dict.fromkeys(gaps))[:256],
    }
    validate_task_manifest(manifest)
    pending = archive_path.with_suffix(archive_path.suffix + ".pending")
    encoded_manifest = json.dumps(
        manifest, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    try:
        used = _safe_source_usage(root, deadline)
        archive_budget = max_bytes - used
        if archive_budget <= 0:
            raise EvidenceError("task_evidence_storage_budget")
        estimate = len(encoded_manifest) + len(observation_bytes or b"") + sum(
            record["size"] for record in files
        ) + 1024 * (len(files) + 2)
        if estimate > min(archive_budget, shutil.disk_usage(archive_path.parent).free):
            raise EvidenceError("task_evidence_storage_budget")
        check_ancestors(pending)
        check_ancestors(archive_path)
        with zipfile.ZipFile(pending, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
            _check_deadline(deadline)
            bundle.writestr("manifest.json", encoded_manifest)
            if observation_bytes is not None:
                info = zipfile.ZipInfo("observations.jsonl")
                info.compress_type = zipfile.ZIP_DEFLATED
                with bundle.open(info, "w") as stream:
                    for offset in range(0, len(observation_bytes), 64 * 1024):
                        _check_deadline(deadline)
                        stream.write(observation_bytes[offset : offset + 64 * 1024])
            for member, source in sources:
                _check_deadline(deadline)
                check_ancestors(source)
                expected = next(item for item in files if item["path"] == member)
                copied = hashlib.sha256()
                copied_size = 0
                info = zipfile.ZipInfo(member)
                info.compress_type = zipfile.ZIP_DEFLATED
                with source.open("rb") as input_stream, bundle.open(info, "w") as output_stream:
                    while block := input_stream.read(64 * 1024):
                        _check_deadline(deadline)
                        copied_size += len(block)
                        if copied_size > max_bytes:
                            raise EvidenceError("task_evidence_archive_too_large")
                        copied.update(block)
                        output_stream.write(block)
                if copied_size != expected["size"] or copied.hexdigest() != expected["sha256"]:
                    raise EvidenceError("task_evidence_material_mismatch")
        verify_task_archive(pending, max_bytes=archive_budget, deadline=deadline)
        pending.replace(archive_path)
    except Exception:
        pending.unlink(missing_ok=True)
        raise
    size, sha256 = _bounded_digest(archive_path, max_bytes, deadline)
    return manifest, sha256


def _external_packages(
    root: Path, result: dict[str, Any], deadline: float | None = None
) -> list[dict[str, Any]]:
    values = []
    for artifact in result.get("artifacts", [])[:16]:
        if not isinstance(artifact, dict) or artifact.get("kind") not in {"apk", "ipa"}:
            continue
        path = artifact.get("path")
        if not isinstance(path, (str, Path)):
            continue
        candidate = Path(path)
        try:
            relative = candidate.absolute().relative_to(root.absolute()).as_posix()
        except ValueError:
            continue
        try:
            candidate = source_path(root, relative)
            size, sha256 = _bounded_digest(
                candidate, max(1, int(artifact.get("size", 0)) + 1), deadline
            )
        except EvidenceError as error:
            if error.code == "task_evidence_seal_timeout":
                raise
            continue
        except (OSError, TypeError, ValueError):
            continue
        if size != artifact.get("size") or sha256 != artifact.get("sha256"):
            continue
        record = {
            "kind": artifact["kind"],
            "size": size,
            "sha256": sha256,
            "source_url": str(artifact.get("url") or result.get("entry_url") or ""),
            "complete": True,
            "validated": True,
        }
        if isinstance(artifact.get("request_ref"), str):
            record["request_ref"] = artifact["request_ref"]
        values.append(record)
    return values


def _attempts(result: dict[str, Any]) -> list[dict[str, Any]]:
    attempts = []
    for item in result.get("attempts", [])[:64]:
        if isinstance(item, dict):
            attempts.append(
                {
                    key: item[key]
                    for key in ("attempt_id", "chain", "url", "outcome", "reason_code", "coverage")
                    if key in item
                    and (
                        isinstance(item.get(key), (str, int, bool))
                        or item.get(key) is None
                    )
                }
            )
    for item in result.get("network_attempts", [])[:8]:
        if isinstance(item, dict):
            value = {
                key: item[key]
                for key in ("attempt_id", "network_mode", "session_continuity", "cookies_inherited")
                if key in item
            }
            detail = item.get("result")
            if isinstance(detail, dict):
                value["result"] = {
                    key: detail[key] for key in ("outcome", "reason_code", "coverage") if key in detail
                }
            attempts.append(value)
    return attempts


def _safe_source_usage(root: Path, deadline: float) -> int:
    pending = [(root, 0)]
    total = entries = 0
    while pending:
        directory, depth = pending.pop()
        _check_deadline(deadline)
        if is_reparse(directory):
            continue
        with os.scandir(directory) as iterator:
            for entry in iterator:
                _check_deadline(deadline)
                entries += 1
                if entries > 50_000:
                    raise EvidenceError("task_evidence_file_count_limit")
                child = Path(entry.path)
                if is_reparse(child):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if depth >= 64:
                        raise EvidenceError("task_evidence_directory_depth_limit")
                    pending.append((child, depth + 1))
                elif entry.is_file(follow_symlinks=False):
                    total += entry.stat(follow_symlinks=False).st_size
    return total


def _result_gaps(result: dict[str, Any]) -> list[str]:
    values: list[str] = []
    sources: list[object] = [result.get("gaps")]
    for name in ("landing", "offline", "page_qr"):
        value = result.get(name)
        if isinstance(value, dict):
            sources.extend([value.get("gaps"), value.get("reasons")])
    for attempt in result.get("network_attempts", [])[:8]:
        detail = attempt.get("result") if isinstance(attempt, dict) else None
        if isinstance(detail, dict):
            sources.append(detail.get("gaps"))
            for name in ("landing", "offline", "page_qr"):
                value = detail.get(name)
                if isinstance(value, dict):
                    sources.extend([value.get("gaps"), value.get("reasons")])
    for source in sources:
        if isinstance(source, list):
            values.extend(item[:256] for item in source[:256] if isinstance(item, str) and item)
    if result.get("collector_mode") in {"http", "http_first"}:
        values.append("http_subresource_coverage_limited")
        values.append("http_javascript_not_executed")
    offline = result.get("offline")
    if isinstance(offline, dict) and offline.get("coverage") == "partial":
        reasons = offline.get("reasons")
        if isinstance(reasons, list):
            values.extend(item[:256] for item in reasons[:64] if isinstance(item, str) and item)
    return values[:512]


def _package_source_facts(root: Path, result: dict[str, Any]) -> tuple[set[str], set[tuple[int, str]]]:
    paths: set[str] = set()
    hashes: set[tuple[int, str]] = set()
    root_abs = root.absolute()
    for artifact in result.get("artifacts", [])[:16]:
        if not isinstance(artifact, dict) or artifact.get("kind") not in {"apk", "ipa"}:
            continue
        raw_path = artifact.get("path")
        if not isinstance(raw_path, (str, Path)):
            continue
        candidate = Path(raw_path)
        try:
            relative = (
                candidate.absolute().relative_to(root_abs).as_posix()
                if candidate.is_absolute()
                else candidate.as_posix()
            )
            source_path(root, relative)
        except (ValueError, EvidenceError):
            continue
        paths.add(relative.casefold())
        size, sha256 = artifact.get("size"), artifact.get("sha256")
        if isinstance(size, int) and not isinstance(size, bool) and isinstance(sha256, str):
            hashes.add((size, sha256))
    return paths, hashes
