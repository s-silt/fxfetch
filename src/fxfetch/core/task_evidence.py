"""Service-facing task evidence archive lifecycle."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .task_evidence_io import build_task_archive, verify_task_archive
from .web_evidence_io import check_ancestors, is_reparse
from .web_evidence_schema import EvidenceError, strict_json

_METADATA_LIMIT = 16 * 1024


def package_filename(entry_url: str) -> str:
    from .web_apk import derive_names

    name = derive_names(entry_url).filename
    return (name[:-4] if name.lower().endswith(".apk") else name) + ".zip"


def package_directory(job_dir: Path) -> Path:
    return job_dir / "data-package"


def write_package_metadata(directory: Path, value: dict[str, Any]) -> None:
    check_ancestors(directory)
    directory.mkdir(parents=True, exist_ok=True)
    pending = directory / "metadata.json.pending"
    metadata = directory / "metadata.json"
    for path in (directory, pending, metadata):
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        if is_reparse(path):
            raise EvidenceError("data_package_storage_path_invalid")
    pending.write_text(json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False), encoding="utf-8")
    pending.replace(metadata)


def package_metadata(
    job_dir: Path,
    job_state: str,
    *,
    active: bool = False,
) -> dict[str, Any]:
    path = package_directory(job_dir) / "metadata.json"
    try:
        check_ancestors(path.parent)
    except EvidenceError:
        return {
            "state": "failed",
            "reason_code": "data_package_storage_path_invalid",
            "web_materials": _empty_summary(["data_package_storage_path_invalid"]),
        }
    if not path.is_file():
        return {"state": "unavailable"}
    try:
        if is_reparse(path) or path.stat().st_size > _METADATA_LIMIT:
            raise EvidenceError("data_package_metadata_invalid")
        value = strict_json(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("state") not in {
            "pending", "building", "ready", "failed", "unavailable"
        }:
            raise EvidenceError("data_package_metadata_invalid")
        state = value["state"]
        if state == "ready":
            filename, size, sha256 = value.get("filename"), value.get("size"), value.get("sha256")
            if (
                not isinstance(filename, str) or Path(filename).name != filename or not filename.endswith(".zip")
                or isinstance(size, bool) or not isinstance(size, int) or size < 0
                or not isinstance(sha256, str) or len(sha256) != 64
            ):
                raise EvidenceError("data_package_metadata_invalid")
            summary = value.get("web_materials")
            if not _valid_material_summary(summary):
                raise EvidenceError("data_package_metadata_invalid")
            return {"state": "ready", "filename": filename, "size": size, "sha256": sha256,
                    "web_materials": summary}
        if state == "failed":
            reason = value.get("reason_code")
            summary = value.get("web_materials")
            if not isinstance(reason, str) or not reason or not _valid_material_summary(summary):
                raise EvidenceError("data_package_metadata_invalid")
            return {"state": "failed", "reason_code": reason, "web_materials": summary}
        if state in {"pending", "building"} and not active:
            if state == "pending" and job_state == "queued":
                return {"state": "pending"}
            return {
                "state": "failed",
                "reason_code": "data_package_interrupted",
                "web_materials": _empty_summary(["data_package_interrupted"]),
            }
        if active and state == "pending" and job_state in {"completed", "cancelled", "failed"}:
            return {"state": "building"}
        return {"state": state}
    except (OSError, UnicodeError, ValueError, EvidenceError, RecursionError):
        return {
            "state": "failed",
            "reason_code": "data_package_metadata_invalid",
            "web_materials": _empty_summary(["data_package_metadata_invalid"]),
        }


def finalize_package(
    job_dir: Path,
    *,
    job_id: str,
    entry_url: str,
    terminal_result: dict[str, Any],
    observation_path: Path,
    max_bytes: int,
) -> dict[str, Any]:
    directory = package_directory(job_dir)
    try:
        name = package_filename(entry_url)
        archive = directory / name
        package_result = {
            "outcome": terminal_result.get("outcome", "failed"),
            "reason_code": terminal_result.get("reason_code"),
            "coverage": terminal_result.get("coverage", "partial"),
        }
        manifest, sha256 = build_task_archive(
            job_dir,
            archive,
            job_id=job_id,
            entry_url=entry_url,
            package_result=package_result,
            result=terminal_result,
            observation_path=observation_path,
            max_bytes=max_bytes,
        )
        size = archive.stat().st_size
        _, actual_hash = verify_task_archive(archive, max_bytes=max_bytes)
        if actual_hash != sha256:
            raise EvidenceError("data_package_hash_mismatch")
        metadata = {
            "state": "ready",
            "filename": name,
            "size": size,
            "sha256": sha256,
            "web_materials": manifest["web_materials"],
        }
        write_package_metadata(directory, metadata)
        return metadata
    except Exception as error:
        reason = error.code if isinstance(error, EvidenceError) else "data_package_build_failed"
        metadata = {
            "state": "failed",
            "reason_code": reason,
            "web_materials": _empty_summary([reason]),
        }
        try:
            write_package_metadata(directory, metadata)
        except Exception:
            pass
        return metadata


def package_file(job_dir: Path, metadata: dict[str, Any], max_bytes: int) -> Path:
    if metadata.get("state") != "ready":
        raise EvidenceError("data_package_not_ready")
    path = package_directory(job_dir) / metadata["filename"]
    check_ancestors(path)
    size = path.stat().st_size
    _, sha256 = verify_task_archive(path, max_bytes=max_bytes)
    if size != metadata["size"] or sha256 != metadata["sha256"]:
        raise EvidenceError("data_package_hash_mismatch")
    return path


def _empty_summary(gaps: list[str]) -> dict[str, Any]:
    return {"state": "empty", "count": 0, "coverage": "partial", "gaps": gaps[:256]}


def _valid_material_summary(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"state", "count", "coverage", "gaps"}
        and value["state"] in {"saved", "empty"}
        and isinstance(value["count"], int)
        and not isinstance(value["count"], bool)
        and value["count"] >= 0
        and value["coverage"] == "partial"
        and isinstance(value["gaps"], list)
        and len(value["gaps"]) <= 256
        and all(isinstance(item, str) and item for item in value["gaps"])
    )
