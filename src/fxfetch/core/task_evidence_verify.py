"""Offline validation of bounded task evidence archives."""

from __future__ import annotations

import hashlib
import stat
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from .task_evidence_observations import MAX_OBSERVATION_BYTES
from .task_evidence_provenance import parse_observations, validate_material_provenance
from .task_evidence_schema import (
    MAX_TASK_FILES,
    MAX_TASK_MANIFEST_BYTES,
    EvidenceError,
    strict_json,
    validate_task_manifest,
)
from .web_evidence_io import check_ancestors, is_reparse
from .web_evidence_schema import portable_path


def verify_task_archive(
    path: Path,
    *,
    max_bytes: int,
    max_seconds: float = 15.0,
    deadline: float | None = None,
) -> tuple[dict[str, Any], str]:
    deadline = deadline if deadline is not None else time.monotonic() + max_seconds
    check_ancestors(path)
    if not path.is_file() or is_reparse(path):
        raise EvidenceError("task_evidence_archive_unavailable")
    if path.stat().st_size > max_bytes:
        raise EvidenceError("task_evidence_archive_too_large")
    try:
        with zipfile.ZipFile(path, "r") as bundle:
            infos = bundle.infolist()
            if not infos or len(infos) > MAX_TASK_FILES + 2:
                raise EvidenceError("task_evidence_entry_count_invalid")
            seen: set[str] = set()
            archive_names: set[str] = set()
            spellings: dict[str, str] = {}
            total = 0
            for info in infos:
                _check_deadline(deadline)
                name = info.filename
                if info.is_dir():
                    raise EvidenceError("task_evidence_directory_entry_invalid")
                safe = PurePosixPath(name)
                if safe.as_posix() != name or name in {"", ".", ".."}:
                    raise EvidenceError("task_evidence_path_invalid")
                portable_path(name)
                folded = name.casefold()
                if folded in seen:
                    raise EvidenceError("task_evidence_path_collision")
                seen.add(folded)
                archive_names.add(name)
                for index in range(1, len(safe.parts) + 1):
                    part = "/".join(safe.parts[:index])
                    key = part.casefold()
                    previous = spellings.get(key)
                    if previous is not None and previous != part:
                        raise EvidenceError("task_evidence_path_collision")
                    spellings[key] = part
                mode = info.external_attr >> 16
                if (
                    stat.S_ISLNK(mode)
                    or info.external_attr & 0x400
                    or info.flag_bits & 1
                    or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    or info.file_size > max_bytes
                ):
                    raise EvidenceError("task_evidence_file_type_invalid")
                total += info.file_size
                if total > max_bytes:
                    raise EvidenceError("task_evidence_archive_too_large")
            if "manifest.json" not in archive_names:
                raise EvidenceError("task_evidence_manifest_missing")
            raw = _read_entry(
                bundle, bundle.getinfo("manifest.json"), MAX_TASK_MANIFEST_BYTES, deadline
            )
            manifest = validate_task_manifest(strict_json(raw.decode("utf-8")))
            expected = {"manifest.json"}
            if manifest["observations"]["path"] is not None:
                expected.add("observations.jsonl")
            expected.update(record["path"] for record in manifest["files"])
            if archive_names != expected:
                raise EvidenceError("task_evidence_unlisted_file")
            rows: list[dict[str, Any]] = []
            if manifest["observations"]["path"] is not None:
                observed = _read_entry(
                    bundle, bundle.getinfo("observations.jsonl"), MAX_OBSERVATION_BYTES, deadline
                )
                if (
                    len(observed) != manifest["observations"]["size"]
                    or hashlib.sha256(observed).hexdigest() != manifest["observations"]["sha256"]
                ):
                    raise EvidenceError("task_evidence_hash_mismatch")
                rows, _, state, _, started, finished = parse_observations(observed)
                observation_gaps = set(manifest["observations"]["gaps"])
                receipt_degraded = bool(
                    observation_gaps
                    & {
                        "observation_receipt_mismatch",
                        "observation_receipt_state_mismatch",
                        "observation_receipt_invalid",
                        "observation_receipt_failed",
                        "observations_receipt_missing",
                    }
                )
                state_rank = {
                    "healthy": 0,
                    "interrupted": 1,
                    "truncated": 2,
                    "failed": 3,
                }
                if (
                    len(rows) != manifest["observations"]["records"]
                    or (
                        state != manifest["observations"]["state"]
                        and not (
                            state in state_rank
                            and manifest["observations"]["state"] in state_rank
                            and state_rank[manifest["observations"]["state"]]
                            >= state_rank[state]
                            and receipt_degraded
                        )
                    )
                    or started != manifest["observations"]["started_at"]
                    or finished != manifest["observations"]["finished_at"]
                ):
                    raise EvidenceError("task_evidence_observation_state_mismatch")
            for record in manifest["files"]:
                info = bundle.getinfo(record["path"])
                if info.file_size != record["size"]:
                    raise EvidenceError("task_evidence_size_mismatch")
                digest_value = hashlib.sha256()
                count = 0
                with bundle.open(info) as stream:
                    while block := stream.read(64 * 1024):
                        _check_deadline(deadline)
                        count += len(block)
                        if count > max_bytes:
                            raise EvidenceError("task_evidence_archive_too_large")
                        digest_value.update(block)
                if count != record["size"] or digest_value.hexdigest() != record["sha256"]:
                    raise EvidenceError("task_evidence_hash_mismatch")
            _validate_zip_file_hierarchy(seen)
            validate_material_provenance(
                rows,
                manifest["files"],
                manifest["external_packages"],
                allow_incomplete=manifest["observations"]["state"] != "healthy",
            )
    except EvidenceError:
        raise
    except (OSError, ValueError, UnicodeError, zipfile.BadZipFile, RuntimeError) as error:
        raise EvidenceError("task_evidence_archive_invalid") from error
    size, sha256 = _bounded_digest(path, max_bytes, deadline)
    return manifest, sha256


def _read_entry(
    bundle: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int, deadline: float
) -> bytes:
    if info.file_size > limit:
        raise EvidenceError("task_evidence_entry_too_large")
    value = bytearray()
    with bundle.open(info) as stream:
        while block := stream.read(min(64 * 1024, limit + 1 - len(value))):
            _check_deadline(deadline)
            value.extend(block)
            if len(value) > limit:
                raise EvidenceError("task_evidence_entry_too_large")
    return bytes(value)


def _validate_zip_file_hierarchy(paths: set[str]) -> None:
    folded_paths = {value.casefold() for value in paths}
    for path in paths:
        parts = PurePosixPath(path).parts
        if any(
            "/".join(parts[:index]).casefold() in folded_paths
            for index in range(1, len(parts))
        ):
            raise EvidenceError("task_evidence_path_collision")


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise EvidenceError("task_evidence_seal_timeout")


def _bounded_digest(
    path: Path, limit: int, deadline: float | None = None
) -> tuple[int, str]:
    check_ancestors(path)
    if is_reparse(path):
        raise EvidenceError("task_evidence_link_rejected")
    digest_value = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        while block := stream.read(64 * 1024):
            if deadline is not None:
                _check_deadline(deadline)
            count += len(block)
            if count > limit:
                raise EvidenceError("task_evidence_archive_too_large")
            digest_value.update(block)
    return count, digest_value.hexdigest()
