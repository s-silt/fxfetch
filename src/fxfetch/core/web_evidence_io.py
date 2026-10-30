"""Bounded filesystem operations for web evidence."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any

from .web_evidence_schema import MAX_FILES, EvidenceError, portable_path, strict_json


def is_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise EvidenceError("evidence_path_unavailable") from error
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def check_ancestors(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    for parent in (absolute, *absolute.parents):
        if parent.exists() and is_reparse(parent):
            raise EvidenceError("evidence_link_rejected")


def create_private_evidence_directory(path: Path) -> None:
    """Create a new evidence root, then secure it before writing any material."""
    from ..build_setup import _private_directory

    check_ancestors(path)
    path.mkdir(mode=0o700, exist_ok=False)
    try:
        check_ancestors(path)
        if not _private_directory(path):
            raise EvidenceError("private_permissions_unavailable")
    except (OSError, ValueError):
        # It is still empty: never recursively remove material on setup failure.
        try:
            path.rmdir()
        except OSError:
            pass
        raise


def contained(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def read_json_object(path: Path, maximum: int) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise EvidenceError("evidence_manifest_too_large")
        value = strict_json(raw.decode("utf-8"))
    except EvidenceError:
        raise
    except (OSError, UnicodeError, ValueError) as error:
        raise EvidenceError("evidence_manifest_invalid") from error
    if not isinstance(value, dict):
        raise EvidenceError("evidence_manifest_invalid")
    return value


def digest(path: Path, limit: int) -> tuple[int, str]:
    value = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as stream:
            while block := stream.read(64 * 1024):
                total += len(block)
                if total > limit:
                    raise EvidenceError("evidence_budget_exceeded")
                value.update(block)
    except EvidenceError:
        raise
    except OSError as error:
        raise EvidenceError("evidence_file_unavailable") from error
    return total, value.hexdigest()


def source_path(root: Path, relative: str) -> Path:
    safe = portable_path(relative)
    candidate = root.joinpath(*PurePosixPath(safe).parts)
    resolved_root = root.resolve()
    resolved_candidate = candidate.resolve(strict=False)
    if not contained(resolved_root, resolved_candidate):
        raise EvidenceError("evidence_path_escape")
    current = root
    for part in PurePosixPath(safe).parts:
        current = current / part
        if current.exists() and is_reparse(current):
            raise EvidenceError("evidence_link_rejected")
    if not candidate.is_file():
        raise EvidenceError("evidence_file_missing")
    return candidate


def directory_inventory(root: Path, expected_files: set[str]) -> tuple[set[str], set[str]]:
    expected = {portable_path(path) for path in expected_files}
    actual_files: set[str] = set()
    actual_dirs: set[str] = set()
    seen_paths: set[str] = set()
    visited_entries = 0
    stack = [root]
    while stack:
        current = stack.pop()
        depth = len(current.relative_to(root).parts)
        if depth > 64:
            raise EvidenceError("evidence_directory_depth")
        with os.scandir(current) as entries:
            for entry in entries:
                visited_entries += 1
                if visited_entries > MAX_FILES + 1:
                    raise EvidenceError("evidence_file_count_invalid")
                path = Path(entry.path)
                relative_path = portable_path(path.relative_to(root).as_posix())
                folded_path = relative_path.casefold()
                if folded_path in seen_paths:
                    raise EvidenceError("evidence_path_collision")
                seen_paths.add(folded_path)
                if is_reparse(path):
                    raise EvidenceError("evidence_link_rejected")
                if entry.is_dir(follow_symlinks=False):
                    stack.append(path)
                    actual_dirs.add(relative_path)
                elif entry.is_file(follow_symlinks=False):
                    actual_files.add(relative_path)
                else:
                    raise EvidenceError("evidence_file_type_invalid")
    if actual_files != expected:
        raise EvidenceError("evidence_unlisted_file")
    expected_dirs: set[str] = set()
    for relative in expected:
        parts = PurePosixPath(relative).parts
        expected_dirs.update("/".join(parts[:index]) for index in range(1, len(parts)))
    if not actual_dirs.issubset(expected_dirs):
        raise EvidenceError("evidence_unlisted_directory")
    return actual_files, actual_dirs


def bounded_directory_size(root: Path, *, max_entries: int = MAX_FILES + 1) -> int:
    check_ancestors(root)
    if is_reparse(root) or not root.is_dir():
        raise EvidenceError("evidence_directory_invalid")
    total = entries_seen = 0
    stack = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > 64:
            raise EvidenceError("evidence_directory_depth")
        with os.scandir(current) as entries:
            for entry in entries:
                entries_seen += 1
                if entries_seen > max_entries:
                    raise EvidenceError("evidence_file_count_invalid")
                path = Path(entry.path)
                if is_reparse(path):
                    raise EvidenceError("evidence_link_rejected")
                if entry.is_dir(follow_symlinks=False):
                    stack.append((path, depth + 1))
                elif entry.is_file(follow_symlinks=False):
                    total += entry.stat(follow_symlinks=False).st_size
                else:
                    raise EvidenceError("evidence_file_type_invalid")
    return total
