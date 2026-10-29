"""Schema and pure validation helpers for web evidence."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any

from .errors import FxfetchError
from .guard import validate_url

BUNDLE_SCHEMA = "fxfetch.web-evidence.v1"
CAPTURE_SCHEMA = "fxfetch.web-capture.v1"
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_FILES = 2000
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MANIFEST_FIELDS = {
    "schema_version", "producer_version", "capture_id", "entry_url", "collector",
    "started_at", "finished_at", "outcome", "reason_code", "coverage", "gaps", "files",
}
FILE_FIELDS = {
    "path", "size", "sha256", "role", "representation", "complete", "source_url", "request_ref",
}
SUMMARY_FIELDS = {
    "schema_version", "capture_id", "entry_url", "collector", "started_at", "finished_at",
    "outcome", "reason_code", "coverage", "gaps", "journal_state", "materials",
}


class EvidenceError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def strict_json(raw: str | bytes) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(
            raw,
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON")),
        )
    except RecursionError as error:
        raise ValueError("JSON nesting exceeds parser budget") from error


def portable_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise EvidenceError("evidence_path_invalid")
    if "\\" in value or value.startswith(("/", "//")) or re.match(r"^[A-Za-z]:", value):
        raise EvidenceError("evidence_path_invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise EvidenceError("evidence_path_invalid")
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
    if any(
        any(char in '<>:"|?*' for char in part)
        or part[-1] in " ."
        or any(ord(char) < 32 for char in part)
        or part.split(".", 1)[0].casefold() in reserved
        for part in path.parts
    ):
        raise EvidenceError("evidence_path_invalid")
    return path.as_posix()


def timestamp(value: object) -> bool:
    if not isinstance(value, str) or len(value) > 64:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.tzinfo is not None
    except ValueError:
        return False


def validate_common(value: dict[str, Any], *, summary: bool) -> None:
    expected = SUMMARY_FIELDS if summary else MANIFEST_FIELDS
    if set(value) != expected:
        raise EvidenceError("evidence_schema_fields_invalid")
    schema = value.get("schema_version")
    required_schema = CAPTURE_SCHEMA if summary else BUNDLE_SCHEMA
    if schema != required_schema:
        raise EvidenceError("evidence_schema_unsupported")
    if summary:
        if value.get("journal_state") not in ("healthy", "truncated", "failed"):
            raise EvidenceError("evidence_journal_state_invalid")
    elif not isinstance(value.get("producer_version"), str) or not value["producer_version"]:
        raise EvidenceError("evidence_producer_invalid")
    capture_id = value.get("capture_id")
    if not isinstance(capture_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", capture_id):
        raise EvidenceError("evidence_capture_id_invalid")
    if not isinstance(value.get("entry_url"), str):
        raise EvidenceError("evidence_entry_url_invalid")
    try:
        validate_url(value["entry_url"])
    except (ValueError, TypeError, FxfetchError) as error:
        raise EvidenceError("evidence_entry_url_invalid") from error
    if value.get("collector") not in ("http", "browser"):
        raise EvidenceError("evidence_collector_invalid")
    if not timestamp(value.get("started_at")) or not timestamp(value.get("finished_at")):
        raise EvidenceError("evidence_timestamp_invalid")
    if value.get("outcome") not in ("captured", "blocked", "failed"):
        raise EvidenceError("evidence_outcome_invalid")
    if not isinstance(value.get("reason_code"), str) or not value["reason_code"]:
        raise EvidenceError("evidence_reason_invalid")
    if value.get("coverage") != "partial":
        raise EvidenceError("evidence_coverage_invalid")
    gaps = value.get("gaps")
    if not isinstance(gaps, list) or len(gaps) > 256 or any(
        not isinstance(gap, str) or not gap or len(gap) > 256 for gap in gaps
    ):
        raise EvidenceError("evidence_gaps_invalid")


def validate_file_record(
    record: object, used_paths: set[str], component_spellings: dict[str, str] | None = None
) -> dict[str, Any]:
    if not isinstance(record, dict) or set(record) != FILE_FIELDS:
        raise EvidenceError("evidence_file_record_invalid")
    path = portable_path(record["path"])
    folded = path.casefold()
    if folded in used_paths:
        raise EvidenceError("evidence_path_collision")
    used_paths.add(folded)
    if component_spellings is not None:
        parts = PurePosixPath(path).parts
        for index in range(1, len(parts) + 1):
            spelling = "/".join(parts[:index])
            key = spelling.casefold()
            previous = component_spellings.get(key)
            if previous is not None and previous != spelling:
                raise EvidenceError("evidence_path_collision")
            component_spellings[key] = spelling
    size = record["size"]
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise EvidenceError("evidence_size_invalid")
    if not isinstance(record["sha256"], str) or not HASH_PATTERN.fullmatch(record["sha256"]):
        raise EvidenceError("evidence_hash_invalid")
    if not isinstance(record["role"], str) or not record["role"] or len(record["role"]) > 128:
        raise EvidenceError("evidence_role_invalid")
    if (
        not isinstance(record["representation"], str)
        or not record["representation"]
        or len(record["representation"]) > 128
    ):
        raise EvidenceError("evidence_representation_invalid")
    if type(record["complete"]) is not bool:
        raise EvidenceError("evidence_completeness_invalid")
    for key in ("source_url", "request_ref"):
        item = record[key]
        if item is not None and (not isinstance(item, str) or not item or len(item) > 8192):
            raise EvidenceError("evidence_reference_invalid")
    if record["source_url"] is not None:
        try:
            validate_url(record["source_url"])
        except (ValueError, FxfetchError) as error:
            raise EvidenceError("evidence_reference_invalid") from error
    if path.casefold() == "manifest.json":
        raise EvidenceError("evidence_manifest_listed")
    return {**record, "path": path}
