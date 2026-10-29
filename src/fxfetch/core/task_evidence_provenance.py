"""Validation of task journal envelopes and material provenance."""

from __future__ import annotations

import hashlib
import time
from datetime import datetime
from typing import Any

from .task_evidence_schema import (
    MAX_TASK_OBSERVATIONS,
    MAX_TASK_OBSERVATIONS_BYTES,
    EvidenceError,
    strict_json,
)
from .web_journal import MAX_RECORD_BYTES

_SAVED_KINDS = {"response_body_saved", "response_prefix_saved", "terminal_snapshot"}


def parse_observations(
    raw: bytes,
) -> tuple[list[dict[str, Any]], bytes, str, list[str], str | None, str | None]:
    if len(raw) > MAX_TASK_OBSERVATIONS_BYTES:
        raise EvidenceError("task_evidence_observations_invalid")
    rows: list[dict[str, Any]] = []
    valid = bytearray()
    gaps: list[str] = []
    state = "healthy"
    started = finished = None
    previous_time: datetime | None = None
    offset = 0
    index = 0
    while offset < len(raw):
        index += 1
        end = raw.find(b"\n", offset)
        terminated = end >= 0
        line = raw[offset : end + 1] if terminated else raw[offset:]
        if len(rows) >= MAX_TASK_OBSERVATIONS or len(line) > MAX_RECORD_BYTES:
            state = "truncated"
            gaps.append("observations_limit")
            break
        if not terminated:
            state = "truncated"
            gaps.append("observations_trailing_record_truncated")
            break
        try:
            value = strict_json(line[:-1].decode("utf-8"))
            if not isinstance(value, dict) or set(value) != {
                "seq", "observed_at", "collector", "attempt_id", "kind", "fields"
            }:
                raise ValueError("envelope")
            if (
                isinstance(value["seq"], bool)
                or not isinstance(value["seq"], int)
                or value["seq"] != index
            ):
                raise ValueError("sequence")
            if (
                not isinstance(value["collector"], str)
                or not 1 <= len(value["collector"]) <= 64
                or not isinstance(value["attempt_id"], str)
                or not 1 <= len(value["attempt_id"]) <= 128
                or not isinstance(value["kind"], str)
                or not 1 <= len(value["kind"]) <= 128
            ):
                raise ValueError("context")
            if not isinstance(value["fields"], dict):
                raise ValueError("fields")
            if finished is not None:
                raise ValueError("record_after_finish")
            if value["kind"] in {
                "request_attempted", "request_permitted", "response_observed",
                "response_body_saved", "response_prefix_saved", "redirect_observed",
                "network_request_observed", "frame_navigated", "subresource_http_error",
                "terminal_snapshot",
            }:
                context = value["fields"]
                if not all(
                    isinstance(context.get(key), str) and context[key]
                    for key in ("collector_id", "attempt_id")
                ):
                    raise ValueError("attempt_context")
            timestamp = value["observed_at"]
            if not isinstance(timestamp, str):
                raise ValueError("timestamp")
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None or (previous_time is not None and parsed < previous_time):
                raise ValueError("timestamp")
        except (ValueError, TypeError, UnicodeError, RecursionError):
            state = "failed"
            gaps.append("observations_invalid")
            break
        previous_time = parsed
        if value["kind"] == "task_observation_started":
            if started is not None or rows:
                state = "truncated"
                gaps.append("observations_lifecycle_invalid")
                break
            started = timestamp
        elif value["kind"] == "task_observation_finished":
            if started is None or value["fields"].get("state") not in {
                "healthy", "failed", "truncated"
            }:
                state = "truncated"
                gaps.append("observations_lifecycle_invalid")
                break
            recorded_count = value["fields"].get("records_before_close")
            if (
                isinstance(recorded_count, bool)
                or not isinstance(recorded_count, int)
                or recorded_count != len(rows)
            ):
                state = "failed"
                gaps.append("observations_lifecycle_invalid")
                break
            lifecycle_gaps = value["fields"].get("gaps", [])
            if (
                not isinstance(lifecycle_gaps, list)
                or len(lifecycle_gaps) > 256
                or any(not isinstance(gap, str) or not gap or len(gap) > 256 for gap in lifecycle_gaps)
            ):
                state = "failed"
                gaps.append("observations_lifecycle_invalid")
                break
            finished = timestamp
            final_state = value["fields"].get("state")
            if final_state == "failed":
                state = "failed"
                gaps.extend(lifecycle_gaps)
            elif final_state == "truncated":
                state = "truncated"
                gaps.extend(lifecycle_gaps)
            elif state != "healthy":
                state = "failed"
                gaps.append("observations_lifecycle_invalid")
        elif value["kind"] == "journal_truncated":
            state = "truncated"
            gaps.append("journal_truncated")
        rows.append(value)
        valid.extend(line)
        offset = end + 1
    if started is None:
        if state == "healthy":
            state = "interrupted"
        gaps.append("observations_start_missing")
    if finished is None:
        if state == "healthy":
            state = "interrupted"
        gaps.append("observations_interrupted")
    return rows, bytes(valid), state, list(dict.fromkeys(gaps)), started, finished


def validate_material_provenance(
    rows: list[dict[str, Any]],
    files: list[dict[str, Any]],
    external_packages: list[dict[str, Any]],
    *,
    allow_incomplete: bool = False,
) -> None:
    requests: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        fields = row.get("fields")
        if (
            row["kind"] == "request_attempted"
            and isinstance(fields, dict)
            and isinstance(fields.get("request_ref"), str)
        ):
            requests.setdefault(fields["request_ref"], []).append(fields)
    request_refs = set(requests)
    for ref, facts in requests.items():
        if len({
            (item.get("url"), item.get("collector_id"), item.get("attempt_id"))
            for item in facts
        }) > 1:
            raise EvidenceError("task_evidence_request_ref_conflict")
        identity = facts[0]
        for row in rows:
            fields = row.get("fields")
            if (
                row["kind"] == "request_permitted"
                and isinstance(fields, dict)
                and fields.get("request_ref") == ref
                and any(
                    fields.get(key) != identity.get(key)
                    for key in ("collector_id", "attempt_id")
                )
            ):
                raise EvidenceError("task_evidence_request_ref_conflict")
    saved = [
        row for row in rows
        if row["kind"] in _SAVED_KINDS and row["fields"].get("package_stream") is not True
    ]
    for record in files:
        ref = record.get("request_ref")
        if record["request_association"] == "known" and ref not in request_refs:
            raise EvidenceError("task_evidence_request_ref_unobserved")
        matches = []
        for row in saved:
            fields = row["fields"]
            if (
                fields.get("path") == record["path"]
                and fields.get("size") == record["size"]
                and fields.get("sha256") == record["sha256"]
                and (fields.get("representation") or "http_response_body") == record["representation"]
                and fields.get("complete") is record["complete"]
                and (fields.get("source_url", fields.get("url")) or None) == record["source_url"]
                and (
                    fields.get("request_ref") == ref
                    or (
                        record["request_association"] == "unknown"
                        and (
                            fields.get("request_ref") is None
                            or (
                                allow_incomplete
                                and fields.get("request_ref") not in request_refs
                            )
                        )
                    )
                )
            ):
                matches.append(row)
        if not matches:
            raise EvidenceError("task_evidence_material_provenance_mismatch")
        if ref is not None:
            source = record.get("source_url")
            matching_requests = requests.get(ref, [])
            matching_saved = [row["fields"] for row in matches]
            if not any(
                request.get("url") == source
                and any(
                    saved.get("collector_id") == request.get("collector_id")
                    and saved.get("attempt_id") == request.get("attempt_id")
                    for saved in matching_saved
                )
                for request in matching_requests
            ):
                raise EvidenceError("task_evidence_request_context_mismatch")
    for package in external_packages:
        ref = package.get("request_ref")
        if ref is not None and ref not in request_refs:
            raise EvidenceError("task_evidence_request_ref_unobserved")
        if ref is not None and not any(
            item.get("url") == package.get("source_url") for item in requests[ref]
        ):
            raise EvidenceError("task_evidence_request_context_mismatch")


def validate_saved_bytes(
    path: Any,
    size: int,
    expected_hash: str,
    max_bytes: int,
    deadline: float | None = None,
) -> None:
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        while block := stream.read(64 * 1024):
            if deadline is not None and time.monotonic() >= deadline:
                raise EvidenceError("task_evidence_seal_timeout")
            count += len(block)
            if count > max_bytes:
                raise EvidenceError("task_evidence_material_too_large")
            digest.update(block)
    if count != size or digest.hexdigest() != expected_hash:
        raise EvidenceError("task_evidence_material_mismatch")
