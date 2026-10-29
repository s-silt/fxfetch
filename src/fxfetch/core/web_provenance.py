"""Journal and material association validation for web evidence."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .web_evidence_schema import EvidenceError, strict_json, timestamp


@dataclass
class JournalFacts:
    request_urls: dict[str, set[str]] = field(default_factory=dict)
    saved_materials: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


def validate_journal(
    path: Path, collector: str, maximum: int, *, complete: bool
) -> tuple[int, str, JournalFacts]:
    digest = hashlib.sha256()
    total = 0
    facts = JournalFacts()
    expected_seq = 1
    try:
        with path.open("rb") as stream:
            while raw := stream.readline(64 * 1024 + 1):
                total += len(raw)
                if total > maximum or total > 8 * 1024 * 1024:
                    raise EvidenceError("evidence_journal_too_large")
                if len(raw) > 64 * 1024:
                    raise EvidenceError("evidence_journal_record_too_large")
                digest.update(raw)
                row = strict_json(raw)
                if (
                    not isinstance(row, dict)
                    or set(row) != {"seq", "observed_at", "collector", "attempt_id", "kind", "fields"}
                    or type(row["seq"]) is not int
                    or row["seq"] != expected_seq
                    or row["collector"] != collector
                    or not timestamp(row["observed_at"])
                    or not isinstance(row["attempt_id"], str)
                    or not row["attempt_id"]
                    or not isinstance(row["kind"], str)
                    or not row["kind"]
                    or not isinstance(row["fields"], dict)
                ):
                    raise EvidenceError("evidence_journal_invalid")
                expected_seq += 1
                if complete and row["kind"] == "journal_truncated":
                    raise EvidenceError("evidence_journal_completeness_mismatch")
                if expected_seq > 20_001:
                    raise EvidenceError("evidence_journal_record_limit")
                fields = row["fields"]
                kind = row["kind"]
                reference = fields.get("request_ref")
                url = fields.get("url", fields.get("source_url"))
                if isinstance(reference, str) and isinstance(url, str) and kind in {
                    "request_attempted", "request_permitted", "response_observed"
                }:
                    urls = facts.request_urls.setdefault(reference, set())
                    if urls and url not in urls:
                        raise EvidenceError("evidence_request_identity_conflict")
                    urls.add(url)
                if kind in {"response_body_saved", "response_prefix_saved", "terminal_snapshot", "snapshot_saved"}:
                    material_path = fields.get("path")
                    if isinstance(material_path, str):
                        facts.saved_materials.setdefault(material_path, []).append(fields)
    except EvidenceError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, KeyError) as error:
        raise EvidenceError("evidence_journal_invalid") from error
    return total, digest.hexdigest(), facts


def validate_material_provenance(
    records: list[dict[str, Any]], facts: JournalFacts, *, allow_missing: bool
) -> None:
    for record in records:
        if record["path"] == "capture.jsonl":
            continue
        if record["request_ref"] is not None:
            urls = facts.request_urls.get(record["request_ref"])
            if urls is None and not allow_missing:
                raise EvidenceError("evidence_reference_unsupported")
            if urls is not None and record["source_url"] not in urls:
                raise EvidenceError("evidence_reference_mismatch")
        matches = [
            item for item in facts.saved_materials.get(record["path"], [])
            if item.get("path") == record["path"]
            and item.get("size") == record["size"]
            and item.get("sha256") == record["sha256"]
            and item.get("representation") == record["representation"]
            and item.get("complete") == record["complete"]
            and item.get("url", item.get("source_url")) == record["source_url"]
            and item.get("request_ref") == record["request_ref"]
        ]
        path_observed = record["path"] in facts.saved_materials
        if not matches and (path_observed or not allow_missing):
            raise EvidenceError("evidence_material_provenance_invalid")
