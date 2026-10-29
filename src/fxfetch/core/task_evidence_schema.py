"""Strict schema validation for unified task evidence packages."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any

from .web_evidence_schema import EvidenceError, portable_path
from .web_evidence_schema import strict_json as strict_json

TASK_EVIDENCE_SCHEMA = "fxfetch.task-evidence.v1"
MAX_TASK_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_TASK_FILES = 2000
MAX_TASK_OBSERVATIONS_BYTES = 8 * 1024 * 1024
MAX_TASK_OBSERVATIONS = 20_000
_HASH = re.compile(r"^[0-9a-f]{64}$")


def validate_task_manifest(value: object) -> dict[str, Any]:
    fields = {
        "schema_version", "producer_version", "job_id", "entry_url", "package_result",
        "web_materials", "observations", "attempts", "files", "external_packages", "gaps",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise EvidenceError("task_evidence_schema_fields_invalid")
    if value["schema_version"] != TASK_EVIDENCE_SCHEMA:
        raise EvidenceError("task_evidence_schema_unsupported")
    if not isinstance(value["producer_version"], str) or not value["producer_version"]:
        raise EvidenceError("task_evidence_producer_invalid")
    if not isinstance(value["job_id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value["job_id"]):
        raise EvidenceError("task_evidence_job_id_invalid")
    if not isinstance(value["entry_url"], str) or len(value["entry_url"]) > 8192:
        raise EvidenceError("task_evidence_entry_url_invalid")
    result = value["package_result"]
    if not isinstance(result, dict) or set(result) != {"outcome", "reason_code", "coverage"}:
        raise EvidenceError("task_evidence_package_result_invalid")
    if result["outcome"] not in {"downloaded", "not_found", "blocked", "failed"}:
        raise EvidenceError("task_evidence_package_outcome_invalid")
    if result["reason_code"] is not None and (
        not isinstance(result["reason_code"], str) or len(result["reason_code"]) > 128
    ):
        raise EvidenceError("task_evidence_reason_invalid")
    if not isinstance(result["coverage"], str) or len(result["coverage"]) > 64:
        raise EvidenceError("task_evidence_coverage_invalid")
    materials = value["web_materials"]
    if not isinstance(materials, dict) or set(materials) != {"state", "count", "coverage", "gaps"}:
        raise EvidenceError("task_evidence_materials_invalid")
    if materials["state"] not in {"saved", "empty"} or materials["coverage"] != "partial":
        raise EvidenceError("task_evidence_materials_invalid")
    if isinstance(materials["count"], bool) or not isinstance(materials["count"], int) or materials["count"] < 0:
        raise EvidenceError("task_evidence_material_count_invalid")
    _validate_gaps(materials["gaps"])
    observations = value["observations"]
    if not isinstance(observations, dict) or set(observations) != {
        "state", "records", "path", "size", "sha256", "started_at", "finished_at", "gaps"
    }:
        raise EvidenceError("task_evidence_observations_invalid")
    if observations["state"] not in {
        "healthy", "truncated", "failed", "unavailable", "interrupted"
    }:
        raise EvidenceError("task_evidence_observations_invalid")
    _validate_size(observations["records"])
    _validate_size(observations["size"])
    if observations["records"] > MAX_TASK_OBSERVATIONS or observations["size"] > MAX_TASK_OBSERVATIONS_BYTES:
        raise EvidenceError("task_evidence_observations_invalid")
    for field in ("started_at", "finished_at"):
        timestamp = observations[field]
        if timestamp is not None:
            if not isinstance(timestamp, str) or len(timestamp) > 64:
                raise EvidenceError("task_evidence_observations_invalid")
            try:
                parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    raise ValueError
            except ValueError as error:
                raise EvidenceError("task_evidence_observations_invalid") from error
    if observations["state"] == "healthy" and (
        observations["started_at"] is None or observations["finished_at"] is None
    ):
        raise EvidenceError("task_evidence_observations_invalid")
    if observations["path"] is not None:
        if portable_path(observations["path"]) != "observations.jsonl":
            raise EvidenceError("task_evidence_observations_path_invalid")
        _validate_hash(observations["sha256"])
    elif observations["sha256"] is not None:
        raise EvidenceError("task_evidence_observations_invalid")
    if observations["path"] is None and (
        observations["records"] != 0
        or observations["size"] != 0
        or observations["started_at"] is not None
        or observations["finished_at"] is not None
    ):
        raise EvidenceError("task_evidence_observations_invalid")
    if observations["state"] == "healthy" and observations["path"] is None:
        raise EvidenceError("task_evidence_observations_invalid")
    _validate_gaps(observations["gaps"])
    for name in ("attempts", "files", "external_packages"):
        if not isinstance(value[name], list) or len(value[name]) > MAX_TASK_FILES:
            raise EvidenceError("task_evidence_list_invalid")
    used_paths: set[str] = {"manifest.json"}
    component_spellings: dict[str, str] = {}
    for record in value["files"]:
        if not isinstance(record, dict):
            raise EvidenceError("task_evidence_file_invalid")
        allowed = {
            "path", "size", "sha256", "representation", "complete", "source_url",
            "request_association",
        }
        if set(record) - (allowed | {"request_ref"}) or not allowed.issubset(record):
            raise EvidenceError("task_evidence_file_invalid")
        path = portable_path(record["path"])
        key = path.casefold()
        if key in used_paths:
            raise EvidenceError("task_evidence_path_collision")
        used_paths.add(key)
        for index in range(1, len(PurePosixPath(path).parts) + 1):
            spelling = "/".join(PurePosixPath(path).parts[:index])
            folded = spelling.casefold()
            old = component_spellings.get(folded)
            if old is not None and old != spelling:
                raise EvidenceError("task_evidence_path_collision")
            component_spellings[folded] = spelling
        _validate_size(record["size"])
        _validate_hash(record["sha256"])
        if not isinstance(record["representation"], str) or not record["representation"]:
            raise EvidenceError("task_evidence_representation_invalid")
        if type(record["complete"]) is not bool:
            raise EvidenceError("task_evidence_completeness_invalid")
        if record["source_url"] is not None and (
            not isinstance(record["source_url"], str) or len(record["source_url"]) > 8192
        ):
            raise EvidenceError("task_evidence_source_invalid")
        if "request_ref" in record and (
            not isinstance(record["request_ref"], str) or not record["request_ref"] or len(record["request_ref"]) > 256
        ):
            raise EvidenceError("task_evidence_request_ref_invalid")
        if record["request_association"] not in {"known", "unknown"} or (
            (record["request_association"] == "known") != ("request_ref" in record)
        ):
            raise EvidenceError("task_evidence_request_association_invalid")
    for item in value["external_packages"]:
        if not isinstance(item, dict):
            raise EvidenceError("task_evidence_external_package_invalid")
        allowed = {"kind", "size", "sha256", "source_url", "complete", "validated"}
        if set(item) - (allowed | {"request_ref"}) or not allowed.issubset(item):
            raise EvidenceError("task_evidence_external_package_invalid")
        if item["kind"] not in {"apk", "ipa"}:
            raise EvidenceError("task_evidence_external_package_invalid")
        _validate_size(item["size"])
        _validate_hash(item["sha256"])
        if not isinstance(item["source_url"], str) or len(item["source_url"]) > 8192:
            raise EvidenceError("task_evidence_external_package_invalid")
        if type(item["complete"]) is not bool or type(item["validated"]) is not bool:
            raise EvidenceError("task_evidence_external_package_invalid")
        if "request_ref" in item and (
            not isinstance(item["request_ref"], str) or not item["request_ref"] or len(item["request_ref"]) > 256
        ):
            raise EvidenceError("task_evidence_request_ref_invalid")
    _validate_gaps(value["gaps"])
    if materials["count"] != len(value["files"]) or (
        materials["state"] == "saved"
    ) != bool(value["files"]):
        raise EvidenceError("task_evidence_material_count_invalid")
    return value


def _validate_size(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EvidenceError("task_evidence_size_invalid")


def _validate_hash(value: object) -> None:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise EvidenceError("task_evidence_hash_invalid")


def _validate_gaps(value: object) -> None:
    if not isinstance(value, list) or len(value) > 256 or any(
        not isinstance(item, str) or not item or len(item) > 256 for item in value
    ):
        raise EvidenceError("task_evidence_gaps_invalid")
