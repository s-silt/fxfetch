"""Private, bounded analysis inputs from a verified task archive."""

from __future__ import annotations

import hashlib
import time
import zipfile
from pathlib import Path
from typing import Any

from ..build_setup import _private_directory
from .analysis_har import json_bytes, project_har
from .analysis_materials import MaterialSources, analysis_suffix
from .task_evidence_provenance import parse_observations
from .task_evidence_schema import MAX_TASK_OBSERVATIONS_BYTES
from .task_evidence_verify import verify_task_archive
from .web_evidence_io import check_ancestors, is_reparse
from .web_evidence_schema import EvidenceError

MAX_INPUT_FILE_BYTES = 8 * 1024 * 1024
MAX_INPUT_BYTES = 80 * 1024 * 1024
MAX_INPUT_FILES = 2000


def write_receipt(output: Path, receipt: dict[str, Any]) -> None:
    pending = output / "analysis.json.pending"
    with pending.open("xb") as stream:
        stream.write(json_bytes(receipt))
    pending.replace(output / "analysis.json")


def _check_time(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise EvidenceError("analysis_preparation_timeout")


def _copy_archive(source: Path, target: Path, max_bytes: int, deadline: float) -> None:
    check_ancestors(source)
    if not source.is_file() or is_reparse(source):
        raise EvidenceError("analysis_archive_unavailable")
    if source.stat().st_size > max_bytes:
        raise EvidenceError("task_evidence_archive_too_large")
    size = 0
    with source.open("rb") as incoming, target.open("xb") as outgoing:
        while block := incoming.read(64 * 1024):
            _check_time(deadline)
            size += len(block)
            if size > max_bytes:
                raise EvidenceError("task_evidence_archive_too_large")
            outgoing.write(block)


def _project_materials(
    bundle: zipfile.ZipFile, manifest: dict[str, Any], inputs: Path, har_size: int, deadline: float,
    sources: MaterialSources,
) -> list[dict[str, Any]]:
    mapping: list[dict[str, Any]] = []
    total = har_size
    count = 1 if har_size else 0
    for index, record in enumerate(manifest["files"], 1):
        _check_time(deadline)
        provenance = sources.describe(record)
        suffix, basis = analysis_suffix(record, provenance)
        item = {"source": record, "analysis_path": None, "analysis_location_prefix": None,
                "provenance": provenance, "type_basis": basis}
        reason = None
        if record["size"] > MAX_INPUT_FILE_BYTES:
            reason = "analysis_file_budget"
        elif total + record["size"] > MAX_INPUT_BYTES or count >= MAX_INPUT_FILES:
            reason = "analysis_total_budget"
        if reason:
            item["omitted_reason"] = reason
        else:
            raw = bundle.read(record["path"])
            if len(raw) != record["size"] or hashlib.sha256(raw).hexdigest() != record["sha256"]:
                raise EvidenceError("task_evidence_material_mismatch")
            name = f"material-{index:04d}{suffix}"
            (inputs / name).write_bytes(raw)
            item["analysis_path"] = f"input/{name}"
            item["analysis_location_prefix"] = f"web/{name}"
            count += 1
            total += len(raw)
        mapping.append(item)
    return mapping


def prepare_analysis(
    archive: Path, output: Path, *, max_bytes: int, max_seconds: float = 60.0,
) -> dict[str, Any]:
    """Keep the original ZIP and metadata outside the directory fxapk scans."""
    check_ancestors(output)
    if output.exists() or output.is_symlink():
        raise EvidenceError("analysis_output_exists")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    if not _private_directory(output):
        raise EvidenceError("private_permissions_unavailable")
    deadline = time.monotonic() + max_seconds
    copied = output / "source.zip"
    try:
        _copy_archive(archive, copied, max_bytes, deadline)
        manifest, archive_hash = verify_task_archive(copied, max_bytes=max_bytes, deadline=deadline)
        inputs = output / "input"
        inputs.mkdir(mode=0o700)
        with zipfile.ZipFile(copied) as bundle:
            raw = bundle.read("observations.jsonl") if manifest["observations"]["path"] else b""
            if len(raw) > MAX_TASK_OBSERVATIONS_BYTES:
                raise EvidenceError("task_evidence_observations_invalid")
            rows, _, _, _, _, _ = parse_observations(raw)
            har, references, unprojected = project_har(rows)
            if references:
                (inputs / "observed.har").write_bytes(har)
            mapping = _project_materials(
                bundle, manifest, inputs, len(har) if references else 0, deadline, MaterialSources(rows),
            )
        _check_time(deadline)
        receipt: dict[str, Any] = {
            "schema_version": "fxfetch.analysis-handoff.v1",
            "state": "prepared",
            "source_archive": {"path": "source.zip", "sha256": archive_hash, "integrity_verified": True},
            "source_manifest": manifest,
            "materials": mapping,
            "har": {"path": "input/observed.har" if references else None,
                    "sha256": hashlib.sha256(har).hexdigest() if references else None,
                    "entries": references, "unprojected_observations": unprojected},
            "analysis": {"state": "not_run", "online": False},
            "coverage": "partial",
            "authenticity_claimed": False,
            "external_packages_verified": False,
            'attachments': {
                'count': len(manifest.get('attachments', [])),
                'bytes': sum(item['size'] for item in manifest.get('attachments', [])),
                'byte_integrity_verified': True,
                'included_in_web_analysis': False,
            },
            "target_app_attribution_verified": False,
        }
        write_receipt(output, receipt)
        return receipt
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        write_receipt(output, {"state": "failed", "reason_code": (
            error.code if isinstance(error, EvidenceError) else "analysis_preparation_failed"
        ), "analysis": {"state": "not_run", "online": False}})
        raise
