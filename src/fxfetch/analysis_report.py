"""Bounded validation and fixed-content publication for analysis reports."""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path
from typing import Any

from .core.analysis_runner import MAX_REPORT_BYTES, _report_receipt
from .core.web_evidence_io import check_ancestors, is_reparse, read_json_object
from .core.web_evidence_schema import EvidenceError

MAX_ANALYSIS_RECEIPT_BYTES = 32 * 1024 * 1024
MAX_ANALYSIS_REPORT_ZIP_BYTES = 64 * 1024 * 1024
_REASON = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def safe_reason(value: object, fallback: str = "analysis_failed") -> str:
    return value if isinstance(value, str) and _REASON.fullmatch(value) else fallback


def bounded_hash(path: Path, maximum: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while block := stream.read(64 * 1024):
            total += len(block)
            if total > maximum:
                raise EvidenceError("analysis_report_too_large")
            digest.update(block)
    return total, digest.hexdigest()


def build_analysis_report(output: Path, pending: Path) -> dict[str, Any]:
    receipt_path = output / "analysis.json"
    try:
        check_ancestors(receipt_path)
        if not receipt_path.is_file() or is_reparse(receipt_path):
            raise EvidenceError("analysis_result_invalid")
        receipt = read_json_object(receipt_path, MAX_ANALYSIS_RECEIPT_BYTES)
    except (OSError, ValueError, EvidenceError) as error:
        raise EvidenceError("analysis_result_invalid") from error

    state = receipt.get("state")
    analysis = receipt.get("analysis")
    if not isinstance(analysis, dict) or state not in {"completed", "failed", "not_analyzed"}:
        raise EvidenceError("analysis_result_invalid")
    if state != "completed":
        return {
            "state": state,
            "reason_code": safe_reason(
                analysis.get("reason_code", receipt.get("reason_code"))
            ),
        }

    try:
        declared = analysis.get("report")
        verified = _report_receipt(output)
        if (
            analysis.get("state") != "completed"
            or not isinstance(declared, dict)
            or declared.get("path") != "report/input.json"
            or declared.get("sha256") != verified["sha256"]
        ):
            raise EvidenceError("analysis_report_invalid")
        report = output / "report" / "input.json"
        check_ancestors(report)
        if not report.is_file() or is_reparse(report) or report.stat().st_size > MAX_REPORT_BYTES:
            raise EvidenceError("analysis_report_invalid")
        sanitized = json.loads(json.dumps(receipt))
        sanitized_analysis = sanitized.get("analysis")
        if isinstance(sanitized_analysis, dict):
            sanitized_analysis.pop("command", None)
            sanitized_analysis.pop("executable", None)
            sanitized_analysis["online"] = False
        check_ancestors(pending.parent)
        if (
            not pending.parent.is_dir()
            or is_reparse(pending.parent)
            or pending.exists()
            or pending.is_symlink()
        ):
            raise EvidenceError("analysis_report_invalid")
        with zipfile.ZipFile(pending, "x", compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr(
                "analysis.json",
                json.dumps(
                    sanitized,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8"),
            )
            bundle.write(report, "report/input.json")
        if is_reparse(pending):
            raise EvidenceError("analysis_report_invalid")
        size, digest = bounded_hash(pending, MAX_ANALYSIS_REPORT_ZIP_BYTES)
        return {
            "state": "completed",
            "reason_code": None,
            "report_size": size,
            "report_sha256": digest,
        }
    except (OSError, ValueError, zipfile.BadZipFile, EvidenceError) as error:
        pending.unlink(missing_ok=True)
        if isinstance(error, EvidenceError) and error.code == "analysis_report_too_large":
            raise
        raise EvidenceError("analysis_report_invalid") from error
