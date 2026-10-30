"""Invoke the existing fxapk CLI offline, without importing its internals."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path
from typing import Any

from .analysis_package import prepare_analysis, write_receipt
from .process_limits import run_limited
from .web_evidence_io import check_ancestors, is_reparse, read_json_object
from .web_evidence_schema import EvidenceError

MAX_REPORT_BYTES = 32 * 1024 * 1024


def _report_receipt(output: Path) -> dict[str, Any]:
    path = output / "report" / "input.json"
    check_ancestors(path)
    if not path.is_file() or is_reparse(path):
        raise EvidenceError("fxapk_report_missing")
    report = read_json_object(path, MAX_REPORT_BYTES)
    meta = report.get("meta")
    web = meta.get("web_evidence") if isinstance(meta, dict) else None
    if not isinstance(meta, dict) or meta.get("online") is not False or not isinstance(web, dict):
        raise EvidenceError("fxapk_report_contract_invalid")
    errors = web.get("load_errors")
    if not isinstance(errors, list) or not all(isinstance(error, str) for error in errors):
        raise EvidenceError("fxapk_report_contract_invalid")
    if type(web.get("file_count")) is not int or web["file_count"] <= 0:
        raise EvidenceError("fxapk_report_empty")
    return {"path": "report/input.json", "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "load_errors": errors, "file_count": web["file_count"]}


def analyze_archive(
    archive: Path, output: Path, *, max_bytes: int, executable: str = "fxapk", timeout: float = 300.0,
    expected_size: int | None = None, expected_sha256: str | None = None,
) -> dict[str, Any]:
    if not 1 <= timeout <= 3600:
        raise EvidenceError("analysis_timeout_invalid")
    receipt = prepare_analysis(archive, output, max_bytes=max_bytes)
    analysis = receipt["analysis"]
    copied = output / "source.zip"
    size_mismatch = (
        expected_size is not None and copied.stat().st_size != expected_size
    )
    hash_mismatch = (
        expected_sha256 is not None
        and receipt["source_archive"]["sha256"] != expected_sha256
    )
    if size_mismatch or hash_mismatch:
        analysis.update(state="failed", reason_code="analysis_source_mismatch")
        receipt["state"] = "failed"
        write_receipt(output, receipt)
        return receipt
    inputs = output / "input"
    if not receipt["har"]["entries"] and not any(item["analysis_path"] for item in receipt["materials"]):
        analysis.update(state="not_run", reason_code="no_analyzable_web_material")
        receipt["state"] = "not_analyzed"
        write_receipt(output, receipt)
        return receipt
    resolved = shutil.which(executable)
    if resolved is None:
        analysis.update(state="failed", reason_code="fxapk_executable_unavailable")
        receipt["state"] = "failed"
        write_receipt(output, receipt)
        return receipt
    command = [str(Path(resolved).resolve()), "analyze-web", str(inputs.resolve()),
               "--offline", "--fmt", "json", "--out", str((output / "report").resolve())]
    analysis.update(state="running", executable=command[0], command=command)
    write_receipt(output, receipt)
    result = run_limited(command, timeout=timeout, memory_bytes=2 * 1024**3,
                         cwd=output.resolve(), max_output_bytes=1024 * 1024)
    (output / "fxapk.stdout.log").write_bytes(result.stdout)
    (output / "fxapk.stderr.log").write_bytes(result.stderr)
    analysis.update(returncode=result.returncode, output_truncated=result.output_truncated,
                    limit_method=result.limit_method, timed_out=result.timed_out)
    reason = result.reason_code
    if result.timed_out:
        reason = "fxapk_timeout"
    elif result.returncode != 0 and not reason:
        reason = "fxapk_analysis_failed"
    if reason:
        analysis.update(state="failed", reason_code=reason)
    else:
        try:
            analysis["report"] = _report_receipt(output)
            analysis["state"] = "completed"
        except (OSError, ValueError) as error:
            analysis.update(state="failed", reason_code=(
                error.code if isinstance(error, EvidenceError) else "fxapk_report_unavailable"
            ))
    receipt["state"] = analysis["state"]
    write_receipt(output, receipt)
    return receipt
