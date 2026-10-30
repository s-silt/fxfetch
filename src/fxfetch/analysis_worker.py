"""Bounded child-process entry for service-owned offline analysis."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from .analysis_report import build_analysis_report, safe_reason
from .core.analysis_runner import analyze_archive
from .core.errors import FxfetchError
from .core.web_evidence_io import is_reparse, read_json_object
from .core.web_evidence_schema import EvidenceError
from .security import contained_path

WORKER_REQUEST_NAME = "worker-request.json"
WORKER_RESULT_NAME = "worker-result.json"
WORKER_REPORT_NAME = "analysis-report.zip.pending"
MAX_WORKER_MESSAGE_BYTES = 16 * 1024
_HASH = re.compile(r"^[0-9a-f]{64}$")


def _load_request(path: Path, root: Path) -> dict[str, Any]:
    try:
        relative = path.absolute().relative_to(root.absolute()).as_posix()
        checked = contained_path(root, relative)
        if is_reparse(checked):
            raise EvidenceError("analysis_worker_request_invalid")
        value = read_json_object(checked, MAX_WORKER_MESSAGE_BYTES)
    except (OSError, ValueError, FxfetchError, EvidenceError) as error:
        raise EvidenceError("analysis_worker_request_invalid") from error
    if set(value) != {
        "schema_version",
        "source_path",
        "source_size",
        "source_sha256",
        "fxapk_executable",
        "analysis_timeout",
        "max_task_bytes",
    } or value["schema_version"] != "fxfetch.analysis-worker.v1":
        raise EvidenceError("analysis_worker_request_invalid")
    source_size = value["source_size"]
    max_task_bytes = value["max_task_bytes"]
    timeout = value["analysis_timeout"]
    executable = value["fxapk_executable"]
    if (
        not isinstance(value["source_path"], str)
        or not value["source_path"]
        or isinstance(source_size, bool)
        or not isinstance(source_size, int)
        or source_size < 0
        or not isinstance(value["source_sha256"], str)
        or _HASH.fullmatch(value["source_sha256"]) is None
        or isinstance(max_task_bytes, bool)
        or not isinstance(max_task_bytes, int)
        or max_task_bytes <= 0
        or source_size > max_task_bytes
        or isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 1 <= timeout <= 3600
        or not isinstance(executable, str)
        or not executable
        or "\0" in executable
        or not Path(executable).is_absolute()
    ):
        raise EvidenceError("analysis_worker_request_invalid")
    return value


def _write_result(folder: Path, value: dict[str, Any]) -> None:
    raw = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_WORKER_MESSAGE_BYTES:
        raise EvidenceError("analysis_worker_result_invalid")
    pending = folder / f"{WORKER_RESULT_NAME}.pending"
    target = folder / WORKER_RESULT_NAME
    with pending.open("xb") as stream:
        stream.write(raw)
    pending.replace(target)


def run_worker(request_path: Path) -> dict[str, Any]:
    root = Path.cwd().absolute()
    request = _load_request(request_path, root)
    source = contained_path(root, request["source_path"])
    folder = request_path.absolute().parent
    output = folder / "output"
    receipt = analyze_archive(
        source,
        output,
        max_bytes=request["max_task_bytes"],
        executable=request["fxapk_executable"],
        timeout=request["analysis_timeout"],
        expected_size=request["source_size"],
        expected_sha256=request["source_sha256"],
    )
    if receipt.get("state") == "failed" and receipt.get("analysis", {}).get(
        "reason_code"
    ) == "analysis_source_mismatch":
        return {"state": "failed", "reason_code": "analysis_source_mismatch"}
    return build_analysis_report(output, folder / WORKER_REPORT_NAME)


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        return 2
    request_path = Path(arguments[0])
    folder = request_path.absolute().parent
    try:
        result = run_worker(request_path)
    except Exception as error:
        code = error.code if isinstance(error, (FxfetchError, EvidenceError)) else None
        result = {"state": "failed", "reason_code": safe_reason(code)}
    try:
        _write_result(folder, result)
    except (OSError, ValueError, EvidenceError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
