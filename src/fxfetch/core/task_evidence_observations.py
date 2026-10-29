"""Bounded task-journal loading and recorder receipt reconciliation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .task_evidence_provenance import parse_observations
from .task_evidence_schema import (
    MAX_TASK_OBSERVATIONS,
    MAX_TASK_OBSERVATIONS_BYTES,
    EvidenceError,
    strict_json,
)
from .web_evidence_io import check_ancestors, is_reparse

MAX_OBSERVATION_BYTES = MAX_TASK_OBSERVATIONS_BYTES


def read_observations(
    path: Path | None,
) -> tuple[bytes | None, str, int, list[str], list[dict[str, Any]], str | None, str | None]:
    if path is None:
        return None, "unavailable", 0, ["observations_unavailable"], [], None, None
    try:
        check_ancestors(path)
        if not path.exists() and not path.is_symlink():
            return None, "unavailable", 0, ["observations_unavailable"], [], None, None
        if is_reparse(path):
            raise EvidenceError("task_evidence_link_rejected")
        with path.open("rb") as stream:
            raw = stream.read(MAX_OBSERVATION_BYTES + 1)
        oversized = len(raw) > MAX_OBSERVATION_BYTES
        bounded = raw[:MAX_OBSERVATION_BYTES]
        rows, _, state, gaps, started, finished = parse_observations(bounded)
        if oversized:
            state = "truncated"
            gaps.append("observations_size_limit")
        receipt_path = path.with_suffix(path.suffix + ".status.json")
        receipt_present = False
        try:
            check_ancestors(receipt_path)
            receipt_present = receipt_path.exists() or receipt_path.is_symlink()
            if receipt_present:
                if is_reparse(receipt_path) or not receipt_path.is_file():
                    raise EvidenceError("task_evidence_receipt_invalid")
                if receipt_path.stat().st_size > 16 * 1024:
                    raise EvidenceError("task_evidence_receipt_invalid")
                receipt = strict_json(receipt_path.read_text(encoding="utf-8"))
            else:
                receipt = None
        except (OSError, UnicodeError, ValueError, EvidenceError, RecursionError):
            receipt = None
            receipt_present = True
            state = "failed"
            gaps.append("observation_receipt_invalid")
        if receipt_present and receipt is None:
            state = "failed"
            gaps.append("observation_receipt_invalid")
        elif not receipt_present:
            gaps.append("observations_receipt_missing")
            if state == "healthy":
                state = "interrupted"
        else:
            if (
                not isinstance(receipt, dict)
                or set(receipt) != {"state", "gaps", "records", "started_at", "finished_at"}
                or receipt.get("state") not in {"healthy", "failed", "truncated"}
                or not isinstance(receipt.get("gaps"), list)
                or len(receipt["gaps"]) > 256
                or any(not isinstance(gap, str) or len(gap) > 256 for gap in receipt["gaps"])
                or isinstance(receipt.get("records"), bool)
                or not isinstance(receipt.get("records"), int)
                or receipt["records"] < 0
                or receipt["records"] > MAX_TASK_OBSERVATIONS
                or receipt.get("records") != len(rows)
                or receipt.get("started_at") != started
                or receipt.get("finished_at") != finished
            ):
                state = "failed"
                gaps.append("observation_receipt_mismatch")
            else:
                gaps.extend(receipt["gaps"])
                if receipt["state"] != state:
                    gaps.append("observation_receipt_state_mismatch")
                    if receipt["state"] in {"failed", "truncated"}:
                        state = receipt["state"]
                    elif state == "healthy":
                        state = "interrupted"
        return (
            bounded,
            state,
            len(rows),
            list(dict.fromkeys(gaps))[:256],
            rows,
            started,
            finished,
        )
    except (OSError, UnicodeError, ValueError, EvidenceError, RecursionError):
        return None, "failed", 0, ["observations_invalid"], [], None, None
