"""Standalone bounded web-material capture orchestration."""

from __future__ import annotations

import threading
import uuid
from pathlib import Path

from .errors import FxfetchError
from .guard import validate_url
from .http_client import HttpClient
from .limits import Limits
from .web_http import collect_http
from .web_journal import EvidenceJournal
from .web_materials import WebCaptureResult, now_utc, save_summary


def capture_web(
    url: str,
    output_dir: Path,
    *,
    collector: str = "http",
    authorized_active: bool,
    service_root: Path,
    limits: Limits | None = None,
    cancel: threading.Event | None = None,
    client: HttpClient | None = None,
) -> WebCaptureResult | None:
    approved_url = validate_url(url)
    if collector not in {"http", "browser"}:
        raise FxfetchError("collector_invalid", "Select the HTTP or browser collector")
    if not authorized_active:
        return None
    limits = limits or Limits()
    output = Path(output_dir)
    if output.exists():
        raise FxfetchError("capture_output_exists", "Capture output directory already exists")
    if not output.parent.is_dir():
        raise FxfetchError("capture_parent_missing", "Capture output parent directory is unavailable")
    output.mkdir()
    result = WebCaptureResult(
        capture_id=uuid.uuid4().hex,
        entry_url=approved_url,
        collector=collector,
        started_at=now_utc(),
    )
    journal: EvidenceJournal | None = None
    try:
        journal = EvidenceJournal(output / "capture.jsonl", collector, uuid.uuid4().hex)
        journal.append("capture_started", {"url": approved_url, "collector": collector})
        active_cancel = cancel or threading.Event()
        if collector == "http":
            collect_http(approved_url, output, result, journal, limits, active_cancel, client)
        else:
            from .web_browser import collect_browser

            collect_browser(approved_url, output, result, journal, limits, active_cancel, service_root)
    except (FxfetchError, OSError, RuntimeError, ValueError) as error:
        result.outcome = "failed"
        result.reason_code = error.code if isinstance(error, FxfetchError) else "collector_unavailable"
        if journal is None and isinstance(error, OSError):
            result.journal_state = "failed"
            result.gaps.append("journal_write_failed")
    finally:
        if journal is not None:
            journal.append(
                "capture_finished",
                {"outcome": result.outcome, "reason_code": result.reason_code},
            )
            journal.close()
            result.gaps.extend(journal.gaps)
            result.journal_state = (
                "failed" if journal.failed else "truncated" if journal.saturated else "healthy"
            )
            if result.journal_state != "healthy":
                result.gaps.append("material_provenance_incomplete")
            if result.journal_state == "failed" and result.outcome == "captured":
                result.outcome, result.reason_code = "failed", "journal_write_failed"
    result.finished_at = now_utc()
    try:
        save_summary(output / "capture.json", result)
    except OSError:
        result.gaps.append("capture_summary_write_failed")
        result.journal_state = "failed"
        result.outcome = "failed"
        result.reason_code = "capture_summary_write_failed"
    return result


__all__ = ["WebCaptureResult", "capture_web"]
