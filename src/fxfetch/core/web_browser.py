"""Android browser collector for standalone web captures."""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import replace
from pathlib import Path

from .android_worker import AndroidLease, AndroidWorker, load_worker_config
from .browser_capture import capture_browser
from .browser_gateway import BrowserGateway
from .errors import FxfetchError
from .limits import Limits
from .web_journal import EvidenceJournal
from .web_materials import WebCaptureResult, collect_browser_materials


def collect_browser(
    url: str,
    capture_dir: Path,
    result: WebCaptureResult,
    journal: EvidenceJournal,
    limits: Limits,
    cancel: threading.Event,
    service_root: Path,
) -> None:
    config = load_worker_config(service_root)
    if config is None:
        raise FxfetchError(
            "browser_worker_configuration_missing",
            "The configured Android browser worker is unavailable",
        )
    started = time.monotonic()
    browser_dir = capture_dir / "browser"
    result.gaps.extend(["single_passive_visit", "interaction_not_performed"])
    journal.append("entry_navigation_attempted", {"url": url, "method": "browser_navigation"})
    with BrowserGateway(
        timeout=limits.chain_timeout,
        max_connections=limits.max_requests,
        max_wire_bytes=min(limits.max_task_bytes, limits.max_web_bytes),
        cancel=cancel,
    ) as gateway:
        with AndroidLease(AndroidWorker(config), gateway, cancel, limits.chain_timeout) as lease:
            remaining = limits.chain_timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise FxfetchError("task_timeout", "Browser startup exhausted task deadline")
            capture = asyncio.run(
                capture_browser(
                    url,
                    browser_dir,
                    cancel,
                    lease=lease,
                    limits=replace(limits, chain_timeout=remaining),
                    purpose="web",
                    journal=journal,
                )
            )
            result.outcome = capture.outcome
            result.reason_code = capture.reason_code
            result.gaps.extend(capture.gaps)
            collect_browser_materials(result, capture, capture_dir, limits.max_task_bytes)
            relevant_errors = [
                row for row in gateway.errors
                if row.get("reason_code") != "browser_request_not_permitted"
            ]
            if relevant_errors:
                result.gaps.append("browser_guard_diagnostics")
                journal.append("browser_guard_diagnostics", {"count": len(relevant_errors)})
