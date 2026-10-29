"""Use HTTP for ordinary links and confined Chrome for dynamic continuation."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from threading import Event

from .android_worker import AndroidLease, AndroidWorker, AndroidWorkerConfig
from .browser_capture import BrowserCaptureResult, capture_browser
from .browser_gateway import BrowserGateway
from .classify import classify_input
from .errors import FxfetchError
from .limits import Limits
from .workflow import Artifact, Attempt, Workflow, WorkflowResult

_TERMINATION_REASONS = {"cancelled", "task_timeout", "chain_timeout", "browser_read_timeout"}
_GUARD_REASONS = {"target_not_public", "browser_wire_limit", "request_limit", "invalid_url"}


def apply_gateway_errors(result: WorkflowResult, errors: list[dict]) -> None:
    if not errors:
        return
    result.landing["network_guard"] = list(errors)
    # Browser background traffic without a page-request permit is expected to
    # be denied. Preserve its private diagnostic without misclassifying the
    # requested page as blocked or replacing its actual capture result.
    relevant = [row for row in errors if row.get("reason_code") != "browser_request_not_permitted"]
    if not relevant:
        return
    if result.artifacts or result.outcome == "blocked" or result.reason_code in _TERMINATION_REASONS:
        return
    strong = next((row for row in relevant if row.get("reason_code") in _GUARD_REASONS), None)
    weak_result = result.reason_code in {
        "browser_dynamic_incomplete",
        "browser_network_error",
        "browser_navigation_failed",
        "browser_capture_failed",
    }
    # Socket shutdown/side-resource noise must not overwrite a CAPTCHA, expired
    # budget or precise download-validation failure.
    if strong or weak_result:
        selected = strong or next(
            (
                row
                for row in relevant
                if row.get("reason_code") not in {"cancelled", "browser_transport_failed"}
            ),
            None,
        )
        if selected:
            result.reason_code = str(selected["reason_code"])
            result.outcome, result.coverage = "failed", "partial"


def project_capture(capture: BrowserCaptureResult, url: str) -> WorkflowResult:
    """Keep browser acquisition facts distinct from the generated APK path."""
    result = WorkflowResult(capture.outcome, capture.reason_code, capture.coverage)
    result.collector_mode = "android_chrome"
    result.artifacts = [Artifact(a.kind, a.path, a.sha256, a.size, a.url) for a in capture.artifacts]
    result.attempts = [Attempt("android", url, result.outcome, result.reason_code, result.coverage)]
    result.hops = [dict(row, chain="android", mode="android_chrome") for row in capture.responses]
    result.bodies = list(capture.partials)
    # Optional material fields allow the capture engine to evolve without
    # introducing an HTTP replay of consumed cookies or one-use download tokens.
    for field in ("offline", "page_qr", "candidates", "selection_candidates"):
        value = getattr(capture, field, None)
        if value is not None:
            setattr(result, field, value)
    result.bodies.extend(getattr(capture, "bodies", []))
    result.landing = {
        "evidence": [{"mode": "android_chrome", "session_replayed": False}],
        "gaps": list(capture.gaps),
    }
    return result


class BrowserWorkflow:
    def __init__(
        self, static: Workflow, config: AndroidWorkerConfig, limits: Limits,
        *, lease_id: str | None = None,
        http_first: bool = False,
    ) -> None:
        self.static, self.config, self.limits = static, config, limits
        self.lease_id = lease_id
        self.http_first = http_first

    def run(
        self,
        url: str,
        output_dir: Path,
        cancel: Event,
        on_event: Callable[[dict[str, object]], None] | None = None,
    ) -> WorkflowResult:
        kind = classify_input(url).kind
        if kind != "http":
            return self.static.run(url, output_dir, cancel, on_event)
        started = time.monotonic()
        preflight = None
        limits = self.limits
        browser_dir = output_dir
        if self.http_first:
            request_count = 0

            def http_event(event: dict[str, object]) -> None:
                nonlocal request_count
                if event.get("event") == "request":
                    request_count += 1
                if on_event:
                    on_event(event)

            preflight = self.static.run(url, output_dir / "http", cancel, http_event)
            dynamic = preflight.reason_code in {
                "browser_required", "challenge_detected", "device_verification_required",
            }
            browser_recoverable_response = preflight.reason_code in {"http_status", "http_access_control"} and any(
                hop.get("status") in {403, 429, 502, 503} for hop in preflight.hops
            )
            if preflight.artifacts or preflight.selection_candidates or not (dynamic or browser_recoverable_response):
                return preflight
            used = sum(p.stat().st_size for p in output_dir.rglob("*") if p.is_file()) if output_dir.exists() else 0
            limits = replace(self.limits,
                             max_requests=self.limits.max_requests - max(request_count, len(preflight.hops)),
                             max_task_bytes=self.limits.max_task_bytes - used,
                             max_web_bytes=self.limits.max_web_bytes - sum(size for b in preflight.bodies
                                                                          if isinstance(size := b.get("size"), int)))
            browser_dir = output_dir / "browser"
            if on_event:
                on_event({"event": "browser_required", "url": url, "reason_code": preflight.reason_code,
                          "new_request_session": True, "cookies_inherited": False})
        result = WorkflowResult("failed", "browser_guard_unavailable", "partial")
        result.collector_mode = "android_chrome_unavailable"
        captured = False
        try:
            if cancel.is_set():
                raise FxfetchError("cancelled", "Collection cancelled")
            remaining = self.limits.chain_timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise FxfetchError("task_timeout", "HTTP resolution exhausted task deadline")
            if min(limits.max_requests, limits.max_task_bytes, limits.max_web_bytes) <= 0:
                raise FxfetchError("request_limit", "HTTP resolution exhausted shared browser budgets")
            if on_event:
                on_event({"event": "browser_preparing", "url": url, "chain": "android"})
            with BrowserGateway(
                timeout=remaining,
                max_connections=limits.max_requests,
                max_wire_bytes=min(
                    limits.max_task_bytes, limits.max_package_bytes + limits.max_web_bytes
                ),
                cancel=cancel,
                on_event=on_event,
            ) as gateway:
                with AndroidLease(
                    AndroidWorker(self.config), gateway, cancel, remaining,
                    lease_id=self.lease_id,
                ) as lease:
                    remaining = self.limits.chain_timeout - (time.monotonic() - started)
                    if remaining <= 0:
                        raise FxfetchError("task_timeout", "Browser startup exhausted task deadline")
                    if on_event:
                        on_event({"event": "browser_started", "url": url, "chain": "android"})
                    capture = asyncio.run(
                        capture_browser(
                            url,
                            browser_dir,
                            cancel,
                            lease=lease,
                            limits=replace(limits, chain_timeout=remaining),
                            on_event=on_event,
                        )
                    )
                    result = project_capture(capture, url)
                    captured = True
                    apply_gateway_errors(result, gateway.errors)
        except (FxfetchError, OSError) as exc:
            code = exc.code if isinstance(exc, FxfetchError) else "browser_worker_unavailable"
            if captured:
                result.landing.setdefault("gaps", []).append(code)  # type: ignore[union-attr]
            else:
                result.outcome, result.reason_code, result.coverage = "failed", code, "partial"
        result.attempts = [Attempt("android", url, result.outcome, result.reason_code, result.coverage)]
        if preflight is not None:
            result.hops[:0] = [dict(row, mode="http") for row in preflight.hops]
            result.bodies[:0] = preflight.bodies
            result.attempts[:0] = preflight.attempts
            result.landing["http_resolution"] = {
                "outcome": preflight.outcome, "reason_code": preflight.reason_code,
                "coverage": preflight.coverage, "new_browser_session": True, "cookies_inherited": False,
            }
            if not result.offline.get("available") and preflight.offline.get("available"):
                result.offline = preflight.offline
        # No fallback is made after an unknown dynamic result. In particular a
        # blocked Android session must not be re-labelled as APK absence or
        # silently restarted with an iPhone UA.
        return result
