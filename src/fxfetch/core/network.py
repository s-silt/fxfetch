"""Direct-first collection with one explicitly recorded, pre-session proxy fallback."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, fields, replace
from pathlib import Path
from threading import Event
from typing import Any, Protocol

from .http_client import HttpClient
from .limits import Limits
from .proxy import LocalConnectProxy
from .public_dns import DefaultPublicDNSResolver
from .workflow import Workflow, WorkflowResult

# Only transport failures before any observed response can change egress.
_DEFAULT_LIMITS = Limits()

RETRYABLE_INITIAL_FAILURES = frozenset(
    {
        "dns_failed",
        "dns_timeout",
        "network_failed",
        "network_timeout",
        "tls_handshake_failed",
        "transfer_failed",
        "connection_failed",
    }
)
_SESSION_EVENTS = frozenset(
    {
        "session_established",
        "interaction_started",
        "response_received",
        "response_progress",
        "response_complete",
        "redirect",
        "page_received",
        "download_candidate",
        "download_started",
        "download_progress",
        "file_verifying",
        "file_verified",
        "challenge_detected",
        "browser_required",
    }
)


def build_default_client(limits: Limits, proxyconfig: LocalConnectProxy | None = None) -> HttpClient:
    """Construct one explicitly selected transport, not the retry policy itself."""
    resolver = DefaultPublicDNSResolver(proxy=proxyconfig)
    return HttpClient(limits, resolver=resolver.resolve, proxy=proxyconfig, dns_timeout=20.0)


class Collector(Protocol):
    def run(
        self,
        url: str,
        output_dir: Path,
        cancel: Event,
        on_event: Callable[[dict[str, object]], None] | None = None,
    ) -> WorkflowResult: ...


CollectorFactory = Callable[[Limits, LocalConnectProxy | None], Collector]


@dataclass
class AcquisitionResult(WorkflowResult):
    network_mode: str = "direct"
    network_attempts: list[dict[str, Any]] = field(default_factory=list)


def _default_collector(limits: Limits, proxy: LocalConnectProxy | None) -> Collector:
    return Workflow(build_default_client(limits, proxy), limits=limits)


class AcquisitionPolicy:
    """Never resume an established session through a different outbound route.

    A proxy is only a configured fallback. An initial request without a response
    may have reached its server: a retry is a separate attempt and session, not a
    claim of continuity. Full original results and evidence remain available.
    """

    def __init__(
        self,
        limits: Limits = _DEFAULT_LIMITS,
        proxy: LocalConnectProxy | None = None,
        *,
        collector_factory: CollectorFactory | None = None,
        browser_root: Path | None = None,
        android_lease_id: str | None = None,
    ) -> None:
        self.limits = limits
        self.proxy = proxy
        self.browser_root = browser_root
        self.android_lease_id = android_lease_id
        self.collector_factory = collector_factory or self._collector

    def _collector(self, limits: Limits, proxy: LocalConnectProxy | None) -> Collector:
        if self.browser_root is not None and proxy is None:
            from .android_worker import load_worker_config

            config = load_worker_config(self.browser_root)
            if config is not None:
                from .browser_workflow import BrowserWorkflow

                return BrowserWorkflow(
                    Workflow(build_default_client(limits), limits), config, limits,
                    lease_id=self.android_lease_id,
                    http_first=True,
                )
        return _default_collector(limits, proxy)

    def run(
        self,
        url: str,
        output_dir: Path,
        cancel: Event,
        on_event: Callable[[dict[str, object]], None] | None = None,
    ) -> AcquisitionResult:
        started = time.monotonic()
        history: list[dict[str, Any]] = []
        last = WorkflowResult("failed", "cancelled" if cancel.is_set() else "task_timeout", "partial")
        active_mode = "direct"
        for index, mode in enumerate(("direct", "proxy")):
            remaining = self.limits.chain_timeout - (time.monotonic() - started)
            if cancel.is_set() or remaining <= 0:
                break
            if mode == "proxy" and self.proxy is None:
                break
            # Disk includes every prior attempt, even failed prefixes and receipts.
            used = (
                sum(p.stat().st_size for p in output_dir.rglob("*") if p.is_file())
                if output_dir.exists()
                else 0
            )
            prior_requests = sum(max(1, len(row["result"].get("hops", []))) for row in history)
            prior_web = sum(
                int(body.get("size", 0)) for row in history for body in row["result"].get("bodies", [])
            )
            limits = replace(
                self.limits,
                chain_timeout=remaining,
                max_requests=self.limits.max_requests - prior_requests,
                max_task_bytes=self.limits.max_task_bytes - used,
                max_web_bytes=self.limits.max_web_bytes - prior_web,
            )
            if min(limits.max_requests, limits.max_task_bytes, limits.max_web_bytes) <= 0:
                break
            active_mode = mode
            if mode == "proxy" and on_event:
                on_event(
                    {
                        "event": "network_fallback",
                        "url": url,
                        "from_mode": "direct",
                        "to_mode": "proxy",
                        "reason_code": history[-1]["result"]["reason_code"],
                        "new_request_session": True,
                        "cookies_inherited": False,
                    }
                )
            attempt_id = f"network-{index + 1}-{mode}"
            session_observed = False
            request_events = 0

            def emit(event: dict[str, object], *, mode: str = mode, attempt_id: str = attempt_id) -> None:
                nonlocal session_observed, request_events
                if event.get("event") == "request":
                    request_events += 1
                if (
                    event.get("session_established") is True
                    or request_events > 1
                    or event.get("event") in _SESSION_EVENTS
                ):
                    session_observed = True
                if on_event:
                    on_event({**event, "network_mode": mode, "attempt_id": attempt_id})

            emit(
                {
                    "event": "network_attempt_started",
                    "url": url,
                    "new_request_session": True,
                    "cookies_inherited": False,
                }
            )
            attempt_dir = output_dir / "network" / mode
            attempt_dir.mkdir(parents=True, exist_ok=True)
            last = self.collector_factory(limits, self.proxy if mode == "proxy" else None).run(
                url, attempt_dir, cancel, emit
            )
            history.append(
                {
                    "attempt_id": attempt_id,
                    "network_mode": mode,
                    "session_continuity": "independent_request_session",
                    "cookies_inherited": False,
                    "result": asdict(last),
                }
            )
            emit(
                {
                    "event": "network_attempt_completed",
                    "url": url,
                    "reason_code": last.reason_code,
                    "outcome": last.outcome,
                }
            )
            eligible = (
                mode == "direct"
                and self.proxy is not None
                and last.outcome == "failed"
                and last.reason_code in RETRYABLE_INITIAL_FAILURES
                and not session_observed
                and not any(
                    (last.hops, last.bodies, last.artifacts, last.candidates, last.selection_candidates)
                )
            )
            if not eligible or cancel.is_set() or time.monotonic() - started >= self.limits.chain_timeout:
                break
        if cancel.is_set() or time.monotonic() - started >= self.limits.chain_timeout:
            # Keep the retained attempt history when the shared deadline stops the task.
            last = WorkflowResult(
                "failed", "cancelled" if cancel.is_set() else "task_timeout", "partial",
                collector_mode=last.collector_mode,
            )
        return AcquisitionResult(
            **{f.name: getattr(last, f.name) for f in fields(WorkflowResult)},
            network_mode=active_mode,
            network_attempts=history,
        )
