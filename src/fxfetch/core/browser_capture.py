"""Original-session Chrome acquisition; requires independently verified confinement."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import time
from collections.abc import Callable, Coroutine
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from threading import Event
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit

from playwright.async_api import Browser, BrowserContext, ElementHandle, Frame, Page, Route, async_playwright
from playwright.async_api import Error as PlaywrightError

from .browser_click_state import write_click_state
from .browser_dom_links import OBSERVE_PACKAGE_LINKS, observed_package_candidates
from .browser_progress import BrowserProgress
from .browser_response import (
    disclosed_html_response,
    expired_resource_dispatch,
    expired_resource_fulfillment,
    optional_resource_failure,
    package_response_candidate,
    write_capture_diagnostic,
)
from .browser_runtime import RuntimeDiagnostics
from .browser_web_evidence import BrowserWebEvidence, record_saved_material
from .cdp_transport import CDPCommandError, CDPMux, resolve_endpoint
from .classify import classify_input
from .discovery import Candidate, device_gate_rejected, download_action, rendered_challenge
from .download import classify_package, is_package_prefix
from .errors import FxfetchError
from .flutter_adapter import MAX_MAIN_BYTES
from .guard import validate_url
from .limits import Limits
from .offline import MAX_RESOURCE_BYTES, MAX_RESOURCE_TOTAL, MAX_RESOURCES, OfflineBundle
from .page_qr import MAX_DECODE_SECONDS, MAX_IMAGE_TOTAL, MAX_IMAGES, decode_saved_image, discover_images
from .script_content import script_content_candidates
from .web_journal import EvidenceJournal

READ_BYTES = 64 * 1024
MAX_NO_PROGRESS_SECONDS = 30.0
_UNSUPPORTED_TARGETS = {"worker", "shared_worker", "service_worker", "worklet", "auction_worklet"}
_DEFAULT_LIMITS = Limits()
_BUSINESS_TEXT = re.compile(
    r"登录|注册|支付|充值|购买|sign.?in|sign.?up|register|payment|purchase", re.IGNORECASE
)
_SEMANTIC_CONTROLS = "a,button,input[type=button],[role=button]"
_ACTION_HINTS = ":is([class*='download' i],[class*='install' i],[class*='button' i],[class*='btn' i],[onclick])"
_INTERACTIVE_CONTROLS = f"{_SEMANTIC_CONTROLS},div{_ACTION_HINTS},span{_ACTION_HINTS}"


@dataclass(frozen=True)
class BrowserLaunchProof:
    executable_path: Path
    profile_root: Path
    proxy_server: str
    extra_args: tuple[str, ...] = ()
    cdp_endpoint: str | None = None
    headless: bool = True
    permit_request: Callable[[str, str], None] | None = None


class BrowserNetworkLease(Protocol):
    def verify_before_launch(self) -> BrowserLaunchProof:
        """Check live network confinement, Chrome identity and hard profile quota.

        A user flag or JSON receipt alone is insufficient. A remote browser must
        belong to the same independently isolated lease.
        """
        ...


@dataclass(frozen=True)
class CapturedPackage:
    kind: str
    path: Path
    size: int
    sha256: str
    url: str
    requires_session: str = "unknown"


@dataclass
class BrowserCaptureResult:
    outcome: str = "failed"
    reason_code: str = "browser_dynamic_incomplete"
    coverage: str = "partial"
    artifacts: list[CapturedPackage] = field(default_factory=list)
    responses: list[dict[str, object]] = field(default_factory=list)
    partials: list[dict[str, object]] = field(default_factory=list)
    gaps: list[str] = field(default_factory=lambda: ["dynamic_scope_not_exhaustive"])
    bodies: list[dict[str, object]] = field(default_factory=list)
    offline: dict[str, Any] = field(default_factory=dict)
    candidates: list[Candidate] = field(default_factory=list)
    selection_candidates: list[Candidate] = field(default_factory=list)
    page_qr: dict[str, Any] = field(default_factory=dict)


async def capture_browser(
    entry_url: str,
    output_dir: Path,
    cancel: Event,
    *,
    lease: BrowserNetworkLease | None = None,
    limits: Limits = _DEFAULT_LIMITS,
    on_event: Callable[[dict[str, object]], None] | None = None,
    chain: str = "android",
    purpose: str = "package",
    journal: EvidenceJournal | None = None,
    observation_context: dict[str, str] | None = None,
) -> BrowserCaptureResult:
    """Capture without HTTP replay, native file staging or downloaded-code execution.

    Tests may inject a tests-only local lease. Production needs its own accepted
    lease issuer. Settled pages with no package stay failed/partial, not not_found.
    """
    if lease is None:
        raise FxfetchError("browser_guard_unavailable", "Browser confinement lease is unavailable")
    proof = lease.verify_before_launch()
    if proof.permit_request is None:
        raise FxfetchError("browser_guard_unavailable", "Browser request permission callback is unavailable")
    if proof.cdp_endpoint is None and (not proof.executable_path.is_file() or not proof.proxy_server):
        raise FxfetchError("browser_guard_unavailable", "Verified Chrome/proxy launch data missing")
    if purpose not in {"package", "web"}:
        raise FxfetchError("unsupported_capture_purpose", "Unsupported browser capture purpose")
    if chain not in {"android", "iphone"} or urlsplit(entry_url).scheme not in {"http", "https"}:
        raise FxfetchError("unsupported_input", "Unsupported browser capture input")
    result = BrowserCaptureResult()
    if purpose == "web":
        result.gaps = ["single_passive_visit", "interaction_not_performed"]
    deadline = time.monotonic() + min(600.0, limits.chain_timeout)
    requests = redirects = body_bytes = candidate_number = interactions = web_bytes = 0
    ready: dict[str, str] = {}
    request_numbers: dict[tuple[str, str], int] = {}
    web_observer = (
        BrowserWebEvidence(journal=journal, event_context=observation_context)
        if purpose == "web" or journal is not None else None
    )
    policy_observer = web_observer if purpose == "web" else None
    target_ready = asyncio.Event()
    tasks: set[asyncio.Task[None]] = set()
    errors: list[FxfetchError] = []
    deferred_resource_errors: list[FxfetchError] = []
    done = asyncio.Event()
    receiving = asyncio.Lock()
    mux: CDPMux | None = None
    context: BrowserContext | None = None
    browser: Browser | None = None
    last_activity = time.monotonic()
    clicked: set[tuple[str, str, str]] = set()
    resources: dict[str, Path] = {}
    resource_aliases: dict[str, str] = {}
    successful_documents: set[str] = set()
    snapshots: dict[str, tuple[Path, str]] = {}
    seen_qr: set[str] = set()
    followed_qr: set[str] = set()
    followed_dom_packages: set[str] = set()
    followed_script_content: set[str] = set()
    script_content_targets: set[str] = set()
    observed_page_challenges: dict[tuple[str, str], str] = {}
    qr_sources: list[dict[str, Any]] = []
    qr_gaps: list[str] = []
    qr_count = qr_bytes = 0
    qr_seconds = 0.0
    runtime_diagnostics = RuntimeDiagnostics(output_dir)
    progress = BrowserProgress()

    def check() -> None:
        if cancel.is_set():
            raise FxfetchError("cancelled", "Browser capture cancelled")
        if time.monotonic() >= deadline:
            raise FxfetchError("chain_timeout", "Browser capture time budget exhausted")

    def emit(event: str, url: str, **values: object) -> None:
        if on_event is not None:
            on_event({"event": event, "url": url, "chain": chain, "request_count": requests, **values})

    def schedule(coroutine: Coroutine[Any, Any, None]) -> None:
        task = asyncio.create_task(coroutine)
        tasks.add(task)

        def finished(item: asyncio.Task[None]) -> None:
            tasks.discard(item)
            if item.cancelled():
                return
            error = item.exception()
            if error is not None:
                if not isinstance(error, FxfetchError):
                    write_capture_diagnostic(output_dir, error, "event_handler")
                errors.append(
                    error
                    if isinstance(error, FxfetchError)
                    else FxfetchError("browser_capture_failed", "Browser event handler failed")
                )
                done.set()

        task.add_done_callback(finished)

    async def send(session: str | None, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        assert mux is not None
        return await mux.send(session, method, params)

    async def controlled(operation: Coroutine[Any, Any, Any]) -> Any:
        """Bound page-side execution even if a hostile getter never returns."""
        task = asyncio.create_task(operation)
        end = min(deadline, time.monotonic() + limits.read_timeout)
        try:
            while not task.done():
                check()
                if time.monotonic() >= end:
                    raise FxfetchError("browser_read_timeout", "Browser page operation exceeded its budget")
                await asyncio.wait({task}, timeout=0.05)
            check()
            return task.result()
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def setup(session: str, data: dict[str, Any]) -> None:
        if data["targetInfo"].get("type") in _UNSUPPORTED_TARGETS:
            result.gaps.append("browser_worker_scope_unsupported")
            raise FxfetchError("browser_worker_scope_unsupported", "Worker targets are outside verified capture scope")
        if web_observer is not None:
            target = data["targetInfo"]
            web_observer.target_attached(session, target)
        await send(session, "Page.enable")
        if purpose == "web":
            frame_tree = await send(session, "Page.getFrameTree")
            frame = frame_tree.get("frameTree", {}).get("frame", {})
            if web_observer is not None:
                web_observer.initial_frame(session, frame)
        await send(session, "Runtime.enable")
        await send(session, "Network.enable")
        await send(session, "Network.setCacheDisabled", {"cacheDisabled": True})
        await send(session, "Network.setBypassServiceWorker", {"bypass": True})
        await send(
            session,
            "Fetch.enable",
            {
                "patterns": [
                    {"urlPattern": "*", "requestStage": "Request"},
                    {"urlPattern": "*", "requestStage": "Response"},
                ]
            },
        )
        await send(
            session,
            "Target.setAutoAttach",
            {
                "autoAttach": True,
                "waitForDebuggerOnStart": True,
                "flatten": True,
                "filter": [{"type": kind} for kind in ["iframe", *sorted(_UNSUPPORTED_TARGETS)]] + [{"exclude": True}],
            },
        )
        # Remote Android Chrome keeps its own fixed platform configuration.
        # Desktop Chrome uses a fixed mobile viewport without UA spoofing.
        if proof.cdp_endpoint is None and data["targetInfo"].get("type") == "page":
            await send(
                session,
                "Emulation.setDeviceMetricsOverride",
                {
                    "width": 412 if chain == "android" else 390,
                    "height": 915 if chain == "android" else 844,
                    "deviceScaleFactor": 1,
                    "mobile": True,
                },
            )
            await send(session, "Emulation.setTouchEmulationEnabled", {"enabled": True})
        ready[data["targetInfo"]["targetId"]] = session
        target_ready.set()
        await send(session, "Runtime.runIfWaitingForDebugger")

    async def stream_package(session: str, event: dict[str, Any], headers: dict[str, str]) -> None:
        nonlocal body_bytes, candidate_number
        async with receiving:
            check()
            request_id, url = event["requestId"], event["request"]["url"]
            if result.artifacts:
                await send(session, "Fetch.failRequest", {"requestId": request_id, "errorReason": "Aborted"})
                return
            candidate_number += 1
            partial = output_dir / "partial" / f"{candidate_number:04d}.package.partial"
            partial.parent.mkdir(parents=True, exist_ok=True)
            expected = (
                int(headers["content-length"])
                if headers.get("content-length", "").isdigit() and not headers.get("content-encoding")
                else None
            )
            if expected is not None and expected > min(
                limits.max_package_bytes, limits.max_task_bytes - body_bytes
            ):
                await send(session, "Fetch.failRequest", {"requestId": request_id, "errorReason": "Aborted"})
                raise FxfetchError("download_limit", "Declared browser candidate exceeds byte limit")
            response = await send(session, "Fetch.takeResponseBodyAsStream", {"requestId": request_id})
            handle = response["stream"]
            size = 0
            digest = hashlib.sha256()
            last_progress = 0.0
            emit("download_started", url, received_bytes=0, total_bytes=expected, package_unverified=True)
            try:
                with partial.open("xb") as output:
                    while True:
                        check()
                        remaining = min(limits.max_package_bytes - size, limits.max_task_bytes - body_bytes)
                        if remaining < 0:
                            raise FxfetchError("download_limit", "Browser body budget exhausted")
                        chunk = await send(
                            session, "IO.read", {"handle": handle, "size": min(READ_BYTES, remaining + 1)}
                        )
                        raw = (
                            base64.b64decode(chunk.get("data", ""), validate=True)
                            if chunk.get("base64Encoded")
                            else chunk.get("data", "").encode("utf-8")
                        )
                        if len(raw) > min(READ_BYTES, remaining + 1):
                            raise FxfetchError(
                                "browser_stream_protocol", "CDP stream exceeded requested read cap"
                            )
                        # DOM/inline evidence can consume the shared task budget
                        # while IO.read awaits. Recheck before any disk write.
                        remaining = max(0, min(limits.max_package_bytes - size, limits.max_task_bytes - body_bytes))
                        accepted = raw[:remaining]
                        output.write(accepted)
                        digest.update(accepted)
                        size += len(accepted)
                        body_bytes += len(accepted)
                        now = time.monotonic()
                        if now - last_progress >= 1 or chunk.get("eof"):
                            emit(
                                "download_progress",
                                url,
                                received_bytes=size,
                                total_bytes=expected,
                                complete=False,
                                package_unverified=True,
                            )
                            last_progress = now
                        if len(raw) != len(accepted):
                            raise FxfetchError(
                                "download_limit", "Browser candidate exceeded hard byte budget"
                            )
                        if chunk.get("eof"):
                            break
                    if expected is not None and size != expected:
                        raise FxfetchError("length_mismatch", "Browser candidate transfer length mismatch")
                check()
                emit("file_verifying", url, size=size)
                kind = classify_package(partial, limits)
                if kind is None or kind != ("apk" if chain == "android" else "ipa"):
                    raise FxfetchError(
                        "candidate_not_package", "Browser candidate failed package/platform validation"
                    )
                check()
                artifact = output_dir / "artifacts" / f"{digest.hexdigest()}.{kind}"
                artifact.parent.mkdir(exist_ok=True)
                partial.replace(artifact)
                result.artifacts.append(CapturedPackage(kind, artifact, size, digest.hexdigest(), url))
                emit(
                    "download_progress",
                    url,
                    received_bytes=size,
                    total_bytes=expected,
                    complete=True,
                    package_unverified=False,
                )
                emit("file_verified", url, kind=kind, size=size, sha256=digest.hexdigest())
                result.outcome, result.reason_code, result.coverage = (
                    "downloaded",
                    "package_verified",
                    "complete",
                )
                result.gaps[:] = [gap for gap in result.gaps if gap in {
                    "browser_optional_resource_http_error", "browser_subresource_http_error",
                    "browser_optional_resource_network_error",
                    "browser_subresource_network_error",
                    "browser_resource_interception_expired",
                }]
                await send(session, "IO.close", {"handle": handle})
                # Taken streams cannot be resumed: terminate the original request.
                await send(session, "Fetch.failRequest", {"requestId": request_id, "errorReason": "Aborted"})
                done.set()
            except (FxfetchError, OSError, ValueError, asyncio.CancelledError):
                if partial.is_file():
                    result.partials.append(
                        {
                            "path": str(partial),
                            "size": size,
                            "sha256": digest.hexdigest(),
                            "hash_scope": "saved_prefix",
                        }
                    )
                emit(
                    "download_progress",
                    url,
                    received_bytes=size,
                    total_bytes=expected,
                    complete=False,
                    package_unverified=True,
                )
                # Lease/browser teardown closes the stream on cancellation too.
                raise

    async def stream_web(session: str, event: dict[str, Any], headers: dict[str, str]) -> None:
        """Keep actual response bytes, then fulfill that same paused request.

        Chrome provides the decoded body. Remove transport encoding headers when
        fulfilling it, and count decoded bytes as well as the gateway wire cap.
        No request is reissued to obtain page resources, scripts, or QR images.
        """
        nonlocal body_bytes, web_bytes, last_activity
        async with receiving:
            check()
            request_id, url = event["requestId"], event["request"]["url"]
            is_main = policy_observer is not None and policy_observer.is_main_request(session, event)
            request_ref = (
                web_observer.request_ref(session, request_id)
                if web_observer is not None
                else f"browser:{session}:{request_id}"
            )
            journal_root = journal.path.parent if journal is not None else output_dir
            mime = headers.get("content-type", "").lower()
            resource_type = event.get("resourceType", "")
            is_resource = (
                mime.startswith("image/") or "text/css" in mime or resource_type in {"Image", "Stylesheet"}
            )
            is_script = resource_type == "Script" or "javascript" in mime
            maximum = (
                MAX_RESOURCE_BYTES if is_resource else MAX_MAIN_BYTES if is_script else limits.max_body_bytes
            )
            length = headers.get("content-length", "")
            expected = int(length) if length.isdigit() and not headers.get("content-encoding") else None
            allowance = min(maximum, limits.max_web_bytes - web_bytes, limits.max_task_bytes - body_bytes)
            if allowance < 0 or expected is not None and expected > allowance:
                await send(session, "Fetch.failRequest", {"requestId": request_id, "errorReason": "Aborted"})
                raise FxfetchError("browser_web_limit", "Browser response exceeds body/web/task byte limit")
            response = await send(session, "Fetch.takeResponseBodyAsStream", {"requestId": request_id})
            handle = response["stream"]
            folder = output_dir / "web"
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / f"response-{len(result.bodies):04d}.body"
            partial = path.with_suffix(".partial")
            size = 0
            digest = hashlib.sha256()
            prefix = bytearray()
            try:
                with partial.open("xb") as output:
                    while True:
                        check()
                        remaining = min(
                            maximum - size,
                            limits.max_web_bytes - web_bytes,
                            limits.max_task_bytes - body_bytes,
                        )
                        if remaining < 0:
                            raise FxfetchError("browser_web_limit", "Browser decoded web budget exhausted")
                        chunk = await send(
                            session, "IO.read", {"handle": handle, "size": min(READ_BYTES, remaining + 1)}
                        )
                        raw = (
                            base64.b64decode(chunk.get("data", ""), validate=True)
                            if chunk.get("base64Encoded")
                            else chunk.get("data", "").encode("utf-8")
                        )
                        prefix.extend(raw[:max(0, 4 - len(prefix))])
                        if len(raw) > min(READ_BYTES, remaining + 1):
                            raise FxfetchError(
                                "browser_stream_protocol", "CDP stream exceeded requested read cap"
                            )
                        remaining = max(0, min(maximum - size, limits.max_web_bytes - web_bytes,
                                               limits.max_task_bytes - body_bytes))
                        accepted = raw[:remaining]
                        output.write(accepted)
                        digest.update(accepted)
                        size += len(accepted)
                        body_bytes += len(accepted)
                        web_bytes += len(accepted)
                        if len(accepted) != len(raw):
                            raise FxfetchError("browser_web_limit", "Browser decoded web byte limit exceeded")
                        if chunk.get("eof"):
                            break
                if expected is not None and expected != size:
                    raise FxfetchError("length_mismatch", "Browser web response length mismatch")
                check()
                partial.replace(path)
                package_stream = is_package_prefix(bytes(prefix))
                result.bodies.append(
                    {
                        "url": url,
                        "path": str(path),
                        "size": size,
                        "sha256": digest.hexdigest(),
                        "content_type": mime,
                        "chain": chain,
                        "purpose": "browser_response",
                        "package_stream": package_stream,
                        "complete": True,
                        "hash_scope": "browser_response_decoded",
                        "request_id": request_numbers.get((session, request_id)),
                    }
                )
                body_record = result.bodies[-1]
                if web_observer is not None:
                    body_record.update(
                        {
                            **web_observer.session_context(session),
                            "request_ref": request_ref,
                            "representation": "browser_response_decoded",
                        }
                    )
                    body_text = None
                    if is_main and size > 0:
                        try:
                            body_text = path.read_bytes().decode("utf-8", errors="replace")
                        except OSError:
                            body_text = ""
                    web_observer.body_saved(
                        session,
                        event,
                        path=path.relative_to(journal_root).as_posix(),
                        size=size,
                        sha256=digest.hexdigest(),
                        representation="browser_response_decoded",
                        complete=True,
                        body_text=body_text,
                        package_stream=package_stream,
                    )
                elif journal is not None:
                    record_saved_material(
                        journal,
                        source_url=url,
                        path=path.relative_to(journal_root).as_posix(),
                        size=size,
                        sha256=digest.hexdigest(),
                        representation="browser_response_decoded",
                        complete=True,
                        request_ref=request_ref,
                        resource_type=resource_type if isinstance(resource_type, str) else None,
                        package_stream=package_stream,
                    )
                if is_resource and 200 <= event["responseStatusCode"] < 300:
                    resource_total = sum(resource.stat().st_size for resource in set(resources.values()))
                    if len(resources) < MAX_RESOURCES and resource_total + size <= MAX_RESOURCE_TOTAL:
                        resources[url] = path
                    else:
                        result.gaps.append("offline_resource_limit")
                if resource_type == "Document" and ("text/html" in mime or "application/xhtml" in mime):
                    successful_documents.add(url)
                fulfillment_headers = [
                    item
                    for item in event.get("responseHeaders", [])
                    if item["name"].lower() not in {"content-length", "content-encoding", "transfer-encoding"}
                ]
                if disclosed_html_response(url, headers, resource_type, url in script_content_targets):
                    # The original page intended to read this as HTML via GET.
                    # Retain the original observation; render the bounded saved
                    # response in the same session without a second request.
                    fulfillment_headers = [h for h in fulfillment_headers
                                           if h["name"].lower() != "content-disposition"]
                    body_record["disposition_handling"] = "inline_disclosed_html"
                fulfillment_headers.append({"name": "Content-Length", "value": str(size)})
                await send(session, "IO.close", {"handle": handle})
                try:
                    await send(
                        session,
                        "Fetch.fulfillRequest",
                        {
                            "requestId": request_id,
                            "responseCode": event["responseStatusCode"],
                            "responseHeaders": fulfillment_headers,
                            "body": base64.b64encode(path.read_bytes()).decode("ascii"),
                        },
                    )
                except CDPCommandError as error:
                    if not expired_resource_fulfillment(error, resource_type, url, headers):
                        raise
                    # Bytes were received completely, but Chrome discarded this
                    # interception. Do not replay the resource or claim delivery.
                    body_record["delivered_to_browser"] = False
                    result.gaps.append("browser_resource_interception_expired")
                    return
                # Rendering starts after fulfillment, possibly long after the
                # response headers arrived; allow the normal idle window now.
                last_activity = time.monotonic()
                progress.content(url, digest.hexdigest())
            except (FxfetchError, OSError, ValueError, asyncio.CancelledError):
                if partial.is_file():
                    prefix_path = partial.relative_to(journal_root).as_posix()
                    package_stream = is_package_prefix(bytes(prefix), incomplete=True)
                    result.partials.append(
                        {
                            "path": str(partial),
                            "size": size,
                            "sha256": digest.hexdigest(),
                            "hash_scope": "saved_prefix",
                            "package_stream": package_stream,
                            **(
                                {
                                    **web_observer.session_context(session),
                                    "request_ref": request_ref,
                                    "url": url,
                                    "representation": "browser_saved_prefix",
                                    "complete": False,
                                }
                                if web_observer is not None
                                else {}
                            ),
                        }
                    )
                    if web_observer is not None:
                        web_observer.record_response_prefix(
                            session,
                            event,
                            path=prefix_path,
                            size=size,
                            sha256=digest.hexdigest(),
                            representation="browser_saved_prefix",
                            package_stream=package_stream,
                        )
                    elif journal is not None:
                        record_saved_material(
                            journal,
                            source_url=url,
                            path=prefix_path,
                            size=size,
                            sha256=digest.hexdigest(),
                            representation="browser_saved_prefix",
                            complete=False,
                            request_ref=request_ref,
                            package_stream=package_stream,
                            resource_type=(
                                event.get("resourceType")
                                if isinstance(event.get("resourceType"), str)
                                else None
                            ),
                        )
                raise

    async def paused(session: str, event: dict[str, Any]) -> None:
        try:
            await handle_paused(session, event)
        except CDPCommandError as error:
            url = event["request"]["url"]
            headers = {item["name"].lower(): item["value"] for item in event.get("responseHeaders", [])}
            if not expired_resource_dispatch(error, event.get("resourceType", ""), url, headers):
                raise
            result.responses.append({"url": url, "resource_type": event.get("resourceType", ""),
                                     "request_cancelled": True, "reason_code": "browser_resource_interception_expired"})
            result.gaps.append("browser_resource_interception_expired")
            # The original request has already been discarded by Chrome; do not
            # retry it, issue another permit, or infer an absent package.

    async def handle_paused(session: str, event: dict[str, Any]) -> None:
        nonlocal requests, redirects, last_activity
        check()
        last_activity = time.monotonic()
        url, request_id = event["request"]["url"], event["requestId"]
        if "responseStatusCode" not in event and "responseErrorReason" not in event:
            requests += 1
            if requests > limits.max_requests:
                if web_observer is not None:
                    web_observer.record_request_denied(
                        session,
                        f"browser:{session}:{request_id}",
                        url=url,
                        reason="request_limit",
                    )
                await send(session, "Fetch.failRequest", {"requestId": request_id, "errorReason": "Aborted"})
                raise FxfetchError("request_limit", "Browser request budget exhausted before dispatch")
            if urlsplit(url).scheme not in {"http", "https"}:
                if web_observer is not None:
                    web_observer.record_unsupported_request(session, event)
                await send(
                    session, "Fetch.failRequest", {"requestId": request_id, "errorReason": "BlockedByClient"}
                )
                raise FxfetchError("unsupported_browser_protocol", "Unsupported browser request protocol")
            network_id = event.get("networkId")
            network_id = network_id if isinstance(network_id, str) else None
            request_ref = (
                web_observer.begin_request(session, event)
                if web_observer is not None
                else f"browser:{session}:{request_id}"
            )
            if event.get("redirectedRequestId"):
                redirects += 1
                if redirects > limits.max_redirects:
                    await send(
                        session, "Fetch.failRequest", {"requestId": request_id, "errorReason": "Aborted"}
                    )
                    raise FxfetchError("redirect_limit", "Browser redirect budget exhausted before dispatch")
            assert proof.permit_request is not None
            try:
                approved_url = validate_url(url)
                proof.permit_request(approved_url, event["request"].get("method", "GET"))
            except FxfetchError as error:
                if web_observer is not None:
                    web_observer.record_request_denied(session, request_ref, reason=error.code)
                raise
            if web_observer is not None:
                web_observer.record_request_permitted(session, request_ref, network_id)
            emit("request", url, method=event["request"].get("method", "GET"))
            request_numbers[(session, request_id)] = requests
            await send(session, "Fetch.continueRequest", {"requestId": request_id})
            return
        if event.get("responseErrorReason"):
            headers = {item["name"].lower(): item["value"] for item in event.get("responseHeaders", [])}
            optional = optional_resource_failure(
                url, event.get("resourceType", ""), headers, network_error=event["responseErrorReason"],
            )
            response_error = (
                web_observer.response_error(session, event, optional)
                if web_observer is not None
                else {
                    "url": url, "network_error": event["responseErrorReason"],
                    "resource_type": event.get("resourceType", ""), "optional_resource_failure": optional,
                }
            )
            result.responses.append(response_error)
            await send(session, "Fetch.failRequest", {"requestId": request_id, "errorReason": "Aborted"})
            if optional and event["responseErrorReason"] == "Aborted":
                # Playwright intentionally aborts implicit favicon requests.
                return
            if (
                policy_observer is not None and not policy_observer.is_main_request(session, event)
            ) or (
                event.get("resourceType", "") != "Document" and not package_response_candidate(url, headers)
            ):
                result.responses[-1]["deferred_network_error"] = True
                result.gaps.append(
                    "browser_optional_resource_network_error" if optional else "browser_subresource_network_error"
                )
                deferred_resource_errors.append(FxfetchError("browser_network_error", "Chrome subresource network failed"))
                return
            if policy_observer is not None and policy_observer.is_main_request(session, event):
                result.outcome, result.reason_code = "failed", "browser_network_error"
            raise FxfetchError("browser_network_error", "Chrome network response failed")
        status = event.get("responseStatusCode", 0)
        headers = {item["name"].lower(): item["value"] for item in event.get("responseHeaders", [])}
        if web_observer is not None:
            response_record, observed_main, _ = web_observer.response_observed(
                session,
                event,
                headers,
                int(status),
                request_numbers.get((session, request_id)),
            )
        else:
            observed_main = False
            response_record = {
                "url": url,
                "status": status,
                "content_type": headers.get("content-type", ""),
                "request_id": request_numbers.get((session, request_id)),
                "resource_type": event.get("resourceType", ""),
            }
        is_main = purpose == "web" and observed_main
        result.responses.append(response_record)
        location_raw = headers.get("location")
        emit("response_received", url, status=status, content_type=headers.get("content-type", ""))
        if 300 <= status < 400 and location_raw and web_observer is not None:
            web_observer.record_redirect(session, event, location_raw)
        candidate = package_response_candidate(url, headers)
        if disclosed_html_response(url, headers, event.get("resourceType", ""), url in script_content_targets):
            candidate = False
            result.responses[-1]["disposition_handling"] = "inline_disclosed_html"
        if purpose == "web":
            if status in {401, 403, 429} or status >= 400:
                if event["request"].get("method") != "HEAD" and status not in {204, 205}:
                    await stream_web(session, event, headers)
                if is_main:
                    if status in {401, 403, 429}:
                        result.outcome, result.reason_code = "blocked", "http_access_control"
                    else:
                        result.outcome, result.reason_code = "failed", "http_status"
                else:
                    if web_observer is not None:
                        web_observer.subresource_http_error(session, event, int(status))
                return
            if 200 <= status < 300 and candidate:
                if web_observer is not None:
                    web_observer.unsupported_download(session, event, int(status))
                result.responses[-1]["body_captured"] = False
                await send(session, "Fetch.failRequest", {"requestId": request_id, "errorReason": "Aborted"})
                if is_main:
                    result.outcome, result.reason_code = "failed", "unsupported_download_response"
                return
            if 200 <= status < 300 and status not in {204, 205} and event["request"].get("method") != "HEAD":
                await stream_web(session, event, headers)
            else:
                if is_main and status in {204, 205}:
                    result.outcome, result.reason_code = "failed", "http_body_missing"
                await send(session, "Fetch.continueRequest", {"requestId": request_id})
            return
        elif status >= 400 and web_observer is not None and not observed_main:
            web_observer.subresource_http_error(session, event, int(status))
        if status >= 400 and event.get("resourceType", "") != "Document" and not candidate:
            optional = optional_resource_failure(url, event.get("resourceType", ""), headers)
            result.responses[-1]["optional_resource_failure"] = optional
            result.responses[-1]["deferred_http_error"] = True
            result.gaps.append("browser_optional_resource_http_error" if optional else "browser_subresource_http_error")
            deferred_resource_errors.append(
                FxfetchError("http_access_control", "Chrome subresource access control", outcome="blocked")
                if status in {401, 403, 429}
                else FxfetchError("browser_http_error", "Chrome subresource returned an HTTP error")
            )
            # Give the original status/body to the page so normal error handlers
            # and fallback download buttons can run, within the same byte caps.
            if event["request"].get("method") == "HEAD":
                await send(session, "Fetch.continueRequest", {"requestId": request_id})
            else:
                await stream_web(session, event, headers)
            return
        if status in {401, 403, 429}:
            await send(session, "Fetch.failRequest", {"requestId": request_id, "errorReason": "Aborted"})
            emit("challenge_detected", url, reason_code="http_access_control")
            raise FxfetchError("http_access_control", "Chrome response access control", outcome="blocked")
        if status >= 400:
            await send(session, "Fetch.failRequest", {"requestId": request_id, "errorReason": "Aborted"})
            raise FxfetchError("browser_http_error", "Chrome response returned an HTTP error")
        if 200 <= status < 300 and candidate:
            emit("download_candidate", url, verified=False, source="response_headers")
            await stream_package(session, event, headers)
        elif 200 <= status < 300 and status not in {204, 205} and event["request"].get("method") != "HEAD":
            await stream_web(session, event, headers)
        else:
            if 300 <= status < 400 and headers.get("location"):
                resource_aliases[url] = urljoin(url, headers["location"])
                if url in script_content_targets:
                    script_content_targets.add(resource_aliases[url])
                emit(
                    "redirect", url, from_url=url, to_url=headers["location"], status=status, mechanism="http"
                )
            await send(session, "Fetch.continueRequest", {"requestId": request_id})

    def event(session: str, method: str, data: dict[str, Any]) -> None:
        if method == "transport_error":
            errors.append(FxfetchError("browser_cdp_failed", "CDP bridge closed"))
            done.set()
        elif method == "Target.attachedToTarget":
            schedule(setup(session, data))
        elif method == "Fetch.requestPaused":
            schedule(paused(session, data))
        elif method == "Page.frameNavigated" and web_observer is not None:
            web_observer.frame_navigated(session, data.get("frame", {}))
        elif method == "Network.requestWillBeSent" and web_observer is not None:
            web_observer.network_request(session, data)
        elif method == "Runtime.exceptionThrown":
            runtime_diagnostics.observe_exception(data)
        elif method in {"Browser.downloadWillBegin", "Page.downloadWillBegin"}:
            if purpose == "web":
                result.outcome, result.reason_code = "failed", "unsupported_download_response"
                if web_observer is not None:
                    web_observer.download_not_captured(method)
            else:
                errors.append(FxfetchError("browser_download_not_intercepted", "Native/blob download was denied"))
            done.set()

    async def navigate(session: str) -> None:
        response = await send(session, "Page.navigate", {"url": entry_url})
        if response.get("errorText") and not receiving.locked() and not result.artifacts:
            raise FxfetchError("browser_navigation_failed", "Browser navigation failed")

    async def follow_disclosed_links(pages: list[Page]) -> bool:
        """Follow explicit file hrefs or bounded literal content-page GET URLs.

        Hidden programmatic anchors are data, not forced click targets. Neither
        page functions nor source-code URL guesses are executed by this path.
        """
        nonlocal interactions, last_activity
        found: dict[str, tuple[Candidate, Frame]] = {}
        content_found: dict[str, tuple[Candidate, Frame]] = {}
        page_challenges: list[tuple[str, str]] = []
        scanned = 0
        for page in pages:
            if page.is_closed():
                continue
            for frame in page.frames:
                check()
                source = frame.url
                if source.partition("#")[0] not in successful_documents:
                    continue
                observed = await controlled(frame.evaluate(
                    OBSERVE_PACKAGE_LINKS,
                    {"links": limits.max_candidates - scanned, "bytes": limits.max_body_bytes},
                ))
                candidates, challenge_reason = observed_package_candidates(observed, source, chain)
                if challenge_reason:
                    page_challenges.append((source, challenge_reason))
                scanned += len(observed["links"])
                for candidate in candidates:
                    found.setdefault(candidate.url, (candidate, frame))
                if not candidates and observed.get("ready") == "complete" and (
                    challenge_reason or followed_script_content
                ):
                    for candidate in script_content_candidates(
                        observed["html"], source, observed.get("base", source), limits.max_candidates,
                    ):
                        content_found.setdefault(candidate.url, (candidate, frame))
                    if len(content_found) > limits.max_candidates:
                        raise FxfetchError("candidate_limit", "Script content candidate limit exceeded")
        if not found:
            found = content_found
        continuation = "blocked"
        if found:
            continuation = ("explicit_script_content_link" if next(iter(found.values()))[0].action == "script_content_link"
                            else "explicit_dom_package_link")
        for source, reason in page_challenges:
            key = (source, reason)
            if key not in observed_page_challenges:
                code = "page_device_verification_observed" if reason == "device_verification_required" else "page_challenge_observed"
                observed_page_challenges[key] = code
                result.responses.append({
                    "url": source, "resource_type": "Document", "page_observation": code,
                    "reason_code": reason, "verification": "not_established",
                })
                emit("challenge_detected", source, reason_code=reason, verification_passed=False,
                     continuation=continuation)
        if not found and page_challenges:
            raise FxfetchError(page_challenges[0][1], "Observed page gate without a disclosed continuation", outcome="blocked")
        if not found:
            return False
        for candidate, _ in found.values():
            if not any(item.url == candidate.url for item in result.candidates):
                result.candidates.append(candidate)
                emit("download_candidate", candidate.url, verified=False, source=candidate.action)
        if len(found) > 1:
            result.selection_candidates = [candidate for candidate, _ in found.values()]
            raise FxfetchError("candidate_selection_required", "Several disclosed links need selection")
        candidate, frame = next(iter(found.values()))
        content_link = candidate.action == "script_content_link"
        if content_link and candidate.url.partition("#")[0] in {
            *followed_script_content, candidate.source_url.partition("#")[0], entry_url.partition("#")[0],
        }:
            raise FxfetchError("browser_content_loop", "Disclosed content navigation would repeat a page")
        if candidate.url in followed_dom_packages:
            return True  # Never replay an already attempted file ticket via a button.
        if interactions >= 4:
            raise FxfetchError("interaction_limit", "Download interaction budget exhausted")
        # The existing connection-time public guard still runs for every actual
        # request and redirect. Validate this selected navigation before dispatch too.
        validate_url(candidate.url)
        await snapshot_and_qr(pages, scan_qr=False, dom_package_sources={candidate.source_url})
        if content_link:
            followed_script_content.add(candidate.source_url.partition("#")[0])
            followed_script_content.add(candidate.url.partition("#")[0])
            script_content_targets.add(candidate.url)
        else:
            followed_dom_packages.add(candidate.url)
        interactions += 1
        emit("download_action", candidate.source_url, action_number=interactions, action="navigate")
        emit("redirect", candidate.source_url, from_url=candidate.source_url, to_url=candidate.url,
             mechanism=candidate.action, same_browser_session=True)
        try:
            await controlled(frame.goto(candidate.url, wait_until="commit",
                                        timeout=1000 * min(10, limits.read_timeout, max(0.001, deadline-time.monotonic()))))
        except PlaywrightError:
            if not receiving.locked() and not result.artifacts and not errors:
                raise
        last_activity = time.monotonic()
        progress.action()
        return True

    async def scan_actions(pages: list[Page], handles: list[ElementHandle]) -> None:
        nonlocal interactions, last_activity
        candidates: dict[tuple[str, str, str], ElementHandle] = {}
        hrefs: dict[tuple[str, str, str], str] = {}
        labels: dict[tuple[str, str, str], str] = {}
        sources: dict[tuple[str, str, str], str] = {}
        scanned = 0
        for page in pages:
            check()
            if page.is_closed() or urlsplit(page.url).scheme not in {"http", "https"}:
                continue
            for frame in page.frames:
                check()
                # Freeze the current nodes, not just their count. Reactive pages
                # can replace the entire tree between sequential CDP operations;
                # nth(index) would wait for an index that no longer exists.
                selector = frame.locator(_INTERACTIVE_CONTROLS)
                if await controlled(selector.count()) > limits.max_candidates - scanned:
                    raise FxfetchError("candidate_limit", "Browser interactive-element budget exhausted")
                elements = await controlled(selector.element_handles())
                handles.extend(elements)
                scanned += len(elements)
                if scanned > limits.max_candidates:
                    raise FxfetchError("candidate_limit", "Browser interactive-element budget exhausted")
                for index, item in enumerate(elements):
                    check()
                    metadata = await controlled(item.evaluate(
                        """(e, selectors) => {
                            if (!e.isConnected) return null;
                            const text=e.innerText||e.value||e.getAttribute('aria-label')||e.querySelector('img')?.alt||'';
                            const extra=!e.matches(selectors.semantic);
                            return {
                            text:text.slice(0,256),longLabel:text.length>256,extra,
                            nested:extra && [...e.querySelectorAll(selectors.all)].some(c=>(c.innerText||c.value||c.getAttribute('aria-label')||'').trim()),
                            href:e.getAttribute('href')||'',resolved:typeof e.href==='string'?e.href:'',
                            attrs:Object.fromEntries(['class','id','download'].filter(k=>e.hasAttribute(k)).map(k=>[k,e.getAttribute(k)])),
                            form:!!e.closest('form')
                        }}""",
                        {"semantic": _SEMANTIC_CONTROLS, "all": _INTERACTIVE_CONTROLS},
                    ))
                    if metadata is None:
                        continue
                    label, href = metadata["text"], metadata["href"]
                    if metadata["form"] or _BUSINESS_TEXT.search(label):
                        continue
                    if metadata["extra"] and (metadata["longLabel"] or metadata["nested"]):
                        continue
                    mismatch = (chain == "android" and re.search(r"iphone|ios|ipa|苹果", label, re.I)) or (
                        chain == "iphone" and re.search(r"android|apk|安卓", label, re.I)
                    )
                    try:
                        parsed_href = urlsplit(href)
                    except ValueError:
                        continue
                    action = download_action(label, href, metadata["attrs"], require_short=metadata["extra"])
                    if mismatch or not (action or (not metadata["extra"] and
                                                   parsed_href.path.lower().endswith((".apk", ".ipa")))):
                        continue
                    if href and parsed_href.scheme not in {"", "http", "https", "javascript"}:
                        continue
                    # Resolve with the browser's baseURI and collapse repeated links
                    # to one actual destination. Retain the node for a normal
                    # in-session click, including its handlers, cookies and popup.
                    resolved = metadata["resolved"] if href and not href.startswith("#") and parsed_href.scheme != "javascript" else ""
                    if resolved and resolved.partition("#")[0] == frame.url.partition("#")[0]:
                        continue
                    identity = ("href", "", resolved) if resolved else (frame.url, label, f"button-index:{index}")
                    if identity not in clicked and await controlled(item.is_visible()) and await controlled(item.is_enabled()):
                        candidates.setdefault(identity, item)
                        hrefs[identity] = resolved
                        labels[identity] = label
                        sources[identity] = frame.url
        if len(candidates) > 1:
            for identity in candidates:
                href = hrefs[identity]
                if not href or urlsplit(href).scheme not in {"", "http", "https"}:
                    result.gaps.append("interaction_selection_unavailable")
                    continue
                parsed = classify_input(href)
                if parsed.request_url is not None and parsed.kind not in {"store", "unsupported"}:
                    candidate = Candidate(
                        parsed.request_url,
                        parsed.kind,
                        sources[identity],
                        label=labels[identity],
                        action="download_link",
                    )
                    if not any(item.url == candidate.url for item in result.candidates):
                        result.candidates.append(candidate)
                    if not any(item.url == candidate.url for item in result.selection_candidates):
                        result.selection_candidates.append(candidate)
            raise FxfetchError(
                "candidate_selection_required", "Several distinct download actions need selection"
            )
        if candidates:
            if interactions >= 4:
                raise FxfetchError("interaction_limit", "Download interaction budget exhausted")
            identity, item = next(iter(candidates.items()))
            interactions += 1
            emit("download_action", sources[identity], action_number=interactions, action="click")
            try:
                await controlled(item.click(
                    timeout=1000 * min(10, limits.read_timeout, max(0.001, deadline - time.monotonic())),
                    no_wait_after=True,
                ))
            except (PlaywrightError, FxfetchError) as error:
                if not cancel.is_set():
                    await write_click_state(item, output_dir, deadline=deadline)
                if "not attached to the DOM" in str(error):
                    return
                raise
            clicked.add(identity)
            last_activity = time.monotonic()
            progress.action()

    async def interact(pages: list[Page]) -> None:
        handles: list[ElementHandle] = []
        try:
            await scan_actions(pages, handles)
        finally:
            # Do not retain detached DOM trees across repeated scans. Disposal is
            # bounded separately so a stopped renderer cannot delay task expiry.
            try:
                await asyncio.wait_for(
                    asyncio.gather(*(handle.dispose() for handle in handles)), timeout=0.5
                )
            except (PlaywrightError, TimeoutError) as error:
                write_capture_diagnostic(output_dir, error, "element_cleanup")

    def saved_resource(url: str) -> Path | None:
        for _ in range(limits.max_redirects + 1):
            if url in resources:
                return resources[url]
            if url not in resource_aliases:
                return None
            url = resource_aliases[url]
        return None

    async def snapshot_and_qr(
        pages: list[Page], *, scan_qr: bool = True, dom_package_sources: set[str] | None = None
    ) -> None:
        nonlocal body_bytes, qr_count, qr_bytes, qr_seconds, interactions, last_activity
        page_for_candidate: dict[str, Page] = {}
        for page in pages:
            check()
            source = page.url
            if page.is_closed() or source.partition("#")[0] not in successful_documents:
                continue
            # Return only bounded markup over CDP. This serializes an observed DOM;
            # it does not fetch any missing image, stylesheet or iframe.
            text = await controlled(page.evaluate(
                "maximum => {const s=document.documentElement?.outerHTML||''; return new TextEncoder().encode(s).length<=maximum?s:null;}",
                limits.max_body_bytes,
            ))
            if text is None:
                result.gaps.append("browser_dom_limit")
                continue
            data = str(text).encode("utf-8")
            visible = await controlled(page.evaluate(
                "maximum => (document.body?.innerText||'').slice(0,maximum)",
                limits.max_body_bytes,
            ))
            gate_rejected = device_gate_rejected(str(text), str(visible))
            challenge_detected = purpose == "web" and rendered_challenge(str(text), str(visible))
            digest = hashlib.sha256(data).hexdigest()
            check()
            if source not in snapshots or snapshots[source][1] != digest:
                if len(snapshots) >= 8 or len(data) > limits.max_task_bytes - body_bytes:
                    result.gaps.append("browser_dom_limit")
                    continue
                if web_observer is not None:
                    path = web_observer.snapshot_path(output_dir, digest)
                else:
                    path = output_dir / "web" / f"dom-{digest}.html"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                body_bytes += len(data)
                snapshots[source] = (path, digest)
                progress.content(source, digest, document=True)
                result.bodies.append(
                    {
                        "url": source,
                        "path": str(path),
                        "size": len(data),
                        "sha256": digest,
                        "chain": chain,
                        "purpose": "browser_rendered_dom",
                        "complete": True,
                        "hash_scope": "serialized_dom",
                        "content_type": "text/html; charset=utf-8",
                    }
                )
                if web_observer is not None:
                    result.bodies[-1]["representation"] = "browser_rendered_dom"
                    result.bodies[-1]["request_ref"] = None
                    web_observer.snapshot_saved(
                        url=source,
                        path=path.relative_to(journal.path.parent if journal is not None else output_dir).as_posix(),
                        size=len(data),
                        sha256=digest,
                    )
                elif journal is not None:
                    record_saved_material(
                        journal,
                        source_url=source,
                        path=path.relative_to(journal.path.parent).as_posix(),
                        size=len(data),
                        sha256=digest,
                        representation="browser_rendered_dom",
                        complete=True,
                    )
            if web_observer is not None and (gate_rejected or challenge_detected):
                snapshot_session = await controlled(page.context.new_cdp_session(page))
                try:
                    target_info = await controlled(snapshot_session.send("Target.getTargetInfo"))
                finally:
                    await controlled(snapshot_session.detach())
                web_observer.challenge_snapshot(
                    source,
                    "device_verification_required" if gate_rejected else "challenge_detected",
                    target_id=target_info.get("targetInfo", {}).get("targetId"),
                )
            if gate_rejected and purpose != "web":
                snapshots.pop(source, None)
                if source not in (dom_package_sources or set()):
                    raise FxfetchError(
                        "device_verification_required",
                        "Observed device verification rejection; protected content was not requested",
                        outcome="blocked",
                    )
            if not scan_qr:
                continue
            images = discover_images(data, source, content_type="text/html; charset=utf-8")
            check()
            qr_gaps.extend(gap for gap in images.gaps if gap not in qr_gaps)
            for reference in images.images:
                check()
                if reference.skip_reason:
                    continue
                image_path = saved_resource(reference.url) if reference.url else None
                if reference.data is not None:
                    image_digest = hashlib.sha256(reference.data).hexdigest()
                    check()
                    if image_digest in seen_qr:
                        continue
                    if len(reference.data) > min(
                        limits.max_image_bytes, MAX_IMAGE_TOTAL - qr_bytes, limits.max_task_bytes - body_bytes
                    ):
                        qr_gaps.append("page_qr_image_limit")
                        continue
                    image_path = output_dir / "web" / f"inline-{image_digest}.image"
                    image_path.write_bytes(reference.data)
                    body_bytes += len(reference.data)
                    result.bodies.append(
                        {
                            "url": source,
                            "path": str(image_path),
                            "size": len(reference.data),
                            "sha256": image_digest,
                            "chain": chain,
                            "purpose": "page_qr_inline",
                            "complete": True,
                            "hash_scope": "decoded_inline_image",
                        }
                    )
                if image_path is None:
                    if "page_qr_image_not_captured" not in qr_gaps:
                        qr_gaps.append("page_qr_image_not_captured")
                    continue
                image_data = image_path.read_bytes()
                image_digest = hashlib.sha256(image_data).hexdigest()
                if image_digest in seen_qr:
                    for candidate in result.candidates:
                        if candidate.source_url == source:
                            page_for_candidate[candidate.url] = page
                    continue
                if (
                    qr_count >= MAX_IMAGES
                    or qr_bytes + len(image_data) > MAX_IMAGE_TOTAL
                    or qr_seconds >= MAX_DECODE_SECONDS
                ):
                    qr_gaps.append("page_qr_scan_limit")
                    continue
                seen_qr.add(image_digest)
                qr_count += 1
                qr_bytes += len(image_data)
                started = time.monotonic()
                decoded = await asyncio.to_thread(
                    decode_saved_image,
                    image_path,
                    replace(
                        limits,
                        image_timeout=min(
                            limits.image_timeout,
                            MAX_DECODE_SECONDS - qr_seconds,
                            max(0.01, deadline - started),
                        ),
                    ),
                )
                qr_seconds += time.monotonic() - started
                check()
                qr_sources.append(
                    {
                        "page_url": source,
                        "image_url": reference.url,
                        "image_index": reference.index,
                        "path": str(image_path),
                        "sha256": image_digest,
                        "decode": asdict(decoded),
                    }
                )
                if decoded.status not in {"decoded", "no_code", "no_supported_url"} or decoded.truncated:
                    qr_gaps.append("page_qr_" + (decoded.reason_code or decoded.status))
                for code in decoded.candidates:
                    if code.url is None or code.kind != "http_url":
                        continue
                    parsed = classify_input(code.text)
                    if parsed.request_url is None or parsed.kind in {"store", "unsupported"}:
                        continue
                    candidate = Candidate(parsed.request_url, parsed.kind, source, action="page_qr")
                    if not any(item.url == candidate.url for item in result.candidates):
                        result.candidates.append(candidate)
                    page_for_candidate[candidate.url] = page
                    emit("download_candidate", candidate.url, verified=False, source="page_qr")
        if not scan_qr:
            return
        result.page_qr = {
            "status": "partial" if qr_gaps else "decoded" if result.candidates else "no_supported_url",
            "sources": qr_sources,
            "gaps": list(dict.fromkeys(qr_gaps)),
            "candidates": [asdict(candidate) for candidate in result.candidates],
        }
        pending = [candidate for candidate in result.candidates if candidate.url not in followed_qr]
        if len(pending) > 1:
            result.selection_candidates = pending
            raise FxfetchError("candidate_selection_required", "Multiple page QR targets need selection")
        if pending and not qr_gaps:
            candidate = pending[0]
            page = page_for_candidate.get(candidate.url)
            if page is not None:
                if interactions >= 4:
                    raise FxfetchError("interaction_limit", "QR navigation budget exhausted")
                interactions += 1
                followed_qr.add(candidate.url)
                emit(
                    "redirect",
                    candidate.source_url,
                    from_url=candidate.source_url,
                    to_url=candidate.url,
                    mechanism="page_qr",
                    same_browser_session=True,
                )
                try:
                    await page.goto(
                        candidate.url,
                        wait_until="commit",
                        timeout=min(3000, max(100, (deadline - time.monotonic()) * 1000)),
                    )
                except PlaywrightError:
                    if not receiving.locked() and not result.artifacts and not errors:
                        raise
                last_activity = time.monotonic()
                progress.action()

    def build_offline() -> None:
        if result.artifacts or not snapshots:
            return
        source, (path, _) = next(reversed(snapshots.items()))
        available = dict(resources)
        for alias in resource_aliases:
            target = saved_resource(alias)
            if target is not None:
                available[alias] = target
        bundle = OfflineBundle(limits).build(
            path,
            source,
            available,
            output_dir / "offline" / "site",
            max_bytes=max(0, limits.max_task_bytes - body_bytes),
            html_content_type="text/html; charset=utf-8",
        )
        result.offline = asdict(bundle)
        result.offline["source_url"] = source
        result.offline["reasons"] = list(dict.fromkeys([*bundle.reasons, *result.gaps, *qr_gaps]))

    try:
        check()
        async with async_playwright() as playwright:
            if proof.cdp_endpoint is None:
                context = await playwright.chromium.launch_persistent_context(
                    str(proof.profile_root),
                    executable_path=str(proof.executable_path),
                    headless=proof.headless,
                    accept_downloads=False,
                    service_workers="block",
                    proxy={"server": proof.proxy_server},
                    timeout=min(30_000, limits.chain_timeout * 1000),
                    args=[
                        "--remote-debugging-port=0",
                        "--remote-debugging-address=127.0.0.1",
                        "--disable-background-networking",
                        "--disable-quic",
                        "--disable-sync",
                        "--no-first-run",
                        "--disable-component-update",
                        *proof.extra_args,
                    ],
                )
                browser = context.browser
                endpoint = resolve_endpoint(proof.profile_root, None)
            else:
                endpoint = await asyncio.to_thread(resolve_endpoint, proof.profile_root, proof.cdp_endpoint)
                browser = await playwright.chromium.connect_over_cdp(
                    endpoint, no_defaults=True, timeout=min(30_000, limits.chain_timeout * 1000)
                )
                if len(browser.contexts) != 1:
                    raise FxfetchError(
                        "browser_context_ambiguous", "Lease must expose one isolated Chrome context"
                    )
                context = browser.contexts[0]
            if browser is None:
                raise FxfetchError("browser_cdp_failed", "Chrome connection unavailable")

            def denied_download(_: object) -> None:
                errors.append(
                    FxfetchError("browser_download_not_intercepted", "Native/blob download was denied")
                )
                done.set()

            def observe_page(page: Page) -> None:
                page.on("download", denied_download)

            context.on("page", observe_page)
            for existing_page in context.pages:
                observe_page(existing_page)

            async def hold_until_attached(route: Route) -> None:
                # Playwright installs context routing before resuming new pages.
                # This also holds a popup's first request until our independent
                # CDP response interceptor is ready. It is NOT the network guard.
                try:
                    while True:
                        check()
                        if mux is not None:
                            targets = await send(None, "Target.getTargets")
                            if any(target.get("type") in _UNSUPPORTED_TARGETS for target in targets["targetInfos"]):
                                result.gaps.append("browser_worker_scope_unsupported")
                                raise FxfetchError("browser_worker_scope_unsupported", "Worker request cannot leave verified page scope")
                            relevant = [
                                target["targetId"]
                                for target in targets["targetInfos"]
                                if target.get("type") in {"page", "iframe"}
                            ]
                            if all(target in ready for target in relevant):
                                break
                        await asyncio.sleep(0.025)
                    await route.continue_()
                except (FxfetchError, PlaywrightError) as error:
                    errors.append(
                        error
                        if isinstance(error, FxfetchError)
                        else FxfetchError("browser_route_failed", "Chrome route continuation failed")
                    )
                    done.set()

            # Playwright deliberately aborts implicit favicon requests when they
            # match context routing. They do not execute script; leave their
            # Fetch interception intact without adding this attachment barrier.
            await context.route(re.compile(r"^(?!.*\/favicon\.ico(?:[?#].*)?$).+", re.I), hold_until_attached)
            try:
                mux = await CDPMux.connect(endpoint, event, check, limits.read_timeout)
                try:
                    await send(
                        None, "Browser.setDownloadBehavior", {"behavior": "deny", "eventsEnabled": True}
                    )
                except FxfetchError as error:
                    if error.code != "browser_cdp_failed":
                        raise
                    raise FxfetchError(
                        "browser_download_guard_unavailable", "Chrome does not accept native download denial"
                    ) from error
                await send(
                    None,
                    "Target.setAutoAttach",
                    {
                        "autoAttach": True,
                        "waitForDebuggerOnStart": True,
                        "flatten": True,
                        "filter": [{"type": kind} for kind in ["page", *sorted(_UNSUPPORTED_TARGETS)]] + [{"exclude": True}],
                    },
                )
                if proof.cdp_endpoint is None:
                    created = await send(None, "Target.createTarget", {"url": "about:blank"})
                else:
                    # Android does not promise desktop Target.createTarget.
                    # Its isolated lease must prepare exactly one blank tab.
                    listed = await send(None, "Target.getTargets")
                    blanks = [
                        target
                        for target in listed["targetInfos"]
                        if target.get("type") == "page" and target.get("url") == "about:blank"
                    ]
                    if len(blanks) != 1:
                        raise FxfetchError(
                            "browser_blank_target_unavailable",
                            "Remote Chrome requires exactly one prepared blank tab",
                        )
                    created = {"targetId": blanks[0]["targetId"]}
                while created["targetId"] not in ready:
                    check()
                    if errors:
                        raise errors[0]
                    try:
                        await asyncio.wait_for(target_ready.wait(), timeout=0.1)
                    except TimeoutError:
                        continue
                    target_ready.clear()
                entry_session = ready[created["targetId"]]
                entry_tree = await send(entry_session, "Page.getFrameTree")
                entry_frame = entry_tree.get("frameTree", {}).get("frame", {})
                if web_observer is not None:
                    web_observer.set_entry_identity(entry_session, entry_frame.get("id"))
                schedule(navigate(entry_session))
                last_scan = time.monotonic()
                last_snapshot = 0.0
                while not done.is_set():
                    check()
                    now = time.monotonic()
                    if not receiving.locked() and now - last_scan >= 0.5 and now - last_activity >= 0.3:
                        try:
                            if purpose == "web":
                                if now - last_snapshot >= 1:
                                    await snapshot_and_qr(context.pages, scan_qr=False)
                                    last_snapshot = now
                            else:
                                followed_package = await follow_disclosed_links(context.pages)
                                if not followed_package:
                                    await interact(context.pages)
                                if not followed_package and now - last_snapshot >= 1 and not receiving.locked():
                                    await snapshot_and_qr(context.pages)
                                    last_snapshot = now
                        except PlaywrightError as error:
                            if "destroyed" not in str(error) and "detached" not in str(error):
                                raise
                        last_scan = now
                    if not receiving.locked() and now - last_activity >= 5:
                        break
                    if not receiving.locked() and progress.stalled(time.monotonic(), MAX_NO_PROGRESS_SECONDS):
                        result.gaps.append("browser_no_progress")
                        break
                    await asyncio.sleep(0.05)
                if errors and not result.artifacts:
                    raise errors[0]
                if purpose != "web" and deferred_resource_errors and not result.artifacts:
                    raise next(
                        (error for error in deferred_resource_errors if error.outcome == "blocked"),
                        deferred_resource_errors[0],
                    )
            finally:
                if (purpose == "web" or not result.artifacts) and not cancel.is_set() and deadline - time.monotonic() > 0.5:
                    try:
                        await asyncio.wait_for(snapshot_and_qr(context.pages, scan_qr=False), timeout=0.5)
                    except (FxfetchError, PlaywrightError, TimeoutError, OSError):
                        result.gaps.append("browser_final_dom_unavailable")
                if purpose != "web" and not result.artifacts and snapshots:
                    try:
                        build_offline()
                    except (FxfetchError, OSError) as error:
                        result.offline = {
                            "available": False,
                            "coverage": "partial",
                            "reasons": [
                                error.code if isinstance(error, FxfetchError) else "offline_storage_failed",
                            ],
                        }
                for task in tuple(tasks):
                    task.cancel()
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                if mux is not None:
                    await mux.close()
                # Remote process teardown belongs to the independent lease.
                if proof.cdp_endpoint is None:
                    await context.close()
                else:
                    await browser.close()
        if purpose == "web" and web_observer is not None:
            result.outcome, result.reason_code = web_observer.final_outcome(
                result.outcome, result.reason_code
            )
    except FxfetchError as error:
        if error.code == "browser_cdp_failed":
            write_capture_diagnostic(output_dir, error, "cdp")
        if not result.artifacts:
            result.outcome, result.reason_code = error.outcome, error.code
    except (PlaywrightError, TimeoutError, OSError, ValueError) as error:
        write_capture_diagnostic(output_dir, error, "capture")
        if not result.artifacts:
            result.reason_code = "browser_capture_failed"
    if web_observer is not None:
        result.gaps.extend(web_observer.gaps)
    result.gaps = list(dict.fromkeys([*result.gaps, *observed_page_challenges.values()]))
    return result
