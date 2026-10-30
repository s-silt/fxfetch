"""HTTP collector for standalone bounded web captures."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any

from .discovery import rendered_challenge
from .errors import FxfetchError
from .http_client import FetchedResponse, HttpClient
from .limits import Limits
from .network import build_default_client
from .web_journal import EvidenceJournal
from .web_materials import WebCaptureResult, file_metadata
from .workflow import ANDROID_UA

BODY_STATUSES_BLOCKED = {401, 403, 429}


@dataclass
class HttpObservation:
    last_attempt_ref: str | None = None
    last_response_ref: str | None = None
    last_response_url: str = ""
    response_status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)


def observe_transport(
    event: dict[str, object],
    *,
    state: HttpObservation,
    gaps: list[str],
    journal: EvidenceJournal,
) -> None:
    kind = event.get("kind")
    fields = {
        key: str(value) if key == "path" and isinstance(value, Path) else value
        for key, value in event.items()
        if key != "kind"
    }
    if kind == "tls_certificate_saved":
        try:
            fields["path"] = Path(str(fields["path"])).absolute().relative_to(
                journal.path.parent.absolute()
            ).as_posix()
        except (KeyError, TypeError, ValueError):
            gaps.append("tls_certificate_not_captured")
            journal.append("gap", {"code": "tls_certificate_not_captured",
                                   "reason_code": "tls_certificate_path_invalid",
                                   "request_ref": fields.get("request_ref")})
            return
    if kind == "request_attempted":
        reference = event.get("request_ref")
        if isinstance(reference, str):
            state.last_attempt_ref = reference
        journal.append("request_attempted", fields)
    elif kind == "response_observed":
        reference = event.get("request_ref")
        if isinstance(reference, str):
            state.last_response_ref = reference
        response_url = event.get("url")
        if isinstance(response_url, str):
            state.last_response_url = response_url
        status = event.get("status")
        if isinstance(status, int) and not isinstance(status, bool):
            state.response_status = status
        headers = event.get("headers")
        if isinstance(headers, dict):
            state.response_headers = headers
        if state.response_status in {301, 302, 303, 307, 308} and event.get("location_raw"):
            if "redirect_body_not_saved" not in gaps:
                gaps.append("redirect_body_not_saved")
        journal.append("response_observed", fields)
    elif kind == "gap":
        code = fields.get("code")
        gaps.append(code if isinstance(code, str) else "location_resolution_failed")
        journal.append("gap", fields)
    else:
        journal.append(str(kind or "transport_observation"), fields)


def _save_prefix(
    destination: Path,
    capture_dir: Path,
    result: WebCaptureResult,
    journal: EvidenceJournal,
    state: HttpObservation,
    maximum: int,
) -> None:
    partial = destination.with_name(destination.name + ".partial")
    if not partial.is_file():
        return
    try:
        material = file_metadata(
            partial,
            capture_dir,
            role="response_prefix",
            representation="http_saved_prefix",
            complete=False,
            source_url=state.last_response_url,
            request_ref=state.last_response_ref or state.last_attempt_ref,
            maximum=maximum,
        )
    except (FxfetchError, OSError):
        return
    result.materials.append(material)
    journal.append("response_prefix_saved", material)


def _classify_http_result(
    result: WebCaptureResult,
    fetched: FetchedResponse,
    *,
    material: dict[str, Any],
    content_type: str,
    state: HttpObservation,
    journal: EvidenceJournal,
    limits: Limits,
) -> None:
    result.materials.append(material)
    journal.append(
        "response_body_saved",
        {
            "request_ref": material["request_ref"],
            "url": fetched.url,
            "path": str(material["path"]),
            "size": material["size"],
            "sha256": material["sha256"],
            "representation": material["representation"],
            "complete": True,
        },
    )
    is_html = content_type in {"text/html", "application/xhtml+xml"}
    challenged = False
    if is_html and fetched.size <= limits.max_body_bytes:
        text = fetched.path.read_bytes().decode("utf-8", errors="replace")
        challenged = rendered_challenge(text, text)
    unsupported_download = material["role"] == "unsupported_download"
    if fetched.status in BODY_STATUSES_BLOCKED:
        result.outcome, result.reason_code = "blocked", "http_access_control"
    elif challenged:
        result.outcome, result.reason_code = "blocked", "challenge_detected"
        journal.append("challenge_detected", {"request_ref": state.last_response_ref, "url": fetched.url})
    elif fetched.status >= 400:
        result.outcome, result.reason_code = "failed", "http_status"
    elif unsupported_download:
        result.outcome, result.reason_code = "failed", "unsupported_download_response"
        result.gaps.append("non_web_response_saved")
    elif fetched.size == 0:
        result.outcome, result.reason_code = "failed", "http_body_missing"
    else:
        result.outcome, result.reason_code = "captured", "web_material_captured"


def collect_http(
    url: str,
    capture_dir: Path,
    result: WebCaptureResult,
    journal: EvidenceJournal,
    limits: Limits,
    cancel: threading.Event,
    client: HttpClient | None,
) -> None:
    result.gaps.extend(["js_not_executed", "subresources_not_collected", "interaction_not_performed"])
    journal.append("entry_navigation_attempted", {"url": url, "method": "GET", "collector": "http"})
    web_dir = capture_dir / "http"
    web_dir.mkdir()
    destination = web_dir / "response.body"
    transport = client or build_default_client(limits)
    state = HttpObservation(last_response_url=url)
    try:
        fetched: FetchedResponse = transport.fetch(
            url,
            destination,
            user_agent=ANDROID_UA,
            cookie_jar=CookieJar(),
            cancel=cancel,
            on_transport_event=lambda event: observe_transport(
                event, state=state, gaps=result.gaps, journal=journal
            ),
            package_streaming=False,
            body_limit_bytes=min(limits.max_body_bytes, limits.max_web_bytes, limits.max_task_bytes),
        )
        state.last_response_ref = state.last_response_ref or state.last_attempt_ref
        with fetched.path.open("rb") as stream:
            prefix = stream.read(4)
        content_type = fetched.headers.get("content-type", "").partition(";")[0].strip().lower()
        unsupported_download = content_type in {
            "application/vnd.android.package-archive",
            "application/x-itunes-ipa",
            "application/octet-stream",
            "application/zip",
        } or prefix in {b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"}
        material = file_metadata(
            fetched.path,
            capture_dir,
            role="unsupported_download" if unsupported_download else "response_body",
            representation="http_response_body",
            complete=True,
            source_url=fetched.url,
            request_ref=state.last_response_ref,
            maximum=limits.max_body_bytes,
        )
        _classify_http_result(
            result,
            fetched,
            material=material,
            content_type=content_type,
            state=state,
            journal=journal,
            limits=limits,
        )
    except (FxfetchError, OSError, ValueError) as error:
        reason = error.code if isinstance(error, FxfetchError) else "http_transport_failed"
        result.outcome = "blocked" if reason in {"http_access_control", "challenge_detected"} else "failed"
        result.reason_code = reason
        if state.response_status in BODY_STATUSES_BLOCKED:
            result.outcome, result.reason_code = "blocked", "http_access_control"
            result.gaps.append(reason)
        _save_prefix(
            destination,
            capture_dir,
            result,
            journal,
            state,
            limits.max_body_bytes,
        )
    finally:
        result.gaps.extend(
            gap for gap in ["js_not_executed", "subresources_not_collected", "interaction_not_performed"]
            if gap not in result.gaps
        )
        if state.response_status is not None:
            journal.append(
                "final_http_response",
                {
                    "request_ref": state.last_response_ref,
                    "url": state.last_response_url,
                    "status": state.response_status,
                    "headers": state.response_headers,
                },
            )
