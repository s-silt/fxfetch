"""Web-only browser observation state and journal projection."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from .browser_tls_evidence import utc_now
from .discovery import rendered_challenge
from .http_client import EVIDENCE_HEADERS, MAX_EVIDENCE_HEADER_BYTES
from .web_journal import EvidenceJournal


class BrowserWebEvidence:
    """Project factual CDP events without owning transport or permissions."""

    def __init__(
        self,
        *,
        journal: EvidenceJournal | None,
        event_context: dict[str, str] | None = None,
        tls_context: Callable[[str, str], dict[str, object]] | None = None,
    ) -> None:
        self.journal = journal
        self.event_context = event_context or {}
        self.tls_context = tls_context
        self.target_ids: dict[str, str] = {}
        self.request_refs: dict[tuple[str, str], str] = {}
        self.request_counts: dict[tuple[str, str], int] = {}
        self.entry_session: str | None = None
        self.entry_frame_id: str | None = None
        self.main_status: int | None = None
        self.main_body_captured = False
        self.main_package_stream = False
        self.main_challenge = False
        self.main_challenge_reason: str | None = None
        self.snapshot_counter = 0
        self.gaps: list[str] = []

    def journal_event(self, kind: str, **fields: object) -> None:
        session, url = fields.get("session_id"), fields.get("source_url", fields.get("url"))
        if self.tls_context is not None and isinstance(session, str) and isinstance(url, str) and "tls_verification" not in fields:
            fields.update(self.tls_context(session, url))
        if self.journal is not None:
            try:
                self.journal.append(kind, {**self.event_context, **fields})
            except Exception:
                self.journal.failed = True
                if "journal_write_failed" not in self.journal.gaps:
                    self.journal.gaps.append("journal_write_failed")

    def session_context(self, session: str) -> dict[str, object]:
        return {"session_id": session, "target_id": self.target_id(session)}

    def fetch_context(self, session: str, event: dict[str, Any]) -> dict[str, object]:
        request_id = event["requestId"]
        return {
            **self.session_context(session),
            "request_ref": self.request_ref(session, request_id),
            "fetch_request_id": request_id,
            "network_id": event.get("networkId"),
            "frame_id": event.get("frameId"),
            "resource_type": event.get("resourceType"),
        }

    def target_id(self, session: str) -> str | None:
        return self.target_ids.get(session)

    def target_attached(self, session: str, target: dict[str, Any]) -> None:
        target_id = target.get("targetId")
        if isinstance(target_id, str):
            self.target_ids[session] = target_id
        self.journal_event(
            "target_attached",
            session_id=session,
            target_id=target_id,
            target_type=target.get("type"),
            url=target.get("url") if isinstance(target.get("url"), str) else None,
        )

    def initial_frame(self, session: str, frame: dict[str, Any]) -> None:
        self.journal_event(
            "frame_navigated",
            **self.session_context(session),
            frame_id=frame.get("id"),
            parent_frame_id=frame.get("parentId"),
            loader_id=frame.get("loaderId"),
            url=frame.get("url") if isinstance(frame.get("url"), str) else None,
            observation="initial_frame_tree",
        )

    def set_entry_identity(self, session: str, frame_id: str | None) -> None:
        self.entry_session = session
        self.entry_frame_id = frame_id

    def is_main_request(self, session: str, event: dict[str, Any]) -> bool:
        return (
            session == self.entry_session
            and event.get("resourceType") == "Document"
            and isinstance(event.get("frameId"), str)
            and event.get("frameId") == self.entry_frame_id
        )

    def begin_request(self, session: str, event: dict[str, Any]) -> str:
        request_id = event["requestId"]
        key = (session, request_id)
        sequence = self.request_counts.get(key, 0) + 1
        self.request_counts[key] = sequence
        request_ref = f"browser:{session}:{request_id}"
        if sequence > 1:
            request_ref = f"{request_ref}:{sequence}"
        self.request_refs[key] = request_ref
        redirected_id = event.get("redirectedRequestId")
        self.journal_event(
            "request_attempted",
            **self.fetch_context(session, event),
            redirected_request_id=redirected_id,
            redirected_request_ref=(
                self.request_refs.get((session, redirected_id))
                if isinstance(redirected_id, str)
                else None
            ),
            url=event["request"]["url"],
            method=event["request"].get("method", "GET"),
            stage="Fetch.request",
            permitted=False,
        )
        if self.is_main_request(session, event):
            self.main_status = None
            self.main_body_captured = False
            self.main_challenge = False
            self.main_challenge_reason = None
        return request_ref

    def record_unsupported_request(self, session: str, event: dict[str, Any]) -> str:
        request_ref = f"browser:{session}:{event['requestId']}"
        self.journal_event(
            "request_attempted",
            **self.session_context(session),
            request_ref=request_ref,
            fetch_request_id=event["requestId"],
            url=event["request"]["url"],
            method=event["request"].get("method", "GET"),
            stage="Fetch.request",
            permitted=False,
        )
        self.journal_event(
            "request_denied",
            **self.session_context(session),
            request_ref=request_ref,
            reason_code="unsupported_browser_protocol",
        )
        return request_ref

    def record_request_denied(self, session: str, request_ref: str, *, url: str | None = None, reason: str) -> None:
        self.journal_event(
            "request_denied",
            **self.session_context(session),
            request_ref=request_ref,
            url=url,
            reason_code=reason,
        )

    def record_request_permitted(self, session: str, request_ref: str, network_id: object, *, url: str | None = None) -> None:
        self.journal_event(
            "request_permitted",
            **self.session_context(session),
            request_ref=request_ref,
            network_id=network_id if isinstance(network_id, str) else None,
            permitted=True,
            **({"url": url} if url is not None else {}),
        )

    def request_ref(self, session: str, request_id: str) -> str | None:
        return self.request_refs.get((session, request_id))

    def response_error(
        self,
        session: str,
        event: dict[str, Any],
        optional: bool,
    ) -> dict[str, object]:
        url = event["request"]["url"]
        request_ref = self.request_ref(session, event["requestId"])
        self.journal_event(
            "response_error_observed",
            **self.fetch_context(session, event),
            url=url,
            error_reason=event["responseErrorReason"],
        )
        response = {
            "url": url,
            "network_error": event["responseErrorReason"],
            "resource_type": event.get("resourceType", ""),
            "optional_resource_failure": optional,
        }
        response.update(
            session_id=session,
            target_id=self.target_id(session),
            request_ref=request_ref,
            frame_id=event.get("frameId"),
        )
        return response

    def response_observed(
        self,
        session: str,
        event: dict[str, Any],
        headers: dict[str, str],
        status: int,
        request_number: int | None,
    ) -> tuple[dict[str, object], bool, dict[str, str]]:
        url = event["request"]["url"]
        request_ref = self.request_ref(session, event["requestId"])
        frame_id = event.get("frameId")
        safe_headers = {
            key: value for key, value in headers.items() if key in EVIDENCE_HEADERS
        }
        if sum(len(key.encode("utf-8")) + len(value.encode("utf-8")) for key, value in safe_headers.items()) > MAX_EVIDENCE_HEADER_BYTES:
            safe_headers = {}
            self.gaps.append("browser_response_headers_omitted")
        response: dict[str, object] = {
            "url": url,
            "status": status,
            "content_type": headers.get("content-type", ""),
            "request_id": request_number,
            "resource_type": event.get("resourceType", ""),
            "session_id": session,
            "target_id": self.target_id(session),
            "request_ref": request_ref,
            "network_id": event.get("networkId"),
            "frame_id": frame_id,
            "method": event["request"].get("method", "GET"),
        }
        location_raw = headers.get("location")
        observed_at = utc_now()
        response["observed_at"] = observed_at
        self.journal_event(
            "response_observed",
            **self.fetch_context(session, event),
            url=url,
            method=event["request"].get("method", "GET"),
            status=status,
            observed_at=observed_at,
            headers=safe_headers,
            location_raw=location_raw,
            location_resolved=urljoin(url, location_raw) if location_raw else None,
        )
        is_main = self.is_main_request(session, event)
        if is_main:
            self.main_status = status
        return response, is_main, safe_headers

    def record_redirect(self, session: str, event: dict[str, Any], location_raw: str) -> None:
        url = event["request"]["url"]
        self.gaps.append("redirect_body_not_saved")
        self.journal_event(
            "redirect_observed",
            **self.session_context(session),
            request_ref=self.request_ref(session, event["requestId"]),
            from_url=url,
            location_raw=location_raw,
            resolved_target=urljoin(url, location_raw),
            mechanism="http",
        )

    def unsupported_download(self, session: str, event: dict[str, Any], status: int) -> None:
        self.journal_event(
            "unsupported_download_response",
            **self.session_context(session),
            request_ref=self.request_ref(session, event["requestId"]),
            url=event["request"]["url"],
            status=status,
            resource_type=event.get("resourceType"),
            body_captured=False,
        )
        self.gaps.append("unsupported_download_body_not_captured")

    def body_saved(
        self,
        session: str,
        event: dict[str, Any],
        *,
        path: str,
        size: int,
        sha256: str,
        representation: str,
        complete: bool,
        body_text: str | None = None,
        package_stream: bool = False,
    ) -> None:
        url = event["request"]["url"]
        request_ref = self.request_ref(session, event["requestId"])
        self.journal_event(
            "response_body_saved" if complete else "response_prefix_saved",
            **self.session_context(session),
            request_ref=request_ref,
            url=url,
            path=path,
            size=size,
            sha256=sha256,
            representation=representation,
            complete=complete,
            resource_type=event.get("resourceType"),
            package_stream=package_stream,
        )
        if package_stream:
            if "package_body_not_included" not in self.gaps:
                self.gaps.append("package_body_not_included")
            if self.is_main_request(session, event):
                self.main_package_stream = True
            return
        if complete and size > 0 and self.is_main_request(session, event):
            self.main_body_captured = True
            if body_text is not None and rendered_challenge(body_text, body_text):
                self.main_challenge = True

    def record_response_prefix(
        self,
        session: str,
        event: dict[str, Any],
        *,
        path: str,
        size: int,
        sha256: str,
        representation: str,
        package_stream: bool = False,
    ) -> None:
        self.body_saved(
            session,
            event,
            path=path,
            size=size,
            sha256=sha256,
            representation=representation,
            complete=False,
            package_stream=package_stream,
        )

    def subresource_http_error(self, session: str, event: dict[str, Any], status: int) -> None:
        self.gaps.append("subresource_http_error")
        self.journal_event(
            "subresource_http_error",
            **self.fetch_context(session, event),
            url=event["request"]["url"],
            status=status,
        )

    def frame_navigated(self, session: str, frame: dict[str, Any]) -> None:
        self.journal_event(
            "frame_navigated",
            **self.session_context(session),
            frame_id=frame.get("id"),
            parent_frame_id=frame.get("parentId"),
            loader_id=frame.get("loaderId"),
            url=frame.get("url") if isinstance(frame.get("url"), str) else None,
        )

    def network_request(self, session: str, data: dict[str, Any]) -> None:
        request = data.get("request", {})
        initiator = data.get("initiator", {})
        initiator_fields: dict[str, object] = {}
        if isinstance(initiator, dict):
            if isinstance(initiator.get("type"), str):
                initiator_fields["type"] = initiator["type"]
            stack = initiator.get("stack")
            if isinstance(stack, dict) and isinstance(stack.get("callFrames"), list):
                initiator_fields["stack"] = [
                    {"url": frame.get("url"), "line_number": frame.get("lineNumber")}
                    for frame in stack["callFrames"][:16]
                    if isinstance(frame, dict)
                    and isinstance(frame.get("url"), str)
                    and isinstance(frame.get("lineNumber"), int)
                ]
        redirect = data.get("redirectResponse")
        redirect_fields: dict[str, object] | None = None
        if isinstance(redirect, dict):
            redirect_headers = redirect.get("headers", {})
            safe_headers = (
                {
                    str(key).lower(): str(value)
                    for key, value in redirect_headers.items()
                    if str(key).lower() in EVIDENCE_HEADERS
                }
                if isinstance(redirect_headers, dict)
                else {}
            )
            redirect_fields = {
                "source_url": redirect.get("url"),
                "status": redirect.get("status"),
                "headers": safe_headers,
                "location_raw": safe_headers.get("location"),
            }
        self.journal_event(
            "network_request_observed",
            session_id=session,
            target_id=self.target_id(session),
            network_id=data.get("requestId") if isinstance(data.get("requestId"), str) else None,
            request_ref=None,
            association="unknown",
            url=request.get("url") if isinstance(request, dict) and isinstance(request.get("url"), str) else None,
            method=request.get("method") if isinstance(request, dict) and isinstance(request.get("method"), str) else None,
            document_url=data.get("documentURL"),
            frame_id=data.get("frameId"),
            loader_id=data.get("loaderId"),
            resource_type=data.get("type"),
            initiator=initiator_fields,
            redirect=redirect_fields,
        )

    def snapshot_path(self, output_dir: Path, digest: str) -> Path:
        self.snapshot_counter += 1
        return output_dir / "web" / f"dom-{self.snapshot_counter:04d}-{digest[:12]}.html"

    def snapshot_saved(
        self,
        *,
        url: str,
        path: str,
        size: int,
        sha256: str,
        request_ref: str | None = None,
    ) -> None:
        self.journal_event(
            "terminal_snapshot",
            url=url,
            path=path,
            size=size,
            sha256=sha256,
            representation="browser_rendered_dom",
            complete=True,
            request_ref=request_ref,
        )

    def challenge_snapshot(
        self, url: str, reason_code: str, *, target_id: str | None
    ) -> None:
        if (
            target_id is not None
            and self.entry_session is not None
            and target_id == self.target_id(self.entry_session)
        ):
            self.main_challenge = True
            if self.main_challenge_reason != "device_verification_required":
                self.main_challenge_reason = reason_code
        self.journal_event(
            "challenge_detected",
            url=url,
            reason_code=reason_code,
            target_id=target_id,
            representation="browser_rendered_dom",
            request_ref=None,
        )

    def download_not_captured(self, event_method: str) -> None:
        self.gaps.append("unsupported_download_body_not_captured")
        self.journal_event("download_not_captured", event_method=event_method, body_captured=False)

    def final_outcome(self, outcome: str, reason_code: str) -> tuple[str, str]:
        if self.main_challenge:
            return "blocked", (
                "device_verification_required"
                if "device_verification_required" in {reason_code, self.main_challenge_reason}
                else "challenge_detected"
            )
        if self.main_status in {401, 403, 429}:
            return "blocked", "http_access_control"
        if isinstance(self.main_status, int) and self.main_status >= 400:
            return "failed", "http_status"
        if self.main_package_stream:
            return "failed", "unsupported_download_response"
        if self.main_body_captured:
            return "captured", "passive_visit_material_captured"
        if reason_code == "browser_dynamic_incomplete":
            return "failed", "browser_body_missing"
        return outcome, reason_code


def record_saved_material(
    journal: EvidenceJournal,
    *,
    source_url: str,
    path: str,
    size: int,
    sha256: str,
    representation: str,
    complete: bool,
    request_ref: str | None = None,
    resource_type: str | None = None,
    package_stream: bool = False,
) -> None:
    fields: dict[str, object] = {
        "source_url": source_url,
        "path": path,
        "size": size,
        "sha256": sha256,
        "representation": representation,
        "complete": complete,
        "package_stream": package_stream,
    }
    if request_ref is not None:
        fields["request_ref"] = request_ref
    if resource_type is not None:
        fields["resource_type"] = resource_type
    try:
        journal.append("response_body_saved" if complete else "response_prefix_saved", fields)
    except Exception:
        journal.failed = True
        if "journal_write_failed" not in journal.gaps:
            journal.gaps.append("journal_write_failed")
