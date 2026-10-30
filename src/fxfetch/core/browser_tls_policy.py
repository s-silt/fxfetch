"""Continue only an observed certificate error for an already permitted request.

The deprecated CDP event has URL/session scope, not a request/connection identity.
No URL match here is promoted to evidence that a particular DER was accepted.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

from .errors import FxfetchError
from .guard import validate_url
from .tls_policy import CERTIFICATE_ERRORS

MAX_CERTIFICATE_EVENTS = 32
MAX_ACTIVE_REQUESTS = 512


def resolve_tls_policy(tls_policy: str, ignore_tls_errors: bool) -> str:
    if type(ignore_tls_errors) is not bool:
        raise ValueError("ignore_tls_errors must be boolean")
    if tls_policy not in {"strict", "auto"}:
        raise ValueError("tls_policy must be strict or auto")
    # Compatibility changes semantics deliberately: never an unconditional bypass.
    return "auto" if ignore_tls_errors else tls_policy


def _origin(url: str) -> tuple[str, str | None, int | None]:
    value = urlsplit(url)
    return value.scheme, value.hostname, value.port or (443 if value.scheme == "https" else 80)


def certificate_failure_is_critical(url: str, resource_type: object, transfer_active: bool) -> bool:
    return urlsplit(url).path.lower().endswith((".apk", ".ipa")) or (resource_type == "Document" and not transfer_active)


class BrowserTLSPolicy:
    def __init__(self, *, policy: str, check: Callable[[], None],
                 send: Callable[[str | None, str, dict[str, Any] | None], Awaitable[dict[str, Any]]],
                 emit: Callable[[str, dict[str, Any]], None]) -> None:
        self.policy, self.check, self.send, self.emit = policy, check, send, emit
        self.sessions: set[str] = set()
        self.active: dict[tuple[str, str], str] = {}
        self.network: dict[tuple[str, str], str] = {}
        self.seen: set[tuple[str, int]] = set()
        self.pending: set[tuple[str, int]] = set()
        self.fallbacks: list[dict[str, Any]] = []
        self.affected: set[tuple[str, tuple[str, str | None, int | None]]] = set()

    async def setup(self, session: str, *, target_type: str = "page") -> None:
        self.sessions.add(session)
        # All tasks and all origins start with checking enabled. This class never
        # sends ignore=true, including the legacy boolean compatibility path.
        await self.send(session, "Security.setIgnoreCertificateErrors", {"ignore": False})
        # Security.enable is expressly restricted to top-level active frames.
        # OOPIFs retain strict validation and Fetch guards; no parent inference.
        if self.policy == "auto" and target_type == "page":
            try:
                await self.send(session, "Security.enable", {})
                await self.send(session, "Security.setOverrideCertificateErrors", {"override": True})
            except FxfetchError as error:
                raise FxfetchError("browser_tls_policy_unavailable", "Per-certificate TLS continuation is unavailable") from error

    def approved(self, session: str, request_id: str, url: str, network_id: str | None = None) -> None:
        if len(self.active) >= MAX_ACTIVE_REQUESTS:
            raise FxfetchError("browser_tls_policy_limit", "Active TLS permission scope is full")
        self.active[(session, request_id)] = url
        if network_id is not None:
            self.network[(session, network_id)] = request_id

    def settled(self, session: str, request_id: str) -> None:
        self.active.pop((session, request_id), None)
        for key, fetch_id in tuple(self.network.items()):
            if key[0] == session and fetch_id == request_id:
                self.network.pop(key, None)

    def network_settled(self, session: str, network_id: object) -> str | None:
        if isinstance(network_id, str):
            request_id = self.network.pop((session, network_id), None)
            if request_id is not None:
                url = self.active.get((session, request_id))
                self.settled(session, request_id)
                return url
        return None

    def detached(self, session: str) -> None:
        self.sessions.discard(session)
        for active_session, request_id in tuple(self.active):
            if active_session == session:
                self.settled(session, request_id)

    def context(self, session: str, url: str) -> dict[str, object]:
        # Chrome can internally reuse a certificate exception without another
        # event. Affected origin observations therefore stay explicitly unknown.
        try:
            affected = (session, _origin(url)) in self.affected
        except ValueError:
            affected = False
        return {"tls_verification": "unknown" if affected else "required"}

    async def certificate_error(self, session: str, event: dict[str, Any]) -> None:
        self.check()
        event_id = event.get("eventId")
        if session not in self.sessions or type(event_id) is not int or not 0 <= event_id < 2**31:
            raise FxfetchError("browser_tls_event_invalid", "Certificate event scope is invalid")
        key = session, event_id
        self.pending.add(key)
        if key in self.seen or len(self.seen) >= MAX_CERTIFICATE_EVENTS:
            await self._cancel(key)
            raise FxfetchError("browser_tls_policy_limit", "Certificate event limit reached")
        self.seen.add(key)
        error_type, raw_url = event.get("errorType"), event.get("requestURL")
        if not isinstance(error_type, str) or error_type not in CERTIFICATE_ERRORS or not isinstance(raw_url, str):
            await self._cancel(key)
            raise FxfetchError("browser_tls_error_unsupported", "Unsupported certificate error")
        try:
            url = validate_url(raw_url)
        except FxfetchError:
            await self._cancel(key)
            raise
        if urlsplit(url).scheme != "https" or not any(
            approved_session == session and approved_url == url
            for (approved_session, _), approved_url in self.active.items()
        ):
            await self._cancel(key)
            raise FxfetchError("browser_tls_unpermitted_error", "Certificate event has no current request permission")
        fields = {"session_id": session, "event_id": event_id, "source_url": url,
                  "tls_verify_reason": CERTIFICATE_ERRORS[error_type], "chrome_error_type": error_type,
                  "association": "browser_certificate_event", "request_association": "url_permission_only"}
        self.emit("tls_certificate_error", {**fields, "tls_verification": "required"})
        if self.policy != "auto":
            await self._cancel(key)
            raise FxfetchError("tls_verification_failed", "Certificate validation failed")
        self.check()
        try:
            await self.send(session, "Security.handleCertificateError", {"eventId": event_id, "action": "continue"})
        except FxfetchError:
            self.emit("gap", {**fields, "code": "tls_policy_continuation_unconfirmed",
                              "reason_code": "tls_policy_continuation_unconfirmed"})
            raise
        self.pending.discard(key)
        self.affected.add((session, _origin(url)))
        fallback = {**fields, "tls_fallback_id": uuid.uuid4().hex, "tls_verification": "ignored"}
        self.fallbacks.append(fallback)
        self.emit("tls_verification_fallback", fallback)

    async def _cancel(self, key: tuple[str, int]) -> None:
        session, event_id = key
        await self.send(session, "Security.handleCertificateError", {"eventId": event_id, "action": "cancel"})
        self.pending.discard(key)

    def unhandled_network_error(self, error_text: object) -> bool:
        if self.policy != "auto" or not isinstance(error_text, str):
            return False
        return error_text.removeprefix("net::") in CERTIFICATE_ERRORS
