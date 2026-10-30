"""Bounded origin-scoped CDP certificate snapshots; never a new origin request."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509

from .tls_evidence import MAX_CERTIFICATE_BYTES, MAX_CERTIFICATE_TOTAL, save_certificate_der

MAX_ORIGINS = 32
MAX_CHAIN_MEMBERS = 8
MAX_REPORTED_CHAIN = 4096
MAX_COMMAND_SECONDS = 1.0
MAX_QUERY_SECONDS = 5.0
CAPTURE_SOURCE = "chrome_cdp_network_get_certificate"


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_origin(url: str) -> str | None:
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            return None
        host = parsed.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        return "https://" + host + (f":{parsed.port}" if parsed.port and parsed.port != 443 else "")
    except ValueError:
        return None


@dataclass
class Observation:
    fields: dict[str, Any]
    response: dict[str, object]
    status: str = "pending"
    chain_length: int = 0
    members: list[tuple[int, bytes]] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    captured_at: str = ""


class BrowserTLSCapture:
    """Query in an independent task; persist after body capture, before CDP close."""

    def __init__(self, *, output_dir: Path, root: Path, max_task_bytes: int, deadline: float,
                 cancel: Event,
                 send: Callable[[str | None, str, dict[str, Any] | None], Awaitable[dict[str, Any]]],
                 emit: Callable[[str, dict[str, Any]], None],
                 remaining_bytes: Callable[[], int], reserve_bytes: Callable[[int], None]):
        self.output_dir, self.root = output_dir, root
        self.max_task_bytes, self.deadline, self.cancel = max_task_bytes, deadline, cancel
        self.send, self.emit = send, emit
        self.remaining_bytes, self.reserve_bytes = remaining_bytes, reserve_bytes
        self.observations: dict[tuple[str, str], Observation] = {}
        self.queue: deque[Observation] = deque()
        self.worker: asyncio.Task[None] | None = None
        self.query_seconds = 0.0
        self.buffered_bytes = 0
        self.finished = False
        self.network_observations: list[Observation] = []

    def preserve_network_event(self, fields: dict[str, Any], members: list[tuple[int, bytes]],
                               chain_length: int, reasons: list[str]) -> None:
        """Accept only the trace parser's bounded, sanitized original chain."""
        observation = Observation(dict(fields), {}, status="received", chain_length=chain_length,
                                  reasons=list(reasons), captured_at=str(fields["captured_at"]))
        for index, der in members:
            if self.buffered_bytes + len(der) > MAX_CERTIFICATE_TOTAL:
                observation.reasons.append("browser_tls_certificate_limit")
                continue
            self.buffered_bytes += len(der)
            observation.members.append((index, der))
        self.network_observations.append(observation)
        if observation.members:
            self.emit("tls_certificate_observed", {**fields, "chain_length": chain_length,
                      "certificate_members": [{"chain_index": index, "size": len(der),
                                               "sha256": hashlib.sha256(der).hexdigest()}
                                              for index, der in observation.members]})

    def _gap(self, observation: Observation, reason: str, *, partial: bool = False) -> None:
        fields = {**observation.fields, "code": "tls_certificate_chain_partial" if partial else "tls_certificate_not_captured",
                  "reason_code": reason, "capture_status": "partial" if partial else "not_captured",
                  "representation": "tls_certificate_der", "complete": False}
        if observation.reasons:
            fields["reasons"] = list(dict.fromkeys(observation.reasons))[:16]
        self.emit("gap", fields)

    def observe_response(self, response: dict[str, object]) -> None:
        url = response.get("url")
        origin = canonical_origin(url) if isinstance(url, str) else None
        status = response.get("status")
        if origin is None or self.finished or type(status) is not int or not 100 <= status <= 599:
            return
        fields = {key: response.get(key) for key in ("session_id", "target_id", "request_ref", "observed_at")}
        fields.update(url=url, source_url=url, origin=origin, capture_source=CAPTURE_SOURCE,
                      association="origin_snapshot", request_association="observation_trigger_only")
        observation = Observation(fields, response)
        if any(not isinstance(fields.get(key), str) or not fields[key]
               for key in ("session_id", "target_id", "request_ref", "observed_at")):
            self._gap(observation, "browser_tls_observation_unbound")
            response["tls_certificate_capture"] = "not_captured"
            return
        key = str(fields["session_id"]), origin
        if key in self.observations:
            response["tls_certificate_capture"] = "origin_snapshot_shared"
            return
        if len(self.observations) >= MAX_ORIGINS:
            self._gap(observation, "browser_tls_origin_limit")
            response["tls_certificate_capture"] = "not_captured"
            return
        self.observations[key] = observation
        self.queue.append(observation)
        response["tls_certificate_capture"] = "pending"
        # Querying while Fetch still owns a paused response can wait for that
        # very response to be released. Only queue here; finish runs after the
        # capture's stream handlers have settled and before the CDP session closes.

    def _remaining_time(self) -> float:
        if self.cancel.is_set():
            return 0.0
        return max(0.0, min(self.deadline - time.monotonic(), MAX_QUERY_SECONDS - self.query_seconds))

    async def _drain(self) -> None:
        while self.queue:
            await self._query(self.queue.popleft())

    async def _query(self, observation: Observation) -> None:
        available = self._remaining_time()
        if available <= 0:
            observation.status = "failed"
            observation.reasons.append("browser_tls_capture_budget")
            return
        started = time.monotonic()
        try:
            reply = await asyncio.wait_for(
                self.send(str(observation.fields["session_id"]), "Network.getCertificate",
                          {"origin": observation.fields["origin"]}),
                timeout=min(MAX_COMMAND_SECONDS, available),
            )
        except asyncio.CancelledError:
            observation.status = "failed"
            observation.reasons.append("browser_tls_capture_budget")
            raise
        except TimeoutError:
            observation.status = "failed"
            observation.reasons.append("browser_tls_query_timeout")
            return
        except Exception:
            # Optional CDP support varies; a fixed gap is preferable to leaking
            # protocol text or letting this auxiliary task cancel the download.
            observation.status = "failed"
            observation.reasons.append("browser_tls_query_unavailable")
            return
        finally:
            self.query_seconds += time.monotonic() - started
        observation.captured_at = utc_now()
        chain = reply.get("tableNames") if isinstance(reply, dict) else None
        if not isinstance(chain, list) or len(chain) > MAX_REPORTED_CHAIN:
            observation.status = "failed"
            observation.reasons.append("browser_tls_chain_invalid")
            return
        if not chain:
            observation.status = "empty"
            return
        observation.status = "received"
        observation.chain_length = len(chain)
        if len(chain) > MAX_CHAIN_MEMBERS:
            observation.reasons.append("browser_tls_chain_limit")
        # Limit encoded bytes before decoding. An invalid/oversized item does
        # not erase independently valid original DER elsewhere in the chain.
        encoded_budget = (MAX_CERTIFICATE_TOTAL - self.buffered_bytes + 2) // 3 * 4
        for index, encoded in enumerate(chain[:MAX_CHAIN_MEMBERS]):
            if (not isinstance(encoded, str) or not encoded
                    or len(encoded) > (MAX_CERTIFICATE_BYTES + 2) // 3 * 4):
                observation.reasons.append("browser_tls_certificate_invalid")
                continue
            if len(encoded) > encoded_budget:
                observation.reasons.append("browser_tls_certificate_limit")
                continue
            encoded_budget -= len(encoded)
            try:
                der = base64.b64decode(encoded, validate=True)
                if not der or len(der) > MAX_CERTIFICATE_BYTES:
                    raise ValueError("certificate size")
                x509.load_der_x509_certificate(der)
            except (ValueError, binascii.Error):
                observation.reasons.append("browser_tls_certificate_invalid")
                continue
            if self.buffered_bytes + len(der) > MAX_CERTIFICATE_TOTAL:
                observation.reasons.append("browser_tls_certificate_limit")
                continue
            self.buffered_bytes += len(der)
            observation.members.append((index, der))

    async def finish(self, flush_deadline: float | None = None) -> None:
        if self.finished:
            return
        if flush_deadline is not None:
            self.deadline = min(self.deadline, flush_deadline)
        self.finished = True
        # One final retry only for an empty first origin cache lookup. The same
        # task deadline and cumulative five-second command budget still apply.
        deferred_gaps: list[tuple[Observation, str, bool]] = []
        network_saved = False
        origins_queried = False
        # Persist already observed originals before optional origin-cache
        # queries can exhaust the shared flush deadline.
        for observation in [*self.network_observations, *self.observations.values()]:
            if observation.fields.get("association") == "origin_snapshot" and not origins_queried:
                origins_queried = True
                if self.queue and self._remaining_time() > 0:
                    self.worker = asyncio.create_task(self._drain())
                if self.worker is not None:
                    if self._remaining_time() <= 0:
                        self.worker.cancel()
                    try:
                        await asyncio.wait_for(self.worker, timeout=max(0.001, self._remaining_time()))
                    except (TimeoutError, asyncio.CancelledError):
                        self.worker.cancel()
                        await asyncio.gather(self.worker, return_exceptions=True)
            if observation.status == "empty":
                await self._query(observation)
            if observation.status == "pending":
                observation.reasons.append("browser_tls_capture_budget")
            stored: list[dict[str, Any]] = []
            for index, der in observation.members:
                if self.cancel.is_set() or time.monotonic() >= self.deadline:
                    observation.reasons.append("browser_tls_capture_budget")
                    break
                try:
                    metadata, written = save_certificate_der(
                        self.output_dir / "tls", der, root=self.root,
                        max_task_bytes=self.max_task_bytes, remaining_bytes=max(0, self.remaining_bytes()),
                        deadline=self.deadline,
                    )
                    self.reserve_bytes(written)
                    metadata["path"] = Path(str(metadata["path"])).relative_to(self.root.absolute()).as_posix()
                    stored.append({**metadata, "chain_index": index,
                                   "cert_role": "leaf" if index == 0 else "chain_member"})
                except (OSError, ValueError):
                    observation.reasons.append("browser_tls_certificate_storage_failed")
            complete = bool(stored) and len(stored) == observation.chain_length
            for metadata in stored:
                self.emit("tls_certificate_saved", {**observation.fields, **metadata,
                          "chain_length": observation.chain_length, "chain_complete": complete,
                          "captured_at": observation.captured_at})
            if stored and observation.fields.get("association") == "browser_network_event":
                network_saved = True
            if not complete:
                reason = next(iter(observation.reasons), "browser_tls_certificate_empty")
                deferred_gaps.append((observation, reason, bool(stored)))
            observation.response["tls_certificate_capture"] = "captured" if complete else "partial" if stored else "not_captured"
            observation.response["tls_certificate_association"] = observation.fields["association"]
            observation.members.clear()
        for observation, reason, partial in deferred_gaps:
            if (network_saved and not partial and reason == "browser_tls_certificate_empty"
                    and observation.fields.get("association") == "origin_snapshot"):
                self.emit("tls_certificate_origin_query_unavailable", {**observation.fields,
                          "reason_code": reason, "alternative_scope": "browser_network_event"})
            else:
                self._gap(observation, reason, partial=partial)
