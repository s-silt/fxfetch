"""Bounded passive Chrome netlog tracing; persist only certificate DER and safe identities."""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import math
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from threading import Event
from typing import Any

from cryptography import x509

from .browser_tls_evidence import MAX_CHAIN_MEMBERS, MAX_REPORTED_CHAIN, utc_now
from .tls_evidence import MAX_CERTIFICATE_BYTES, MAX_CERTIFICATE_TOTAL

MAX_TRACE_BYTES = 8 * 1024 * 1024
MAX_TRACE_EVENTS = 50_000
MAX_TLS_EVENTS = 32
SOURCE = "chrome_netlog_ssl_certificates_received"
_PEM = re.compile(r"\A-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----\s*\Z")


class BrowserTLSTrace:
    def __init__(self, *, deadline: float, cancel: Event,
                 send: Callable[[str | None, str, dict[str, Any] | None], Awaitable[dict[str, Any]]],
                 emit: Callable[[str, dict[str, Any]], None],
                 preserve: Callable[[dict[str, Any], list[tuple[int, bytes]], int, list[str]], None],
                 cleanup: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]] | None = None):
        self.deadline, self.cancel, self.send, self.emit, self.preserve = deadline, cancel, send, emit, preserve
        self.trace_id = uuid.uuid4().hex
        self.started_at = ""
        self.owned = False
        self.finished = False
        self.complete = asyncio.Event()
        self.stream: str | None = None
        self.start_failed: str | None = None
        self.end_requested = False
        self.data_loss = False
        self.expected = False
        self.cleanup = cleanup

    def _gap(self, reason: str) -> None:
        if not self.expected:
            return
        self.emit("gap", {"code": "tls_certificate_not_captured", "reason_code": reason,
                          "capture_status": "not_captured", "capture_source": SOURCE,
                          "association": "browser_network_event", "request_association": "unknown",
                          "source_url": "", "trace_id": self.trace_id})

    async def _command(self, method: str, params: dict[str, Any], deadline: float) -> dict[str, Any]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        operation = (self.cleanup(method, params) if self.cleanup is not None and method in {"Tracing.end", "IO.close"}
                     else self.send(None, method, params))
        return await asyncio.wait_for(operation, timeout=min(1.0, remaining))

    async def start(self) -> None:
        if self.cancel.is_set() or time.monotonic() >= self.deadline:
            self.start_failed = "browser_tls_trace_budget"
            return
        self.started_at = utc_now()
        try:
            await self._command("Tracing.start", {
                "transferMode": "ReturnAsStream", "streamFormat": "json",
                "traceConfig": {"recordMode": "recordContinuously", "traceBufferSizeInKb": 4096,
                                "includedCategories": ["netlog"]},
            }, self.deadline)
            self.owned = True
        except Exception:
            # Includes another observer already tracing: never stop a trace
            # unless our start was acknowledged successfully.
            self.start_failed = "browser_tls_trace_unavailable"

    def event(self, method: str, data: dict[str, Any]) -> None:
        if method == "Tracing.tracingComplete" and self.owned and self.end_requested:
            self.data_loss = data.get("dataLossOccurred") is True
            handle = data.get("stream")
            if isinstance(handle, str) and 0 < len(handle) <= 256:
                self.stream = handle
            self.complete.set()

    async def finish(self, flush_deadline: float) -> None:
        if self.finished:
            return
        self.finished = True
        if not self.owned:
            self._gap(self.start_failed or "browser_tls_trace_unavailable")
            return
        # Ending our passive trace is control-plane cleanup, permitted for at
        # most two seconds even after acquisition cancellation/deadline.
        cleanup_deadline = time.monotonic() + 2.0
        try:
            self.end_requested = True
            await self._command("Tracing.end", {}, cleanup_deadline)
            await asyncio.wait_for(self.complete.wait(), timeout=max(.001, cleanup_deadline - time.monotonic()))
            self.owned = False
            if self.cancel.is_set() or time.monotonic() >= min(self.deadline, flush_deadline):
                self._gap("browser_tls_trace_budget")
                return
            if self.stream is None:
                self._gap("browser_tls_trace_stream_missing")
                return
            raw = bytearray()
            while True:
                part = await self._command("IO.read", {"handle": self.stream, "size": 65536},
                                           min(self.deadline, flush_deadline))
                data = part.get("data")
                if not isinstance(data, str) or len(data) > 128 * 1024:
                    raise ValueError("invalid trace chunk")
                block = base64.b64decode(data, validate=True) if part.get("base64Encoded") else data.encode("utf-8")
                if len(raw) + len(block) > MAX_TRACE_BYTES:
                    self._gap("browser_tls_trace_size_limit")
                    return
                raw.extend(block)
                if part.get("eof"):
                    break
            self.parse(bytes(raw), deadline=min(self.deadline, flush_deadline))
            if self.data_loss:
                self._gap("browser_tls_trace_data_loss")
        except TimeoutError:
            self._gap("browser_tls_trace_budget")
        except (ValueError, OSError, binascii.Error):
            self._gap("browser_tls_trace_invalid")
        except Exception:
            self._gap("browser_tls_trace_unavailable")
        finally:
            if self.stream is not None:
                try:
                    await self._command("IO.close", {"handle": self.stream}, max(cleanup_deadline, time.monotonic() + .25))
                except Exception:
                    self._gap("browser_tls_trace_close_failed")

    def parse(self, raw: bytes, *, deadline: float) -> None:
        if len(raw) > MAX_TRACE_BYTES:
            self._gap("browser_tls_trace_size_limit")
            return
        value = json.loads(raw)
        events = value.get("traceEvents") if isinstance(value, dict) else None
        if not isinstance(events, list):
            raise ValueError("missing trace events")
        seen: set[tuple[int, str, float]] = set()
        observed = 0
        decoded_bytes = 0
        for event in events[:MAX_TRACE_EVENTS]:
            if self.cancel.is_set() or time.monotonic() >= deadline:
                self._gap("browser_tls_trace_budget")
                break
            if not isinstance(event, dict) or event.get("cat") != "netlog" or event.get("name") != "SSL_CERTIFICATES_RECEIVED":
                continue
            args = event.get("args")
            if not isinstance(args, dict) or args.get("source_type") != "SOCKET":
                continue
            self.expected = True
            params = args.get("params")
            chain = params.get("certificates") if isinstance(params, dict) else None
            source_id = event.get("id2", {}).get("local") if isinstance(event.get("id2"), dict) else event.get("id")
            pid, timestamp = event.get("pid"), event.get("ts")
            if (not isinstance(chain, list) or not 0 < len(chain) <= MAX_REPORTED_CHAIN
                    or type(pid) is not int or not 0 < pid < 2**32
                    or not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool)
                    or not math.isfinite(timestamp) or timestamp < 0
                    or not isinstance(source_id, (str, int)) or isinstance(source_id, bool)
                    or not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,32}", str(source_id))):
                self._gap("browser_tls_trace_event_invalid")
                continue
            identity = pid, str(source_id), float(timestamp)
            if identity in seen:
                continue
            if observed >= MAX_TLS_EVENTS:
                self._gap("browser_tls_trace_event_limit")
                break
            seen.add(identity)
            observed += 1
            members, reasons = [], []
            if len(chain) > MAX_CHAIN_MEMBERS:
                reasons.append("browser_tls_chain_limit")
            for index, pem in enumerate(chain[:MAX_CHAIN_MEMBERS]):
                if not isinstance(pem, str) or len(pem) > 2 * MAX_CERTIFICATE_BYTES:
                    reasons.append("browser_tls_certificate_invalid")
                    continue
                try:
                    match = _PEM.fullmatch(pem)
                    if match is None:
                        raise ValueError("invalid PEM envelope")
                    encoded = "".join(match[1].split())
                    if len(encoded) > (MAX_CERTIFICATE_BYTES + 2) // 3 * 4:
                        raise ValueError("certificate size")
                    if len(encoded) > (MAX_CERTIFICATE_TOTAL - decoded_bytes + 2) // 3 * 4:
                        reasons.append("browser_tls_certificate_limit")
                        continue
                    der = base64.b64decode(encoded, validate=True)
                    if not 0 < len(der) <= MAX_CERTIFICATE_BYTES:
                        raise ValueError("certificate size")
                    x509.load_der_x509_certificate(der)
                    if decoded_bytes + len(der) > MAX_CERTIFICATE_TOTAL:
                        reasons.append("browser_tls_certificate_limit")
                        continue
                    decoded_bytes += len(der)
                    members.append((index, der))
                except (ValueError, binascii.Error):
                    reasons.append("browser_tls_certificate_invalid")
            fields = {"capture_source": SOURCE, "association": "browser_network_event",
                      "request_association": "unknown", "source_url": "", "trace_id": self.trace_id,
                      "trace_started_at": self.started_at, "captured_at": utc_now(),
                      "netlog_source_id": str(source_id), "netlog_source_type": "SOCKET",
                      "netlog_pid": pid, "netlog_event_name": "SSL_CERTIFICATES_RECEIVED",
                      "netlog_timestamp": timestamp}
            self.preserve(fields, members, len(chain), reasons)
        if len(events) > MAX_TRACE_EVENTS:
            self._gap("browser_tls_trace_event_limit")
        if observed == 0:
            self._gap("browser_tls_trace_certificate_empty")
