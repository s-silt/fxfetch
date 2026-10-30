"""Bounded flat-session CDP transport over an explicitly local control endpoint.

Playwright's public CDPSession cannot address auto-attached flat session IDs.
The bridge uses the Node runtime shipped by Playwright, never a target script.
"""

from __future__ import annotations

import asyncio
import http.client
import ipaddress
import json
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import playwright

from .errors import FxfetchError

_BRIDGE_SOURCE = r"""
const socket = new WebSocket(process.argv[1]);
const readline = require('node:readline');
let opened = false;
const waiting = [];
socket.addEventListener('open', () => {
  opened = true;
  for (const row of waiting) socket.send(row);
  waiting.length = 0;
});
socket.addEventListener('message', event => {
  process.stdout.write(String(event.data) + '\n');
});
socket.addEventListener('error', () => process.exit(2));
socket.addEventListener('close', () => process.exit(0));
const input = readline.createInterface({input: process.stdin, crlfDelay: Infinity});
input.on('line', row => { if (opened) socket.send(row); else waiting.push(row); });
input.on('close', () => { socket.close(); setTimeout(() => process.exit(0), 50); });
"""


def _local_endpoint(endpoint: str) -> None:
    parsed = urlsplit(endpoint)
    try:
        local = ipaddress.ip_address(parsed.hostname or "").is_loopback
        port = parsed.port
    except ValueError as error:
        raise FxfetchError("browser_cdp_failed", "Invalid CDP endpoint") from error
    if not local or not port or parsed.scheme not in {"http", "ws"} or parsed.username or parsed.password:
        raise FxfetchError("browser_cdp_failed", "CDP control endpoint must be a literal loopback address")
    if parsed.query or parsed.fragment:
        raise FxfetchError("browser_cdp_failed", "Unexpected CDP endpoint parameters")


def _browser_path(path: str) -> bool:
    # Chromium's discoverable browser target (including Android) can expose the
    # exact /devtools/browser path; desktop's nondiscoverable target adds a UUID.
    return path == "/devtools/browser" or path.startswith("/devtools/browser/")


def resolve_endpoint(profile: Path, endpoint: str | None) -> str:
    """Resolve only a lease-supplied loopback control endpoint, never a target URL."""
    if endpoint is None:
        port_file = profile / "DevToolsActivePort"
        if port_file.stat().st_size > 1024:
            raise FxfetchError("browser_cdp_failed", "Invalid local CDP endpoint receipt")
        lines = port_file.read_text("utf-8").splitlines()
        if len(lines) != 2 or not lines[0].isdigit() or not _browser_path(lines[1]):
            raise FxfetchError("browser_cdp_failed", "Invalid local CDP endpoint receipt")
        endpoint = f"ws://127.0.0.1:{int(lines[0])}{lines[1]}"
    _local_endpoint(endpoint)
    parsed = urlsplit(endpoint)
    if parsed.scheme == "ws":
        if not _browser_path(parsed.path):
            raise FxfetchError("browser_cdp_failed", "Expected a browser CDP endpoint")
        return endpoint
    if parsed.path not in {"", "/"}:
        raise FxfetchError("browser_cdp_failed", "Unexpected CDP HTTP path")
    assert parsed.hostname is not None
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=3)
    try:
        connection.request("GET", "/json/version")
        response = connection.getresponse()
        body = response.read(4097)
        if response.status != 200 or len(body) > 4096:
            raise FxfetchError("browser_cdp_failed", "CDP discovery response rejected")
        discovered = urlsplit(json.loads(body)["webSocketDebuggerUrl"])
        if discovered.scheme != "ws" or not _browser_path(discovered.path):
            raise FxfetchError("browser_cdp_failed", "Invalid CDP discovery response")
        # An SSH/ADB tunnel can expose a different local port from the guest.
        return urlunsplit(("ws", parsed.netloc, discovered.path, "", ""))
    except (KeyError, TypeError, ValueError, OSError, http.client.HTTPException) as error:
        raise FxfetchError("browser_cdp_failed", "Local CDP discovery failed") from error
    finally:
        connection.close()


class CDPMux:
    def __init__(
        self,
        process: asyncio.subprocess.Process,
        handler: Callable[[str, str, dict[str, Any]], None],
        check: Callable[[], None],
        command_timeout: float,
    ) -> None:
        self.process, self.handler, self.check = process, handler, check
        self.command_timeout = command_timeout
        self.sequence = 0
        self.pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self.methods: dict[int, str] = {}
        self.reader_task = asyncio.create_task(self._read())
        self.closed = False

    @classmethod
    async def connect(
        cls,
        endpoint: str,
        handler: Callable[[str, str, dict[str, Any]], None],
        check: Callable[[], None],
        command_timeout: float,
    ) -> CDPMux:
        _local_endpoint(endpoint)
        node = Path(playwright.__file__).parent / "driver" / ("node.exe" if os.name == "nt" else "node")
        process = await asyncio.create_subprocess_exec(
            str(node),
            "-e",
            _BRIDGE_SOURCE,
            endpoint,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=2 * 1024 * 1024,
        )
        return cls(process, handler, check, command_timeout)

    async def _read(self) -> None:
        assert self.process.stdout is not None
        try:
            while row := await self.process.stdout.readline():
                message = json.loads(row)
                if "id" in message:
                    future = self.pending.pop(message["id"], None)
                    if future is not None and not future.done():
                        if "error" in message:
                            failure = message["error"]
                            category = "command_rejected"
                            detail = str(failure.get("message", "")).lower()
                            for marker, label in (
                                ("invalid interceptionid", "interception_gone"),
                                ("invalid interception id", "interception_gone"),
                                ("session", "session_error"),
                                ("target", "target_error"),
                                ("stream", "stream_error"),
                            ):
                                if marker in detail:
                                    category = label
                                    break
                            future.set_exception(CDPCommandError(self.methods.get(message["id"], ""), category))
                        else:
                            future.set_result(message.get("result", {}))
                else:
                    data = message.get("params", {})
                    session = (
                        data["sessionId"]
                        if message.get("method") == "Target.attachedToTarget"
                        else message.get("sessionId", "")
                    )
                    self.handler(session, message.get("method", ""), data)
        except (OSError, ValueError, KeyError, TypeError):
            self.handler("", "transport_error", {})
        finally:
            if not self.closed:
                self.handler("", "transport_error", {})
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(FxfetchError("browser_cdp_failed", "CDP transport closed"))

    async def send(
        self, session: str | None, method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return await self._send(session, method, params, self.check, self.command_timeout)

    async def send_cleanup(self, method: str, *, stream: str | None = None) -> dict[str, Any]:
        """Fixed control-plane cleanup, never navigation or network commands."""
        if method == "Tracing.end" and stream is None:
            params = {}
        elif method == "IO.close" and isinstance(stream, str) and 0 < len(stream) <= 256:
            params = {"handle": stream}
        else:
            raise ValueError("Unsupported cleanup operation")
        return await self._send(None, method, params, lambda: None, 1.0)

    async def restore_tls_verification(self, session: str) -> dict[str, Any]:
        """Cleanup can only restore checking, never disable TLS validation."""
        if not isinstance(session, str) or not 0 < len(session) <= 256:
            raise ValueError("Invalid cleanup session")
        try:
            await self._send(session, "Security.setOverrideCertificateErrors", {"override": False}, lambda: None, 1.0)
        finally:
            result = await self._send(session, "Security.setIgnoreCertificateErrors", {"ignore": False}, lambda: None, 1.0)
        return result

    async def cancel_certificate_error(self, session: str, event_id: int) -> dict[str, Any]:
        """Independent bounded cleanup can reject an owned event, never continue it."""
        if (not isinstance(session, str) or not 0 < len(session) <= 256
                or type(event_id) is not int or not 0 <= event_id < 2**31):
            raise ValueError("Invalid certificate cleanup scope")
        return await self._send(session, "Security.handleCertificateError", {"eventId": event_id, "action": "cancel"},
                                lambda: None, 1.0)

    async def _send(self, session: str | None, method: str, params: dict[str, Any] | None,
                    check: Callable[[], None], timeout: float) -> dict[str, Any]:
        check()
        self.sequence += 1
        sequence = self.sequence
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self.pending[sequence] = future
        self.methods[sequence] = method
        message: dict[str, Any] = {"id": sequence, "method": method, "params": params or {}}
        if session:
            message["sessionId"] = session
        assert self.process.stdin is not None
        end = time.monotonic() + timeout
        drain: asyncio.Task[None] | None = None
        try:
            self.process.stdin.write(json.dumps(message).encode() + b"\n")
            drain = asyncio.create_task(self.process.stdin.drain())
            while not drain.done():
                check()
                if time.monotonic() >= end:
                    raise FxfetchError("browser_read_timeout", "CDP command write exceeded its time budget")
                await asyncio.wait({drain}, timeout=0.05)
            await drain
            while not future.done():
                check()
                if time.monotonic() >= end:
                    raise FxfetchError(
                        "browser_read_timeout", "CDP operation made no progress within its time budget"
                    )
                await asyncio.wait({future}, timeout=0.05)
            return future.result()
        finally:
            self.pending.pop(sequence, None)
            self.methods.pop(sequence, None)
            if drain is not None and not drain.done():
                drain.cancel()
                await asyncio.gather(drain, return_exceptions=True)
            if not future.done():
                future.cancel()
            elif not future.cancelled():
                future.exception()

    async def close(self) -> None:
        self.closed = True
        if self.process.stdin is not None:
            self.process.stdin.close()
        self.reader_task.cancel()
        await asyncio.gather(self.reader_task, return_exceptions=True)
        if self.process.returncode is None:
            self.process.kill()
        await self.process.wait()


class CDPCommandError(FxfetchError):
    """Private fixed-category diagnostics, excluding raw remote error messages."""

    def __init__(self, method: str, category: str) -> None:
        super().__init__("browser_cdp_failed", "CDP command rejected")
        self.method = method
        self.category = category
