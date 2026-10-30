"""Loopback-only browser egress gate: public DNS, pinned TCP and wire budgets.

This is an internal confinement component, not an alternate Internet proxy.
It always connects directly. Native HTTPS remains end-to-end between Chrome
and the origin; the gate never decrypts TLS or installs certificates.
HTTP permits identify one method/URL request. HTTPS permits identify only a
CONNECT authority for this lease: encrypted paths/methods and connection reuse
cannot be distinguished here and remain subject to the controlled CDP session.
"""

from __future__ import annotations

import errno
import ipaddress
import re
import select
import socket
import socketserver
import sys
import threading
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from .errors import FxfetchError
from .guard import is_public, validate_url
from .public_dns import DefaultPublicDNSResolver, bounded_dns_records

HEADER_LIMIT = 32768
BLOCK = 65536
_BUDGET_ERRORS = frozenset({
    "browser_connection_limit", "request_limit", "request_header_limit",
    "browser_wire_limit", "browser_permit_limit", "task_timeout",
})
_DNS_FAILURES = frozenset({
    "dns_failed", "dns_no_addresses", "dns_nxdomain", "dns_invalid_response",
    "dns_tls_verification_failed", "proxy_failed", "proxy_timeout",
})


class BrowserGateway:
    def __init__(
        self,
        *,
        port: int = 18767,
        timeout: float = 600,
        max_connections: int = 300,
        max_wire_bytes: int = 640 * 1024 * 1024,
        cancel: threading.Event | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        if timeout <= 0 or max_connections < 1 or max_wire_bytes < 1:
            raise ValueError("invalid browser gateway budget")
        self.port, self.timeout = port, timeout
        self.max_connections, self.max_wire_bytes = max_connections, max_wire_bytes
        self.cancel = cancel or threading.Event()
        self.on_event = on_event
        self.deadline = 0.0
        self.connections = self.wire_bytes = 0
        self.errors: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(16)
        self._stopped = threading.Event()
        self._armed_lease_id: str | None = None
        self._http_permits: dict[tuple[str, str, str, int, str, str], int] = {}
        self._https_authorities: set[tuple[str, int]] = set()
        self._permit_count = 0
        self._sockets: set[socket.socket] = set()
        self._server: socketserver.TCPServer | None = None
        self._thread: threading.Thread | None = None
        self._port_owner: socket.socket | None = None

    def __enter__(self) -> BrowserGateway:
        if self._server is not None or self._stopped.is_set():
            raise RuntimeError("Browser gateway instances cannot be reused")
        gate = self

        class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
            daemon_threads = True
            block_on_close = False
            # Linux must reuse closed connections in TIME_WAIT between tasks.
            # SO_REUSEADDR alone permits two dormant binds, so the abstract
            # socket below reserves ownership before this TCP socket can bind.
            allow_reuse_address = sys.platform == "linux"

            def verify_request(self, request, client_address):
                # Reject at accept time: a dormant connection must not wait for
                # a later lease to arm the gate, consume its budget, or resolve
                # an old task's destination.
                return ipaddress.ip_address(client_address[0]).is_loopback and gate.armed

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                gate._handle(self.request)

        self.deadline = time.monotonic() + self.timeout
        # Reserve the exact local port, but do not listen until proof succeeds.
        # Otherwise a dormant connection could remain in the kernel backlog
        # and be accepted after a later arm, carrying the old task's request.
        server = Server(("127.0.0.1", self.port), Handler, bind_and_activate=False)
        try:
            if sys.platform == "linux" and self.port:
                self._reserve_port(self.port)
            server.server_bind()
            if sys.platform == "linux" and not self.port:
                self._reserve_port(server.server_address[1])
        except (OSError, ValueError, OverflowError):
            server.server_close()
            self._release_port()
            raise
        self._server = server
        self.port = self._server.server_address[1]
        return self

    def _reserve_port(self, port: int) -> None:
        # Abstract Unix sockets are scoped to the Linux network namespace,
        # unlike a /tmp lock shared across containers. Binding is atomic and
        # ownership disappears on process exit; no stale lock file remains.
        family = getattr(socket, "AF_UNIX", None)
        if family is None:
            raise OSError("Linux abstract Unix sockets are unavailable")
        owner = socket.socket(family, socket.SOCK_DGRAM)
        try:
            owner.bind(f"\0fxfetch-browser-gateway-{port}")
        except OSError:
            owner.close()
            raise
        self._port_owner = owner

    def _release_port(self) -> None:
        if self._port_owner is not None:
            self._port_owner.close()
            self._port_owner = None

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        self._stopped.set()
        with self._lock:
            self._armed_lease_id = None
            self._http_permits.clear()
            self._https_authorities.clear()
            self._permit_count = 0
            sockets = list(self._sockets)
        for connection in sockets:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # Closed concurrently by its request handler.
            connection.close()
        if self._server is not None:
            if self._thread is not None:
                self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(2)
        self._release_port()

    @property
    def active(self) -> bool:
        return bool(
            self._server and not self._stopped.is_set()
            and (self._thread is None or self._thread.is_alive())
        )

    @property
    def armed(self) -> bool:
        return bool(
            self._armed_lease_id and self.active and not self.cancel.is_set()
            and time.monotonic() < self.deadline
        )

    def arm(self, lease_id: str) -> None:
        """Called only after the current lease's live confinement proof passes."""
        if not re.fullmatch(r"[0-9a-f]{32}", lease_id) or lease_id == "0" * 32:
            raise ValueError("invalid_gateway_lease_id")
        with self._lock:
            if not self.active or self.cancel.is_set() or time.monotonic() >= self.deadline:
                raise FxfetchError("browser_guard_unavailable", "Browser gateway is no longer active")
            if self._armed_lease_id not in {None, lease_id}:
                raise FxfetchError("browser_guard_unavailable", "Browser gateway belongs to another lease")
            if self._armed_lease_id == lease_id:
                return
            assert self._server is not None
            try:
                self._server.server_activate()
            except OSError as error:
                raise FxfetchError("browser_guard_unavailable", "Browser gateway cannot listen") from error
            self._armed_lease_id = lease_id
            self._thread = threading.Thread(
                target=self._server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
            )
            self._thread.start()

    @staticmethod
    def _request_key(url: str, method: str) -> tuple[str, str, str, int, str, str]:
        parts = urlsplit(validate_url(url))
        assert parts.hostname
        return (
            method, parts.scheme, parts.hostname.rstrip("."),
            parts.port or (443 if parts.scheme == "https" else 80),
            parts.path or "/", parts.query,
        )

    def permit_request(self, lease_id: str, url: str, method: str) -> None:
        """Register a controlled CDP Request-stage request before continuing it.

        The callback is bound to the verified lease, never exposed to HTTP
        clients. TLS authority permission lasts until close; HTTP is one-use.
        """
        self._check()
        if method not in {"GET", "HEAD", "POST", "OPTIONS"}:
            raise FxfetchError("browser_method_unsupported", "Unsupported browser method")
        key = self._request_key(url, method)
        with self._lock:
            self._check()
            if lease_id != self._armed_lease_id:
                raise FxfetchError("browser_guard_unavailable", "Request permit belongs to another lease")
            if self._permit_count >= self.max_connections:
                raise FxfetchError("browser_permit_limit", "Browser request permit budget reached")
            self._permit_count += 1
            if key[1] == "https":
                self._https_authorities.add((key[2], key[3]))
            else:
                self._http_permits[key] = self._http_permits.get(key, 0) + 1

    def _authorize_request(self, url: str, method: str) -> None:
        key = self._request_key(url, method)
        with self._lock:
            self._check()
            if method == "CONNECT":
                allowed = (key[2], key[3]) in self._https_authorities
            else:
                count = self._http_permits.get(key, 0)
                allowed = count > 0
                if count == 1:
                    del self._http_permits[key]
                elif count > 1:
                    self._http_permits[key] = count - 1
            if not allowed:
                raise FxfetchError("browser_request_not_permitted", "No controlled page request permits this connection")

    def _check(self) -> float:
        if self._stopped.is_set() or self.cancel.is_set():
            raise FxfetchError("cancelled", "Browser gateway stopped")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise FxfetchError("task_timeout", "Browser gateway deadline reached")
        if self._armed_lease_id is None:
            raise FxfetchError("browser_guard_unavailable", "Browser gateway has no verified lease")
        return remaining

    def _destination(self, url: str) -> tuple[str, int]:
        self._check()
        parts = urlsplit(validate_url(url))
        assert parts.hostname
        port = parts.port or (443 if parts.scheme == "https" else 80)
        try:
            literal = ipaddress.ip_address(parts.hostname)
        except ValueError:
            resolver = DefaultPublicDNSResolver()
            failure: FxfetchError | None = None
            try:
                addresses = resolver.resolve(parts.hostname, port)
                self._check()
            except FxfetchError as error:
                failure = error
                raise
            finally:
                records = bounded_dns_records(resolver.last_records)
                normal_close = bool(failure is not None and failure.code == "cancelled"
                                    and self._stopped.is_set() and not self.cancel.is_set())
                if failure is not None and failure.code in {"task_timeout", "cancelled"}:
                    # DNS can finish after the lease's deadline. Retain its
                    # evidence as discarded, never advertise usable answers.
                    for record in records:
                        record.update(status="discarded", reason_code=failure.code,
                                      late_answer_discarded=True)
                if self.on_event and not normal_close:
                    for record in records:
                        self.on_event({"event": "dns_resolution_observed", "url": url,
                                       "host": parts.hostname, "dns_record": record})
                    if failure is not None:
                        last = next((row for row in reversed(records) if row.get("query_type")), {})
                        self.on_event({"event": "dns_resolution_failed", "url": url,
                                       "provider": last.get("provider", last.get("endpoint")),
                                       "query_type": last.get("query_type"),
                                       "reason_code": failure.code})
        else:
            addresses = (str(literal),)
        if not addresses or any(not is_public(value) for value in addresses):
            raise FxfetchError("target_not_public", "Browser destination is not public")
        self._check()
        return addresses[0], port

    def _record_error(self, code: str, url: str, *, connected: bool = False) -> None:
        # _check() also uses cancelled when ordinary lease teardown closes the
        # gate. That expected local shutdown is not a failed target request.
        if code == "cancelled" and self._stopped.is_set() and not self.cancel.is_set():
            return
        unattributed = code == "browser_request_not_permitted"
        name = "browser_connection_blocked"
        if code == "cancelled":
            name = "browser_connection_cancelled"
        elif code in _BUDGET_ERRORS:
            name = "browser_budget_exhausted"
        elif code == "browser_transport_failed":
            name = "browser_transport_failed" if connected else "browser_connection_failed"
        elif code in _DNS_FAILURES:
            name = "browser_connection_failed"
        event: dict[str, Any] = {"event": name, "reason_code": code}
        if name in {"browser_connection_failed", "browser_transport_failed"}:
            event["connection_phase"] = "established" if connected else "before_connect"
        if unattributed:
            event["host"] = urlsplit(url).hostname or ""
        else:
            event["url"] = url
        with self._lock:
            self.errors.append(event)
            del self.errors[:-128]
        if self.on_event and not unattributed:
            self.on_event(event)

    def _closed_socket_error(
        self, error: OSError | ValueError, sockets: tuple[socket.socket | None, ...],
        *, selecting: bool,
    ) -> bool:
        # Do not suppress a genuine timeout/reset merely because close raced
        # with it. Only a closed local descriptor, while stopping, proves this
        # particular failure came from teardown rather than the destination.
        if not (self._stopped.is_set() or self.cancel.is_set()):
            return False
        if not any(connection is not None and connection.fileno() < 0 for connection in sockets):
            return False
        if isinstance(error, ValueError):
            return selecting
        return error.errno in {errno.EBADF, errno.ENOTSOCK, 10038}

    def _charge(self, amount: int) -> None:
        with self._lock:
            if self.wire_bytes + amount > self.max_wire_bytes:
                raise FxfetchError("browser_wire_limit", "Browser wire budget reached")
            self.wire_bytes += amount

    def _handle(self, client: socket.socket) -> None:
        if not self._slots.acquire(blocking=False):
            client.close()
            self._record_error("browser_connection_limit", "")
            return
        remote: socket.socket | None = None
        url = ""
        connected = False
        established = False
        selecting = False
        body_remaining = 0
        try:
            with self._lock:
                self._sockets.add(client)
                if self.connections >= self.max_connections:
                    raise FxfetchError("request_limit", "Browser connection budget reached")
                self.connections += 1
            client.settimeout(min(2.0, self._check()))
            headers = bytearray()
            while not headers.endswith(b"\r\n\r\n"):
                if len(headers) >= HEADER_LIMIT:
                    raise FxfetchError("request_header_limit", "Browser headers exceed limit")
                self._check()
                block = client.recv(1)
                if not block:
                    return
                headers.extend(block)
            try:
                rows = headers.decode("latin-1").split("\r\n")
                method, target, version = rows[0].split(" ")
            except ValueError as error:
                raise FxfetchError("invalid_request", "Invalid browser request") from error
            if version != "HTTP/1.1":
                raise FxfetchError("invalid_request", "Unsupported proxy request version")
            if method == "CONNECT":
                if any(mark in target for mark in ("/", "?", "#", "@")):
                    raise FxfetchError("invalid_url", "Invalid CONNECT authority")
                url = validate_url("https://" + target + "/")
                forward = None
            else:
                if method not in {"GET", "HEAD", "POST", "OPTIONS"}:
                    raise FxfetchError("browser_method_unsupported", "Unsupported browser method")
                url = validate_url(target)
                parts = urlsplit(url)
                if parts.scheme != "http":
                    raise FxfetchError("invalid_url", "HTTPS requires a CONNECT tunnel")
                request_headers = []
                hosts = []
                lengths = []
                for row in rows[1:-2]:
                    if not row or row[:1].isspace() or ":" not in row:
                        raise FxfetchError("invalid_header", "Invalid browser request header")
                    key, value = row.split(":", 1)
                    if key.lower() == "host":
                        hosts.append(value.strip().lower())
                    if key.lower() in {"transfer-encoding", "upgrade"}:
                        raise FxfetchError("browser_http_body_unsupported", "Chunked or upgraded browser requests are outside the permitted HTTP stream")
                    if key.lower() == "content-length":
                        lengths.append(value.strip())
                    if key.lower() not in {"proxy-connection", "proxy-authorization", "connection"}:
                        request_headers.append(row)
                if hosts != [parts.netloc.lower()]:
                    raise FxfetchError("invalid_header", "HTTP authority mismatch")
                if len(lengths) > 1 or (lengths and not re.fullmatch(r"[0-9]{1,12}", lengths[0])):
                    raise FxfetchError("invalid_header", "Invalid HTTP request body length")
                body_remaining = int(lengths[0]) if lengths else 0
                if body_remaining > self.max_wire_bytes:
                    raise FxfetchError("browser_wire_limit", "HTTP request body exceeds the wire budget")
                path = parts.path or "/"
                if parts.query:
                    path += "?" + parts.query
                forward = (
                    f"{method} {path} HTTP/1.1\r\n"
                    + "\r\n".join(request_headers)
                    + "\r\nConnection: close\r\n\r\n"
                ).encode("latin-1")
            # This central check cannot be bypassed by a destination resolver
            # override. No DNS lookup or upstream socket exists before it.
            self._authorize_request(url, method)
            address, port = self._destination(url)
            remote = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
            with self._lock:
                self._sockets.add(remote)
            remote.settimeout(min(10.0, self._check()))
            remote.connect((address, port))
            connected = True
            if ipaddress.ip_address(remote.getpeername()[0]) != ipaddress.ip_address(address):
                raise FxfetchError("peer_mismatch", "Browser TCP peer differs from validated IP")
            if forward is None:
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                self._charge(len(forward))
                remote.sendall(forward)
            established = True
            if self.on_event:
                self.on_event({"event": "browser_connection", "url": url, "requested_ip": address})
            for connection in (client, remote):
                connection.settimeout(1.0)
            while True:
                self._check()
                # One cleartext request per connection. Never relay a pipelined
                # second request as opaque body bytes past the permit check.
                sources = [remote]
                if forward is None or body_remaining:
                    sources.append(client)
                selecting = True
                readable, _, _ = select.select(sources, [], [], 0.1)
                selecting = False
                for source in readable:
                    size = min(BLOCK, body_remaining) if source is client and forward is not None else BLOCK
                    block = source.recv(size)
                    if not block:
                        return
                    self._charge(len(block))
                    if source is client and forward is not None:
                        body_remaining -= len(block)
                    destination = remote if source is client else client
                    destination.sendall(block)
        except FxfetchError as error:
            self._record_error(error.code, url, connected=connected)
            if not established:
                try:
                    client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                except OSError:
                    pass  # Browser may already have cancelled the request.
        except (OSError, ValueError) as error:
            if self._closed_socket_error(error, (client, remote), selecting=selecting):
                if self.cancel.is_set():
                    self._record_error("cancelled", url, connected=connected)
            else:
                self._record_error("browser_transport_failed", url, connected=connected)
        finally:
            for connection in (client, remote):
                if connection is not None:
                    with self._lock:
                        self._sockets.discard(connection)
                    connection.close()
            self._slots.release()
