"""Direct, pinned HTTP GET transport. Call only after explicit task authorization."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import os
import socket
import ssl
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial as bind_callback
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit
from urllib.request import Request

from .download import is_package_prefix
from .errors import FxfetchError
from .guard import is_public, resolve_public, validate_url
from .limits import Limits
from .proxy import LocalConnectProxy

_DEFAULT_LIMITS = Limits()
MAX_RESPONSE_HEADER_BYTES = 64 * 1024
MAX_EVIDENCE_HEADER_BYTES = 16 * 1024
EVIDENCE_HEADERS = frozenset(
    {
        "content-type",
        "content-length",
        "content-disposition",
        "content-encoding",
        "transfer-encoding",
        "location",
        "server",
        "date",
        "etag",
        "last-modified",
        "cache-control",
        "www-authenticate",
        "retry-after",
    }
)


class _SingleRequestConnection(http.client.HTTPConnection):
    def close(self) -> None:
        # Keep our socket live until the bounded response reader has finished,
        # including HTTP/1.0 and Connection: close responses.
        self.sock = None


@dataclass(frozen=True)
class Hop:
    url: str
    status: int
    headers: dict[str, str]
    connection_ip: str
    tls_der_sha256: str | None
    connection_source: str = "direct"
    requested_ip: str | None = None
    connection_attempts: tuple[dict[str, str], ...] = ()


@dataclass(frozen=True)
class FetchedResponse:
    url: str
    status: int
    headers: dict[str, str]
    path: Path
    size: int
    sha256: str
    hops: tuple[Hop, ...]
    request_ref: str | None = None


class HttpClient:
    def __init__(
        self,
        limits: Limits = _DEFAULT_LIMITS,
        *,
        resolver: Callable[[str, int], tuple[str, ...]] | None = None,
        proxy: LocalConnectProxy | None = None,
        dns_timeout: float | None = None,
        transport_observer: Callable[[dict[str, object]], None] | None = None,
    ) -> None:
        self.limits = limits
        self.resolver = resolver
        self.proxy = proxy
        self.dns_timeout = limits.connect_timeout if dns_timeout is None else dns_timeout
        self.transport_observer = transport_observer

    def _resolve(self, host: str, port: int) -> tuple[str, ...]:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            if not is_public(str(literal)):
                raise FxfetchError("target_not_public", "Literal target address must be confirmed public")
            return (str(literal),)
        addresses = (self.resolver or resolve_public)(host, port)
        try:
            valid = bool(addresses) and all(is_public(address) for address in addresses)
        except ValueError:
            valid = False
        if not valid:
            raise FxfetchError("target_not_public", "All resolved addresses must be confirmed public")
        return addresses

    def _tls_context(self) -> ssl.SSLContext:
        return ssl.create_default_context()

    def _connect(self, host: str, port: int, address: str, secure: bool, timeout: float) -> socket.socket:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        started = time.monotonic()
        sock = (
            self.proxy.tunnel(address, port, timeout)
            if self.proxy
            else socket.socket(family, socket.SOCK_STREAM)
        )
        try:
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError("Connection time budget exceeded")
            sock.settimeout(remaining)
            if not self.proxy:
                sock.connect((address, port))
            if not self.proxy and ipaddress.ip_address(sock.getpeername()[0]) != ipaddress.ip_address(
                address
            ):
                raise FxfetchError("peer_mismatch", "Connected peer differs from validated address")
            if secure:
                return self._tls_context().wrap_socket(sock, server_hostname=host)
            return sock
        except (OSError, FxfetchError):
            sock.close()
            raise

    def fetch(
        self,
        url: str,
        destination: Path,
        *,
        user_agent: str,
        cookie_jar: CookieJar,
        cancel: threading.Event,
        referer: str | None = None,
        on_event: Callable[[dict[str, object]], None] | None = None,
        on_transport_event: Callable[[dict[str, object]], None] | None = None,
        package_streaming: bool = True,
        body_limit_bytes: int | None = None,
    ) -> FetchedResponse:
        current = validate_url(url)
        if any(c in user_agent for c in "\r\n"):
            raise FxfetchError("invalid_header", "Invalid user agent")
        initial_origin = (urlsplit(current).scheme, urlsplit(current).netloc)
        safe_referer = validate_url(referer) if referer else None
        start = time.monotonic()
        hops: list[Hop] = []
        visited: set[str] = set()

        def emit(event: str, **details: object) -> None:
            if on_event is not None:
                on_event({"event": event, "url": current, **details})

        def emit_transport(event: str, **details: object) -> None:
            value: dict[str, object] = {"kind": event, **details}
            observer = self.transport_observer
            if observer is not None:
                try:
                    observer(value)
                except Exception:
                    failed = getattr(observer, "mark_failed", None)
                    if callable(failed):
                        try:
                            failed("transport_observer_failed")
                        except Exception:
                            pass
            if on_transport_event is not None and on_transport_event != observer:
                try:
                    on_transport_event(value)
                except Exception:
                    failed = getattr(on_transport_event, "mark_failed", None)
                    if callable(failed):
                        try:
                            failed("transport_observer_failed")
                        except Exception:
                            pass

        partial = destination.with_name(destination.name + ".partial")
        if destination.exists() or partial.exists():
            raise FxfetchError("destination_exists", "Destination or partial already exists")

        def check() -> float:
            if cancel.is_set():
                error = FxfetchError("cancelled", "Download cancelled")
                error.__dict__["hops"] = tuple(hops)
                raise error
            remaining = self.limits.chain_timeout - (time.monotonic() - start)
            if remaining <= 0:
                error = FxfetchError("chain_timeout", "Download time budget exceeded")
                error.__dict__["hops"] = tuple(hops)
                raise error
            return remaining

        def resolve(host: str, port: int) -> tuple[str, ...]:
            completed = threading.Event()
            result: list[tuple[str, ...]] = []
            errors: list[Exception] = []

            def run() -> None:
                try:
                    result.append(self._resolve(host, port))
                except Exception as exc:
                    errors.append(exc)
                finally:
                    completed.set()

            threading.Thread(target=run, daemon=True, name="fxfetch-dns").start()
            deadline = time.monotonic() + self.dns_timeout
            while not completed.wait(0.05):
                check()
                if time.monotonic() >= deadline:
                    raise FxfetchError("dns_timeout", "DNS resolution exceeded time budget")
            check()
            if errors:
                raise errors[0]
            return result[0]

        active_progress: Callable[[], None] | None = None
        transfer_complete = False
        active_request_ref: str | None = None
        active_status: int | None = None
        active_headers: dict[str, str] = {}
        active_digest: Any = None
        active_size = 0
        active_package_stream = False
        try:
            for index in range(min(self.limits.max_redirects + 1, self.limits.max_requests)):
                check()
                if current in visited:
                    raise FxfetchError("redirect_cycle", "HTTP redirect loop detected")
                visited.add(current)
                request_id = f"http-{uuid.uuid4().hex}"
                active_request_ref = request_id
                active_status = None
                active_headers = {}
                active_digest = None
                active_size = 0
                active_package_stream = False
                emit("request", request_id=request_id)
                emit_transport(
                    "request_attempted", request_ref=request_id, url=current, method="GET"
                )
                parts = urlsplit(current)
                host = parts.hostname
                assert host is not None
                secure = parts.scheme == "https"
                port = parts.port or (443 if secure else 80)
                addresses = resolve(host, port)
                check()
                # Only a failed connection before any HTTP request may try another
                # already validated DNS address. Never replay a request/body here.
                connection_attempts: list[dict[str, str]] = []
                sock: socket.socket | None = None
                selected_address = addresses[0]
                for address in tuple(dict.fromkeys(addresses))[:4]:
                    selected_address = address
                    try:
                        sock = self._connect(
                            host, port, address, secure, min(check(), self.limits.connect_timeout)
                        )
                        connection_attempts.append({"ip": address, "outcome": "connected"})
                        break
                    except ssl.SSLCertVerificationError:
                        # Identity verification must never be relaxed or retried
                        # through another endpoint. A plain handshake interruption
                        # is handled below as a connection failure before any GET.
                        raise
                    except FxfetchError:
                        raise
                    except OSError as error:
                        connection_attempts.append(
                            {
                                "ip": address,
                                "outcome": "failed",
                                "reason_code": "tls_handshake_failed"
                                if isinstance(error, ssl.SSLError)
                                else "network_timeout"
                                if isinstance(error, TimeoutError)
                                else "connection_failed",
                            }
                        )
                        check()
                        if len(connection_attempts) >= min(4, len(set(addresses))):
                            raise
                assert sock is not None
                stopped = threading.Event()

                def interrupt_wait(stop_event: threading.Event, connection_socket: socket.socket) -> None:
                    while not stop_event.wait(0.05):
                        if cancel.is_set() or time.monotonic() - start >= self.limits.chain_timeout:
                            try:
                                connection_socket.shutdown(socket.SHUT_RDWR)
                            except OSError:
                                return
                            return

                watcher = threading.Thread(
                    target=interrupt_wait, args=(stopped, sock), daemon=True, name="fxfetch-transfer-budget"
                )
                watcher.start()
                connection = _SingleRequestConnection(host, port)
                connection.sock = sock
                response: http.client.HTTPResponse | None = None
                try:
                    connection_ip = sock.getpeername()[0]
                    certificate = (
                        sock.getpeercert(binary_form=True) if isinstance(sock, ssl.SSLSocket) else None
                    )
                    sock.settimeout(min(check(), self.limits.read_timeout))
                    request = Request(
                        current, headers={"User-Agent": user_agent, "Accept-Encoding": "identity"}
                    )
                    cookie_jar.add_cookie_header(request)
                    headers = dict(request.header_items())
                    headers["Host"] = parts.netloc
                    referer_parts = urlsplit(safe_referer) if safe_referer else None
                    if (
                        safe_referer
                        and referer_parts is not None
                        and (parts.scheme, parts.netloc) == initial_origin
                        and (referer_parts.scheme, referer_parts.netloc) == initial_origin
                    ):
                        headers["Referer"] = safe_referer
                    target = parts.path or "/"
                    if parts.query:
                        target += "?" + parts.query
                    connection.request("GET", target, headers=headers)
                    response = connection.getresponse()
                    hops.append(
                        Hop(
                            current,
                            response.status,
                            {},
                            connection_ip,
                            hashlib.sha256(certificate).hexdigest() if certificate else None,
                            "explicit_proxy_connect" if self.proxy else "direct",
                            selected_address,
                            tuple(connection_attempts),
                        )
                    )
                    raw_headers = response.getheaders()
                    if (
                        sum(
                            len(key.encode("latin-1")) + len(value.encode("latin-1")) + 4
                            for key, value in raw_headers
                        )
                        > MAX_RESPONSE_HEADER_BYTES
                    ):
                        raise FxfetchError("response_header_limit", "Response headers exceed aggregate limit")
                    response_headers = {
                        key.lower(): value for key, value in raw_headers if key.lower() in EVIDENCE_HEADERS
                    }
                    active_status = response.status
                    active_headers = response_headers
                    if (
                        sum(len(key) + len(value) + 4 for key, value in response_headers.items())
                        > MAX_EVIDENCE_HEADER_BYTES
                    ):
                        raise FxfetchError(
                            "response_header_limit", "Evidence response headers exceed aggregate limit"
                        )
                    hops[-1] = Hop(
                        current,
                        response.status,
                        response_headers,
                        connection_ip,
                        hashlib.sha256(certificate).hexdigest() if certificate else None,
                        "explicit_proxy_connect" if self.proxy else "direct",
                        selected_address,
                        tuple(connection_attempts),
                    )
                    raw_location = response.getheader("Location")
                    resolved_location = None
                    emit("response_received", status=response.status,
                         content_type=response_headers.get("content-type", ""), request_id=request_id)
                    if self.transport_observer is not None or on_transport_event is not None:
                        emit_transport(
                            "response_observed",
                            request_ref=request_id,
                            url=current,
                            status=response.status,
                            headers=response_headers,
                            connection_ip=connection_ip,
                            requested_ip=selected_address,
                            tls_der_sha256=hashlib.sha256(certificate).hexdigest() if certificate else None,
                            location_raw=raw_location,
                            location_resolved=None,
                        )
                        if raw_location is not None:
                            try:
                                if len(raw_location) > 8192 or any(ord(char) < 32 for char in raw_location):
                                    raise ValueError("invalid Location")
                                resolved_location = urljoin(current, raw_location)
                            except (TypeError, ValueError):
                                emit_transport(
                                    "gap",
                                    request_ref=request_id,
                                    code="location_resolution_failed",
                                    url=current,
                                    location_raw=raw_location,
                                )
                            else:
                                emit_transport(
                                    "location_resolved",
                                    request_ref=request_id,
                                    url=current,
                                    location_raw=raw_location,
                                    location_resolved=resolved_location,
                                )
                    cookie_jar.extract_cookies(response, request)  # type: ignore[arg-type]
                    if response.status in (301, 302, 303, 307, 308) and raw_location:
                        if index >= self.limits.max_redirects:
                            raise FxfetchError("redirect_limit", "Redirect budget exceeded")
                        target_url = validate_url(urljoin(current, raw_location))
                        resolved_location = urljoin(current, raw_location)
                        emit_transport(
                            "redirect_observed",
                            request_ref=request_id,
                            from_url=current,
                            location_raw=raw_location,
                            resolved_target=resolved_location,
                        )
                        if target_url in visited:
                            raise FxfetchError("redirect_cycle", "HTTP redirect loop detected")
                        emit("redirect", from_url=current, to_url=target_url,
                             status=response.status, mechanism="http", request_id=request_id,
                             location_raw=raw_location)
                        current = target_url
                        continue
                    encoding = response.getheader("Content-Encoding", "identity").lower()
                    if encoding not in ("identity", ""):
                        raise FxfetchError(
                            "content_encoding_unsupported", "Server ignored identity encoding request"
                        )
                    lengths = response.headers.get_all("Content-Length", [])
                    if len(lengths) > 1 or (lengths and not lengths[0].isdigit()):
                        raise FxfetchError("invalid_length", "Invalid or duplicate Content-Length")
                    expected = int(lengths[0]) if lengths else None
                    transfer = response.getheader("Transfer-Encoding")
                    if transfer and (transfer.lower() != "chunked" or lengths):
                        raise FxfetchError("invalid_framing", "Unsupported or ambiguous response framing")
                    body_budget = (
                        min(self.limits.max_body_bytes, self.limits.max_package_bytes)
                        if not package_streaming
                        else self.limits.max_package_bytes
                    )
                    if body_limit_bytes is not None:
                        body_budget = min(body_budget, body_limit_bytes)
                    if expected is not None and expected > body_budget:
                        raise FxfetchError("download_limit", "Declared response exceeds byte limit")
                    size = 0
                    digest = hashlib.sha256()
                    active_digest = digest
                    # Sniff actual bytes, never grant the package budget based on MIME or suffix.
                    prefix = bytearray()
                    while len(prefix) < 4:
                        sock.settimeout(min(check(), self.limits.read_timeout))
                        block = response.read1(4 - len(prefix))
                        if not block:
                            break
                        prefix.extend(block)
                    package_prefix = is_package_prefix(bytes(prefix))
                    body_limit = (
                        body_budget
                        if package_prefix and package_streaming
                        else min(body_budget, self.limits.max_body_bytes)
                    )
                    active_package_stream = package_prefix and package_streaming
                    package_stream = active_package_stream and 200 <= response.status < 300
                    if package_stream:
                        emit("download_started", package_unverified=True,
                             received_bytes=len(prefix), total_bytes=expected)
                    last_progress = time.monotonic()
                    progress_state = {"size": 0}

                    def progress(
                        *, complete: bool = False, force: bool = False,
                        state: dict[str, int] = progress_state,
                        expected: int | None = expected, package_stream: bool = package_stream,
                    ) -> None:
                        nonlocal last_progress
                        now = time.monotonic()
                        if not force and now - last_progress < 1.0:
                            return
                        details: dict[str, object] = {
                            "received_bytes": state["size"], "total_bytes": expected,
                            "complete": complete, "package_unverified": package_stream,
                        }
                        if expected is not None and expected > 0:
                            details["percent"] = min(100.0, round(state["size"] * 100 / expected, 1))
                        emit("download_progress" if package_stream else "response_progress", **details)
                        last_progress = now

                    active_progress = bind_callback(progress, force=True)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with partial.open("xb") as output:
                        first = bytes(prefix[:body_limit])
                        output.write(first)
                        digest.update(first)
                        size += len(first)
                        active_size = size
                        progress_state["size"] = size
                        progress(force=True)
                        if len(prefix) > body_limit or (expected is not None and expected > body_limit):
                            raise FxfetchError("download_limit", "Response exceeds applicable body budget")
                        while True:
                            sock.settimeout(min(check(), self.limits.read_timeout))
                            data = response.read1(min(65536, body_limit - size + 1))
                            if not data:
                                break
                            allowed = data[: body_limit - size]
                            output.write(allowed)
                            digest.update(allowed)
                            size += len(allowed)
                            active_size = size
                            progress_state["size"] = size
                            progress()
                            if len(allowed) != len(data):
                                raise FxfetchError("download_limit", "Response exceeds byte limit")
                        check()
                        if expected is not None and size != expected:
                            raise FxfetchError("length_mismatch", "Response ended before declared length")
                        output.flush()
                        os.fsync(output.fileno())
                    partial.replace(destination)
                    transfer_complete = True
                    progress(complete=True, force=True)
                    emit("response_complete", status=response.status, size=size,
                         is_package_stream=package_stream)
                    emit_transport(
                        "response_body_saved",
                        request_ref=request_id,
                        url=current,
                        source_url=current,
                        status=response.status,
                        path=destination,
                        size=size,
                        sha256=digest.hexdigest(),
                        content_type=response_headers.get("content-type", ""),
                        representation="http_response_decoded",
                        complete=True,
                        package_stream=active_package_stream,
                    )
                    return FetchedResponse(
                        current,
                        response.status,
                        response_headers,
                        destination,
                        size,
                        digest.hexdigest(),
                        tuple(hops),
                        request_id,
                    )
                finally:
                    stopped.set()
                    watcher.join()
                    if response is not None:
                        response.close()
                    connection.close()
                    sock.close()
            raise FxfetchError("request_limit", "Request budget exceeded")
        except FxfetchError as exc:
            exc.__dict__["hops"] = tuple(hops)
            exc.__dict__["request_ref"] = active_request_ref
            raise
        except TimeoutError as exc:
            check()
            error = FxfetchError("network_timeout", "Connection or read timed out")
            error.__dict__["hops"] = tuple(hops)
            error.__dict__["request_ref"] = active_request_ref
            raise error from exc
        except ssl.SSLCertVerificationError as exc:
            error = FxfetchError("tls_verification_failed", "TLS certificate verification failed")
            error.__dict__["hops"] = tuple(hops)
            error.__dict__["request_ref"] = active_request_ref
            raise error from exc
        except ssl.SSLError as exc:
            error = FxfetchError("tls_handshake_failed", "TLS handshake failed")
            error.__dict__["hops"] = tuple(hops)
            raise error from exc
        except (OSError, http.client.HTTPException, ValueError) as exc:
            check()
            error = FxfetchError(
                "transfer_failed", "Transfer failed; partial bytes are not a completed response"
            )
            error.__dict__["hops"] = tuple(hops)
            raise error from exc
        finally:
            if (
                not transfer_complete
                and active_request_ref is not None
                and active_digest is not None
                and active_size > 0
                and partial.is_file()
            ):
                emit_transport(
                    "response_prefix_saved",
                    request_ref=active_request_ref,
                    url=current,
                    source_url=current,
                    status=active_status,
                    headers=active_headers,
                    path=partial,
                    size=active_size,
                    sha256=active_digest.hexdigest(),
                    content_type=active_headers.get("content-type", ""),
                    representation="http_response_prefix",
                    complete=False,
                    package_stream=active_package_stream,
                )
            if active_progress is not None and not transfer_complete:
                active_progress()
