"""Explicit pinned HTTPS public DNS; never used by the default system resolver."""

from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
from collections.abc import Callable
from urllib.parse import urlencode, urlsplit

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype

from .errors import FxfetchError
from .guard import is_public, validate_url
from .proxy import LocalConnectProxy

MAX_RESPONSE_BYTES = 64 * 1024
ENDPOINTS = {
    "alidns": ("dns.alidns.com", "223.5.5.5", "/dns-query"),
    "dnspod": ("doh.pub", "119.29.29.29", "/dns-query"),
    "cloudflare": ("cloudflare-dns.com", "1.1.1.1", "/dns-query"),
    "google": ("dns.google", "8.8.8.8", "/resolve"),
}
Transport = Callable[[str, str, str, float], bytes]


def _request(
    host: str, address: str, path: str, timeout: float, proxy: LocalConnectProxy | None = None
) -> bytes:
    """No implicit proxy, DNS, redirects, alternate addresses, or untrusted TLS context."""
    deadline = time.monotonic() + timeout
    sock = (
        proxy.tunnel(address, 443, min(10.0, timeout))
        if proxy
        else socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    )
    connection = http.client.HTTPConnection(host, 443)
    response: http.client.HTTPResponse | None = None

    def interrupt() -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass  # Already closed or not connected; the bounded connect handles that case.

    timer = threading.Timer(timeout, interrupt)
    timer.daemon = True
    timer.start()

    def remaining() -> float:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("Public DNS request budget exceeded")
        return min(10.0, left)

    try:
        sock.settimeout(remaining())
        if proxy is None:
            sock.connect((address, 443))
        sock.settimeout(remaining())
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        connection.sock = sock
        sock.settimeout(remaining())
        connection.request(
            "GET",
            path,
            headers={
                "Host": host,
                "Accept": "application/dns-message" if "?dns=" in path else "application/dns-json",
                "Accept-Encoding": "identity",
            },
        )
        sock.settimeout(remaining())
        # Own response lifetime explicitly, including HTTP/1.0/Connection: close.
        response = http.client.HTTPResponse(sock)
        response.begin()
        if response.status != 200 or response.getheader("Content-Encoding", "identity") != "identity":
            raise FxfetchError("dns_failed", "Public DNS returned an unsupported HTTP response")
        content_length = response.getheader("Content-Length")
        if content_length is not None and (
            not content_length.isdigit() or int(content_length) > MAX_RESPONSE_BYTES
        ):
            raise FxfetchError("dns_invalid_response", "Public DNS response exceeds size limit")
        body = bytearray()
        while True:
            sock.settimeout(remaining())
            chunk = response.read1(min(8192, MAX_RESPONSE_BYTES + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > MAX_RESPONSE_BYTES:
                raise FxfetchError("dns_invalid_response", "Public DNS response exceeds size limit")
        if content_length is not None and len(body) != int(content_length):
            raise FxfetchError("dns_invalid_response", "Public DNS response was truncated")
        return bytes(body)
    finally:
        timer.cancel()
        if response is not None:
            response.close()
        connection.close()
        sock.close()


class PublicDNSResolver:
    def __init__(
        self,
        endpoint: str = "alidns",
        *,
        transport: Transport | None = None,
        proxy: LocalConnectProxy | None = None,
    ) -> None:
        if endpoint not in ENDPOINTS:
            raise ValueError("Choose an explicitly supported public DNS endpoint")
        self.endpoint = endpoint
        self.proxy = proxy
        self._transport: Transport = transport or (
            lambda host, address, path, timeout: _request(host, address, path, timeout, proxy)
        )
        self.last_records: list[dict[str, object]] = []

    def resolve(self, host: str, port: int) -> tuple[str, ...]:
        self.last_records = []
        authority = f"[{host}]" if ":" in host else host
        normalized = urlsplit(validate_url(f"https://{authority}:{port}/")).hostname
        assert normalized is not None
        try:
            ipaddress.ip_address(normalized)
        except ValueError:
            pass
        else:
            raise FxfetchError("target_not_public", "Public DNS requires a hostname")
        normalized = normalized.rstrip(".")
        if "." not in normalized or normalized.endswith((".localhost", ".local", ".internal", ".home.arpa")):
            raise FxfetchError("target_not_public", "Public DNS requires a public hostname")
        deadline = time.monotonic() + 20.0
        return self._resolve_normalized(normalized, deadline)

    def _resolve_normalized(self, normalized: str, deadline: float) -> tuple[str, ...]:
        hostname, address, path = ENDPOINTS[self.endpoint]
        addresses: list[str] = []
        try:
            for query_type in ("A", "AAAA"):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Public DNS resolution budget exceeded")
                wire = self.endpoint in ("alidns", "dnspod")
                query = dns.message.make_query(normalized, query_type)
                query_path = (
                    path + "?dns=" + base64.urlsafe_b64encode(query.to_wire()).rstrip(b"=").decode("ascii")
                    if wire
                    else path + "?" + urlencode({"name": normalized, "type": query_type})
                )
                raw = self._transport(hostname, address, query_path, remaining)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise FxfetchError("dns_invalid_response", "Oversized DNS response")
                found = self._wire_answers(raw, query) if wire else self._json_answers(raw)
                self.last_records.append(
                    {
                        "endpoint": self.endpoint,
                        "host": normalized,
                        "query_type": query_type,
                        "status": 0,
                        "addresses": tuple(found),
                        "connection_source": "explicit_proxy_connect" if self.proxy else "direct",
                        "requested_ip": address,
                    }
                )
                addresses.extend(found)
        except (OSError, http.client.HTTPException) as exc:
            raise FxfetchError("dns_failed", "Public DNS resolution failed") from exc
        if not addresses:
            raise FxfetchError("dns_no_addresses", "Public DNS returned no addresses")
        return tuple(dict.fromkeys(addresses))

    @staticmethod
    def _public_values(values: list[str]) -> list[str]:
        try:
            found = [str(ipaddress.ip_address(value)) for value in values]
        except ValueError as exc:
            raise FxfetchError("dns_invalid_response", "Invalid DNS address") from exc
        if any(not is_public(value) for value in found):
            raise FxfetchError("target_not_public", "Public DNS returned an unsafe address")
        return found

    @staticmethod
    def _check_status(status: int) -> None:
        if status == dns.rcode.NXDOMAIN:
            raise FxfetchError("dns_nxdomain", "Public DNS reports NXDOMAIN")
        if status != dns.rcode.NOERROR:
            raise FxfetchError("dns_failed", "Public DNS service could not resolve the question")

    def _wire_answers(self, raw: bytes, query: dns.message.Message) -> list[str]:
        try:
            response = dns.message.from_wire(raw, ignore_trailing=False)
            if (
                not isinstance(response, dns.message.QueryMessage)
                or not query.is_response(response)
                or response.flags & dns.flags.TC
            ):
                raise FxfetchError("dns_invalid_response", "Inconsistent or truncated DNS response")
            values: list[str] = []
            for rrset in response.answer:
                if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    values.extend(record.to_text() for record in rrset)
            found = self._public_values(values)
            self._check_status(response.rcode())
            # Validate CNAME chaining; check every returned address even when unrelated.
            response.resolve_chaining()
            return found
        except dns.exception.DNSException as exc:
            raise FxfetchError("dns_invalid_response", "Malformed DNS response") from exc

    def _json_answers(self, raw: bytes) -> list[str]:
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict) or not isinstance(payload.get("Status"), int):
                raise ValueError("invalid DNS status")
            answers = payload.get("Answer", [])
            if not isinstance(answers, list) or any(not isinstance(item, dict) for item in answers):
                raise ValueError("invalid DNS answers")
            found = self._public_values(
                [str(item.get("data", "")) for item in answers if item.get("type") in (1, 28)]
            )
            self._check_status(payload["Status"])
            return found
        except (ValueError, UnicodeError) as exc:
            raise FxfetchError("dns_invalid_response", "Malformed DNS JSON response") from exc


class DefaultPublicDNSResolver:
    """User-selected AliDNS first, DNSPod backup only for transport/service failures."""

    def __init__(self, *, proxy: LocalConnectProxy | None = None, transport: Transport | None = None) -> None:
        self.proxy = proxy
        self.transport = transport
        self.last_records: list[dict[str, object]] = []

    def resolve(self, host: str, port: int) -> tuple[str, ...]:
        self.last_records = []
        deadline = time.monotonic() + 20.0
        for endpoint in ("alidns", "dnspod"):
            resolver = PublicDNSResolver(endpoint, proxy=self.proxy, transport=self.transport)
            # Allocate the first provider at most half the total budget.
            original = resolver._transport
            provider_deadline = min(deadline, time.monotonic() + (10.0 if endpoint == "alidns" else 20.0))

            def bounded(
                hostname: str,
                address: str,
                path: str,
                timeout: float,
                *,
                provider_deadline: float = provider_deadline,
                original: Transport = original,
            ) -> bytes:
                remaining = min(timeout, provider_deadline - time.monotonic())
                if remaining <= 0:
                    raise TimeoutError("Public DNS provider budget exceeded")
                return original(hostname, address, path, remaining)

            resolver._transport = bounded
            try:
                result = resolver.resolve(host, port)
            except FxfetchError as exc:
                self.last_records.extend(resolver.last_records)
                self.last_records.append(
                    {
                        "endpoint": endpoint,
                        "requested_ip": ENDPOINTS[endpoint][1],
                        "status": "failed",
                        "reason_code": exc.code,
                    }
                )
                if exc.code not in ("dns_failed", "proxy_failed", "proxy_timeout") or endpoint == "dnspod":
                    raise
            else:
                self.last_records.extend(resolver.last_records)
                return result
        raise FxfetchError("dns_failed", "Public DNS providers unavailable")
