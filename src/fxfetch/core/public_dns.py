"""Explicit pinned HTTPS public DNS; never used by the default system resolver."""

from __future__ import annotations

import base64
import hashlib
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
import dns.name
import dns.rcode
import dns.rdatatype

from .errors import FxfetchError
from .guard import is_public, validate_url
from .proxy import LocalConnectProxy

MAX_RESPONSE_BYTES = 64 * 1024
MAX_ANSWER_RECORDS = 128
MAX_CNAME_HOPS = 16
MAX_DNS_RECORD_BYTES = 24 * 1024
ENDPOINTS = {
    "alidns": ("dns.alidns.com", "223.5.5.5", "/dns-query"),
    "dnspod": ("doh.pub", "119.29.29.29", "/dns-query"),
    "cloudflare": ("cloudflare-dns.com", "1.1.1.1", "/dns-query"),
    "google": ("dns.google", "8.8.8.8", "/resolve"),
}
Transport = Callable[[str, str, str, float], bytes]


def bounded_dns_records(records: object) -> list[dict[str, object]]:
    """Allowlisted diagnostic projection; never emit a raw provider payload."""
    if not isinstance(records, (list, tuple)):
        return []
    result: list[dict[str, object]] = []
    text_limits = {"provider": 32, "endpoint": 32, "host": 253, "query_type": 8,
                   "reason_code": 64, "connection_source": 32, "requested_ip": 64,
                   "response_sha256": 64}
    for source in records[:8]:
        if not isinstance(source, dict):
            continue
        row: dict[str, object] = {}
        for key, maximum in text_limits.items():
            value = source.get(key)
            if isinstance(value, str) and len(value) <= maximum:
                row[key] = value
        for key, maximum in (("rcode", 4095), ("response_size", MAX_RESPONSE_BYTES)):
            value = source.get(key)
            if value is None or type(value) is int and 0 <= value <= maximum:
                row[key] = value
        if type(source.get("status")) is int and source["status"] == 0 or source.get("status") in ("pending", "rejected", "failed"):
            row["status"] = source["status"]
        if source.get("answers_truncated") is True:
            row["answers_truncated"] = True
        values = source.get("addresses", ())
        if isinstance(values, (list, tuple)):
            row["addresses"] = tuple(value for value in values[:MAX_ANSWER_RECORDS]
                                     if isinstance(value, str) and len(value) <= 64)
        answers = source.get("answers", [])
        if isinstance(answers, list):
            projected = []
            for answer in answers[:MAX_ANSWER_RECORDS]:
                if not isinstance(answer, dict):
                    continue
                item = {key: value for key in ("name", "type", "data", "classification")
                        if isinstance((value := answer.get(key)), str) and len(value) <= 255}
                for key in ("selected", "query_match"):
                    if type(answer.get(key)) is bool:
                        item[key] = answer[key]
                projected.append(item)
            row["answers"] = projected
            row["answers_omitted_count"] = len(answers) - len(projected)
        if "response_sha256" in row:
            row["response_digest_scope"] = "dns_response_bytes"
            row["response_body_saved"] = False
        # Match the journal's ASCII JSON encoding, including escaping. Keep the
        # entire diagnostic field below its 32 KiB limit even for long owners.
        while len(json.dumps(row, ensure_ascii=True, separators=(",", ":")).encode("ascii")) > MAX_DNS_RECORD_BYTES:
            projected_answers = row.get("answers")
            addresses = row.get("addresses")
            if isinstance(projected_answers, list) and projected_answers:
                projected_answers.pop()
                omitted_count = row.get("answers_omitted_count", 0)
                row["answers_omitted_count"] = (omitted_count if isinstance(omitted_count, int) else 0) + 1
                row["answers_truncated"] = True
            elif isinstance(addresses, tuple) and addresses:
                row["addresses"] = addresses[:-1]
                omitted_count = row.get("addresses_omitted_count", 0)
                row["addresses_omitted_count"] = (omitted_count if isinstance(omitted_count, int) else 0) + 1
            else:
                break  # Allowlisted scalar fields together are below this bound.
        result.append(row)
    return result


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
                record: dict[str, object] = {
                    "endpoint": self.endpoint, "provider": self.endpoint, "host": normalized,
                    "query_type": query_type, "rcode": None, "status": "pending",
                    "answers": [], "addresses": (),
                    "connection_source": "explicit_proxy_connect" if self.proxy else "direct",
                    "requested_ip": address,
                }
                self.last_records.append(record)
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
                record.update(response_size=len(raw), response_sha256=hashlib.sha256(raw).hexdigest())
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise FxfetchError("dns_invalid_response", "Oversized DNS response")
                found = self._wire_answers(raw, query, record) if wire else self._json_answers(raw, query, record)
                record.update(status=0, addresses=tuple(found), reason_code="dns_answer_accepted")
                addresses.extend(found)
        except FxfetchError as exc:
            record.update(status="rejected", reason_code=exc.code)
            exc.__dict__["dns_records"] = list(self.last_records)
            raise
        except ssl.SSLCertVerificationError as exc:
            record.update(status="rejected", reason_code="dns_tls_verification_failed")
            failure = FxfetchError("dns_tls_verification_failed", "Public DNS TLS certificate verification failed")
            failure.__dict__["dns_records"] = list(self.last_records)
            raise failure from exc
        except (OSError, http.client.HTTPException) as exc:
            record.update(status="failed", reason_code="dns_failed")
            failure = FxfetchError("dns_failed", "Public DNS resolution failed")
            failure.__dict__["dns_records"] = list(self.last_records)
            raise failure from exc
        if not addresses:
            failure = FxfetchError("dns_no_addresses", "Public DNS returned no question-matched addresses")
            failure.__dict__["dns_records"] = list(self.last_records)
            raise failure
        return tuple(dict.fromkeys(addresses))

    @staticmethod
    def _public_values(values: list[str]) -> list[str]:
        try:
            found = [str(ipaddress.ip_address(value)) for value in values]
        except ValueError as exc:
            raise FxfetchError("dns_invalid_response", "Invalid DNS address") from exc
        if any(not is_public(value) for value in found):
            raise FxfetchError("dns_unsafe_answer", "Public DNS response contains an unsafe address")
        return found

    @staticmethod
    def _check_status(status: int) -> None:
        if status == dns.rcode.NXDOMAIN:
            raise FxfetchError("dns_nxdomain", "Public DNS reports NXDOMAIN")
        if status != dns.rcode.NOERROR:
            raise FxfetchError("dns_failed", "Public DNS service could not resolve the question")

    @staticmethod
    def _classification(address: str) -> str:
        try:
            value = ipaddress.ip_address(address)
        except ValueError:
            return "invalid_address"
        if isinstance(value, ipaddress.IPv6Address) and (value.ipv4_mapped or value.sixtofour or value.teredo):
            return "ipv6_transition"
        if is_public(str(value)):
            return "public"
        for attribute, label in (("is_loopback", "loopback"), ("is_link_local", "link_local"),
                                 ("is_multicast", "multicast"), ("is_unspecified", "unspecified"),
                                 ("is_reserved", "reserved"), ("is_private", "private")):
            if getattr(value, attribute):
                return label
        return "non_public"

    @staticmethod
    def _name(value: str) -> str:
        name = dns.name.from_text(value).canonicalize().to_text()
        if len(name) > 255:
            raise FxfetchError("dns_invalid_response", "DNS owner name exceeds limit")
        return name

    def _select_answers(self, rows: list[dict[str, object]], query: dns.message.Message,
                        status: int, evidence: dict[str, object]) -> list[str]:
        evidence["rcode"] = status
        evidence["answers"] = rows[:MAX_ANSWER_RECORDS]
        values: list[str] = []
        for row in rows:
            row["selected"] = False
            if row["type"] in ("A", "AAAA"):
                value = str(row["data"])
                row["classification"] = self._classification(value)
                values.append(value)
            else:
                row["classification"] = "alias" if row["type"] == "CNAME" else "other_record"
        if len(rows) > MAX_ANSWER_RECORDS:
            evidence["answers_truncated"] = True
            raise FxfetchError("dns_invalid_response", "DNS answer count exceeds limit")
        # Security applies to every returned address, even unrelated injection.
        self._public_values(values)
        self._check_status(status)
        name = self._name(query.question[0].name.to_text())
        wanted = dns.rdatatype.to_text(query.question[0].rdtype)
        seen: set[str] = set()
        for _ in range(MAX_CNAME_HOPS + 1):
            if name in seen:
                raise FxfetchError("dns_invalid_response", "DNS CNAME cycle")
            seen.add(name)
            aliases = {str(row["data"]) for row in rows if row["name"] == name and row["type"] == "CNAME"}
            address_rows = [row for row in rows if row["name"] == name and row["type"] in ("A", "AAAA")]
            if len(aliases) > 1 or (aliases and address_rows):
                raise FxfetchError("dns_invalid_response", "DNS CNAME owner has conflicting answers")
            if not aliases:
                for row in rows:
                    row["query_match"] = row["name"] in seen
                    row["selected"] = row["name"] == name and row["type"] == wanted
                return [str(row["data"]) for row in rows if row["selected"]]
            name = next(iter(aliases))
        raise FxfetchError("dns_invalid_response", "DNS CNAME hop limit exceeded")

    def _wire_answers(self, raw: bytes, query: dns.message.Message,
                      evidence: dict[str, object] | None = None) -> list[str]:
        evidence = {} if evidence is None else evidence
        try:
            response = dns.message.from_wire(raw, ignore_trailing=False, one_rr_per_rrset=True)
            evidence["rcode"] = response.rcode()
            if (
                not isinstance(response, dns.message.QueryMessage)
                or not query.is_response(response)
                or response.flags & dns.flags.TC
            ):
                raise FxfetchError("dns_invalid_response", "Inconsistent or truncated DNS response")
            rows: list[dict[str, object]] = []
            for rrset in response.answer:
                if rrset.rdclass != 1:
                    raise FxfetchError("dns_invalid_response", "Unexpected DNS answer class")
                for item in rrset:
                    kind = dns.rdatatype.to_text(rrset.rdtype)
                    row: dict[str, object] = {"name": self._name(rrset.name.to_text()), "type": kind}
                    if kind in ("A", "AAAA"):
                        row["data"] = item.to_text()
                    elif kind == "CNAME":
                        row["data"] = self._name(item.to_text())
                    rows.append(row)
                    if len(rows) > MAX_ANSWER_RECORDS:
                        return self._select_answers(rows, query, response.rcode(), evidence)
            return self._select_answers(rows, query, response.rcode(), evidence)
        except dns.exception.DNSException as exc:
            raise FxfetchError("dns_invalid_response", "Malformed DNS response") from exc

    def _json_answers(self, raw: bytes, query: dns.message.Message,
                      evidence: dict[str, object] | None = None) -> list[str]:
        evidence = {} if evidence is None else evidence
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict) or type(payload.get("Status")) is not int:
                raise ValueError("invalid DNS status")
            status = payload["Status"]
            evidence["rcode"] = status
            if not 0 <= status <= 4095 or payload.get("TC") is True:
                raise ValueError("invalid DNS response flags")
            question = payload.get("Question")
            if (not isinstance(question, list) or len(question) != 1 or not isinstance(question[0], dict)
                    or type(question[0].get("type")) is not int
                    or question[0]["type"] != query.question[0].rdtype
                    or not isinstance(question[0].get("name"), str)
                    or self._name(question[0]["name"]) != self._name(query.question[0].name.to_text())):
                raise ValueError("DNS question mismatch")
            answers = payload.get("Answer", [])
            if not isinstance(answers, list) or any(not isinstance(item, dict) for item in answers):
                raise ValueError("invalid DNS answers")
            rows: list[dict[str, object]] = []
            for item in answers[:MAX_ANSWER_RECORDS + 1]:
                if not isinstance(item.get("name"), str) or type(item.get("type")) is not int:
                    raise ValueError("invalid DNS answer owner")
                kind = dns.rdatatype.to_text(item["type"])
                row: dict[str, object] = {"name": self._name(item["name"]), "type": kind}
                if kind in ("A", "AAAA", "CNAME"):
                    if not isinstance(item.get("data"), str) or len(item["data"]) > 255:
                        raise ValueError("invalid DNS answer data")
                    row["data"] = self._name(item["data"]) if kind == "CNAME" else item["data"]
                    if kind in ("A", "AAAA") and ipaddress.ip_address(str(row["data"])).version != (4 if kind == "A" else 6):
                        raise ValueError("DNS address type mismatch")
                rows.append(row)
            return self._select_answers(rows, query, status, evidence)
        except (ValueError, UnicodeError, dns.exception.DNSException) as exc:
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
                    exc.__dict__["dns_records"] = list(self.last_records)
                    raise
            else:
                self.last_records.extend(resolver.last_records)
                return result
        raise FxfetchError("dns_failed", "Public DNS providers unavailable")
