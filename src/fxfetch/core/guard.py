"""Offline URL validation and connection-time public address validation."""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import quote, urlsplit, urlunsplit

from .errors import FxfetchError


def validate_url(url: str) -> str:
    try:
        if not url or len(url.encode("utf-8")) > 8192 or re.search(r"[\x00-\x20\x7f\\]", url):
            raise FxfetchError("invalid_url", "URL contains forbidden characters or exceeds limit")
        parts = urlsplit(url)
        if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
            raise ValueError("HTTP(S) host required")
        if parts.username is not None or parts.password is not None or "%" in parts.netloc:
            raise ValueError("userinfo and scoped hosts forbidden")
        host = parts.hostname
        port = parts.port
        if parts.netloc.endswith(":"):
            raise ValueError("empty port")
        if not host or (port is not None and not 1 <= port <= 65535):
            raise ValueError("invalid host or port")
        try:
            address = ipaddress.ip_address(host)
            host = f"[{address}]" if address.version == 6 else str(address)
        except ValueError:
            host = host.encode("idna").decode("ascii").lower()
            if len(host) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in host.rstrip(".").split(".")
            ):
                raise ValueError("invalid hostname") from None
        authority = host + (f":{port}" if port is not None else "")
        # Preserve existing escapes, reserved delimiters and their case. Only
        # encode characters which cannot occur literally in an ASCII URI.
        path = quote(parts.path or "/", safe="/:@!$&'()*+,;=-._~%[]")
        query = quote(parts.query, safe="/?:@!$&'()*+,;=-._~%[]")
        return urlunsplit((parts.scheme.lower(), authority, path, query, ""))
    except UnicodeError as exc:
        raise FxfetchError("invalid_url", "URL cannot be safely encoded") from exc
    except ValueError as exc:
        raise FxfetchError("invalid_url", str(exc)) from exc


def is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped or ip.sixtofour or ip.teredo:
            return False
    return ip.is_global and not (ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def resolve_public(host: str, port: int) -> tuple[str, ...]:
    try:
        addresses = tuple(
            dict.fromkeys(str(item[4][0]) for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        )
    except OSError as exc:
        raise FxfetchError("dns_failed", "DNS resolution failed") from exc
    if not addresses or any(not is_public(address) for address in addresses):
        raise FxfetchError("target_not_public", "All resolved addresses must be confirmed public")
    return addresses
