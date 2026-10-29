"""Trusted server-side loopback CONNECT proxy configuration; never URL input."""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import dataclass

from .errors import FxfetchError
from .guard import is_public


@dataclass(frozen=True)
class LocalConnectProxy:
    host: str
    port: int

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError as exc:
            raise ValueError("Proxy must use a literal loopback address") from exc
        if not address.is_loopback or isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise ValueError("Proxy must use a loopback address and valid port")

    def tunnel(self, public_target_ip: str, port: int, timeout: float) -> socket.socket:
        try:
            address = ipaddress.ip_address(public_target_ip)
        except ValueError as exc:
            raise FxfetchError("target_not_public", "CONNECT requires a validated public IP") from exc
        if not is_public(str(address)) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise FxfetchError("target_not_public", "CONNECT requires a public IP and valid port")
        if timeout <= 0:
            raise FxfetchError("proxy_timeout", "CONNECT time budget exceeded")
        authority = f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"
        deadline = time.monotonic() + timeout
        sock = socket.socket(socket.AF_INET6 if ":" in self.host else socket.AF_INET, socket.SOCK_STREAM)

        def remaining() -> float:
            value = deadline - time.monotonic()
            if value <= 0:
                raise TimeoutError("CONNECT time budget exceeded")
            return min(10.0, value)

        try:
            sock.settimeout(remaining())
            sock.connect((self.host, self.port))
            if ipaddress.ip_address(sock.getpeername()[0]) != ipaddress.ip_address(self.host):
                raise FxfetchError("peer_mismatch", "Proxy peer differs from configured loopback IP")
            sock.settimeout(remaining())
            sock.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii"))
            headers = bytearray()
            while not headers.endswith(b"\r\n\r\n"):
                if len(headers) >= 16384:
                    raise FxfetchError("proxy_failed", "CONNECT response headers exceed limit")
                sock.settimeout(remaining())
                chunk = sock.recv(1)
                if not chunk:
                    raise FxfetchError("proxy_failed", "CONNECT response was truncated")
                headers.extend(chunk)
            if re.fullmatch(rb"HTTP/1\.[01] 200(?: [^\r\n]*)?", bytes(headers).split(b"\r\n", 1)[0]) is None:
                raise FxfetchError("proxy_failed", "CONNECT proxy did not establish a tunnel")
            return sock
        except (OSError, FxfetchError):
            sock.close()
            raise
