"""Server-owned configuration; HTTP clients cannot override storage or limits."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .core.lan import validate_bind, validate_lan_networks
from .core.limits import Limits
from .core.proxy import LocalConnectProxy


@dataclass(frozen=True)
class Settings:
    root: Path
    password_hash: str
    allowed_hosts: tuple[str, ...] = ("127.0.0.1:8765", "localhost:8765")
    secure_cookie: bool = False
    session_seconds: int = 8 * 3600
    limits: Limits = field(default_factory=Limits)
    host: str = "127.0.0.1"
    port: int = 8765
    allowed_networks: tuple[str, ...] = ("127.0.0.0/8",)
    # Optional fallback only: every new task starts with a direct transport.
    proxy_host: str | None = None
    proxy_port: int = 7890

    def __post_init__(self) -> None:
        validate_bind(self.host)
        if isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise ValueError("invalid_server_port")
        object.__setattr__(self, "allowed_networks", validate_lan_networks(self.allowed_networks))
        if isinstance(self.proxy_port, bool) or not 1 <= self.proxy_port <= 65535:
            raise ValueError("invalid_proxy_port")
        if self.proxy_host is not None:
            LocalConnectProxy(self.proxy_host, self.proxy_port)
