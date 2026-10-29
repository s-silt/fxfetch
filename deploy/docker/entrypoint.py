"""Container-only local configuration; no target resolution or startup collection."""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import sys
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path

from fxfetch.core.lan import validate_bind, validate_lan_networks


@dataclass(frozen=True)
class Deployment:
    root: Path
    bind: str
    public_ip: str
    port: int
    allowed_hosts: tuple[str, ...]
    allowed_networks: tuple[str, ...]


def deployment(environ: Mapping[str, str]) -> Deployment:
    root = Path(environ.get("FXFETCH_ROOT", "/var/lib/fxfetch"))
    if not root.is_absolute():
        raise ValueError("container_root_must_be_absolute")
    bind = validate_bind(environ.get("FXFETCH_CONTAINER_IP", "172.30.246.2"))
    public = validate_bind(environ.get("FXFETCH_PUBLIC_IP", "127.0.0.1"))
    subnet = validate_lan_networks((environ.get("FXFETCH_CONTAINER_SUBNET", "172.30.246.0/28"),))[0]
    address = ipaddress.IPv4Address(bind)
    network = ipaddress.IPv4Network(subnet)
    if address.is_loopback or address not in network or address in (network.network_address, network.broadcast_address):
        raise ValueError("container_address_outside_usable_bridge")
    port = int(environ.get("FXFETCH_PORT", "18765"))
    if not 1024 <= port <= 65535:
        raise ValueError("container_port_must_be_unprivileged")
    peers = tuple(item.strip() for item in environ.get("FXFETCH_TRUSTED_PEERS", "172.30.246.1/32").split(","))
    allowed = validate_lan_networks((*peers, f"{bind}/32"))
    hosts = (f"{public}:{port}", f"{bind}:{port}")
    if public == "127.0.0.1":
        hosts += (f"localhost:{port}",)
    return Deployment(root, bind, public, port, hosts, allowed)


def clear_proxy_environment() -> None:
    # Cover mixed-case variants too. Never ingest host proxy values into acquisition.
    for key in list(os.environ):
        if key.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}:
            os.environ.pop(key, None)
    os.environ["NO_PROXY"] = "*"
    os.environ["no_proxy"] = "*"


def healthcheck(config: Deployment) -> int:
    connection = http.client.HTTPConnection(config.bind, config.port, timeout=3)
    try:
        connection.request("GET", "/api/session", headers={"Host": config.allowed_hosts[0]})
        response = connection.getresponse()
        content = response.read(8193)
        if response.status != 200 or len(content) > 8192:
            return 1
        document = json.loads(content)
        return 0 if document.get("authenticated") is False else 1
    except (OSError, ValueError, http.client.HTTPException):
        return 1
    finally:
        connection.close()


def main(arguments: list[str] | None = None) -> int:
    clear_proxy_environment()
    args = sys.argv[1:] if arguments is None else arguments
    mode = args[0] if args else "serve"
    config = deployment(os.environ)
    if mode == "check":
        print(json.dumps({**asdict(config), "network_mode": "direct", "target_requests": 0}, default=str))
        return 0
    if mode == "healthcheck":
        return healthcheck(config)
    if mode in {"init", "doctor", "init-build"}:
        from fxfetch.cli import main as cli_main

        return cli_main([mode, "--out", str(config.root), *args[1:]])
    if mode != "serve" or len(args) > 1:
        raise ValueError("unsupported_container_command")

    import uvicorn

    from fxfetch.build_setup import load_builder
    from fxfetch.cli import _load_auth
    from fxfetch.config import Settings
    from fxfetch.service import JobService
    from fxfetch.web.api import create_app

    # The dedicated container volume may contain copied Windows server.json; use only
    # the validated container configuration, never its listen address or proxy fields.
    settings = Settings(
        root=config.root,
        password_hash=_load_auth(config.root),
        host=config.bind,
        port=config.port,
        allowed_hosts=config.allowed_hosts,
        allowed_networks=config.allowed_networks,
        proxy_host=None,
    )
    service = JobService(settings, builder=load_builder(config.root))
    uvicorn.run(
        create_app(settings, service=service),
        host=config.bind,
        port=config.port,
        workers=1,
        proxy_headers=False,
        access_log=False,
        server_header=False,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError):
        print(json.dumps({"state": "failed", "reason_code": "invalid_container_configuration"}))
        raise SystemExit(1) from None
