"""Explicit local setup, offline URL preview, and single-process LAN serving."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path
from threading import Event
from urllib.parse import urlsplit

from .build_setup import _private_directory, load_builder, setup_build
from .config import Settings
from .core.classify import classify_input
from .core.errors import FxfetchError
from .core.lan import validate_bind, validate_lan_networks
from .core.limits import Limits
from .core.network import AcquisitionPolicy, build_default_client
from .core.proxy import LocalConnectProxy
from .core.workflow import Workflow
from .security import password_hash
from .service import JobService
from .web.api import create_app

_ROOT = Path(".runtime/service")


def _print(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, default=str))


def _load_auth(root: Path) -> str:
    path = root / "auth.json"
    if not path.is_file() or path.stat().st_size > 4096:
        raise ValueError("auth_not_initialized")
    config = json.loads(path.read_text(encoding="utf-8"))
    encoded = config.get("password_hash") if isinstance(config, dict) else None
    if not isinstance(encoded, str) or not re.fullmatch(
        r"pbkdf2_sha256\$600000\$[0-9a-f]{32}\$[0-9a-f]{64}", encoded
    ):
        raise ValueError("invalid_auth_configuration")
    return encoded


def _allowed_hosts(host: str, port: int, extra: Sequence[str]) -> tuple[str, ...]:
    validate_bind(host)
    if not 1 <= port <= 65535:
        raise ValueError("invalid_server_port")
    if host in {"0.0.0.0", "::"} and not extra:
        raise ValueError("wildcard_bind_requires_allowed_host")
    values = list(extra)
    if host not in {"0.0.0.0", "::"}:
        values.append(f"[{host}]:{port}" if ":" in host else f"{host}:{port}")
    if host == "127.0.0.1":
        values.append(f"localhost:{port}")
    result: list[str] = []
    for value in values:
        if any(character in value for character in "*/\\@?#") or any(
            character.isspace() for character in value
        ):
            raise ValueError("invalid_allowed_host")
        parsed = urlsplit("//" + value)
        if not parsed.hostname or parsed.port != port or parsed.path or parsed.username or parsed.password:
            raise ValueError("allowed_host_requires_explicit_server_port")
        result.append(value.lower())
    return tuple(dict.fromkeys(result))


def _server_config(root: Path, options: argparse.Namespace | None = None) -> dict:
    config: dict = {
        "host": "127.0.0.1",
        "port": 8765,
        "allowed_networks": ["127.0.0.0/8"],
        "proxy_host": None,
        "proxy_port": 7890,
    }
    path = root / "server.json"
    if path.exists():
        if path.stat().st_size > 8192:
            raise ValueError("invalid_server_configuration")
        saved = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(saved, dict) or set(saved) - set(config):
            raise ValueError("invalid_server_configuration")
        config.update(saved)
    if options is not None:
        for key in config:
            value = getattr(options, key, None)
            if value is not None:
                config[key] = value
        if getattr(options, "no_proxy", False):
            config["proxy_host"] = None
    if not isinstance(config["host"], str):
        raise ValueError("invalid_server_configuration")
    config["host"] = validate_bind(config["host"])
    for key in ("port", "proxy_port"):
        value = config[key]
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
            raise ValueError("invalid_server_configuration")
    networks = config["allowed_networks"]
    if not isinstance(networks, (list, tuple)) or not all(isinstance(item, str) for item in networks):
        raise ValueError("invalid_server_configuration")
    config["allowed_networks"] = validate_lan_networks(tuple(networks))
    if config["proxy_host"] is not None:
        if not isinstance(config["proxy_host"], str):
            raise ValueError("invalid_server_configuration")
        LocalConnectProxy(config["proxy_host"], config["proxy_port"])
    return config


def _parser(command: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fxfetch" + (f" {command}" if command else ""))
    parser.add_argument("--out", type=Path, default=_ROOT, help="Private local output/service root")
    if command == "serve":
        parser.add_argument("--host")
        parser.add_argument("--port", type=int)
        parser.add_argument("--allowed-network", dest="allowed_networks", action="append")
        parser.add_argument("--allowed-host", action="append", default=[], metavar="HOST:PORT")
        parser.add_argument(
            "--secure-cookie", action="store_true", help="Use only behind local HTTPS termination"
        )
    elif command == "init-build":
        parser.add_argument("--sdk", type=Path, required=True)
        parser.add_argument("--build-tools", type=Path, required=True)
        parser.add_argument("--java-home", type=Path, required=True)
    elif command is None:
        parser.add_argument("url", nargs="?")
        parser.add_argument(
            "--authorized-active", action="store_true", help="Authorize this invocation to resolve/connect"
        )
        parser.epilog = "Commands: init, init-build, serve, doctor. Run fxfetch COMMAND --help."
    if command in (None, "serve"):
        proxy = parser.add_mutually_exclusive_group()
        proxy.add_argument(
            "--proxy-host",
            help="Optional literal loopback CONNECT fallback after an initial direct transport failure",
        )
        proxy.add_argument("--no-proxy", action="store_true")
        parser.add_argument("--proxy-port", type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    command = (
        arguments.pop(0) if arguments and arguments[0] in {"init", "serve", "doctor", "init-build"} else None
    )
    parser = _parser(command)
    options = parser.parse_args(arguments)
    root = options.out.resolve()
    try:
        if command == "init":
            if (root / "auth.json").exists():
                raise ValueError("auth_already_initialized")
            password = getpass.getpass("Service password (at least 12 characters): ")
            confirmation = getpass.getpass("Confirm password: ")
            if len(password) < 12 or len(password.encode()) > 1024 or password != confirmation:
                raise ValueError("password_length_or_confirmation_failed")
            if not _private_directory(root):
                raise ValueError("private_permissions_unavailable")
            encoded = password_hash(password)
            with (root / "auth.json").open("x", encoding="utf-8") as stream:
                json.dump({"password_hash": encoded}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            _print({"state": "initialized"})
            return 0
        if command == "init-build":
            result = setup_build(root, options.sdk, options.build_tools, options.java_home)
            _print(asdict(result))
            return 0 if result.state == "ready" else 1
        if command == "doctor":
            network = _server_config(root)
            builder = load_builder(root).probe()
            try:
                _load_auth(root)
                auth_ready = True
            except (OSError, ValueError):
                auth_ready = False
            _print(
                {
                    "auth_initialized": auth_ready,
                    "chrome": {"enabled": False, "reason_code": "browser_guard_unavailable"},
                    "web_apk": {
                        "enabled": builder.enabled,
                        "reason_codes": builder.reasons,
                        "scratch_limit_method": builder.scratch_limit_method,
                    },
                    "network_requests": 0,
                    "server": network,
                    "public_dns": ["223.5.5.5", "119.29.29.29"],
                }
            )
            return 0
        if command == "serve":
            import uvicorn

            network = _server_config(root, options)
            allowed = _allowed_hosts(network["host"], network["port"], options.allowed_host)
            settings = Settings(
                root=root,
                password_hash=_load_auth(root),
                allowed_hosts=allowed,
                secure_cookie=options.secure_cookie,
                **network,
            )
            service = JobService(settings, builder=load_builder(root))
            application = create_app(settings, service=service)
            _print({"state": "starting", "allowed_hosts": allowed, "chrome_enabled": False})
            uvicorn.run(
                application,
                host=network["host"],
                port=network["port"],
                workers=1,
                proxy_headers=False,
                access_log=False,
                server_header=False,
            )
            return 0
        if not options.url:
            parser.print_help()
            return 0
        classified = classify_input(options.url)
        host = urlsplit(classified.request_url).hostname if classified.request_url else None
        if not options.authorized_active:
            _print(
                {
                    "mode": "offline",
                    "kind": classified.kind,
                    "host": host,
                    "network_requests": 0,
                    "steps": ["offline_classification", "explicit_authorization_required"],
                    "outcome": None,
                }
            )
            return 0
        network = _server_config(root, options)
        proxyconfig = (
            LocalConnectProxy(network["proxy_host"], network["proxy_port"])
            if network["proxy_host"] is not None
            else None
        )
        limits = Limits()
        result = AcquisitionPolicy(
            limits,
            proxyconfig,
            collector_factory=lambda attempt_limits, proxy: Workflow(
                client=build_default_client(attempt_limits, proxy), limits=attempt_limits
            ),
        ).run(options.url, root, Event())
        _print(asdict(result))
        return 0 if result.outcome in {"downloaded", "not_found"} else 1
    except (FxfetchError, OSError, ValueError) as error:
        code = (
            error.code
            if isinstance(error, FxfetchError)
            else (
                str(error)
                if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]+", str(error))
                else "local_configuration_failed"
            )
        )
        _print({"state": "failed", "reason_code": code})
        return 1
    except (EOFError, KeyboardInterrupt):
        _print({"state": "cancelled"})
        return 130
