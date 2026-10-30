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
        "fxapk_executable": None,
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
    executable = config["fxapk_executable"]
    if executable is not None and (
        not isinstance(executable, str) or not executable or "\0" in executable
    ):
        raise ValueError("invalid_server_configuration")
    return config


def _parser(command: str | None = None) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fxfetch" + (f" {command}" if command else ""))
    if command in {"capture-web", "export-web", "prepare-analysis", "analyze-data"}:
        parser.add_argument("--out", type=Path, required=True, help="New private output directory")
    elif command not in {"verify-web", "verify-data"}:
        parser.add_argument("--out", type=Path, default=_ROOT, help="Private local output/service root")
    if command == "capture-web":
        parser.add_argument("url")
        parser.add_argument("--authorized-active", action="store_true")
        parser.add_argument("--collector", choices=("http", "browser"), default="http")
        parser.add_argument("--service-root", type=Path, default=_ROOT)
    elif command == "export-web":
        parser.add_argument("capture_dir", type=Path)
    elif command == "verify-web":
        parser.add_argument("bundle_dir", type=Path)
    elif command == "verify-data":
        parser.add_argument("archive_path", type=Path)
    elif command in {"prepare-analysis", "analyze-data"}:
        parser.add_argument("archive_path", type=Path)
        if command == "analyze-data":
            parser.add_argument("--fxapk", default="fxapk", help="Trusted local fxapk executable (not a shell command)")
            parser.add_argument("--timeout", type=float, default=300.0, help="Analysis deadline in seconds (1–3600)")
    elif command == "serve":
        parser.add_argument("--host")
        parser.add_argument("--port", type=int)
        parser.add_argument("--allowed-network", dest="allowed_networks", action="append")
        parser.add_argument("--allowed-host", action="append", default=[], metavar="HOST:PORT")
        parser.add_argument("--fxapk", dest="fxapk_executable")
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
        parser.epilog = (
            "Commands: init, init-build, serve, doctor, capture-web, export-web, verify-web, verify-data, "
            "prepare-analysis, analyze-data. "
            "Run fxfetch COMMAND --help."
        )
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
        arguments.pop(0)
        if arguments and arguments[0] in {
            "init", "serve", "doctor", "init-build", "capture-web", "export-web", "verify-web", "verify-data",
            "prepare-analysis", "analyze-data",
        }
        else None
    )
    parser = _parser(command)
    options = parser.parse_args(arguments)
    root = options.out.resolve() if hasattr(options, "out") else _ROOT.resolve()
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
        if command == "capture-web":
            from .core.guard import validate_url
            from .core.web_capture import capture_web

            approved_url = validate_url(options.url)
            classified = classify_input(approved_url)
            if classified.kind != "http":
                raise FxfetchError("unsupported_input", "Only HTTP(S) URLs can be captured")
            if not options.authorized_active:
                _print(
                    {
                        "mode": "offline",
                        "kind": "web",
                        "network_requests": 0,
                        "steps": ["offline_classification", "explicit_authorization_required"],
                        "outcome": None,
                    }
                )
                return 0
            result = capture_web(
                approved_url,
                root,
                collector=options.collector,
                authorized_active=True,
                service_root=options.service_root.resolve(),
                limits=Limits(),
                cancel=Event(),
            )
            assert result is not None
            _print(
                {
                    "state": "web_capture",
                    "capture_id": result.capture_id,
                    "collector": result.collector,
                    "outcome": result.outcome,
                    "reason_code": result.reason_code,
                    "coverage": result.coverage,
                    "materials": len(result.materials),
                    "gaps": result.gaps,
                    "journal_state": result.journal_state,
                }
            )
            return 0 if result.outcome == "captured" and result.journal_state == "healthy" else 1
        if command == "export-web":
            from .core.web_evidence import export_web

            manifest, digest = export_web(options.capture_dir, root, Limits())
            _print(
                {
                    "state": "exported",
                    "capture_outcome": manifest["outcome"],
                    "coverage": manifest["coverage"],
                    "gaps": manifest["gaps"],
                    "schema_version": manifest["schema_version"],
                    "capture_id": manifest["capture_id"],
                    "files": len(manifest["files"]),
                    "manifest_sha256": digest,
                    "private_bundle": True,
                    "authenticity_claimed": False,
                }
            )
            return 0
        if command == "verify-web":
            from .core.web_evidence import verify_web

            manifest, digest = verify_web(options.bundle_dir, Limits())
            _print(
                {
                    "state": "verified",
                    "capture_outcome": manifest["outcome"],
                    "coverage": manifest["coverage"],
                    "gaps": manifest["gaps"],
                    "schema_version": manifest["schema_version"],
                    "capture_id": manifest["capture_id"],
                    "files": len(manifest["files"]),
                    "manifest_sha256": digest,
                    "private_bundle": True,
                    "authenticity_claimed": False,
                }
            )
            return 0
        if command in {"prepare-analysis", "analyze-data"}:
            from .core.analysis_package import prepare_analysis
            from .core.analysis_runner import analyze_archive

            if command == "prepare-analysis":
                receipt = prepare_analysis(options.archive_path, options.out, max_bytes=Limits().max_task_bytes)
            else:
                receipt = analyze_archive(
                    options.archive_path, options.out, max_bytes=Limits().max_task_bytes,
                    executable=options.fxapk, timeout=options.timeout,
                )
            _print({"state": receipt["state"], "receipt": str(options.out / "analysis.json"),
                    "analysis_state": receipt["analysis"]["state"],
                    "reason_code": receipt["analysis"].get("reason_code"),
                    "coverage": "partial", "online": False})
            return 0 if receipt["state"] in {"prepared", "completed"} else 1
        if command == "verify-data":
            from .core.task_evidence_io import verify_task_archive

            manifest, digest = verify_task_archive(options.archive_path, max_bytes=Limits().max_task_bytes)
            _print(
                {
                    "state": "verified",
                    "schema_version": manifest["schema_version"],
                    "sha256": digest,
                    "files": len(manifest["files"]),
                    "web_materials": manifest["web_materials"],
                    "external_packages_verified": False,
                }
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
        from .core.task_evidence import finalize_package
        from .core.task_evidence_recorder import TaskEvidenceRecorder

        recorder = TaskEvidenceRecorder(root)
        try:
            result = AcquisitionPolicy(
                limits,
                proxyconfig,
                collector_factory=lambda attempt_limits, proxy: Workflow(
                    client=build_default_client(attempt_limits, proxy, recorder), limits=attempt_limits
                ),
                transport_observer=recorder,
            ).run(options.url, root, Event())
        finally:
            recorder.close()
        task_result = asdict(result)
        data_package = finalize_package(
            root,
            job_id="cli",
            entry_url=options.url,
            terminal_result=task_result,
            observation_path=root / "task-observations.jsonl",
            max_bytes=limits.max_task_bytes,
        )
        _print({"result": task_result, "data_package": data_package})
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
