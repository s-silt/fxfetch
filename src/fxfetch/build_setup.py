"""Local administrator setup for a persistent private APK signing identity."""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path

from .core.offline_font import _local_bytes
from .core.process_limits import jvm_memory_options, run_limited
from .core.web_apk import WebApkBuilder, WebApkSettings

_FIELDS = {"sdk_root", "build_tools_root", "java_home"}
_FONT_PINS = {
    "size": 16437364,
    "sha256": "2c76254f6fc379fddfce0a7e84fb5385bb135d3e399294f6eeb6680d0365b74b",
    "git_blob_sha1": "dc15562470b4f842321894787a0d066879ccff8b",
    "license_sha256": "6a73f9541c2de74158c0e7cf6b0a58ef774f5a780bf191f2d7ec9cc53efe2bf2",
}


def _font_settings(root: Path, settings: WebApkSettings) -> WebApkSettings:
    import hashlib

    path = root / "offline-font.json"
    if not path.exists():
        return settings
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400 or info.st_size > 8192:
        raise ValueError("invalid offline font configuration")
    config = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or set(config) != {"path", "license_path", *_FONT_PINS}:
        raise ValueError("invalid offline font configuration fields")
    if any(config[key] != value for key, value in _FONT_PINS.items()):
        raise ValueError("offline font metadata differs from pinned official release")
    for key in ("path", "license_path"):
        if not isinstance(config[key], str) or not Path(config[key]).is_absolute():
            raise ValueError("offline font paths must be absolute")
    font_path, license_path = Path(config["path"]), Path(config["license_path"])
    font = _local_bytes(font_path, 20 * 1024 * 1024)
    license_data = _local_bytes(license_path, 64 * 1024)
    blob = b"blob " + str(len(font)).encode("ascii") + b"\0" + font
    if (len(font) != _FONT_PINS["size"] or hashlib.sha256(font).hexdigest() != _FONT_PINS["sha256"]
            or hashlib.sha1(blob).hexdigest() != _FONT_PINS["git_blob_sha1"]
            or hashlib.sha256(license_data).hexdigest() != _FONT_PINS["license_sha256"]):
        raise ValueError("offline font local content does not match official release")
    return replace(settings, offline_font_path=font_path, offline_font_license_path=license_path,
                   offline_font_sha256=config["sha256"], offline_font_size=config["size"],
                   offline_font_git_blob_sha1=config["git_blob_sha1"])


@dataclass(frozen=True)
class BuildSetupResult:
    state: str
    reason_codes: tuple[str, ...] = ()


def _private_directory(path: Path) -> bool:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        path.chmod(0o700)
        return True
    system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    identity = run_limited(
        [str(system / "whoami.exe"), "/user", "/fo", "csv", "/nh"], timeout=10, memory_bytes=128 * 1024**2
    )
    match = re.search(rb"S-1-[0-9-]+", identity.stdout)
    if identity.returncode != 0 or identity.reason_code or not match:
        return False
    sid = match.group().decode("ascii")
    permission = run_limited(
        [str(system / "icacls.exe"), str(path), "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F"],
        timeout=10,
        memory_bytes=128 * 1024**2,
    )
    return permission.returncode == 0 and permission.reason_code is None


def load_builder(root: Path) -> WebApkBuilder:
    """Load fixed local fields only; never accept build paths from an HTTP body."""
    root = root.resolve()
    config_file = root / "build.json"
    if not config_file.is_file():
        return WebApkBuilder(_font_settings(root, WebApkSettings()))
    if config_file.stat().st_size > 16 * 1024:
        raise ValueError("invalid local build configuration")
    config = json.loads(config_file.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or set(config) != _FIELDS:
        raise ValueError("invalid local build configuration fields")
    paths: dict[str, Path] = {}
    for key in _FIELDS:
        value = config[key]
        if not isinstance(value, str) or not Path(value).is_absolute():
            raise ValueError("local build paths must be absolute")
        paths[key] = Path(value)
    private = root / ".build-private"
    return WebApkBuilder(
        _font_settings(root, WebApkSettings(
            sdk_root=paths["sdk_root"],
            build_tools_root=paths["build_tools_root"],
            java_home=paths["java_home"],
            signing_keystore=private / "application.p12",
            signing_password_file=private / "password",
            scratch_root=private / "scratch",
        ))
    )


def setup_build(root: Path, sdk_root: Path, build_tools_root: Path, java_home: Path) -> BuildSetupResult:
    """Initialize once; preserve an existing signing identity and never print secrets."""
    root = root.resolve()
    private = root / ".build-private"
    try:
        if not _private_directory(private):
            return BuildSetupResult("failed", ("private_permissions_unavailable",))
        (private / "scratch").mkdir(mode=0o700, exist_ok=True)
        key, password = private / "application.p12", private / "password"
        if key.exists() != password.exists():
            return BuildSetupResult("failed", ("incomplete_signing_identity",))
        keytool = java_home / "bin" / ("keytool.exe" if os.name == "nt" else "keytool")
        if not keytool.is_file():
            return BuildSetupResult("disabled", ("missing_keytool",))
        if not key.exists():
            # Password is carried by a private file, never argv, configuration or logs.
            with password.open("x", encoding="ascii") as stream:
                stream.write(secrets.token_urlsafe(48) + "\n")
            password.chmod(0o600)
            pending_key = private / "application.pending.p12"
            generated = run_limited(
                [
                    str(keytool.resolve()),
                    *jvm_memory_options(launcher=True),
                    "-J-Xmx256m",
                    "-genkeypair",
                    "-noprompt",
                    "-alias",
                    "app",
                    "-keyalg",
                    "RSA",
                    "-keysize",
                    "3072",
                    "-validity",
                    "10000",
                    "-dname",
                    "CN=Application",
                    "-storetype",
                    "PKCS12",
                    "-keystore",
                    str(pending_key),
                    "-storepass:file",
                    str(password),
                    "-keypass:file",
                    str(password),
                ],
                timeout=60,
                memory_bytes=1024**3,
            )
            if generated.returncode != 0 or generated.reason_code or not pending_key.is_file():
                pending_key.unlink(missing_ok=True)
                password.unlink(missing_ok=True)
                return BuildSetupResult("failed", (generated.reason_code or "key_generation_failed",))
            pending_key.replace(key)
        verified = run_limited(
            [
                str(keytool.resolve()),
                *jvm_memory_options(launcher=True),
                "-J-Xmx256m",
                "-list",
                "-alias",
                "app",
                "-keystore",
                str(key),
                "-storepass:file",
                str(password),
            ],
            timeout=20,
            memory_bytes=1024**3,
        )
        if verified.returncode != 0 or verified.reason_code:
            return BuildSetupResult("failed", ("signing_identity_unreadable",))
        config = {
            "sdk_root": str(sdk_root.resolve()),
            "build_tools_root": str(build_tools_root.resolve()),
            "java_home": str(java_home.resolve()),
        }
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=root, prefix="build-", suffix=".json.tmp", delete=False
        ) as stream:
            temporary = Path(stream.name)
            json.dump(config, stream)
        temporary.replace(root / "build.json")
        capability = load_builder(root).probe()
        return BuildSetupResult("ready" if capability.enabled else "disabled", capability.reasons)
    except (OSError, ValueError):
        return BuildSetupResult("failed", ("local_build_setup_failed",))
