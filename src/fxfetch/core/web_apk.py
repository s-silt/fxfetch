"""Offline WebView APK naming and fail-closed local Android toolchain builds."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import tempfile
import time
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Thread
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

import tldextract

from .offline_connection import write_connection_page
from .offline_font import MAX_BUNDLE_BYTES, FontResult, apply_offline_font
from .process_limits import jvm_memory_options, run_limited

_PSL = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
_TEMPLATE = Path(__file__).resolve().parents[1] / "templates" / "android-webview"
_ANDROID = "http://schemas.android.com/apk/res/android"


@dataclass(frozen=True)
class ApkNames:
    host: str
    display_name: str
    filename: str
    package_base: str


def _host(url: str) -> str:
    if len(url.encode("utf-8")) > 8192 or any(ord(char) < 32 for char in url):
        raise ValueError("invalid URL length or controls")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
        raise ValueError("an HTTP/HTTPS URL without credentials is required")
    if parsed.password is not None or parsed.port == 0 or "\\" in parsed.netloc:
        raise ValueError("invalid URL authority")
    host = parsed.hostname.rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        host = host.encode("idna").decode("ascii")
    if len(host) > 253 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")
    ):
        raise ValueError("invalid host")
    return host


def derive_names(url: str) -> ApkNames:
    """Use bundled PSL only. Display IDNs as canonical ASCII IDNA labels."""
    host = _host(url)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        extracted = _PSL(host)
        suffix = extracted.suffix.split(".") if extracted.suffix else []
        labels = host.split(".")
        prefix = labels[: -len(suffix)] if suffix else labels
        short = [label[:5] for label in prefix] + suffix
        display = ".".join(short)
        package_labels = list(reversed(short))
    else:
        display = str(address).replace(":", "_")
        package_labels = ["ip", "a" + address.packed.hex()]
    if display.upper().split(".")[0] in {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *[f"COM{i}" for i in range(1, 10)],
        *[f"LPT{i}" for i in range(1, 10)],
    }:
        display = "_" + display
    legal: list[str] = []
    for label in package_labels:
        value = re.sub(r"[^a-z0-9_]", "_", label.lower())
        if not value or not value[0].isalpha():
            value = "a" + value
        if value in {
            "abstract",
            "assert",
            "boolean",
            "break",
            "byte",
            "case",
            "catch",
            "char",
            "class",
            "const",
            "continue",
            "default",
            "do",
            "double",
            "else",
            "enum",
            "extends",
            "final",
            "finally",
            "float",
            "for",
            "goto",
            "if",
            "implements",
            "import",
            "instanceof",
            "int",
            "interface",
            "long",
            "native",
            "new",
            "package",
            "private",
            "protected",
            "public",
            "return",
            "short",
            "static",
            "strictfp",
            "super",
            "switch",
            "synchronized",
            "this",
            "throw",
            "throws",
            "transient",
            "try",
            "void",
            "volatile",
            "while",
            "true",
            "false",
            "null",
        }:
            value = "a" + value
        legal.append(value)
    if len(legal) == 1:
        legal.insert(0, "app")
    return ApkNames(host, display, display + ".apk", ".".join(legal))


@dataclass(frozen=True)
class WebApkSettings:
    sdk_root: Path | None = None
    java_home: Path | None = None
    build_tools_root: Path | None = None
    compile_sdk: int = 35
    build_tools_version: str = "37.0.0"
    signing_keystore: Path | None = None
    signing_password_file: Path | None = None
    signing_alias: str = "app"
    scratch_root: Path | None = None
    timeout_seconds: float = 900
    memory_bytes: int = 2 * 1024**3
    max_scratch_bytes: int = 8 * 1024**3
    max_apk_bytes: int = 30_000_000
    offline_font_path: Path | None = None
    offline_font_license_path: Path | None = None
    offline_font_sha256: str | None = None
    offline_font_size: int | None = None
    offline_font_git_blob_sha1: str | None = None


@dataclass(frozen=True)
class BuildCapability:
    enabled: bool
    reasons: tuple[str, ...]
    tools: dict[str, str]
    build_system: str = "android-sdk-direct-java"
    gradle_required: bool = False
    scratch_limit_method: str = "monitored_soft_budget"


@dataclass(frozen=True)
class BuildResult:
    state: str
    reason_code: str | None = None
    artifact_path: Path | None = None
    sha256: str | None = None
    size: int | None = None
    filename: str | None = None
    signing_certificate_sha256: str | None = None
    runtime_validation: str = "not_run"
    font_applied: bool = False
    font_reason: str = "font_not_configured"
    offline_content_kind: str | None = None
    offline_content_reason: str | None = None
    resource_bytes: int = 0
    resource_files: int = 0


class _BuildStopped(Exception):
    def __init__(self, code: str, state: str = "failed") -> None:
        self.code = code
        self.state = state


class WebApkBuilder:
    def __init__(self, settings: WebApkSettings | None = None) -> None:
        self.settings = settings or WebApkSettings()

    def probe(self) -> BuildCapability:
        settings = self.settings
        sdk = settings.sdk_root or Path(
            os.environ.get("ANDROID_HOME", os.environ.get("ANDROID_SDK_ROOT", ""))
        )
        jdk = settings.java_home or Path(os.environ.get("JAVA_HOME", ""))
        extension = ".exe" if os.name == "nt" else ""
        build_tools = settings.build_tools_root or sdk / "build-tools" / settings.build_tools_version
        tools = {
            "java": jdk / "bin" / ("java" + extension),
            "javac": jdk / "bin" / ("javac" + extension),
            "aapt2": build_tools / ("aapt2" + extension),
            "zipalign": build_tools / ("zipalign" + extension),
            "d8": build_tools / "lib" / "d8.jar",
            "apksigner": build_tools / "lib" / "apksigner.jar",
            "android_jar": sdk / "platforms" / f"android-{settings.compile_sdk}" / "android.jar",
        }
        reasons = [f"missing_{name}" for name, path in tools.items() if not path.is_file()]
        if settings.signing_keystore is None or not settings.signing_keystore.is_file():
            reasons.append("missing_signing_keystore")
        if settings.signing_password_file is None or not settings.signing_password_file.is_file():
            reasons.append("missing_signing_password_file")
        return BuildCapability(not reasons, tuple(reasons), {name: str(path) for name, path in tools.items()})

    def build(
        self,
        url: str,
        output_dir: Path,
        package_name: str,
        version_code: int,
        cancel: Event | None = None,
        *,
        offline_dir: Path | None = None,
        on_event: Callable[[dict], None] | None = None,
    ) -> BuildResult:
        names = derive_names(url)
        if not re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+", package_name):
            raise ValueError("invalid Android application ID")
        if not 1 <= version_code <= 2_100_000_000:
            raise ValueError("invalid Android version code")
        if cancel is not None and cancel.is_set():
            return BuildResult("cancelled", "cancelled")
        capability = self.probe()
        if not capability.enabled:
            return BuildResult("disabled", ",".join(capability.reasons))
        settings, tools = self.settings, capability.tools
        root = (settings.scratch_root or Path(tempfile.gettempdir()) / "fxfetch-build-scratch").resolve()
        try:
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            if shutil.disk_usage(root).free < settings.max_scratch_bytes:
                return BuildResult("failed", "scratch_insufficient_space")
            scratch = Path(tempfile.mkdtemp(prefix="build-", dir=root)).resolve()
        except OSError:
            return BuildResult("failed", "scratch_unavailable")
        if scratch == root or not scratch.is_relative_to(root):
            return BuildResult("failed", "unsafe_scratch_path")
        deadline = time.monotonic() + settings.timeout_seconds
        run_cancel, monitor_stop = Event(), Event()
        monitor_reason: list[str] = []

        def monitor() -> None:
            # This deliberately reports a soft budget: a write can overshoot between scans.
            while not monitor_stop.is_set():
                if cancel is not None and cancel.is_set():
                    run_cancel.set()
                    return
                try:
                    total = 0
                    for path in scratch.rglob("*"):
                        if path.is_file():
                            total += path.stat().st_size
                        if total > settings.max_scratch_bytes:
                            monitor_reason.append("scratch_soft_budget_exceeded")
                            run_cancel.set()
                            return
                except OSError:
                    monitor_reason.append("scratch_monitor_failed")
                    run_cancel.set()
                    return
                monitor_stop.wait(0.1)

        watcher = Thread(target=monitor, name="apk-scratch-monitor", daemon=True)
        watcher.start()

        def stage(event: str) -> None:
            if cancel is not None and cancel.is_set():
                raise _BuildStopped("cancelled", "cancelled")
            if time.monotonic() >= deadline:
                raise _BuildStopped("build_timed_out")
            if on_event is not None:
                on_event({"event": event})

        try:
            stage("build_preparing")
            self._render(scratch, url, names.display_name, package_name, version_code)
            stage("build_resources")
            content_kind, content_reason, font_result, resource_bytes, resource_files = self._prepare_offline(
                scratch, url, offline_dir
            )
            classes, dex = scratch / "classes", scratch / "dex"
            classes.mkdir()
            dex.mkdir()
            env = {
                key: value
                for key, value in os.environ.items()
                if key.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"}
            }
            java = [tools["java"], *jvm_memory_options(), "-Xmx512m", f"-Djava.io.tmpdir={scratch}"]
            commands = [
                [
                    tools["aapt2"],
                    "compile",
                    "--dir",
                    str(scratch / "res"),
                    "-o",
                    str(scratch / "resources.zip"),
                ],
                [
                    tools["aapt2"],
                    "link",
                    "-o",
                    str(scratch / "base.apk"),
                    "-I",
                    tools["android_jar"],
                    "--manifest",
                    str(scratch / "AndroidManifest.xml"),
                    "-A",
                    str(scratch / "assets"),
                    str(scratch / "resources.zip"),
                ],
                [
                    tools["javac"],
                    *jvm_memory_options(launcher=True),
                    "-J-Xmx512m",
                    "-encoding",
                    "UTF-8",
                    "-source",
                    "8",
                    "-target",
                    "8",
                    "-bootclasspath",
                    tools["android_jar"],
                    "-d",
                    str(classes),
                    str(scratch / "MainActivity.java"),
                ],
            ]

            def execute(command: list[str]) -> bool:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _BuildStopped("build_timed_out")
                if monitor_reason:
                    raise _BuildStopped(monitor_reason[0])
                if cancel is not None and cancel.is_set():
                    raise _BuildStopped("cancelled", "cancelled")
                result = run_limited(
                    command,
                    timeout=remaining,
                    memory_bytes=settings.memory_bytes,
                    cwd=scratch,
                    env=env,
                    cancel=run_cancel,
                    max_output_bytes=256 * 1024,
                )
                if monitor_reason:
                    raise _BuildStopped(monitor_reason[0])
                if cancel is not None and cancel.is_set():
                    raise _BuildStopped("cancelled", "cancelled")
                if result.returncode != 0 or result.reason_code:
                    raise _BuildStopped(result.reason_code or "build_command_failed")
                return True

            stage("build_compiling")
            for command in commands:
                if not execute(command):
                    return BuildResult(
                        "cancelled" if cancel and cancel.is_set() else "failed", "build_command_failed"
                    )
            class_files = [str(path) for path in classes.rglob("*.class")]
            if not class_files or not execute(
                java
                + [
                    "-cp",
                    tools["d8"],
                    "com.android.tools.r8.D8",
                    "--release",
                    "--min-api",
                    "24",
                    "--lib",
                    tools["android_jar"],
                    "--output",
                    str(dex),
                    *class_files,
                ]
            ):
                return BuildResult("failed", "dex_failed")
            with zipfile.ZipFile(scratch / "base.apk", "a", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.write(dex / "classes.dex", "classes.dex")
            assert settings.signing_keystore is not None and settings.signing_password_file is not None
            if not execute(
                [tools["zipalign"], "-f", "4", str(scratch / "base.apk"), str(scratch / "aligned.apk")]
            ):
                return BuildResult("failed", "zipalign_failed")
            stage("build_signing")
            sign = java + [
                "-jar",
                tools["apksigner"],
                "sign",
                "--ks",
                str(settings.signing_keystore.resolve()),
                "--ks-key-alias",
                settings.signing_alias,
                "--ks-pass",
                "file:" + str(settings.signing_password_file.resolve()),
                "--out",
                str(scratch / "signed.apk"),
                str(scratch / "aligned.apk"),
            ]
            if not execute(sign):
                return BuildResult("failed", "signing_failed")
            stage("build_verifying")
            verified = run_limited(
                java
                + [
                    "-jar",
                    tools["apksigner"],
                    "verify",
                    "--verbose",
                    "--print-certs",
                    str(scratch / "signed.apk"),
                ],
                timeout=max(0.01, deadline - time.monotonic()),
                memory_bytes=settings.memory_bytes,
                cwd=scratch,
                env=env,
                cancel=run_cancel,
            )
            if monitor_reason:
                return BuildResult("failed", monitor_reason[0])
            if cancel is not None and cancel.is_set():
                return BuildResult("cancelled", "cancelled")
            match = re.search(rb"certificate SHA-256 digest:\s*([0-9a-fA-F]{64})", verified.stdout)
            if verified.returncode != 0 or verified.reason_code or not match:
                return BuildResult("failed", "signature_verification_failed")
            source = scratch / "signed.apk"
            if not 0 < source.stat().st_size <= min(settings.max_apk_bytes, 30_000_000):
                return BuildResult("failed", "apk_size_limit")
            with zipfile.ZipFile(source) as archive:
                if (
                    not {"AndroidManifest.xml", "classes.dex"}.issubset(archive.namelist())
                    or archive.testzip()
                ):
                    return BuildResult("failed", "apk_structure_invalid")
            if monitor_reason:
                return BuildResult("failed", monitor_reason[0])
            if cancel and cancel.is_set():
                return BuildResult("cancelled", "cancelled")
            with source.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            stage("build_saving")
            output_dir.mkdir(parents=True, exist_ok=True)
            destination = output_dir / f"{digest}.apk"
            with tempfile.NamedTemporaryFile(dir=output_dir, suffix=".partial", delete=False) as pending:
                temporary = Path(pending.name)
                with source.open("rb") as stream:
                    shutil.copyfileobj(stream, pending, 1024 * 1024)
            if cancel and cancel.is_set():
                temporary.unlink(missing_ok=True)
                return BuildResult("cancelled", "cancelled")
            if time.monotonic() >= deadline:
                temporary.unlink(missing_ok=True)
                return BuildResult("failed", "build_timed_out")
            temporary.replace(destination)
            return BuildResult(
                "built",
                artifact_path=destination,
                sha256=digest,
                size=destination.stat().st_size,
                filename=names.filename,
                signing_certificate_sha256=match.group(1).decode().lower(),
                font_applied=font_result.applied,
                font_reason=font_result.reason,
                offline_content_kind=content_kind,
                offline_content_reason=content_reason,
                resource_bytes=resource_bytes,
                resource_files=resource_files,
            )
        except _BuildStopped as error:
            return BuildResult(error.state, error.code)
        except (OSError, ValueError, zipfile.BadZipFile):
            return BuildResult("failed", "local_build_failed")
        finally:
            monitor_stop.set()
            watcher.join()
            # Only this fresh, checked scratch child is removed.
            shutil.rmtree(scratch)

    def _prepare_offline(
        self, root: Path, url: str, source: Path | None,
    ) -> tuple[str, str, FontResult, int, int]:
        site = root / "assets" / "site"
        kind, reason = "connection_page", "snapshot_unavailable"
        if source is not None:
            try:
                self._copy_offline(source, site)
                document = (site / "index.html").read_text(encoding="utf-8")
                if (
                    "connect-src &#x27;none&#x27;" not in document
                    or re.search(r"<\s*(?:script|iframe|form|object|embed)\b", document, re.I)
                    or not (re.sub(r"<[^>]*>", "", document).strip() or "<img " in document)
                ):
                    raise _BuildStopped("offline_snapshot_invalid")
                kind, reason = "site_snapshot", "saved_static_content"
            except (_BuildStopped, OSError, UnicodeError) as error:
                if isinstance(error, _BuildStopped) and error.code not in {
                    "offline_snapshot_invalid", "offline_bundle_missing_entry",
                }:
                    # Unsafe paths, malformed layouts and exhausted hard budgets fail closed.
                    raise
                reason = error.code if isinstance(error, _BuildStopped) else "offline_snapshot_unreadable"
                if site.exists():
                    shutil.rmtree(site)
        if kind == "connection_page":
            write_connection_page(site, url)
        settings = self.settings
        font = apply_offline_font(
            site, root / "assets" / "licenses" / "offline-sc.txt",
            font_path=settings.offline_font_path, license_path=settings.offline_font_license_path,
            sha256=settings.offline_font_sha256, size=settings.offline_font_size,
            git_blob_sha1=settings.offline_font_git_blob_sha1,
        )
        (root / "assets" / "config.json").write_text(
            json.dumps({"url": url, "offline": True}, ensure_ascii=True), encoding="utf-8"
        )
        resources = [path for path in site.rglob("*") if path.is_file()]
        license_file = root / "assets" / "licenses" / "offline-sc.txt"
        if license_file.is_file():
            resources.append(license_file)
        byte_count = sum(path.stat().st_size for path in resources)
        if byte_count > MAX_BUNDLE_BYTES:
            raise _BuildStopped("offline_bundle_byte_limit")
        return kind, reason, font, byte_count, len(resources)

    @staticmethod
    def _render(root: Path, url: str, display_name: str, package_name: str, version_code: int) -> None:
        shutil.copytree(_TEMPLATE, root, dirs_exist_ok=True)
        ET.register_namespace("android", _ANDROID)
        manifest = ET.parse(root / "AndroidManifest.xml")
        manifest.getroot().set("package", package_name)
        manifest.getroot().set(f"{{{_ANDROID}}}versionCode", str(version_code))
        manifest.getroot().set(f"{{{_ANDROID}}}versionName", str(version_code))
        manifest.write(root / "AndroidManifest.xml", encoding="utf-8", xml_declaration=True)
        values = ET.Element("resources")
        ET.SubElement(values, "string", name="app_name").text = display_name
        ET.ElementTree(values).write(
            root / "res" / "values" / "strings.xml", encoding="utf-8", xml_declaration=True
        )
        config = ET.Element("network-security-config")
        ET.SubElement(config, "base-config", cleartextTrafficPermitted="false")
        if urlsplit(url).scheme == "http":
            domain = ET.SubElement(config, "domain-config", cleartextTrafficPermitted="true")
            ET.SubElement(domain, "domain", includeSubdomains="false").text = _host(url)
        ET.ElementTree(config).write(
            root / "res" / "xml" / "network_security_config.xml", encoding="utf-8", xml_declaration=True
        )
        # Structured JSON is ordinary runtime configuration; no input is interpolated into code.
        (root / "assets").mkdir(exist_ok=True)
        (root / "assets" / "config.json").write_text(
            json.dumps({"url": url, "offline": False}, ensure_ascii=True), encoding="utf-8"
        )

    @staticmethod
    def _copy_offline(source: Path, destination: Path) -> None:
        """Copy only the sanitizer's bounded static layout; never follow links or scripts."""
        from PIL import Image, UnidentifiedImageError

        source = source.absolute()
        maximum = MAX_BUNDLE_BYTES
        files: list[Path] = []
        image_name = re.compile(r"[a-f0-9]{64}\.(?:png|jpg|jpeg|webp)")

        def check_link(path: Path) -> None:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise _BuildStopped("offline_bundle_unsafe_path")

        for ancestor in (source, *source.parents):
            check_link(ancestor)
        if not source.is_dir():
            raise _BuildStopped("offline_bundle_invalid")
        with os.scandir(source) as entries:
            for entry in entries:
                path = Path(entry.path)
                check_link(path)
                if path.name == "index.html" and path.is_file():
                    files.append(path)
                elif path.name == "assets" and path.is_dir():
                    with os.scandir(path) as assets:
                        for item in assets:
                            asset = Path(item.path)
                            check_link(asset)
                            if not asset.is_file() or not (
                                asset.name == "style.css" or image_name.fullmatch(asset.name)
                            ):
                                raise _BuildStopped("offline_bundle_invalid")
                            files.append(asset)
                            if len(files) > 30:
                                raise _BuildStopped("offline_bundle_file_limit")
                else:
                    raise _BuildStopped("offline_bundle_invalid")
                if len(files) > 30:
                    raise _BuildStopped("offline_bundle_file_limit")
        if source / "index.html" not in files:
            raise _BuildStopped("offline_bundle_missing_entry")
        if sum(path.stat().st_size for path in files) > maximum:
            raise _BuildStopped("offline_bundle_byte_limit")
        destination.mkdir(parents=True, exist_ok=False)
        total = 0
        for path in sorted(files):
            relative = path.relative_to(source)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            check_link(path)
            with path.open("rb") as stream, target.open("xb") as output:
                while block := stream.read(64 * 1024):
                    total += len(block)
                    if total > maximum:
                        raise _BuildStopped("offline_bundle_byte_limit")
                    output.write(block)
            if relative.parent == Path("assets") and path.name != "style.css":
                try:
                    with Image.open(target, formats=["PNG", "JPEG", "WEBP"]) as image:
                        if image.width * image.height > 4_000_000 or getattr(image, "n_frames", 1) != 1:
                            raise _BuildStopped("offline_bundle_invalid_image")
                        expected = {"PNG": ".png", "JPEG": ".jpg", "WEBP": ".webp"}.get(image.format or "")
                        if expected != target.suffix.lower() and not (
                            expected == ".jpg" and target.suffix == ".jpeg"
                        ):
                            raise _BuildStopped("offline_bundle_invalid_image")
                        image.verify()
                except (UnidentifiedImageError, Image.DecompressionBombError, ValueError, OSError) as error:
                    raise _BuildStopped("offline_bundle_invalid_image") from error
