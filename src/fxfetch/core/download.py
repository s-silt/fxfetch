"""Bounded ZIP metadata inspection; never extracts files to a directory."""

from __future__ import annotations

import plistlib
import struct
import zipfile
import zlib
from pathlib import Path

from .errors import FxfetchError
from .limits import Limits

_DEFAULT_LIMITS = Limits()


def classify_package(path: Path, limits: Limits = _DEFAULT_LIMITS) -> str | None:
    if path.stat().st_size > limits.max_package_bytes:
        raise FxfetchError("package_limit", "Package exceeds byte limit")
    with path.open("rb") as stream:
        stream.seek(max(0, path.stat().st_size - 65557))
        tail = stream.read(65557)
    offset = tail.rfind(b"PK\x05\x06")
    if offset < 0:
        return None
    try:
        record = struct.unpack_from("<4s4H2LH", tail, offset)
        _, disk, directory_disk, disk_entries, entries, directory_size, _, comment = record
        if offset + 22 + comment != len(tail) or disk or directory_disk or disk_entries != entries:
            raise FxfetchError("archive_invalid", "Split or trailing ZIP data rejected")
        if entries == 65535 or directory_size == 0xFFFFFFFF:
            raise FxfetchError("archive_unsupported", "ZIP64 inspection is not supported")
        if entries > limits.max_archive_entries or directory_size > limits.max_archive_directory_bytes:
            raise FxfetchError("archive_limit", "ZIP directory exceeds limit")
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            if len(names) != len(set(names)) or len(names) != entries:
                raise FxfetchError("archive_invalid", "Duplicate or inconsistent ZIP entries")
            if any("\\" in name or name.startswith("/") or ".." in name.split("/") for name in names):
                raise FxfetchError("archive_invalid", "Unsafe ZIP entry")
            if sum(info.file_size for info in infos) > limits.max_package_bytes:
                raise FxfetchError("archive_limit", "Expanded archive exceeds integrity-check budget")
            checked = 0
            for info in infos:
                if info.flag_bits & 1:
                    raise FxfetchError("archive_unsupported", "Encrypted ZIP entry")
                with archive.open(info) as member:
                    while chunk := member.read(65536):
                        checked += len(chunk)
                        if checked > limits.max_package_bytes:
                            raise FxfetchError(
                                "archive_limit", "Expanded archive exceeds integrity-check budget"
                            )
            apk = "AndroidManifest.xml" in names and any(
                name.startswith("classes") and name.endswith(".dex") and "/" not in name for name in names
            )
            ipa_names = [
                name
                for name in names
                if name.startswith("Payload/")
                and len(name.split("/")) == 3
                and name.split("/")[1].endswith(".app")
                and name.endswith("/Info.plist")
            ]
            if apk and ipa_names or len(ipa_names) > 1:
                raise FxfetchError("archive_ambiguous", "Archive contains ambiguous package structures")
            selected = ["AndroidManifest.xml"] if apk else ipa_names
            budget = 0
            for name in selected:
                info = archive.getinfo(name)
                budget += info.file_size
                if budget > limits.max_archive_metadata_bytes:
                    raise FxfetchError("archive_limit", "Package metadata exceeds limit")
                data = archive.read(info)
                if not data:
                    raise FxfetchError("archive_invalid", "Empty package metadata")
                if ipa_names:
                    metadata = plistlib.loads(data)
                    if not isinstance(metadata, dict) or not metadata.get("CFBundleIdentifier"):
                        raise FxfetchError("archive_invalid", "IPA application metadata missing")
            return "apk" if apk else "ipa" if ipa_names else None
    except FxfetchError:
        raise
    except (
        ValueError,
        OSError,
        EOFError,
        zlib.error,
        struct.error,
        zipfile.BadZipFile,
        RuntimeError,
        plistlib.InvalidFileException,
    ) as exc:
        raise FxfetchError("archive_invalid", "Invalid package archive") from exc
