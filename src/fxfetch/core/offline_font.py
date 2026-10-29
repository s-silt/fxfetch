"""Optional, pinned local font for sanitized snapshots; never performs network I/O."""

from __future__ import annotations

import hashlib
import html
import re
import stat
from dataclasses import dataclass
from pathlib import Path

MAX_BUNDLE_BYTES = 28 * 1024 * 1024
FONT_CSS = (
    '\n@font-face{font-family:OfflineSC;src:url("offline-sc.otf") format("opentype");'
    "font-weight:400;font-style:normal;font-display:swap}"
    "body,body *{font-family:OfflineSC,sans-serif!important}\n"
)


@dataclass(frozen=True)
class FontResult:
    applied: bool = False
    reason: str = "font_not_configured"


def _local_bytes(path: Path, limit: int) -> bytes:
    for item in (path.absolute(), *path.absolute().parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("font_link")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if not data or len(data) > limit:
        raise ValueError("font_size")
    return data


def apply_offline_font(
    site: Path,
    license_destination: Path,
    *,
    font_path: Path | None,
    license_path: Path | None,
    sha256: str | None,
    size: int | None,
    git_blob_sha1: str | None = None,
) -> FontResult:
    """Append trusted CSS only to the sanitizer's fixed document, within its budget."""
    if font_path is None or license_path is None:
        return FontResult()
    try:
        entry = site / "index.html"
        document = entry.read_text(encoding="utf-8")
        text = html.unescape(re.sub(r"<[^>]*>", "", document))
        if not text.strip():
            return FontResult(reason="font_no_text_content")
        if not sha256 or not re.fullmatch(r"[0-9a-f]{64}", sha256) or size is None:
            return FontResult(reason="font_missing_pin")
        font = _local_bytes(font_path, MAX_BUNDLE_BYTES)
        license_data = _local_bytes(license_path, 64 * 1024)
        if len(font) != size or hashlib.sha256(font).hexdigest() != sha256:
            return FontResult(reason="font_pin_mismatch")
        if font[:4] != b"OTTO":
            return FontResult(reason="font_invalid_format")
        if git_blob_sha1 is not None:
            blob = b"blob " + str(len(font)).encode("ascii") + b"\0" + font
            if hashlib.sha1(blob).hexdigest() != git_blob_sha1:
                return FontResult(reason="font_blob_mismatch")
        license_text = license_data.decode("utf-8")
        if "SIL OPEN FONT LICENSE Version 1.1" not in license_text:
            return FontResult(reason="font_license_invalid")
        old = "default-src &#x27;none&#x27;; img-src &#x27;self&#x27;;"
        if document.count(old) != 1:
            return FontResult(reason="font_snapshot_csp_unrecognized")
        updated = document.replace(old, old + " font-src &#x27;self&#x27;;", 1)
        css = site / "assets" / "style.css"
        css_bytes = css.read_bytes() + FONT_CSS.encode("utf-8")
        total = sum(p.stat().st_size for p in site.rglob("*") if p.is_file())
        extra = len(font) + len(license_data) + len(FONT_CSS.encode())
        extra += len(updated.encode()) - len(document.encode())
        if total + extra > MAX_BUNDLE_BYTES:
            return FontResult(reason="font_bundle_budget")
    except (OSError, UnicodeError, ValueError):
        return FontResult(reason="font_local_validation_failed")
    # Once mutation starts, failure must abort the whole APK build. The builder
    # owns this fresh scratch tree and cleans it without publishing partial assets.
    (site / "assets" / "offline-sc.otf").write_bytes(font)
    license_destination.parent.mkdir(parents=True, exist_ok=True)
    license_destination.write_bytes(license_data)
    css.write_bytes(css_bytes)
    entry.write_text(updated, encoding="utf-8")
    return FontResult(True, "font_applied")
