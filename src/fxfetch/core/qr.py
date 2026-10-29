"""Offline QR evidence extraction, isolated from the service process."""

from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import io
import json
import os
import re
import sys
import tempfile
import warnings
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .limits import Limits
from .process_limits import run_limited

DEFAULT_LIMITS = Limits()
IMAGE_FORMATS = ("PNG", "JPEG", "WEBP", "HEIF", "BMP", "GIF", "TIFF", "AVIF")
MAX_THUMBNAIL_BYTES = 1024 * 1024


@dataclass
class QRCandidate:
    id: str
    text: str
    url: str | None
    kind: str
    position: list[list[int]]
    raw_bytes_base64: str
    conversion: str = "strict_utf8"
    reason_code: str | None = None


@dataclass
class QRResult:
    status: str
    sha256: str | None = None
    format: str | None = None
    width: int | None = None
    height: int | None = None
    candidates: list[QRCandidate] = field(default_factory=list)
    truncated: bool = False
    reason_code: str | None = None
    versions: dict[str, str] = field(default_factory=dict)
    coordinate_space: str = "original_image_pixels"
    transforms: list[str] = field(default_factory=list)
    thumbnail_available: bool = False


def _http_url(value: str, max_bytes: int) -> bool:
    if len(value.encode("utf-8")) > max_bytes or any(c.isspace() or ord(c) < 32 for c in value):
        return False
    if "\\" in value or re.search(r"%(?![0-9a-fA-F]{2})", value):
        return False
    try:
        parts = urlsplit(value)
        return (
            parts.scheme.lower() in ("http", "https")
            and bool(parts.hostname)
            and parts.username is None
            and parts.password is None
            and (parts.port is None or 0 < parts.port <= 65535)
        )
    except ValueError:
        return False


def _classify(text: str, max_bytes: int) -> tuple[str | None, str, str | None]:
    if _http_url(text, max_bytes):
        host = (urlsplit(text).hostname or "").lower()
        if host in ("apps.apple.com", "itunes.apple.com", "testflight.apple.com"):
            return None, "out_of_scope", "store_link"
        return text, "http_url", None
    try:
        parts = urlsplit(text)
        if parts.scheme.lower() == "itms-services":
            if any(c.isspace() or ord(c) < 32 for c in text) or re.search(r"%(?![0-9a-fA-F]{2})", text):
                return None, "unsupported", "invalid_itms_manifest"
            query = parse_qs(parts.query, keep_blank_values=True, strict_parsing=True, errors="strict")
            if (
                len(text.encode("utf-8")) <= max_bytes
                and text.lower().startswith("itms-services://?")
                and not parts.netloc
                and not parts.path
                and not parts.fragment
                and set(query) == {"action", "url"}
                and query["action"] == ["download-manifest"]
                and len(query["url"]) == 1
                and _http_url(query["url"][0], max_bytes)
            ):
                return query["url"][0], "itms_manifest", None
            return None, "unsupported", "invalid_itms_manifest"
    except ValueError:
        return None, "unsupported", "invalid_url"
    return None, "text", "unsupported_url"


def _decode_bytes(data: bytes, limits: Limits, thumbnail_path: Path | None = None) -> QRResult:
    import zxingcpp
    from PIL import Image, ImageOps, UnidentifiedImageError
    from pillow_heif import register_heif_opener

    register_heif_opener(thumbnails=False)

    result = QRResult("invalid_image", sha256=hashlib.sha256(data).hexdigest())
    result.versions = {
        name: importlib.metadata.version(name) for name in ("Pillow", "zxing-cpp", "pillow-heif")
    }
    # These globals are changed only in this disposable worker, never the parent.
    Image.MAX_IMAGE_PIXELS = limits.max_image_pixels
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data), formats=list(IMAGE_FORMATS)) as image:
                result.format, result.width, result.height = image.format, image.width, image.height
                if image.width * image.height > limits.max_image_pixels:
                    result.status, result.reason_code = "limit_exceeded", "image_pixels"
                    return result
                if getattr(image, "n_frames", 1) != 1 or getattr(image, "is_animated", False):
                    result.reason_code = (
                        "animated_image" if getattr(image, "is_animated", False) else "multi_page_image"
                    )
                    return result
                image.verify()
            with Image.open(io.BytesIO(data), formats=list(IMAGE_FORMATS)) as image:
                image.load()
                orientation = image.getexif().get(274, 1)
                decoder_orientation = image.info.get("original_orientation")
                if image.format == "HEIF" and decoder_orientation in (2, 3, 4, 5, 6, 7, 8):
                    result.transforms.append(f"heif_decoder_orientation_{decoder_orientation}")
                    result.coordinate_space = "decoder_oriented_image_pixels"
                working = ImageOps.exif_transpose(image)
                if orientation in (2, 3, 4, 5, 6, 7, 8):
                    result.transforms.append(f"exif_orientation_{orientation}")
                    result.coordinate_space = "exif_transposed_image_pixels"
                rgb = working.convert("RGB")
                codes = zxingcpp.read_barcodes(
                    rgb, formats=zxingcpp.BarcodeFormats(zxingcpp.BarcodeFormat.QRCode)
                )
                if thumbnail_path is not None:
                    rgb.thumbnail((640, 640))
                    clean = Image.new("RGB", rgb.size, "white")
                    clean.paste(rgb)
                    clean.save(thumbnail_path, format="JPEG", quality=85, optimize=False)
                    if thumbnail_path.stat().st_size > MAX_THUMBNAIL_BYTES:
                        thumbnail_path.unlink()
                    else:
                        result.thumbnail_available = True
        for index, code in enumerate(codes[: limits.max_qr_candidates]):
            raw = bytes(code.bytes)
            conversion = "strict_utf8"
            try:
                text = raw.decode("utf-8", errors="strict")
                url, kind, reason = _classify(text, limits.max_url_bytes)
            except UnicodeDecodeError:
                text, url, kind, reason = str(code.text), None, "binary", "non_utf8_payload"
                conversion = "zxing_display_only"
            position = [
                [int(point.x), int(point.y)]
                for point in (
                    code.position.top_left,
                    code.position.top_right,
                    code.position.bottom_right,
                    code.position.bottom_left,
                )
            ]
            result.candidates.append(
                QRCandidate(
                    f"qr-{index + 1}",
                    text,
                    url,
                    kind,
                    position,
                    base64.b64encode(raw).decode("ascii"),
                    conversion,
                    reason,
                )
            )
        result.truncated = len(codes) > limits.max_qr_candidates
        result.status = (
            "limit_exceeded"
            if result.truncated
            else "no_code"
            if not codes
            else "decoded"
            if any(c.url for c in result.candidates)
            else "no_supported_url"
        )
        result.reason_code = "qr_candidates" if result.truncated else None
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        result.status, result.reason_code = "limit_exceeded", "image_pixels"
    except (UnidentifiedImageError, OSError, SyntaxError, ValueError):
        result.reason_code = "invalid_image"
    return result


def decode_image(
    path: Path, limits: Limits = DEFAULT_LIMITS, *, thumbnail_path: Path | None = None
) -> QRResult:
    """Decode immutable bytes and optionally publish a metadata-free JPEG preview.

    The caller supplies a private controlled destination; no host path is returned.
    Invalid images and failed workers never publish a thumbnail.
    """
    try:
        with path.open("rb") as source:
            data = source.read(limits.max_image_bytes + 1)
    except OSError:
        return QRResult("invalid_image", reason_code="image_read_failed")
    if len(data) > limits.max_image_bytes:
        return QRResult("limit_exceeded", reason_code="image_bytes")
    digest = hashlib.sha256(data).hexdigest()
    try:
        with tempfile.TemporaryDirectory(prefix="fxfetch-qr-") as scratch:
            snapshot = Path(scratch) / "image.bin"
            snapshot.write_bytes(data)
            preview = Path(scratch) / "preview.jpg"
            command = [sys.executable, "-m", "fxfetch.core.qr", str(snapshot), json.dumps(asdict(limits))]
            if thumbnail_path is not None:
                command.append(str(preview))
            execution = run_limited(
                command,
                timeout=limits.image_timeout,
                memory_bytes=limits.image_memory_bytes,
                max_output_bytes=512 * 1024,
            )
            if execution.timed_out:
                return QRResult("timed_out", sha256=digest, reason_code="image_timeout")
            if not execution.memory_limited or execution.returncode != 0 or execution.output_truncated:
                return QRResult(
                    "failed", sha256=digest, reason_code=execution.reason_code or "decoder_worker_failed"
                )
            try:
                payload = json.loads(execution.stdout)
                payload["candidates"] = [QRCandidate(**candidate) for candidate in payload["candidates"]]
                result = QRResult(**payload)
            except (ValueError, TypeError, KeyError):
                return QRResult("failed", sha256=digest, reason_code="decoder_output_invalid")
            if result.thumbnail_available:
                if (
                    thumbnail_path is None
                    or not preview.is_file()
                    or preview.stat().st_size > MAX_THUMBNAIL_BYTES
                    or result.status not in ("decoded", "no_code", "no_supported_url", "limit_exceeded")
                ):
                    result.thumbnail_available = False
                else:
                    # Copy into the destination filesystem before atomic replacement.
                    with tempfile.NamedTemporaryFile(
                        dir=thumbnail_path.parent, suffix=".jpg", delete=False
                    ) as pending:
                        pending_path = Path(pending.name)
                        pending.write(preview.read_bytes())
                    try:
                        os.replace(pending_path, thumbnail_path)
                    finally:
                        pending_path.unlink(missing_ok=True)
            return result
    except OSError:
        return QRResult("failed", sha256=digest, reason_code="decoder_scratch_failed")


def _main() -> None:
    try:
        limits = Limits(**json.loads(sys.argv[2]))
        data = Path(sys.argv[1]).read_bytes()
        result = _decode_bytes(data, limits, Path(sys.argv[3]) if len(sys.argv) == 4 else None)
        print(json.dumps(asdict(result), ensure_ascii=True))
    except MemoryError:
        print(json.dumps(asdict(QRResult("limit_exceeded", reason_code="image_memory"))))


if __name__ == "__main__":
    _main()
