"""Pure bounded discovery of explicit page images; no network operations."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin

from .discovery import MAX_HTML_INPUT_BYTES, BoundedHTMLParser
from .errors import FxfetchError
from .guard import validate_url
from .limits import Limits
from .qr import QRResult, decode_image
from .text_decode import decode_html

MAX_IMAGES = 8
MAX_IMAGE_TOTAL = 20 * 1024 * 1024
MAX_DECODE_SECONDS = 20.0


@dataclass(frozen=True)
class ImageReference:
    index: int
    source_url: str
    url: str | None = None
    data: bytes | None = None
    skip_reason: str | None = None


@dataclass
class ImageDiscovery:
    images: list[ImageReference] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)


class _Images(BoundedHTMLParser):
    def __init__(self, source: str) -> None:
        super().__init__("page_qr_html_limit")
        self.source = source
        self.result = ImageDiscovery()
        self.has_base = False
        self.count = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.start_budget(tag, attrs)
        values = dict(attrs)
        if tag == "base":
            self.has_base = True
        if tag != "img":
            return
        self.count += 1
        width, height = values.get("width") or "", values.get("height") or ""
        if (
            len(width) <= 2
            and len(height) <= 2
            and width.isdigit()
            and height.isdigit()
            and int(width) <= 16
            and int(height) <= 16
        ):
            self.result.images.append(
                ImageReference(self.count, self.source, skip_reason="tracking_image_skipped")
            )
            return
        if len([item for item in self.result.images if not item.skip_reason]) >= MAX_IMAGES:
            self.result.gaps.append("page_qr_image_limit")
            return
        raw = values.get("src") or ""
        if not raw:
            self.result.gaps.append("page_qr_image_source_unavailable")
            return
        if raw.startswith("data:"):
            match = re.fullmatch(
                r"data:image/(png|jpeg|webp|heic|heif|bmp|gif|tiff|avif);base64,([A-Za-z0-9+/=]+)", raw
            )
            if not match:
                self.result.gaps.append("page_qr_data_invalid")
                return
            try:
                decoded = base64.b64decode(match[2], validate=True)
            except binascii.Error:
                self.result.gaps.append("page_qr_data_invalid")
                return
            self.result.images.append(ImageReference(self.count, self.source, data=decoded))
            return
        try:
            url = validate_url(urljoin(self.source, raw))
        except FxfetchError:
            self.result.gaps.append("page_qr_image_url_invalid")
            return
        if not any(item.url == url for item in self.result.images):
            self.result.images.append(ImageReference(self.count, self.source, url=url))

    def handle_endtag(self, tag: str) -> None:
        self.end_budget(tag)

    def handle_data(self, data: str) -> None:
        self.node_budget()


def discover_images(
    data: bytes, source_url: str, *, content_type: str | None = None
) -> ImageDiscovery:
    if len(data) > MAX_HTML_INPUT_BYTES:
        raise FxfetchError("page_qr_html_limit", "Page image discovery byte limit")
    parser = _Images(source_url)
    try:
        parser.feed(decode_html(data, content_type).text)
        parser.close()
    except (ValueError, UnicodeError, AssertionError) as error:
        raise FxfetchError("page_qr_html_invalid", "Page image discovery failed") from error
    if parser.has_base and parser.result.images:
        parser.result.gaps.append("page_qr_base_unsupported")
        parser.result.images = [
            item for item in parser.result.images if item.data is not None or item.skip_reason
        ]
    parser.result.gaps = list(dict.fromkeys(parser.result.gaps))
    return parser.result


def decode_saved_image(path: Path, limits: Limits) -> QRResult:
    return decode_image(path, limits)
