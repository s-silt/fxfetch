"""Local, inert HTML snapshots from already collected, bounded materials."""

from __future__ import annotations

import hashlib
import html
import re
import warnings
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from PIL import Image

from .discovery import MAX_HTML_DEPTH, MAX_HTML_INPUT_BYTES, BoundedHTMLParser
from .errors import FxfetchError
from .guard import validate_url
from .limits import Limits
from .text_decode import decode_html

DEFAULT_LIMITS = Limits()
MAX_RESOURCES = 20
MAX_RESOURCE_BYTES = 2 * 1024 * 1024
MAX_RESOURCE_TOTAL = 16 * 1024 * 1024
NEUTRAL_CSS = "body{font-family:sans-serif;line-height:1.6;margin:1rem;color:#222;background:#fff;overflow-wrap:anywhere}img{max-width:100%;height:auto}table{border-collapse:collapse;max-width:100%}td,th{border:1px solid #ddd;padding:.4rem}pre{white-space:pre-wrap}a{color:inherit}"
SAFE_PROPERTIES = frozenset(
    {
        "color",
        "background-color",
        "font-size",
        "font-weight",
        "font-style",
        "text-align",
        "text-decoration",
        "line-height",
        "margin",
        "margin-top",
        "margin-bottom",
        "margin-left",
        "margin-right",
        "padding",
        "border",
        "border-color",
        "border-width",
        "border-style",
        "display",
        "width",
        "height",
        "max-width",
        "min-width",
        "max-height",
        "border-radius",
    }
)


def _origin(url: str) -> tuple[str, str | None, int]:
    parts = urlsplit(url)
    return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)


def _declarations(text: str) -> str:
    if len(text) > 65536 or re.search(
        r"url\s*\(|expression|@|\\|/\*|[<>]|javascript|binding|behavior", text, re.I
    ):
        return ""
    declarations: list[str] = []
    for part in text.split(";"):
        key, separator, value = part.partition(":")
        key, value = key.strip().lower(), value.strip()
        if (
            separator
            and key in SAFE_PROPERTIES
            and len(value) <= 128
            and re.fullmatch(r"[a-zA-Z0-9#.,%() +\-]+", value)
        ):
            declarations.append(f"{key}:{value}")
    return ";".join(declarations)


def _stylesheet(data: bytes) -> str:
    if len(data) > MAX_RESOURCE_BYTES:
        return ""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError:
        return ""
    if re.search(r"url\s*\(|expression|@|\\|/\*|[<>]|javascript|binding|behavior", text, re.I):
        return ""
    # One forward scan; an unanchored regex here can retry a long selector
    # at every position when its opening/closing brace is absent.
    result: list[str] = []
    position = 0
    rules = 0
    output_bytes = 0
    while position < len(text):
        opening = text.find("{", position)
        if opening < 0:
            break
        closing = text.find("}", opening + 1)
        if closing < 0:
            return ""
        if text.find("{", opening + 1, closing) >= 0:
            return ""
        rules += 1
        if rules > 1000:
            return ""
        selector = text[position:opening].strip()
        body = text[opening + 1 : closing]
        position = closing + 1
        declarations = _declarations(body)
        if declarations and len(selector) <= 256 and re.fullmatch(r"[a-zA-Z0-9.# _>*,:+\-]+", selector):
            rule = selector + "{" + declarations + "}"
            output_bytes += len(rule)
            if output_bytes > 65536:
                return ""
            result.append(rule)
    return "".join(result)


@dataclass(frozen=True)
class ResourceReference:
    url: str
    kind: str


class _Resources(BoundedHTMLParser):
    def __init__(self, source: str) -> None:
        super().__init__("offline_html_limit")
        self.source = source
        self.references: list[ResourceReference] = []
        self.has_base = False
        self.relative: set[str] = set()

    def add(self, raw: str, kind: str) -> None:
        if len(self.references) > MAX_RESOURCES:
            return
        try:
            url = validate_url(urljoin(self.source, raw))
            reference = ResourceReference(url, kind)
            if _origin(url) == _origin(self.source) and reference not in self.references:
                self.references.append(reference)
                if not urlsplit(raw).scheme:
                    self.relative.add(url)
        except (FxfetchError, ValueError):
            return

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.start_budget(tag, attrs)
        values = dict(attrs)
        if tag == "base":
            self.has_base = True
        if tag == "img" and values.get("src"):
            self.add(values["src"] or "", "image")
        if tag == "link" and "stylesheet" in (values.get("rel") or "").lower().split() and values.get("href"):
            self.add(values["href"] or "", "css")

    def handle_endtag(self, tag: str) -> None:
        self.end_budget(tag)

    def handle_data(self, data: str) -> None:
        self.node_budget()

    def finish(self) -> None:
        if self.has_base:
            self.references = [
                reference for reference in self.references if reference.url not in self.relative
            ]


def resource_references(
    data: bytes, source_url: str, content_type: str | None = None
) -> list[ResourceReference]:
    if len(data) > MAX_HTML_INPUT_BYTES:
        raise FxfetchError("offline_html_limit", "Offline HTML exceeds parser byte budget")
    parser = _Resources(validate_url(source_url))
    try:
        parser.feed(decode_html(data, content_type).text)
        parser.close()
        parser.finish()
    except (ValueError, UnicodeError, AssertionError) as exc:
        raise FxfetchError("offline_html_invalid", "Static resource references could not be parsed") from exc
    return parser.references


@dataclass
class OfflineResult:
    available: bool = False
    entry: Path | None = None
    files: list[Path] = field(default_factory=list)
    bytes: int = 0
    coverage: str = "partial"
    reasons: list[str] = field(default_factory=list)


class _Sanitizer(BoundedHTMLParser):
    allowed = frozenset(
        {
            "p",
            "div",
            "span",
            "article",
            "section",
            "header",
            "footer",
            "main",
            "nav",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "ul",
            "ol",
            "li",
            "dl",
            "dt",
            "dd",
            "br",
            "hr",
            "strong",
            "b",
            "em",
            "i",
            "u",
            "small",
            "blockquote",
            "pre",
            "code",
            "table",
            "thead",
            "tbody",
            "tfoot",
            "tr",
            "td",
            "th",
            "caption",
            "figure",
            "figcaption",
        }
    )
    blocked = frozenset(
        {
            "script",
            "form",
            "iframe",
            "object",
            "embed",
            "svg",
            "math",
            "template",
            "style",
            "head",
            "noscript",
            "audio",
            "video",
            "canvas",
        }
    )
    void = BoundedHTMLParser.void_tags

    def __init__(self, source: str, images: dict[str, str]) -> None:
        super().__init__("offline_html_limit")
        self.source = source
        self.images = images
        self.output: list[str] = []
        self.suppressed: list[str] = []
        self.open_tags: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.start_budget(tag, attrs)
        if self.suppressed:
            if tag not in self.void:
                if len(self.suppressed) >= MAX_HTML_DEPTH:
                    raise FxfetchError("offline_html_limit", "Suppressed HTML nesting exceeds limit")
                self.suppressed.append(tag)
            return
        if tag in self.blocked:
            if tag not in self.void:
                self.suppressed.append(tag)
            return
        values = dict(attrs)
        if tag == "img":
            try:
                url = validate_url(urljoin(self.source, values.get("src") or ""))
            except FxfetchError:
                return
            if url in self.images:
                self.output.append(
                    '<img src="'
                    + html.escape(self.images[url], quote=True)
                    + '" alt="'
                    + html.escape((values.get("alt") or "")[:512], quote=True)
                    + '">'
                )
            elif values.get("alt"):
                self.output.append(html.escape((values["alt"] or "")[:512]))
            return
        rendered = "span" if tag == "a" else tag
        if rendered not in self.allowed:
            return
        safe_attrs = ""
        for key in ("id", "class"):
            value = values.get(key) or ""
            if value and len(value) <= 256 and re.fullmatch(r"[a-zA-Z0-9_ \-]+", value):
                safe_attrs += f' {key}="{html.escape(value, quote=True)}"'
        declarations = _declarations(values.get("style") or "")
        if declarations:
            safe_attrs += ' style="' + html.escape(declarations, quote=True) + '"'
        self.output.append("<" + rendered + safe_attrs + ">")
        if tag not in self.void:
            if len(self.open_tags) >= MAX_HTML_DEPTH:
                raise FxfetchError("offline_html_limit", "Rendered HTML nesting exceeds limit")
            self.open_tags.append((tag, rendered))

    def handle_endtag(self, tag: str) -> None:
        self.end_budget(tag)
        if self.suppressed:
            if tag in self.suppressed:
                reverse = len(self.suppressed) - 1 - self.suppressed[::-1].index(tag)
                del self.suppressed[reverse:]
            return
        for index in range(len(self.open_tags) - 1, -1, -1):
            if self.open_tags[index][0] == tag:
                self.output.extend("</" + rendered + ">" for _, rendered in reversed(self.open_tags[index:]))
                del self.open_tags[index:]
                break

    def handle_data(self, data: str) -> None:
        self.node_budget()
        if not self.suppressed:
            self.output.append(html.escape(data))

    def finish(self) -> str:
        self.output.extend("</" + rendered + ">" for _, rendered in reversed(self.open_tags))
        return "".join(self.output)


class OfflineBundle:
    def __init__(self, limits: Limits = DEFAULT_LIMITS) -> None:
        self.limits = limits

    def build(
        self,
        html_path: Path,
        source_url: str,
        resources: Mapping[str, Path],
        output_dir: Path,
        *,
        max_bytes: int | None = None,
        html_content_type: str | None = None,
    ) -> OfflineResult:
        result = OfflineResult(reasons=["static_snapshot_only"])
        byte_budget = min(
            self.limits.max_task_bytes,
            max_bytes
            if max_bytes is not None
            else self.limits.max_body_bytes + MAX_RESOURCE_TOTAL + 2 * 1024 * 1024,
        )
        written = 0
        try:
            if html_path.stat().st_size > self.limits.max_body_bytes:
                raise FxfetchError("offline_html_limit", "Saved HTML exceeds snapshot limit")
            data = html_path.read_bytes()
            decoded = decode_html(data, html_content_type)
            references = resource_references(data, source_url, html_content_type)
            if len(references) > MAX_RESOURCES:
                result.reasons.append("resource_limit")
            output_dir.mkdir(parents=True, exist_ok=True)
            assets = output_dir / "assets"
            assets.mkdir(exist_ok=True)
            images: dict[str, str] = {}
            css = NEUTRAL_CSS
            source_bytes = 0
            for reference in references[:MAX_RESOURCES]:
                path = resources.get(reference.url)
                if path is None:
                    result.reasons.append("resource_unavailable")
                    continue
                size = path.stat().st_size
                source_bytes += size
                if size > MAX_RESOURCE_BYTES or source_bytes > MAX_RESOURCE_TOTAL:
                    result.reasons.append("resource_limit")
                    continue
                if reference.kind == "css":
                    cleaned = _stylesheet(path.read_bytes())
                    if cleaned:
                        css += cleaned
                    else:
                        result.reasons.append("css_removed")
                    continue
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("error", Image.DecompressionBombWarning)
                        with Image.open(path) as image:
                            extension = {"PNG": "png", "JPEG": "jpg", "WEBP": "webp"}.get(image.format or "")
                            if (
                                extension is None
                                or getattr(image, "n_frames", 1) != 1
                                or image.width * image.height > 4_000_000
                            ):
                                raise ValueError("unsafe snapshot image")
                            image.verify()
                    raw = path.read_bytes()
                    name = hashlib.sha256(raw).hexdigest() + "." + extension
                    target = assets / name
                    if target not in result.files and written + len(raw) > byte_budget:
                        result.reasons.append("offline_disk_limit")
                        continue
                    target.write_bytes(raw)
                    images[reference.url] = "assets/" + name
                    if target not in result.files:
                        result.files.append(target)
                        written += len(raw)
                except (OSError, ValueError, Image.DecompressionBombError, Image.DecompressionBombWarning):
                    result.reasons.append("image_removed")
            parser = _Sanitizer(source_url, images)
            parser.feed(decoded.text)
            parser.close()
            body = parser.finish()
            visible_text = html.unescape(re.sub(r"<[^>]*>", "", body)).strip()
            if not visible_text and "<img " not in body:
                raise FxfetchError("offline_no_visible_content", "Saved HTML has no usable static content")
            style = assets / "style.css"
            if written + len(css.encode("utf-8")) > byte_budget:
                raise FxfetchError("offline_disk_limit", "Offline asset budget exceeded")
            style.write_text(css, encoding="utf-8")
            written += style.stat().st_size
            entry = output_dir / "index.html"
            csp = "default-src 'none'; img-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'none'; connect-src 'none'; frame-src 'none'"
            document = (
                '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="'
                + html.escape(csp, quote=True)
                + '"><link rel="stylesheet" href="assets/style.css"></head><body>'
                + body
                + "</body></html>"
            )
            encoded = document.encode("utf-8")
            if len(encoded) > self.limits.max_body_bytes:
                raise FxfetchError("offline_html_limit", "Sanitized snapshot exceeds limit")
            if written + len(encoded) > byte_budget:
                raise FxfetchError("offline_disk_limit", "Offline document budget exceeded")
            entry.write_bytes(encoded)
            result.files.extend([style, entry])
            result.available, result.entry = True, entry
            result.bytes = sum(path.stat().st_size for path in result.files)
            result.reasons = list(dict.fromkeys(result.reasons))
        except (FxfetchError, OSError, UnicodeError, ValueError, AssertionError) as error:
            result.reasons.append(error.code if isinstance(error, FxfetchError) else "offline_build_failed")
        return result
