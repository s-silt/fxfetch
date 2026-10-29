"""Strict, bounded charset selection for saved web material; no heuristic replacement."""

from __future__ import annotations

import codecs
import re
from dataclasses import dataclass
from html.parser import HTMLParser

from .errors import FxfetchError

_CHARSET = re.compile(r"charset\s*=\s*[\"']?\s*([a-zA-Z0-9_.:-]+)", re.I)
_ALLOWED = frozenset(
    {
        "utf-8",
        "utf-16",
        "utf-16-le",
        "utf-16-be",
        "utf-32",
        "utf-32-le",
        "utf-32-be",
        "gb18030",
        "big5",
        "cp1252",
        "iso8859-1",
        "ascii",
        "shift_jis",
        "euc_jp",
        "euc_kr",
    }
)


@dataclass(frozen=True)
class DecodedText:
    text: str
    encoding: str
    source: str


def _canonical(label: str) -> str:
    try:
        name = codecs.lookup(label.strip()).name
    except LookupError as exc:
        raise FxfetchError("text_charset_unsupported", "Unsupported declared text encoding") from exc
    if name in {"gb2312", "gbk"}:
        name = "gb18030"
    if name == "utf-8-sig":
        name = "utf-8"
    if name not in _ALLOWED:
        raise FxfetchError("text_charset_unsupported", "Unsupported declared text encoding")
    return name


class _MetaCharsets(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.labels: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "meta":
            return
        values = dict(attrs)
        if values.get("charset"):
            self.labels.append(values["charset"] or "")
        elif (values.get("http-equiv") or "").lower() == "content-type":
            match = _CHARSET.search(values.get("content") or "")
            if match:
                self.labels.append(match[1])


def decode_html(data: bytes, content_type: str | None = None) -> DecodedText:
    """Honor consistent explicit declarations; otherwise require valid UTF-8.

    Ambiguous or corrupt bytes remain a coverage gap, never U+FFFD output.
    Only the initial 8192 bytes are inspected for HTML declarations.
    """
    declarations: list[tuple[str, str]] = []
    bom_encoding: str | None = None
    for bom, encoding in (
        (codecs.BOM_UTF32_LE, "utf-32-le"),
        (codecs.BOM_UTF32_BE, "utf-32-be"),
        (codecs.BOM_UTF8, "utf-8"),
        (codecs.BOM_UTF16_LE, "utf-16-le"),
        (codecs.BOM_UTF16_BE, "utf-16-be"),
    ):
        if data.startswith(bom):
            bom_encoding = encoding
            declarations.append((encoding, "bom"))
            break
    if content_type:
        for match in _CHARSET.finditer(content_type):
            declarations.append((_canonical(match[1]), "http"))
    prefix_encoding = bom_encoding or "latin-1"
    try:
        prefix = data[:8192].decode(prefix_encoding, errors="ignore")
    except UnicodeError as exc:
        raise FxfetchError("text_decode_failed", "Text prefix could not be decoded") from exc
    parser = _MetaCharsets()
    parser.feed(prefix)
    for label in parser.labels:
        declarations.append((_canonical(label), "meta"))
    encoding, source = declarations[0] if declarations else ("utf-8", "default")
    for other, _ in declarations[1:]:
        if other == encoding or (other in {"utf-16", "utf-32"} and encoding.startswith(other + "-")):
            continue
        raise FxfetchError("text_charset_conflict", "Saved text contains conflicting charset declarations")
    try:
        text = data.decode(encoding).lstrip("\ufeff")
    except UnicodeError as exc:
        raise FxfetchError("text_decode_failed", "Saved text is invalid for its selected charset") from exc
    if "\ufffd" in text or "\x00" in text:
        raise FxfetchError("text_decode_failed", "Saved text already contains replacement characters")
    return DecodedText(text, encoding, source)
