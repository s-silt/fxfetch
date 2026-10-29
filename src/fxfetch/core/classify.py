"""Input classification without DNS, HTTP, or preview requests."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

from .errors import FxfetchError
from .guard import validate_url


@dataclass(frozen=True)
class ClassifiedInput:
    kind: str
    original: str
    request_url: str | None


def normalize_entry_url(text: str) -> str:
    """Complete a user-entered web address offline, preserving path/query/fragment.

    This is an input convenience only; validate_url and the connection-time
    public-address guard remain mandatory. Explicit foreign schemes are never
    reinterpreted as hostnames. The existing strict IPA manifest entry remains.
    """
    if len(text.encode("utf-8")) > 8192:
        raise FxfetchError("invalid_url", "Input exceeds limit")
    value = text.strip()
    if not value or re.search(r"[\x00-\x20\x7f\\]", value):
        raise FxfetchError("invalid_url", "Input contains forbidden characters")
    if re.match(r"(?i)^itms-services:", value):
        classify_input(value)
        return value
    if re.match(r"(?i)^https?:/(?!/)", value):
        value = value.replace(":/", "://", 1)
    elif value.startswith("//"):
        value = "https:" + value
    elif not re.match(r"(?i)^https?://", value):
        scheme = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", value)
        # A dotted host with a numeric port is unambiguous pasted authority.
        host_port = re.match(r"^[^/?#:\[\]]+\.[^/?#:]+:[0-9]+(?:[/?#]|$)", value)
        if scheme and not host_port:
            raise FxfetchError("unsupported_input", "Unsupported explicit URL scheme")
        candidate = "https://" + value
        normalized = validate_url(candidate)
        host = urlsplit(normalized).hostname or ""
        if "." not in host and ":" not in host:
            raise FxfetchError("invalid_url", "Enter a domain name or a complete HTTP(S) URL")
        value = candidate
    validate_url(value)
    return value


def classify_input(url: str) -> ClassifiedInput:
    if len(url.encode("utf-8")) > 8192 or re.search(r"[\x00-\x20\x7f\\]", url):
        raise FxfetchError("invalid_url", "Input contains forbidden characters or exceeds limit")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise FxfetchError("invalid_url", "Malformed URL") from exc
    if parts.scheme.lower() == "itms-services":
        if parts.netloc or parts.path not in ("", "/") or parts.fragment:
            raise FxfetchError("invalid_manifest_url", "Invalid itms-services structure")
        values = parse_qs(parts.query, keep_blank_values=True)
        if (
            set(values) != {"action", "url"}
            or values["action"] != ["download-manifest"]
            or len(values["url"]) != 1
        ):
            raise FxfetchError("invalid_manifest_url", "Expected one download-manifest URL")
        return ClassifiedInput("itms_manifest", url, validate_url(values["url"][0]))
    if parts.scheme.lower() not in ("http", "https"):
        return ClassifiedInput("unsupported", url, None)
    normalized = validate_url(url)
    parts = urlsplit(normalized)
    host = parts.hostname or ""
    if host in ("apps.apple.com", "itunes.apple.com", "testflight.apple.com", "play.google.com"):
        return ClassifiedInput("store", url, normalized)
    path = parts.path.lower()
    kind = (
        "direct_apk"
        if path.endswith(".apk")
        else "direct_ipa"
        if path.endswith(".ipa")
        else "itms_manifest"
        if path.endswith(".plist")
        else "http"
    )
    return ClassifiedInput(kind, url, normalized)
