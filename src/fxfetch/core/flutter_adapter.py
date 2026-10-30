"""Bounded Flutter source inspection; never executes compiled application code."""

from __future__ import annotations

import codecs
import hashlib
import io
import re
import time
from collections.abc import Callable
from pathlib import Path
from threading import Event
from urllib.parse import urljoin, urlsplit

from .classify import classify_input
from .discovery import BoundedHTMLParser, Candidate
from .errors import FxfetchError
from .guard import validate_url
from .landing_adapter import LandingResult
from .text_decode import decode_html

MAX_BOOTSTRAP_BYTES = 256 * 1024
MAX_MAIN_BYTES = 64 * 1024 * 1024
SCAN_CHUNK_BYTES = 64 * 1024
_LITERAL_WINDOW = 8208
_LITERAL = re.compile(r"([\"\'])(https?://[^\"\'\\\r\n\s]{1,8192})\1")


class _Shell(BoundedHTMLParser):
    def __init__(self) -> None:
        super().__init__("flutter_html_limit")
        self.scripts: list[str] = []
        self.bases: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.start_budget(tag, attrs)
        values = dict(attrs)
        if tag == "script" and values.get("src"):
            self.scripts.append(values["src"] or "")
        if tag == "base" and values.get("href"):
            self.bases.append(values["href"] or "")

    def handle_endtag(self, tag: str) -> None:
        self.end_budget(tag)

    def handle_data(self, data: str) -> None:
        self.node_budget()


def _same_origin(reference: str, parent: str, source: str) -> str:
    url = validate_url(urljoin(parent, reference))
    def origin(value: str) -> tuple[str, str | None, int]:
        parts = urlsplit(value)
        return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)
    if origin(url) != origin(source):
        raise FxfetchError("flutter_resource_not_same_origin", "Flutter source changes origin")
    return url


def _check_scan(cancel: Event | None, deadline: float | None) -> None:
    if cancel is not None and cancel.is_set():
        raise FxfetchError("cancelled", "Flutter source scan cancelled")
    if deadline is not None and time.monotonic() >= deadline:
        raise FxfetchError("chain_timeout", "Flutter source scan time budget exceeded")


def _scan_source(
    resource: bytes | Path, maximum: int, chain: str, source_url: str,
    cancel: Event | None, deadline: float | None, *, bootstrap: bool = False,
) -> tuple[str, list[Candidate], int, str]:
    """Read once with bounded memory; publish results only after strict EOF."""
    decoder = codecs.getincrementaldecoder("utf-8-sig")("strict")
    digest = hashlib.sha256()
    size = 0
    window = ""
    bootstrap_parts: list[str] = []
    candidates: list[Candidate] = []
    seen: set[str] = set()
    wanted = "direct_apk" if chain == "android" else "direct_ipa"
    stream = resource.open("rb") if isinstance(resource, Path) else io.BytesIO(resource)
    with stream:
        while True:
            _check_scan(cancel, deadline)
            raw = stream.read(min(SCAN_CHUNK_BYTES, maximum - size + 1))
            if not raw:
                text = decoder.decode(b"", final=True)
            else:
                size += len(raw)
                if size > maximum:
                    raise FxfetchError("flutter_source_limit", "Flutter source exceeds byte limit")
                digest.update(raw)
                text = decoder.decode(raw)
            if bootstrap:
                bootstrap_parts.append(text)
            else:
                window += text
                # Re-scan the small overlap; URL deduplication makes this harmless.
                # Retaining the maximal literal length includes its opening quote.
                for match in _LITERAL.finditer(window):
                    # Compiled libraries contain URL examples and URI prefixes.
                    # Strings are data, not fetch instructions: discard malformed
                    # package literals locally, without hiding transport guard errors.
                    try:
                        path = urlsplit(match[2]).path.lower()
                    except ValueError:
                        continue
                    suffix = ".apk" if chain == "android" else ".ipa"
                    if not path.endswith(suffix):
                        continue
                    try:
                        item = classify_input(match[2])
                    except FxfetchError as error:
                        if error.code != "invalid_url":
                            raise
                        continue
                    if item.kind != wanted or item.request_url is None or item.request_url in seen:
                        continue
                    if len(seen) >= 32:
                        raise FxfetchError("flutter_candidate_limit", "Too many literal package references")
                    seen.add(item.request_url)
                    candidates.append(Candidate(item.request_url, item.kind, source_url,
                                                "", "script_literal"))
                window = window[-_LITERAL_WINDOW:]
            _check_scan(cancel, deadline)
            if not raw:
                break
    _check_scan(cancel, deadline)
    return "".join(bootstrap_parts), candidates, size, digest.hexdigest()


def discover_flutter(
    data: bytes, source_url: str, chain: str, fetch_resource: Callable[[str, int], bytes | Path],
    *, content_type: str | None = None, cancel: Event | None = None,
    deadline: float | None = None,
) -> LandingResult:
    """Inspect two explicit same-origin references under caller-enforced byte limits.

    Literal package strings remain unverified candidates. Flutter execution/API
    coverage is deliberately unresolved even when a literal was discovered.
    """
    result = LandingResult()
    parser = _Shell()
    parser.feed(decode_html(data, content_type).text)
    parser.close()
    bootstraps = [value for value in parser.scripts
                  if urlsplit(value).path.rsplit("/", 1)[-1] == "flutter_bootstrap.js"]
    if not bootstraps:
        return result
    result.supported = True
    try:
        if len(bootstraps) != 1 or len(parser.bases) > 1:
            raise FxfetchError("flutter_entry_ambiguous", "Flutter entry references are ambiguous")
        base = _same_origin(parser.bases[0], source_url, source_url) if parser.bases else source_url
        bootstrap_url = _same_origin(bootstraps[0], base, source_url)

        def fetch(
            url: str, maximum: int, role: str, parent: str,
        ) -> tuple[str, list[Candidate]]:
            _check_scan(cancel, deadline)
            resource = fetch_resource(url, maximum)
            _check_scan(cancel, deadline)
            text, candidates, size, digest = _scan_source(
                resource, maximum, chain, url, cancel, deadline, bootstrap=role == "flutter_bootstrap",
            )
            result.evidence.append({"url": url, "parent": parent, "role": role,
                                    "size": size, "sha256": digest})
            return text, candidates

        bootstrap, _ = fetch(bootstrap_url, MAX_BOOTSTRAP_BYTES, "flutter_bootstrap", source_url)
        paths = re.findall(r'"mainJsPath"\s*:\s*"([^"\\]{1,512})"', bootstrap)
        if len(paths) != 1:
            raise FxfetchError("flutter_main_reference_unknown", "No unique literal mainJsPath")
        main_url = _same_origin(paths[0], base, source_url)
        _, candidates = fetch(main_url, MAX_MAIN_BYTES, "flutter_main", bootstrap_url)
        _check_scan(cancel, deadline)
        result.candidates = candidates
        result.gaps = ["flutter_runtime_required"]
    except FxfetchError as error:
        if error.outcome == "blocked" or error.code in {
            "cancelled", "chain_timeout", "target_not_public", "dns_unsafe_answer", "dns_tls_verification_failed",
            "peer_mismatch", "tls_verification_failed",
            "invalid_url", "invalid_header", "invalid_framing", "response_header_limit",
        }:
            raise
        result.candidates = []
        result.gaps = ["flutter_source_" + error.code if error.code == "download_limit" else error.code]
    except OSError:
        result.candidates = []
        result.gaps = ["flutter_source_read_failed"]
    except UnicodeError:
        result.candidates = []
        result.gaps = ["flutter_source_encoding_unsupported"]
    return result
