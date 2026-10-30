"""Bounded APK URLs in explicit download fields of already received JSON scripts.

This does not fetch API endpoints, external scripts or arbitrary string values.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlsplit

from .classify import classify_input
from .discovery import BoundedHTMLParser, Candidate, Discovery
from .errors import FxfetchError

MAX_JSON_BYTES = 256 * 1024
MAX_JSON_TOTAL = 512 * 1024
MAX_JSON_SCRIPTS = 16
MAX_JSON_NODES = 4096
MAX_JSON_DEPTH = 16
_FIELDS = {"apk", "apkurl", "apkdownloadurl", "androidapkurl", "androiddownloadurl",
           "downloadurl", "packageurl", "packagedownloadurl", "download", "package"}
_CONTAINERS = {"download", "downloads", "package", "packages", "apk"}


class _EmbeddedJSON(BoundedHTMLParser):
    def __init__(self) -> None:
        super().__init__("embedded_json_limit")
        self.parts: list[tuple[int, str]] = []
        self.active: int | None = None
        self.script_number = 0
        self.current: list[str] = []
        self.current_bytes = self.total_bytes = 0
        self.has_base = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.start_budget(tag, attrs)
        if tag == "base":
            self.has_base = True
        if tag == "script":
            self.script_number += 1
            values = dict(attrs)
            if (not values.get("src") and (values.get("type") or "").strip().lower() == "application/json"
                    and not any(parent in {"template", "noscript", "svg"} for parent in self.budget_stack)):
                if len(self.parts) >= MAX_JSON_SCRIPTS:
                    raise FxfetchError("embedded_json_limit", "Embedded JSON script count exceeded")
                self.active = self.script_number
                self.current, self.current_bytes = [], 0

    def handle_data(self, data: str) -> None:
        self.node_budget()
        if self.active is not None:
            size = len(data.encode("utf-8"))
            self.current_bytes += size
            self.total_bytes += size
            if self.current_bytes > MAX_JSON_BYTES or self.total_bytes > MAX_JSON_TOTAL:
                raise FxfetchError("embedded_json_limit", "Embedded JSON byte budget exceeded")
            self.current.append(data)

    def handle_endtag(self, tag: str) -> None:
        self.end_budget(tag)
        if tag == "script" and self.active is not None:
            self.parts.append((self.active, "".join(self.current)))
            self.active, self.current = None, []


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON key")
        value[key] = item
    return value


def _values(value: object) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    pending: list[tuple[object, str, int, bool]] = [(value, "", 0, False)]
    count = 0
    while pending:
        item, pointer, depth, container = pending.pop()
        count += 1
        if count > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ValueError("JSON structural budget exceeded")
        if isinstance(item, dict):
            if count + len(pending) + len(item) > MAX_JSON_NODES:
                raise ValueError("JSON structural budget exceeded")
            for key, child in reversed(list(item.items())):
                if len(key) > 256:
                    raise ValueError("JSON key exceeds budget")
                path = pointer + "/" + key.replace("~", "~0").replace("/", "~1")
                field = re.sub(r"[_-]", "", key).lower()
                if isinstance(child, str) and (field in _FIELDS or (container and field == "url")):
                    if len(path) <= 120:
                        found.append((path, child))
                    else:
                        raise ValueError("JSON source pointer exceeds budget")
                pending.append((child, path, depth + 1, field in _CONTAINERS))
        elif isinstance(item, list):
            if count + len(pending) + len(item) > MAX_JSON_NODES:
                raise ValueError("JSON structural budget exceeded")
            pending.extend((child, pointer + "/" + str(index), depth + 1, container)
                           for index, child in reversed(list(enumerate(item))))
    return found


def _reject_constant(_: str) -> object:
    raise ValueError("Nonfinite JSON")


def embedded_json_packages(html: str, source: str, maximum: int) -> Discovery:
    result = Discovery()
    parser = _EmbeddedJSON()
    try:
        parser.feed(html)
        parser.close()
    except FxfetchError:
        result.gaps.append("embedded_json_limit")
        return result
    if parser.active is not None:
        result.gaps.append("embedded_json_incomplete")
    found: dict[str, Candidate] = {}
    for number, text in parser.parts:
        try:
            value = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
            references = _values(value)
        except (ValueError, RecursionError):
            result.gaps.append("embedded_json_incomplete")
            continue
        for pointer, reference in references:
            try:
                if parser.has_base and not urlsplit(reference).scheme:
                    continue
                parsed = classify_input(urljoin(source, reference))
            except (ValueError, FxfetchError):
                continue
            if parsed.kind != "direct_apk" or parsed.request_url is None:
                continue
            found.setdefault(parsed.request_url, Candidate(
                parsed.request_url, parsed.kind, source,
                label=f"JSON script {number} {pointer}", action="embedded_json_package_link",
            ))
            if len(found) > maximum:
                raise FxfetchError("candidate_limit", "Embedded JSON package candidate budget exceeded")
    result.candidates = list(found.values())
    result.gaps = list(dict.fromkeys(result.gaps))
    return result
