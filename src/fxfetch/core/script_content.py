"""Bounded, non-executing discovery of literal GET requests for HTML content."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urljoin, urlsplit

from .discovery import BoundedHTMLParser, Candidate
from .errors import FxfetchError
from .guard import is_public, validate_url

MAX_SCRIPT_BYTES = 256 * 1024
MAX_SCRIPT_TOTAL = 1024 * 1024
MAX_TOKENS = 50_000
_LEX = re.compile(
    r'''(?P<skip>\s+|//[^\r\n]*|/\*[\s\S]*?\*/)|'''
    r'''(?P<string>"(?:\\[^\r\n]|[^"\\\r\n])*"|'(?:\\[^\r\n]|[^'\\\r\n])*')|'''
    r'''(?P<opaque>`(?:\\[\s\S]|[^`\\])*`|/(?:\\[^\r\n]|\[(?:\\.|[^\]\\\r\n])*\]|[^/\\\r\n])+/[a-z]*)|'''
    r'''(?P<word>[A-Za-z_$][\w$]*)|(?P<punct>.)'''
)
_ESCAPE = re.compile(r"\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[\\/'\"bfnrt])")


def _literal(token: tuple[str, str]) -> str | None:
    if token[0] != "string":
        return None
    text = token[1][1:-1]
    escapes = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
    if "\\" in _ESCAPE.sub("", text):
        return None
    return _ESCAPE.sub(lambda m: chr(int(m[1][1:], 16)) if m[1][0] in "ux"
                       else escapes.get(m[1], m[1]), text)


def _object(tokens: list[tuple[str, str]], start: int, depth: int = 0) -> tuple[dict, int]:
    """Only literal string dictionaries; reject expressions, spreads and calls."""
    if depth > 1 or tokens[start][1] != "{":
        raise ValueError("Not a bounded literal object")
    result: dict = {}
    index = start + 1
    while index < len(tokens) and tokens[index][1] != "}":
        key = _literal(tokens[index]) if tokens[index][0] == "string" else tokens[index][1]
        if tokens[index][0] not in {"word", "string"} or key in result or tokens[index + 1][1] != ":":
            raise ValueError("Invalid object key")
        index += 2
        if tokens[index][1] == "{":
            value, index = _object(tokens, index, depth + 1)
        else:
            value = _literal(tokens[index])
            if value is None:
                raise ValueError("Nonliteral value")
            index += 1
        result[key] = value
        if tokens[index][1] == ",":
            index += 1
        elif tokens[index][1] != "}":
            raise ValueError("Invalid object separator")
    if index >= len(tokens):
        raise ValueError("Unclosed object")
    return result, index + 1


def literal_html_requests(script: str) -> list[str]:
    if len(script.encode("utf-8")) > MAX_SCRIPT_BYTES:
        raise FxfetchError("browser_script_limit", "Inline script discovery byte limit exceeded")
    tokens: list[tuple[str, str]] = []
    for match in _LEX.finditer(script):
        if match.lastgroup == "punct" and match[0] in {"'", '"', "`"}:
            return []  # Do not reinterpret the contents of an unterminated literal.
        if match.lastgroup != "skip":
            tokens.append((match.lastgroup or "punct", match[0]))
        if len(tokens) > MAX_TOKENS:
            raise FxfetchError("browser_script_limit", "Inline script discovery token limit exceeded")
    found = []
    for index, token in enumerate(tokens):
        if token != ("word", "fetch"):
            continue
        if index and tokens[index - 1][1] == ".":
            if index < 2 or tokens[index - 2][1] not in {"window", "globalThis"}:
                continue
            if index >= 3 and tokens[index - 3][1] == ".":
                continue
        try:
            if tokens[index + 1][1] != "(":
                continue
            url = _literal(tokens[index + 2])
            if not url or not urlsplit(url).path.lower().endswith((".html", ".htm")):
                continue
            end = index + 3
            if tokens[end][1] == ",":
                # Bound each options parse independently, even in a large script.
                options, consumed = _object(tokens[end + 1:end + 65], 0)
                end += 1 + consumed
                if set(options) - {"method", "headers"} or options.get("method", "GET") != "GET":
                    continue
                headers = options.get("headers", {})
                if not isinstance(headers, dict) or any(k.lower() != "accept" or v != "text/html"
                                                       for k, v in headers.items()):
                    continue
            if tokens[end][1] != ")":
                continue
            found.append(url)
        except (ValueError, IndexError, TypeError, AttributeError):
            continue  # Unsupported syntax is not a request instruction.
    return list(dict.fromkeys(found))


class _Scripts(BoundedHTMLParser):
    def __init__(self) -> None:
        super().__init__("browser_script_limit")
        self.parts: list[str] = []
        self.active = False
        self.total = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.start_budget(tag, attrs)
        if tag == "script":
            values = dict(attrs)
            self.active = not values.get("src") and values.get("type", "") in {
                "", "text/javascript", "application/javascript", "module",
            }

    def handle_endtag(self, tag: str) -> None:
        self.end_budget(tag)
        if tag == "script":
            self.active = False

    def handle_data(self, data: str) -> None:
        self.node_budget()
        if self.active:
            self.total += len(data.encode("utf-8"))
            if self.total > MAX_SCRIPT_TOTAL or len(self.parts) >= 32:
                raise FxfetchError("browser_script_limit", "Inline script discovery total limit exceeded")
            self.parts.append(data)


def script_content_candidates(html: str, source: str, base: str, maximum: int) -> list[Candidate]:
    parser = _Scripts()
    parser.feed(html)
    parser.close()
    found: dict[str, Candidate] = {}
    for script in parser.parts:
        for literal in literal_html_requests(script):
            try:
                url = validate_url(urljoin(base, literal))
            except (ValueError, FxfetchError):
                continue
            try:
                address = ipaddress.ip_address(urlsplit(url).hostname or "")
            except ValueError:
                address = None  # DNS is checked only by the connection-time guard.
            if address is not None and not is_public(str(address)):
                continue
            found.setdefault(url, Candidate(url, "http", source, action="script_content_link"))
            if len(found) > maximum:
                raise FxfetchError("candidate_limit", "Script content candidate limit exceeded")
    return list(found.values())
