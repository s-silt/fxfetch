"""Bounded static discovery; strings never imply successful package retrieval."""

from __future__ import annotations

import json
import plistlib
import re
import sys
import tempfile
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from threading import Event
from urllib.parse import urldefrag, urljoin, urlsplit

from .classify import classify_input
from .errors import FxfetchError
from .process_limits import run_limited

MAX_HTML_INPUT_BYTES = 8 * 1024 * 1024
MAX_HTML_NODES = 20_000
MAX_HTML_DEPTH = 256
MAX_HTML_OPERATIONS = 1_000_000


class BoundedHTMLParser(HTMLParser):
    """Charge parser events and cap stack scans before doing subclass work."""

    void_tags = frozenset(
        {
            "area",
            "base",
            "br",
            "col",
            "embed",
            "hr",
            "img",
            "input",
            "link",
            "meta",
            "param",
            "source",
            "track",
            "wbr",
        }
    )

    def __init__(self, reason_code: str) -> None:
        super().__init__(convert_charrefs=True)
        self.budget_reason = reason_code
        self.budget_nodes = 0
        self.budget_operations = 0
        self.budget_stack: list[str] = []

    def node_budget(self, operations: int = 1) -> None:
        self.budget_nodes += 1
        self.budget_operations += operations
        if self.budget_nodes > MAX_HTML_NODES or self.budget_operations > MAX_HTML_OPERATIONS:
            raise FxfetchError(self.budget_reason, "HTML node or operation budget exceeded")

    def start_budget(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.node_budget(len(attrs) + 1)
        attribute_bytes = 0
        for key, value in attrs:
            text = value or ""
            # Inline images have their own decode/pixel budgets. Count their
            # payload against the bounded HTML input, not the small ordinary
            # attribute budget used for URLs, IDs and other page metadata.
            inline_image = tag == "img" and key == "src" and re.match(
                r"^data:image/[a-z0-9.+-]+;base64,", text[:128], re.I,
            )
            if inline_image:
                if len(text) > MAX_HTML_INPUT_BYTES:
                    raise FxfetchError(self.budget_reason, "Inline image attribute exceeds HTML budget")
                attribute_bytes += len(key) + 128
            else:
                attribute_bytes += len(key) + len(text)
        if (
            len(tag) > 128
            or len(attrs) > 128
            or attribute_bytes > 65536
        ):
            raise FxfetchError(self.budget_reason, "HTML tag or attributes exceed parser budget")
        if tag not in self.void_tags:
            if len(self.budget_stack) >= MAX_HTML_DEPTH:
                raise FxfetchError(self.budget_reason, "HTML nesting exceeds parser budget")
            self.budget_stack.append(tag)

    def end_budget(self, tag: str) -> None:
        self.node_budget(len(self.budget_stack) + 1)
        for index in range(len(self.budget_stack) - 1, -1, -1):
            if self.budget_stack[index] == tag:
                del self.budget_stack[index:]
                return

    def handle_comment(self, data: str) -> None:
        self.node_budget()

    def handle_decl(self, decl: str) -> None:
        self.node_budget()

    def handle_pi(self, data: str) -> None:
        self.node_budget()

    def unknown_decl(self, data: str) -> None:
        self.node_budget()


@dataclass(frozen=True)
class Candidate:
    url: str
    kind: str
    source_url: str
    label: str = ""
    action: str = ""


@dataclass
class Discovery:
    candidates: list[Candidate] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)


def download_action(
    label: str, href: str, attrs: dict[str, str | None], *, require_short: bool = False
) -> str:
    """Recognize a download control, excluding keyword-bearing article/navigation text."""
    if "download" in attrs and not require_short:
        return "download_attribute"
    control = bool(re.search(
        r"(?:^|[\s_-])(?:download|install)(?:[\s_-]?(?:btn|button))?(?:$|[\s_-])",
        (attrs.get("class") or "") + " " + (attrs.get("id") or ""), re.I,
    ))
    short_action = bool(re.fullmatch(
        r"(?:(?:立即|点击|免费|官方|安全|安卓|苹果|Android|iOS|iPhone|APK|APP)\s*)*"
        r"(?:下载并安装|下载安装|下载|安装|download(?:\s+and\s+install)?|install)"
        r"(?:\s*(?:APP|APK|Android|iOS|now|app))?",
        " ".join(label.split()), re.I,
    ) or re.fullmatch(
        r"get\s+(?:(?:the\s+)?(?:apk|android\s+app)|(?:the\s+)?app\s+for\s+android)",
        " ".join(label.split()), re.I,
    ))
    navigation = bool(re.search(r"首页|分类|标签|文章|教程|指南|说明|帮助|客服|如何|怎么|遇|之后|后|\?", label))
    html_article = bool(re.search(r"\.(?:html?|php)$", urlsplit(href).path, re.I))
    return "download_control" if (control and not require_short) or (
        short_action and not navigation and not html_article
    ) else ""


class _Parser(BoundedHTMLParser):
    def __init__(self, source: str, maximum: int) -> None:
        super().__init__("html_parse_limit")
        self.source = source
        self.maximum = maximum
        self.result = Discovery()
        self.anchor_href: str | None = None
        self.anchor_text: list[str] = []
        self.anchor_attrs: dict[str, str | None] = {}

    def add(self, raw: str, explicit: bool = False, *, label: str = "", action: str = "") -> None:
        if not raw.strip() or raw.strip().startswith("#"):
            return
        absolute = urljoin(self.source, raw.strip())
        if urldefrag(absolute)[0] == urldefrag(self.source)[0]:
            return
        try:
            item = classify_input(absolute)
        except FxfetchError:
            self.result.gaps.append("invalid_candidate")
            return
        if item.kind in ("store", "unsupported"):
            if explicit:
                self.result.gaps.append("unsupported_candidate")
            return
        if item.kind == "http" and not explicit:
            return
        if item.request_url is None:
            return
        label = " ".join(label.split())[:160]
        candidate = Candidate(item.request_url, item.kind, self.source, label, action)
        existing = next(
            (
                i
                for i, old in enumerate(self.result.candidates)
                if old.url == candidate.url and old.kind == candidate.kind
            ),
            None,
        )
        if existing is not None:
            if action and not self.result.candidates[existing].action:
                self.result.candidates[existing] = candidate
        else:
            if len(self.result.candidates) >= self.maximum:
                raise FxfetchError("candidate_limit", "Static candidate limit exceeded")
            self.result.candidates.append(candidate)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.start_budget(tag, attrs)
        values = dict(attrs)
        if tag in ("script", "iframe", "frame", "object", "embed", "form") or any(
            key.startswith("on") for key in values
        ):
            self.result.gaps.append("browser_required")
        if tag == "base":
            self.result.gaps.append("base_url_unsupported")
        if tag in ("a", "area") and values.get("href"):
            if tag == "area":
                self.add(
                    values["href"] or "",
                    explicit="download" in values,
                    label=values.get("alt") or "",
                    action="download_attribute" if "download" in values else "",
                )
            if tag == "a":
                self.anchor_href = values["href"]
                self.anchor_text = []
                self.anchor_attrs = values
        if tag == "meta" and (values.get("http-equiv") or "").lower() == "refresh":
            match = re.fullmatch(
                r"\s*\d+(?:\.\d+)?\s*;\s*url\s*=\s*[\"\']?(.*?)[\"\']?\s*", values.get("content") or "", re.I
            )
            if match:
                self.add(match[1], explicit=True, action="refresh")
            else:
                self.result.gaps.append("invalid_refresh")

    def handle_data(self, data: str) -> None:
        self.node_budget()
        if self.anchor_href is not None:
            self.anchor_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        self.end_budget(tag)
        if tag == "a" and self.anchor_href is not None:
            label = " ".join("".join(self.anchor_text).split())
            attrs = self.anchor_attrs
            action = download_action(label, self.anchor_href, attrs)
            self.add(
                self.anchor_href,
                explicit=bool(action),
                label=label,
                action=action,
            )
            self.anchor_href = None
            self.anchor_text = []


class _ChallengePage(BoundedHTMLParser):
    """Require rendered verification UI; SDK names and fallback text are not gates."""

    def __init__(self) -> None:
        super().__init__("html_parse_limit")
        self.elements: list[tuple[str, bool]] = []
        self.visible: list[str] = []
        self.widget = False
        self.credentials = False
        self.cf_structure = False
        self.cf_script = False
        self.active_control = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.start_budget(tag, attrs)
        values = dict(attrs)
        suppressed = (
            bool(self.elements and self.elements[-1][1])
            or tag in {"script", "style", "noscript", "template", "svg"}
            or "hidden" in values
            or (values.get("aria-hidden") or "").lower() == "true"
            or bool(
                re.search(r"(?:display\s*:\s*none|visibility\s*:\s*hidden)", values.get("style") or "", re.I)
            )
        )
        if tag not in self.void_tags:
            self.elements.append((tag, suppressed))
        if tag == "script" and "/cdn-cgi/challenge-platform/" in (values.get("src") or ""):
            self.cf_script = True
        if suppressed:
            return
        identity = " ".join(values.get(key) or "" for key in ("id", "class", "name"))
        if re.search(
            r"(?:^|[\s_-])(?:challenge-form|challenge-stage|challenge-running|cf-challenge-running)(?:$|[\s_-])",
            identity,
            re.I,
        ):
            self.cf_structure = True
        if tag == "input" and (values.get("type") or "").lower() in {"password", "email", "tel"}:
            self.credentials = True
        if tag == "form" and re.search(
            r"(?:login|sign[-_]?in|register)", identity + " " + (values.get("action") or ""), re.I
        ):
            self.credentials = True
        if tag == "input" and (values.get("autocomplete") or "") in {
            "username",
            "current-password",
            "new-password",
        }:
            self.credentials = True
        if tag in {"button", "input", "iframe"}:
            self.active_control = True
        if tag in {"input", "iframe", "img", "div"} and re.search(
            r"captcha|turnstile|h-captcha|recaptcha", identity, re.I
        ):
            self.widget = True

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in self.void_tags:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        self.end_budget(tag)
        for index in range(len(self.elements) - 1, -1, -1):
            if self.elements[index][0] == tag:
                del self.elements[index:]
                break

    def handle_data(self, data: str) -> None:
        self.node_budget()
        if not self.elements or not self.elements[-1][1]:
            self.visible.append(data)

    def detected(self, visible_text: str | None = None) -> bool:
        text = " ".join((visible_text if visible_text is not None else " ".join(self.visible)).split())
        prompt = bool(
            re.search(
                r"verify\s+(?:that\s+)?you(?:'re|\s+are)?\s+(?:a\s+)?human|"
                r"confirm\s+you\s+are\s+human|complete\s+(?:the\s+)?(?:captcha|security\s+check)|"
                r"checking\s+(?:your\s+)?browser|验证.{0,12}(?:真人|人类|身份)|人机验证|完成.{0,8}验证码|请输入.{0,4}验证码",
                text,
                re.I,
            )
        )
        if (
            self.cf_structure
            and self.cf_script
            and (prompt or re.search(r"just a moment|请稍候", text, re.I))
        ):
            return True
        # A normal sign-in form with a captcha is not evidence that public downloads are gated.
        return prompt and self.widget and self.active_control and not self.credentials


def _challenge_page(text: str) -> bool:
    parser = _ChallengePage()
    parser.feed(text)
    parser.close()
    return parser.detected()


def rendered_challenge(html: str, visible_text: str) -> bool:
    """Use observed body text with recognized challenge structure, not script strings."""
    parser = _ChallengePage()
    parser.feed(html)
    parser.close()
    return parser.detected(visible_text)


def _device_gate_branch(text: str) -> re.Match[str] | None:
    """Recognize a conjunctive device-score gate, not ordinary UA analytics."""
    if not all(
        marker in text
        for marker in (
            "navigator.webdriver",
            "WEBGL_debug_renderer_info",
            "UNMASKED_RENDERER_WEBGL",
        )
    ):
        return None
    gate = re.search(
        r"function\s+([A-Za-z_$][\w$]*)\s*\(\s*\)\s*\{\s*"
        r"if\s*\(\s*[A-Za-z_$][\w$]*\(\s*\)\s*\)\s*return\s+false\s*;\s*"
        r"return\s+[A-Za-z_$][\w$]*\(\s*\)\s*>=\s*[A-Za-z_$][\w$]*\s*;?\s*\}",
        text,
    )
    if gate is None:
        return None
    branch = re.search(
        r"window\.onload\s*=\s*function\s*\(\s*\)\s*\{\s*"
        r"if\s*\(\s*" + re.escape(gate[1]) + r"\(\s*\)\s*\)\s*\{\s*"
        r"([A-Za-z_$][\w$]*)\(\s*\)\s*;\s*return\s*;",
        text,
    )
    if branch is None:
        return None
    # Conditional content loading is essential: fingerprints alone are analytics.
    loader = re.search(
        r"async\s+function\s+" + re.escape(branch[1]) + r"\s*\(\s*\)\s*\{",
        text,
    )
    return branch if loader is not None and re.search(r"await\s+fetch\s*\(", text[loader.end() :]) else None


def _device_gate(text: str) -> bool:
    return _device_gate_branch(text) is not None


def device_gate_rejected(html: str, visible_text: str) -> bool:
    """Require both the known conditional device gate and its observed rejection text.

    Presence of fingerprint code alone cannot block a browser that passed it.
    This only reads script syntax and rendered text; it never calls page functions
    or retrieves an address mentioned inside the conditional loader.
    """
    class Scripts(BoundedHTMLParser):
        def __init__(self) -> None:
            super().__init__("html_parse_limit")
            self.parts: list[str] = []

        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            self.start_budget(tag, attrs)

        def handle_endtag(self, tag: str) -> None:
            self.end_budget(tag)

        def handle_data(self, data: str) -> None:
            self.node_budget()
            if self.budget_stack and self.budget_stack[-1] == "script":
                self.parts.append(data)

    parser = Scripts()
    parser.feed(html)
    parser.close()
    script = "\n".join(parser.parts)
    branch = _device_gate_branch(script)
    if branch is None:
        return False
    # The recognized onload success arm returns. Only simple text assignments
    # after that arm, before its closing statement, are rejection evidence.
    rejected = script[branch.end():].partition("};")[0]
    visible = " ".join(visible_text.split())
    labels = re.finditer(
        r"\.(textContent|innerText|innerHTML)\s*=\s*(['\"])([^'\"\\\r\n]{1,256})\2", rejected
    )
    for match in labels:
        label = match[3]
        if match[1] == "innerHTML":
            # Parse a bounded literal fragment as data; never evaluate HTML/JS.
            fragment = _ChallengePage()
            fragment.feed(label)
            fragment.close()
            label = " ".join(fragment.visible)
        label = " ".join(label.split())
        if label and label in visible:
            return True
    return False


def discover_html(
    data: bytes, source_url: str, maximum: int = 200, *, content_type: str | None = None
) -> Discovery:
    if len(data) > MAX_HTML_INPUT_BYTES:
        raise FxfetchError("html_parse_limit", "HTML input exceeds parser byte budget")
    from .text_decode import decode_html

    text = decode_html(data, content_type).text
    parser = _Parser(source_url, maximum)
    try:
        parser.feed(text)
        parser.close()
    except (ValueError, AssertionError) as exc:
        raise FxfetchError("html_parse_failed", "Static HTML parse failed") from exc
    if "browser_required" in parser.result.gaps:
        from .json_package import embedded_json_packages
        from .script_package import script_package_candidates

        try:
            for candidate in script_package_candidates(text, source_url, maximum):
                parser.add(candidate.url, action=candidate.action)
        except FxfetchError as error:
            if error.code != "browser_script_limit":
                raise
            # Optional literal discovery cannot turn an unprocessed script
            # into package absence or prevent the existing Chrome handoff.
            parser.result.gaps.append("script_package_incomplete")
        embedded = embedded_json_packages(text, source_url, maximum)
        for candidate in embedded.candidates:
            parser.add(candidate.url, label=candidate.label, action=candidate.action)
        parser.result.gaps.extend(embedded.gaps)
    if any(item.action == "download_attribute" for item in parser.result.candidates):
        parser.result.candidates = [
            item
            for item in parser.result.candidates
            if item.kind != "http" or item.action != "download_control"
        ]
    if _device_gate(text):
        parser.result.gaps.extend(["device_verification_detected", "challenge_detected"])
    if _challenge_page(text):
        parser.result.gaps.append("challenge_detected")
    return parser.result


def _parse_manifest(data: bytes, source_url: str, maximum: int = 200) -> Discovery:
    try:
        if len(data) > 16 * 1024 * 1024 or b"<!ENTITY" in data:
            raise FxfetchError("manifest_limit", "Manifest exceeds safe parser scope")
        root = plistlib.loads(data)
        pending: list[tuple[object, int]] = [(root, 0)]
        while pending:
            value, depth = pending.pop()
            if depth > 64:
                raise FxfetchError("manifest_limit", "Manifest depth exceeds limit")
            if isinstance(value, dict):
                pending.extend((child, depth + 1) for child in value.values())
            elif isinstance(value, list):
                pending.extend((child, depth + 1) for child in value)
        if not isinstance(root, dict) or not isinstance(root.get("items"), list):
            raise ValueError("missing items")
        result = Discovery()
        for item in root["items"]:
            if not isinstance(item, dict) or not isinstance(item.get("assets"), list):
                raise ValueError("missing assets")
            for asset in item["assets"]:
                if isinstance(asset, dict) and asset.get("kind") == "software-package":
                    raw = asset.get("url")
                    if not isinstance(raw, str):
                        raise ValueError("missing package URL")
                    parsed = classify_input(raw)
                    if parsed.request_url is None or parsed.kind in ("store", "unsupported", "itms_manifest"):
                        raise ValueError("unsupported package URL")
                    if len(result.candidates) >= maximum:
                        raise FxfetchError("candidate_limit", "Manifest candidate limit exceeded")
                    result.candidates.append(Candidate(parsed.request_url, "direct_ipa", source_url))
        return result
    except (ValueError, TypeError, RecursionError, plistlib.InvalidFileException) as exc:
        raise FxfetchError("manifest_invalid", "Manifest could not be parsed safely") from exc


def discover_manifest_file(
    path: Path, source_url: str, maximum: int = 200, cancel: Event | None = None, timeout: float = 5.0
) -> Discovery:
    if path.stat().st_size > 16 * 1024 * 1024:
        raise FxfetchError("manifest_limit", "Manifest exceeds byte limit")
    execution = run_limited(
        [sys.executable, "-m", "fxfetch.core.discovery", str(path.resolve()), source_url, str(maximum)],
        timeout=timeout,
        memory_bytes=256 * 1024 * 1024,
        cancel=cancel,
        max_output_bytes=2 * 1024 * 1024,
    )
    if execution.cancelled:
        raise FxfetchError("cancelled", "Manifest parsing cancelled")
    if execution.reason_code or execution.returncode != 0 or not execution.memory_limited:
        raise FxfetchError(
            "manifest_" + (execution.reason_code or "process_failed"),
            "Constrained manifest parser did not complete",
        )
    try:
        payload = json.loads(execution.stdout)
        if "error" in payload:
            raise FxfetchError(payload["error"], "Manifest parser rejected input")
        return Discovery([Candidate(**item) for item in payload["candidates"]], payload["gaps"])
    except (ValueError, KeyError, TypeError) as exc:
        raise FxfetchError("manifest_process_protocol", "Invalid parser output") from exc


def discover_manifest(data: bytes, source_url: str, maximum: int = 200) -> Discovery:
    if len(data) > 16 * 1024 * 1024:
        raise FxfetchError("manifest_limit", "Manifest exceeds byte limit")
    with tempfile.TemporaryDirectory(prefix="fxfetch-manifest-") as scratch:
        path = Path(scratch) / "manifest.bin"
        path.write_bytes(data)
        return discover_manifest_file(path, source_url, maximum)


if __name__ == "__main__":
    from dataclasses import asdict

    try:
        result = _parse_manifest(Path(sys.argv[1]).read_bytes(), sys.argv[2], int(sys.argv[3]))
        print(json.dumps(asdict(result)))
    except (FxfetchError, MemoryError) as error:
        print(
            json.dumps({"error": error.code if isinstance(error, FxfetchError) else "manifest_memory_limit"})
        )
