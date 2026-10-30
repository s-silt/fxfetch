"""Conservative discovery of literal package URLs used by inline navigation.

This recognizes declarations and references, not JavaScript execution or proven
reachability. Only a subsequent guarded download can establish package success.
"""

from __future__ import annotations

from .classify import classify_input
from .discovery import Candidate
from .errors import FxfetchError
from .script_content import _LEX, MAX_SCRIPT_BYTES, MAX_TOKENS, _literal, _Scripts


class _PackageScripts(_Scripts):
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        super().handle_starttag(tag, attrs)
        if tag == "script" and any(parent in {"template", "noscript", "svg"} for parent in self.budget_stack):
            self.active = False


def script_package_candidates(html: str, source: str, maximum: int) -> list[Candidate]:
    parser = _PackageScripts()
    parser.feed(html)
    parser.close()
    tokens: list[tuple[str, str]] = []
    for script in parser.parts:
        if len(script.encode("utf-8")) > MAX_SCRIPT_BYTES:
            raise FxfetchError("browser_script_limit", "Inline package script byte budget exceeded")
        for match in _LEX.finditer(script):
            if match.lastgroup == "punct" and (
                match[0] in {"'", '"', "`"}
                or script[match.start():match.start() + 2] == "/*"
            ):
                return []  # Unterminated strings/comments must not expose fake code.
            if match.lastgroup != "skip":
                tokens.append((match.lastgroup or "punct", match[0]))
            if len(tokens) > MAX_TOKENS:
                raise FxfetchError("browser_script_limit", "Inline package script token budget exceeded")
        tokens.append(("punct", ";"))

    # Top-level, single literal declarations only. Any use other than the
    # declaration and a complete location assignment makes that name ambiguous
    # (reassignment, shadowing, property access, concatenation, arguments, etc.).
    declarations: dict[str, tuple[int, str]] = {}
    references: dict[str, set[int]] = {}
    destinations: set[int] = set()
    depth = 0
    values = [token[1] for token in tokens]
    for index, (kind, value) in enumerate(tokens):
        if kind == "word" and value in {"window", "location"} and index and values[index - 1] in {
            "var", "let", "const", "function", "(", ",",
        }:
            return []  # A local binding/parameter may replace the browser navigation object.
        if kind == "word" and value in {"with", "eval", "Function"} and values[index + 1:index + 2] == ["("]:
            return []  # Runtime scope mutation cannot be resolved statically.
    for index, (kind, value) in enumerate(tokens):
        if kind == "word":
            references.setdefault(value, set()).add(index)
        if kind == "punct":
            depth += int(value == "{") - int(value == "}")
        if depth < 0:
            return []
        if (
            value in {"var", "let", "const"} and depth == 0 and index + 4 < len(tokens)
            and (index == 0 or values[index - 1] in {";", "}"})
        ):
            name = tokens[index + 1]
            if name[0] == "word" and values[index + 2] == "=" and values[index + 4] == ";":
                literal = _literal(tokens[index + 3])
                if literal is not None:
                    declarations[name[1]] = (index + 1, literal)
        if kind != "word" or index + 1 >= len(tokens) or values[index + 1] not in {";", "}"}:
            continue
        for prefix in (
            ["window", ".", "location", ".", "href", "="],
            ["location", ".", "href", "="],
            ["window", ".", "location", "="],
            ["location", "="],
        ):
            start = index - len(prefix)
            if start >= 0 and values[start:index] == prefix and (start == 0 or values[start - 1] != "."):
                destinations.add(index)
                break

    found: dict[str, Candidate] = {}
    for name, (declaration, literal) in declarations.items():
        uses = references.get(name, set()) - {declaration}
        if not uses or not uses.issubset(destinations):
            continue
        try:
            parsed = classify_input(literal)
        except FxfetchError:
            continue
        if parsed.kind not in {"direct_apk", "direct_ipa"} or parsed.request_url is None:
            continue
        found.setdefault(parsed.request_url, Candidate(parsed.request_url, parsed.kind, source,
                                                      action="script_package_link"))
        if len(found) > maximum:
            raise FxfetchError("candidate_limit", "Inline package candidate limit exceeded")
    return list(found.values())
