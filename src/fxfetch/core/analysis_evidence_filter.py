"""Source-bound publication of static secret clues, never cryptographic validation."""

from __future__ import annotations

import copy
import hashlib
import re
from pathlib import Path
from typing import Any

from .analysis_package import MAX_INPUT_BYTES, MAX_INPUT_FILE_BYTES, MAX_INPUT_FILES
from .web_evidence_io import check_ancestors, is_reparse

POLICY = "source_bound_static_secrets_v1"
_TARGET_IDS = {
    "CRYPTO-HARDCODED-KEY",
    "CRYPTO-RECIPE-AES",
    "JS-HARDCODED-SECRET",
    "JS-HARDCODED-AES-KEY",
    "JS-HARDCODED-JWT",
    "JS-HARDCODED-PEM",
}
_MATERIAL = re.compile(r"input/(material-[0-9]{4}\.(?:body|txt|html?|js|json|css|xml))\Z")
_ASSIGNMENT = re.compile(
    r"""(?<![\w$])(?P<name>[A-Za-z_$][\w$]{0,127})["']?\s*[:=]\s*(?P<quote>["'])(?P<value>[^"'\\\r\n]{4,4096})(?P=quote)"""
)
_PAIR = re.compile(r"([A-Za-z_$][\w$]{0,127})=([^\r\n]{4,4096})\Z")
_LIMITED_CLAIM = "仅确认已保存源码中的完整字面值与定位，不确认真实用途、凭据有效性或解密成功。"


def _target(value: dict) -> bool:
    identifier = str(value.get("id", ""))
    if re.search(r"APP[-_]?ID|APP[-_]?KEY", identifier, re.I):
        return False
    title = str(value.get("title", ""))
    return (
        identifier in _TARGET_IDS
        or bool(re.search(r"HARDCODED.*(?:KEY|SECRET|CREDENTIAL|TOKEN|(?:^|-)IV)(?:-|$)", identifier, re.I))
        or bool(
            re.search(
                r"(?:硬编码|hard.?coded).{0,24}(?:密钥|凭证|\bkey\b|\biv\b|secret|credential)", title, re.I
            )
        )
    )


def _secret_name(name: str) -> bool:
    value = re.sub(r"[^a-z0-9]", "", name.lower())
    return value in {"key", "iv", "ivspec", "initializationvector"} or value.endswith(
        (
            "secret",
            "token",
            "password",
            "apikey",
            "accesskey",
            "privatekey",
            "aeskey",
            "deskey",
            "encryptkey",
            "encryptionkey",
            "decryptionkey",
            "signingkey",
            "secretkey",
        )
    )


def _complete(value: str) -> bool:
    return len(value) >= 4 and not any(marker in value for marker in ("…", "...", "<redacted>", "[REDACTED]"))


class _Sources:
    def __init__(self, output: Path, receipt: dict) -> None:
        self.items: dict[str, str] = {}
        self.indices: dict[str, set[tuple[str, str]]] = {}
        self.lines: dict[str, list[str]] = {}
        self.checked_evidences = 0
        self.assignment_count = 0
        self.search_bytes = 0
        self.budget_exhausted = False

        total = 0
        rows = receipt.get("materials", [])
        if not isinstance(rows, list):
            return
        for item in rows[:MAX_INPUT_FILES]:
            if not isinstance(item, dict):
                continue
            relative = item.get("analysis_path")
            match = _MATERIAL.fullmatch(relative) if isinstance(relative, str) else None
            source = item.get("source")
            if not match or not isinstance(relative, str) or not isinstance(source, dict):
                continue
            size, digest = source.get("size"), source.get("sha256")
            if (
                type(size) is not int
                or not 0 < size <= MAX_INPUT_FILE_BYTES
                or total + size > MAX_INPUT_BYTES
            ):
                continue
            path = output / relative
            try:
                check_ancestors(path)
                if not path.is_file() or is_reparse(path) or path.stat().st_size != size:
                    continue
                with path.open("rb") as stream:
                    raw = stream.read(size + 1)
                if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest or raw.startswith(b"PK"):
                    continue
                text = raw.decode("utf-8")
            except (OSError, ValueError, UnicodeError):
                continue
            total += size
            self.items["web/" + match[1]] = text

    def locate(self, location: object) -> tuple[str, str] | None:
        if not isinstance(location, str) or len(location) > 512:
            return None
        match = re.fullmatch(r"(web/material-[0-9]{4}\.[a-z]+)(?::([1-9][0-9]{0,6}))?", location)
        if not match or match[1] not in self.items:
            return None
        text = self.items[match[1]]
        if match[2]:
            if match[1] not in self.lines:
                self.lines[match[1]] = text.split("\n", 100001)[:100000]
            lines = self.lines[match[1]]
            line = int(match[2])
            if line > len(lines):
                return None
            text = lines[line - 1]
        return match[1], text

    def assignments(self, location: str) -> set[tuple[str, str]]:
        if location not in self.indices:
            located = self.locate(location)
            indexed: set[tuple[str, str]] = set()
            if located:
                for match in _ASSIGNMENT.finditer(located[1]):
                    self.assignment_count += 1
                    if self.assignment_count > 50000:
                        self.budget_exhausted = True
                        indexed = set()
                        break
                    indexed.add((match["name"], match["value"]))
            self.indices[location] = indexed
        return self.indices[location]


def _pairs(snippet: str) -> list[tuple[str, str]]:
    pairs = [(match["name"], match["value"]) for match in _ASSIGNMENT.finditer(snippet)]
    match = _PAIR.fullmatch(snippet.strip())
    if match:
        pairs.append((match[1], match[2]))
    return [(name, value) for name, value in pairs if _secret_name(name) and _complete(value)]


def _supported_evidence(evidence: object, sources: _Sources, identifier: str) -> bool:
    if not isinstance(evidence, dict) or evidence.get("source") not in {
        "js",
        "resource",
        "web",
        "html",
        "text",
    }:
        return False
    sources.checked_evidences += 1
    if sources.checked_evidences > 8192:
        sources.budget_exhausted = True
        return False
    located = sources.locate(evidence.get("location"))
    snippet = evidence.get("snippet")
    if not located or not isinstance(snippet, str) or not 0 < len(snippet) <= 8192:
        return False
    text = located[1]
    if identifier in {"JS-HARDCODED-JWT", "JS-HARDCODED-PEM"}:
        sources.search_bytes += len(text)
        if sources.search_bytes > 320 * 1024 * 1024:
            sources.budget_exhausted = True
            return False
    if identifier == "JS-HARDCODED-JWT":
        return bool(
            re.fullmatch(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", snippet)
            and re.search(r"(?<![A-Za-z0-9_.-])" + re.escape(snippet) + r"(?![A-Za-z0-9_.-])", text)
        )
    if identifier == "JS-HARDCODED-PEM":
        return bool(
            re.fullmatch(
                r"-----BEGIN (RSA PRIVATE KEY|EC PRIVATE KEY|PRIVATE KEY|PUBLIC KEY|CERTIFICATE)-----[\s\S]{32,4096}-----END \1-----",
                snippet,
            )
            and snippet in text
        )
    return any(
        (name, value) in sources.assignments(str(evidence["location"])) for name, value in _pairs(snippet)
    )


def _recipe_supported(recipe: dict, sources: _Sources) -> bool:
    key = recipe.get("key")
    located = sources.locate(recipe.get("source"))
    if not isinstance(key, str) or not _complete(key) or not located:
        return False
    text = located[1]
    sources.search_bytes += len(text)
    if sources.search_bytes > 320 * 1024 * 1024:
        sources.budget_exhausted = True
        return False
    if not re.search(r"\b(?:AES|DES|TripleDES)\s*\.\s*(?:encrypt|decrypt)\s*\(", text):
        return False
    names = [name for name, value in sources.assignments(str(recipe["source"])) if value == key]
    if len(names) > 8:
        sources.budget_exhausted = True
        return False
    for original_name in names:
        name = re.escape(original_name)
        if re.search(
            r"\benc\s*\.\s*(?:Utf8|Hex|Base64)\s*\.\s*parse\s*\(\s*" + name + r"\s*\)", text
        ) or re.search(
            r"\b(?:AES|DES|TripleDES)\s*\.\s*(?:encrypt|decrypt)\s*\([^,\r\n]{1,512},\s*" + name + r"\b", text
        ):
            return True
    return False


def filter_report(
    report: dict[str, Any], output: Path, receipt: dict
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return a detached publication copy; the supplied native report stays untouched."""
    result = copy.deepcopy(report)
    sources = _Sources(output, receipt)
    recipes: dict[str, dict] = {}

    def clean_recipes(node: object) -> None:
        if isinstance(node, dict):
            recipe = node.get("crypto_recipe")
            if isinstance(recipe, dict) and "key" in recipe:
                if _recipe_supported(recipe, sources):
                    iv = recipe.get("iv_value")
                    located = sources.locate(recipe.get("source"))
                    if iv is not None and (
                        not isinstance(iv, str)
                        or not _complete(iv)
                        or not located
                        or not (
                            any(
                                re.sub(r"[^a-z0-9]", "", name.lower())
                                in {"iv", "ivspec", "initializationvector"}
                                and value == iv
                                for name, value in sources.assignments(str(recipe["source"]))
                            )
                            or re.search(
                                r"\biv\s*:\s*[A-Za-z_$][\w$]*\.enc\.(?:Utf8|Hex|Base64)\.parse\(\s*([\"'])"
                                + re.escape(iv)
                                + r"\1\s*\)",
                                located[1],
                            )
                        )
                    ):
                        recipe["iv_value"] = None
                        recipe["iv_derive"] = "unknown"
                    recipe.update(evidence_status="source_literal_only", decryption_verified=False)
                    recipes[recipe["source"]] = recipe
                else:
                    node.pop("crypto_recipe")
                    if "crypto_recipe_count" in node:
                        node["crypto_recipe_count"] = 0
            for value in list(node.values()):
                clean_recipes(value)
        elif isinstance(node, list):
            for value in node:
                clean_recipes(value)

    clean_recipes(result.get("meta"))
    findings = result.get("findings")
    original = findings if isinstance(findings, list) else []
    kept, removed = [], []
    supported_by_id: dict[str, dict] = {}
    for finding in original:
        if not isinstance(finding, dict) or not _target(finding):
            kept.append(finding)
            continue
        identifier = str(finding.get("id", ""))
        evidences = finding.get("evidences", [])
        valid = (
            [e for e in evidences if _supported_evidence(e, sources, identifier)]
            if isinstance(evidences, list)
            else []
        )
        if identifier == "CRYPTO-RECIPE-AES":
            valid = [
                e
                for e in evidences
                if isinstance(e, dict)
                and e.get("source") in {"js", "resource"}
                and e.get("location") in recipes
                and isinstance(e.get("snippet"), str)
                and _complete(e["snippet"])
                and e["snippet"] in sources.items.get(e["location"], "")
            ]
        if not valid:
            removed.append(finding)
            continue
        for evidence in valid:
            for claim in ("verified", "decryption_verified", "key_verified"):
                evidence.pop(claim, None)
        finding.update(
            title="静态硬编码凭据 / 密钥线索",
            description=_LIMITED_CLAIM,
            recommendation="结合具体源码定位复核其用途；本报告未执行凭据有效性或解密验证。",
            evidences=valid,
            evidence_status="source_literal_only",
            decryption_verified=False,
        )
        kept.append(finding)
        supported_by_id[identifier] = finding
    if isinstance(findings, list):
        result["findings"] = kept
    removed_ids = ({str(f["id"]) for f in removed if "id" in f} | _TARGET_IDS) - set(supported_by_id)
    removed_titles = {str(f.get("title", "")) for f in removed}

    def summaries(node: object) -> None:
        if isinstance(node, dict):
            ids = node.get("finding_ids")
            if isinstance(ids, list):
                removed_ids.update(
                    str(value)
                    for value in ids
                    if _target({"id": value}) and str(value) not in supported_by_id
                )
                removed_count = len({str(value) for value in ids if str(value) in removed_ids})
                node["finding_ids"] = [value for value in ids if str(value) not in removed_ids]
                if type(node.get("findings")) is int:
                    node["findings"] = max(0, node["findings"] - removed_count)
            summaries_list = node.get("findings")
            if isinstance(summaries_list, list):
                filtered = []
                for value in summaries_list:
                    if isinstance(value, dict) and _target(value):
                        if str(value.get("id", "")) in supported_by_id:
                            filtered.append(copy.deepcopy(supported_by_id[str(value["id"])]))
                    elif isinstance(value, str) and (value in removed_ids or value in removed_titles):
                        continue
                    else:
                        filtered.append(value)
                node["findings"] = filtered
            for value in node.values():
                summaries(value)
        elif isinstance(node, list):
            for value in node:
                summaries(value)

    summaries(result.get("meta"))
    leads = result.get("leads")
    if isinstance(leads, list):
        filtered_leads = []
        for lead in leads:
            if not isinstance(lead, dict) or lead.get("category") != "crypto_recipe":
                filtered_leads.append(lead)
                continue
            refs = lead.get("source_refs", [])
            if not isinstance(refs, list) or not any(
                isinstance(ref, dict) and ref.get("location") in recipes for ref in refs
            ):
                continue
            lead.update(
                notes=_LIMITED_CLAIM,
                where_to_request="静态源码线索；未验证解密结果。",
                evidence_to_obtain=["定位已保存源码，核验字面值的实际用途与调用关系。"],
                decryption_verified=False,
            )
            filtered_leads.append(lead)
        result["leads"] = filtered_leads
    stats = {
        "policy": POLICY,
        "input_source_files": len(sources.items),
        "suppressed_findings": len(removed),
        "retained_static_secret_findings": sum(
            1 for value in kept if isinstance(value, dict) and _target(value)
        ),
        "decryption_verified": False,
        "checked_evidences": min(sources.checked_evidences, 8192),
        "budget_exhausted": sources.budget_exhausted,
    }
    return result, stats
