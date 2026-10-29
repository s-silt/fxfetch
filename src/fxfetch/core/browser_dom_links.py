"""Classify explicit package anchors from a bounded rendered-DOM observation."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from .discovery import Candidate, device_gate_rejected, rendered_challenge
from .errors import FxfetchError
from .guard import validate_url

OBSERVE_PACKAGE_LINKS = """limits => {
    const anchors=document.querySelectorAll('a[href]');
    if(anchors.length>limits.links)return {tooMany:true};
    const html=document.documentElement?.outerHTML||'';
    if(new TextEncoder().encode(html).length>limits.bytes)return {tooLarge:true};
    return {html,base:document.baseURI,visible:(document.body?.innerText||'').slice(0,limits.bytes),ready:document.readyState,
        links:[...anchors].map(a=>typeof a.href==='string'?a.href:'')};
}"""


def observed_package_candidates(
    observed: dict[str, Any], source: str, chain: str
) -> tuple[list[Candidate], str | None]:
    if observed.get("tooMany"):
        raise FxfetchError("candidate_limit", "Rendered anchor budget exhausted")
    if observed.get("tooLarge"):
        raise FxfetchError("browser_dom_limit", "Rendered document exceeds observation budget")
    challenge_reason = None
    if device_gate_rejected(observed["html"], observed["visible"]):
        challenge_reason = "device_verification_required"
    elif rendered_challenge(observed["html"], observed["visible"]):
        challenge_reason = "challenge_detected"
    if observed.get("ready") != "complete":
        return [], challenge_reason  # Let normal loading and onload checks finish first.
    extension = ".apk" if chain == "android" else ".ipa"
    found: dict[str, Candidate] = {}
    for href in observed["links"]:
        try:
            if not urlsplit(href).path.lower().endswith(extension):
                continue
            approved = validate_url(href)
        except (ValueError, FxfetchError):
            continue
        found.setdefault(approved, Candidate(
            approved, "direct_apk" if chain == "android" else "direct_ipa",
            source, action="rendered_package_link",
        ))
    return list(found.values()), challenge_reason
