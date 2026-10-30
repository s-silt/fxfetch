"""Conservative HAR projection of task observations, not a new capture."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Any
from urllib.parse import urljoin, urlsplit

MAX_HAR_ENTRIES = 1000
MAX_HAR_BYTES = 8 * 1024 * 1024
_KINDS = {"request_attempted", "request_permitted", "response_observed", "redirect_observed"}
_CONTEXT = ("collector_id", "attempt_id", "request_ref", "session_id", "target_id",
            "frame_id", "resource_type", "network_id", "stage", "permitted")


def json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _url(value: object, base: str = "") -> str | None:
    if not isinstance(value, str) or len(value) > 8192 or any(ord(c) < 32 for c in value):
        return None
    try:
        result = urljoin(base, value) if base else value
        parts = urlsplit(result)
        if parts.scheme in {"http", "https"} and parts.hostname and parts.port != 0:
            return result
    except ValueError:
        pass
    return None


def _entry(rows: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, str | None]:
    requests = [row for row in rows if row["kind"] == "request_attempted"]
    responses = [row for row in rows if row["kind"] == "response_observed"]
    if len(requests) != 1 or len(responses) > 1:
        return None, "request_identity_ambiguous_or_missing"
    request = requests[0]
    fields = request["fields"]
    url = _url(fields.get("url"))
    if not url:
        return None, "request_url_unsupported"
    if fields.get("permitted") is False and not responses and not any(
        row["kind"] == "request_permitted" for row in rows
    ):
        return None, "request_not_permitted"
    response = responses[0]["fields"] if responses else {}
    if responses and (
        response.get("url") != fields.get("url")
        or responses[0]["seq"] <= request["seq"]
        or type(response.get("status")) is not int
        or not 100 <= response["status"] <= 599
    ):
        return None, "response_identity_or_status_invalid"
    method = fields.get("method")
    if not isinstance(method, str) or not method.isascii() or not method.isalpha() or len(method) > 32:
        method = "UNKNOWN"
    # No cookies, request headers, payloads, invented bodies or timing measurements.
    entry: dict[str, Any] = {
        "startedDateTime": request["observed_at"],
        "request": {"url": url, "method": method},
        "response": {"status": response.get("status", 0), "content": {}},
    }
    if responses and 300 <= response["status"] < 400:
        targets = {
            target for row in rows
            if row["kind"] == "redirect_observed"
            and row["fields"].get("from_url") == url
            and row["seq"] > responses[0]["seq"]
            if (target := _url(row["fields"].get("resolved_target")))
        }
        if target := _url(response.get("location_raw"), url):
            targets.add(target)
        if len(targets) == 1:
            entry["response"]["redirectURL"] = targets.pop()
        elif len(targets) > 1:
            return entry, "redirect_observations_conflict"
    return entry, None


def project_har(rows: list[dict[str, Any]]) -> tuple[bytes, list[dict[str, Any]], dict[str, int]]:
    """Join only explicit collector/attempt/request identities; retain gaps separately."""
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    omitted: Counter[str] = Counter()
    for row in rows:
        if row["kind"] not in _KINDS:
            omitted[row["kind"]] += 1
            continue
        fields = row["fields"]
        identity = tuple(fields.get(name) for name in ("collector_id", "attempt_id", "request_ref"))
        if not all(isinstance(value, str) and value for value in identity):
            omitted["request_identity_missing"] += 1
            continue
        grouped[identity].append(row)  # type: ignore[index]
    entries: list[dict[str, Any]] = []
    references: list[dict[str, Any]] = []
    size = 256
    for group in grouped.values():
        entry, gap = _entry(group)
        if gap:
            omitted[gap] += 1
        if entry is None:
            continue
        entry_size = len(json_bytes(entry)) + 1
        if len(entries) >= MAX_HAR_ENTRIES or size + entry_size > MAX_HAR_BYTES:
            omitted["har_projection_budget"] += 1
            continue
        request = next(row for row in group if row["kind"] == "request_attempted")
        references.append({
            "analysis_location": f"web/observed.har#/log/entries/{len(entries)}",
            "observation_sequences": [row["seq"] for row in group],
            "context": {key: request["fields"][key] for key in _CONTEXT if key in request["fields"]},
            "representation": "derived_request_attempt_and_optional_response",
        })
        entries.append(entry)
        size += entry_size
    return json_bytes({"log": {"version": "1.2", "creator": {"name": "fxfetch-offline-projection", "version": "1"},
                               "entries": entries}}), references, dict(omitted)
