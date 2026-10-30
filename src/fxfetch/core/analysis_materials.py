"""Parser selection and provenance for verified material bytes; no content rewriting."""

from __future__ import annotations

from collections import defaultdict
from pathlib import PurePosixPath
from typing import Any

_SAVED = {"response_body_saved", "response_prefix_saved", "terminal_snapshot"}
_CONTEXT = ("collector_id", "attempt_id", "request_ref", "session_id", "target_id",
            "frame_id", "resource_type")
_SUFFIXES = {".html", ".htm", ".js", ".mjs", ".cjs", ".json", ".css", ".xml"}
_MIME_SUFFIXES = {
    "text/html": ".html", "application/xhtml+xml": ".html",
    "text/javascript": ".js", "application/javascript": ".js",
    "text/ecmascript": ".js", "application/ecmascript": ".js",
    "application/json": ".json", "text/json": ".json", "text/css": ".css",
    "text/xml": ".xml", "application/xml": ".xml",
}


def _identity(fields: dict[str, Any]) -> tuple[str, str, str] | None:
    collector_id = fields.get("collector_id")
    attempt_id = fields.get("attempt_id")
    request_ref = fields.get("request_ref")
    if (
        isinstance(collector_id, str) and collector_id
        and isinstance(attempt_id, str) and attempt_id
        and isinstance(request_ref, str) and request_ref
    ):
        return collector_id, attempt_id, request_ref
    return None


def _saved_key(fields: dict[str, Any]) -> tuple[str, int, str] | None:
    path, size, digest = fields.get("path"), fields.get("size"), fields.get("sha256")
    if isinstance(path, str) and type(size) is int and isinstance(digest, str):
        return path, size, digest
    return None


def _matches(row: dict[str, Any], record: dict[str, Any]) -> bool:
    fields = row["fields"]
    return (
        (fields.get("representation") or "http_response_body") == record["representation"]
        and fields.get("complete") is record["complete"]
        and (fields.get("source_url", fields.get("url")) or None) == record["source_url"]
        and (record["request_association"] == "unknown" or fields.get("request_ref") == record.get("request_ref"))
    )


def _media_type(fields: dict[str, Any]) -> tuple[str | None, bool]:
    values = [fields.get("content_type")]
    headers = fields.get("headers")
    if isinstance(headers, dict):
        values.extend(value for key, value in headers.items() if key.lower() == "content-type")
    types = {value.partition(";")[0].strip().lower() for value in values if isinstance(value, str) and value.strip()}
    return (next(iter(types)), False) if len(types) == 1 else (None, len(types) > 1)


class MaterialSources:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.saved: dict[tuple[str, int, str], list[dict[str, Any]]] = defaultdict(list)
        self.requests: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
        self.responses: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            fields = row["fields"]
            if row["kind"] in _SAVED and fields.get("package_stream") is not True:
                key = _saved_key(fields)
                if key is not None:
                    self.saved[key].append(row)
            identity = _identity(fields)
            if identity is not None:
                if row["kind"] == "request_attempted":
                    self.requests[identity].append(row)
                elif row["kind"] == "response_observed":
                    self.responses[identity].append(row)

    def describe(self, record: dict[str, Any]) -> dict[str, Any]:
        key = _saved_key(record)
        saved = [row for row in self.saved.get(key, []) if _matches(row, record)] if key is not None else []
        result: dict[str, Any] = {
            "observations": [{"seq": row["seq"], "kind": row["kind"], **{
                key: row["fields"][key] for key in _CONTEXT if key in row["fields"]
            }} for row in saved],
            "response_observation_sequence": None, "media_type": None, "gaps": [],
        }
        identities = {_identity(row["fields"]) for row in saved}
        identity = next(iter(identities)) if len(identities) == 1 else None
        if identity is not None:
            requests = self.requests.get(identity, [])
            responses = self.responses.get(identity, [])
            if len(requests) == len(responses) == 1 and (
                requests[0]["fields"].get("url") == record["source_url"]
                and responses[0]["fields"].get("url") == record["source_url"]
                and requests[0]["seq"] < responses[0]["seq"] < min(row["seq"] for row in saved)
            ):
                media_type, conflict = _media_type(responses[0]["fields"])
                result.update(media_type=media_type, response_observation_sequence=responses[0]["seq"])
                if conflict:
                    result["gaps"].append("response_media_type_conflict")
            elif responses:
                result["gaps"].append("response_association_ambiguous")
        elif saved:
            result["gaps"].append("response_association_unknown")
        return result


def analysis_suffix(record: dict[str, Any], source: dict[str, Any]) -> tuple[str, str]:
    if record["representation"] == "browser_rendered_dom":
        return ".html", "rendered_dom"
    media_type = source["media_type"]
    if media_type:
        suffix = _MIME_SUFFIXES.get(media_type)
        if not suffix and media_type.startswith("application/"):
            suffix = ".json" if media_type.endswith("+json") else ".xml" if media_type.endswith("+xml") else None
        return (suffix, "response_media_type") if suffix else (".body", "content_sniff")
    if source["gaps"]:
        return ".body", "content_sniff"
    suffix = PurePosixPath(record["path"]).suffix.lower()
    return (suffix, "filename") if suffix in _SUFFIXES else (".body", "content_sniff")
