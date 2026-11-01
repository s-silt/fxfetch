"""Public fxapk CLI sidecar; metadata stays outside the text evidence directory."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .analysis_har import json_bytes
from .web_evidence_schema import EvidenceError

SCHEMA = "fxapk.web-evidence-handoff.v1"
MAX_HANDOFF_BYTES = 8 * 1024 * 1024


def _tls(rows: list[dict]) -> str:
    values = {row["fields"]["tls_verification"] for row in rows if "tls_verification" in row["fields"]}
    if "ignored" in values:
        return "ignored"
    if len(values) > 1:
        values.discard("required")
    if len(values) == 1 and next(iter(values)) in {"verified", "required", "not_applicable"}:
        return next(iter(values))
    return "unknown"


def write_handoff(output: Path, receipt: dict, observations: list[dict]) -> dict[str, Any]:
    by_sequence = {row["seq"]: row for row in observations}
    archive_hash = receipt["source_archive"]["sha256"]
    files: list[dict] = []
    for material in receipt["materials"]:
        if material["analysis_path"] is None:
            continue
        source, provenance = material["source"], material["provenance"]
        sequences = [item["seq"] for item in provenance["observations"]]
        if provenance["response_observation_sequence"] is not None:
            sequences.append(provenance["response_observation_sequence"])
        rows = [by_sequence[seq] for seq in sequences]
        files.append({
            "path": Path(material["analysis_path"]).name,
            "sha256": source["sha256"], "size": source["size"],
            "source": {"archive_sha256": archive_hash, "material": source,
                       "analysis_path": material["analysis_path"],
                       "analysis_location_prefix": material["analysis_location_prefix"],
                       "observations": provenance},
            "capture": {"complete": source["complete"], "representation": source["representation"],
                        "request_association": source["request_association"], "tls_verification": _tls(rows)},
        })
    har = receipt["har"]
    if har["path"] is not None:
        entries = []
        for entry in har["entries"]:
            rows = [by_sequence[seq] for seq in entry["observation_sequences"]]
            entries.append({
                "pointer": entry["analysis_location"].split("#", 1)[1],
                "source": entry,
                "capture": {"complete": None, "representation": entry["representation"],
                            "request_association": "known", "tls_verification": _tls(rows)},
            })
        files.append({
            "path": "observed.har", "sha256": har["sha256"],
            "size": (output / har["path"]).stat().st_size,
            "source": {"archive_sha256": archive_hash, "representation": "derived_har"},
            "capture": {"complete": None, "request_association": "unknown", "tls_verification": "unknown"},
            "entries": entries,
        })
    payload = json_bytes({
        "schema_version": SCHEMA, "files": files,
        "coverage": {
            "source_manifest": receipt["source_manifest"],
            "status": receipt["coverage"],
            "unprojected_observations": har["unprojected_observations"],
            "omitted_materials": [item for item in receipt["materials"] if item["analysis_path"] is None],
            "attachments": receipt["attachments"],
            "source_gaps": receipt["source_manifest"].get("gaps", []),
            "authenticity_claimed": False, "target_app_attribution_verified": False,
        },
    })
    if len(payload) > MAX_HANDOFF_BYTES:
        raise EvidenceError("analysis_handoff_budget")
    (output / "evidence-handoff.json").write_bytes(payload)
    return {"path": "evidence-handoff.json", "schema_version": SCHEMA,
            "sha256": hashlib.sha256(payload).hexdigest()}
