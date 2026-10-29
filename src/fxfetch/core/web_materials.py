"""Material metadata for standalone web captures."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .errors import FxfetchError
from .web_evidence_schema import CAPTURE_SCHEMA

if TYPE_CHECKING:
    from .browser_capture import BrowserCaptureResult


@dataclass
class WebCaptureResult:
    capture_id: str
    entry_url: str
    collector: str
    started_at: str
    finished_at: str = ""
    outcome: str = "failed"
    reason_code: str = "not_started"
    coverage: str = "partial"
    gaps: list[str] = field(default_factory=list)
    materials: list[dict[str, Any]] = field(default_factory=list)
    journal_state: str = "healthy"

    def summary(self) -> dict[str, Any]:
        return {
            "schema_version": CAPTURE_SCHEMA,
            "capture_id": self.capture_id,
            "entry_url": self.entry_url,
            "collector": self.collector,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "outcome": self.outcome,
            "reason_code": self.reason_code,
            "coverage": "partial",
            "gaps": list(dict.fromkeys(self.gaps)),
            "journal_state": self.journal_state,
            "materials": self.materials,
        }


def now_utc() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def file_metadata(
    path: Path,
    capture_dir: Path,
    *,
    role: str,
    representation: str,
    complete: bool,
    source_url: str | None,
    request_ref: str | None,
    maximum: int,
) -> dict[str, Any]:
    relative = path.relative_to(capture_dir).as_posix()
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while block := stream.read(64 * 1024):
            size += len(block)
            if size > maximum:
                raise FxfetchError("evidence_budget_exceeded", "Captured material exceeds task budget")
            digest.update(block)
    return {
        "path": relative,
        "size": size,
        "sha256": digest.hexdigest(),
        "role": role,
        "representation": representation,
        "complete": complete,
        "source_url": source_url,
        "request_ref": request_ref,
    }


def save_summary(path: Path, result: WebCaptureResult) -> None:
    data = json.dumps(result.summary(), ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(data)
        stream.write("\n")
        stream.flush()


def collect_browser_materials(
    result: WebCaptureResult,
    capture: BrowserCaptureResult,
    capture_dir: Path,
    maximum: int,
) -> None:
    for body in [*capture.bodies, *capture.partials]:
        raw_path = body.get("path")
        path = Path(raw_path) if isinstance(raw_path, (str, Path)) else None
        if path is None or not path.is_file():
            result.gaps.append("browser_material_missing")
            continue
        try:
            path.relative_to(capture_dir)
        except ValueError:
            result.gaps.append("browser_material_path_invalid")
            continue
        size = body.get("size")
        digest = body.get("sha256")
        if not isinstance(size, int) or isinstance(size, bool) or not isinstance(digest, str):
            result.gaps.append("browser_material_metadata_invalid")
            continue
        try:
            actual_size = path.stat().st_size
        except OSError:
            result.gaps.append("browser_material_missing")
            continue
        if actual_size != size:
            result.gaps.append("browser_material_size_mismatch")
            continue
        raw_source_url = body.get("url")
        raw_request_ref = body.get("request_ref")
        try:
            calculated = file_metadata(
                path,
                capture_dir,
                role="rendered_dom" if body.get("representation") == "browser_rendered_dom" else "response_body",
                representation=str(body.get("representation") or "browser_response_body"),
                complete=body.get("complete") is True,
                source_url=raw_source_url if isinstance(raw_source_url, str) else None,
                request_ref=raw_request_ref if isinstance(raw_request_ref, str) else None,
                maximum=maximum,
            )
        except (FxfetchError, OSError):
            result.gaps.append("browser_material_changed")
            continue
        if calculated["sha256"] == digest:
            result.materials.append(calculated)
        else:
            result.gaps.append("browser_material_hash_mismatch")
