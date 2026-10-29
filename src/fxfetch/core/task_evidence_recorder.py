"""Durable, bounded observations for a unified acquisition task."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .web_journal import EvidenceJournal


class TaskEvidenceRecorder:
    def __init__(self, root: Path, path: Path | None = None) -> None:
        self.root = root.absolute()
        self.path = path or self.root / "task-observations.jsonl"
        self.journal: EvidenceJournal | None = None
        self._failed = False
        self._lock = threading.Lock()
        self._context = ("task", "unknown")
        self.started_at = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.journal = EvidenceJournal(self.path, "task", self.root.name[:128] or "task")
            self.append("task_observation_started", {"started_at": self.started_at})
        except OSError:
            self._failed = True

    def set_context(self, collector_id: str, attempt_id: str) -> tuple[str, str]:
        previous = self._context
        self._context = (collector_id[:64], attempt_id[:128])
        return previous

    def restore_context(self, previous: tuple[str, str]) -> None:
        self._context = previous

    @property
    def context(self) -> tuple[str, str]:
        return self._context

    def observe_transport(self, event: dict[str, Any]) -> None:
        value = dict(event)
        kind = value.pop("event", value.pop("kind", "transport_observed"))
        value["collector_id"], value["attempt_id"] = self._context
        path = value.get("path")
        if isinstance(path, Path):
            value["path"] = str(path)
        if isinstance(value.get("path"), str):
            candidate = Path(value["path"])
            if candidate.is_absolute():
                try:
                    value["path"] = candidate.resolve(strict=False).relative_to(
                        self.root.resolve()
                    ).as_posix()
                except (OSError, ValueError):
                    value.pop("path", None)
                    self.mark_failed("material_path_unavailable")
                    return
        self.append(str(kind), value)

    def observe_progress(self, event: dict[str, Any]) -> None:
        self.append("acquisition_event", dict(event))

    def append(self, kind: str, fields: dict[str, Any]) -> None:
        journal = self.journal
        if journal is None:
            self._failed = True
            return
        try:
            if not journal.append(kind, fields):
                if journal.failed:
                    self._failed = True
        except Exception:
            self.mark_failed("observation_callback_failed")

    def mark_failed(self, reason: str) -> None:
        with self._lock:
            self._failed = True
            if self.journal is not None and reason not in self.journal.gaps:
                self.journal.gaps.append(reason)

    def close(self) -> None:
        if self.journal is not None:
            state, gaps, records = self.status()
            self.append(
                "task_observation_finished",
                {"state": state, "gaps": gaps[:256], "records_before_close": records},
            )
            self.journal.close()
            if self.journal.failed:
                self._failed = True
            state, gaps, records = self.status()
            try:
                lines = self.path.read_bytes().splitlines()
                first_row = json.loads(lines[0])
                last_row = json.loads(lines[-1])
                started_at = first_row.get("observed_at")
                finished_at = (
                    last_row.get("observed_at")
                    if last_row.get("kind") == "task_observation_finished"
                    else None
                )
            except (OSError, IndexError, ValueError, TypeError):
                started_at = finished_at = None
            receipt = {
                "state": state,
                "gaps": gaps[:256],
                "records": records,
                "started_at": started_at,
                "finished_at": finished_at,
            }
            try:
                target = self.path.with_suffix(self.path.suffix + ".status.json")
                pending = target.with_suffix(target.suffix + ".pending")
                pending.write_text(
                    json.dumps(receipt, ensure_ascii=True, separators=(",", ":")),
                    encoding="utf-8",
                )
                pending.replace(target)
            except OSError:
                self._failed = True

    def status(self) -> tuple[str, list[str], int]:
        if self.journal is None:
            return "failed", ["observation_journal_unavailable"], 0
        state = "failed" if self._failed or self.journal.failed else (
            "truncated" if self.journal.saturated else "healthy"
        )
        try:
            with self.path.open("rb") as stream:
                records = sum(1 for _ in stream)
        except OSError:
            state = "failed"
            records = 0
        return state, list(dict.fromkeys(self.journal.gaps))[:256], records

    def __call__(self, event: dict[str, Any]) -> None:
        self.observe_transport(event)
