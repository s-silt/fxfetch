"""Bounded append-only provenance for standalone web captures."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_RECORDS = 20_000
MAX_JSONL_BYTES = 8 * 1024 * 1024
MAX_RECORD_BYTES = 64 * 1024
_TRUNCATION_RESERVE = 2048


class EvidenceJournal:
    def __init__(self, path: Path, collector: str, attempt_id: str) -> None:
        self.path = path
        self.collector = collector
        self.attempt_id = attempt_id
        self._stream = path.open("xb")
        self._bytes = 0
        self._records = 0
        self._closed = False
        self.failed = False
        self.saturated = False
        self.gaps: list[str] = []
        self._lock = threading.Lock()

    def append(self, kind: str, fields: dict[str, Any]) -> bool:
        with self._lock:
            if self.failed or self._closed or self.saturated:
                return False
            safe_fields = dict(fields)
            omitted = []
            for key, value in tuple(safe_fields.items()):
                try:
                    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
                except (TypeError, ValueError, RecursionError):
                    safe_fields.pop(key)
                    omitted.append(key)
                    continue
                if isinstance(value, str) and len(encoded) > MAX_RECORD_BYTES // 2:
                    safe_fields.pop(key)
                    omitted.append(key)
                elif len(encoded) > MAX_RECORD_BYTES // 2:
                    safe_fields.pop(key)
                    omitted.append(key)
            if omitted:
                safe_fields["omitted_fields"] = omitted
                safe_fields["gaps"] = ["journal_optional_field_omitted"]
                if "journal_optional_field_omitted" not in self.gaps:
                    self.gaps.append("journal_optional_field_omitted")
            row = self._row(kind, safe_fields, self._records + 1)
            encoded_row = self._encode(row)
            if len(encoded_row) > MAX_RECORD_BYTES:
                for key in sorted(safe_fields, key=lambda item: len(str(safe_fields[item])), reverse=True):
                    if key in {"omitted_fields", "gaps"}:
                        continue
                    safe_fields.pop(key)
                    omitted.append(key)
                    safe_fields["omitted_fields"] = omitted
                    safe_fields["gaps"] = ["journal_optional_field_omitted"]
                    row = self._row(kind, safe_fields, self._records + 1)
                    encoded_row = self._encode(row)
                    if len(encoded_row) <= MAX_RECORD_BYTES:
                        if "journal_optional_field_omitted" not in self.gaps:
                            self.gaps.append("journal_optional_field_omitted")
                        break
            if len(encoded_row) > MAX_RECORD_BYTES:
                safe_fields = {
                    "gaps": ["journal_record_omitted"],
                    "omitted_fields": ["record_fields"],
                }
                row = self._row(kind, safe_fields, self._records + 1)
                encoded_row = self._encode(row)
                if "journal_optional_field_omitted" not in self.gaps:
                    self.gaps.append("journal_optional_field_omitted")
            if (
                self._records >= MAX_RECORDS - 1
                or self._bytes + len(encoded_row) > MAX_JSONL_BYTES - _TRUNCATION_RESERVE
            ):
                self._write_truncation(
                    "record_limit" if self._records >= MAX_RECORDS - 1 else "byte_limit"
                )
                return False
            return self._write(encoded_row)

    def _row(self, kind: str, fields: dict[str, Any], seq: int) -> dict[str, Any]:
        return {
            "seq": seq,
            "observed_at": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "collector": self.collector,
            "attempt_id": self.attempt_id,
            "kind": kind,
            "fields": fields,
        }

    @staticmethod
    def _encode(row: dict[str, Any]) -> bytes:
        return json.dumps(row, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"

    def _write(self, encoded_row: bytes) -> bool:
        try:
            self._stream.write(encoded_row)
            self._stream.flush()
        except OSError:
            self.failed = True
            if "journal_write_failed" not in self.gaps:
                self.gaps.append("journal_write_failed")
            return False
        self._bytes += len(encoded_row)
        self._records += 1
        return True

    def _write_truncation(self, reason: str) -> None:
        marker = self._encode(
            self._row("journal_truncated", {"reason": reason}, self._records + 1)
        )
        self.saturated = True
        if self._records < MAX_RECORDS and self._bytes + len(marker) <= MAX_JSONL_BYTES:
            self._write(marker)
        if "journal_truncated" not in self.gaps:
            self.gaps.append("journal_truncated")

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._stream.flush()
                self._stream.close()
            except OSError:
                self.failed = True
                if "journal_write_failed" not in self.gaps:
                    self.gaps.append("journal_write_failed")
            self._closed = True
