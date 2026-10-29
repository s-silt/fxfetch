"""Bounded, private observations of page runtime failures, never stop policy."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_RUNTIME_DIAGNOSTICS = 16


def runtime_exception_category(details: dict[str, Any]) -> str:
    """Read only a bounded prefix and return a fixed vocabulary, not page text."""
    exception = details.get("exception")
    exception = exception if isinstance(exception, dict) else {}
    values = [details.get("text"), exception.get("description"), exception.get("value")]
    text = " ".join(value[:2048] for value in values if isinstance(value, str)).lower()
    if "webgl" in text or "opengl" in text:
        return "webgl_unavailable"
    if ("wasm" in text or "webassembly" in text) and any(
        marker in text for marker in ("compile", "instantiate", "linkerror", "validation")
    ):
        return "wasm_compile_error"
    return "script_exception"


class RuntimeDiagnostics:
    """The first 16 exceptions only; no raw text, URL, frame or object values."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.entries: list[dict[str, str | int]] = []

    def observe_exception(self, event: dict[str, Any]) -> None:
        if len(self.entries) >= MAX_RUNTIME_DIAGNOSTICS:
            return
        details = event.get("exceptionDetails")
        if not isinstance(details, dict):
            return
        entry: dict[str, str | int] = {"category": runtime_exception_category(details)}
        for source, dest in (("lineNumber", "line"), ("columnNumber", "column")):
            value = details.get(source)
            if type(value) is int and 0 <= value <= 10_000_000:
                entry[dest] = value
        self.entries.append(entry)
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            path = self.directory / "runtime-diagnostic.json"
            path.write_text(json.dumps({"exceptions": self.entries}, separators=(",", ":")), encoding="utf-8")
        except OSError:
            return  # Observation storage cannot change acquisition outcomes.
