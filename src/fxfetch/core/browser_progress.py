"""Bounded content progress tracking independent of network heartbeats."""

from __future__ import annotations

import time
from collections.abc import Callable


class BrowserProgress:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self.clock = clock
        self.last = clock()
        self.responses: set[tuple[str, str]] = set()
        self.documents: set[tuple[str, str]] = set()

    def action(self) -> None:
        self.last = self.clock()

    def content(self, url: str, digest: str, *, document: bool = False) -> None:
        seen = self.documents if document else self.responses
        key = (url, digest)
        if key not in seen and len(seen) < 300:
            seen.add(key)
            self.action()

    def stalled(self, now: float, maximum: float) -> bool:
        return now - self.last >= maximum
