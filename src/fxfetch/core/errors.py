"""Stable errors shared by command line, workers and HTTP endpoints."""

from __future__ import annotations


class FxfetchError(Exception):
    def __init__(self, code: str, message: str, *, outcome: str = "failed") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.outcome = outcome
