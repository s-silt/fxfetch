"""Serial service-owned lifecycle for offline fxapk analysis jobs."""

from __future__ import annotations

import json
import logging
import re
import shutil
import sys
import threading
import time
from pathlib import Path
from typing import Any

from .analysis_report import MAX_ANALYSIS_REPORT_ZIP_BYTES, bounded_hash
from .analysis_store import AnalysisStore
from .analysis_worker import (
    MAX_WORKER_MESSAGE_BYTES,
    WORKER_REPORT_NAME,
    WORKER_REQUEST_NAME,
    WORKER_RESULT_NAME,
)
from .core.errors import FxfetchError
from .core.process_limits import run_limited
from .core.web_evidence_io import check_ancestors, is_reparse, read_json_object
from .core.web_evidence_schema import EvidenceError
from .security import contained_path

log = logging.getLogger(__name__)
_HASH = re.compile(r"^[0-9a-f]{64}$")


class AnalysisService:
    def __init__(self, jobs: Any):
        self.jobs = jobs
        self.store = AnalysisStore(jobs.store)
        self._wake = threading.Event()
        self._cancels: dict[str, threading.Event] = {}

    def _resolved_executable(self) -> str | None:
        configured = self.jobs.settings.fxapk_executable
        if configured is None:
            return None
        resolved = shutil.which(configured)
        return str(Path(resolved).resolve()) if resolved else None

    def capability(self) -> dict:
        enabled = self._resolved_executable() is not None
        limits = self.jobs.settings.limits
        return {
            "enabled": enabled,
            "reason_code": None if enabled else "analysis_unavailable",
            "online": False,
            "timeout_seconds": limits.analysis_timeout,
            "queue_timeout_seconds": limits.analysis_queue_timeout,
        }

    def start(self) -> None:
        worker = threading.Thread(target=self._loop, daemon=True, name="fxfetch-analysis")
        self.jobs._threads.append(worker)
        worker.start()

    def stop(self) -> None:
        with self.jobs._mutex:
            self.stop_locked()

    def stop_locked(self) -> None:
        self._wake.set()
        for event in self._cancels.values():
            event.set()

    def create(self, owner: str, job_id: str, idem: str) -> dict:
        with self.jobs._mutex:
            replay = self.store.replay(owner, job_id, idem)
            if replay is not None:
                return replay
            self.jobs.store.get_job(owner, job_id)
            executable = self._resolved_executable()
            if executable is None:
                raise FxfetchError("analysis_unavailable", "Offline analysis is unavailable")
            try:
                source = self.jobs.analysis_source_descriptor(owner, job_id)
            except FxfetchError as error:
                if error.code == "not_found":
                    raise FxfetchError(
                        "analysis_source_unavailable", "Data package is not ready"
                    ) from error
                raise
            limits = self.jobs.settings.limits
            value, created = self.store.create(
                owner,
                job_id,
                idem,
                executable=executable,
                source=source,
                max_queue=limits.max_queued_analyses,
                max_per_job=limits.max_analyses_per_job,
                queue_timeout=limits.analysis_queue_timeout,
            )
            if created:
                self._wake.set()
            return value

    def list(self, owner: str, job_id: str) -> list[dict]:
        return self.store.list(owner, job_id)

    def get(self, owner: str, job_id: str, identifier: str) -> dict:
        return self.store.get(owner, job_id, identifier)

    def cancel(self, owner: str, job_id: str, identifier: str) -> dict:
        with self.jobs._mutex:
            value, running = self.store.cancel(owner, job_id, identifier)
            if running:
                event = self._cancels.get(identifier)
                if event is not None:
                    event.set()
            self._wake.set()
            return value

    def cancel_owner(self, owner: str) -> None:
        for identifier in self.store.cancel_owner(owner):
            event = self._cancels.get(identifier)
            if event is not None:
                event.set()
        self._wake.set()

    def expire_queued(self) -> None:
        if self.store.expire_queued():
            self._wake.set()

    def report_file(self, owner: str, job_id: str, identifier: str) -> tuple[Path, str]:
        value = self.store.get_private(owner, job_id, identifier)
        if value["state"] != "completed" or not value["report_path"]:
            raise FxfetchError("not_found", "Analysis report is unavailable")
        try:
            path = contained_path(self.jobs.store.root, value["report_path"])
            size, digest = bounded_hash(path, MAX_ANALYSIS_REPORT_ZIP_BYTES)
            valid = (
                path.is_file()
                and not is_reparse(path)
                and size == value["report_size"]
                and digest == value["report_sha256"]
            )
        except (OSError, FxfetchError, EvidenceError):
            valid = False
        if not valid:
            raise FxfetchError("not_found", "Analysis report is unavailable")
        return path, f"analysis-{identifier}.zip"

    def _loop(self) -> None:
        while True:
            with self.jobs._mutex:
                if self.jobs._stop.is_set():
                    return
                item = self.store.claim(self.jobs.settings.limits.analysis_timeout)
                if item is not None:
                    cancel = threading.Event()
                    self._cancels[item["id"]] = cancel
                    execution_deadline = (
                        time.monotonic() + self.jobs.settings.limits.analysis_timeout
                    )
            if item is None:
                self._wake.wait(1)
                self._wake.clear()
                continue
            try:
                self._run(item, cancel, execution_deadline)
            except Exception as error:
                log.error(
                    "analysis_worker_error id=%s exception_type=%s",
                    item["id"],
                    type(error).__name__,
                )
                self._finish_guarded(
                    item["id"],
                    cancel,
                    execution_deadline,
                    "failed",
                    "analysis_internal_error",
                )
            finally:
                with self.jobs._mutex:
                    self._cancels.pop(item["id"], None)

    def _override(
        self, cancel: threading.Event, execution_deadline: float
    ) -> tuple[str, str] | None:
        if self.jobs._stop.is_set():
            return "interrupted", "service_stopped"
        if cancel.is_set():
            return "cancelled", "cancelled"
        if time.monotonic() >= execution_deadline:
            return "failed", "analysis_timeout"
        return None

    def _finish_guarded(
        self,
        identifier: str,
        cancel: threading.Event,
        execution_deadline: float,
        state: str,
        reason_code: str | None,
    ) -> bool:
        with self.jobs._mutex:
            override = self._override(cancel, execution_deadline)
            if override is not None:
                state, reason_code = override
            return self.store.finish(identifier, state, reason_code)

    def _run(
        self, item: dict, cancel: threading.Event, execution_deadline: float
    ) -> None:
        with self.jobs._mutex:
            override = self._override(cancel, execution_deadline)
            if override is not None:
                self.store.finish(item["id"], *override)
                return
        folder = contained_path(
            self.jobs.store.root, item["output_path"], must_exist=False
        )
        folder.mkdir(mode=0o700, parents=True, exist_ok=False)
        request_path = folder / WORKER_REQUEST_NAME
        self._write_request(request_path, item)
        remaining = execution_deadline - time.monotonic()
        if remaining <= 0:
            self._finish_guarded(
                item["id"], cancel, execution_deadline, "failed", "analysis_timeout"
            )
            return
        result = run_limited(
            [
                sys.executable,
                "-m",
                "fxfetch.analysis_worker",
                str(request_path.resolve()),
            ],
            timeout=remaining,
            memory_bytes=2 * 1024 * 1024 * 1024,
            cwd=self.jobs.store.root,
            cancel=cancel,
            max_output_bytes=1024 * 1024,
        )
        if result.timed_out:
            self._finish_guarded(
                item["id"], cancel, execution_deadline, "failed", "analysis_timeout"
            )
            return
        if result.cancelled:
            self._finish_guarded(
                item["id"], cancel, execution_deadline, "cancelled", "cancelled"
            )
            return
        if result.reason_code or result.returncode != 0:
            self._finish_guarded(
                item["id"],
                cancel,
                execution_deadline,
                "failed",
                result.reason_code or "analysis_worker_failed",
            )
            return
        try:
            status = self._worker_result(folder)
        except (OSError, ValueError, EvidenceError):
            self._finish_guarded(
                item["id"],
                cancel,
                execution_deadline,
                "failed",
                "analysis_result_invalid",
            )
            return
        if status["state"] != "completed":
            self._finish_guarded(
                item["id"],
                cancel,
                execution_deadline,
                status["state"],
                status["reason_code"],
            )
            return
        self._publish_completed(item, folder, status, cancel, execution_deadline)

    def _write_request(self, path: Path, item: dict) -> None:
        value = {
            "schema_version": "fxfetch.analysis-worker.v1",
            "source_path": item["source_path"],
            "source_size": item["source_size"],
            "source_sha256": item["source_sha256"],
            "fxapk_executable": item["executable_path"],
            "analysis_timeout": self.jobs.settings.limits.analysis_timeout,
            "max_task_bytes": self.jobs.settings.limits.max_task_bytes,
        }
        raw = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode(
            "utf-8"
        )
        if len(raw) > MAX_WORKER_MESSAGE_BYTES:
            raise ValueError("analysis worker request too large")
        with path.open("xb") as stream:
            stream.write(raw)

    def _worker_result(self, folder: Path) -> dict:
        path = folder / WORKER_RESULT_NAME
        check_ancestors(path)
        if not path.is_file() or is_reparse(path):
            raise EvidenceError("analysis_worker_result_invalid")
        value = read_json_object(path, MAX_WORKER_MESSAGE_BYTES)
        state = value.get("state")
        if state not in {"completed", "failed", "not_analyzed"}:
            raise EvidenceError("analysis_worker_result_invalid")
        if state != "completed":
            reason = value.get("reason_code")
            if (
                set(value) != {"state", "reason_code"}
                or not isinstance(reason, str)
                or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", reason)
            ):
                raise EvidenceError("analysis_worker_result_invalid")
            return value
        size = value.get("report_size")
        digest = value.get("report_sha256")
        if (
            set(value)
            != {
                "state",
                "reason_code",
                "report_size",
                "report_sha256",
            }
            or value["reason_code"] is not None
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 < size <= MAX_ANALYSIS_REPORT_ZIP_BYTES
            or not isinstance(digest, str)
            or _HASH.fullmatch(digest) is None
        ):
            raise EvidenceError("analysis_worker_result_invalid")
        pending = folder / WORKER_REPORT_NAME
        check_ancestors(pending)
        if not pending.is_file() or is_reparse(pending):
            raise EvidenceError("analysis_worker_result_invalid")
        actual_size, actual_digest = bounded_hash(
            pending, MAX_ANALYSIS_REPORT_ZIP_BYTES
        )
        if actual_size != size or actual_digest != digest:
            raise EvidenceError("analysis_worker_result_invalid")
        return value

    def _publish_completed(
        self,
        item: dict,
        folder: Path,
        status: dict,
        cancel: threading.Event,
        execution_deadline: float,
    ) -> None:
        pending = folder / WORKER_REPORT_NAME
        target = folder / "analysis-report.zip"
        with self.jobs._mutex:
            override = self._override(cancel, execution_deadline)
            if override is not None:
                self.store.finish(item["id"], *override)
                return
            try:
                if target.exists() or target.is_symlink():
                    raise OSError("analysis report path occupied")
                pending.replace(target)
            except OSError:
                self.store.finish(
                    item["id"], "failed", "analysis_report_invalid"
                )
                return
            override = self._override(cancel, execution_deadline)
            if override is not None:
                target.unlink(missing_ok=True)
                self.store.finish(item["id"], *override)
                return
            published = self.store.finish(
                item["id"],
                "completed",
                None,
                report_path=str(target.relative_to(self.jobs.store.root)),
                report_size=status["report_size"],
                report_sha256=status["report_sha256"],
            )
            if not published:
                target.unlink(missing_ok=True)
