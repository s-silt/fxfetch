"""SQLite state transitions for independently managed offline analyses."""

from __future__ import annotations

import secrets
import time
from typing import Any

from .core.errors import FxfetchError
from .store import TERMINAL, Store

ACTIVE_ANALYSES = {"queued", "running"}
ANALYSIS_TERMINAL = {"completed", "failed", "not_analyzed", "cancelled", "interrupted"}


class AnalysisStore:
    def __init__(self, store: Store):
        self.store = store

    @staticmethod
    def public(row: Any) -> dict:
        value = dict(row)
        result = {
            key: value[key]
            for key in (
                "id",
                "job_id",
                "state",
                "reason_code",
                "created",
                "updated",
                "started",
                "deadline",
                "queue_deadline",
            )
        }
        ready = value["state"] == "completed" and bool(value.get("report_path"))
        result.update(online=False, coverage="partial", report_ready=ready)
        if ready:
            result.update(report_size=value["report_size"], report_sha256=value["report_sha256"])
        return result

    def replay(self, owner: str, job_id: str, idem: str) -> dict | None:
        with self.store.connect() as db:
            row = db.execute(
                "SELECT analyses.* FROM analyses JOIN jobs ON jobs.id=analyses.job_id "
                "WHERE analyses.owner=? AND analyses.job_id=? AND analyses.idem=? "
                "AND jobs.owner=? AND jobs.archived=0",
                (owner, job_id, idem, owner),
            ).fetchone()
            return self.public(row) if row else None

    def create(
        self,
        owner: str,
        job_id: str,
        idem: str,
        *,
        executable: str,
        source: dict,
        max_queue: int,
        max_per_job: int,
        queue_timeout: float,
    ) -> tuple[dict, bool]:
        with self.store.connect() as db:
            existing = db.execute(
                "SELECT * FROM analyses WHERE owner=? AND job_id=? AND idem=?",
                (owner, job_id, idem),
            ).fetchone()
            if existing:
                parent = db.execute(
                    "SELECT 1 FROM jobs WHERE id=? AND owner=? AND archived=0", (job_id, owner)
                ).fetchone()
                if parent is None:
                    raise FxfetchError("not_found", "Job is unavailable")
                return self.public(existing), False
            parent = db.execute(
                "SELECT state FROM jobs WHERE id=? AND owner=? AND archived=0", (job_id, owner)
            ).fetchone()
            if parent is None:
                raise FxfetchError("not_found", "Job is unavailable")
            if parent["state"] not in TERMINAL:
                raise FxfetchError("analysis_source_unavailable", "Data package is not ready")
            if db.execute(
                "SELECT 1 FROM analyses WHERE job_id=? AND state IN ('queued','running')", (job_id,)
            ).fetchone():
                raise FxfetchError("analysis_active", "An analysis is already active")
            if db.execute("SELECT count(*) FROM analyses WHERE job_id=?", (job_id,)).fetchone()[0] >= max_per_job:
                raise FxfetchError("analysis_limit", "Analysis attempt limit reached")
            if db.execute(
                "SELECT count(*) FROM analyses WHERE state='queued'"
            ).fetchone()[0] >= max_queue:
                raise FxfetchError("analysis_queue_full", "Analysis queue is full")
            identifier, now = secrets.token_hex(16), time.time()
            output = f"analyses/{identifier}"
            db.execute(
                "INSERT INTO analyses "
                "(id,job_id,owner,idem,state,reason_code,created,updated,started,deadline,"
                "queue_deadline,output_path,executable_path,source_path,source_size,source_sha256,"
                "report_path,report_size,report_sha256) "
                "VALUES (?,?,?,?,'queued',NULL,?,?,NULL,NULL,?,?,?,?,?,?,NULL,NULL,NULL)",
                (
                    identifier,
                    job_id,
                    owner,
                    idem,
                    now,
                    now,
                    now + queue_timeout,
                    output,
                    executable,
                    source["path"],
                    source["size"],
                    source["sha256"],
                ),
            )
            row = db.execute("SELECT * FROM analyses WHERE id=?", (identifier,)).fetchone()
            return self.public(row), True

    def list(self, owner: str, job_id: str) -> list[dict]:
        with self.store.connect() as db:
            parent = db.execute(
                "SELECT 1 FROM jobs WHERE id=? AND owner=? AND archived=0", (job_id, owner)
            ).fetchone()
            if parent is None:
                raise FxfetchError("not_found", "Job is unavailable")
            return [
                self.public(row)
                for row in db.execute(
                    "SELECT * FROM analyses WHERE owner=? AND job_id=? ORDER BY created", (owner, job_id)
                )
            ]

    def get_private(self, owner: str, job_id: str, identifier: str) -> dict:
        with self.store.connect() as db:
            row = db.execute(
                "SELECT analyses.* FROM analyses JOIN jobs ON jobs.id=analyses.job_id "
                "WHERE analyses.id=? AND analyses.job_id=? AND analyses.owner=? "
                "AND jobs.owner=? AND jobs.archived=0",
                (identifier, job_id, owner, owner),
            ).fetchone()
            if row is None:
                raise FxfetchError("not_found", "Analysis is unavailable")
            return dict(row)

    def get(self, owner: str, job_id: str, identifier: str) -> dict:
        return self.public(self.get_private(owner, job_id, identifier))

    def claim(self, timeout: float) -> dict | None:
        with self.store.connect() as db:
            now = time.time()
            db.execute(
                "UPDATE analyses SET state='failed',reason_code='queue_timeout',updated=? "
                "WHERE state='queued' AND queue_deadline<=?",
                (now, now),
            )
            row = db.execute(
                "SELECT analyses.* FROM analyses JOIN jobs ON jobs.id=analyses.job_id "
                "WHERE analyses.state='queued' AND analyses.queue_deadline>? "
                "AND jobs.archived=0 ORDER BY analyses.created LIMIT 1",
                (now,),
            ).fetchone()
            if row is None:
                return None
            changed = db.execute(
                "UPDATE analyses SET state='running',started=?,deadline=?,updated=? "
                "WHERE id=? AND state='queued'",
                (now, now + timeout, now, row["id"]),
            ).rowcount
            if not changed:
                return None
            value = dict(row)
            value.update(state="running", started=now, deadline=now + timeout, updated=now)
            return value

    def finish(
        self,
        identifier: str,
        state: str,
        reason_code: str | None,
        *,
        report_path: str | None = None,
        report_size: int | None = None,
        report_sha256: str | None = None,
    ) -> bool:
        if state not in ANALYSIS_TERMINAL:
            raise ValueError("invalid analysis state")
        with self.store.connect() as db:
            return bool(
                db.execute(
                    "UPDATE analyses SET state=?,reason_code=?,updated=?,report_path=?,"
                    "report_size=?,report_sha256=? WHERE id=? AND state='running'",
                    (
                        state,
                        reason_code,
                        time.time(),
                        report_path,
                        report_size,
                        report_sha256,
                        identifier,
                    ),
                ).rowcount
            )

    def cancel(self, owner: str, job_id: str, identifier: str) -> tuple[dict, bool]:
        self.get_private(owner, job_id, identifier)
        with self.store.connect() as db:
            running = bool(
                db.execute(
                    "SELECT 1 FROM analyses WHERE id=? AND state='running'", (identifier,)
                ).fetchone()
            )
            db.execute(
                "UPDATE analyses SET state='cancelled',reason_code='cancelled',updated=? "
                "WHERE id=? AND state IN ('queued','running')",
                (time.time(), identifier),
            )
            row = db.execute("SELECT * FROM analyses WHERE id=?", (identifier,)).fetchone()
            return self.public(row), running

    def cancel_owner(self, owner: str) -> list[str]:
        with self.store.connect() as db:
            running = [
                row["id"]
                for row in db.execute(
                    "SELECT id FROM analyses WHERE owner=? AND state='running'", (owner,)
                )
            ]
            db.execute(
                "UPDATE analyses SET state='cancelled',reason_code='cancelled',updated=? "
                "WHERE owner=? AND state IN ('queued','running')",
                (time.time(), owner),
            )
            return running

    def expire_queued(self) -> int:
        with self.store.connect() as db:
            return db.execute(
                "UPDATE analyses SET state='failed',reason_code='queue_timeout',updated=? "
                "WHERE state='queued' AND queue_deadline<=?",
                (time.time(), time.time()),
            ).rowcount
