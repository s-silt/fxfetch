"""Small SQLite repository. Transactions own idempotency and state transitions."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .core.errors import FxfetchError

TERMINAL = {"completed", "cancelled", "interrupted"}
PROGRESS_TIMING = (
    "started_at",
    "deadline_at",
    "timeout_seconds",
    "queue_deadline_at",
    "queue_timeout_seconds",
    "execution_limit_method",
)


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


class Store:
    def __init__(self, root: Path):
        self.root = root.absolute()
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "service.sqlite3"
        self.lock = threading.RLock()
        with self.connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, csrf TEXT NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS images (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, path TEXT NOT NULL, result TEXT NOT NULL,
                    created REAL NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL, idem TEXT NOT NULL, request_hash TEXT NOT NULL,
                    input TEXT NOT NULL, state TEXT NOT NULL, outcome TEXT, reason_code TEXT,
                    result TEXT, progress TEXT, created REAL NOT NULL, updated REAL NOT NULL,
                    UNIQUE(owner,idem));
                CREATE TABLE IF NOT EXISTS continuations (
                    parent_id TEXT NOT NULL, child_id TEXT UNIQUE NOT NULL, candidate_id TEXT NOT NULL,
                    PRIMARY KEY(parent_id,candidate_id));
                CREATE TABLE IF NOT EXISTS names (
                    host TEXT PRIMARY KEY, package TEXT UNIQUE NOT NULL, version INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS builds (
                    id TEXT PRIMARY KEY, job_id TEXT NOT NULL, owner TEXT NOT NULL, idem TEXT NOT NULL,
                    request_hash TEXT NOT NULL, url TEXT NOT NULL, package TEXT NOT NULL, version INTEGER NOT NULL,
                    filename TEXT NOT NULL, state TEXT NOT NULL, result TEXT, created REAL NOT NULL,
                    updated REAL NOT NULL, UNIQUE(owner,job_id,idem));
                CREATE TABLE IF NOT EXISTS artifacts (
                    id TEXT PRIMARY KEY, job_id TEXT NOT NULL, owner TEXT NOT NULL, build_id TEXT,
                    path TEXT NOT NULL, filename TEXT NOT NULL, kind TEXT NOT NULL, sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL, origin TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS analyses (
                    id TEXT PRIMARY KEY, job_id TEXT NOT NULL, owner TEXT NOT NULL, idem TEXT NOT NULL,
                    state TEXT NOT NULL, reason_code TEXT, created REAL NOT NULL, updated REAL NOT NULL,
                    started REAL, deadline REAL, queue_deadline REAL, output_path TEXT NOT NULL,
                    executable_path TEXT NOT NULL, source_path TEXT NOT NULL, source_size INTEGER NOT NULL,
                    source_sha256 TEXT NOT NULL, report_path TEXT, report_size INTEGER, report_sha256 TEXT,
                    UNIQUE(owner,job_id,idem));
            """)
            if sum(bool(row[5]) for row in db.execute("PRAGMA table_info(continuations)")) == 1:
                db.execute("ALTER TABLE continuations RENAME TO continuations_old")
                db.execute(
                    "CREATE TABLE continuations (parent_id TEXT NOT NULL, child_id TEXT UNIQUE NOT NULL, candidate_id TEXT NOT NULL, PRIMARY KEY(parent_id,candidate_id))"
                )
                db.execute("INSERT INTO continuations SELECT * FROM continuations_old")
                db.execute("DROP TABLE continuations_old")
            if "archived" not in {row[1] for row in db.execute("PRAGMA table_info(jobs)")}:
                db.execute("ALTER TABLE jobs ADD COLUMN archived INTEGER NOT NULL DEFAULT 0")
            if "progress" not in {row[1] for row in db.execute("PRAGMA table_info(builds)")}:
                db.execute("ALTER TABLE builds ADD COLUMN progress TEXT")
            if "used" not in {row[1] for row in db.execute("PRAGMA table_info(images)")}:
                db.execute("ALTER TABLE images ADD COLUMN used INTEGER NOT NULL DEFAULT 0")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        with self.lock:
            db = sqlite3.connect(self.path, timeout=10)
            db.row_factory = sqlite3.Row
            try:
                db.execute("BEGIN IMMEDIATE")
                yield db
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()

    def restart_interrupt(self) -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE jobs SET state='interrupted',reason_code='service_restarted',updated=? "
                "WHERE state NOT IN ('completed','cancelled','interrupted')",
                (time.time(),),
            )
            db.execute(
                "UPDATE builds SET state='interrupted',updated=? WHERE state IN ('queued','running')",
                (time.time(),),
            )
            db.execute(
                "UPDATE analyses SET state='interrupted',reason_code='service_restarted',updated=? "
                "WHERE state IN ('queued','running')",
                (time.time(),),
            )

    def session(self, digest: str) -> dict | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM sessions WHERE token_hash=? AND expires>?", (digest, time.time())
            ).fetchone()
            return dict(row) if row else None

    def new_session(self, digest: str, duration: int) -> dict:
        value = {
            "id": secrets.token_hex(16),
            "csrf": secrets.token_urlsafe(32),
            "expires": time.time() + duration,
        }
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
            db.execute(
                "INSERT INTO sessions VALUES (?,?,?,?)",
                (value["id"], digest, value["csrf"], value["expires"]),
            )
        return value

    def logout(self, owner: str) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE id=?", (owner,))

    def image(self, owner: str, image_id: str) -> dict:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM images WHERE id=? AND owner=? AND expires>?", (image_id, owner, time.time())
            ).fetchone()
        if not row:
            raise FxfetchError("not_found", "Image is unavailable")
        result = dict(row)
        result["result"] = json.loads(result["result"])
        return result

    def add_image(self, owner: str, path: str, result: dict, ttl: int, limit: int) -> str:
        identifier = secrets.token_hex(16)
        with self.connect() as db:
            count = db.execute(
                "SELECT count(*) FROM images WHERE owner=? AND expires>? AND used=0", (owner, time.time())
            ).fetchone()[0]
            if count >= limit:
                raise FxfetchError("image_queue_full", "Too many pending images")
            db.execute(
                "INSERT INTO images (id,owner,path,result,created,expires) VALUES (?,?,?,?,?,?)",
                (identifier, owner, path, json_text(result), time.time(), time.time() + ttl),
            )
        return identifier

    def mark_image_used(self, owner: str, identifier: str) -> None:
        with self.connect() as db:
            db.execute("UPDATE images SET used=1 WHERE id=? AND owner=?", (identifier, owner))

    def replay_job(self, owner: str, idem: str, request_value: dict) -> dict | None:
        digest = hashlib.sha256(json_text(request_value).encode()).hexdigest()
        with self.connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE owner=? AND idem=?", (owner, idem)).fetchone()
            if row is None:
                return None
            if row["archived"]:
                raise FxfetchError("not_found", "Job is unavailable")
            if row["request_hash"] != digest:
                raise FxfetchError("idempotency_conflict", "Key already used for a different request")
            return self._job(row)

    def create_job(
        self, owner: str, idem: str, value: dict, max_queue: int, request_value: dict | None = None
    ) -> tuple[dict, bool]:
        digest = hashlib.sha256(
            json_text(request_value if request_value is not None else value).encode()
        ).hexdigest()
        with self.connect() as db:
            existing = db.execute("SELECT * FROM jobs WHERE owner=? AND idem=?", (owner, idem)).fetchone()
            if existing:
                if existing["archived"]:
                    raise FxfetchError("not_found", "Job is unavailable")
                if existing["request_hash"] != digest:
                    raise FxfetchError("idempotency_conflict", "Key already used for a different request")
                return self._job(existing), False
            if db.execute("SELECT count(*) FROM jobs WHERE state='queued'").fetchone()[0] >= max_queue:
                raise FxfetchError("queue_full", "Download queue is full")
            identifier, now = secrets.token_hex(16), time.time()
            db.execute(
                "INSERT INTO jobs (id,owner,idem,request_hash,input,state,outcome,reason_code,result,progress,created,updated) VALUES (?,?,?,?,?,'queued',NULL,NULL,NULL,NULL,?,?)",
                (identifier, owner, idem, digest, json_text(value), now, now),
            )
            row = db.execute("SELECT * FROM jobs WHERE id=?", (identifier,)).fetchone()
            return self._job(row), True

    def continuation_children(self, owner: str, parent_id: str) -> list[dict]:
        with self.connect() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT candidate_id,child_id,jobs.state FROM continuations JOIN jobs ON jobs.id=continuations.child_id "
                    "WHERE parent_id=? AND jobs.owner=? AND jobs.archived=0",
                    (parent_id, owner),
                )
            ]

    def continuation_child(self, owner: str, parent_id: str) -> str | None:
        return next(
            (
                row["child_id"]
                for row in self.continuation_children(owner, parent_id)
                if row["state"] in {"queued", "running"}
            ),
            None,
        )

    def create_continuation(
        self, owner: str, parent_id: str, candidate_id: str, idem: str, source: dict, max_queue: int
    ) -> tuple[dict, bool]:
        request = {"parent_job_id": parent_id, "candidate_id": candidate_id}
        digest = hashlib.sha256(json_text(request).encode()).hexdigest()
        with self.connect() as db:
            parent = db.execute(
                "SELECT * FROM jobs WHERE id=? AND owner=? AND archived=0", (parent_id, owner)
            ).fetchone()
            if parent is None:
                raise FxfetchError("not_found", "Job is unavailable")
            existing = db.execute("SELECT * FROM jobs WHERE owner=? AND idem=?", (owner, idem)).fetchone()
            if existing:
                if existing["archived"]:
                    raise FxfetchError("not_found", "Job is unavailable")
                if existing["request_hash"] != digest:
                    raise FxfetchError("idempotency_conflict", "Key already used for a different request")
                return self._job(existing), False
            if parent["state"] != "completed" or parent["outcome"] == "downloaded":
                raise FxfetchError(
                    "invalid_continuation", "Selection requires a completed job without an original"
                )
            if db.execute(
                "SELECT 1 FROM continuations WHERE parent_id=? AND candidate_id=?", (parent_id, candidate_id)
            ).fetchone():
                raise FxfetchError(
                    "candidate_already_selected",
                    "This candidate already has a continuation; view its child job",
                )
            if db.execute(
                "SELECT 1 FROM continuations JOIN jobs ON jobs.id=continuations.child_id "
                "WHERE parent_id=? AND jobs.state IN ('queued','running')",
                (parent_id,),
            ).fetchone():
                raise FxfetchError("continuation_active", "Wait for the active candidate job to finish")
            if db.execute("SELECT count(*) FROM jobs WHERE state='queued'").fetchone()[0] >= max_queue:
                raise FxfetchError("queue_full", "Download queue is full")
            identifier, now = secrets.token_hex(16), time.time()
            db.execute(
                "INSERT INTO jobs (id,owner,idem,request_hash,input,state,created,updated) VALUES (?,?,?,?,?,'queued',?,?)",
                (identifier, owner, idem, digest, json_text(source), now, now),
            )
            db.execute("INSERT INTO continuations VALUES (?,?,?)", (parent_id, identifier, candidate_id))
            return self._job(db.execute("SELECT * FROM jobs WHERE id=?", (identifier,)).fetchone()), True

    @staticmethod
    def _job(row: sqlite3.Row) -> dict:
        result = dict(row)
        for key in ("input", "result", "progress"):
            result[key] = json.loads(result[key]) if result[key] else None
        for key in ("request_hash", "idem"):
            result.pop(key, None)
        return result

    def get_job(self, owner: str, identifier: str, *, include_archived: bool = False) -> dict:
        with self.connect() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=? AND owner=?", (identifier, owner)).fetchone()
            if row is None or (row["archived"] and not include_archived):
                raise FxfetchError("not_found", "Job is unavailable")
            result = self._job(row)
            result["artifacts"] = [
                dict(item)
                for item in db.execute(
                    "SELECT id,kind,filename,size,sha256,origin,build_id FROM artifacts WHERE job_id=?",
                    (identifier,),
                )
            ]
            result["builds"] = [
                self._build(item)
                for item in db.execute("SELECT * FROM builds WHERE job_id=? ORDER BY created", (identifier,))
            ]
            return result

    def list_jobs(self, owner: str) -> list[dict]:
        with self.connect() as db:
            return [
                self._job(row)
                for row in db.execute(
                    "SELECT jobs.*, (SELECT count(*) FROM builds WHERE builds.job_id=jobs.id "
                    "AND builds.state IN ('queued','running')) AS active_builds "
                    ",(SELECT count(*) FROM analyses WHERE analyses.job_id=jobs.id "
                    "AND analyses.state IN ('queued','running')) AS active_analyses "
                    "FROM jobs WHERE owner=? AND archived=0 ORDER BY created DESC LIMIT 50",
                    (owner,),
                )
            ]

    def clear_jobs(self, owner: str) -> tuple[int, list[str]]:
        """Atomically hide one session's history and cancel its unclaimed work.

        Active workers retain private access and finish cancellation normally.
        No evidence, downloaded files or other session records are deleted.
        """
        with self.connect() as db:
            jobs = list(db.execute("SELECT id FROM jobs WHERE owner=? AND archived=0", (owner,)))
            active = [
                row[0]
                for row in db.execute(
                    "SELECT id FROM jobs WHERE owner=? AND archived=0 AND state='running'", (owner,)
                )
            ]
            active.extend(
                row[0]
                for row in db.execute(
                    "SELECT builds.id FROM builds JOIN jobs ON jobs.id=builds.job_id WHERE jobs.owner=? AND jobs.archived=0 AND builds.state='running'",
                    (owner,),
                )
            )
            now = time.time()
            db.execute(
                "UPDATE builds SET state='cancelled',updated=? WHERE state='queued' AND job_id IN (SELECT id FROM jobs WHERE owner=? AND archived=0)",
                (now, owner),
            )
            db.execute(
                "UPDATE jobs SET state='cancelled',reason_code='cancelled',updated=? WHERE owner=? AND archived=0 AND state='queued'",
                (now, owner),
            )
            db.execute("UPDATE jobs SET archived=1,updated=? WHERE owner=? AND archived=0", (now, owner))
            return len(jobs), active

    def claim_job(self) -> dict | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM jobs WHERE state='queued' AND archived=0 ORDER BY created LIMIT 1"
            ).fetchone()
            if not row:
                return None
            db.execute("UPDATE jobs SET state='running',updated=? WHERE id=?", (time.time(), row["id"]))
            value = self._job(row)
            value["state"] = "running"
            return value

    def progress(self, identifier: str, value: dict, *, build: bool = False) -> None:
        table = "builds" if build else "jobs"
        with self.connect() as db:
            row = db.execute(f"SELECT progress,state FROM {table} WHERE id=?", (identifier,)).fetchone()
            if row is None or row["state"] not in {"queued", "running"}:
                return
            previous = json.loads(row["progress"]) if row["progress"] else {}
            events = previous.get("events", [])
            event = {
                key: value[key]
                for key in (
                    "event",
                    "url",
                    "chain",
                    "status",
                    "content_type",
                    "from_url",
                    "to_url",
                    "mechanism",
                    "same_browser_session",
                    "verification_passed",
                    "continuation",
                    "received_bytes",
                    "total_bytes",
                    "percent",
                    "complete",
                    "size",
                    "kind",
                    "reason_code",
                    "label",
                    "source_url",
                    "package_unverified",
                    "network_mode",
                    "attempt_id",
                    "from_mode",
                    "to_mode",
                    "new_request_session",
                    "cookies_inherited",
                    "outcome",
                    "request_count",
                )
                if key in value
            }
            now = time.time()
            if event.get("event"):
                event.update(seq=previous.get("seq", 0) + 1, at=now)
                # Replace a frequent progress sample in-place, preserving bounded meaningful history.
                if (
                    events
                    and event["event"] == "download_progress"
                    and events[-1].get("event") == "download_progress"
                    and events[-1].get("url") == event.get("url")
                ):
                    events = events[:-1]
                events = (events + [event])[-128:]
                previous = {key: previous[key] for key in PROGRESS_TIMING if key in previous}
                previous.update(event)
            previous.update(
                {
                    key: value[key]
                    for key in (
                        "started_at",
                        "deadline_at",
                        "timeout_seconds",
                        "queue_deadline_at",
                        "queue_timeout_seconds",
                        "execution_limit_method",
                    )
                    if key in value
                }
            )
            previous["events"] = events
            db.execute(
                f"UPDATE {table} SET progress=?,updated=? WHERE id=?", (json_text(previous), now, identifier)
            )

    def expire_queued(self, collect_timeout: float, build_timeout: float) -> list[dict]:
        now = time.time()
        expired_jobs: list[dict] = []
        with self.connect() as db:
            for table, timeout in (("jobs", collect_timeout), ("builds", build_timeout)):
                columns = "id,progress,input" if table == "jobs" else "id,progress"
                rows = list(
                    db.execute(
                        f"SELECT {columns} FROM {table} WHERE state='queued' AND created<=?",
                        (now - timeout,),
                    )
                )
                for row in rows:
                    progress = json.loads(row["progress"]) if row["progress"] else {}
                    event = {
                        "event": "queue_timeout",
                        "reason_code": "queue_timeout",
                        "at": now,
                        "seq": progress.get("seq", 0) + 1,
                    }
                    progress.update(event)
                    progress["events"] = (progress.get("events", []) + [event])[-128:]
                    result = {"outcome": "failed", "reason_code": "queue_timeout", "coverage": "not_started"}
                    if table == "jobs":
                        updated = db.execute(
                            "UPDATE jobs SET state='completed',outcome='failed',reason_code='queue_timeout',result=?,progress=?,updated=? WHERE id=? AND state='queued'",
                            (json_text(result), json_text(progress), now, row["id"]),
                        )
                        if updated.rowcount:
                            expired_jobs.append({
                                "id": row["id"], "input": json.loads(row["input"]), "result": result,
                            })
                    else:
                        db.execute(
                            "UPDATE builds SET state='failed',result=?,progress=?,updated=? WHERE id=? AND state='queued'",
                            (json_text(result), json_text(progress), now, row["id"]),
                        )
        return expired_jobs

    def finish_job(self, identifier: str, state: str, result: dict) -> None:
        if state not in TERMINAL:
            raise ValueError("invalid terminal job state")
        with self.connect() as db:
            db.execute(
                "UPDATE jobs SET state=?,outcome=?,reason_code=?,result=?,updated=? "
                "WHERE id=? AND state='running'",
                (
                    state,
                    result.get("outcome"),
                    result.get("reason_code"),
                    json_text(result),
                    time.time(),
                    identifier,
                ),
            )

    def cancel_queued_job(self, owner: str, identifier: str) -> None:
        self.get_job(owner, identifier)
        with self.connect() as db:
            db.execute(
                "UPDATE jobs SET state='cancelled',reason_code='cancelled',updated=? "
                "WHERE id=? AND state='queued'",
                (time.time(), identifier),
            )

    def fail_pending_job(self, identifier: str) -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE jobs SET state='interrupted',reason_code='input_persistence_failed',updated=? "
                "WHERE id=? AND state='queued'",
                (time.time(), identifier),
            )

    def finish_with_artifacts(
        self,
        identifier: str,
        state: str,
        result: dict,
        artifacts: list[dict],
        deadline: float,
        cancel: Any,
        *,
        build: bool = False,
    ) -> dict:
        """Publish validated outputs and terminal state in the same transaction."""
        table = "builds" if build else "jobs"
        with self.connect() as db:
            row = db.execute(f"SELECT state,result FROM {table} WHERE id=?", (identifier,)).fetchone()
            if row is None:
                raise FxfetchError("not_found", "Task is unavailable")
            if row["state"] != "running":
                return {"state": row["state"], "result": json.loads(row["result"]) if row["result"] else {}}
            cancelled = cancel.is_set()
            expired = time.monotonic() >= deadline
            if cancelled or expired:
                code = "cancelled" if cancelled else "build_timeout" if build else "task_timeout"
                state = "cancelled" if cancelled else "failed" if build else "completed"
                result = {"reason_code": code, "outcome": "failed", "coverage": "partial"}
                if build:
                    result["state"] = state
                artifacts = []
            current = db.execute(f"SELECT progress FROM {table} WHERE id=?", (identifier,)).fetchone()
            progress = json.loads(current["progress"]) if current["progress"] else {}
            reason = result.get("reason_code")
            event = {
                "event": reason
                if reason in {"task_timeout", "build_timeout", "cancelled"}
                else state
                if build
                else "task_completed",
                "reason_code": reason,
                "at": time.time(),
                "seq": progress.get("seq", 0) + 1,
            }
            events = (progress.get("events", []) + [event])[-128:]
            progress = {key: progress[key] for key in PROGRESS_TIMING if key in progress}
            progress.update(event)
            progress["events"] = events
            db.execute(f"UPDATE {table} SET progress=? WHERE id=?", (json_text(progress), identifier))
            for artifact in artifacts:
                artifact_id = secrets.token_hex(16)
                db.execute(
                    "INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        artifact_id,
                        artifact["job_id"],
                        artifact["owner"],
                        artifact.get("build_id"),
                        artifact["path"],
                        artifact["filename"],
                        artifact["kind"],
                        artifact["sha256"],
                        artifact["size"],
                        artifact["origin"],
                    ),
                )
                if build:
                    result["artifact_id"] = artifact_id
            if build:
                db.execute(
                    "UPDATE builds SET state=?,result=?,updated=? WHERE id=? AND state='running'",
                    (state, json_text(result), time.time(), identifier),
                )
            else:
                db.execute(
                    "UPDATE jobs SET state=?,outcome=?,reason_code=?,result=?,updated=? WHERE id=? AND state='running'",
                    (
                        state,
                        result.get("outcome"),
                        result.get("reason_code"),
                        json_text(result),
                        time.time(),
                        identifier,
                    ),
                )

        return {"state": state, "result": result}

    def add_artifact(
        self,
        *,
        job_id: str,
        owner: str,
        path: str,
        filename: str,
        kind: str,
        sha256: str,
        size: int,
        origin: str,
        build_id: str | None = None,
    ) -> str:
        identifier = secrets.token_hex(16)
        with self.connect() as db:
            db.execute(
                "INSERT INTO artifacts VALUES (?,?,?,?,?,?,?,?,?,?)",
                (identifier, job_id, owner, build_id, path, filename, kind, sha256, size, origin),
            )
        return identifier

    def artifact(self, owner: str, job_id: str, identifier: str) -> dict:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM artifacts WHERE id=? AND job_id=? AND owner=? AND EXISTS (SELECT 1 FROM jobs WHERE jobs.id=artifacts.job_id AND jobs.archived=0)",
                (identifier, job_id, owner),
            ).fetchone()
        if not row:
            raise FxfetchError("not_found", "Artifact is unavailable")
        return dict(row)

    @staticmethod
    def _build(row: sqlite3.Row) -> dict:
        value = dict(row)
        value["result"] = json.loads(value["result"]) if value["result"] else None
        value["progress"] = json.loads(value["progress"]) if value.get("progress") else None
        for key in ("request_hash", "idem", "owner"):
            value.pop(key, None)
        return value

    def create_build(self, owner: str, job_id: str, idem: str, url: str, names: Any, max_queue: int) -> dict:
        digest = hashlib.sha256(url.encode()).hexdigest()
        with self.connect() as db:
            parent = db.execute(
                "SELECT state,outcome FROM jobs WHERE id=? AND owner=? AND archived=0", (job_id, owner)
            ).fetchone()
            if parent is None or parent["state"] not in TERMINAL or parent["outcome"] == "downloaded":
                raise FxfetchError(
                    "invalid_build_source", "Build requires an owned finished job without an original package"
                )
            existing = db.execute(
                "SELECT * FROM builds WHERE owner=? AND job_id=? AND idem=? AND EXISTS (SELECT 1 FROM jobs WHERE jobs.id=builds.job_id AND jobs.archived=0)",
                (owner, job_id, idem),
            ).fetchone()
            if existing:
                if existing["request_hash"] != digest:
                    raise FxfetchError("idempotency_conflict", "Build key already used")
                return self._build(existing)
            if db.execute("SELECT count(*) FROM builds WHERE state='queued'").fetchone()[0] >= max_queue:
                raise FxfetchError("queue_full", "Build queue is full")
            row = db.execute("SELECT * FROM names WHERE host=?", (names.host,)).fetchone()
            if row:
                package, version = row["package"], row["version"] + 1
                db.execute("UPDATE names SET version=? WHERE host=?", (version, names.host))
            else:
                package, version = names.package_base, 1
                if db.execute("SELECT 1 FROM names WHERE package=?", (package,)).fetchone():
                    package += ".h" + hashlib.sha256(names.host.encode()).hexdigest()[:16]
                db.execute("INSERT INTO names VALUES (?,?,?)", (names.host, package, version))
            identifier, now = secrets.token_hex(16), time.time()
            db.execute(
                "INSERT INTO builds (id,job_id,owner,idem,request_hash,url,package,version,filename,state,result,created,updated) VALUES (?,?,?,?,?,?,?,?,?,'queued',NULL,?,?)",
                (identifier, job_id, owner, idem, digest, url, package, version, names.filename, now, now),
            )
            return self._build(db.execute("SELECT * FROM builds WHERE id=?", (identifier,)).fetchone())

    def get_build(self, owner: str, job_id: str, identifier: str) -> dict:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM builds WHERE id=? AND job_id=? AND owner=? AND EXISTS (SELECT 1 FROM jobs WHERE jobs.id=builds.job_id AND jobs.archived=0)",
                (identifier, job_id, owner),
            ).fetchone()
            if not row:
                raise FxfetchError("not_found", "Build is unavailable")
            return self._build(row)

    def replay_build(self, owner: str, job_id: str, idem: str, url: str) -> dict | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM builds WHERE owner=? AND job_id=? AND idem=? AND EXISTS (SELECT 1 FROM jobs WHERE jobs.id=builds.job_id AND jobs.archived=0)",
                (owner, job_id, idem),
            ).fetchone()
            if row is None:
                return None
            if row["request_hash"] != hashlib.sha256(url.encode()).hexdigest():
                raise FxfetchError("idempotency_conflict", "Build key already used")
            return self._build(row)

    def claim_build(self) -> dict | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM builds WHERE state='queued' AND EXISTS (SELECT 1 FROM jobs WHERE jobs.id=builds.job_id AND jobs.archived=0) ORDER BY created LIMIT 1"
            ).fetchone()
            if not row:
                return None
            db.execute("UPDATE builds SET state='running',updated=? WHERE id=?", (time.time(), row["id"]))
            value = dict(row)
            value["state"] = "running"
            return value

    def finish_build(self, identifier: str, state: str, result: dict) -> None:
        if state not in {"built", "failed", "disabled", "cancelled", "interrupted"}:
            raise ValueError("invalid terminal build state")
        with self.connect() as db:
            db.execute(
                "UPDATE builds SET state=?,result=?,updated=? WHERE id=? AND state='running'",
                (state, json_text(result), time.time(), identifier),
            )

    def cancel_queued_build(self, owner: str, job_id: str, identifier: str) -> None:
        self.get_build(owner, job_id, identifier)
        with self.connect() as db:
            db.execute(
                "UPDATE builds SET state='cancelled',updated=? WHERE id=? AND state='queued'",
                (time.time(), identifier),
            )
