"""Seven-day task retention; fixed owned paths, resumable deletion and active guards."""
from __future__ import annotations

import logging
import os
import re
import shutil
import sqlite3
import stat
import time
from pathlib import Path
from typing import TYPE_CHECKING

from .core.errors import FxfetchError
from .security import contained_path

if TYPE_CHECKING:
    from .store import Store

SECONDS = 7 * 24 * 3600
log = logging.getLogger(__name__)


def initialize(db: sqlite3.Connection) -> None:
    for table in ("jobs", "builds", "analyses"):
        if "finished_at" not in {row[1] for row in db.execute(f"PRAGMA table_info({table})")}:
            db.execute(f"ALTER TABLE {table} ADD COLUMN finished_at REAL")
            db.execute(f"UPDATE {table} SET finished_at=updated WHERE state NOT IN ('queued','running')")
        # Only state transitions affect this clock. Refresh/archive and reads do not.
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS retention_{table}_update
            AFTER UPDATE OF state ON {table} BEGIN
            UPDATE {table} SET finished_at=CASE
              WHEN NEW.state IN ('queued','running') THEN NULL
              WHEN OLD.state IN ('queued','running') OR OLD.finished_at IS NULL THEN NEW.updated
              ELSE OLD.finished_at END WHERE id=NEW.id; END""")
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS retention_{table}_insert
            AFTER INSERT ON {table} WHEN NEW.state NOT IN ('queued','running') BEGIN
            UPDATE {table} SET finished_at=NEW.updated WHERE id=NEW.id; END""")
    if "purging" not in {row[1] for row in db.execute("PRAGMA table_info(jobs)")}:
        db.execute("ALTER TABLE jobs ADD COLUMN purging INTEGER NOT NULL DEFAULT 0")
    if "retention_checked" not in {row[1] for row in db.execute("PRAGMA table_info(jobs)")}:
        db.execute("ALTER TABLE jobs ADD COLUMN retention_checked REAL NOT NULL DEFAULT 0")


def status(db: sqlite3.Connection, identifier: str, protected: set[str] | None = None) -> dict:
    family = [row[0] for row in db.execute(
        "WITH RECURSIVE family(id) AS (SELECT ? UNION SELECT c.child_id FROM continuations c "
        "JOIN family f ON c.parent_id=f.id) SELECT id FROM family", (identifier,),
    )]
    placeholders = ",".join("?" for _ in family)
    rows = list(db.execute(f"SELECT id,state,finished_at FROM jobs WHERE id IN ({placeholders})", family))
    for table in ("builds", "analyses"):
        rows.extend(db.execute(f"SELECT id,state,finished_at FROM {table} WHERE job_id IN ({placeholders})", family))
    active = not rows or any(row["state"] in {"queued", "running"} or row["finished_at"] is None
                            or row["id"] in (protected or set()) for row in rows)
    finished = max((row["finished_at"] or 0 for row in rows), default=0)
    return {"days": 7, "protected_active": active,
            "finished_at": None if active else finished,
            "expires_at": None if active else finished + SECONDS}


def _safe_tree(root: Path, relative: str) -> Path:
    path = contained_path(root, relative, must_exist=False)
    if not path.exists():
        return path
    if not path.is_dir():
        raise ValueError("retention_not_directory")
    for current, directories, files in os.walk(path, followlinks=False):
        for name in (*directories, *files):
            info = (Path(current) / name).lstat()
            if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
                    or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))):
                raise ValueError("retention_link_or_special_file")
    return path


def _remove_owned(root: Path, kind: str, identifier: str) -> None:
    if kind not in {"jobs", "analyses"} or not re.fullmatch(r"[0-9a-f]{32}", identifier):
        raise ValueError("retention_invalid_identity")
    source = _safe_tree(root, f"{kind}/{identifier}")
    trash = _safe_tree(root, f".retention-trash/{kind}-{identifier}")
    # Both paths have been checked before any recursive deletion or move.
    if trash.exists():
        shutil.rmtree(trash)
    if source.exists():
        contained_path(root, ".retention-trash", must_exist=False).mkdir(mode=0o700, exist_ok=True)
        source.rename(trash)
        _safe_tree(root, f".retention-trash/{kind}-{identifier}")
        shutil.rmtree(trash)


def cleanup(store: Store, protected: set[str], *, now: float | None = None, limit: int = 20) -> int:
    """Caller holds JobService._mutex, shared by creation/claim/publication paths."""
    now = time.time() if now is None else now
    with store.connect() as db:
        candidates = [row[0] for row in db.execute(
            "SELECT id FROM jobs WHERE purging=1 OR (finished_at IS NOT NULL AND finished_at<=?) "
            "ORDER BY retention_checked,finished_at LIMIT ?", (now - SECONDS, limit),
        )]
    removed = 0
    for identifier in candidates:
        try:
            with store.connect() as db:
                db.execute("UPDATE jobs SET retention_checked=? WHERE id=?", (now, identifier))
                value = status(db, identifier, protected)
                if value["protected_active"] or value["expires_at"] > now:
                    continue
                analyses = [row[0] for row in db.execute("SELECT id FROM analyses WHERE job_id=?", (identifier,))]
                # Validate every tree before hiding or deleting any part of this task.
                for kind, item in [("jobs", identifier), *[("analyses", item) for item in analyses]]:
                    if not re.fullmatch(r"[0-9a-f]{32}", item):
                        raise ValueError("retention_invalid_identity")
                    _safe_tree(store.root, f"{kind}/{item}")
                    _safe_tree(store.root, f".retention-trash/{kind}-{item}")
                db.execute("UPDATE jobs SET archived=1,purging=1 WHERE id=?", (identifier,))
            for item in analyses:
                _remove_owned(store.root, "analyses", item)
            _remove_owned(store.root, "jobs", identifier)
            with store.connect() as db:
                for table in ("artifacts", "analyses", "builds"):
                    db.execute(f"DELETE FROM {table} WHERE job_id=?", (identifier,))
                db.execute("DELETE FROM continuations WHERE parent_id=? OR child_id=?", (identifier, identifier))
                db.execute("DELETE FROM jobs WHERE id=? AND purging=1", (identifier,))
            removed += 1
        except (OSError, ValueError, sqlite3.Error, FxfetchError) as error:
            log.warning("retention_cleanup_failed job_id=%s exception_type=%s", identifier, type(error).__name__)
            with store.connect() as db:
                db.execute("UPDATE jobs SET retention_checked=? WHERE id=?", (now, identifier))
    return removed
