"""Synthetic retention clocks, active-worker protection and safe deletion."""

import pytest

from fxfetch import retention
from fxfetch.config import Settings
from fxfetch.core.errors import FxfetchError
from fxfetch.service import JobService
from fxfetch.store import Store

NOW = 2_000_000_000.0
OLD = NOW - retention.SECONDS
JOB = "a" * 32
OTHER = "b" * 32
CHILD = "c" * 32


def job(store, identifier=JOB, finished=OLD, state="completed"):
    with store.connect() as db:
        db.execute("INSERT INTO jobs (id,owner,idem,request_hash,input,state,created,updated) "
                   "VALUES (?,'owner',?,'hash','{\"entry_url\":\"https://example.test/\"}',?,?,?)", (identifier, identifier, state, finished, finished))
    folder = store.root / "jobs" / identifier
    folder.mkdir(parents=True)
    (folder / "sample.apk").write_bytes(b"synthetic-original")
    return folder


def operation(store, table, state, finished=OLD, parent=JOB, identifier=OTHER):
    with store.connect() as db:
        if table == "analyses":
            db.execute("INSERT INTO analyses (id,job_id,owner,idem,state,created,updated,output_path,"
                       "executable_path,source_path,source_size,source_sha256) "
                       "VALUES (?,?,'owner',?,?,?,?,'ignored','synthetic','synthetic',1,'hash')",
                       (identifier, parent, identifier, state, finished, finished))
            path = store.root / "analyses" / identifier
            path.mkdir(parents=True)
            (path / "report.zip").write_bytes(b"synthetic-report")
        else:
            db.execute("INSERT INTO builds (id,job_id,owner,idem,request_hash,url,package,version,filename,state,created,updated) "
                       "VALUES (?,?,'owner',?,'hash','https://example.test','test.package',1,'sample.apk',?,?,?)",
                       (identifier, parent, identifier, state, finished, finished))


def test_exact_boundary_removes_all_owned_material_and_rows(tmp_path):
    store = Store(tmp_path)
    folder = job(store)
    operation(store, "analyses", "completed")
    operation(store, "builds", "built", identifier=CHILD)
    protected = tmp_path / "auth.json"
    protected.write_text("keep")
    with store.connect() as db:
        db.execute("INSERT INTO artifacts VALUES ('artifact',?,'owner',NULL,'jobs/path','sample.apk','apk','hash',1,'original')", (JOB,))
    assert retention.cleanup(store, set(), now=NOW - .01) == 0
    assert retention.cleanup(store, set(), now=NOW) == 1
    assert not folder.exists() and not (tmp_path / "analyses" / OTHER).exists()
    assert protected.read_text() == "keep"
    with store.connect() as db:
        for table in ("jobs", "analyses", "artifacts", "builds"):
            assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


@pytest.mark.parametrize("table", ["jobs", "builds", "analyses"])
@pytest.mark.parametrize("state", ["queued", "running"])
def test_active_work_survives_regardless_of_age(tmp_path, table, state):
    store = Store(tmp_path)
    folder = job(store, state=state if table == "jobs" else "completed")
    if table != "jobs":
        operation(store, table, state)
    assert retention.cleanup(store, set(), now=NOW + 100 * retention.SECONDS) == 0
    assert folder.exists()


def test_latest_related_completion_and_refresh_do_not_shorten_or_reset(tmp_path):
    store = Store(tmp_path)
    job(store)
    operation(store, "analyses", "completed", finished=NOW - 100)
    with store.connect() as db:
        assert retention.status(db, JOB)["expires_at"] == NOW - 100 + retention.SECONDS
    store.clear_jobs("owner")
    assert retention.cleanup(store, set(), now=NOW) == 0
    assert retention.cleanup(store, set(), now=NOW - 100 + retention.SECONDS) == 1


def test_state_clock_survives_reopen_and_records_restart_interruption(tmp_path, monkeypatch):
    store = Store(tmp_path)
    job(store, state="running")
    monkeypatch.setattr("fxfetch.store.time.time", lambda: NOW)
    store.restart_interrupt()
    store = Store(tmp_path)
    with store.connect() as db:
        assert retention.status(db, JOB)["expires_at"] == NOW + retention.SECONDS
    assert retention.cleanup(store, set(), now=NOW) == 0


def test_legacy_clock_backfilled_once(tmp_path):
    store = Store(tmp_path)
    job(store)
    with store.connect() as db:
        for table in ("jobs", "builds", "analyses"):
            db.execute(f"DROP TRIGGER retention_{table}_insert")
            db.execute(f"DROP TRIGGER retention_{table}_update")
            db.execute(f"ALTER TABLE {table} DROP COLUMN finished_at")
    store = Store(tmp_path)
    with store.connect() as db:
        assert retention.status(db, JOB)["expires_at"] == NOW


def test_live_worker_registry_protects_cancelled_task(tmp_path):
    service = JobService(Settings(root=tmp_path, password_hash="unused"))
    job(service.store, state="cancelled")
    service._data_package_active.add(JOB)
    assert service.cleanup_retention(now=NOW) == 0
    service._data_package_active.clear()
    assert service.cleanup_retention(now=NOW) == 1


def test_descendant_activity_protects_parent(tmp_path):
    store = Store(tmp_path)
    parent = job(store)
    job(store, CHILD, state="running")
    with store.connect() as db:
        db.execute("INSERT INTO continuations VALUES (?,?,'candidate')", (JOB, CHILD))
    assert retention.cleanup(store, set(), now=NOW) == 0
    assert parent.exists()


def test_failed_delete_is_hidden_then_retried_after_restart(tmp_path, monkeypatch):
    store = Store(tmp_path)
    job(store)
    original = retention.shutil.rmtree
    def fail(_):
        raise PermissionError("synthetic open file")
    monkeypatch.setattr(retention.shutil, "rmtree", fail)
    assert retention.cleanup(store, set(), now=NOW) == 0
    with pytest.raises(FxfetchError):
        store.get_job("owner", JOB)
    assert (tmp_path / ".retention-trash" / ("jobs-" + JOB) / "sample.apk").exists()
    monkeypatch.setattr(retention.shutil, "rmtree", original)
    assert retention.cleanup(Store(tmp_path), set(), now=NOW + 60) == 1


def test_link_never_deletes_external_content(tmp_path):
    store = Store(tmp_path / "service")
    folder = job(store)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("keep")
    try:
        (folder / "escape").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("Windows symlink privilege unavailable; exercised on Linux")
    assert retention.cleanup(store, set(), now=NOW) == 0
    assert (outside / "keep").read_text() == "keep"


def test_protected_oldest_does_not_starve_next_batch(tmp_path):
    store = Store(tmp_path)
    job(store)
    job(store, OTHER, finished=OLD + 1)
    operation(store, "analyses", "running")
    assert retention.cleanup(store, set(), now=NOW + 2, limit=1) == 0
    assert retention.cleanup(store, set(), now=NOW + 3, limit=1) == 1


def test_terminal_clock_is_not_mutable_by_progress_or_clear(tmp_path):
    store = Store(tmp_path)
    job(store)
    store.clear_jobs("owner")
    with store.connect() as db:
        db.execute("UPDATE jobs SET updated=?,state='completed' WHERE id=?", (NOW, JOB))
        assert retention.status(db, JOB)["expires_at"] == NOW


def test_job_api_retention_metadata(tmp_path):
    service = JobService(Settings(root=tmp_path, password_hash="unused"))
    job(service.store)
    assert service.get_job("owner", JOB)["retention"]["expires_at"] == NOW


def test_concurrent_downloads_protected_until_last_response(tmp_path):
    service = JobService(Settings(root=tmp_path, password_hash="unused"))
    job(service.store)
    service.retain_download("owner", JOB)
    service.retain_download("owner", JOB)
    assert service.cleanup_retention(now=NOW) == 0
    service.release_download(JOB)
    assert service.cleanup_retention(now=NOW) == 0
    service.release_download(JOB)
    assert service.cleanup_retention(now=NOW) == 1
    with pytest.raises(FxfetchError):
        service.retain_download("owner", JOB)
