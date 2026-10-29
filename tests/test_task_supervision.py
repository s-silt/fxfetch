"""Task-wide supervision uses real bounded subprocesses and synthetic operations only."""

from __future__ import annotations

import json
import sys
import threading
import time
from dataclasses import replace

from fxfetch.config import Settings
from fxfetch.core.limits import Limits
from fxfetch.core.process_limits import run_limited
from fxfetch.core.web_apk import derive_names
from fxfetch.service import JobService
from fxfetch.store import Store


def make_service(tmp_path, **limits):
    return JobService(Settings(tmp_path, "synthetic-unused-hash", limits=replace(Limits(), **limits)))


def queued(service, key="synthetic-one"):
    item, _ = service.store.create_job("owner", key, {"entry_url": "https://synthetic.invalid/"}, 20)
    return item


def test_progress_is_bounded_coalesced_and_terminal_immutable(tmp_path):
    store = Store(tmp_path)
    job, _ = store.create_job("owner", "synthetic-one", {"entry_url": "https://synthetic.invalid/"}, 20)
    store.claim_job()
    store.progress(
        job["id"], {"event": "task_started", "started_at": 10, "deadline_at": 610, "timeout_seconds": 600}
    )
    for index in range(150):
        store.progress(
            job["id"], {"event": "request", "url": "https://synthetic.invalid/", "received_bytes": index}
        )
    for index in range(10):
        store.progress(
            job["id"],
            {
                "event": "download_progress",
                "url": "https://synthetic.invalid/app.apk",
                "received_bytes": index,
            },
        )
    value = store.get_job("owner", job["id"])["progress"]
    assert len(value["events"]) == 128
    assert value["received_bytes"] == 9 and value["started_at"] == 10
    assert sum(item["event"] == "download_progress" for item in value["events"]) == 1
    store.finish_job(job["id"], "completed", {"outcome": "failed"})
    store.progress(job["id"], {"event": "late"})
    assert store.get_job("owner", job["id"])["progress"] == value


def test_progress_keeps_verification_observation_separate_from_file_navigation(tmp_path):
    store = Store(tmp_path)
    job, _ = store.create_job("owner", "dom-link", {"entry_url": "https://synthetic.invalid/"}, 20)
    store.claim_job()
    store.progress(job["id"], {
        "event": "challenge_detected", "verification_passed": False,
        "continuation": "explicit_dom_package_link", "cookie": "synthetic-private",
    })
    store.progress(job["id"], {
        "event": "redirect", "mechanism": "rendered_package_link", "same_browser_session": True,
    })
    events = store.get_job("owner", job["id"])["progress"]["events"]
    assert events[0]["verification_passed"] is False
    assert events[0]["continuation"] == "explicit_dom_package_link"
    assert "cookie" not in events[0]
    assert events[1]["same_browser_session"] is True
    assert events[1]["mechanism"] == "rendered_package_link"


def test_queue_expiry_without_claim_expires_both_kinds(tmp_path):
    service = make_service(tmp_path)
    item = queued(service)
    service.store.claim_job()
    service.store.finish_job(item["id"], "completed", {"outcome": "failed"})
    build = service.store.create_build(
        "owner",
        item["id"],
        "synthetic-build",
        "https://synthetic.invalid/",
        derive_names("https://synthetic.invalid/"),
        10,
    )
    waiting = queued(service, "synthetic-two")
    with service.store.connect() as db:
        db.execute("UPDATE jobs SET created=? WHERE id=?", (time.time() - 700, waiting["id"]))
        db.execute("UPDATE builds SET created=? WHERE id=?", (time.time() - 1000, build["id"]))
    service.store.expire_queued(600, 900)
    result = service.get_job("owner", waiting["id"])
    assert result["reason_code"] == "queue_timeout" and result["result"]["coverage"] == "not_started"
    assert result["progress"]["events"][-1]["event"] == "queue_timeout"
    assert (
        service.store.get_build("owner", item["id"], build["id"])["result"]["reason_code"] == "queue_timeout"
    )
    assert service.store.claim_job() is None and service.store.claim_build() is None


def test_expired_finalization_never_registers_success(tmp_path):
    service = make_service(tmp_path)
    item = queued(service)
    service.store.claim_job()
    artifact = {
        "job_id": item["id"],
        "owner": "owner",
        "path": "partial.apk",
        "filename": "partial.apk",
        "kind": "apk",
        "sha256": "synthetic",
        "size": 1,
        "origin": "downloaded_original",
    }
    service.store.finish_with_artifacts(
        item["id"],
        "completed",
        {"outcome": "downloaded"},
        [artifact],
        time.monotonic() - 1,
        threading.Event(),
    )
    value = service.get_job("owner", item["id"])
    assert value["outcome"] == "failed" and value["reason_code"] == "task_timeout"
    assert value["artifacts"] == [] and value["progress"]["event"] == "task_timeout"


def test_real_dead_loop_killed_then_next_job_runs(tmp_path, monkeypatch):
    service = make_service(tmp_path, chain_timeout=0.8)
    assert service._isolated_collect
    real_runner = run_limited
    calls = []

    def runner(command, **options):
        calls.append(command)
        if len(calls) == 1:
            script = "while True: pass"
        else:
            path = command[-1]
            script = (
                "from pathlib import Path; import json; Path("
                + repr(path)
                + ").write_text(json.dumps({'outcome':'failed','reason_code':'synthetic_finished','coverage':'partial'}))"
            )
        return real_runner([sys.executable, "-c", script], **options)

    monkeypatch.setattr("fxfetch.service.run_limited", runner)
    first = queued(service)
    started = time.monotonic()
    service._collect(service.store.claim_job(), threading.Event())
    assert time.monotonic() - started < 5
    value = service.get_job("owner", first["id"])
    assert value["reason_code"] == "task_timeout" and not value["artifacts"]
    assert (
        json.loads((service.store.root / "jobs" / first["id"] / "evidence.json").read_text())["summary"][
            "reason_code"
        ]
        == "task_timeout"
    )
    second = queued(service, "synthetic-next")
    service._collect(service.store.claim_job(), threading.Event())
    assert service.get_job("owner", second["id"])["reason_code"] == "synthetic_finished"


def test_real_worker_disabled_build_and_progress(tmp_path):
    service = make_service(tmp_path)
    assert service._isolated_build
    item = queued(service)
    service.store.claim_job()
    service.store.finish_job(item["id"], "completed", {"outcome": "failed"})
    build = service.store.create_build(
        "owner",
        item["id"],
        "synthetic-build",
        "https://synthetic.invalid/",
        derive_names("https://synthetic.invalid/"),
        10,
    )
    service._build(service.store.claim_build(), threading.Event())
    value = service.store.get_build("owner", item["id"], build["id"])
    assert value["state"] == "disabled"
    assert value["progress"]["timeout_seconds"] == 900
    assert value["progress"]["events"][-1]["event"] == "disabled"
    assert not (service.store.root / ".build-private" / "scratch" / ("task-" + build["id"])).exists()


def test_maintenance_expires_waiting_job_without_claim(tmp_path):
    service = make_service(tmp_path, chain_timeout=0.1)
    item = queued(service)
    worker = threading.Thread(target=service._loop, args=("maintenance",))
    worker.start()
    try:
        deadline = time.monotonic() + 3
        while service.get_job("owner", item["id"])["state"] == "queued" and time.monotonic() < deadline:
            time.sleep(0.05)
        assert service.get_job("owner", item["id"])["reason_code"] == "queue_timeout"
    finally:
        service._stop.set()
        worker.join(2)
    assert not worker.is_alive()


def test_real_build_timeout_and_cancel_kill_descendant_tree(tmp_path, monkeypatch):
    service = make_service(tmp_path, build_timeout=0.8)
    item = queued(service)
    service.store.claim_job()
    service.store.finish_job(item["id"], "completed", {"outcome": "failed"})
    marker = tmp_path / "surviving-descendant.txt"
    child_script = (
        "import time; from pathlib import Path; time.sleep(1.4); Path("
        + repr(str(marker))
        + ").write_text('survived')"
    )
    script = (
        "import subprocess, sys; subprocess.Popen([sys.executable, '-c', "
        + repr(child_script)
        + "]);\nwhile True: pass"
    )

    def runner(command, **options):
        return run_limited([sys.executable, "-c", script], **options)

    monkeypatch.setattr("fxfetch.service.run_limited", runner)
    for key, cancelled in (("synthetic-timeout", False), ("synthetic-cancel", True)):
        build = service.store.create_build(
            "owner",
            item["id"],
            key,
            "https://synthetic.invalid/",
            derive_names("https://synthetic.invalid/"),
            10,
        )
        cancel = threading.Event()
        timer = threading.Timer(0.3, cancel.set) if cancelled else None
        if timer:
            timer.start()
        service._build(service.store.claim_build(), cancel)
        if timer:
            timer.join()
        value = service.store.get_build("owner", item["id"], build["id"])
        assert value["state"] == ("cancelled" if cancelled else "failed")
        assert value["result"]["reason_code"] == ("cancelled" if cancelled else "build_timeout")
        assert service.get_job("owner", item["id"])["artifacts"] == []
    time.sleep(1.6)
    assert not marker.exists()


def test_progress_new_unknown_length_event_clears_old_metrics(tmp_path):
    store = Store(tmp_path)
    job, _ = store.create_job("owner", "synthetic-metrics", {"entry_url": "https://synthetic.invalid/"}, 20)
    store.claim_job()
    store.progress(
        job["id"], {"event": "task_started", "started_at": 10, "deadline_at": 610, "timeout_seconds": 600}
    )
    store.progress(
        job["id"],
        {
            "event": "download_progress",
            "url": "https://synthetic.invalid/one.apk",
            "received_bytes": 10,
            "total_bytes": 20,
            "percent": 50,
        },
    )
    store.progress(
        job["id"],
        {"event": "download_progress", "url": "https://synthetic.invalid/two.apk", "received_bytes": 3},
    )
    value = store.get_job("owner", job["id"])["progress"]
    assert value["received_bytes"] == 3
    assert "total_bytes" not in value and "percent" not in value
    assert value["started_at"] == 10 and value["deadline_at"] == 610
    assert value["seq"] == 3 and value["events"][-2]["percent"] == 50
    store.progress(job["id"], {"event": "request", "url": "https://synthetic.invalid/next"})
    assert "received_bytes" not in store.get_job("owner", job["id"])["progress"]


class CompletedSyntheticWorkflow:
    def run(self, url, output_dir, cancel, on_event=None):
        import hashlib

        from fxfetch.core.workflow import Artifact, WorkflowResult

        path = output_dir / "artifacts" / "synthetic.apk"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"synthetic-validated")
        return WorkflowResult(
            "downloaded",
            "package_verified",
            "complete",
            artifacts=[
                Artifact("apk", path, hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_size, url)
            ],
        )


def test_evidence_uses_actual_terminal_after_late_timeout_or_cancel(tmp_path, monkeypatch):
    import fxfetch.service as module

    for kind in ("timeout", "cancel"):
        service = JobService(
            Settings(
                tmp_path / kind,
                "synthetic-unused",
                limits=replace(Limits(), chain_timeout=0.2 if kind == "timeout" else 600),
            ),
            workflow=CompletedSyntheticWorkflow(),
        )
        item = queued(service)
        cancel = threading.Event()
        real_write = module.atomic_json
        calls = []

        def delayed(path, value, real_write=real_write, calls=calls, kind=kind, cancel=cancel):
            real_write(path, value)
            calls.append(value)
            if len(calls) == 1:
                if kind == "timeout":
                    time.sleep(0.25)
                else:
                    cancel.set()

        with monkeypatch.context() as patch:
            patch.setattr(module, "atomic_json", delayed)
            service._collect(service.store.claim_job(), cancel)
        result = service.get_job("owner", item["id"])
        evidence = json.loads((service.store.root / "jobs" / item["id"] / "evidence.json").read_text())
        assert result["reason_code"] == ("task_timeout" if kind == "timeout" else "cancelled")
        assert evidence["summary"] == service.store.get_job("owner", item["id"])["result"]
        assert evidence["worker_summary"]["outcome"] == "downloaded"
        assert evidence["terminal_status"] == "committed" and not result["artifacts"]


def test_final_evidence_write_failure_keeps_committed_success(tmp_path, monkeypatch, caplog):
    import fxfetch.service as module

    service = JobService(Settings(tmp_path, "synthetic-unused"), workflow=CompletedSyntheticWorkflow())
    item = queued(service)
    real_write = module.atomic_json
    calls = []

    def fail_final(path, value):
        calls.append(value)
        if len(calls) == 2:
            raise OSError("synthetic-disk-error")
        real_write(path, value)

    monkeypatch.setattr(module, "atomic_json", fail_final)
    service._collect(service.store.claim_job(), threading.Event())
    result = service.get_job("owner", item["id"])
    assert result["outcome"] == "downloaded" and len(result["artifacts"]) == 1
    evidence = json.loads((service.store.root / "jobs" / item["id"] / "evidence.json").read_text())
    assert evidence["terminal_status"] == "pending_database_commit" and "summary" not in evidence
    assert evidence["authoritative_record"]["job_id"] == item["id"]
    assert "final_evidence_write_failed" in caplog.text


def test_capabilities_report_real_execution_methods(tmp_path):
    production = make_service(tmp_path / "production").capabilities()["task_limits"]
    assert production["execution_limit_method"] == "isolated_process_tree"
    injected = JobService(
        Settings(tmp_path / "injected", "synthetic-unused"), workflow=CompletedSyntheticWorkflow()
    ).capabilities()["task_limits"]
    assert injected["collection_limit_method"] == "injected_test_callable"
    assert injected["build_limit_method"] == "isolated_process_tree"
    assert injected["execution_limit_method"] == "mixed_or_injected"


def test_expired_claim_never_starts_worker(tmp_path, monkeypatch):
    service = make_service(tmp_path)
    item = queued(service)
    with service.store.connect() as db:
        db.execute("UPDATE jobs SET created=? WHERE id=?", (time.time() - 601, item["id"]))

    def forbidden(*args, **kwargs):
        raise AssertionError("expired queue must not launch a subprocess")

    monkeypatch.setattr(service, "_isolated", forbidden)
    service._collect(service.store.claim_job(), threading.Event())
    value = service.get_job("owner", item["id"])
    assert value["reason_code"] == "queue_timeout" and value["result"]["coverage"] == "not_started"
    assert "started_at" not in value["progress"]
    build = service.store.create_build(
        "owner",
        item["id"],
        "synthetic-expired-build",
        "https://synthetic.invalid/",
        derive_names("https://synthetic.invalid/"),
        10,
    )
    with service.store.connect() as db:
        db.execute("UPDATE builds SET created=? WHERE id=?", (time.time() - 901, build["id"]))
    service._build(service.store.claim_build(), threading.Event())
    result = service.store.get_build("owner", item["id"], build["id"])
    assert result["state"] == "failed" and result["result"]["reason_code"] == "queue_timeout"
    assert "started_at" not in result["progress"]
