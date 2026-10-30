from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import threading
import time
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest
from analysis_fixtures import analysis_archive

from fxfetch.analysis_report import build_analysis_report
from fxfetch.analysis_worker import WORKER_REPORT_NAME, WORKER_RESULT_NAME
from fxfetch.cli import _parser, _server_config
from fxfetch.config import Settings
from fxfetch.core.errors import FxfetchError
from fxfetch.core.process_limits import ProcessResult
from fxfetch.service import JobService


def seed_job(
    service: JobService, root: Path, owner: str, suffix: str, *, empty: bool = False
) -> dict:
    archive = analysis_archive(root / f"source-{suffix}", empty=empty)
    job, _ = service.store.create_job(
        owner,
        f"job-{suffix}",
        {"entry_url": f"https://{suffix}.example.test/"},
        20,
    )
    target = service.store.root / "jobs" / job["id"] / "data-package"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(archive.parent, target)
    result = {"outcome": "blocked", "reason_code": "synthetic_blocked", "coverage": "partial"}
    with service.store.connect() as db:
        db.execute(
            "UPDATE jobs SET state='completed',outcome='blocked',reason_code=?,result=? WHERE id=?",
            ("synthetic_blocked", json.dumps(result), job["id"]),
        )
    return service.store.get_job(owner, job["id"])


def completed_runner(command: list[str], **_: object) -> ProcessResult:
    folder = Path(command[-1]).parent
    output = folder / "output"
    report = output / "report" / "input.json"
    report.parent.mkdir(parents=True)
    report.write_text(
        json.dumps(
            {
                "meta": {
                    "online": False,
                    "web_evidence": {"load_errors": [], "file_count": 1},
                }
            }
        ),
        encoding="utf-8",
    )
    digest = hashlib.sha256(report.read_bytes()).hexdigest()
    receipt = {
        "state": "completed",
        "coverage": "partial",
        "source": {"archive_sha256": "a" * 64},
        "gaps": ["synthetic_gap"],
        "analysis": {
            "state": "completed",
            "online": False,
            "executable": sys.executable,
            "command": command,
            "report": {"path": "report/input.json", "sha256": digest},
        },
    }
    (output / "analysis.json").write_text(json.dumps(receipt), encoding="utf-8")
    status = build_analysis_report(output, folder / WORKER_REPORT_NAME)
    (folder / WORKER_RESULT_NAME).write_text(json.dumps(status), encoding="utf-8")
    return ProcessResult(0, limit_method="synthetic")


def wait_analysis(service: JobService, owner: str, job_id: str, identifier: str, state: str) -> dict:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        value = service.analysis.get(owner, job_id, identifier)
        if value["state"] == state:
            return value
        time.sleep(0.01)
    pytest.fail(f"analysis did not become {state}: {value}")


def test_start_idempotency_concurrency_report_boundary_and_tamper(tmp_path, monkeypatch):
    entered = threading.Event()
    release = threading.Event()

    def gated(command, **kwargs):
        entered.set()
        release.wait(5)
        return completed_runner(command, **kwargs)

    monkeypatch.setattr("fxfetch.analysis_service.run_limited", gated)
    service = JobService(Settings(tmp_path, "unused", fxapk_executable=sys.executable))
    owner = "owner-one"
    job = seed_job(service, tmp_path, owner, "blocked")
    assert service.analysis.list(owner, job["id"]) == []
    service.start()
    try:
        first = service.analysis.create(owner, job["id"], "analysis-one")
        assert entered.wait(2)
        assert first["state"] == "queued"
        assert service.analysis.create(owner, job["id"], "analysis-one")["id"] == first["id"]
        with pytest.raises(FxfetchError, match="already active") as active:
            service.analysis.create(owner, job["id"], "analysis-two")
        assert active.value.code == "analysis_active"
        release.set()
        completed = wait_analysis(service, owner, job["id"], first["id"], "completed")
        assert completed["report_ready"] is True
        assert service.store.get_job(owner, job["id"])["outcome"] == "blocked"
        source_before, _ = service.data_package_file(owner, job["id"])
        source_digest = hashlib.sha256(source_before.read_bytes()).hexdigest()
        path, filename = service.analysis.report_file(owner, job["id"], first["id"])
        assert filename == f"analysis-{first['id']}.zip"
        with zipfile.ZipFile(path) as bundle:
            assert bundle.namelist() == ["analysis.json", "report/input.json"]
            receipt = json.loads(bundle.read("analysis.json"))
            assert "command" not in receipt["analysis"]
            assert "executable" not in receipt["analysis"]
            assert receipt["analysis"]["online"] is False
            assert "source.zip" not in bundle.namelist()
        source_after, _ = service.data_package_file(owner, job["id"])
        assert hashlib.sha256(source_after.read_bytes()).hexdigest() == source_digest
        retry = service.analysis.create(owner, job["id"], "analysis-retry")
        assert retry["id"] != first["id"]
        retry = wait_analysis(service, owner, job["id"], retry["id"], "completed")
        retry_path, _ = service.analysis.report_file(owner, job["id"], retry["id"])
        assert retry_path != path
        retry_path.unlink()
        with pytest.raises(FxfetchError) as missing_report:
            service.analysis.report_file(owner, job["id"], retry["id"])
        assert missing_report.value.code == "not_found"
        path.write_bytes(path.read_bytes() + b"tampered")
        with pytest.raises(FxfetchError) as tampered:
            service.analysis.report_file(owner, job["id"], first["id"])
        assert tampered.value.code == "not_found"
    finally:
        release.set()
        service.close()


def test_missing_capability_pending_source_and_restart_interrupt(tmp_path):
    disabled = JobService(Settings(tmp_path / "disabled", "unused"))
    job = seed_job(disabled, tmp_path / "disabled", "owner", "disabled")
    with pytest.raises(FxfetchError) as missing:
        disabled.analysis.create("other-owner", job["id"], "hidden")
    assert missing.value.code == "not_found"
    with pytest.raises(FxfetchError) as unavailable:
        disabled.analysis.create("owner", job["id"], "one")
    assert unavailable.value.code == "analysis_unavailable"

    root = tmp_path / "restart"
    first = JobService(Settings(root, "unused", fxapk_executable=sys.executable))
    pending, _ = first.store.create_job(
        "owner", "pending", {"entry_url": "https://pending.example.test/"}, 20
    )
    with first.store.connect() as db:
        db.execute("UPDATE jobs SET state='completed' WHERE id=?", (pending["id"],))
    with pytest.raises(FxfetchError) as source:
        first.analysis.create("owner", pending["id"], "pending-analysis")
    assert source.value.code == "analysis_source_unavailable"
    ready = seed_job(first, root, "owner", "restart")
    queued = first.analysis.create("owner", ready["id"], "queued")
    second = JobService(Settings(root, "unused", fxapk_executable=sys.executable))
    second.start()
    try:
        assert second.analysis.get("owner", ready["id"], queued["id"])["state"] == "interrupted"
        assert second.analysis.list("owner", ready["id"])[0]["reason_code"] == "service_restarted"
    finally:
        second.close()


def test_fxapk_server_configuration_is_validated(tmp_path):
    options = _parser("serve").parse_args(["--fxapk", "trusted-fxapk"])
    assert _server_config(tmp_path, options)["fxapk_executable"] == "trusted-fxapk"
    (tmp_path / "server.json").write_text(
        json.dumps({"fxapk_executable": "configured-fxapk"}), encoding="utf-8"
    )
    assert _server_config(tmp_path)["fxapk_executable"] == "configured-fxapk"
    with pytest.raises(ValueError, match="invalid_server_configuration"):
        _server_config(tmp_path, _parser("serve").parse_args(["--fxapk", ""]))
    with pytest.raises(ValueError, match="invalid_fxapk_executable"):
        Settings(tmp_path, "unused", fxapk_executable="bad\0path")


def test_source_descriptor_is_cheap_and_claim_expires_in_transaction(
    tmp_path, monkeypatch
):
    service = JobService(
        Settings(tmp_path, "unused", fxapk_executable=sys.executable)
    )
    job = seed_job(service, tmp_path, "owner", "descriptor")

    def forbidden(*args, **kwargs):
        raise AssertionError("full archive verification reached create")

    monkeypatch.setattr("fxfetch.service.package_file", forbidden)
    queued = service.analysis.create("owner", job["id"], "descriptor")
    private = service.analysis.store.get_private(
        "owner", job["id"], queued["id"]
    )
    assert private["source_path"].endswith(".zip")
    assert private["source_size"] > 0
    assert len(private["source_sha256"]) == 64
    with service.store.connect() as db:
        db.execute(
            "UPDATE analyses SET queue_deadline=? WHERE id=?",
            (time.time() - 1, queued["id"]),
        )
    assert service.analysis.store.claim(60) is None
    expired = service.analysis.get("owner", job["id"], queued["id"])
    assert expired["state"] == "failed"
    assert expired["reason_code"] == "queue_timeout"


def test_corrupt_source_is_rejected_asynchronously(tmp_path):
    service = JobService(
        Settings(tmp_path, "unused", fxapk_executable=sys.executable)
    )
    job = seed_job(service, tmp_path, "owner", "corrupt")
    descriptor = service.analysis_source_descriptor("owner", job["id"])
    source = service.store.root / descriptor["path"]
    source.write_bytes(b"x" * descriptor["size"])
    service.start()
    try:
        queued = service.analysis.create("owner", job["id"], "corrupt")
        value = wait_analysis(service, "owner", job["id"], queued["id"], "failed")
        assert not value["report_ready"]
    finally:
        service.close()


def test_queued_and_running_cancel_late_result_and_owner_isolation(tmp_path, monkeypatch):
    entered = threading.Event()
    release = threading.Event()

    def delayed(command, *, cancel, **kwargs):
        entered.set()
        release.wait(5)
        return completed_runner(command)

    monkeypatch.setattr("fxfetch.analysis_service.run_limited", delayed)
    service = JobService(Settings(tmp_path, "unused", fxapk_executable=sys.executable))
    first_job = seed_job(service, tmp_path, "owner-one", "running")
    second_job = seed_job(service, tmp_path, "owner-two", "queued")
    service.start()
    try:
        running = service.analysis.create("owner-one", first_job["id"], "running")
        queued = service.analysis.create("owner-two", second_job["id"], "queued")
        assert entered.wait(2)
        with pytest.raises(FxfetchError):
            service.analysis.get("owner-two", first_job["id"], running["id"])
        assert service.analysis.cancel("owner-two", second_job["id"], queued["id"])["state"] == "cancelled"
        assert service.analysis.cancel("owner-one", first_job["id"], running["id"])["state"] == "cancelled"
        assert not service.analysis.store.finish(
            running["id"],
            "completed",
            None,
            report_path="analyses/late/report.zip",
            report_size=1,
            report_sha256="a" * 64,
        )
        release.set()
        time.sleep(0.1)
        value = service.analysis.get("owner-one", first_job["id"], running["id"])
        assert value["state"] == "cancelled" and not value["report_ready"]
        with pytest.raises(FxfetchError):
            service.analysis.report_file("owner-one", first_job["id"], running["id"])
    finally:
        release.set()
        service.close()


def test_timeout_is_terminal_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "fxfetch.analysis_service.run_limited",
        lambda *args, **kwargs: ProcessResult(None, timed_out=True, reason_code="timed_out"),
    )
    service = JobService(Settings(tmp_path, "unused", fxapk_executable=sys.executable))
    job = seed_job(service, tmp_path, "owner", "timeout")
    service.start()
    try:
        analysis = service.analysis.create("owner", job["id"], "timeout")
        value = wait_analysis(service, "owner", job["id"], analysis["id"], "failed")
        assert value["reason_code"] == "analysis_timeout"
    finally:
        service.close()


def test_monotonic_deadline_blocks_late_publication(tmp_path, monkeypatch):
    def slow_success(command, **kwargs):
        time.sleep(0.1)
        return completed_runner(command)

    monkeypatch.setattr("fxfetch.analysis_service.run_limited", slow_success)
    limits = replace(Settings(tmp_path, "unused").limits, analysis_timeout=0.05)
    service = JobService(
        Settings(
            tmp_path,
            "unused",
            limits=limits,
            fxapk_executable=sys.executable,
        )
    )
    job = seed_job(service, tmp_path, "owner", "late-publication")
    service.start()
    try:
        analysis = service.analysis.create("owner", job["id"], "late")
        value = wait_analysis(service, "owner", job["id"], analysis["id"], "failed")
        assert value["reason_code"] == "analysis_timeout"
        folder = service.store.root / "analyses" / analysis["id"]
        assert not (folder / "analysis-report.zip").exists()
    finally:
        service.close()


def test_no_material_result_remains_not_analyzed(tmp_path, monkeypatch):
    def no_material(command, **kwargs):
        folder = Path(command[-1]).parent
        status = {
            "state": "not_analyzed",
            "reason_code": "no_analyzable_web_material",
        }
        (folder / WORKER_RESULT_NAME).write_text(json.dumps(status), encoding="utf-8")
        return ProcessResult(0, limit_method="synthetic")

    monkeypatch.setattr("fxfetch.analysis_service.run_limited", no_material)
    service = JobService(Settings(tmp_path, "unused", fxapk_executable=sys.executable))
    job = seed_job(service, tmp_path, "owner", "empty", empty=True)
    service.start()
    try:
        analysis = service.analysis.create("owner", job["id"], "no-material")
        value = wait_analysis(service, "owner", job["id"], analysis["id"], "not_analyzed")
        assert value["reason_code"] == "no_analyzable_web_material"
        assert not value["report_ready"]
    finally:
        service.close()


def test_queue_expiry_runs_while_serial_analysis_is_busy(tmp_path, monkeypatch):
    entered = threading.Event()
    release = threading.Event()

    def delayed(command, **kwargs):
        entered.set()
        release.wait(5)
        return completed_runner(command)

    monkeypatch.setattr("fxfetch.analysis_service.run_limited", delayed)
    limits = replace(Settings(tmp_path, "unused").limits, analysis_queue_timeout=0.2)
    service = JobService(Settings(tmp_path, "unused", limits=limits, fxapk_executable=sys.executable))
    first_job = seed_job(service, tmp_path, "owner", "serial-one")
    second_job = seed_job(service, tmp_path, "owner", "serial-two")
    service.start()
    try:
        first = service.analysis.create("owner", first_job["id"], "first")
        assert entered.wait(2)
        queued = service.analysis.create("owner", second_job["id"], "second")
        value = wait_analysis(service, "owner", second_job["id"], queued["id"], "failed")
        assert value["reason_code"] == "queue_timeout"
        release.set()
        wait_analysis(service, "owner", first_job["id"], first["id"], "completed")
    finally:
        release.set()
        service.close()


def test_clear_cancels_owner_analysis_before_archiving_parent(tmp_path, monkeypatch):
    entered = threading.Event()
    release = threading.Event()

    def delayed(command, *, cancel, **kwargs):
        entered.set()
        release.wait(5)
        completed_runner(command)
        return ProcessResult(0, cancelled=cancel.is_set(), limit_method="synthetic")

    monkeypatch.setattr("fxfetch.analysis_service.run_limited", delayed)
    service = JobService(Settings(tmp_path, "unused", fxapk_executable=sys.executable))
    job = seed_job(service, tmp_path, "owner", "clear-running")
    service.start()
    try:
        analysis = service.analysis.create("owner", job["id"], "clear")
        assert entered.wait(2)
        assert service.clear_jobs("owner")["cleared"] == 1
        with service.store.connect() as db:
            row = db.execute("SELECT state FROM analyses WHERE id=?", (analysis["id"],)).fetchone()
            parent = db.execute("SELECT archived FROM jobs WHERE id=?", (job["id"],)).fetchone()
        assert row["state"] == "cancelled" and parent["archived"] == 1
        release.set()
        with pytest.raises(FxfetchError):
            service.analysis.report_file("owner", job["id"], analysis["id"])
    finally:
        release.set()
        service.close()


@pytest.mark.skipif(not os.environ.get("FXAPK_EXECUTABLE"), reason="FXAPK_EXECUTABLE not configured")
def test_real_service_fxapk_subprocess_is_offline(tmp_path, monkeypatch):
    guard = tmp_path / "network-guard"
    guard.mkdir()
    ready = tmp_path / "network-guard-loaded"
    tripwire = tmp_path / "network-attempted"
    (guard / "sitecustomize.py").write_text(
        "import os, sys\n"
        "open(os.environ['FXAPK_NETWORK_GUARD_READY'], 'w').write('ready')\n"
        "def guard(event, args):\n"
        "    if event in {'socket.connect','socket.getaddrinfo','socket.gethostbyname','socket.gethostbyaddr','socket.sendto'}:\n"
        "        open(os.environ['FXAPK_NETWORK_TRIPWIRE'], 'a').write(event+'\\n')\n"
        "        raise RuntimeError('offline service analysis network forbidden')\n"
        "sys.addaudithook(guard)\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PYTHONPATH", str(guard) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    monkeypatch.setenv("FXAPK_NETWORK_GUARD_READY", str(ready))
    monkeypatch.setenv("FXAPK_NETWORK_TRIPWIRE", str(tripwire))
    service = JobService(
        Settings(tmp_path / "service", "unused", fxapk_executable=os.environ["FXAPK_EXECUTABLE"])
    )
    job = seed_job(service, tmp_path / "service", "owner", "real")
    service.start()
    try:
        analysis = service.analysis.create("owner", job["id"], "real")
        value = wait_analysis(service, "owner", job["id"], analysis["id"], "completed")
        assert value["report_ready"]
        report_zip, _ = service.analysis.report_file("owner", job["id"], analysis["id"])
        with zipfile.ZipFile(report_zip) as published:
            assert published.namelist() == ["analysis.json", "report/input.json"]
            receipt = json.loads(published.read("analysis.json"))
            assert "command" not in receipt["analysis"] and "executable" not in receipt["analysis"]
            native = json.loads(published.read("report/input.json"))
            assert native["meta"]["online"] is False
        output = (
            service.store.root
            / service.analysis.store.get_private("owner", job["id"], analysis["id"])["output_path"]
            / "output"
        )
        assert (output / "source.zip").is_file()
        assert not (output / "input" / "source.zip").exists()
        assert ready.read_text() == "ready"
        assert not tripwire.exists()
    finally:
        service.close()
