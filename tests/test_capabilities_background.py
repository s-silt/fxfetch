"""Readiness is observational, single-flight, and never blocks record cleanup."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from fxfetch.config import Settings
from fxfetch.core import android_worker
from fxfetch.core.errors import FxfetchError
from fxfetch.core.workflow import WorkflowResult
from fxfetch.security import password_hash
from fxfetch.service import JobService
from fxfetch.web.api import create_app


@pytest.fixture
def readiness(tmp_path, monkeypatch):
    started, release = threading.Event(), threading.Event()
    calls = []
    result = {"enabled": True, "mode": "android_chrome", "version": "synthetic"}

    class Worker:
        def __init__(self, config):
            pass

        def probe(self):
            calls.append("readiness")
            started.set()
            assert release.wait(5), "Test did not release its synthetic probe"
            return dict(result)

    monkeypatch.setattr(android_worker, "load_worker_config", lambda root: object())
    monkeypatch.setattr(android_worker, "AndroidWorker", Worker)
    service = JobService(
        Settings(tmp_path, password_hash("synthetic-only"), allowed_hosts=("testserver",)),
        workflow=SimpleNamespace(run=lambda *args: WorkflowResult("failed", "synthetic", "partial")),
    )
    yield SimpleNamespace(service=service, started=started, release=release, calls=calls, result=result)
    service._stop.set()
    release.set()
    if service._chrome_probe_thread:
        service._chrome_probe_thread.join(2)


def test_slow_probe_returns_checking_immediately_and_is_single_flight(readiness):
    before = time.monotonic()
    first = readiness.service.capabilities()["chrome"]
    assert time.monotonic() - before < 1
    assert first["checking"] is True and first["cached"] is False
    assert readiness.started.wait(1)
    with ThreadPoolExecutor(max_workers=8) as pool:
        replies = list(pool.map(lambda _: readiness.service.capabilities()["chrome"], range(16)))
    assert all(row["checking"] for row in replies)
    assert readiness.calls == ["readiness"]
    readiness.release.set()
    readiness.service._chrome_probe_thread.join(2)
    cached = readiness.service.capabilities()["chrome"]
    assert cached["enabled"] and cached["cached"] and not cached["checking"]
    assert readiness.calls == ["readiness"]


def test_refresh_keeps_explicit_cached_result_while_only_one_new_probe_runs(readiness):
    readiness.release.set()
    readiness.service.capabilities()
    readiness.service._chrome_probe_thread.join(2)
    readiness.release.clear()
    readiness.started.clear()
    readiness.result["enabled"] = False
    readiness.service._chrome_probe_at = time.monotonic() - 31
    value = readiness.service.capabilities()["chrome"]
    assert value["enabled"] is True and value["checking"] is True and value["cached"] is True
    assert readiness.started.wait(1)
    assert readiness.calls == ["readiness", "readiness"]
    readiness.release.set()
    readiness.service._chrome_probe_thread.join(2)
    value = readiness.service.capabilities()["chrome"]
    assert value["enabled"] is False and value["checking"] is False


def test_probe_failure_is_cached_and_does_not_leave_checking_stuck(readiness, monkeypatch):
    def unavailable(root):
        raise FxfetchError("browser_worker_configuration", "synthetic private detail")

    monkeypatch.setattr(android_worker, "load_worker_config", unavailable)
    readiness.service.capabilities()
    readiness.service._chrome_probe_thread.join(2)
    value = readiness.service.capabilities()["chrome"]
    assert value == {"enabled": False, "reason_code": "browser_worker_configuration", "checking": False, "cached": True}
    assert "private" not in str(value)


def test_capabilities_http_and_clear_records_finish_while_probe_is_blocked(readiness):
    service = readiness.service
    with TestClient(create_app(service.settings, service=service), client=("127.0.0.1", 50000)) as client:
        headers = {"Origin": "http://testserver"}
        login = client.post("/api/login", json={"password": "synthetic-only"}, headers=headers)
        headers["X-CSRF-Token"] = login.json()["csrf_token"]
        job = client.post("/api/jobs", json={"url": "https://entry.synthetic.invalid/"}, headers={**headers, "Idempotency-Key": "synthetic-capability-clear"})
        assert job.status_code == 202
        before = time.monotonic()
        response = client.get("/api/capabilities")
        assert time.monotonic() - before < 1
        assert response.status_code == 200 and response.json()["chrome"]["checking"] is True
        assert readiness.started.wait(1) and not readiness.release.is_set()
        assert client.delete("/api/jobs", headers=headers).status_code == 200
        assert client.get("/api/jobs").json()["jobs"] == []
        assert readiness.calls == ["readiness"]
        readiness.release.set()
