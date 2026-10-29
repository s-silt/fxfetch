"""Parent-owned Android leases survive hard worker cancellation as identities."""

from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import asdict
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

from fxfetch.config import Settings
from fxfetch.core.android_worker import AndroidLease, AndroidWorkerConfig
from fxfetch.core.errors import FxfetchError
from fxfetch.core.limits import Limits
from fxfetch.core.network import AcquisitionPolicy
from fxfetch.core.process_limits import ProcessResult
from fxfetch.core.workflow import WorkflowResult
from fxfetch.service import JobService


@pytest.fixture
def configured(tmp_path, monkeypatch):
    import fxfetch.core.android_worker as module

    key, hosts = tmp_path / "key", tmp_path / "hosts"
    key.write_text("synthetic key")
    hosts.write_text("synthetic hosts")
    config = AndroidWorkerConfig(key, hosts, "a" * 64, "b" * 64, "c" * 64, "d" * 64)
    monkeypatch.setattr(module, "load_worker_config", lambda root: config)
    return JobService(Settings(tmp_path / "service", "synthetic-password-hash")), config


def request(service, url="https://entry.test/"):
    return {
        "operation": "collect", "root": str(service.store.root), "identifier": "synthetic-job",
        "url": url, "output_dir": str(service.store.root / "output"), "limits": asdict(Limits()),
        # Even a caller-provided field in this private dictionary is discarded.
        "android_lease_id": "f" * 32,
    }


@pytest.mark.parametrize("failure", ["cancelled", "task_timeout", "worker_failed", "worker_result_invalid"])
def test_hard_stop_releases_only_its_lease_then_next_task_can_run(configured, monkeypatch, failure):
    service, _ = configured
    active = None
    worker_stopped = False
    starts, ends = [], []
    cancel = Event()

    class Worker:
        def __init__(self, config):
            pass

        def call(self, action, lease_id):
            nonlocal active
            assert worker_stopped and action == "end"
            assert active == lease_id
            ends.append(lease_id)
            active = None
            return {"state": "ended", "lease_id": lease_id}

    def runner(command, **kwargs):
        nonlocal active, worker_stopped
        saved = json.loads(Path(command[-2]).read_text())
        lease_id = saved["android_lease_id"]
        assert re.fullmatch(r"[a-f0-9]{32}", lease_id) and lease_id != "f" * 32
        assert active is None, "Previous remote lease would reject this begin"
        active = lease_id
        starts.append(lease_id)
        worker_stopped = True  # run_limited returns only after local teardown.
        if len(starts) == 1:
            if failure == "cancelled":
                cancel.set()
                return ProcessResult(1, cancelled=True)
            if failure == "task_timeout":
                return ProcessResult(1, timed_out=True)
            if failure == "worker_failed":
                return ProcessResult(1)
            Path(command[-1]).write_text("not json")
            return ProcessResult(0)
        # A successful child closes its own lease and returns its result.
        active = None
        Path(command[-1]).write_text(json.dumps({"outcome": "downloaded", "artifacts": [{"sha256": "e" * 64}]}))
        return ProcessResult(0)

    monkeypatch.setattr("fxfetch.core.android_worker.AndroidWorker", Worker)
    monkeypatch.setattr("fxfetch.service.run_limited", runner)
    first = service._isolated(request(service), service.store.root / "first", time.monotonic() + 60, cancel)
    assert first["reason_code"] == failure
    assert active is None and ends == starts
    cancel.clear()
    second = service._isolated(request(service), service.store.root / "second", time.monotonic() + 60, cancel)
    assert second == {"outcome": "downloaded", "artifacts": [{"sha256": "e" * 64}]}
    assert len(set(starts)) == 2
    assert ends == starts[:1]  # No extra cleanup after normal child teardown.


def test_cleanup_error_does_not_replace_cancellation(configured, monkeypatch, caplog):
    service, _ = configured

    class Worker:
        def __init__(self, config):
            pass

        def call(self, action, lease_id):
            raise FxfetchError("browser_worker_unavailable", "synthetic private control failure")

    monkeypatch.setattr("fxfetch.core.android_worker.AndroidWorker", Worker)
    monkeypatch.setattr("fxfetch.service.run_limited", lambda *args, **kwargs: ProcessResult(1, cancelled=True))
    result = service._isolated(request(service), service.store.root / "failure", time.monotonic() + 60, Event())
    assert result["reason_code"] == "cancelled"
    assert "android_cleanup_failed reason_code=browser_worker_unavailable" in caplog.text
    assert "synthetic private control failure" not in caplog.text


@pytest.mark.parametrize("url", ["https://entry.test/app.apk", "https://entry.test/app.ipa", "https://entry.test/install.plist"])
def test_package_routes_do_not_allocate_or_end_android_leases(configured, monkeypatch, url):
    service, _ = configured

    def runner(command, **kwargs):
        assert "android_lease_id" not in json.loads(Path(command[-2]).read_text())
        return ProcessResult(1, cancelled=True)

    monkeypatch.setattr("fxfetch.core.android_worker.AndroidWorker", lambda *args: pytest.fail("No Android lease"))
    monkeypatch.setattr("fxfetch.service.run_limited", runner)
    assert service._isolated(request(service, url), service.store.root / "direct", time.monotonic() + 60, Event())["reason_code"] == "cancelled"


def test_private_worker_hands_parent_identity_to_acquisition(configured, monkeypatch):
    import fxfetch.task_worker as module

    service, _ = configured
    payload = request(service)
    payload["android_lease_id"] = "e" * 32
    source, output = service.store.root / "request.json", service.store.root / "result.json"
    source.write_text(json.dumps(payload))
    observed = []

    class Policy:
        def __init__(self, *args, **kwargs):
            observed.append(kwargs["android_lease_id"])

        def run(self, *args):
            return WorkflowResult("failed", "synthetic_finished", "partial")

    monkeypatch.setattr(module, "AcquisitionPolicy", Policy)
    monkeypatch.setattr(sys, "argv", ["task_worker", str(source), str(output)])
    assert module.main() == 0
    assert observed == ["e" * 32]


def test_policy_and_browser_workflow_pass_identity_to_actual_lease(configured, monkeypatch):
    import fxfetch.core.browser_workflow as module

    service, config = configured
    lease_id = "e" * 32
    policy = AcquisitionPolicy(browser_root=service.store.root, android_lease_id=lease_id)
    workflow = policy._collector(Limits(), None)
    # Production now resolves via HTTP first. Keep this lease-identity test
    # entirely synthetic and explicitly model a page requiring JavaScript.
    monkeypatch.setattr(workflow.static, "run", lambda *args: module.WorkflowResult(
        "failed", "browser_required", "partial"))
    observed = []

    class Gate:
        active, port = True, 18767

        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class Lease(AndroidLease):
        def __enter__(self):
            observed.append(self.lease_id)
            raise FxfetchError("browser_guard_unavailable", "synthetic stop before any control command")

    monkeypatch.setattr(module, "BrowserGateway", Gate)
    monkeypatch.setattr(module, "AndroidLease", Lease)
    assert workflow.run("https://entry.test/", service.store.root / "output", Event()).reason_code == "browser_guard_unavailable"
    assert observed == [lease_id]
    with pytest.raises(ValueError, match="invalid_worker_lease_id"):
        AndroidLease(SimpleNamespace(config=config), Gate(), Event(), 60, lease_id="0" * 32)
