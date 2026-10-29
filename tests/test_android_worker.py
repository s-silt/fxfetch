import json
import time
from threading import Event
from types import SimpleNamespace

import pytest

from fxfetch.core.android_worker import (
    IMAGE,
    AndroidLease,
    AndroidWorker,
    AndroidWorkerConfig,
    load_worker_config,
)
from fxfetch.core.browser_capture import BrowserCaptureResult, CapturedPackage
from fxfetch.core.browser_workflow import BrowserWorkflow, apply_gateway_errors, project_capture
from fxfetch.core.errors import FxfetchError
from fxfetch.core.limits import Limits
from fxfetch.core.workflow import WorkflowResult


@pytest.fixture
def config(tmp_path):
    key, hosts = tmp_path / "key", tmp_path / "known_hosts"
    key.write_text("synthetic test key")
    hosts.write_text("synthetic pinned host")
    return AndroidWorkerConfig(key, hosts, "a" * 64, "b" * 64, "d" * 64, "e" * 64)


def status(config, lease_id):
    return {
        "guard_ready": True,
        "lease_id": lease_id,
        "expires_at": time.time() + 60,
        "data_capacity_bytes": 2 * 1024**3,
        "image_digest": IMAGE,
        "chrome_package": "com.android.chrome",
        "chrome_source_sha256": config.chrome_source_sha256,
        "trichrome_source_sha256": config.trichrome_source_sha256,
        "firewall_sha256": "c" * 64,
        "cdp_endpoint": "http://127.0.0.1:9222",
    }


@pytest.mark.parametrize(
    "key,value",
    [
        ("guard_ready", False),
        ("data_capacity_bytes", 3 * 1024**3),
        ("image_digest", "latest"),
        ("chrome_package", "org.example.browser"),
        ("chrome_source_sha256", "d" * 64),
        ("firewall_sha256", "yes"),
        ("cdp_endpoint", "http://192.168.1.1:9222"),
        ("expires_at", 1),
        ("lease_id", "e" * 32),
    ],
)
def test_reject_changed_live_environment(config, key, value):
    metadata = status(config, "f" * 32)
    metadata[key] = value
    with pytest.raises(FxfetchError, match=".*"):
        AndroidWorker(config).validate(metadata, "f" * 32)


def test_fixed_ssh_command_and_json_stdin(config, monkeypatch):
    import fxfetch.core.android_worker as module

    observed = []
    monkeypatch.setattr(module.shutil, "which", lambda name: "ssh.exe")

    def run(args, **kwargs):
        observed.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps(status(config, "f" * 32)))

    monkeypatch.setattr(module.subprocess, "run", run)
    worker = AndroidWorker(config)
    worker.validate(worker.call("begin", "f" * 32, 120), "f" * 32)
    args, kwargs = observed[0]
    assert "StrictHostKeyChecking=yes" in args
    assert "worker@127.0.0.1" in args
    assert json.loads(kwargs["input"]) == {"lease_id": "f" * 32, "timeout_seconds": 120}
    assert args[-1].endswith("/opt/fxfetch/guest_session.py begin")
    with pytest.raises(ValueError):
        worker.call("begin; arbitrary", "f" * 32, 120)
    assert len(observed) == 1


def test_explicit_idle_recovery_is_fixed_and_bounded(config, monkeypatch):
    import fxfetch.core.android_worker as module

    observed = []
    monkeypatch.setattr(module.shutil, "which", lambda name: "ssh.exe")

    def run(args, **kwargs):
        observed.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout='{"state":"idle"}')

    monkeypatch.setattr(module.subprocess, "run", run)
    worker = AndroidWorker(config)
    assert worker.call("recover-idle", module.PROBE_ID)["state"] == "idle"
    args, kwargs = observed[0]
    assert args[-1].endswith("/opt/fxfetch/guest_session.py recover-idle")
    assert kwargs["timeout"] == 60
    assert json.loads(kwargs["input"]) == {"lease_id": module.PROBE_ID}
    with pytest.raises(ValueError, match="recovery_requires_probe_id"):
        worker.call("recover-idle", "a" * 32)
    with pytest.raises(ValueError):
        worker.call("recover-idle; arbitrary", module.PROBE_ID)
    assert len(observed) == 1


@pytest.mark.parametrize("action,timeout", [("end", 30), ("status", 45)])
def test_control_has_bounded_budget_for_measured_android_io(config, monkeypatch, action, timeout):
    import fxfetch.core.android_worker as module

    observed = []
    monkeypatch.setattr(module.shutil, "which", lambda name: "ssh.exe")

    def run(args, **kwargs):
        observed.append(kwargs)
        return SimpleNamespace(returncode=0, stdout='{"state":"ended"}')

    monkeypatch.setattr(module.subprocess, "run", run)
    assert AndroidWorker(config).call(action, "a" * 32)["state"] == "ended"
    assert observed[0]["timeout"] == timeout


@pytest.mark.parametrize("duration,expected", [(60, 60), (180, 180), (600, 240)])
def test_begin_budget_never_exceeds_lease_or_preparation_ceiling(config, monkeypatch, duration, expected):
    import fxfetch.core.android_worker as module

    seen = []
    monkeypatch.setattr(module.shutil, "which", lambda name: "ssh.exe")

    def run(args, **kwargs):
        seen.append(kwargs)
        return SimpleNamespace(returncode=0, stdout="{}")

    monkeypatch.setattr(module.subprocess, "run", run)
    AndroidWorker(config).call("begin", "a" * 32, duration)
    assert seen[0]["timeout"] == expected
    assert json.loads(seen[0]["input"])["timeout_seconds"] == duration


@pytest.mark.parametrize("action", ["begin", "status", "end"])
def test_startup_timeout_is_distinct_from_control_disconnect(config, monkeypatch, action):
    import fxfetch.core.android_worker as module

    monkeypatch.setattr(module.shutil, "which", lambda name: "ssh.exe")

    def stalled(args, **kwargs):
        raise module.subprocess.TimeoutExpired(args, kwargs["timeout"], stderr=b"private diagnostic")

    monkeypatch.setattr(module.subprocess, "run", stalled)
    with pytest.raises(FxfetchError) as caught:
        AndroidWorker(config).call(action, "a" * 32, 600 if action == "begin" else None)
    expected = "browser_worker_start_timeout" if action == "begin" else "browser_worker_unavailable"
    assert caught.value.code == expected
    assert "private diagnostic" not in str(caught.value)


@pytest.mark.parametrize("failure", ["guard", "cancel", "tunnel"])
def test_failed_live_recheck_never_arms_gateway(config, failure):
    from fxfetch.core.browser_gateway import BrowserGateway

    cancel = Event()
    gate = BrowserGateway(port=0, cancel=cancel)
    # In-memory active listener stub; no socket is opened by this regression.
    gate._server = SimpleNamespace(shutdown=lambda: None, server_close=lambda: None)
    gate._thread = SimpleNamespace(is_alive=lambda: True, join=lambda timeout: None)
    gate.deadline = time.monotonic() + 60
    tunnel = SimpleNamespace(poll=lambda: None)

    class Worker(AndroidWorker):
        def call(self, action, lease_id, timeout_seconds=None):
            value = status(config, lease_id)
            if failure == "guard":
                value["guard_ready"] = False
            elif failure == "cancel":
                cancel.set()
            else:
                tunnel.poll = lambda: 1
            return value

    lease = AndroidLease(Worker(config), gate, cancel, 60)
    lease.started, lease.tunnel = True, tunnel
    with pytest.raises(FxfetchError):
        lease.verify_before_launch()
    assert not gate.armed and not gate.active


def test_readiness_never_grants_a_browser_lease(config):
    metadata = status(config, "f" * 32)
    metadata.update(state="idle", guard_ready=False, deployment_ready=True)
    worker = AndroidWorker(config)
    with pytest.raises(FxfetchError):
        worker.validate(metadata, readiness=True)
    metadata["deployment_verified"] = True
    worker.validate(metadata, readiness=True)
    with pytest.raises(FxfetchError):
        worker.validate(metadata, "f" * 32)


def test_config_missing_and_malformed_fail_closed(tmp_path):
    assert load_worker_config(tmp_path) is None
    (tmp_path / "android-worker.json").write_text('{"enabled":true}')
    with pytest.raises(FxfetchError) as caught:
        load_worker_config(tmp_path)
    assert caught.value.code == "browser_worker_configuration"


def test_projection_retains_original_package_and_unknown_coverage(tmp_path):
    package = CapturedPackage("apk", tmp_path / "one.apk", 40, "a" * 64, "https://cdn.test/a.apk")
    capture = BrowserCaptureResult(outcome="downloaded", reason_code="package_verified", artifacts=[package])
    capture.responses = [{"url": "https://entry.test/", "status": 302}]
    capture.partials = [{"complete": False, "path": str(tmp_path / "partial")}]
    projected = project_capture(capture, "https://entry.test/")
    assert projected.artifacts[0].path == package.path
    assert projected.coverage == "partial"
    assert projected.hops[0]["mode"] == "android_chrome"
    assert projected.landing["evidence"][0]["session_replayed"] is False


@pytest.mark.parametrize("target_error", [None, "target_not_public", "browser_connect_failed"])
def test_background_denial_cannot_replace_target_capture_result(target_error):
    result = WorkflowResult("failed", "browser_dynamic_incomplete", "partial")
    errors = [{"reason_code": "browser_request_not_permitted", "host": "background.synthetic.test"}]
    if target_error:
        errors.append({"reason_code": target_error, "url": "https://entry.synthetic.test/"})
    apply_gateway_errors(result, errors)
    assert result.reason_code == (target_error or "browser_dynamic_incomplete")
    assert result.landing["network_guard"] == errors
    assert result.outcome == "failed" and result.coverage == "partial"


def test_direct_package_does_not_start_android(config, tmp_path, monkeypatch):
    import fxfetch.core.browser_workflow as module

    calls = []

    class Static:
        def run(self, url, *args):
            calls.append(url)
            return WorkflowResult("downloaded", "package_verified", "complete")

    monkeypatch.setattr(module, "AndroidWorker", lambda *args: pytest.fail("Must not start Android"))
    workflow = BrowserWorkflow(Static(), config, Limits())
    assert workflow.run("https://cdn.test/file.apk", tmp_path, Event()).outcome == "downloaded"
    assert calls == ["https://cdn.test/file.apk"]


def test_browser_guard_failure_never_replays_entry(config, tmp_path, monkeypatch):
    import fxfetch.core.browser_workflow as module

    class Static:
        def run(self, *args):
            pytest.fail("Must not replay generic entry after failed browser lease")

    class NoGate:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            raise FxfetchError("browser_guard_unavailable", "Synthetic guard denial")

        def __exit__(self, *args):
            pass

    monkeypatch.setattr(module, "BrowserGateway", NoGate)
    result = BrowserWorkflow(Static(), config, Limits()).run("https://entry.test/", tmp_path, Event())
    assert result.outcome == "failed"
    assert result.reason_code == "browser_guard_unavailable"
    assert result.artifacts == []


@pytest.mark.parametrize(
    "outcome,code",
    [
        ("blocked", "challenge_detected"),
        ("failed", "cancelled"),
        ("failed", "task_timeout"),
        ("failed", "chain_timeout"),
        ("failed", "length_mismatch"),
    ],
)
def test_gateway_teardown_noise_does_not_reclassify_precise_results(outcome, code):
    result = WorkflowResult(outcome, code, "partial")
    apply_gateway_errors(result, [{"reason_code": "browser_transport_failed"}])
    assert (result.outcome, result.reason_code) == (outcome, code)
    assert result.landing["network_guard"]


def test_actual_gateway_rejection_resolves_generic_network_failure():
    result = WorkflowResult("failed", "browser_network_error", "partial")
    apply_gateway_errors(result, [{"reason_code": "target_not_public"}, {"reason_code": "cancelled"}])
    assert result.reason_code == "target_not_public"


def test_lease_cuts_data_plane_before_waiting_for_guest_cleanup():
    order = []

    class Gate:
        def close(self):
            order.append("network_closed")

    class Worker:
        def call(self, action, lease_id):
            order.append(action)
            raise FxfetchError("browser_worker_unavailable", "Synthetic disconnected SSH")

    lease = AndroidLease(Worker(), Gate(), Event(), 60)
    lease.started = True
    with pytest.raises(FxfetchError):
        lease.close()
    assert order == ["network_closed", "end"]


def test_cleanup_failure_preserves_captured_challenge(config, tmp_path, monkeypatch):
    import fxfetch.core.browser_workflow as module

    class Gate:
        errors = []

        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class Lease:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            raise FxfetchError("browser_worker_unavailable", "Synthetic cleanup timeout")

    async def capture(*args, **kwargs):
        return BrowserCaptureResult(outcome="blocked", reason_code="challenge_detected")

    monkeypatch.setattr(module, "BrowserGateway", Gate)
    monkeypatch.setattr(module, "AndroidLease", Lease)
    monkeypatch.setattr(module, "capture_browser", capture)
    result = BrowserWorkflow(None, config, Limits()).run("https://entry.test/", tmp_path, Event())
    assert (result.outcome, result.reason_code) == ("blocked", "challenge_detected")
    assert "browser_worker_unavailable" in result.landing["gaps"]
