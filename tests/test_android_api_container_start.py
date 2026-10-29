"""Local startup contract; no SSH, VM, Docker daemon or target networking."""

import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from fxfetch.core.errors import FxfetchError

ROOT = Path(__file__).resolve().parents[1]


def load_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


load_file("container_entrypoint", ROOT / "deploy/docker/entrypoint.py")
entry = load_file("android_api_entrypoint", ROOT / "deploy/android-docker/api_entrypoint.py")


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    source, root = tmp_path / "source", tmp_path / "state"
    source.mkdir()
    root.mkdir()
    (source / "selected-key").write_bytes(b"synthetic-private-key")
    (source / "selected-hosts").write_bytes(b"synthetic-pinned-host-key")
    if os.name == "posix":
        (source / "selected-key").chmod(0o777)  # Emulate Windows bind-mount permissions.
        (source / "selected-hosts").chmod(0o777)
    document = {field: "a" * 64 for field in entry.DIGEST_FIELDS}
    document.update(key_path=str(source / "selected-key"), known_hosts_path=str(source / "selected-hosts"))
    (source / "android-worker.json").write_text(json.dumps(document), encoding="utf-8")
    calls = []

    class Worker:
        def __init__(self, config):
            calls.append(("config", config))

        def call(self, action, lease):
            calls.append((action, lease))
            assert (root / "android-worker.json").is_file()
            return {"state": "idle", "deployment_verified": True}

        def validate(self, status, *, readiness):
            calls.append(("validate", readiness))

    monkeypatch.setattr(entry, "AndroidWorker", Worker)
    return source, root, document, calls, Worker


def test_copy_selected_ssh_files_to_private_volume_then_recover_once(prepared):
    source, root, document, calls, _ = prepared
    assert entry.prepare_worker(root, source) == {"state": "ready", "reason_code": None}
    stored = json.loads((root / "android-worker.json").read_text(encoding="utf-8"))
    assert stored["key_path"] == str(root / "android-control/identity")
    assert stored["known_hosts_path"] == str(root / "android-control/known_hosts")
    assert Path(stored["key_path"]).read_bytes() == b"synthetic-private-key"
    assert Path(stored["known_hosts_path"]).read_bytes() == b"synthetic-pinned-host-key"
    assert all(stored[field] == document[field] for field in entry.DIGEST_FIELDS)
    assert calls[1:] == [("recover-idle", "0" * 32), ("validate", True)]
    assert not list(root.rglob("*.new"))
    if os.name == "posix":
        assert stat.S_IMODE((root / "android-control").stat().st_mode) == 0o700
        assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in (
            root / "android-control/identity", root / "android-control/known_hosts", root / "android-worker.json",
        ))


def test_failed_recovery_keeps_browser_routing_and_does_not_retry(prepared, monkeypatch):
    from fxfetch.core.browser_workflow import BrowserWorkflow
    from fxfetch.core.limits import Limits
    from fxfetch.core.network import AcquisitionPolicy

    source, root, _, calls, worker = prepared

    def fail(self, action, lease):
        calls.append((action, lease))
        raise FxfetchError("browser_worker_unavailable", "private diagnostic must not escape")

    monkeypatch.setattr(worker, "call", fail)
    result = entry.prepare_worker(root, source)
    assert result == {"state": "unavailable", "reason_code": "browser_worker_unavailable"}
    assert calls[1:] == [("recover-idle", "0" * 32)]
    assert isinstance(AcquisitionPolicy(browser_root=root)._collector(Limits(), None), BrowserWorkflow)


def test_live_but_not_idle_result_is_not_startup_readiness(prepared, monkeypatch):
    source, root, _, _, worker = prepared
    monkeypatch.setattr(worker, "call", lambda *_: {"state": "running", "guard_ready": True})
    assert entry.prepare_worker(root, source)["state"] == "unavailable"
    assert (root / "android-worker.json").is_file()


@pytest.mark.parametrize("change", ["extra_field", "outside_key", "relative_key", "bad_digest", "oversized_key"])
def test_rejects_ambiguous_or_unbounded_configuration_before_ssh(prepared, change):
    source, root, document, calls, _ = prepared
    if change == "extra_field":
        document["enabled"] = True
    elif change == "outside_key":
        outside = source.parent / "outside-key"
        outside.write_bytes(b"synthetic-outside")
        document["key_path"] = str(outside)
    elif change == "relative_key":
        document["key_path"] = "selected-key"
    elif change == "bad_digest":
        document["helper_sha256"] = "not-a-digest"
    else:
        (source / "selected-key").write_bytes(b"x" * 16385)
    (source / "android-worker.json").write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError):
        entry.prepare_worker(root, source)
    assert not calls and not (root / "android-worker.json").exists()


def test_unavailable_recovery_continues_api_without_logging_secret(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["api_entrypoint.py", "serve"])
    monkeypatch.setattr(entry, "deployment", lambda _: type("Config", (), {"root": tmp_path})())
    monkeypatch.setattr(entry, "prepare_worker", lambda _: {
        "state": "unavailable", "reason_code": "browser_worker_unavailable",
    })
    calls = []
    monkeypatch.setattr(entry, "base_main", lambda args: calls.append(args) or 0)
    assert entry.main() == 0 and calls == [["serve"]]
    assert json.loads(capsys.readouterr().out) == {
        "event": "android_worker_startup", "state": "unavailable", "reason_code": "browser_worker_unavailable",
    }
