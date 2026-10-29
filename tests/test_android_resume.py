"""The restart helper may operate only on the recorded dedicated VM."""

import importlib.util
import json
from pathlib import Path

import pytest


@pytest.fixture
def helper():
    path = Path(__file__).parents[1] / "scripts/android-worker/resume_worker.py"
    spec = importlib.util.spec_from_file_location("resume_worker_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record(state, helper, *, config=None, identifier="8248efd7-1384-4ac0-8a43-31daa58e7264"):
    target = config or state / helper.NAME / (helper.NAME + ".vbox")
    text = f'name="{helper.NAME}"\nUUID="{identifier}"\nCfgFile="{target}"\nVMState="running"'
    (state / "vm-prepared.json").write_text(
        json.dumps({"vm_name": helper.NAME, "vm_uuid": text}), encoding="utf-8"
    )
    return text


@pytest.mark.parametrize("changed", ["uuid", "name", "path", "state"])
def test_reject_changed_registered_vm(helper, tmp_path, changed):
    text = record(tmp_path, helper)
    expected = helper.expected_identity(tmp_path)
    replacements = {
        "uuid": (expected[0], "9248efd7-1384-4ac0-8a43-31daa58e7264"),
        "name": (f'name="{helper.NAME}"', 'name="unrelated"'),
        "path": (str(expected[1]), str(tmp_path / "unrelated.vbox")),
        "state": ('VMState="running"', 'VMState="restoring"'),
    }
    with pytest.raises(ValueError):
        helper.verify_live_identity(expected, text.replace(*replacements[changed]))


def test_reject_record_outside_project(helper, tmp_path):
    record(tmp_path, helper, config=tmp_path.parent / "unrelated.vbox")
    with pytest.raises(ValueError, match="outside_project"):
        helper.expected_identity(tmp_path)


def test_unconfigured_service_never_touches_vm(helper, tmp_path, monkeypatch):
    monkeypatch.setattr(helper, "run", lambda *args: pytest.fail("VM control must not run"))
    assert helper.resume(tmp_path)["reason_code"] == "browser_worker_not_configured"


@pytest.mark.parametrize("vm_state", ["running", "poweroff"])
def test_resume_only_expected_vm_and_idle_guards(helper, tmp_path, monkeypatch, vm_state):
    text = record(tmp_path, helper).replace('VMState="running"', f'VMState="{vm_state}"')
    binary = tmp_path / "control.exe"
    binary.touch()
    monkeypatch.setattr(helper, "STATE", tmp_path)
    monkeypatch.setattr(helper, "VBOX", binary)
    monkeypatch.setattr(helper, "load_worker_config", lambda root: object())
    calls = []
    monkeypatch.setattr(helper, "run", lambda args, timeout: calls.append(args) or text)

    class Worker:
        def __init__(self, config):
            pass

        def _ssh(self):
            return ["ssh-test-only"]

        def call(self, action, lease):
            assert (action, lease) == ("recover-idle", helper.PROBE_ID)
            return {"chrome_version": "test"}

        def validate(self, value, *, readiness):
            assert readiness is True

    monkeypatch.setattr(helper, "AndroidWorker", Worker)
    result = helper.resume(tmp_path)
    assert result["enabled"] and result["navigation_started"] is False
    starts = [args for args in calls if "startvm" in args]
    assert len(starts) == (vm_state == "poweroff")
    if starts:
        assert starts[0][2:] == [result["vm_uuid"], "--type", "headless"]
