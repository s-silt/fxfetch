"""Guest control regressions without SSH, Docker, VM access, or large images.

Load the real guest helper with a synthetic environment. Interleavings are
injected at external command/fsync boundaries; this is not a Linux flock test.
Unexpected commands fail instead of falling through to the host subprocess API.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/android-worker/guest_session.py"
LEASE_A = "a" * 32
LEASE_B = "b" * 32
CONTAINER_A = "1" * 64
CONTAINER_B = "2" * 64


def unexpected(*args, **kwargs):
    pytest.fail(f"Unexpected external operation: {args!r}")


def completed(args, code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args, code, stdout, stderr)


def accepted_baseline(guest):
    if not guest.BASE.exists():
        guest.BASE.write_bytes(b"synthetic accepted baseline")
    data = guest.BASE.read_bytes()
    guest.env.DATA_BYTES = len(data)
    receipt = {"accepted": True, "chrome_version": "145.test", "base_sha256": hashlib.sha256(data).hexdigest()}
    guest.acceptance = lambda: receipt
    return receipt


@pytest.fixture
def guest(tmp_path, monkeypatch):
    environment = ModuleType("guest_environment")
    environment.ROOT = tmp_path
    environment.NAME = "synthetic-android"
    environment.IMAGE = "synthetic-image@sha256:" + "3" * 64
    environment.DATA_BYTES = 2 * 1024**3
    environment.run = unexpected
    environment.firewall = unexpected
    environment.start_offline = unexpected
    environment.wait_for_boot = unexpected
    environment.wait_for_cdp = unexpected
    environment.namespace_firewall = unexpected
    environment.validate_vm = unexpected
    environment.prepare = unexpected
    environment.__file__ = str(tmp_path / "environment.py")
    Path(environment.__file__).write_text("synthetic environment")
    monkeypatch.setitem(sys.modules, "guest_environment", environment)
    # Windows has no fcntl. Deterministic interleavings below do not require a
    # real advisory lock; production's lock_state body still opens/closes files.
    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace(LOCK_EX=2, flock=lambda *_: None))
    spec = importlib.util.spec_from_file_location("fxfetch_guest_control_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.subprocess = SimpleNamespace(run=unexpected, SubprocessError=subprocess.SubprocessError)
    module.os = SimpleNamespace(getpid=os.getpid, fsync=os.fsync)
    module.time = SimpleNamespace(time=lambda: 1000.0, monotonic=lambda: 50.0)
    module.SCRIPT = SCRIPT
    return module


@pytest.mark.parametrize("interleave_at", ["stop", "rm"])
def test_delayed_end_cannot_stop_or_overwrite_a_successor(guest, interleave_at):
    guest.save_state({"lease_id": LEASE_A, "state": "running"})
    commands = []
    guard_calls = []
    successor = {"lease_id": LEASE_B, "state": "running", "container_id": CONTAINER_B}
    replaced = False

    def run(*args, **kwargs):
        assert args[:4] == ("docker", "ps", "-aq", "--no-trunc")
        assert args[-1] == f"label=io.fxfetch.lease={LEASE_A}"
        return CONTAINER_A

    def command(args, **kwargs):
        nonlocal replaced
        commands.append(tuple(args))
        assert args[0] == "docker" and args[-1] == CONTAINER_A
        if args[1] == interleave_at and not replaced:
            # Another end(A) removed A and committed ended; begin(B) then
            # reserved the state and created B before this old command returns.
            guest.save_state(successor)
            replaced = True
        if replaced:
            return completed(args, 1, stderr="No such container: old A")
        return completed(args)

    guest.env.run = run
    guest.env.firewall = lambda **kwargs: guard_calls.append(kwargs)
    guest.subprocess.run = command
    assert guest.end(LEASE_A)["state"] == "ended"
    assert replaced
    assert guest.read_json(guest.STATE) == successor
    assert {args[-1] for args in commands} == {CONTAINER_A}
    assert any(args[1] == "rm" for args in commands)
    assert guard_calls == [{"deny_established": True}]


def test_replayed_end_does_not_close_successor_network_or_state(guest):
    successor = {"lease_id": LEASE_B, "state": "running", "container_id": CONTAINER_B}
    guest.save_state(successor)
    own_staging = guest.env.ROOT / f"session-{LEASE_A}.ext4"
    own_staging.write_bytes(b"interrupted A copy")
    later_staging = guest.env.ROOT / f"session-{LEASE_B}.ext4"
    later_staging.write_bytes(b"B copy")
    active = guest.env.ROOT / "android-data.ext4"
    active.write_bytes(b"B active image")

    def run(*args, **kwargs):
        assert args[:4] == ("docker", "ps", "-aq", "--no-trunc")
        assert args[-1] == f"label=io.fxfetch.lease={LEASE_A}"
        return ""

    guest.env.run = run
    assert guest.end(LEASE_A)["already_ended"] is True
    assert guest.read_json(guest.STATE) == successor
    assert not own_staging.exists()
    assert later_staging.read_bytes() == b"B copy"
    assert active.read_bytes() == b"B active image"
    # Firewall/subprocess remain fail-on-use stubs: a replay cannot touch B.


def test_firewall_close_failure_still_stops_the_exact_container(guest):
    guest.save_state({"lease_id": LEASE_A, "state": "running"})
    commands = []

    def deny(**kwargs):
        raise RuntimeError("synthetic nft failure")

    def command(args, **kwargs):
        commands.append(tuple(args))
        return completed(args)

    guest.env.run = lambda *args, **kwargs: CONTAINER_A
    guest.env.firewall = deny
    guest.subprocess.run = command
    with pytest.raises(RuntimeError, match="firewall close failed"):
        guest.end(LEASE_A)
    assert commands == [
        ("docker", "stop", "--time", "5", CONTAINER_A),
        ("docker", "rm", CONTAINER_A),
    ]
    assert guest.read_json(guest.STATE)["state"] == "ended"


def test_expired_staging_never_replaces_successor_data(guest):
    guest.BASE.write_bytes(b"synthetic accepted baseline")
    active = guest.env.ROOT / "android-data.ext4"
    active.write_bytes(b"previous data")
    later_staging = guest.env.ROOT / f"session-{LEASE_B}.ext4"
    later_staging.write_bytes(b"successor staging")
    accepted_baseline(guest)
    guard_calls = []
    commands = []
    successor = {"lease_id": LEASE_B, "state": "starting"}

    def run(*args, **kwargs):
        commands.append(args)
        if args[:3] == ("docker", "ps", "-aq"):
            return ""
        if args[0] == "systemd-run":
            return ""
        unexpected(*args, **kwargs)

    def supersede_after_copy(fd):
        os.fsync(fd)
        # Expire(A) completed while A copied outside the state lock. B has
        # since committed its own active image. A resumes before installation.
        guest.save_state(successor)
        active.write_bytes(b"successor active data")

    guest.env.run = run
    guest.env.firewall = lambda **kwargs: guard_calls.append(kwargs)
    guest.os.fsync = supersede_after_copy
    with pytest.raises(RuntimeError, match="session_expired_during_preparation"):
        guest.begin(LEASE_A, 60)
    assert active.read_bytes() == b"successor active data"
    assert later_staging.read_bytes() == b"successor staging"
    assert not (guest.env.ROOT / f"session-{LEASE_A}.ext4").exists()
    assert guest.read_json(guest.STATE) == successor
    assert guard_calls == [{"deny_established": True}]  # Only A's offline reservation.
    assert not any(args[0] in {"mount", "umount"} for args in commands)


def test_begin_rejects_an_existing_preparation_without_a_container(guest):
    guest.save_state({"lease_id": LEASE_A, "state": "starting"})
    accepted_baseline(guest)
    with pytest.raises(RuntimeError, match="requires an explicit end"):
        guest.begin(LEASE_B, 60)
    assert guest.read_json(guest.STATE)["lease_id"] == LEASE_A


@pytest.mark.parametrize("same_lease_ending", [False, True])
def test_expired_begin_cannot_control_a_successor_after_adb_wait(guest, same_lease_ending):
    guest.BASE.write_bytes(b"synthetic accepted baseline")
    accepted_baseline(guest)
    successor = (
        {"lease_id": LEASE_A, "state": "ending", "container_id": CONTAINER_A}
        if same_lease_ending
        else {"lease_id": LEASE_B, "state": "starting", "container_id": CONTAINER_B}
    )
    crossed_boundary = False
    successor_mutations = []

    def run(*args, **kwargs):
        nonlocal crossed_boundary
        if args[:3] == ("docker", "ps", "-aq"):
            return ""  # A is absent after the interleaving; do not return B.
        if args[0] in {"systemd-run", "mount", "umount"}:
            return ""
        if args == ("adb", "connect", "127.0.0.1:15600"):
            assert kwargs == {"timeout": 5}
            # This command was in flight when expire(A) removed A. Another
            # begin(B) now owns the fixed Android name and forwarding endpoint.
            guest.save_state(successor)
            crossed_boundary = True
            return "connected"
        if args[0] == "adb":
            if crossed_boundary:
                successor_mutations.append(args)
            return ""
        if args[:2] == ("docker", "exec"):
            if crossed_boundary and args[2] == guest.env.NAME:
                successor_mutations.append(args)
            return ""
        unexpected(*args, **kwargs)

    def namespace(**kwargs):
        assert kwargs["expected_container_id"] == CONTAINER_A
        if crossed_boundary:
            successor_mutations.append(("namespace_firewall",))
        return {"rules": "deny", "network_namespace": "net:[synthetic]"}

    guest.env.run = run
    guest.env.firewall = lambda **kwargs: None
    guest.env.start_offline = lambda **kwargs: CONTAINER_A

    def wait_for_boot(timeout, *, container_id):
        assert container_id == CONTAINER_A
        assert 0 < timeout <= 120

    guest.env.wait_for_boot = wait_for_boot
    guest.env.namespace_firewall = namespace
    with pytest.raises(RuntimeError, match="session_expired_during_preparation"):
        guest.begin(LEASE_A, 60)
    assert crossed_boundary
    if same_lease_ending:
        assert guest.read_json(guest.STATE)["previous_lease_id"] == LEASE_A
        assert guest.read_json(guest.STATE)["state"] == "ended"
    else:
        assert guest.read_json(guest.STATE) == successor
    assert successor_mutations == []


@pytest.mark.parametrize("container_exists,active_state", [(True, None), (False, None), (False, "starting"), (False, "ending")])
def test_idle_readiness_requires_no_residual_container(guest, container_exists, active_state):
    if active_state:
        guest.save_state({"lease_id": LEASE_A, "state": active_state, "expires_at": 1060})
    assets = guest.env.ROOT / "assets"
    assets.mkdir()
    chrome = b"synthetic Chrome"
    library = b"synthetic Trichrome"
    (assets / "Chrome.apk").write_bytes(chrome)
    (assets / "TrichromeLibrary.apk").write_bytes(library)
    guest.BASE.write_bytes(b"synthetic baseline")
    rules = "synthetic deny-all rules"
    receipt = {
        "chrome_sha256": hashlib.sha256(chrome).hexdigest(),
        "trichrome_sha256": hashlib.sha256(library).hexdigest(),
        "base_sha256": hashlib.sha256(guest.BASE.read_bytes()).hexdigest(),
        "deny_firewall_sha256": hashlib.sha256(rules.encode()).hexdigest(),
        "image_id": "synthetic-image-id",
    }
    # Receipt authentication/2 GiB image creation are separate acceptance;
    # actual asset/base hashing and the readiness decision still execute here.
    guest.acceptance = lambda: receipt

    def run(*args, **kwargs):
        if args[0] == "nft":
            return rules
        if args[0] == "findmnt":
            return json.dumps({"filesystems": [{"target": str(guest.env.ROOT / "data"), "source": "/dev/loop-test"}]})
        if args[0] == "blockdev":
            return str(guest.env.DATA_BYTES)
        if args[:3] == ("docker", "image", "inspect"):
            return json.dumps([{"Id": receipt["image_id"]}])
        unexpected(*args, **kwargs)

    def command(args, **kwargs):
        if args == ["systemctl", "is-active", f"fxfetch-session-{LEASE_A}.timer"]:
            assert active_state
            return completed(args, stdout="active")
        assert args == ["docker", "inspect", guest.env.NAME]
        if not container_exists:
            return completed(args, 1, stderr="No such object")
        return completed(args, stdout=json.dumps([{
            "State": {"Running": False}, "Id": CONTAINER_A, "Image": receipt["image_id"],
        }]))

    guest.env.run = run
    guest.subprocess.run = command
    result = guest.inspect_status(guest.ZERO)
    assert result["guard_ready"] is False
    assert result["deployment_ready"] is (not container_exists and not active_state)
    assert result["deployment_verified"] is (not container_exists and not active_state)
    assert result["state"] == ("stopped_unreleased" if container_exists else active_state or "idle")


@pytest.mark.parametrize("expiry", [1060, None])
def test_recover_idle_refuses_live_or_unbounded_lease(guest, expiry):
    state = {"lease_id": LEASE_A, "state": "running", "expires_at": expiry}
    guest.save_state(state)
    with pytest.raises(RuntimeError, match="active or unbounded session"):
        guest.recover_idle()
    assert guest.read_json(guest.STATE) == state


@pytest.mark.parametrize("successor_arrives", [False, True])
def test_recover_idle_ends_only_expired_lease_before_preparing(guest, successor_arrives):
    guest.save_state({"lease_id": LEASE_A, "state": "running", "expires_at": 999})
    successor = {"lease_id": LEASE_B, "state": "starting", "expires_at": 1060}
    order = []

    def run(*args, **kwargs):
        assert args[:3] == ("docker", "ps", "-aq")
        if args[-1] == f"label=io.fxfetch.lease={LEASE_A}":
            return CONTAINER_A
        assert args[-1] == f"name=^/{guest.env.NAME}$"
        return ""

    def command(args, **kwargs):
        assert args[-1] == CONTAINER_A
        order.append(tuple(args))
        if args[1] == "rm" and successor_arrives:
            guest.save_state(successor)
        return completed(args)

    def prepare(**kwargs):
        assert kwargs == {"announce": False, "require_existing_data": True}
        order.append(("prepare",))

    guest.env.run = run
    guest.env.firewall = lambda **kwargs: order.append(("deny", kwargs))
    guest.subprocess.run = command
    guest.env.prepare = prepare
    guest.inspect_status = lambda identifier: {"lease_id": identifier, "deployment_verified": True}
    if successor_arrives:
        with pytest.raises(RuntimeError, match="Session changed during recovery"):
            guest.recover_idle()
        assert guest.read_json(guest.STATE) == successor
        assert ("prepare",) not in order
    else:
        assert guest.recover_idle() == {"lease_id": guest.ZERO, "deployment_verified": True}
        assert order[-1] == ("prepare",)
        assert guest.read_json(guest.STATE)["previous_lease_id"] == LEASE_A
    assert order[:3] == [
        ("deny", {"deny_established": True}),
        ("docker", "stop", "--time", "5", CONTAINER_A),
        ("docker", "rm", CONTAINER_A),
    ]


@pytest.mark.parametrize("residual_container", [False, True])
def test_recover_idle_restores_only_a_clean_idle_environment(guest, residual_container):
    calls = []

    def run(*args, **kwargs):
        assert args == ("docker", "ps", "-aq", "--filter", f"name=^/{guest.env.NAME}$")
        return CONTAINER_B if residual_container else ""

    guest.env.run = run
    guest.env.prepare = lambda **kwargs: calls.append(kwargs)
    guest.inspect_status = lambda identifier: {"lease_id": identifier, "deployment_verified": True}
    if residual_container:
        with pytest.raises(RuntimeError, match="Unreleased Android container"):
            guest.recover_idle()
        assert calls == []
    else:
        assert guest.recover_idle() == {"lease_id": guest.ZERO, "deployment_verified": True}
        assert calls == [{"announce": False, "require_existing_data": True}]
    # start_offline, namespace, firewall and subprocess stay fail-on-use stubs.


def test_expiry_kills_its_container_before_waiting_for_state_cleanup(guest, monkeypatch, capsys):
    order = []
    guest.env.validate_vm = lambda: None

    def run(*args, **kwargs):
        assert args[:4] == ("docker", "ps", "-q", "--no-trunc")
        assert args[-1] == f"label=io.fxfetch.lease={LEASE_A}"
        return CONTAINER_A

    def command(args, **kwargs):
        order.append(tuple(args))
        assert args == ["docker", "kill", CONTAINER_A]
        return completed(args)

    def end(lease_id):
        assert lease_id == LEASE_A
        order.append(("state_cleanup", lease_id))
        return {"state": "ended"}

    guest.env.run = run
    guest.subprocess.run = command
    guest.end = end
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "expire", "--lease-id", LEASE_A])
    guest.main()
    assert order == [("docker", "kill", CONTAINER_A), ("state_cleanup", LEASE_A)]
    assert json.loads(capsys.readouterr().out) == {"state": "ended"}


@pytest.fixture
def cdp(monkeypatch):
    """Load the real CDP wait; all time, commands and HTTP are local stubs."""
    monkeypatch.setitem(sys.modules, "fcntl", SimpleNamespace())
    path = SCRIPT.with_name("guest_environment.py")
    spec = importlib.util.spec_from_file_location("fxfetch_guest_environment_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    clock = SimpleNamespace(now=1000.0)
    calls = []
    documents = {
        "version": {"Browser": "Chrome/145.test"},
        "list": [{"type": "page", "url": "about:blank"}],
    }
    harness = SimpleNamespace(module=module, clock=clock, calls=calls, documents=documents, after_read=None)

    def sleep(seconds):
        assert 0 <= seconds <= 0.5
        calls.append(("sleep", seconds))
        clock.now += seconds

    def run(*args, **kwargs):
        assert args == ("docker", "inspect", "--format", "{{.State.Running}}", CONTAINER_A)
        assert kwargs == {"timeout": 2}
        calls.append(("inspect", CONTAINER_A))
        return "true"

    class Response:
        def __init__(self, endpoint):
            self.endpoint = endpoint

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, limit):
            expected = 16385 if self.endpoint == "version" else 65537
            assert limit == expected
            calls.append(("read", self.endpoint, limit))
            if harness.after_read:
                harness.after_read(self.endpoint)
            return json.dumps(documents[self.endpoint]).encode()

    class Opener:
        def open(self, url, *, timeout):
            assert 0 < timeout <= 2
            assert url in {"http://127.0.0.1:9222/json/version", "http://127.0.0.1:9222/json/list"}
            endpoint = url.rsplit("/", 1)[-1]
            calls.append(("open", endpoint))
            if isinstance(documents[endpoint], Exception):
                raise documents[endpoint]
            return Response(endpoint)

    def build_opener(proxy):
        assert proxy == {}  # Environment proxies must never affect local CDP.
        return Opener()

    module.run = run
    module.subprocess = SimpleNamespace(run=unexpected)
    module.time = SimpleNamespace(monotonic=lambda: clock.now, sleep=sleep)
    module.urllib = SimpleNamespace(request=SimpleNamespace(
        ProxyHandler=lambda proxies: proxies, build_opener=build_opener,
    ))
    return harness


def test_cdp_wait_accepts_only_version_matched_unique_blank_page(cdp):
    checks = []
    result = cdp.module.wait_for_cdp(
        CONTAINER_A, expected_version="145.test", check=lambda: checks.append(True),
    )
    assert result["cdp"] == cdp.documents["version"]
    assert result["targets"] == cdp.documents["list"]
    assert result["ready_seconds"] == 0
    assert len(checks) == 6
    assert [call for call in cdp.calls if call[0] == "open"] == [("open", "version"), ("open", "list")]
    assert not any(call[0] == "sleep" for call in cdp.calls)


@pytest.mark.parametrize("invalid", ["nonblank", "multiple_pages", "wrong_version"])
def test_cdp_wait_rejects_unaccepted_browser_or_target_until_deadline(cdp, invalid):
    if invalid == "nonblank":
        cdp.documents["list"] = [{"type": "page", "url": "https://synthetic.invalid/"}]
    elif invalid == "multiple_pages":
        cdp.documents["list"] *= 2
    else:
        cdp.documents["version"] = {"Browser": "Chrome/unaccepted.test"}
    with pytest.raises(RuntimeError, match="CDP unavailable within its budget"):
        cdp.module.wait_for_cdp(CONTAINER_A, timeout=1, expected_version="145.test")
    assert cdp.clock.now == 1001
    assert len([call for call in cdp.calls if call[0] == "inspect"]) == 2


def test_cdp_wait_bounds_retries_when_local_endpoint_times_out(cdp):
    cdp.documents["version"] = TimeoutError("synthetic local CDP timeout")
    with pytest.raises(RuntimeError, match="synthetic local CDP timeout"):
        cdp.module.wait_for_cdp(CONTAINER_A, timeout=1, expected_version="145.test")
    assert cdp.clock.now == 1001
    assert [call for call in cdp.calls if call[0] == "open"] == [("open", "version")] * 2


@pytest.mark.parametrize("cancel_after", ["version", "list"])
def test_cdp_wait_stops_after_lease_changes_during_http_read(cdp, cancel_after):
    current_lease = LEASE_A

    def change_lease(endpoint):
        nonlocal current_lease
        if endpoint == cancel_after:
            current_lease = LEASE_B

    def check():
        if current_lease != LEASE_A:
            raise RuntimeError("session_expired_during_preparation")

    cdp.after_read = change_lease
    with pytest.raises(RuntimeError, match="session_expired_during_preparation"):
        cdp.module.wait_for_cdp(CONTAINER_A, expected_version="145.test", check=check)
    expected = [("open", "version")]
    if cancel_after == "list":
        expected.append(("open", "list"))
    assert [call for call in cdp.calls if call[0] == "open"] == expected
    assert not any(call[0] == "sleep" for call in cdp.calls)


def test_begin_cdp_wait_binds_version_and_prevents_late_broker_open(guest):
    guest.BASE.write_bytes(b"synthetic accepted baseline")
    accepted_baseline(guest)
    successor = {"lease_id": LEASE_B, "state": "starting", "container_id": CONTAINER_B}
    firewall_calls = []
    waited = []

    def run(*args, **kwargs):
        if args[:3] == ("docker", "ps", "-aq") or args[0] in {"systemd-run", "mount", "umount"}:
            return ""
        if args[0] == "adb":
            assert kwargs == {"timeout": 5}
            return ""
        if args[:2] == ("docker", "exec"):
            assert args[2] == CONTAINER_A
            assert kwargs == {"timeout": 15 if args[4] == "start" else 5}
            return ""
        unexpected(*args, **kwargs)

    def wait_for_cdp(container_id, *, timeout, expected_version, check):
        assert container_id == CONTAINER_A and 0 < timeout <= 60
        assert expected_version == "145.test"
        check()
        waited.append(container_id)
        guest.save_state(successor)
        check()

    guest.env.run = run
    guest.env.firewall = lambda **kwargs: firewall_calls.append(kwargs)
    guest.env.start_offline = lambda **kwargs: CONTAINER_A
    guest.env.wait_for_boot = lambda timeout, *, container_id: None
    guest.env.namespace_firewall = lambda **kwargs: {"rules": "synthetic", "network_namespace": "net:[synthetic]"}
    guest.env.wait_for_cdp = wait_for_cdp
    with pytest.raises(RuntimeError, match="session_expired_during_preparation"):
        guest.begin(LEASE_A, 60)
    assert waited == [CONTAINER_A]
    assert guest.read_json(guest.STATE) == successor
    assert firewall_calls == [{"deny_established": True}]


def test_guest_phase_marker_contains_only_control_metadata(guest):
    guest.mark_phase(LEASE_A, "base_metadata", "complete", 49.5)
    path = guest.env.ROOT / "diagnostics" / f"begin-{LEASE_A}.jsonl"
    row = json.loads(path.read_text())
    assert set(row) == {"phase", "event", "elapsed_seconds", "utc", "pid"}
    assert row["phase"] == "base_metadata" and row["event"] == "complete"
    assert row["elapsed_seconds"] == 0.5 and row["pid"] == os.getpid()
    assert "://" not in path.read_text()


def test_guest_phase_write_failure_still_ends_reserved_lease(guest):
    accepted_baseline(guest)
    phases = []
    guards = []

    def mark(lease_id, phase, event, started):
        assert lease_id == LEASE_A
        phases.append((phase, event))
        if phase in {"copy", "begin"}:
            raise OSError("synthetic diagnostic storage failure")

    def run(*args, **kwargs):
        assert args[:3] == ("docker", "ps", "-aq") or args[0] == "systemd-run"
        return ""

    guest.mark_phase = mark
    guest.env.run = run
    guest.env.firewall = lambda **kwargs: guards.append(kwargs)
    with pytest.raises(OSError, match="diagnostic storage failure"):
        guest.begin(LEASE_A, 60)
    assert ("begin", "failed") in phases
    assert guest.read_json(guest.STATE)["previous_lease_id"] == LEASE_A
    assert guest.read_json(guest.STATE)["state"] == "ended"
    assert guards == [{"deny_established": True}] * 2


@pytest.mark.parametrize("damage", ["hash", "long", "short"])
def test_begin_never_mounts_or_starts_an_unverified_copy(guest, damage):
    accepted_baseline(guest)
    data = guest.BASE.read_bytes()
    guest.BASE.write_bytes(b"X" + data[1:] if damage == "hash" else data + b"X" if damage == "long" else data[:-1])
    active = guest.env.ROOT / "android-data.ext4"
    active.write_bytes(b"previous active image")

    def run(*args, **kwargs):
        assert args[:3] == ("docker", "ps", "-aq") or args[0] == "systemd-run"
        return ""

    guest.env.run = run
    guest.env.firewall = lambda **kwargs: None
    with pytest.raises(RuntimeError, match="baseline_copy_(verification_failed|capacity_mismatch)"):
        guest.begin(LEASE_A, 60)
    assert active.read_bytes() == b"previous active image"
    assert not (guest.env.ROOT / f"session-{LEASE_A}.ext4").exists()
    assert guest.read_json(guest.STATE)["state"] == "ended"
    # Mount/start/boot/ADB remain fail-on-use stubs or rejected commands.
