"""Offline QMP protocol tests: no Docker, guest, network or process is started."""

import importlib.util
import json
import signal
from pathlib import Path
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def entry():
    spec = importlib.util.spec_from_file_location("qemu_entrypoint", ROOT / "deploy/android-docker/entrypoint.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def frame(value):
    return json.dumps(value).encode() + b"\r\n"


class FakeQMP:
    def __init__(self, responses):
        self.pending = bytearray(responses)
        self.sent = []
        self.closed = False
        self.received = bytearray()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True

    def settimeout(self, seconds):
        assert 0 < seconds <= 5

    def connect(self, path):
        assert path == "/run/fxfetch/qmp.sock"

    def recv(self, size):
        # Exercise fragmentation rather than always returning whole JSON frames.
        count = min(size, 19, len(self.pending))
        data = bytes(self.pending[:count])
        del self.pending[:count]
        self.received.extend(data)
        return data

    def sendall(self, value):
        self.sent.append(json.loads(value))


def patch_peer(entry, monkeypatch, responses):
    peer = FakeQMP(responses)
    monkeypatch.setattr(entry.socket, "AF_UNIX", 1, raising=False)
    monkeypatch.setattr(entry.socket, "socket", lambda *_args: peer)
    return peer


def test_waits_for_matching_powerdown_reply_amid_events(entry, monkeypatch):
    messages = [
        {"QMP": {"version": {}, "capabilities": []}},
        {"event": "RESUME"},
        {"return": {}, "id": "unrelated"},
        {"return": {}, "id": "fxfetch-capabilities"},
        {"event": "POWERDOWN"},
        {"return": {}, "id": "fxfetch-powerdown"},
    ]
    peer = patch_peer(entry, monkeypatch, b"".join(map(frame, messages)))
    entry.request_powerdown()
    assert peer.closed and not peer.pending
    assert peer.sent == [
        {"execute": "qmp_capabilities", "id": "fxfetch-capabilities"},
        {"execute": "system_powerdown", "id": "fxfetch-powerdown"},
    ]


@pytest.mark.parametrize("last,reason", [
    (b"", "qmp_unexpected_eof"),
    (frame({"error": {"desc": "private guest data"}, "id": "fxfetch-powerdown"}), "qmp_command_rejected"),
    (b"x" * 8193, "qmp_frame_limit"),
    (b"not-json\n", "qmp_invalid_json"),
    (frame({"event": "POWERDOWN"}) * 33, "qmp_message_limit"),
])
def test_missing_ack_and_malformed_peer_fail_bounded(entry, monkeypatch, last, reason):
    prefix = frame({"QMP": {}}) + frame({"return": {}, "id": "fxfetch-capabilities"})
    peer = patch_peer(entry, monkeypatch, prefix + last)
    with pytest.raises(entry.QMPProtocolError, match=reason):
        entry.request_powerdown()
    assert peer.closed


def test_total_deadline_is_not_reset_by_partial_traffic(entry, monkeypatch):
    peer = patch_peer(entry, monkeypatch, frame({"QMP": {}}) + frame({"event": "POWERDOWN"}) * 20)
    ticks = iter(range(30))
    monkeypatch.setattr(entry.time, "monotonic", lambda: next(ticks))
    with pytest.raises(TimeoutError, match="qmp_deadline"):
        entry.request_powerdown(timeout=5)
    assert peer.closed


def test_signal_reentry_requests_once_and_waits_for_supervised_child(entry, monkeypatch, capsys):
    child = Mock()
    child.poll.return_value = None
    handler = entry.ShutdownHandler(child)
    calls = []

    def reenter():
        calls.append(True)
        handler(signal.SIGTERM, None)

    monkeypatch.setattr(entry, "request_powerdown", reenter)
    handler(signal.SIGTERM, None)
    handler(signal.SIGINT, None)
    assert calls == [True]
    child.terminate.assert_not_called()
    child.kill.assert_not_called()
    assert "guest_acpi_shutdown_acknowledged" in capsys.readouterr().out


def test_control_error_logs_metadata_without_abandoning_child(entry, monkeypatch, capsys):
    child = Mock()
    child.poll.return_value = None
    monkeypatch.setattr(entry, "request_powerdown", Mock(side_effect=OSError("secret control detail")))
    handler = entry.ShutdownHandler(child)
    handler(signal.SIGTERM, None)
    handler(signal.SIGTERM, None)
    output = capsys.readouterr().out
    assert "guest_acpi_shutdown_failed" in output and "OSError" in output
    assert "secret control detail" not in output
    entry.request_powerdown.assert_called_once()
    child.terminate.assert_not_called()
    child.kill.assert_not_called()
