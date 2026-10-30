"""Synthetic real-socket regression for close/transport/guard event categories."""

from __future__ import annotations

import select
import socket
import struct
import sys
import threading
import time
from types import SimpleNamespace

import pytest
from test_browser_gateway import LEASE_ID, connect, gate_for
from test_browser_gateway import origin as origin

from fxfetch.core.errors import FxfetchError


@pytest.mark.parametrize("cancelled", [False, True], ids=["normal_close", "user_cancel"])
def test_close_during_select_is_not_a_public_guard_or_transport_failure(origin, monkeypatch, cancelled):
    port, _ = origin
    selected, release, finished = threading.Event(), threading.Event(), threading.Event()
    original_select = select.select

    def held_select(read, write, errors, timeout):
        selected.set()
        assert release.wait(2), "bounded close-race barrier"
        # close() has closed these real sockets, reproducing ValueError/EBADF.
        return original_select(read, write, errors, timeout)

    monkeypatch.setattr("fxfetch.core.browser_gateway.select", SimpleNamespace(select=held_select))
    events = []
    cancel = threading.Event()
    with gate_for(port, on_event=events.append, cancel=cancel) as gate:
        original_handle = gate._handle

        def handle(client):
            try:
                original_handle(client)
            finally:
                finished.set()

        gate._handle = handle
        gate.arm(LEASE_ID)
        gate.permit_request(LEASE_ID, "https://fixture.synthetic.invalid/", "GET")
        client, header = connect(gate)
        try:
            assert b"200 Connection Established" in header and selected.wait(1)
            if cancelled:
                cancel.set()
            gate.close()
            release.set()
            assert finished.wait(2), "gateway handler did not settle"
        finally:
            release.set()
            client.close()
    failures = [row for row in events if row["event"] != "browser_connection"]
    if cancelled:
        assert failures == [{"event": "browser_connection_cancelled", "reason_code": "cancelled",
                             "url": "https://fixture.synthetic.invalid:443/"}]
    else:
        assert not failures and not gate.errors


def test_real_connect_refusal_is_not_reported_as_public_guard_block():
    events = []
    # Reserve a real local port without listening, so connect is refused.
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        with gate_for(reserved.getsockname()[1], on_event=events.append, timeout=1) as gate:
            gate.arm(LEASE_ID)
            gate.permit_request(LEASE_ID, "https://fixture.synthetic.invalid/", "GET")
            client, _ = connect(gate)
            client.close()
            deadline = time.monotonic() + 1
            while not gate.errors and time.monotonic() < deadline:
                time.sleep(0.01)
    assert gate.errors[-1]["reason_code"] == "browser_transport_failed"
    assert gate.errors[-1]["event"] == "browser_connection_failed"
    assert gate.errors[-1]["connection_phase"] == "before_connect"


def test_real_connected_peer_reset_remains_a_transport_failure():
    accepted, reset = threading.Event(), threading.Event()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(2)

        def reset_peer():
            peer, _ = listener.accept()
            with peer:
                accepted.set()
                assert reset.wait(2), "bounded peer-reset barrier"
                peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                struct.pack("hh" if sys.platform == "win32" else "ii", 1, 0))

        worker = threading.Thread(target=reset_peer, daemon=True)
        worker.start()
        with gate_for(listener.getsockname()[1]) as gate:
            gate.arm(LEASE_ID)
            gate.permit_request(LEASE_ID, "https://fixture.synthetic.invalid/", "GET")
            client, header = connect(gate)
            try:
                assert b"200 Connection Established" in header and accepted.wait(1)
                reset.set()
                assert client.recv(1) == b""
            finally:
                reset.set()
                client.close()
        worker.join(2)
        assert not worker.is_alive()
    assert gate.errors == [{
        "event": "browser_transport_failed", "reason_code": "browser_transport_failed",
        "connection_phase": "established", "url": "https://fixture.synthetic.invalid:443/",
    }]


@pytest.mark.parametrize("failure", [ConnectionResetError(10054, "synthetic"), TimeoutError("synthetic")])
def test_real_transport_error_is_not_hidden_by_simultaneous_close(origin, monkeypatch, failure):
    port, _ = origin
    selected, release, finished = threading.Event(), threading.Event(), threading.Event()

    def failed_select(*args):
        selected.set()
        assert release.wait(2)
        # Fault injection retains a real transport failure racing with close;
        # a stopped flag and closed FD alone must not suppress its category.
        raise failure

    monkeypatch.setattr("fxfetch.core.browser_gateway.select", SimpleNamespace(select=failed_select))
    with gate_for(port) as gate:
        original_handle = gate._handle

        def handle(client):
            try:
                original_handle(client)
            finally:
                finished.set()

        gate._handle = handle
        gate.arm(LEASE_ID)
        gate.permit_request(LEASE_ID, "https://fixture.synthetic.invalid/", "GET")
        client, header = connect(gate)
        try:
            assert b"200 Connection Established" in header and selected.wait(1)
            gate.close()
            release.set()
            assert finished.wait(2)
        finally:
            release.set()
            client.close()
    assert len(gate.errors) == 1
    assert gate.errors[0]["event"] == "browser_transport_failed"
    assert gate.errors[0]["connection_phase"] == "established"


@pytest.mark.parametrize(("code", "event"), [
    ("target_not_public", "browser_connection_blocked"),
    ("dns_unsafe_answer", "browser_connection_blocked"),
    ("browser_wire_limit", "browser_budget_exhausted"),
    ("task_timeout", "browser_budget_exhausted"),
    ("dns_no_addresses", "browser_connection_failed"),
])
def test_guard_budget_and_dns_failure_survive_a_concurrent_stop(monkeypatch, code, event):
    # Fail before any upstream socket can be made; stop races with that actual
    # typed failure rather than turning it into a normal local teardown.
    with gate_for(1) as gate:
        def rejected_destination(url):
            gate._stopped.set()
            raise FxfetchError(code, "synthetic rejection")

        monkeypatch.setattr(gate, "_destination", rejected_destination)
        gate.arm(LEASE_ID)
        gate.permit_request(LEASE_ID, "https://fixture.synthetic.invalid/", "GET")
        client, header = connect(gate)
        client.close()
        assert b"502" in header
    assert len(gate.errors) == 1
    assert gate.errors[0]["event"] == event
    assert gate.errors[0]["reason_code"] == code
