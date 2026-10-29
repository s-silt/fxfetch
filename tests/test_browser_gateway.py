import errno
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from fxfetch.core.browser_gateway import BrowserGateway
from fxfetch.core.errors import FxfetchError
from fxfetch.core.guard import validate_url

LEASE_ID = "a" * 32


@pytest.fixture
def origin():
    received = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            try:
                value = self.request.recv(65536)
            except OSError:
                return
            received.append(value)
            if value.startswith(b"GET"):
                self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong")
            elif value:
                self.request.sendall(value)

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    yield server.server_address[1], received
    server.shutdown()
    server.server_close()
    thread.join(2)


def gate_for(port, **options):
    class SyntheticGateway(BrowserGateway):
        def _destination(self, url):
            assert urlsplit(validate_url(url)).hostname in {"fixture.synthetic.invalid", "other.synthetic.invalid"}
            return "127.0.0.1", port

    return SyntheticGateway(port=0, **options)


def connect(gate, request=b"CONNECT fixture.synthetic.invalid:443 HTTP/1.1\r\nHost: fixture.synthetic.invalid:443\r\n\r\n"):
    client = socket.create_connection(("127.0.0.1", gate.port), timeout=2)
    client.sendall(request)
    header = bytearray()
    while not header.endswith(b"\r\n\r\n"):
        try:
            block = client.recv(1)
        except ConnectionResetError:
            break  # Closing a rejected unread pipeline can reset on Windows.
        if not block:
            break
        header.extend(block)
    return client, bytes(header)


def test_connect_keeps_original_stream_and_reports_target(origin):
    port, received = origin
    events = []
    with gate_for(port, on_event=events.append) as gate:
        gate.arm(LEASE_ID)
        gate.permit_request(LEASE_ID, "https://fixture.synthetic.invalid/", "GET")
        client, header = connect(gate)
        assert b"200 Connection Established" in header
        client.sendall(b"synthetic-tls-record")
        assert client.recv(100) == b"synthetic-tls-record"
        client.close()
    assert received == [b"synthetic-tls-record"]
    assert any(event["event"] == "browser_connection" for event in events)


def test_plain_http_converts_absolute_target_and_strips_proxy_credentials(origin):
    port, received = origin
    with gate_for(port) as gate:
        gate.arm(LEASE_ID)
        gate.permit_request(LEASE_ID, "http://fixture.synthetic.invalid/path?q=1", "GET")
        client, header = connect(gate, b"GET http://fixture.synthetic.invalid/path?q=1 HTTP/1.1\r\nHost: fixture.synthetic.invalid\r\nProxy-Authorization: synthetic-only\r\n\r\n")
        assert b"200 OK" in header
        assert client.recv(100) == b"pong"
        client.close()
    assert received[0].startswith(b"GET /path?q=1 HTTP/1.1\r\n")
    assert b"Proxy-Authorization" not in received[0]


@pytest.mark.parametrize("authority", ["127.0.0.1:80", "[::1]:80", "169.254.169.254:80", "10.0.0.1:443", "2001::1"])
def test_guard_rejects_local_addresses_before_connection(authority):
    with BrowserGateway(port=0) as gate:
        gate.arm(LEASE_ID)
        if authority != "2001::1":
            gate.permit_request(LEASE_ID, f"https://{authority}/", "GET")
        client, header = connect(gate, f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        assert b"502" in header
        client.close()
    assert gate.wire_bytes == 0 and gate.errors
    assert gate.errors[-1]["reason_code"] in {"target_not_public", "invalid_url"}


def test_http_host_mismatch_does_not_reach_origin(origin):
    port, received = origin
    with gate_for(port) as gate:
        gate.arm(LEASE_ID)
        client, header = connect(gate, b"GET http://fixture.synthetic.invalid/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        assert b"502" in header
        client.close()
    assert received == []
    assert gate.errors[-1]["reason_code"] == "invalid_header"


def test_wire_limit_stops_before_forwarding_extra_bytes(origin):
    port, received = origin
    with gate_for(port, max_wire_bytes=8) as gate:
        gate.arm(LEASE_ID)
        gate.permit_request(LEASE_ID, "https://fixture.synthetic.invalid/", "GET")
        client, header = connect(gate)
        assert b"200" in header
        client.sendall(b"x" * 32)
        assert client.recv(100) == b""
        client.close()
    assert not any(received)
    assert gate.wire_bytes <= 8 and gate.errors[-1]["reason_code"] == "browser_wire_limit"


@pytest.mark.parametrize("stop", ["cancel", "deadline"])
def test_active_tunnel_is_stopped(origin, stop):
    port, _ = origin
    cancelled = threading.Event()
    with gate_for(port, cancel=cancelled, timeout=0.25 if stop == "deadline" else 3) as gate:
        gate.arm(LEASE_ID)
        gate.permit_request(LEASE_ID, "https://fixture.synthetic.invalid/", "GET")
        client, header = connect(gate)
        assert b"200" in header
        started = time.monotonic()
        if stop == "cancel":
            cancelled.set()
        assert client.recv(100) == b""
        assert time.monotonic() - started < 1.5
        client.close()
    assert gate.errors[-1]["reason_code"] == ("cancelled" if stop == "cancel" else "task_timeout")


def dormant_attempt(gate):
    try:
        client = socket.create_connection(("127.0.0.1", gate.port), timeout=0.25)
    except (ConnectionRefusedError, TimeoutError):
        return  # Windows may drop SYNs to a bound, non-listening port.
    with client:
        try:
            client.sendall(b"CONNECT fixture.synthetic.invalid:443 HTTP/1.1\r\nHost: fixture.synthetic.invalid:443\r\n\r\n")
            assert client.recv(100) == b""
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            pass  # Accept-time denial can reset a request already being sent.


def test_dormant_gateway_never_resolves_or_charges_old_requests(monkeypatch):
    monkeypatch.setattr(
        "fxfetch.core.browser_gateway.DefaultPublicDNSResolver",
        lambda: pytest.fail("Dormant gateway must not perform DNS"),
    )
    with BrowserGateway(port=0) as gate:
        assert gate.active and not gate.armed
        dormant_attempt(gate)
        assert gate.connections == gate.wire_bytes == 0
        assert gate.errors == []
        with pytest.raises(FxfetchError, match="no verified lease"):
            gate._destination("https://fixture.synthetic.invalid/")


def test_failed_new_lease_cannot_lend_its_gateway_to_old_chrome(origin, monkeypatch, tmp_path):
    import fxfetch.core.browser_workflow as module

    port, received = origin
    gateway = gate_for(port)
    denied_attempt = []

    class FailedLease:
        def __init__(self, worker, gate, *args, **kwargs):
            self.gate = gate

        def __enter__(self):
            # The old Chrome can reach the fixed listener while begin rejects
            # a remaining guest lease, but must never reach this task's origin.
            dormant_attempt(self.gate)
            denied_attempt.append(True)
            raise FxfetchError("browser_worker_unavailable", "Old lease still exists")

        def __exit__(self, *args):
            pytest.fail("Failed enter does not grant a lease")

    monkeypatch.setattr(module, "BrowserGateway", lambda **kwargs: gateway)
    monkeypatch.setattr(module, "AndroidLease", FailedLease)
    result = module.BrowserWorkflow(None, None, module.Limits()).run(
        "https://entry.test/", tmp_path, threading.Event()
    )
    assert result.reason_code == "browser_worker_unavailable"
    assert denied_attempt == [True]
    assert received == [] and gateway.connections == gateway.wire_bytes == 0
    assert not gateway.armed and not gateway.active


def test_verified_lease_arms_transmission_and_close_revokes_it(origin):
    from fxfetch.core.android_worker import AndroidLease

    port, received = origin

    class Worker:
        def call(self, action, lease_id):
            assert action == "status" and lease_id == LEASE_ID
            return {"synthetic_live_guard": True}

        def validate(self, value, lease_id):
            assert value["synthetic_live_guard"] and lease_id == LEASE_ID

    class Tunnel:
        def poll(self):
            return None

    with gate_for(port) as gate:
        lease = AndroidLease(Worker(), gate, threading.Event(), 60, lease_id=LEASE_ID)
        lease.started, lease.tunnel = True, Tunnel()
        assert not gate.armed
        proof = lease.verify_before_launch()
        assert gate.armed
        assert proof.permit_request is not None
        proof.permit_request("https://fixture.synthetic.invalid/", "GET")
        client, header = connect(gate)
        assert b"200" in header
        client.sendall(b"verified-session")
        assert client.recv(100) == b"verified-session"
        client.close()
        with pytest.raises(FxfetchError, match="another lease"):
            gate.arm("b" * 32)
    assert received == [b"verified-session"] and not gate.armed
    with pytest.raises(FxfetchError):
        gate.arm(LEASE_ID)


def http_request(url, method="GET", headers=""):
    authority = urlsplit(url).netloc
    return f"{method} {url} HTTP/1.1\r\nHost: {authority}\r\n{headers}\r\n".encode()


@pytest.mark.parametrize("wire_request", [
    b"CONNECT background.synthetic.invalid:443 HTTP/1.1\r\nHost: background.synthetic.invalid\r\n\r\n",
    http_request("http://background.synthetic.invalid/path?private=synthetic"),
])
def test_unpermitted_background_request_has_zero_dns_and_no_ui_noise(monkeypatch, wire_request):
    monkeypatch.setattr("fxfetch.core.browser_gateway.DefaultPublicDNSResolver", lambda: pytest.fail("No permit must mean no DNS"))
    events = []
    with BrowserGateway(port=0, on_event=events.append) as gate:
        gate.arm(LEASE_ID)
        client, response = connect(gate, wire_request)
        assert b"502" in response
        client.close()
    assert gate.wire_bytes == 0 and events == []
    assert gate.errors == [{"event": "browser_connection_blocked", "reason_code": "browser_request_not_permitted", "host": "background.synthetic.invalid"}]


def test_destination_override_cannot_bypass_missing_page_permit(origin):
    port, received = origin
    with gate_for(port) as gate:
        gate.arm(LEASE_ID)
        client, response = connect(gate, http_request("http://fixture.synthetic.invalid/"))
        assert b"502" in response
        client.close()
    assert received == []
    assert gate.errors[-1]["reason_code"] == "browser_request_not_permitted"


def test_request_permits_bind_current_lease_and_are_revoked_on_close(origin):
    port, received = origin
    gate = gate_for(port)
    with gate:
        gate.arm(LEASE_ID)
        with pytest.raises(FxfetchError, match="another lease"):
            gate.permit_request("b" * 32, "https://fixture.synthetic.invalid/", "GET")
        client, response = connect(gate)
        assert b"502" in response
        client.close()
        gate.permit_request(LEASE_ID, "https://fixture.synthetic.invalid/", "GET")
        gate.permit_request(LEASE_ID, "http://fixture.synthetic.invalid/", "GET")
    assert received == []
    assert gate._http_permits == {} and gate._https_authorities == set()
    with pytest.raises(FxfetchError) as denied:
        gate.permit_request(LEASE_ID, "https://fixture.synthetic.invalid/", "GET")
    assert denied.value.code == "cancelled"


def test_http_permit_normalizes_authority_but_is_method_path_and_one_use(origin):
    port, received = origin
    with gate_for(port) as gate:
        gate.arm(LEASE_ID)
        gate.permit_request(LEASE_ID, "HTTP://fixture.synthetic.invalid/path?q=1#fragment", "GET")
        target = "http://fixture.synthetic.invalid:80/path?q=1"
        for denied in (http_request(target, "HEAD"), http_request(target + "2")):
            client, response = connect(gate, denied)
            assert b"502" in response
            client.close()
        client, response = connect(gate, http_request(target))
        assert b"200" in response and client.recv(4) == b"pong"
        client.close()
        client, response = connect(gate, http_request(target))
        assert b"502" in response
        client.close()
    assert len(received) == 1


@pytest.mark.parametrize("next_url", ["http://fixture.synthetic.invalid/next", "http://other.synthetic.invalid/next"])
def test_redirect_destination_needs_its_own_request_permit(origin, next_url):
    port, received = origin
    with gate_for(port) as gate:
        gate.arm(LEASE_ID)
        gate.permit_request(LEASE_ID, "http://fixture.synthetic.invalid/first", "GET")
        client, response = connect(gate, http_request(next_url))
        assert b"502" in response
        client.close()
        gate.permit_request(LEASE_ID, next_url, "GET")
        client, response = connect(gate, http_request(next_url))
        assert b"200" in response and client.recv(4) == b"pong"
        client.close()
    assert len(received) == 1


def test_https_permit_is_only_for_exact_connect_authority(origin):
    port, received = origin
    with gate_for(port) as gate:
        gate.arm(LEASE_ID)
        gate.permit_request(LEASE_ID, "https://fixture.synthetic.invalid/private/path", "GET")
        for authority in ("fixture.synthetic.invalid:444", "other.synthetic.invalid:443"):
            client, response = connect(gate, f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
            assert b"502" in response
            client.close()
        client, response = connect(gate, http_request("http://fixture.synthetic.invalid/private/path"))
        assert b"502" in response
        client.close()
        # CONNECT cannot see a TLS path/method. Multiple TLS connections to the
        # permitted authority remain possible within the lease's hard budget.
        for payload in (b"tls-one", b"tls-two"):
            client, response = connect(gate)
            assert b"200" in response
            client.sendall(payload)
            assert client.recv(30) == payload
            client.close()
    assert received == [b"tls-one", b"tls-two"]


def test_permit_registration_has_a_task_wide_hard_limit(origin):
    port, _ = origin
    with gate_for(port, max_connections=2) as gate:
        gate.arm(LEASE_ID)
        gate.permit_request(LEASE_ID, "http://fixture.synthetic.invalid/", "GET")
        gate.permit_request(LEASE_ID, "https://fixture.synthetic.invalid/", "GET")
        with pytest.raises(FxfetchError) as denied:
            gate.permit_request(LEASE_ID, "http://fixture.synthetic.invalid/third", "GET")
        assert denied.value.code == "browser_permit_limit"


def test_http_does_not_forward_an_unpermitted_pipelined_request(origin):
    port, received = origin
    with gate_for(port) as gate:
        gate.arm(LEASE_ID)
        first = "http://fixture.synthetic.invalid/first"
        gate.permit_request(LEASE_ID, first, "GET")
        client, response = connect(gate, http_request(first) + http_request("http://fixture.synthetic.invalid/unpermitted"))
        assert b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n".startswith(response)
        client.close()
    assert len(received) == 1 and b"unpermitted" not in received[0]


@pytest.mark.parametrize("headers", ["Transfer-Encoding: chunked\r\n", "Upgrade: websocket\r\n", "Content-Length: 4\r\nContent-Length: 4\r\n"])
def test_ambiguous_or_upgraded_http_body_never_reaches_origin(origin, headers):
    port, received = origin
    with gate_for(port) as gate:
        gate.arm(LEASE_ID)
        target = "http://fixture.synthetic.invalid/"
        gate.permit_request(LEASE_ID, target, "POST")
        client, response = connect(gate, http_request(target, "POST", headers))
        assert b"502" in response
        client.close()
    assert received == []


@pytest.mark.parametrize("pipeline", [False, True])
def test_http_forwards_exact_content_length_and_no_following_request(pipeline):
    received = []

    class BodyHandler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            headers = bytearray()
            while not headers.endswith(b"\r\n\r\n"):
                headers.extend(self.request.recv(1))
            body = bytearray()
            while len(body) < 4:
                body.extend(self.request.recv(4 - len(body)))
            self.request.settimeout(0.1)
            try:
                extra = self.request.recv(1000)
            except TimeoutError:
                extra = b""
            received.append((bytes(body), extra))
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), BodyHandler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            with gate_for(server.server_address[1]) as gate:
                gate.arm(LEASE_ID)
                target = "http://fixture.synthetic.invalid/post"
                gate.permit_request(LEASE_ID, target, "POST")
                request = http_request(target, "POST", "Content-Length: 4\r\n") + b"DATA"
                if pipeline:
                    request += http_request(target)
                client, response = connect(gate, request)
                if pipeline:
                    assert b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".startswith(response)
                else:
                    assert b"200" in response
                client.close()
        finally:
            server.shutdown()
            thread.join(2)
    assert received == [(b"DATA", b"")]


@pytest.mark.skipif(sys.platform != "linux", reason="Linux TIME_WAIT and abstract socket ownership")
def test_linux_closed_connections_allow_immediate_consecutive_tasks(monkeypatch):
    monkeypatch.setattr(
        "fxfetch.core.browser_gateway.DefaultPublicDNSResolver",
        lambda: pytest.fail("Unpermitted local test request must never resolve DNS"),
    )
    port = 0
    for _ in range(3):
        with BrowserGateway(port=port) as gate:
            port = gate.port
            dormant_attempt(gate)
            gate.arm(LEASE_ID)
            client, response = connect(gate)
            with client:
                assert b"502" in response
                # Let the server send FIN first, creating TIME_WAIT at its port.
                assert client.recv(1) == b""
        assert any(
            row.split()[1].endswith(f":{port:04X}") and row.split()[3] == "06"
            for row in Path("/proc/net/tcp").read_text().splitlines()[1:]
        ), "The test must exercise an actual server-side TIME_WAIT connection"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux abstract socket ownership")
@pytest.mark.parametrize("armed", [False, True])
def test_linux_port_ownership_excludes_same_and_other_processes(armed):
    with BrowserGateway(port=0) as gate:
        if armed:
            gate.arm(LEASE_ID)
        competing = BrowserGateway(port=gate.port)
        with pytest.raises(OSError) as denied:
            competing.__enter__()
        assert denied.value.errno == errno.EADDRINUSE
        assert not competing.active and competing._port_owner is None
        code = """
import errno, sys
from fxfetch.core.browser_gateway import BrowserGateway
try:
    with BrowserGateway(port=int(sys.argv[1])):
        raise AssertionError('A second process acquired the active gateway port')
except OSError as error:
    assert error.errno == errno.EADDRINUSE
    print('exclusive')
"""
        result = subprocess.run(
            [sys.executable, "-c", code, str(gate.port)],
            capture_output=True, text=True, check=True, timeout=5,
        )
        assert result.stdout.strip() == "exclusive"
        assert gate.active
    with BrowserGateway(port=gate.port) as replacement:
        assert replacement.active and not replacement.armed


@pytest.mark.skipif(sys.platform != "linux", reason="Linux abstract socket ownership")
def test_linux_failed_tcp_bind_releases_abstract_ownership():
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen(1)
        port = occupied.getsockname()[1]
        gate = BrowserGateway(port=port)
        with pytest.raises(OSError) as denied:
            gate.__enter__()
        assert denied.value.errno == errno.EADDRINUSE
        assert not gate.active and gate._port_owner is None
    with BrowserGateway(port=port) as replacement:
        assert replacement.active


@pytest.mark.skipif(sys.platform != "linux", reason="Linux abstract socket ownership")
def test_linux_process_exit_releases_dormant_port_ownership():
    import select

    code = """
import time
from fxfetch.core.browser_gateway import BrowserGateway
with BrowserGateway(port=0) as gate:
    print(gate.port, flush=True)
    time.sleep(30)
"""
    child = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert child.stdout is not None
        assert select.select([child.stdout], [], [], 5)[0], "Child did not reserve a port"
        port = int(child.stdout.readline())
        with pytest.raises(OSError):
            BrowserGateway(port=port).__enter__()
        child.kill()  # No Python cleanup: the kernel must release ownership.
        child.communicate(timeout=5)
        with BrowserGateway(port=port) as replacement:
            assert replacement.active and not replacement.armed
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=5)
