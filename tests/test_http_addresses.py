"""Connection retries only before sending a request, using synthetic local transport."""

import ssl
import threading
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fxfetch.core.errors import FxfetchError
from fxfetch.core.http_client import HttpClient


@pytest.fixture
def address_server():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            requests.append((self.path, self.headers.get("Host")))
            self.send_response(200)
            self.send_header("Content-Length", "20" if self.path == "/truncated" else "2")
            self.end_headers()
            self.wfile.write(b"ok")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_port, requests
    server.shutdown()
    server.server_close()
    thread.join()


@pytest.mark.parametrize(
    "failure,code",
    [
        (TimeoutError("synthetic timeout"), "network_timeout"),
        (ssl.SSLError("synthetic handshake interruption"), "tls_handshake_failed"),
    ],
)
def test_failed_address_then_second_address_sends_one_request(address_server, tmp_path, failure, code):
    port, requests = address_server

    class SyntheticClient(HttpClient):
        def _connect(self, host, port, address, secure, timeout):
            if address == "8.8.8.8":
                raise failure
            return super()._connect(host, port, "127.0.0.1", secure, timeout)

    client = SyntheticClient(resolver=lambda *_: ("8.8.8.8", "1.1.1.1"))
    response = client.fetch(
        f"http://synthetic.invalid:{port}/",
        tmp_path / "body",
        user_agent="Synthetic",
        cookie_jar=CookieJar(),
        cancel=threading.Event(),
    )
    assert response.path.read_bytes() == b"ok"
    assert requests == [("/", f"synthetic.invalid:{port}")]
    assert response.hops[0].requested_ip == "1.1.1.1"
    assert response.hops[0].connection_attempts == (
        {"ip": "8.8.8.8", "outcome": "failed", "reason_code": code},
        {"ip": "1.1.1.1", "outcome": "connected"},
    )


@pytest.mark.parametrize(
    "error",
    [
        ssl.SSLCertVerificationError("synthetic certificate mismatch"),
        FxfetchError("peer_mismatch", "synthetic peer mismatch"),
    ],
)
def test_security_failure_never_changes_address(error, tmp_path):
    calls = []

    class SyntheticClient(HttpClient):
        def _connect(self, host, port, address, secure, timeout):
            calls.append(address)
            raise error

    with pytest.raises(FxfetchError) as raised:
        SyntheticClient(resolver=lambda *_: ("8.8.8.8", "1.1.1.1")).fetch(
            "https://synthetic.invalid/",
            tmp_path / "body",
            user_agent="Synthetic",
            cookie_jar=CookieJar(),
            cancel=threading.Event(),
        )
    assert calls == ["8.8.8.8"]
    assert raised.value.code == (
        "tls_verification_failed" if isinstance(error, ssl.SSLCertVerificationError) else "peer_mismatch"
    )


def test_address_attempt_limit_and_cancel(tmp_path):
    calls = []
    cancelled = threading.Event()

    class SyntheticClient(HttpClient):
        def _connect(self, host, port, address, secure, timeout):
            calls.append(address)
            raise TimeoutError("synthetic connection timeout")

    client = SyntheticClient(resolver=lambda *_: ("8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4", "1.0.0.1"))
    with pytest.raises(FxfetchError, match="timed out"):
        client.fetch(
            "https://synthetic.invalid/",
            tmp_path / "body",
            user_agent="Synthetic",
            cookie_jar=CookieJar(),
            cancel=cancelled,
        )
    assert len(calls) == 4
    calls.clear()
    cancelled.set()
    with pytest.raises(FxfetchError) as raised:
        client.fetch(
            "https://synthetic.invalid/",
            tmp_path / "body",
            user_agent="Synthetic",
            cookie_jar=CookieJar(),
            cancel=cancelled,
        )
    assert raised.value.code == "cancelled" and calls == []


def test_partial_response_never_replayed_on_another_address(address_server, tmp_path):
    port, requests = address_server
    calls = []

    class SyntheticClient(HttpClient):
        def _connect(self, host, port, address, secure, timeout):
            calls.append(address)
            return super()._connect(host, port, "127.0.0.1", secure, timeout)

    with pytest.raises(FxfetchError):
        SyntheticClient(resolver=lambda *_: ("8.8.8.8", "1.1.1.1")).fetch(
            f"http://synthetic.invalid:{port}/truncated",
            tmp_path / "body",
            user_agent="Synthetic",
            cookie_jar=CookieJar(),
            cancel=threading.Event(),
        )
    assert calls == ["8.8.8.8"]
    assert len(requests) == 1
