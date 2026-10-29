import socket
import threading
from contextlib import contextmanager
from http.cookiejar import CookieJar

import pytest

from fxfetch.core.errors import FxfetchError
from fxfetch.core.http_client import HttpClient
from fxfetch.core.proxy import LocalConnectProxy


@contextmanager
def synthetic_proxy(reply=b"HTTP/1.1 200 Connection established\r\n\r\n", serve_http=False):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)
    requests = []
    errors = []

    def run():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(3)
                for index in range(2 if serve_http else 1):
                    data = bytearray()
                    while not data.endswith(b"\r\n\r\n"):
                        value = connection.recv(1)
                        if not value:
                            return
                        data.extend(value)
                    requests.append(bytes(data))
                    if index == 0:
                        connection.sendall(reply)
                    else:
                        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody")
        except OSError as exc:
            errors.append(exc)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    try:
        yield LocalConnectProxy("127.0.0.1", listener.getsockname()[1]), requests
    finally:
        listener.close()
        worker.join(4)
        assert not worker.is_alive()
        assert not errors


@pytest.mark.parametrize(
    "host", ["localhost", "proxy.example", "93.184.216.34", "127.0.0.1\r\nX: y", "user:pass@127.0.0.1"]
)
def test_only_literal_loopback_proxy_config(host):
    with pytest.raises(ValueError):
        LocalConnectProxy(host, 7890)


@pytest.mark.parametrize(
    "target", ["download.example", "127.0.0.1", "198.18.0.1", "::1", "93.184.216.34\r\nX: y"]
)
def test_unsafe_target_rejected_before_proxy_connection(target):
    with pytest.raises(FxfetchError):
        LocalConnectProxy("127.0.0.1", 1).tunnel(target, 443, 1)


@pytest.mark.parametrize(
    "target,authority",
    [("93.184.216.34", b"93.184.216.34:443"), ("2606:4700:4700::1111", b"[2606:4700:4700::1111]:443")],
)
def test_connect_uses_public_ip_not_hostname(target, authority):
    with synthetic_proxy() as (proxy, requests):
        proxy.tunnel(target, 443, 2).close()
    assert requests == [b"CONNECT " + authority + b" HTTP/1.1\r\nHost: " + authority + b"\r\n\r\n"]


@pytest.mark.parametrize(
    "reply",
    [
        b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
        b"HTTP/1.1 302 Found\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX: " + b"x" * 17000 + b"\r\n\r\n",
    ],
    ids=["auth_required", "redirect", "oversized_headers"],
)
def test_proxy_rejections_are_not_followed(reply):
    with synthetic_proxy(reply) as (proxy, _):
        with pytest.raises(FxfetchError):
            proxy.tunnel("93.184.216.34", 443, 2)


def test_http_host_and_proxy_evidence(tmp_path):
    with synthetic_proxy(serve_http=True) as (proxy, requests):
        client = HttpClient(proxy=proxy, resolver=lambda host, port: ("93.184.216.34",))
        result = client.fetch(
            "http://download.example/file",
            tmp_path / "body",
            user_agent="synthetic",
            cookie_jar=CookieJar(),
            cancel=threading.Event(),
        )
    assert b"Host: download.example\r\n" in requests[1]
    assert result.hops[0].connection_ip == "127.0.0.1"
    assert result.hops[0].requested_ip == "93.184.216.34"
    assert result.hops[0].connection_source == "explicit_proxy_connect"


def test_https_keeps_original_sni(monkeypatch):
    calls = []

    class InspectContext:
        def wrap_socket(self, sock, *, server_hostname):
            calls.append(server_hostname)
            return sock

    client = HttpClient()
    monkeypatch.setattr(client, "_tls_context", lambda: InspectContext())
    with synthetic_proxy() as (proxy, _):
        client.proxy = proxy
        client._connect("download.example", 443, "93.184.216.34", True, 2).close()
    assert calls == ["download.example"]
