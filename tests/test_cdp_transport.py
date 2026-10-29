"""Offline rejection tests for the local CDP control channel."""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fxfetch.core.browser_response import write_capture_diagnostic
from fxfetch.core.cdp_transport import CDPCommandError, CDPMux, resolve_endpoint
from fxfetch.core.errors import FxfetchError


@pytest.mark.parametrize(
    "endpoint",
    [
        "ws://example.com:9222/devtools/browser/synthetic",
        "http://localhost:9222",
        "http://192.168.1.2:9222",
        "http://127.0.0.1:9222/not-control",
        "http://user:password@127.0.0.1:9222",
        "ws://127.0.0.1:9222/devtools/page/synthetic",
        "ws://127.0.0.1:9222/devtools/browser/synthetic?token=x",
    ],
)
def test_remote_or_unexpected_cdp_endpoint_is_rejected_without_network(endpoint, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Invalid control endpoints must not open a connection")

    monkeypatch.setattr("http.client.HTTPConnection", forbidden)
    with pytest.raises(FxfetchError, match="CDP"):
        resolve_endpoint(Path("unused"), endpoint)


def test_local_websocket_requires_no_discovery_request(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("WebSocket endpoint must not make an HTTP discovery request")

    monkeypatch.setattr("http.client.HTTPConnection", forbidden)
    endpoint = "ws://127.0.0.1:19222/devtools/browser/synthetic"
    assert resolve_endpoint(Path("unused"), endpoint) == endpoint


def test_discoverable_browser_websocket_accepts_android_path_without_uuid():
    endpoint = "ws://127.0.0.1:19222/devtools/browser"
    assert resolve_endpoint(Path("unused"), endpoint) == endpoint


def test_android_http_discovery_rewrites_only_the_forwarded_authority(monkeypatch):
    calls = []

    class Connection:
        status = 200

        def __init__(self, host, port, timeout):
            calls.append((host, port, timeout))

        def request(self, method, path):
            calls.append((method, path))

        def getresponse(self):
            return self

        def read(self, maximum):
            assert maximum == 4097
            return json.dumps({"webSocketDebuggerUrl": "ws://localhost:9222/devtools/browser"}).encode()

        def close(self):
            calls.append("closed")

    monkeypatch.setattr("http.client.HTTPConnection", Connection)
    assert (
        resolve_endpoint(Path("unused"), "http://127.0.0.1:19222") == "ws://127.0.0.1:19222/devtools/browser"
    )
    assert calls == [("127.0.0.1", 19222, 3), ("GET", "/json/version"), "closed"]


def test_command_failure_keeps_method_but_not_remote_error_secrets(tmp_path):
    async def exercise():
        reader = asyncio.StreamReader()
        reader.feed_data(json.dumps({"id": 1, "error": {
            "code": -32602, "message": "Invalid InterceptionId. secret=https://example.test/token",
        }}).encode() + b"\n")
        reader.feed_eof()
        mux = CDPMux(SimpleNamespace(stdout=reader), lambda *_: None, lambda: None, 1)
        mux.closed = True
        future = asyncio.get_running_loop().create_future()
        mux.pending[1] = future
        mux.methods[1] = "Fetch.failRequest"
        await mux.reader_task
        with pytest.raises(CDPCommandError) as caught:
            await future
        assert caught.value.method == "Fetch.failRequest"
        assert caught.value.category == "interception_gone"
        write_capture_diagnostic(tmp_path, caught.value, "cdp")

    asyncio.run(exercise())
    text = (tmp_path / "capture-diagnostic.json").read_text()
    assert "Fetch.failRequest" in text and "interception_gone" in text
    assert "secret" not in text and "https" not in text and "token" not in text
