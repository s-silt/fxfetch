from __future__ import annotations

import threading
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from fxfetch.core.errors import FxfetchError
from fxfetch.core.guard import validate_url
from fxfetch.core.http_client import HttpClient


@pytest.mark.parametrize(
    "url,expected",
    [
        (
            "https://synthetic.example/目录/图.png?q=中文&literal=%2f%25%23&plus=a+b#保留原文",
            "https://synthetic.example/%E7%9B%AE%E5%BD%95/%E5%9B%BE.png?q=%E4%B8%AD%E6%96%87&literal=%2f%25%23&plus=a+b",
        ),
        (
            "https://例子.测试/😀?a=é&a=%C3%A9&x=%252F",
            "https://xn--fsqu00a.xn--0zwm56d/%F0%9F%98%80?a=%C3%A9&a=%C3%A9&x=%252F",
        ),
        (
            "https://synthetic.example/a;b:@!$&'()*+,=-._~%2F?q=/?:@!$&'()*+,;=-._~%2f",
            "https://synthetic.example/a;b:@!$&'()*+,=-._~%2F?q=/?:@!$&'()*+,;=-._~%2f",
        ),
    ],
)
def test_ascii_uri_preserves_escapes_boundaries_and_is_idempotent(url, expected):
    original = url
    assert validate_url(url) == expected
    assert validate_url(expected) == expected
    assert url == original
    expected.encode("ascii")


@pytest.mark.parametrize(
    "url",
    ["https://synthetic.example/\ud800", "https://synthetic.example/?x=\udfff", "https://\ud800.example/"],
)
def test_invalid_unicode_has_stable_failure_code_without_original_value(url):
    with pytest.raises(FxfetchError) as exc:
        validate_url(url)
    assert exc.value.code == "invalid_url"
    assert exc.value.message == "URL cannot be safely encoded"
    assert "synthetic" not in exc.value.message


def test_http_sends_encoded_path_query_and_referer_across_redirect(tmp_path):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            requests.append((self.path, self.headers.get("Referer")))
            if self.path.startswith("/redirect"):
                self.send_response(302)
                self.send_header("Location", "/café.png?clé=%2f&clé=é#fragment")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

    class SyntheticLocalClient(HttpClient):
        def _resolve(self, host, port):
            return ("127.0.0.1",)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        base = f"http://synthetic.example:{server.server_port}"
        result = SyntheticLocalClient().fetch(
            base + "/redirect/入口?x=中文&raw=%2f#fragment",
            tmp_path / "body",
            user_agent="synthetic",
            cookie_jar=CookieJar(),
            cancel=threading.Event(),
            referer=base + "/来源?key=中文&raw=%2f",
        )
        assert requests == [
            (
                "/redirect/%E5%85%A5%E5%8F%A3?x=%E4%B8%AD%E6%96%87&raw=%2f",
                base + "/%E6%9D%A5%E6%BA%90?key=%E4%B8%AD%E6%96%87&raw=%2f",
            ),
            (
                "/caf%C3%A9.png?cl%C3%A9=%2f&cl%C3%A9=%C3%A9",
                base + "/%E6%9D%A5%E6%BA%90?key=%E4%B8%AD%E6%96%87&raw=%2f",
            ),
        ]
        assert result.path.read_bytes() == b"ok"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(3)
