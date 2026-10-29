import hashlib
import io
import ssl
import threading
import time
import zipfile
from datetime import UTC, datetime, timedelta
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from fxfetch.core.errors import FxfetchError
from fxfetch.core.http_client import HttpClient
from fxfetch.core.limits import Limits


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_literal_does_not_call_dns(address):
    def forbidden(host, port):
        pytest.fail("literal IP target attempted DNS")

    assert HttpClient(resolver=forbidden)._resolve(address, 443) == (address,)


@pytest.mark.parametrize("address", [
    "127.0.0.1", "192.168.1.1", "10.1.2.3", "172.16.1.1", "198.18.0.1",
    "169.254.1.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fc00::1",
])
def test_nonpublic_literal_rejected_without_dns(address):
    def forbidden(host, port):
        pytest.fail("nonpublic literal attempted DNS")

    with pytest.raises(FxfetchError) as raised:
        HttpClient(resolver=forbidden)._resolve(address, 443)
    assert raised.value.code == "target_not_public"


class LocalClient(HttpClient):
    def _resolve(self, host, port):
        return ("127.0.0.1",)


@pytest.fixture
def server():
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == "/bad-location-200":
                body = b"body retained despite malformed Location"
                self.send_response(200)
                self.send_header("Location", "http://[")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/bad-redirect":
                self.send_response(302)
                self.send_header("Location", "http://[")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path in ("/redirect-page", "/back-to-page"):
                self.send_response(302)
                self.send_header("Location", "/download-page" if self.path == "/redirect-page" else "/loop-page")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path in ("/download-page", "/valid-package", "/loop-page"):
                content_type = "text/html"
                body = b'<a href="/valid-package" download>Download</a>'
                if self.path == "/loop-page":
                    body = b'<a href="/back-to-page" download>Download</a>'
                if self.path == "/valid-package":
                    archive_bytes = io.BytesIO()
                    with zipfile.ZipFile(archive_bytes, "w") as archive:
                        archive.writestr("AndroidManifest.xml", b"manifest")
                        archive.writestr("classes.dex", b"dex\n035\0")
                    body = archive_bytes.getvalue()
                    content_type = "application/octet-stream"
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/cycle":
                self.send_response(302)
                self.send_header("Location", "/cycle")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path in ("/large-package", "/zip-chunked", "/zip-short"):
                body = b"PK\x03\x04" + b"x" * (2 * 1024 * 1024 if self.path == "/large-package" else 100)
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                if self.path == "/zip-chunked":
                    self.send_header("Transfer-Encoding", "chunked")
                else:
                    self.send_header("Content-Length", str(len(body) + (10 if self.path == "/zip-short" else 0)))
                self.end_headers()
                if self.path == "/zip-chunked":
                    self.wfile.write(f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
                else:
                    self.wfile.write(body)
                if self.path == "/zip-short":
                    self.close_connection = True
                return
            if self.path == "/huge-headers":
                self.send_response(200)
                for index in range(20):
                    self.send_header(f"X-Synthetic-{index}", "x" * 4000)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path == "/chunked":
                self.send_response(200)
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self.wfile.write(b"7\r\npackage\r\n0\r\n\r\n")
                return
            if self.path in ("/zip-unknown", "/oversized-text"):
                body = b"PK\x03\x04" + b"x" * 100 if self.path == "/zip-unknown" else b"<html>" + b"x" * 100
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/cookie")
                self.send_header("Set-Cookie", "test=ok; Path=/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = (
                b"cookie"
                if self.path == "/cookie" and "test=ok" in self.headers.get("Cookie", "")
                else b"package"
            )
            self.send_response(200)
            self.send_header("Content-Length", "99" if self.path == "/short" else str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            if self.path == "/short":
                self.close_connection = True

    service = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    yield f"http://synthetic.test:{service.server_port}"
    service.shutdown()
    service.server_close()
    thread.join()


def test_download_redirect_cookie(server, tmp_path):
    result = LocalClient().fetch(
        server + "/redirect",
        tmp_path / "out",
        user_agent="Synthetic",
        cookie_jar=CookieJar(),
        cancel=threading.Event(),
    )
    assert result.path.read_bytes() == b"cookie"
    assert result.sha256 == hashlib.sha256(b"cookie").hexdigest()
    assert len(result.hops) == 2
    assert result.hops[0].connection_ip == "127.0.0.1"


@pytest.mark.parametrize(
    "route,limits,code",
    [("/short", Limits(), "length_mismatch"), ("/", Limits(max_package_bytes=3), "download_limit")],
)
def test_failure(server, tmp_path, route, limits, code):
    with pytest.raises(FxfetchError) as error:
        LocalClient(limits).fetch(
            server + route,
            tmp_path / "out",
            user_agent="Synthetic",
            cookie_jar=CookieJar(),
            cancel=threading.Event(),
        )
    assert error.value.code == code
    assert not (tmp_path / "out").exists()


def test_cancel_before_dns(tmp_path, monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **kw: pytest.fail("DNS forbidden"))
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(FxfetchError) as error:
        HttpClient().fetch(
            "http://synthetic.test",
            tmp_path / "out",
            user_agent="Synthetic",
            cookie_jar=CookieJar(),
            cancel=cancel,
        )
    assert error.value.code == "cancelled"


def test_chunked_limit_retains_bounded_partial(server, tmp_path):
    with pytest.raises(FxfetchError) as error:
        LocalClient(Limits(max_package_bytes=3)).fetch(
            server + "/chunked",
            tmp_path / "out",
            user_agent="Synthetic",
            cookie_jar=CookieJar(),
            cancel=threading.Event(),
        )
    assert error.value.code == "download_limit"
    assert (tmp_path / "out.partial").read_bytes() == b"pac"
    assert not (tmp_path / "out").exists()


def test_private_target_never_connects(tmp_path, monkeypatch):
    monkeypatch.setattr("socket.socket.connect", lambda *args: pytest.fail("Private TCP forbidden"))
    with pytest.raises(FxfetchError) as error:
        HttpClient().fetch(
            "http://127.0.0.1",
            tmp_path / "out",
            user_agent="Synthetic",
            cookie_jar=CookieJar(),
            cancel=threading.Event(),
        )
    assert error.value.code == "target_not_public"


def test_dns_timeout(tmp_path):
    class SlowClient(HttpClient):
        def _resolve(self, host, port):
            time.sleep(0.2)
            return ("127.0.0.1",)

    with pytest.raises(FxfetchError) as error:
        SlowClient(Limits(connect_timeout=0.05)).fetch(
            "http://synthetic.test",
            tmp_path / "out",
            user_agent="Synthetic",
            cookie_jar=CookieJar(),
            cancel=threading.Event(),
        )
    assert error.value.code == "dns_timeout"


def test_unknown_zip_budget_and_metadata_limit(server, tmp_path):
    client = LocalClient(Limits(max_body_bytes=10, max_package_bytes=200))
    result = client.fetch(
        server + "/zip-unknown",
        tmp_path / "zip",
        user_agent="Synthetic",
        cookie_jar=CookieJar(),
        cancel=threading.Event(),
    )
    assert result.size == 104
    with pytest.raises(FxfetchError) as error:
        client.fetch(
            server + "/oversized-text",
            tmp_path / "text",
            user_agent="Synthetic",
            cookie_jar=CookieJar(),
            cancel=threading.Event(),
        )
    assert error.value.code == "download_limit"
    assert (tmp_path / "text.partial").stat().st_size <= 10


def test_response_header_total_limit(server, tmp_path):
    with pytest.raises(FxfetchError) as error:
        LocalClient().fetch(
            server + "/huge-headers",
            tmp_path / "headers",
            user_agent="Synthetic",
            cookie_jar=CookieJar(),
            cancel=threading.Event(),
        )
    assert error.value.code == "response_header_limit"
    assert error.value.__dict__["hops"][0].status == 200
    assert not (tmp_path / "headers").exists()


def test_tls_sni_hostname_and_der(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic.test")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("synthetic.test")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    observed_sni = []
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            requests.append(self.headers["Host"])
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    context.set_servername_callback(lambda sock, name, ctx: observed_sni.append(name))
    service = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    service.socket = context.wrap_socket(service.socket, server_side=True)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()

    class TrustedTestClient(LocalClient):
        def _tls_context(self):
            return ssl.create_default_context(cafile=str(cert_path))

    try:
        client = TrustedTestClient()
        result = client.fetch(
            f"https://synthetic.test:{service.server_port}/",
            tmp_path / "ok",
            user_agent="Synthetic",
            cookie_jar=CookieJar(),
            cancel=threading.Event(),
        )
        assert observed_sni == ["synthetic.test"]
        assert requests == [f"synthetic.test:{service.server_port}"]
        assert result.hops[0].tls_der_sha256 == certificate.fingerprint(hashes.SHA256()).hex()
        with pytest.raises(FxfetchError) as error:
            client.fetch(
                f"https://wrong.synthetic.test:{service.server_port}/",
                tmp_path / "bad",
                user_agent="Synthetic",
                cookie_jar=CookieJar(),
                cancel=threading.Event(),
            )
        assert error.value.code == "tls_verification_failed"
        assert len(requests) == 1
        with pytest.raises(FxfetchError) as error:
            LocalClient().fetch(
                f"https://synthetic.test:{service.server_port}/",
                tmp_path / "untrusted",
                user_agent="Synthetic",
                cookie_jar=CookieJar(),
                cancel=threading.Event(),
            )
        assert error.value.code == "tls_verification_failed"
        assert len(requests) == 1
    finally:
        service.shutdown()
        service.server_close()
        thread.join()


def test_http_events_observe_redirect_and_plain_response_without_package_claim(server, tmp_path):
    events = []
    LocalClient().fetch(server + "/redirect", tmp_path / "response", user_agent="Synthetic",
                        cookie_jar=CookieJar(), cancel=threading.Event(), on_event=events.append)
    assert [e["event"] for e in events].count("request") == 2
    redirect = next(e for e in events if e["event"] == "redirect")
    assert redirect["from_url"] == server + "/redirect"
    assert redirect["to_url"] == server + "/cookie"
    assert redirect["status"] == 302
    assert not any(e["event"] in ("download_started", "file_verified") for e in events)
    assert events[-1]["event"] == "response_complete"


@pytest.mark.parametrize("route,known_total", [("/large-package", True), ("/zip-chunked", False)])
def test_http_package_progress_is_throttled_and_requires_actual_zip(server, tmp_path, route, known_total):
    events = []
    stamps = []
    def record(event):
        events.append(event)
        if event["event"] == "download_progress":
            stamps.append(time.monotonic())
    response = LocalClient().fetch(server + route, tmp_path / "response", user_agent="Synthetic",
                                   cookie_jar=CookieJar(), cancel=threading.Event(), on_event=record)
    assert any(e["event"] == "download_started" for e in events)
    progress = [e for e in events if e["event"] == "download_progress"]
    assert progress[0]["complete"] is False
    assert progress[-1]["complete"] is True
    assert progress[-1]["received_bytes"] == response.size
    if known_total:
        assert progress[-1]["total_bytes"] == response.size
        assert progress[-1]["percent"] == 100.0
    else:
        assert all(e["total_bytes"] is None and "percent" not in e for e in progress)
    # Interior events are one second apart; the final receipt is always emitted.
    assert all(right - left >= 0.99 for left, right in zip(stamps[:-2], stamps[1:-1], strict=False))
    assert not any(e["event"] == "file_verified" for e in events)


def test_http_truncated_zip_progress_never_claims_complete_or_verified(server, tmp_path):
    events = []
    observations = []
    with pytest.raises(FxfetchError) as error:
        LocalClient().fetch(server + "/zip-short", tmp_path / "response", user_agent="Synthetic",
                            cookie_jar=CookieJar(), cancel=threading.Event(), on_event=events.append,
                            on_transport_event=observations.append)
    assert error.value.code == "length_mismatch"
    progress = [e for e in events if e["event"] == "download_progress"]
    assert progress[-1]["received_bytes"] == 104
    assert all(e["complete"] is False for e in progress)
    assert not any(e["event"] in ("response_complete", "file_verified") for e in events)
    prefix = next(e for e in observations if e["kind"] == "response_prefix_saved")
    assert prefix["package_stream"] is True
    assert prefix["complete"] is False
    assert prefix["representation"] == "http_response_prefix"


def test_http_redirect_cycle_stops_before_second_request(server, tmp_path):
    events = []
    with pytest.raises(FxfetchError) as error:
        LocalClient().fetch(server + "/cycle", tmp_path / "response", user_agent="Synthetic",
                            cookie_jar=CookieJar(), cancel=threading.Event(), on_event=events.append)
    assert error.value.code == "redirect_cycle"
    assert sum(e["event"] == "request" for e in events) == 1


def test_malformed_location_on_http_200_does_not_break_fetch(server, tmp_path):
    response = LocalClient().fetch(
        server + "/bad-location-200",
        tmp_path / "body",
        user_agent="Synthetic",
        cookie_jar=CookieJar(),
        cancel=threading.Event(),
    )
    assert response.path.read_bytes() == b"body retained despite malformed Location"


def test_invalid_redirect_retains_raw_location_observation(server, tmp_path):
    observed = []
    with pytest.raises((FxfetchError, ValueError)):
        LocalClient().fetch(
            server + "/bad-redirect",
            tmp_path / "body",
            user_agent="Synthetic",
            cookie_jar=CookieJar(),
            cancel=threading.Event(),
            on_transport_event=observed.append,
        )
    response = next(row for row in observed if row["kind"] == "response_observed")
    assert response["location_raw"] == "http://["


def test_real_transport_workflow_event_chain_and_shared_redirect_limit(server, tmp_path):
    from fxfetch.core.workflow import Workflow
    events = []
    result = Workflow(LocalClient()).run(server + "/redirect-page", tmp_path / "complete",
                                         threading.Event(), events.append)
    assert result.outcome == "downloaded"
    assert sum(e["event"] == "request" for e in events) == 3
    assert [e["mechanism"] for e in events if e["event"] == "redirect"] == ["http", "static"]
    assert events[-1]["event"] == "file_verified"
    assert all(e["chain"] == "android" for e in events)
    limited = []
    result = Workflow(LocalClient(), Limits(max_redirects=1)).run(
        server + "/redirect-page", tmp_path / "limited", threading.Event(), limited.append)
    assert result.reason_code == "redirect_limit"
    assert sum(e["event"] == "request" for e in limited) == 2
    assert not any(e["event"] == "file_verified" for e in limited)


def test_workflow_http_redirect_to_prior_page_stops_before_revisit(server, tmp_path):
    from fxfetch.core.workflow import Workflow
    events = []
    result = Workflow(LocalClient()).run(server + "/loop-page", tmp_path,
                                         threading.Event(), events.append)
    assert result.reason_code == "discovery_cycle"
    assert sum(e["event"] == "request" for e in events) == 2
