"""Certificate originals from one verified synthetic TLS connection; never external DNS."""

from __future__ import annotations

import hashlib
import json
import ssl
import threading
import time
import zipfile
from collections import Counter
from datetime import UTC, datetime, timedelta
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from fxfetch.core.errors import FxfetchError
from fxfetch.core.http_client import HttpClient
from fxfetch.core.limits import Limits
from fxfetch.core.task_evidence import finalize_package
from fxfetch.core.task_evidence_recorder import TaskEvidenceRecorder
from fxfetch.core.task_evidence_verify import verify_task_archive
from fxfetch.core.tls_evidence import MAX_CERTIFICATE_BYTES, save_leaf_der
from fxfetch.core.web_evidence_schema import EvidenceError

BODY = b"synthetic fully received body"


@pytest.fixture
def tls_server(tmp_path, request):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tls.synthetic.test")])
    now = datetime.now(UTC)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(days=1))
                   .not_valid_after(now - timedelta(minutes=1) if getattr(request, "param", None) == "expired"
                                    else now + timedelta(days=1))
                   .add_extension(x509.SubjectAlternativeName([
                       x509.DNSName("tls.synthetic.test"), x509.DNSName("localhost")]), False)
                   .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "certificate.pem", tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    counts: Counter[str] = Counter()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            counts[self.path] += 1
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/body")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, cert_path, certificate.public_bytes(serialization.Encoding.DER), counts
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


class LocalTLSClient(HttpClient):
    def __init__(self, certificate, *args, trusted=True, **kwargs):
        super().__init__(*args, **kwargs)
        self.certificate, self.trusted = certificate, trusted

    def _resolve(self, host, port):
        assert host == "tls.synthetic.test"
        return ("127.0.0.1",)

    def _tls_context(self):
        # The trust anchor is confined to this test client's SSLContext.
        return ssl.create_default_context(cafile=str(self.certificate) if self.trusted else None)


def fetch(client, port, target, route="/body"):
    return client.fetch(f"https://tls.synthetic.test:{port}{route}", target,
                        user_agent="Synthetic TLS test", cookie_jar=CookieJar(),
                        cancel=threading.Event())


def test_verified_leaf_is_original_deduplicated_and_bound_per_request(tls_server, tmp_path):
    port, certificate, der, counts = tls_server
    root = tmp_path / "capture"
    recorder = TaskEvidenceRecorder(root)
    try:
        client = LocalTLSClient(certificate, transport_observer=recorder)
        response = fetch(client, port, root / "web" / "body", "/redirect")
        assert response.path.read_bytes() == BODY
        rows = [json.loads(line) for line in recorder.path.read_text().splitlines()]
        saved = [r["fields"] for r in rows if r["kind"] == "tls_certificate_saved"]
        responses = {r["fields"]["request_ref"]: r["fields"] for r in rows if r["kind"] == "response_observed"}
        assert len(saved) == 2 and len({r["request_ref"] for r in saved}) == 2
        assert len({r["path"] for r in saved}) == 1
        assert len(list(root.rglob("*.der"))) == 1
        for item in saved:
            assert (root / item["path"]).read_bytes() == der
            assert item["sha256"] == item["tls_der_sha256"] == hashlib.sha256(der).hexdigest()
            assert responses[item["request_ref"]]["tls_der_sha256"] == item["sha256"]
            assert item["source_url"] == responses[item["request_ref"]]["url"]
            assert item["connection_ip"] == "127.0.0.1" and item["complete"] is True
            assert item["association"] == "same_connection" and item["cert_role"] == "leaf"
            assert item["capture_source"] == "verified_tls_socket"
        assert counts == {"/redirect": 1, "/body": 1}
    finally:
        recorder.close()
    metadata = finalize_package(
        root, job_id="synthetic-tls", entry_url=f"https://tls.synthetic.test:{port}/redirect",
        terminal_result={"outcome": "failed", "reason_code": "synthetic_complete", "coverage": "partial"},
        observation_path=recorder.path, max_bytes=16 * 1024 * 1024,
    )
    assert metadata["state"] == "ready", metadata
    archive_path = root / "data-package" / metadata["filename"]
    manifest, _ = verify_task_archive(archive_path, max_bytes=16 * 1024 * 1024)
    attachments = [item for item in manifest["attachments"] if item["kind"] == "certificate"]
    assert len(attachments) == 2 and len({item["request_ref"] for item in attachments}) == 2
    with zipfile.ZipFile(archive_path) as archive:
        for item in attachments:
            assert archive.read(item["path"]) == der
            assert item["sha256"] == hashlib.sha256(der).hexdigest()


def test_opt_in_unverified_socket_is_task_local_and_keeps_original(tls_server, tmp_path):
    port, _, der, counts = tls_server

    class ResolverOnlyClient(HttpClient):
        def _resolve(self, host, port):
            assert host == "tls.synthetic.test"
            return ("127.0.0.1",)

    records = []
    strict = ResolverOnlyClient()
    with pytest.raises(FxfetchError) as rejected:
        fetch(strict, port, tmp_path / "strict.body")
    assert rejected.value.code == "tls_verification_failed" and not counts
    permissive = ResolverOnlyClient(ignore_tls_errors=True, transport_observer=records.append)
    response = fetch(permissive, port, tmp_path / "ignored.body")
    assert response.path.read_bytes() == BODY and counts == {"/body": 1}
    saved = [item for item in records if item["kind"] == "tls_certificate_saved"]
    assert len(saved) == 1
    assert Path(saved[0]["path"]).read_bytes() == der
    assert saved[0]["capture_source"] == "unverified_tls_socket"
    assert saved[0]["association"] == "same_connection" and saved[0]["tls_verification"] == "ignored"
    assert saved[0]["ignore_tls_errors"] is True
    failures = [item for item in records if item["kind"] == "tls_verification_failed"]
    fallbacks = [item for item in records if item["kind"] == "tls_verification_fallback"]
    assert len(failures) == len(fallbacks) == 1
    assert failures[0]["tls_verification"] == "required"
    assert failures[0]["tls_fallback_id"] == fallbacks[0]["tls_fallback_id"] == saved[0]["tls_fallback_id"]
    assert saved[0]["tls_verify_code"] == 18 and saved[0]["tls_verify_reason"] == "self_signed_certificate"
    assert permissive._tls_context().verify_mode == ssl.CERT_REQUIRED
    assert response.hops[0].tls_der_sha256 == hashlib.sha256(der).hexdigest()
    assert response.hops[0].tls_verification == "ignored"
    # A fresh default client remains strict, as does the earlier instance.
    for index, client in enumerate((ResolverOnlyClient(), strict)):
        assert client._tls_context().verify_mode == ssl.CERT_REQUIRED
        assert client._tls_context().check_hostname is True
        with pytest.raises(FxfetchError) as rejected:
            fetch(client, port, tmp_path / f"strict-after-{index}.body")
        assert rejected.value.code == "tls_verification_failed"
    assert counts == {"/body": 1}


def test_ignore_tls_errors_retains_public_destination_guard_and_requires_bool(tmp_path):
    for invalid in ("true", "false", 1, None):
        with pytest.raises(ValueError):
            HttpClient(ignore_tls_errors=invalid)
    client = HttpClient(ignore_tls_errors=True)
    with pytest.raises(FxfetchError) as rejected:
        client.fetch("https://127.0.0.1/private", tmp_path / "body", user_agent="Synthetic",
                     cookie_jar=CookieJar(), cancel=threading.Event())
    assert rejected.value.code == "target_not_public"
    assert not (tmp_path / "body").exists()


@pytest.mark.parametrize("mode", ["disk_failure", "no_remaining_budget"])
def test_certificate_gap_does_not_lose_completed_body(tls_server, tmp_path, monkeypatch, mode):
    port, certificate, _, counts = tls_server
    events = []
    if mode == "disk_failure":
        def fail(*args, **kwargs):
            raise OSError("synthetic disk failure")
        monkeypatch.setattr("fxfetch.core.http_client.save_leaf_der", fail)
    client = LocalTLSClient(certificate, Limits(max_package_bytes=len(BODY)) if mode == "no_remaining_budget" else Limits(),
                            transport_observer=events.append)
    response = fetch(client, port, tmp_path / "capture" / "body")
    assert response.path.read_bytes() == BODY and response.sha256 == hashlib.sha256(BODY).hexdigest()
    assert any(e["kind"] == "gap" and e["code"] == "tls_certificate_not_captured" for e in events)
    assert not any(e["kind"] == "tls_certificate_saved" for e in events)
    assert not list((tmp_path / "capture").rglob("*.der")) and counts == {"/body": 1}


def test_untrusted_tls_never_saves_certificate_as_verified(tls_server, tmp_path):
    port, certificate, _, counts = tls_server
    events = []
    with pytest.raises(FxfetchError) as error:
        fetch(LocalTLSClient(certificate, trusted=False, transport_observer=events.append),
              port, tmp_path / "capture" / "body")
    assert error.value.code == "tls_verification_failed" and not counts
    assert not any(e["kind"] == "tls_certificate_saved" for e in events)
    assert any(e.get("reason_code") == "tls_certificate_unverified" for e in events)
    assert not list((tmp_path / "capture").rglob("*.der"))


def test_certificate_storage_obeys_full_task_budget_and_existing_content(tmp_path):
    root = tmp_path / "capture"
    root.mkdir()
    (root / "body").write_bytes(b"body")
    der = b"synthetic unit-only original bytes"
    with pytest.raises(EvidenceError, match="tls_certificate_storage_limit"):
        save_leaf_der(root / "tls", der, root=root, max_task_bytes=4, remaining_bytes=999)
    metadata, written = save_leaf_der(root / "tls", der, root=root, max_task_bytes=999, remaining_bytes=999)
    assert written == len(der)
    duplicate, written = save_leaf_der(root / "tls", der, root=root, max_task_bytes=999, remaining_bytes=0)
    assert written == 0 and duplicate == metadata
    Path(str(metadata["path"])).write_bytes(b"x" * len(der))
    with pytest.raises(EvidenceError, match="tls_certificate_existing_mismatch"):
        save_leaf_der(root / "tls", der, root=root, max_task_bytes=999, remaining_bytes=999)
    with pytest.raises(EvidenceError, match="tls_certificate_size_limit"):
        save_leaf_der(root / "tls", b"x" * (MAX_CERTIFICATE_BYTES + 1), root=root,
                      max_task_bytes=999999, remaining_bytes=999999)


def test_bound_observer_method_uses_job_root_for_budget(tls_server, tmp_path):
    port, certificate, _, _ = tls_server
    root = tmp_path / "capture"
    recorder = TaskEvidenceRecorder(root)
    (root / "other-material.bin").write_bytes(b"x" * 8192)
    try:
        client = LocalTLSClient(certificate, Limits(max_task_bytes=4096),
                                transport_observer=recorder.observe_transport)
        response = fetch(client, port, root / "web" / "body")
        assert response.path.read_bytes() == BODY
        rows = [json.loads(line) for line in recorder.path.read_text().splitlines()]
        assert not any(row["kind"] == "tls_certificate_saved" for row in rows)
        assert any(row["fields"].get("reason_code") == "tls_certificate_storage_limit" for row in rows)
        assert not list(root.rglob("*.der"))
    finally:
        recorder.close()


def test_certificate_write_skipped_after_cancellation_and_deadline(tls_server, tmp_path):
    port, certificate, der, _ = tls_server
    cancel, events = threading.Event(), []

    def observe(event):
        events.append(event)
        if event["kind"] == "response_body_saved":
            cancel.set()

    destination = tmp_path / "capture" / "body"
    response = LocalTLSClient(certificate, transport_observer=observe).fetch(
        f"https://tls.synthetic.test:{port}/body", destination,
        user_agent="Synthetic TLS test", cookie_jar=CookieJar(), cancel=cancel,
    )
    assert response.path.read_bytes() == BODY
    assert any(e.get("reason_code") == "tls_certificate_capture_deadline" for e in events)
    assert not list(destination.parent.rglob("*.der"))
    with pytest.raises(EvidenceError, match="tls_certificate_capture_deadline"):
        save_leaf_der(destination.parent / "tls", der, root=destination.parent,
                      max_task_bytes=999999, remaining_bytes=999999, deadline=time.monotonic() - 1)
    assert not list(destination.parent.rglob("*.der"))
