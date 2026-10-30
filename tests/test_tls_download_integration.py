"""Real local self-signed TLS through Workflow and the verified evidence ZIP."""

from __future__ import annotations

import hashlib
import json
import ssl
import threading
import zipfile
from collections import Counter
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from test_workflow import apk_bytes

from fxfetch.core.http_client import HttpClient
from fxfetch.core.task_evidence_io import build_task_archive
from fxfetch.core.task_evidence_recorder import TaskEvidenceRecorder
from fxfetch.core.task_evidence_verify import verify_task_archive
from fxfetch.core.workflow import Workflow

HOST = "tls-workflow.synthetic.test"
MAX_BYTES = 64 * 1024 * 1024


@pytest.fixture
def local_tls_download(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "server.pem", tmp_path / "server-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    payload = apk_bytes()
    counts = Counter()
    host_headers, observed_sni = [], []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            assert self.path in {"/entry", "/landing", "/original.apk"}
            counts[self.path] += 1
            host_headers.append(self.headers["Host"])
            if self.path == "/entry":
                self.send_response(302)
                self.send_header("Location", "/landing")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = (b'<!doctype html><html><a href="/original.apk">Android download APK</a></html>'
                    if self.path == "/landing" else payload)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8" if self.path == "/landing"
                             else "application/vnd.android.package-archive")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    context.set_servername_callback(lambda socket, server_name, context: observed_sni.append(server_name))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, cert.public_bytes(serialization.Encoding.DER), payload, counts, host_headers, observed_sni
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def test_real_tls_workflow_download_archive_and_default_strict_isolation(tmp_path, local_tls_download):
    port, der, payload, counts, host_headers, observed_sni = local_tls_download
    entry = f"https://{HOST}:{port}/entry"

    class ExactLocalClient(HttpClient):
        # The only test transport seam: this exact synthetic hostname/port maps
        # to our listener. TLS, SNI, Host, response/body and package validation
        # all use production code; no global DNS or trust modifications.
        def _resolve(self, host, requested_port):
            assert (host, requested_port) == (HOST, port)
            return ("127.0.0.1",)

        def _connect(self, host, requested_port, address, secure, timeout):
            assert (host, requested_port, address, secure) == (HOST, port, "127.0.0.1", True)
            return super()._connect(host, requested_port, address, secure, timeout)

    for label, ignore in (("default-before", False), ("auto-once", True), ("default-after", False)):
        root = tmp_path / label
        recorder = TaskEvidenceRecorder(root)
        recorder.set_context("http", label)
        policy = "auto" if ignore else "strict"
        recorder.append("task_tls_policy", {"tls_policy": policy})
        # Default rounds omit the optional constructor argument entirely.
        options = {"tls_policy": "auto"} if ignore else {}
        client = ExactLocalClient(transport_observer=recorder.observe_transport, **options)
        before_count = sum(counts.values())
        try:
            outcome = Workflow(client).run(entry, root, threading.Event(), recorder.observe_progress)
        finally:
            recorder.close()
        result = json.loads(json.dumps(asdict(outcome), default=str))
        package_result = {key: result[key] for key in ("outcome", "reason_code", "coverage")}
        archive_path = root / "data-package" / "synthetic.zip"
        manifest, digest = build_task_archive(
            root, archive_path, job_id=label, entry_url=entry, package_result=package_result,
            result=result, observation_path=recorder.path, max_bytes=MAX_BYTES,
            tls_policy=policy,
        )
        verified, verified_digest = verify_task_archive(archive_path, max_bytes=MAX_BYTES)
        assert manifest == verified and digest == verified_digest
        assert manifest["tls_policy"] == policy
        with zipfile.ZipFile(archive_path) as bundle:
            observations = [json.loads(line) for line in bundle.read("observations.jsonl").splitlines()]
            assert [row["fields"]["tls_policy"] for row in observations
                    if row["kind"] == "task_tls_policy"] == [policy]
            packages = [item for item in manifest["attachments"] if item["kind"] == "package"]
            certificates = [item for item in manifest["attachments"] if item["kind"] == "certificate"]
            if ignore:
                assert outcome.outcome == "downloaded" and len(outcome.artifacts) == 1
                assert outcome.artifacts[0].path.read_bytes() == payload
                assert sum(counts.values()) - before_count == 3
                assert len(packages) == 1 and len(certificates) == 3
                assert bundle.read(packages[0]["path"]) == payload
                assert packages[0]["sha256"] == hashlib.sha256(payload).hexdigest()
                assert len({item["request_ref"] for item in certificates}) == 3
                fallbacks = {row["fields"]["tls_fallback_id"]: row["fields"] for row in observations
                             if row["kind"] == "tls_verification_fallback"}
                failures = {row["fields"]["tls_fallback_id"]: row["fields"] for row in observations
                            if row["kind"] == "tls_verification_failed"}
                assert len(fallbacks) == len(failures) == 3
                assert manifest["tls_fallback"]["count"] == 3
                for certificate in certificates:
                    assert bundle.read(certificate["path"]) == der
                    assert certificate["sha256"] == hashlib.sha256(der).hexdigest()
                    assert certificate["capture_source"] == "unverified_tls_socket"
                    assert certificate["tls_verification"] == "ignored"
                    assert certificate["association"] == "same_connection"
                    fallback = fallbacks[certificate["tls_fallback_id"]]
                    failure = failures[certificate["tls_fallback_id"]]
                    assert fallback["request_ref"] == failure["request_ref"] == certificate["request_ref"]
                    assert certificate["tls_verify_code"] == 18
                    assert certificate["tls_verify_reason"] == "self_signed_certificate"
                assert [hop["status"] for hop in result["hops"]] == [302, 200, 200]
                assert all(hop["tls_verification"] == "ignored" for hop in result["hops"])
            else:
                assert outcome.outcome == "failed" and outcome.reason_code == "tls_verification_failed"
                assert not packages and not certificates and not outcome.artifacts
                assert sum(counts.values()) == before_count
    assert counts == {"/entry": 1, "/landing": 1, "/original.apk": 1}
    assert host_headers == [f"{HOST}:{port}"] * 3
    assert len(observed_sni) == 8 and set(observed_sni) == {HOST}
