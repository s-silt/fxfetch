"""Tests-only private-profile trust and synthetic local HTTPS, never OS trust.

Schema references (Chrome ServerCertificate database version 1):
https://chromium.googlesource.com/chromium/src/+/HEAD/components/server_certificate_database/server_certificate_database.cc
https://chromium.googlesource.com/chromium/src/+/HEAD/components/server_certificate_database/server_certificate_database.proto
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import sqlite3
import ssl
import threading
import zipfile
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

RUNTIME_TEMP = Path(__file__).resolve().parents[1] / ".runtime" / "temp"
CHROME_ARGS = [
    "--remote-debugging-port=0", "--remote-debugging-address=127.0.0.1",
    "--disable-background-networking", "--disable-component-update", "--disable-quic",
    "--no-proxy-server",
    "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1",
]


def private_directory(path: Path) -> Path:
    path = path.resolve()
    path.relative_to(RUNTIME_TEMP.resolve())
    path.mkdir(parents=True, exist_ok=True)
    return path


def create_trusted_profile(profile: Path, root_der: bytes, *, additional_roots: tuple[bytes, ...] = ()) -> Path:
    """Create a new offline profile database; never edit an existing profile."""
    profile = profile.resolve()
    profile.relative_to(RUNTIME_TEMP.resolve())
    if profile.exists():
        raise ValueError("Refusing to change an existing Chrome profile")
    (profile / "Default").mkdir(parents=True)
    db_path = profile / "Default" / "ServerCertificate"
    with sqlite3.connect(db_path) as database:
        database.execute("CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)")
        database.executemany("INSERT INTO meta VALUES(?,?)", [("version", "1"), ("last_compatible_version", "1")])
        database.execute("CREATE TABLE certificates(sha256hash_hex TEXT PRIMARY KEY, der_cert BLOB NOT NULL, trust_settings BLOB NOT NULL)")
        # CertificateMetadata.trust (field 1), CertificateTrust.trust_type=TRUSTED(3).
        metadata = b"\x0a\x02\x08\x03"
        for der in (root_der, *additional_roots):
            database.execute("INSERT INTO certificates VALUES(?,?,?)", (hashlib.sha256(der).hexdigest(), der, metadata))
    return db_path


def _issue(subject, issuer, public_key, signer, *, ca: bool, path_length: int | None = None):
    now = datetime.now(UTC)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(public_key).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
               .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                           key_encipherment=not ca, data_encipherment=False,
                                           key_agreement=False, key_cert_sign=ca, crl_sign=ca,
                                           encipher_only=None, decipher_only=None), critical=True))
    if not ca:
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]), critical=False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    return builder.sign(signer, hashes.SHA256())


@dataclass
class SyntheticTLS:
    origin: str
    certificates: tuple[bytes, ...]
    apk: bytes
    counts: Counter


@contextmanager
def trusted_tls_server(directory: Path, *, blocked_redirect: str | None = None, embedded_origin: str | None = None):
    for local_url in (blocked_redirect, embedded_origin):
        if local_url is None:
            continue
        destination = urlsplit(local_url)
        if (destination.scheme != "https" or destination.hostname not in {"localhost", "127.0.0.1"}
                or destination.port is None or destination.username or destination.password):
            raise ValueError("Synthetic redirect must point to a local TLS canary")
    directory = private_directory(directory)
    keys = [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(3)]
    names = [x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])
             for value in ("Synthetic Profile Root " + directory.name[:24],
                           "Synthetic Intermediate " + directory.name[:24], "localhost")]
    root = _issue(names[0], names[0], keys[0].public_key(), keys[0], ca=True, path_length=1)
    intermediate = _issue(names[1], names[0], keys[1].public_key(), keys[0], ca=True, path_length=0)
    leaf = _issue(names[2], names[1], keys[2].public_key(), keys[1], ca=False)
    certificates = (leaf, intermediate, root)
    chain_path = directory / "server-chain.pem"
    key_path = directory / "server-key.pem"
    chain_path.write_bytes(b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in certificates[:2]))
    key_path.write_bytes(keys[2].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"synthetic manifest")
        archive.writestr("classes.dex", b"dex\n035\0" + bytes(104))
    apk = package.getvalue()
    counts: Counter[str] = Counter()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            counts[self.path] += 1
            if self.path == "/redirect-blocked" and blocked_redirect is not None:
                self.send_response(302)
                self.send_header("Location", blocked_redirect)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path == "/app.apk":
                body, media = apk, "application/vnd.android.package-archive"
            elif self.path in {"/timing", "/download"}:
                body = (b"<!doctype html><title>Synthetic trusted TLS</title><link rel='icon' href='data:,'><p>Local TLS body.</p>"
                        b"<a href='/app.apk'>Download APK</a>")
                media = "text/html"
            elif self.path == "/iframe-download" and embedded_origin is not None:
                body = ("<!doctype html><title>Trusted iframe</title><link rel='icon' href='data:,'>"
                        "<a id='download'>Download APK</a><iframe src='" + embedded_origin + "/frame' "
                        "onload=\"document.getElementById('download').href='/app.apk'\"></iframe>").encode()
                media = "text/html"
            elif self.path == "/frame":
                body, media = b"<!doctype html><title>Trusted child frame</title><p>Synthetic frame.</p>", "text/html"
            elif self.path == "/favicon.ico":
                body, media = b"", "image/x-icon"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(chain_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield SyntheticTLS(f"https://localhost:{server.server_port}",
                           tuple(cert.public_bytes(serialization.Encoding.DER) for cert in certificates), apk, counts)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        key_path.unlink(missing_ok=True)
