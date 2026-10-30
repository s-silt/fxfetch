"""HTTP certificate-only fallback, never a generic TLS/network retry switch."""

import json
import ssl
import threading
import time
from http.cookiejar import CookieJar

import pytest
from test_tls_evidence import BODY, LocalTLSClient, fetch, tls_server

from fxfetch.core.errors import FxfetchError
from fxfetch.core.http_client import HttpClient
from fxfetch.core.limits import Limits

__all__ = ["tls_server"]


def verification_error():
    error = ssl.SSLCertVerificationError(1, "secret remote text")
    error.verify_code = 18
    error.verify_message = "secret remote verification detail"
    return error


class FailingHandshakeClient(HttpClient):
    def __init__(self, failure, *, cancel=None, delay=0, **kwargs):
        super().__init__(**kwargs)
        self.failure, self.cancel, self.delay = failure, cancel, delay
        self.calls = []

    def _resolve(self, host, port):
        assert host == "tls.synthetic.test" and port == 443
        return ("93.184.216.34", "93.184.216.35")

    def _connect(self, host, port, address, secure, timeout):
        self.calls.append(("strict", host, port, address))
        if self.delay:
            time.sleep(self.delay)
        if self.cancel:
            self.cancel.set()
        raise self.failure

    def _connect_unverified(self, host, port, address, timeout):
        self.calls.append(("fallback", host, port, address))
        raise ssl.SSLError("synthetic retry handshake failed")


def fetch_failure(client, tmp_path, cancel=None):
    with pytest.raises(FxfetchError) as caught:
        client.fetch("https://tls.synthetic.test/", tmp_path / "body", user_agent="Synthetic",
                     cookie_jar=CookieJar(), cancel=cancel or threading.Event())
    return caught.value


@pytest.mark.parametrize("error", [ssl.SSLError("generic TLS"), TimeoutError("timeout"), OSError("network")])
def test_auto_never_relaxes_generic_network_or_handshake_errors(tmp_path, error):
    events = []
    client = FailingHandshakeClient(error, tls_policy="auto", transport_observer=events.append)
    fetch_failure(client, tmp_path)
    assert all(call[0] == "strict" for call in client.calls)
    assert not any(row["kind"] == "tls_verification_fallback" for row in events)


def test_certificate_failure_retries_once_same_ip_and_sanitizes_metadata(tmp_path):
    events = []
    client = FailingHandshakeClient(verification_error(), tls_policy="auto", transport_observer=events.append)
    error = fetch_failure(client, tmp_path)
    assert error.code == "tls_handshake_failed"
    assert client.calls == [("strict", "tls.synthetic.test", 443, "93.184.216.34"),
                            ("fallback", "tls.synthetic.test", 443, "93.184.216.34")]
    failures = [row for row in events if row["kind"] == "tls_verification_failed"]
    fallbacks = [row for row in events if row["kind"] == "tls_fallback_failed"]
    assert len(failures) == len(fallbacks) == 1
    assert failures[0]["tls_fallback_id"] == fallbacks[0]["tls_fallback_id"]
    assert failures[0]["tls_verify_code"] == 18 and failures[0]["tls_verify_reason"] == "self_signed_certificate"
    assert "secret" not in json.dumps(events)
    assert not any(row["kind"] == "tls_verification_fallback" for row in events)
    assert any(row.get("reason_code") == "tls_fallback_handshake_failed" for row in events)
    assert not (tmp_path / "body").exists()


@pytest.mark.parametrize("mode", ["strict", "cancel", "deadline"])
def test_policy_cancel_and_connection_budget_prevent_fallback(tmp_path, mode):
    cancel = threading.Event()
    client = FailingHandshakeClient(
        verification_error(), tls_policy="strict" if mode == "strict" else "auto",
        cancel=cancel if mode == "cancel" else None, delay=.03 if mode == "deadline" else 0,
        limits=Limits(connect_timeout=.01) if mode == "deadline" else Limits(),
    )
    error = fetch_failure(client, tmp_path, cancel)
    assert error.code == {"strict": "tls_verification_failed", "cancel": "cancelled", "deadline": "network_timeout"}[mode]
    assert len(client.calls) == 1 and client.calls[0][0] == "strict"


def test_auto_trusted_socket_never_becomes_ignored(tls_server, tmp_path):
    port, certificate, _, counts = tls_server
    events = []
    client = LocalTLSClient(certificate, tls_policy="auto", transport_observer=events.append)
    response = fetch(client, port, tmp_path / "trusted.body", "/redirect")
    assert response.path.read_bytes() == BODY and counts == {"/redirect": 1, "/body": 1}
    assert all(hop.tls_verification == "verified" for hop in response.hops)
    assert not any(row["kind"] == "tls_verification_fallback" for row in events)
    originals = [row for row in events if row["kind"] == "tls_certificate_saved"]
    assert len(originals) == 2
    assert all(row["capture_source"] == "verified_tls_socket" and row["tls_verification"] == "verified" for row in originals)
    assert all("tls_fallback_id" not in row for row in originals)


def test_policy_validation_and_compatibility_are_strict_first():
    for invalid in (None, False, {}, [], "off", "ignore"):
        with pytest.raises(ValueError):
            HttpClient(tls_policy=invalid)
    for client in (HttpClient(tls_policy="auto"), HttpClient(ignore_tls_errors=True)):
        assert client.tls_policy == "auto"
        assert client._tls_context().verify_mode == ssl.CERT_REQUIRED
        assert client._tls_context().check_hostname is True


@pytest.mark.parametrize("invalid_first", [True, False])
def test_redirect_after_fallback_restarts_strict_and_does_not_inherit_risk(tls_server, tmp_path, invalid_first):
    port, certificate, _, counts = tls_server
    events = []

    class ChangingTrustClient(LocalTLSClient):
        strict_contexts = 0

        def _tls_context(self):
            self.strict_contexts += 1
            # Test-only trust changes let one redirect chain contain both an
            # invalid and a valid strict handshake, without global CA changes.
            trusted = (self.strict_contexts > 1) == invalid_first
            return ssl.create_default_context(cafile=str(self.certificate) if trusted else None)

    client = ChangingTrustClient(certificate, tls_policy="auto", transport_observer=events.append)
    response = fetch(client, port, tmp_path / "mixed.body", "/redirect")
    assert client.strict_contexts == 2
    assert counts == {"/redirect": 1, "/body": 1}
    assert [hop.tls_verification for hop in response.hops] == (["ignored", "verified"] if invalid_first else ["verified", "ignored"])
    saved = [row for row in events if row["kind"] == "tls_certificate_saved"]
    assert [row["capture_source"] for row in saved] == (["unverified_tls_socket", "verified_tls_socket"]
                                                      if invalid_first else ["verified_tls_socket", "unverified_tls_socket"])
    assert all(("tls_fallback_id" in row) == (row["tls_verification"] == "ignored") for row in saved)


@pytest.mark.parametrize("tls_server", ["expired"], indirect=True)
def test_real_expired_trusted_certificate_records_specific_failure_then_retries(tls_server, tmp_path):
    port, certificate, der, counts = tls_server
    events = []
    client = LocalTLSClient(certificate, tls_policy="auto", transport_observer=events.append)
    response = fetch(client, port, tmp_path / "expired.body")
    assert response.path.read_bytes() == BODY and counts == {"/body": 1}
    fallback = next(row for row in events if row["kind"] == "tls_verification_fallback")
    assert fallback["tls_verify_code"] == 10 and fallback["tls_verify_reason"] == "certificate_expired"
    saved = next(row for row in events if row["kind"] == "tls_certificate_saved")
    assert saved["tls_fallback_id"] == fallback["tls_fallback_id"]
    assert saved["tls_verification"] == "ignored" and saved["size"] == len(der)
