"""Controlled CDP-only certificate paths; no browser, sockets or target fixtures."""

import asyncio
import base64
import hashlib
import time
from datetime import UTC, datetime, timedelta
from threading import Event

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from fxfetch.core.browser_tls_evidence import BrowserTLSCapture, canonical_origin


@pytest.fixture(scope="module")
def chain():
    key = ec.generate_private_key(ec.SECP256R1())
    result = []
    for serial in range(1, 4):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"synthetic-{serial}.test")])
        now = datetime.now(UTC)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(serial)
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                .sign(key, hashes.SHA256()))
        result.append(cert.public_bytes(serialization.Encoding.DER))
    return result


def reply(chain):
    return {"tableNames": [base64.b64encode(der).decode("ascii") for der in chain]}


def response(url="https://synthetic.test/path", session="session", ref="request"):
    return {"url": url, "status": 200, "session_id": session, "target_id": "target",
            "request_ref": ref, "observed_at": "2026-01-01T00:00:00.000Z"}


class FakeMux:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = []
        self.blocked = False

    async def send(self, session, method, params):
        self.calls.append((session, method, params))
        assert method == "Network.getCertificate" and set(params) == {"origin"}
        if self.blocked:
            await asyncio.sleep(10)
        item = self.replies.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def collector(tmp_path, mux, *, cancel=None, deadline=None, remaining=9999999):
    events, charged = [], []
    value = BrowserTLSCapture(
        output_dir=tmp_path, root=tmp_path, max_task_bytes=9999999,
        deadline=deadline or time.monotonic() + 10, cancel=cancel or Event(), send=mux.send,
        emit=lambda kind, fields: events.append({"kind": kind, **fields}),
        remaining_bytes=lambda: remaining - sum(charged), reserve_bytes=charged.append,
    )
    return value, events, charged


def test_complete_original_chain_is_deferred_origin_scoped_and_deduplicated(tmp_path, chain):
    mux = FakeMux(reply(chain))
    capture, events, charged = collector(tmp_path, mux)
    record = response("https://SYNTHETIC.test:443/path")
    capture.observe_response(record)
    capture.observe_response(response("https://synthetic.test/other", ref="other"))
    assert mux.calls == [] and not events and not list(tmp_path.rglob("*.der"))
    asyncio.run(capture.finish())
    saved = [e for e in events if e["kind"] == "tls_certificate_saved"]
    assert len(mux.calls) == 1 and len(saved) == 3
    assert mux.calls[0][2] == {"origin": "https://synthetic.test"}
    for index, event in enumerate(saved):
        assert (tmp_path / event["path"]).read_bytes() == chain[index]
        assert event["sha256"] == event["tls_der_sha256"] == hashlib.sha256(chain[index]).hexdigest()
        assert event["association"] == "origin_snapshot"
        assert event["request_association"] == "observation_trigger_only"
        assert event["capture_source"] == "chrome_cdp_network_get_certificate"
        assert event["chain_complete"] is True and event["chain_length"] == 3 and event["chain_index"] == index
        assert event["cert_role"] == ("leaf" if index == 0 else "chain_member")
        assert event["observed_at"] == record["observed_at"] and event["captured_at"] >= event["observed_at"]
    assert sum(charged) == sum(map(len, chain)) and record["tls_certificate_capture"] == "captured"
    asyncio.run(capture.finish())
    assert len(mux.calls) == 1 and len(events) == 3


def test_empty_origin_cache_retried_once_after_released_response(tmp_path, chain):
    mux = FakeMux({"tableNames": []}, reply(chain))
    capture, events, _ = collector(tmp_path, mux)
    capture.observe_response(response())
    asyncio.run(capture.finish())
    assert len(mux.calls) == 2
    assert len([e for e in events if e["kind"] == "tls_certificate_saved"]) == 3


@pytest.mark.parametrize("value,reason,calls", [
    ({"tableNames": []}, "browser_tls_certificate_empty", 2),
    ({"tableNames": "invalid"}, "browser_tls_chain_invalid", 1),
    (RuntimeError("synthetic unsupported method"), "browser_tls_query_unavailable", 1),
])
def test_unavailable_certificate_is_explicit_gap_only(tmp_path, value, reason, calls):
    mux = FakeMux(value, value)
    capture, events, _ = collector(tmp_path, mux)
    record = response()
    capture.observe_response(record)
    asyncio.run(capture.finish())
    assert len(mux.calls) == calls and not list(tmp_path.rglob("*.der"))
    assert events[0]["kind"] == "gap" and events[0]["code"] == "tls_certificate_not_captured"
    assert events[0]["reason_code"] == reason and record["tls_certificate_capture"] == "not_captured"


def test_bad_chain_members_preserve_valid_original_and_source_indices(tmp_path, chain):
    mux = FakeMux({"tableNames": ["not-base64!", base64.b64encode(b"invalid DER").decode(),
                                 base64.b64encode(chain[2]).decode()]})
    capture, events, _ = collector(tmp_path, mux)
    capture.observe_response(response())
    asyncio.run(capture.finish())
    saved = [e for e in events if e["kind"] == "tls_certificate_saved"]
    assert len(saved) == 1 and saved[0]["chain_index"] == 2 and saved[0]["chain_length"] == 3
    assert saved[0]["chain_complete"] is False and saved[0]["cert_role"] == "chain_member"
    assert (tmp_path / saved[0]["path"]).read_bytes() == chain[2]
    assert events[-1]["code"] == "tls_certificate_chain_partial"


def test_chain_count_limit_retains_first_eight_with_partial_marker(tmp_path, chain):
    mux = FakeMux(reply([chain[0]] * 10))
    capture, events, charged = collector(tmp_path, mux)
    capture.observe_response(response())
    asyncio.run(capture.finish())
    saved = [e for e in events if e["kind"] == "tls_certificate_saved"]
    assert [e["chain_index"] for e in saved] == list(range(8))
    assert all(e["chain_length"] == 10 and e["chain_complete"] is False for e in saved)
    assert sum(charged) == len(chain[0]) and len(list(tmp_path.rglob("*.der"))) == 1
    assert events[-1]["reason_code"] == "browser_tls_chain_limit"


def test_cumulative_memory_limit_preserves_valid_subset(tmp_path, chain, monkeypatch):
    maximum = len(chain[0]) + 10
    monkeypatch.setattr("fxfetch.core.browser_tls_evidence.MAX_CERTIFICATE_TOTAL", maximum)
    capture, events, charged = collector(tmp_path, FakeMux(reply(chain)))
    capture.observe_response(response())
    asyncio.run(capture.finish())
    assert capture.buffered_bytes <= maximum and sum(charged) <= maximum
    assert len([e for e in events if e["kind"] == "tls_certificate_saved"]) == 1
    assert events[-1]["code"] == "tls_certificate_chain_partial"


@pytest.mark.parametrize("kind", ["cancelled", "deadline", "storage"])
def test_task_budget_and_cancel_gaps_never_propagate(tmp_path, chain, kind):
    cancel = Event()
    if kind == "cancelled":
        cancel.set()
    mux = FakeMux(reply(chain))
    capture, events, _ = collector(tmp_path, mux, cancel=cancel,
                                  deadline=time.monotonic() - 1 if kind == "deadline" else None,
                                  remaining=0 if kind == "storage" else 9999999)
    capture.observe_response(response())
    asyncio.run(capture.finish())
    assert not list(tmp_path.rglob("*.der"))
    assert all(e["kind"] == "gap" for e in events)
    assert events[-1]["reason_code"] == ("browser_tls_certificate_storage_failed" if kind == "storage" else "browser_tls_capture_budget")
    assert len(mux.calls) == (1 if kind == "storage" else 0)


def test_total_command_budget_cancels_without_retry_storm(tmp_path, monkeypatch):
    monkeypatch.setattr("fxfetch.core.browser_tls_evidence.MAX_COMMAND_SECONDS", .03)
    monkeypatch.setattr("fxfetch.core.browser_tls_evidence.MAX_QUERY_SECONDS", .055)
    mux = FakeMux()
    mux.blocked = True
    capture, events, _ = collector(tmp_path, mux)
    for index in range(4):
        capture.observe_response(response(f"https://origin{index}.test/", ref=f"request{index}"))
    started = time.monotonic()
    asyncio.run(capture.finish())
    assert time.monotonic() - started < .5 and len(mux.calls) <= 2
    assert len(events) == 4 and all(e["kind"] == "gap" for e in events)


def test_only_bound_https_responses_query_and_origin_count_is_bounded(tmp_path, chain, monkeypatch):
    monkeypatch.setattr("fxfetch.core.browser_tls_evidence.MAX_ORIGINS", 1)
    mux = FakeMux(reply(chain))
    capture, events, _ = collector(tmp_path, mux)
    capture.observe_response(response("http://plain.test/"))
    incomplete = response()
    incomplete.pop("status")
    capture.observe_response(incomplete)
    capture.observe_response(response())
    capture.observe_response(response("https://second.test/"))
    asyncio.run(capture.finish())
    assert len(mux.calls) == 1
    assert any(e.get("reason_code") == "browser_tls_origin_limit" for e in events)
    assert canonical_origin("https://[::1]:443/path") == "https://[::1]"
    assert canonical_origin("https://user:password@host.test/path") is None
