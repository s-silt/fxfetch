"""Synthetic DoH evidence and question-bound DNS routing; no external requests."""

import base64
import hashlib
import json
import ssl
import threading
import time
from http.cookiejar import CookieJar
from urllib.parse import parse_qs, urlsplit

import dns.message
import dns.rdatatype
import dns.rrset
import pytest

from fxfetch.core.errors import FxfetchError
from fxfetch.core.http_client import HttpClient
from fxfetch.core.limits import Limits
from fxfetch.core.network import build_default_client
from fxfetch.core.public_dns import (
    MAX_ANSWER_RECORDS,
    MAX_DNS_RECORD_BYTES,
    DefaultPublicDNSResolver,
    PublicDNSResolver,
    bounded_dns_records,
)
from fxfetch.core.web_journal import EvidenceJournal

HOST = "download.synthetic.test"
PUBLIC = "93.184.216.34"
OTHER_PUBLIC = "93.184.216.35"


def wire(rows, *, only_a=True, mutate=None):
    def transport(host, address, path, timeout):
        encoded = parse_qs(urlsplit(path).query)["dns"][0]
        query = dns.message.from_wire(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        response = dns.message.make_response(query)
        if not only_a or query.question[0].rdtype == dns.rdatatype.A:
            for owner, kind, value in rows:
                response.answer.append(dns.rrset.from_text(owner.rstrip(".") + ".", 60, "IN", kind,
                                                          value.rstrip(".") + "." if kind == "CNAME" else value))
        if mutate:
            mutate(response)
        return response.to_wire()
    return transport


def test_only_question_cname_terminal_owner_and_qtype_are_returned():
    resolver = PublicDNSResolver(transport=wire([
        ("unrelated.synthetic.test", "A", OTHER_PUBLIC),
        (HOST, "CNAME", "alias.synthetic.test"),
        ("alias.synthetic.test", "CNAME", "final.synthetic.test"),
        ("final.synthetic.test", "A", PUBLIC),
        ("final.synthetic.test", "AAAA", "2606:4700:4700::1111"),
    ]))
    assert resolver.resolve(HOST, 443) == (PUBLIC,)
    answers = resolver.last_records[0]["answers"]
    assert [row["data"] for row in answers if row["selected"]] == [PUBLIC]
    assert next(row for row in answers if row["name"].startswith("unrelated"))["query_match"] is False
    assert all(row["classification"] in {"public", "alias"} for row in answers)


@pytest.mark.parametrize("rows", [
    [("unrelated.synthetic.test", "A", PUBLIC)],
    [(HOST, "CNAME", "missing.synthetic.test"), ("unrelated.synthetic.test", "A", PUBLIC)],
])
def test_unrelated_public_addresses_cannot_supply_missing_answer(rows):
    resolver = PublicDNSResolver(transport=wire(rows))
    with pytest.raises(FxfetchError) as caught:
        resolver.resolve(HOST, 443)
    assert caught.value.code == "dns_no_addresses"
    assert not any(answer["selected"] for row in resolver.last_records for answer in row["answers"])


@pytest.mark.parametrize("unsafe,kind,classification", [
    ("10.17.23.9", "A", "private"), ("127.0.0.9", "A", "loopback"),
    ("2002:c000:201::1", "AAAA", "ipv6_transition"),
])
def test_unsafe_including_unrelated_answers_fail_closed_and_keep_evidence(unsafe, kind, classification):
    calls = []
    responder = wire([(HOST, "A", PUBLIC), ("unrelated.synthetic.test", kind, unsafe)])
    def transport(*args):
        calls.append(args)
        return responder(*args)
    resolver = DefaultPublicDNSResolver(transport=transport)
    with pytest.raises(FxfetchError) as caught:
        resolver.resolve(HOST, 443)
    assert caught.value.code == "dns_unsafe_answer"
    assert len(calls) == 1 and calls[0][1] == "223.5.5.5"
    record = resolver.last_records[0]
    assert record["provider"] == "alidns" and record["query_type"] == "A" and record["rcode"] == 0
    assert record["status"] == "rejected" and record["reason_code"] == "dns_unsafe_answer"
    assert {item["classification"] for item in record["answers"]} == {"public", classification}
    assert record["addresses"] == ()
    assert caught.value.dns_records == resolver.last_records


@pytest.mark.parametrize("rows", [
    [(HOST, "CNAME", "alias.synthetic.test"), ("alias.synthetic.test", "CNAME", HOST)],
    [(HOST, "CNAME", "one.synthetic.test"), (HOST, "CNAME", "two.synthetic.test")],
    [(HOST, "CNAME", "alias.synthetic.test"), (HOST, "A", PUBLIC)],
])
def test_conflicting_or_cyclic_alias_is_rejected_without_fallback(rows):
    resolver = DefaultPublicDNSResolver(transport=wire(rows))
    with pytest.raises(FxfetchError) as caught:
        resolver.resolve(HOST, 443)
    assert caught.value.code == "dns_invalid_response"
    assert {row["endpoint"] for row in resolver.last_records} == {"alidns"}


def test_answer_limit_bounds_rejected_diagnostics():
    rows = [(f"item-{i}.synthetic.test", "A", PUBLIC) for i in range(MAX_ANSWER_RECORDS + 1)]
    resolver = PublicDNSResolver(transport=wire(rows))
    with pytest.raises(FxfetchError) as caught:
        resolver.resolve(HOST, 443)
    assert caught.value.code == "dns_invalid_response"
    record = resolver.last_records[0]
    assert len(record["answers"]) == MAX_ANSWER_RECORDS and record["answers_truncated"] is True
    assert len(record["response_sha256"]) == 64


def test_doh_certificate_failure_is_not_a_transport_fallback():
    calls = []
    def transport(*args):
        calls.append(args)
        raise ssl.SSLCertVerificationError(1, "synthetic")
    resolver = DefaultPublicDNSResolver(transport=transport)
    with pytest.raises(FxfetchError) as caught:
        resolver.resolve(HOST, 443)
    assert caught.value.code == "dns_tls_verification_failed" and len(calls) == 1


def test_json_requires_echoed_question_and_owner_bound_chain():
    def transport(host, address, path, timeout):
        question = parse_qs(urlsplit(path).query)
        kind = 1 if question["type"] == ["A"] else 28
        return json.dumps({"Status": 0, "Question": [{"name": HOST, "type": kind}], "Answer": [
            {"name": "other.synthetic.test", "type": 1, "data": OTHER_PUBLIC},
            {"name": HOST, "type": 5, "data": "alias.synthetic.test"},
            {"name": "alias.synthetic.test", "type": 1, "data": PUBLIC},
        ]}).encode()
    resolver = PublicDNSResolver("google", transport=transport)
    assert resolver.resolve(HOST, 443) == (PUBLIC,)
    bad = PublicDNSResolver("google", transport=lambda *_: json.dumps({"Status": 0, "Answer": [
        {"name": HOST, "type": 1, "data": PUBLIC}]}).encode())
    with pytest.raises(FxfetchError) as caught:
        bad.resolve(HOST, 443)
    assert caught.value.code == "dns_invalid_response"


class NoTargetConnectionClient(HttpClient):
    connected = False

    def _connect(self, *args):
        self.connected = True
        raise FxfetchError("synthetic_stop", "DNS complete; do not connect a target")


@pytest.mark.parametrize("unsafe", [False, True])
def test_http_dns_hook_preserves_success_and_rejection_once(unsafe, tmp_path):
    resolver = DefaultPublicDNSResolver(transport=wire([(HOST, "A", "10.17.23.9" if unsafe else PUBLIC)]))
    events, progress = [], []
    client = NoTargetConnectionClient(resolver=resolver.resolve, dns_records=lambda: resolver.last_records,
                                     transport_observer=events.append)
    with pytest.raises(FxfetchError) as caught:
        client.fetch(f"https://{HOST}/", tmp_path / "body", user_agent="Synthetic", cookie_jar=CookieJar(),
                     cancel=threading.Event(), on_event=progress.append)
    observed = [event for event in events if event["kind"] == "dns_resolution_observed"]
    assert len(observed) == (1 if unsafe else 2)
    assert len({row["request_ref"] for row in observed}) == 1
    assert all(row["host"] == HOST and row["url"] == f"https://{HOST}/" for row in observed)
    assert client.connected is not unsafe
    if unsafe:
        assert caught.value.code == "dns_unsafe_answer"
        failure = next(row for row in progress if row["event"] == "dns_resolution_failed")
        assert failure["provider"] == "alidns" and failure["query_type"] == "A"
        assert "answers" not in failure and "dns_record" not in failure
    else:
        assert all(row["dns_record"]["status"] == 0 for row in observed)


def test_late_dns_never_connects_or_emits_success(tmp_path):
    finished = threading.Event()
    record = {"host": HOST, "status": 0, "provider": "alidns", "query_type": "A", "addresses": [PUBLIC]}
    def resolver(host, port):
        time.sleep(.03)
        finished.set()
        return (PUBLIC,)
    events = []
    client = NoTargetConnectionClient(resolver=resolver, dns_timeout=.01, dns_records=lambda: [record],
                                     transport_observer=events.append)
    with pytest.raises(FxfetchError) as caught:
        client.fetch(f"https://{HOST}/", tmp_path / "body", user_agent="Synthetic", cookie_jar=CookieJar(),
                     cancel=threading.Event())
    assert caught.value.code == "dns_timeout" and not client.connected
    assert finished.wait(1)
    records = [row["dns_record"] for row in events if row["kind"] == "dns_resolution_observed"]
    assert len(records) == 1 and records[0]["status"] == "failed"


def test_default_client_supplies_dns_records_without_target_requests(monkeypatch):
    class Resolver:
        last_records = [{"host": HOST, "provider": "alidns", "query_type": "A"}]
        def __init__(self, **kwargs):
            pass
        def resolve(self, host, port):
            raise AssertionError("No resolution expected")
    monkeypatch.setattr("fxfetch.core.network.DefaultPublicDNSResolver", Resolver)
    client = build_default_client(Limits())
    assert client.dns_records() == Resolver.last_records


def test_response_digest_is_of_original_wire_bytes():
    payloads = []
    responder = wire([(HOST, "A", PUBLIC)])
    def transport(*args):
        payload = responder(*args)
        payloads.append(payload)
        return payload
    resolver = PublicDNSResolver(transport=transport)
    resolver.resolve(HOST, 443)
    assert [row["response_sha256"] for row in resolver.last_records] == [hashlib.sha256(raw).hexdigest() for raw in payloads]


def test_large_dns_diagnostic_preserves_summary_without_journal_omission(tmp_path):
    record = {"host": HOST, "provider": "alidns", "query_type": "A", "status": "rejected",
              "reason_code": "dns_unsafe_answer", "response_sha256": "a" * 64,
              "answers": [{"name": "域" * 255, "type": "CNAME", "data": "名" * 255,
                           "classification": "alias", "selected": False} for _ in range(128)]}
    projected = bounded_dns_records([record])[0]
    assert len(json.dumps(projected, ensure_ascii=True, separators=(",", ":")).encode("ascii")) <= MAX_DNS_RECORD_BYTES < 32 * 1024
    assert projected["answers_omitted_count"] > 0 and projected["answers_truncated"]
    assert len(projected["answers"]) + projected["answers_omitted_count"] == 128
    assert projected["response_digest_scope"] == "dns_response_bytes" and projected["response_body_saved"] is False
    journal = EvidenceJournal(tmp_path / "dns.jsonl", "synthetic", "attempt")
    assert journal.append("dns_resolution_observed", {"dns_record": projected})
    journal.close()
    assert journal.gaps == []
    saved = json.loads((tmp_path / "dns.jsonl").read_text())
    assert saved["fields"]["dns_record"] == json.loads(json.dumps(projected))
