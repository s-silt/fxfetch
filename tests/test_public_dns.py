import json

import pytest

from fxfetch.core.errors import FxfetchError
from fxfetch.core.http_client import HttpClient
from fxfetch.core.public_dns import PublicDNSResolver


def test_explicit_pinned_queries_and_metadata():
    calls = []

    def transport(host, address, path, timeout):
        calls.append((host, address, path, timeout))
        record = (
            {"type": 1, "data": "93.184.216.34"}
            if "type=A&" in path or path.endswith("type=A")
            else {"type": 28, "data": "2606:2800:220:1:248:1893:25c8:1946"}
        )
        return json.dumps({"Status": 0, "Answer": [{"type": 5, "data": "alias.example"}, record]}).encode()

    resolver = PublicDNSResolver("google", transport=transport)
    result = resolver.resolve("download.example", 443)
    assert len(result) == 2
    assert all(call[:2] == ("dns.google", "8.8.8.8") for call in calls)
    assert all(0 < call[3] <= 20 for call in calls)
    assert resolver.last_records[0]["query_type"] == "A"
    assert HttpClient(resolver=resolver.resolve)._resolve("download.example", 443) == result


@pytest.mark.parametrize(
    "payload",
    [
        b'{"Status": 3}',
        b'{"Status": 0}',
        b"broken",
        b'{"Status": 0, "Answer": [{"type": 1, "data": "198.18.0.1"}]}',
        b'{"Status": 0, "Answer": [{"type": 28, "data": "::1"}]}',
        b"x" * 65537,
    ],
    ids=["nxdomain", "empty", "malformed", "fake_ip", "loopback", "oversized"],
)
def test_bad_answers_fail_without_fallback(payload):
    calls = []

    def transport(*args):
        calls.append(args)
        return payload

    with pytest.raises(FxfetchError):
        PublicDNSResolver(transport=transport).resolve("download.example", 443)
    assert 1 <= len(calls) <= 2


@pytest.mark.parametrize(
    "host", ["localhost", "a.localhost", "a.local", "127.0.0.1", "::1", "1.1.1.1", "a.home.arpa"]
)
def test_local_or_literal_hosts_never_query(host):
    def transport(*args):
        pytest.fail("unexpected DNS request")

    with pytest.raises(FxfetchError):
        PublicDNSResolver(transport=transport).resolve(host, 443)


@pytest.mark.parametrize("addresses", [(), ("127.0.0.1",), ("93.184.216.34", "198.18.0.1"), ("invalid",)])
def test_injected_resolver_still_validates_all_addresses(addresses):
    with pytest.raises(FxfetchError, match="public"):
        HttpClient(resolver=lambda host, port: addresses)._resolve("download.example", 443)


def test_endpoint_must_be_explicit_supported_choice():
    with pytest.raises(ValueError):
        PublicDNSResolver("arbitrary.example")


def wire_transport(answer="93.184.216.34", rcode=0, mismatched=False):
    import base64
    from urllib.parse import parse_qs, urlsplit

    import dns.message
    import dns.rdatatype
    import dns.rrset

    def transport(host, address, path, timeout):
        encoded = parse_qs(urlsplit(path).query)["dns"][0]
        query = dns.message.from_wire(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        response = dns.message.make_response(query)
        response.set_rcode(rcode)
        if mismatched:
            response.id ^= 1
        if answer and query.question[0].rdtype == dns.rdatatype.A:
            response.answer.append(dns.rrset.from_text(query.question[0].name, 60, "IN", "A", answer))
        return response.to_wire()

    return transport


def test_wire_default_endpoint_and_questions():
    calls = []
    responder = wire_transport()

    def transport(*args):
        calls.append(args)
        return responder(*args)

    resolver = PublicDNSResolver(transport=transport)
    assert resolver.resolve("download.example", 443) == ("93.184.216.34",)
    assert len(calls) == 2
    assert all(call[:2] == ("dns.alidns.com", "223.5.5.5") for call in calls)
    assert all("?dns=" in call[2] for call in calls)


@pytest.mark.parametrize(
    "failure, expected",
    [
        ("network", "success"),
        ("servfail", "success"),
        ("nxdomain", "dns_nxdomain"),
        ("unsafe", "target_not_public"),
        ("mismatch", "dns_invalid_response"),
        ("empty", "dns_no_addresses"),
    ],
)
def test_default_provider_failover_is_bounded_by_reason(failure, expected):
    import dns.rcode

    from fxfetch.core.public_dns import DefaultPublicDNSResolver

    calls = []

    def transport(host, address, path, timeout):
        calls.append(address)
        if address == "223.5.5.5":
            if failure == "network":
                raise TimeoutError("synthetic")
            return wire_transport(
                answer="198.18.0.1"
                if failure == "unsafe"
                else (None if failure == "empty" else "93.184.216.34"),
                rcode=dns.rcode.SERVFAIL
                if failure == "servfail"
                else (dns.rcode.NXDOMAIN if failure == "nxdomain" else 0),
                mismatched=failure == "mismatch",
            )(host, address, path, timeout)
        return wire_transport()(host, address, path, timeout)

    resolver = DefaultPublicDNSResolver(transport=transport)
    if expected == "success":
        assert resolver.resolve("download.example", 443) == ("93.184.216.34",)
        assert calls == ["223.5.5.5", "119.29.29.29", "119.29.29.29"]
        assert resolver.last_records[0]["endpoint"] == "alidns"
    else:
        with pytest.raises(FxfetchError) as exc:
            resolver.resolve("download.example", 443)
        assert exc.value.code == expected
        assert set(calls) == {"223.5.5.5"}
