"""Administrator-selected DNS profiles keep transport and public-address guards."""
import json
import ssl
from urllib.parse import parse_qs, urlsplit

import pytest

from fxfetch.core.errors import FxfetchError
from fxfetch.core.public_dns import DefaultPublicDNSResolver


def response(path, address="93.184.216.34"):
    query = parse_qs(urlsplit(path).query)
    kind = 1 if query["type"] == ["A"] else 28
    return json.dumps({"Status": 0, "Question": [{"name": query["name"][0], "type": kind}],
                       "Answer": [{"name": query["name"][0], "type": 1, "data": address}] if kind == 1 else []}).encode()


def test_selected_profile_uses_pinned_primary_then_bounded_backup(monkeypatch):
    monkeypatch.setenv("FXFETCH_DNS_PROVIDERS", "cloudflare,google")
    calls = []
    def transport(host, address, path, timeout):
        calls.append((host, address, timeout))
        if host == "cloudflare-dns.com":
            raise TimeoutError("Synthetic unavailable primary")
        return response(path)

    resolver = DefaultPublicDNSResolver(transport=transport)
    assert resolver.resolve("download.synthetic.test", 443) == ("93.184.216.34",)
    assert [item[:2] for item in calls] == [("cloudflare-dns.com", "1.1.1.1"), ("dns.google", "8.8.8.8"), ("dns.google", "8.8.8.8")]
    assert 0 < calls[0][2] <= 10 and all(0 < item[2] <= 20 for item in calls)
    assert {r["endpoint"] for r in resolver.last_records} == {"cloudflare", "google"}


@pytest.mark.parametrize("failure,expected", [("unsafe", "dns_unsafe_answer"), ("tls", "dns_tls_verification_failed")])
def test_selected_profile_never_falls_back_after_security_rejection(monkeypatch, failure, expected):
    monkeypatch.setenv("FXFETCH_DNS_PROVIDERS", "cloudflare,google")
    calls = []
    def transport(host, address, path, timeout):
        calls.append(host)
        if failure == "tls":
            raise ssl.SSLCertVerificationError("Synthetic untrusted DNS service")
        return response(path, "127.0.0.1")
    with pytest.raises(FxfetchError) as caught:
        DefaultPublicDNSResolver(transport=transport).resolve("download.synthetic.test", 443)
    assert caught.value.code == expected
    assert calls == ["cloudflare-dns.com"]


@pytest.mark.parametrize("setting", ["", "cloudflare,cloudflare", "google,alidns,dnspod", "https://dns.synthetic.test", "127.0.0.1", "unknown"])
def test_invalid_admin_profile_fails_closed(monkeypatch, setting):
    monkeypatch.setenv("FXFETCH_DNS_PROVIDERS", setting)
    with pytest.raises(FxfetchError) as caught:
        DefaultPublicDNSResolver()
    assert caught.value.code == "dns_configuration_invalid"


def test_unconfigured_profile_preserves_default_and_selected_profile_is_frozen(monkeypatch):
    monkeypatch.delenv("FXFETCH_DNS_PROVIDERS", raising=False)
    resolver = DefaultPublicDNSResolver()
    monkeypatch.setenv("FXFETCH_DNS_PROVIDERS", "google")
    assert resolver.providers == ("alidns", "dnspod")
    assert DefaultPublicDNSResolver().providers == ("google",)
