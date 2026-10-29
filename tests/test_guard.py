import pytest

from fxfetch.core.errors import FxfetchError
from fxfetch.core.guard import is_public, resolve_public, validate_url


@pytest.mark.parametrize(
    "url",
    [
        "file:///tmp/x",
        "http://user@synthetic.test",
        "http://x:99999/",
        "http://x/\n",
        "http://x\\y/",
        "http://[::1%25lo]/",
    ],
)
def test_invalid_urls(url):
    with pytest.raises(FxfetchError):
        validate_url(url)


def test_offline_preserves_query(monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **kw: pytest.fail("DNS forbidden"))
    assert validate_url("HTTPS://Synthetic.test/a?x=%2F&x=1#fragment") == "https://synthetic.test/a?x=%2F&x=1"


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.1", "::1", "::ffff:8.8.8.8", "2002:0808:0808::", "224.0.0.1", "192.0.2.1"],
)
def test_special_addresses(address):
    assert not is_public(address)


def test_mixed_dns_rejected(monkeypatch):
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda *a, **kw: [(2, 1, 6, "", ("8.8.8.8", 80)), (2, 1, 6, "", ("127.0.0.1", 80))],
    )
    with pytest.raises(FxfetchError) as error:
        resolve_public("synthetic.test", 80)
    assert error.value.code == "target_not_public"
