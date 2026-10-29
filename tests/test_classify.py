from urllib.parse import quote

import pytest

from fxfetch.core.classify import classify_input, normalize_entry_url
from fxfetch.core.errors import FxfetchError


def test_offline_input(monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **kw: pytest.fail("Offline input performed DNS"))
    result = classify_input("https://synthetic.test/app.apk?a=%2F#x")
    assert result.kind == "direct_apk"
    assert result.original.endswith("#x")
    assert result.request_url == "https://synthetic.test/app.apk?a=%2F"
    assert classify_input("https://apps.apple.com/app/test").kind == "store"
    assert classify_input("javascript:alert(1)").kind == "unsupported"


def test_itms_manifest():
    url = "https://synthetic.test/m.plist?a=1&b=2"
    result = classify_input("itms-services://?action=download-manifest&url=" + quote(url, safe=""))
    assert result.kind == "itms_manifest"
    assert result.request_url == url
    with pytest.raises(FxfetchError):
        classify_input("itms-services://?action=download-manifest&url=http://x&url=http://y")


@pytest.mark.parametrize("entered,expected", [
    ("entry.test/path?a=%2F#part", "https://entry.test/path?a=%2F#part"),
    ("www.entry.test", "https://www.entry.test"),
    ("//entry.test/path", "https://entry.test/path"),
    ("https:/entry.test/path", "https://entry.test/path"),
    ("http://Entry.test/path?q=1#x", "http://Entry.test/path?q=1#x"),
    ("entry.test:8443/path", "https://entry.test:8443/path"),
    ("  entry.test/path  ", "https://entry.test/path"),
    ("[::1]:8443/path", "https://[::1]:8443/path"),
])
def test_entry_completion_is_offline_and_preserves_target_text(entered, expected, monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **kw: pytest.fail("Input completion performed DNS"))
    assert normalize_entry_url(entered) == expected
    assert normalize_entry_url(expected) == expected


@pytest.mark.parametrize("entered", [
    "javascript:alert(1)", "data:text/html,test", "file:///tmp/test", "ftp://entry.test/",
    "custom:entry.test", "https:entry.test", "not a website", "word", "/relative/path",
    "https:///entry.test", "user@entry.test", "entry.test:99999/path", "entry.test\\path",
])
def test_entry_completion_rejects_foreign_schemes_and_malformed_input(entered):
    with pytest.raises(FxfetchError):
        normalize_entry_url(entered)


def test_completed_private_literal_still_fails_connection_guard(monkeypatch):
    from fxfetch.core.guard import resolve_public

    normalized = normalize_entry_url("127.0.0.1/private")
    assert normalized == "https://127.0.0.1/private"
    monkeypatch.setattr("socket.getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, ("127.0.0.1", 443))])
    with pytest.raises(FxfetchError) as caught:
        resolve_public("127.0.0.1", 443)
    assert caught.value.code == "target_not_public"
