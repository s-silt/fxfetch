import codecs

import pytest

from fxfetch.core.errors import FxfetchError
from fxfetch.core.offline import OfflineBundle, resource_references
from fxfetch.core.text_decode import decode_html


@pytest.mark.parametrize("label", ["gb2312", "gbk", "gb18030"])
def test_declared_chinese_roundtrip(label):
    raw = ('<meta charset="' + label + '"><p>中文页面，𠀀</p>').encode("gb18030")
    decoded = decode_html(raw)
    assert "中文页面，𠀀" in decoded.text
    assert decoded.encoding == "gb18030"


def test_http_charset_and_bom():
    assert decode_html("中文".encode("gb18030"), "text/html; charset=GBK").text == "中文"
    assert decode_html(codecs.BOM_UTF8 + "中文".encode()).text == "中文"
    assert decode_html('<meta charset="utf-16"><p>中文</p>'.encode("utf-16")).text.endswith("中文</p>")


@pytest.mark.parametrize(
    "raw,header,code",
    [
        (b'<meta charset="gbk">hello', "text/html;charset=utf-8", "text_charset_conflict"),
        (b'<meta charset="made-up">hello', None, "text_charset_unsupported"),
        (b"<p>\xff</p>", None, "text_decode_failed"),
        (b'<meta charset="utf-8"><p>\xff</p>', None, "text_decode_failed"),
        ("<p>\ufffd</p>".encode(), None, "text_decode_failed"),
    ],
)
def test_explicit_gap_instead_of_mojibake(raw, header, code):
    with pytest.raises(FxfetchError) as error:
        decode_html(raw, header)
    assert error.value.code == code


def test_saved_chinese_snapshot_is_transcoded_without_target_access(tmp_path, monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **kw: pytest.fail("No network"))
    source = tmp_path / "source.html"
    source.write_bytes(
        '<meta charset="gbk"><h1>中文标题</h1><img src="/图.png" alt="图像">'.encode("gb18030")
    )
    assert resource_references(source.read_bytes(), "https://example.test/")[0].url.endswith("/%E5%9B%BE.png")
    result = OfflineBundle().build(source, "https://example.test/", {}, tmp_path / "site")
    assert result.available
    assert "中文标题" in result.entry.read_text(encoding="utf-8")
    assert "图像" in result.entry.read_text(encoding="utf-8")


def test_http_only_charset_can_be_passed_to_snapshot(tmp_path):
    source = tmp_path / "source.html"
    source.write_bytes("<h1>中文标题</h1>".encode("gb18030"))
    failed = OfflineBundle().build(source, "https://example.test/", {}, tmp_path / "bad")
    assert not failed.available and "text_decode_failed" in failed.reasons
    result = OfflineBundle().build(
        source, "https://example.test/", {}, tmp_path / "site", html_content_type="text/html;charset=gbk"
    )
    assert result.available
