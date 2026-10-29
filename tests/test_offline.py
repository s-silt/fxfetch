import io

import pytest
from PIL import Image

from fxfetch.core.discovery import MAX_HTML_DEPTH, MAX_HTML_NODES
from fxfetch.core.errors import FxfetchError
from fxfetch.core.offline import OfflineBundle, _Sanitizer, _stylesheet, resource_references

ROOT = "https://synthetic.test/page"


def png_bytes():
    buffer = io.BytesIO()
    Image.new("RGB", (8, 8), "blue").save(buffer, format="PNG")
    return buffer.getvalue()


def test_bundle_is_local_inert_and_has_no_source_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", lambda *a, **kw: pytest.fail("Offline builder performed DNS"))
    source = tmp_path / "source.html"
    source.write_text(
        '<html><head><script>bad()</script></head><body><h1 onclick="bad()" style="color:blue">Title</h1><a href="https://other.synthetic.test/pay">Download</a><img src="/logo" onerror="bad()" alt="Picture"><link rel="stylesheet" href="/sheet"><script src="/logic.js"></script><iframe src="/frame"></iframe><form action="/login">Hidden form<input name="secret"></form><p style="background-image:url(https://other.synthetic.test/x)">Text</p></body></html>',
        encoding="utf-8",
    )
    image = tmp_path / "image"
    image.write_bytes(png_bytes())
    css = tmp_path / "sheet"
    css.write_text("h1{color:green;padding:4px}", encoding="utf-8")
    output = tmp_path / "offline"
    result = OfflineBundle().build(
        source, ROOT, {"https://synthetic.test/logo": image, "https://synthetic.test/sheet": css}, output
    )
    assert result.available
    assert result.coverage == "partial"
    assert result.reasons == ["static_snapshot_only"]
    text = result.entry.read_text(encoding="utf-8")
    assert '<h1 style="color:blue">Title</h1>' in text
    assert "<span>Download</span>" in text
    assert "onclick" not in text and "onerror" not in text
    assert "<script" not in text and "<iframe" not in text and "<form" not in text
    assert "Hidden form" not in text and "other.synthetic.test" not in text
    assert ROOT not in text
    assert len(list((output / "assets").glob("*.png"))) == 1
    assert "h1{color:green;padding:4px}" in (output / "assets/style.css").read_text()
    assert set(path.suffix for path in result.files) == {".html", ".css", ".png"}
    assert result.bytes == sum(path.stat().st_size for path in result.files)
    assert not list(output.glob("*.json"))


def test_references_only_explicit_same_origin_and_no_css_recursion():
    data = b'<img src="/ok.png"><img src="https://other.synthetic.test/a.png"><script src="/js"></script><a href="/next">Next</a><link rel="stylesheet" href="/style.css">'
    assert [(item.url, item.kind) for item in resource_references(data, ROOT)] == [
        ("https://synthetic.test/ok.png", "image"),
        ("https://synthetic.test/style.css", "css"),
    ]
    assert not resource_references(
        b'<base href="https://other.synthetic.test/"><img src="relative.png">', ROOT
    )


def test_css_network_removal_and_invalid_images(tmp_path):
    source = tmp_path / "source.html"
    source.write_text(
        '<html><img src="/evil.svg"><link rel="stylesheet" href="/sheet"><p style="color:red;expression(alert(1))">Text</p></html>'
    )
    image = tmp_path / "image"
    image.write_text('<svg onload="bad()"></svg>')
    css = tmp_path / "css"
    css.write_text(
        '@import "https://other.synthetic.test/x";p{background:url(https://other.synthetic.test/x)}'
    )
    result = OfflineBundle().build(
        source,
        ROOT,
        {"https://synthetic.test/evil.svg": image, "https://synthetic.test/sheet": css},
        tmp_path / "out",
    )
    assert result.available
    assert "image_removed" in result.reasons and "css_removed" in result.reasons
    assert "expression" not in result.entry.read_text()
    assert "other.synthetic" not in (tmp_path / "out/assets/style.css").read_text()


def test_offline_write_budget(tmp_path):
    source = tmp_path / "source.html"
    source.write_text("<html>Snapshot</html>")
    result = OfflineBundle().build(source, ROOT, {}, tmp_path / "out", max_bytes=10)
    assert not result.available
    assert "offline_disk_limit" in result.reasons
    assert sum(path.stat().st_size for path in (tmp_path / "out").rglob("*") if path.is_file()) <= 10


def test_missing_image_keeps_text(tmp_path):
    source = tmp_path / "source.html"
    source.write_text('<html><p>Visible</p><img src="/missing" alt="Missing picture"></html>')
    result = OfflineBundle().build(source, ROOT, {}, tmp_path / "out")
    assert result.available
    assert "resource_unavailable" in result.reasons
    assert "Visible" in result.entry.read_text() and "Missing picture" in result.entry.read_text()


def test_script_only_page_is_not_a_useful_offline_bundle(tmp_path):
    source = tmp_path / "source.html"
    source.write_text('<html><body><div id="app"></div><script>render()</script></body></html>')
    result = OfflineBundle().build(source, ROOT, {}, tmp_path / "out")
    assert not result.available
    assert "offline_no_visible_content" in result.reasons
    assert not (tmp_path / "out/index.html").exists()


@pytest.mark.parametrize(
    "data",
    [b"<div>" * (MAX_HTML_DEPTH + 1), b"<br>" * (MAX_HTML_NODES + 1), b"<div>" * 255 + b"</unknown>" * 5000],
    ids=["depth", "nodes", "operations"],
)
def test_offline_parser_budgets_return_unavailable(tmp_path, data):
    with pytest.raises(FxfetchError) as error:
        resource_references(data, ROOT)
    assert error.value.code == "offline_html_limit"
    source = tmp_path / "source.html"
    source.write_bytes(data)
    result = OfflineBundle().build(source, ROOT, {}, tmp_path / "out")
    assert not result.available
    assert "offline_html_limit" in result.reasons
    assert not (tmp_path / "out/index.html").exists()
    parser = _Sanitizer(ROOT, {})
    with pytest.raises(FxfetchError) as error:
        parser.feed(data.decode())
    assert error.value.code == "offline_html_limit"


def test_stylesheet_malformed_long_input_uses_forward_scan():
    assert _stylesheet(b"a" * (2 * 1024 * 1024)) == ""
    assert _stylesheet(b"a" * 1_000_000 + b"{color:red") == ""
    assert _stylesheet(b"p{color:red}" * 1001) == ""
