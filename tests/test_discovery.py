import plistlib

import pytest

from fxfetch.core.discovery import (
    MAX_HTML_DEPTH,
    MAX_HTML_NODES,
    device_gate_rejected,
    discover_html,
    discover_manifest,
    download_action,
)
from fxfetch.core.errors import FxfetchError


def test_large_inline_image_does_not_exhaust_ordinary_attribute_budget():
    html = '<img src="data:image/png;base64,' + 'A' * 100_000 + '"><a href="/app.apk">Download</a>'
    result = discover_html(html.encode(), "https://synthetic.test/")
    assert result.candidates[0].url == "https://synthetic.test/app.apk"
    assert not device_gate_rejected(html, "Download")


@pytest.mark.parametrize("prefix", ['<div title="', '<img src="https://synthetic.test/', '<img src="data:text/html;base64,'])
def test_large_ordinary_attributes_still_fail(prefix):
    with pytest.raises(FxfetchError) as caught:
        discover_html((prefix + 'A' * 100_000 + '">').encode(), "https://synthetic.test/")
    assert caught.value.code == "html_parse_limit"


def test_static_candidates_and_gaps():
    result = discover_html(
        b'<html><a href="/a.apk">Android</a><a href="/i.ipa">iPhone</a><script src="/app.js"></script></html>',
        "https://synthetic.test/",
    )
    assert [item.kind for item in result.candidates] == ["direct_apk", "direct_ipa"]
    assert result.gaps == ["browser_required"]


def test_download_and_refresh():
    result = discover_html(
        b'<a href="/blob?id=1" download>Get</a><meta http-equiv="refresh" content="0;url=/next">',
        "https://synthetic.test/",
    )
    assert [item.url for item in result.candidates] == [
        "https://synthetic.test/blob?id=1",
        "https://synthetic.test/next",
    ]


def test_manifest():
    data = plistlib.dumps(
        {"items": [{"assets": [{"kind": "software-package", "url": "https://synthetic.test/binary"}]}]}
    )
    result = discover_manifest(data, "https://synthetic.test/m.plist")
    assert result.candidates[0].kind == "direct_ipa"


def test_manifest_depth_and_invalid_fail_in_worker():
    value = {}
    for _ in range(70):
        value = {"nested": value}
    with pytest.raises(FxfetchError) as error:
        discover_manifest(plistlib.dumps(value), "https://synthetic.test/m.plist")
    assert error.value.code == "manifest_limit"
    with pytest.raises(FxfetchError) as error:
        discover_manifest(b"not a plist", "https://synthetic.test/m.plist")
    assert error.value.code == "manifest_invalid"


@pytest.mark.parametrize(
    "data",
    [b"<div>" * (MAX_HTML_DEPTH + 1), b"<br>" * (MAX_HTML_NODES + 1), b"<div>" * 255 + b"</unknown>" * 5000],
    ids=["depth", "nodes", "operations"],
)
def test_html_parser_budgets_fail_explicitly(data):
    with pytest.raises(FxfetchError) as error:
        discover_html(data, "https://synthetic.test/")
    assert error.value.code == "html_parse_limit"


def test_download_actions_exclude_navigation_articles_and_self():
    data = """<a href="https://mirror.synthetic.test/" class="download-btn" download>下载</a>
    <a href="https://mirror.synthetic.test/" download>下载</a>
    <a href="/">钱包官方下载</a>
    <a href="/category/">分类：安卓版app下载安装</a>
    <a href="/article/12.html">下载钱包后如何使用？</a>
    <a href="/tags/">安全下载</a><a href="#">下载</a>
    <a href="/article/3.html">安装好钱包后这些建议助您使用</a>""".encode()
    result = discover_html(data, "https://synthetic.test/")
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.url == "https://mirror.synthetic.test/"
    assert candidate.label == "下载"
    assert candidate.action == "download_attribute"


def test_short_download_action_and_direct_packages_retain_labels():
    result = discover_html(
        '<a href="/get">立即下载</a><a href="/app.apk">Android package</a>'
        '<a href="/intro.html">下载</a>'.encode(),
        "https://synthetic.test/",
    )
    assert [(item.kind, item.label, item.action) for item in result.candidates] == [
        ("http", "立即下载", "download_control"),
        ("direct_apk", "Android package", ""),
    ]


def test_explicit_download_attribute_preserves_html_endpoint_and_js_gap():
    result = discover_html(
        b'<a href="/get.php" download>Get package</a><script src="/app.js"></script>',
        "https://synthetic.test/",
    )
    assert result.candidates[0].url == "https://synthetic.test/get.php"
    assert result.candidates[0].action == "download_attribute"
    assert result.gaps == ["browser_required"]


def test_device_score_gate_is_blocked_but_analytics_is_not():
    fingerprint = """const automated = navigator.webdriver;
    const renderer = gl.getExtension('WEBGL_debug_renderer_info');
    const detail = gl.getParameter(renderer.UNMASKED_RENDERER_WEBGL);"""
    gating = """function allowed() { if (rejected()) return false; return grade() >= threshold; }
    async function content() { const response = await fetch('/public-content'); }
    window.onload = function () { if (allowed()) { content(); return; } showUnavailable(); };"""
    result = discover_html(("<script>" + fingerprint + gating + "</script>").encode(),
                           "https://synthetic.test/")
    assert "device_verification_detected" in result.gaps
    assert "challenge_detected" in result.gaps
    assert result.candidates == []
    analytics = discover_html(("<script>" + fingerprint + "</script>").encode(),
                             "https://synthetic.test/")
    assert analytics.gaps == ["browser_required"]


@pytest.mark.parametrize("property,literal", [
    ("textContent", "Synthetic denial"), ("innerText", "Synthetic denial"),
    ("innerHTML", "<p>Synthetic denial</p>"),
])
def test_device_rejection_requires_observed_plain_text(property, literal):
    code = """<script>
    const probes=['navigator.webdriver','WEBGL_debug_renderer_info','UNMASKED_RENDERER_WEBGL'];
    function allowed(){if(rejected()) return false;return grade()>=threshold;}
    async function content(){await fetch('/protected');}
    window.onload=function(){if(allowed()){content();return;}
    document.querySelector('#status').PROPERTY='LITERAL';};</script>"""
    html = code.replace("PROPERTY", property).replace("LITERAL", literal)
    assert device_gate_rejected(html, "Synthetic denial")
    assert not device_gate_rejected(html, "Normal content")
    assert not device_gate_rejected(html, "")


@pytest.mark.parametrize("label,expected", [
    ("下载安装", True), ("下载并安装", True), ("立即下载 APK", True),
    ("安卓安装说明", False), ("下载帮助", False), ("下载并注册", False),
    ("下载安装 下载说明", False), ("http://synthetic.test/app.apk", False),
])
def test_nonsemantic_action_requires_complete_short_text(label, expected):
    attrs = {"class": "download button_install", "download": ""}
    assert bool(download_action(label, "", attrs, require_short=True)) is expected
