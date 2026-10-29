"""Only explicit, bounded GET content references are navigation candidates."""

import pytest

from fxfetch.core.errors import FxfetchError
from fxfetch.core.script_content import literal_html_requests, script_content_candidates


@pytest.mark.parametrize("source,expected", [
    ("async function load(){const r=await fetch('/content.html');}", ["/content.html"]),
    ("fetch('/content.html',{method:'GET',headers:{'Accept':'text/html'}})", ["/content.html"]),
    (r"window.fetch('https:\/\/example.test\x2fpage.html?q=1')", ["https://example.test/page.html?q=1"]),
    ("fetch('/content.html',{method:'POST'})", []),
    ("fetch('/content.html',{method:'GET',body:'x'})", []),
    ("fetch('/content.html',{headers:{Authorization:'secret'}})", []),
    ("fetch('/content.html',{headers:{Accept:dynamic}})", []),
    ("fetch('/content.html',options)", []),
    ("fetch('/content.html'+token)", []),
    ("fetch(url)", []),
    ("fetch(`/content.html?${token}`)", []),
    ("fetch('/api.json')", []),
    ("fetch('/app.apk')", []),
    ('// fetch("/comment.html")\n/* fetch("/block.html") */', []),
    ('''const x="fetch('/string.html')";const y=/fetch('regex.html')/;''', []),
    ("service.fetch('/service.html');other.window.fetch('/other.html')", []),
    ("fetch('/first.html');fetch('/first.html');fetch('/second.htm')", ["/first.html", "/second.htm"]),
])
def test_literal_get_scope(source, expected):
    assert literal_html_requests(source) == expected


def test_relative_url_base_and_source_are_separate():
    result = script_content_candidates("<script>fetch('content.html?ticket=once')</script>",
                                       "https://entry.test/gate", "https://cdn.test/folder/", 2)
    assert len(result) == 1 and result[0].url == "https://cdn.test/folder/content.html?ticket=once"
    assert result[0].source_url == "https://entry.test/gate" and result[0].action == "script_content_link"


def test_data_scripts_comments_and_unsafe_addresses_are_not_candidates():
    html = '''<!-- <script>fetch('/comment.html')</script> -->
      <script type="application/json">fetch('/data.html')</script>
      <script src="/not-loaded.js">fetch('/ignored.html')</script>
      <script>fetch('file:///private.html');fetch('http://127.0.0.1/private.html');
      fetch('https://user:secret@example.test/private.html');</script>'''
    assert script_content_candidates(html, "https://entry.test/", "https://entry.test/", 3) == []


def test_content_discovery_is_bounded():
    with pytest.raises(FxfetchError, match="candidate"):
        script_content_candidates("<script>fetch('/a.html');fetch('/b.html')</script>",
                                  "https://entry.test/", "https://entry.test/", 1)
    with pytest.raises(FxfetchError, match="byte limit"):
        literal_html_requests(" " * (256 * 1024 + 1))


def test_unclosed_options_do_not_create_a_candidate():
    assert literal_html_requests("fetch('/page.html', {headers: {") == []
