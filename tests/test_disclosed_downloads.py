"""Synthetic, already-disclosed download controls, navigation and JSON only."""

import json
import threading

import pytest
from test_workflow import ROOT, SyntheticClient, apk_bytes

from fxfetch.core.discovery import discover_html, download_action
from fxfetch.core.errors import FxfetchError
from fxfetch.core.json_package import MAX_JSON_BYTES, MAX_JSON_DEPTH, MAX_JSON_NODES
from fxfetch.core.workflow import Workflow


def json_html(value):
    return ('<script type="application/json">' + json.dumps(value) + '</script>').encode()


@pytest.mark.parametrize("label", ["Get APK", "get apk", "Get the APK", "Get Android app",
                                   "Get the Android app", "Get app for Android", "Get the app for Android"])
def test_precise_get_package_semantics_select_opaque_download_endpoint(label):
    assert download_action(label, "/android/download", {}) == "download_control"
    assert download_action(label, "", {}, require_short=True) == "download_control"
    result = discover_html(f'<a href="/android/download">{label}</a>'.encode(), ROOT)
    assert len(result.candidates) == 1
    assert result.candidates[0].url == ROOT + "/android/download"


@pytest.mark.parametrize("label", ["Android", "APK", "Get", "Get started", "Get Android",
                                   "How to get APK", "Get APK help", "Get app support for Android"])
def test_non_download_language_is_not_promoted(label):
    assert download_action(label, "/endpoint", {}) == ""


@pytest.mark.parametrize("left", ["window.location.href", "location.href", "window.location", "location"])
def test_literal_navigation_preserves_relative_url_and_ticket(left):
    result = discover_html(f'<script>{left}="/app.apk?ticket=a%2Fb";</script>'.encode(), ROOT)
    assert [candidate.url for candidate in result.candidates] == [ROOT + "/app.apk?ticket=a%2Fb"]
    assert result.candidates[0].source_url == ROOT
    assert result.candidates[0].action == "script_package_link"


@pytest.mark.parametrize("script", [
    'location.href="/app.apk"+ticket;',
    'other.location.href="/app.apk";',
    'function f(location){location.href="/app.apk";}',
    'var location={};location.href="/app.apk";',
    '// location.href="/app.apk";',
    'const text=\'location.href="/app.apk";\';',
    'location.href="https://[invalid/app.apk";',
    'location.href="javascript:app.apk";',
    'location.href="/api/undisclosed";',
])
def test_ambiguous_navigation_and_arbitrary_content_are_not_new_requests(script):
    assert not discover_html(('<script>' + script + '</script>').encode(), ROOT).candidates


def test_base_element_does_not_invent_relative_script_or_json_target():
    html = b'<base href="https://different.synthetic.test/"><script>location.href="/app.apk";</script>'
    html += json_html({"downloadUrl": "/another.apk"})
    assert not discover_html(html, ROOT).candidates


def test_json_explicit_fields_preserve_source_and_multiple_independent_candidates():
    value = {"state": {"download_url": ROOT + "/one.apk?ticket=x%2Fy",
                       "packages": [{"url": "/two.apk"}],
                       "download": {"url": "/three.apk"},
                       "thumbnail": ROOT + "/irrelevant.apk"}}
    candidates = discover_html(json_html(value), ROOT).candidates
    assert {item.url for item in candidates} == {ROOT + "/one.apk?ticket=x%2Fy", ROOT + "/two.apk", ROOT + "/three.apk"}
    assert all(item.source_url == ROOT and item.action == "embedded_json_package_link" for item in candidates)
    assert {item.label for item in candidates} == {"JSON script 1 /state/download_url",
                                                  "JSON script 1 /state/packages/0/url",
                                                  "JSON script 1 /state/download/url"}


@pytest.mark.parametrize("value", [
    {"image": ROOT + "/app.apk"}, {"url": ROOT + "/app.apk"},
    {"downloadUrl": "javascript:payload.apk"}, {"downloadUrl": ROOT + "/get"},
    {"downloadUrl": ROOT + "/ios.ipa"}, {"downloadUrl": {"unrelated": ROOT + "/app.apk"}},
    ROOT + "/app.apk", [ROOT + "/app.apk"],
])
def test_json_only_explicit_apk_download_fields_are_used(value):
    assert not discover_html(json_html(value), ROOT).candidates


@pytest.mark.parametrize("wrapper", [
    '<template>{}</template>', '<noscript>{}</noscript>', '<svg>{}</svg>', '<!--{}-->',
])
def test_inactive_json_is_not_a_download_source(wrapper):
    assert not discover_html(wrapper.format(json_html({"apkUrl": ROOT + "/app.apk"}).decode()).encode(), ROOT).candidates


def test_external_json_script_is_not_requested_or_parsed():
    data = b'<script type="application/json" src="/config.json">{"apkUrl":"/app.apk"}</script>'
    assert not discover_html(data, ROOT).candidates


@pytest.mark.parametrize("payload", [
    '{"apkUrl":"/one.apk","apkUrl":"/two.apk"}',
    '{"apkUrl":"/one.apk", "invalid": NaN}',
    '{"apkUrl":"/one.apk",',
    '[' * (MAX_JSON_DEPTH + 2) + '0' + ']' * (MAX_JSON_DEPTH + 2),
    json.dumps({"many": [0] * MAX_JSON_NODES, "apkUrl": "/app.apk"}),
])
def test_invalid_or_over_budget_json_is_an_explicit_gap(payload):
    data = ('<script type="application/json">' + payload + '</script>').encode()
    result = discover_html(data, ROOT)
    assert not result.candidates and "embedded_json_incomplete" in result.gaps


def test_json_byte_budget_does_not_erase_explicit_anchor():
    data = b'<script type="application/json">"' + b'x' * MAX_JSON_BYTES + b'"</script><a href="/app.apk">Download</a>'
    result = discover_html(data, ROOT)
    assert [item.url for item in result.candidates] == [ROOT + "/app.apk"]
    assert "embedded_json_limit" in result.gaps


def test_unclosed_json_is_incomplete_and_preserves_previous_complete_script():
    truncated = b'<script type="application/json">{"apkUrl":"/unclosed.apk"}'
    incomplete = discover_html(truncated, ROOT)
    assert not incomplete.candidates and "embedded_json_incomplete" in incomplete.gaps
    result = discover_html(json_html({"apkUrl": "/complete.apk"}) + truncated, ROOT)
    assert [item.url for item in result.candidates] == [ROOT + "/complete.apk"]
    assert "embedded_json_incomplete" in result.gaps


def test_combined_candidate_limit_is_not_silently_truncated():
    data = b'<a href="/first.apk">Download</a>' + json_html({"apkUrl": "/second.apk"})
    with pytest.raises(FxfetchError) as caught:
        discover_html(data, ROOT, maximum=1)
    assert caught.value.code == "candidate_limit"


@pytest.mark.parametrize("html", [
    b'<a href="/download">Get APK</a>',
    b'<script>location.href="/download.apk";</script>',
    json_html({"downloadUrl": ROOT + "/download.apk"}),
])
def test_workflow_follows_only_the_disclosed_candidate_once(tmp_path, html):
    destination = ROOT + ("/download" if b"Get APK" in html else "/download.apk")
    client = SyntheticClient({ROOT + "/": (200, "text/html", html),
                              destination: (200, "application/octet-stream", apk_bytes())})
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == "downloaded" and result.artifacts[0].kind == "apk"
    assert [call[0] for call in client.calls] == [ROOT + "/", destination]


def test_multiple_json_links_wait_for_selection_and_do_not_fetch(tmp_path):
    data = json_html({"packages": [{"url": "/one.apk"}, {"url": "/two.apk"}]})
    client = SyntheticClient({ROOT + "/": (200, "text/html", data)})
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == "candidate_selection_required" and len(result.selection_candidates) == 2
    assert len(client.calls) == 1


def test_json_discovery_cannot_override_connection_guard(tmp_path):
    class RejectingClient(SyntheticClient):
        def fetch(self, url, *args, **kwargs):
            if url.endswith(".apk"):
                raise FxfetchError("target_not_public", "Synthetic guard denied destination")
            return super().fetch(url, *args, **kwargs)

    client = RejectingClient({ROOT + "/": (200, "text/html", json_html({"apkUrl": "/app.apk"}))})
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == "target_not_public" and not result.artifacts
