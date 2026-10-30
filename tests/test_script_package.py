import threading

import pytest
from test_workflow import ROOT, SyntheticClient, apk_bytes

from fxfetch.core.discovery import discover_html
from fxfetch.core.errors import FxfetchError
from fxfetch.core.script_content import MAX_SCRIPT_BYTES
from fxfetch.core.workflow import Workflow


def document(script):
    return ('<script>' + script + '</script>').encode()


def test_both_platform_literals_are_download_candidates():
    data = document('''
        var androidUrl = 'https://synthetic.test/android.apk?ticket=a%2Fb';
        var iosUrl = "https://synthetic.test/ios.ipa";
        document.addEventListener('DOMContentLoaded', function() {
            installButton.onclick = function() {
                if (isIOS) { window.location.href = iosUrl; }
                else { window.location.href = androidUrl; }
            };
        });
    ''')
    result = discover_html(data, ROOT)
    assert [(c.kind, c.url) for c in result.candidates] == [
        ('direct_apk', ROOT + '/android.apk?ticket=a%2Fb'), ('direct_ipa', ROOT + '/ios.ipa')]
    assert all(c.action == 'script_package_link' for c in result.candidates)
    assert 'browser_required' in result.gaps


@pytest.mark.parametrize('script', [
    "// var a='https://synthetic.test/a.apk'; location.href=a;",
    "/* var a='https://synthetic.test/a.apk'; location.href=a; */",
    "/* var a='https://synthetic.test/a.apk'; location.href=a;",
    '''const text = "var a='https://synthetic.test/a.apk'; location.href=a;";''',
    "const text = `var a='https://synthetic.test/a.apk'; location.href=a;`;",
    "var a='https://synthetic.test/a.apk' + '?ticket=dynamic'; location.href=a;",
    "var a='https://synthetic.test/a.apk'; location.href=a + suffix;",
    "var a='https://synthetic.test/a.apk'; a=resolveTicket(); location.href=a;",
    "var a='https://synthetic.test/a.apk'; function f(a) { location.href=a; }",
    "var a='https://synthetic.test/a.apk'; console.log(a);",
    "var a='https://synthetic.test/a.apk'; var a='https://synthetic.test/b.apk'; location.href=a;",
    "var a='https://synthetic.test/a.apk'; other.location.href=a;",
    "var a='/relative.apk'; location.href=a;",
    "var a='https://synthetic.test/api/get'; location.href=a;",
    "var a='https://synthetic.test/a.apk'; fetch(a);",
    "var a='https://synthetic.test/a.apk'; var location={}; location.href=a;",
    "var a='https://synthetic.test/a.apk'; function f(window){window.location.href=a;}",
    "var a='https://synthetic.test/a.apk'; with(config){location.href=a;}",
    "var a='https://synthetic.test/a.apk';",  # An unrelated string is not a navigation candidate.
])
def test_unsupported_or_ambiguous_script_is_not_a_package_link(script):
    assert not discover_html(document(script), ROOT).candidates


@pytest.mark.parametrize('wrapper', [
    '<script type="application/json">{}</script>',
    '<script src="/external.js">{}</script>',
    '<template><script>{}</script></template>',
    '<noscript><script>{}</script></noscript>',
    '<!-- <script>{}</script> -->',
])
def test_inactive_scripts_are_ignored(wrapper):
    script = "var a='https://synthetic.test/a.apk'; location.href=a;"
    assert not discover_html(wrapper.format(script).encode(), ROOT).candidates


def test_literal_script_limit_preserves_chrome_fallback_and_explicit_anchor():
    data = document('x' * (MAX_SCRIPT_BYTES + 1))
    result = discover_html(data, ROOT)
    assert 'script_package_incomplete' in result.gaps and 'browser_required' in result.gaps
    result = discover_html(data + b'<a href="/a.apk">Download</a>', ROOT)
    assert len(result.candidates) == 1 and result.candidates[0].url == ROOT + '/a.apk'


def test_candidate_limit_not_silently_truncated():
    script = "var a='https://synthetic.test/a.apk'; location.href=a;"
    script += "var b='https://synthetic.test/b.apk'; location.href=b;"
    with pytest.raises(FxfetchError) as error:
        discover_html(document(script), ROOT, maximum=1)
    assert error.value.code == 'candidate_limit'


def test_script_apk_before_qr_limit_and_ipa_anchor(tmp_path, monkeypatch):
    html = document("var a='https://synthetic.test/a.apk'; location.href=a;")
    html += b'<a href="/ios.ipa">iOS</a>'
    html += ''.join(f'<img src="/decorative-{i}.png">' for i in range(20)).encode()
    client = SyntheticClient({ROOT + '/': (200, 'text/html', html),
                              ROOT + '/a.apk': (200, 'application/octet-stream', apk_bytes())})
    monkeypatch.setattr('fxfetch.core.workflow.decode_saved_image', lambda *args: pytest.fail('APK before QR'))
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == 'downloaded' and result.artifacts[0].kind == 'apk'
    assert [call[0] for call in client.calls] == [ROOT + '/', ROOT + '/a.apk']
    assert result.page_qr['status'] == 'not_started'


def test_multiple_script_apks_require_selection_without_package_request(tmp_path):
    html = document("var a='https://synthetic.test/a.apk'; location.href=a;"
                    "var b='https://synthetic.test/b.apk'; location.href=b;")
    client = SyntheticClient({ROOT + '/': (200, 'text/html', html)})
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == 'candidate_selection_required'
    assert len(result.selection_candidates) == 2 and len(client.calls) == 1


def test_script_candidate_cannot_override_connection_guard(tmp_path):
    html = document("var a='https://synthetic.test/a.apk'; location.href=a;")

    class RejectingClient(SyntheticClient):
        def fetch(self, url, *args, **kwargs):
            if url.endswith('.apk'):
                raise FxfetchError('target_not_public', 'Synthetic connection guard denial')
            return super().fetch(url, *args, **kwargs)

    result = Workflow(RejectingClient({ROOT + '/': (200, 'text/html', html)})).run(
        ROOT, tmp_path, threading.Event())
    assert result.outcome == 'failed' and result.reason_code == 'target_not_public'
    assert not result.artifacts


def test_regex_literal_contents_are_not_package_statements():
    # A valid JS regular expression: its URL slashes are escaped. Regex bodies
    # are opaque lexer tokens, even if their text resembles valid statements.
    script = r'''var rx = /;var fake = "https:\/\/download.test\/fake.apk";location=fake;/;'''
    assert not discover_html(document(script), ROOT).candidates


def test_device_regex_does_not_hide_real_navigation_declaration():
    script = r'''
        var isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
        var androidUrl = 'https://synthetic.test/android.apk';
        var iosUrl = 'https://synthetic.test/ios.ipa';
        if (isIOS) { window.location.href = iosUrl; }
        else { window.location.href = androidUrl; }
    '''
    assert [candidate.kind for candidate in discover_html(document(script), ROOT).candidates] == [
        'direct_apk', 'direct_ipa']
