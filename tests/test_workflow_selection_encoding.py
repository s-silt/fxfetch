"""Selection provenance, declared encodings, and bounded Flutter integration."""

import threading
from dataclasses import replace
from pathlib import Path

import pytest
from test_workflow import ROOT, SyntheticClient, apk_bytes

from fxfetch.core.errors import FxfetchError
from fxfetch.core.flutter_adapter import MAX_MAIN_BYTES
from fxfetch.core.limits import Limits
from fxfetch.core.workflow import Workflow


def test_http_charset_reaches_discovery_and_offline_snapshot(tmp_path):
    body = '<h1>中文标题</h1><p>这是正文</p><script src="app.js"></script>'.encode('gb18030')
    client = SyntheticClient({ROOT + '/': (200, 'text/html;charset=gb2312', body)})
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == 'browser_required'
    assert result.offline['available']
    assert '中文标题' in result.offline['entry'].read_text(encoding='utf-8')
    assert '\ufffd' not in result.offline['entry'].read_text(encoding='utf-8')
    assert len(client.calls) == 1


def test_encoding_conflict_never_becomes_absence_or_ipa_fallback(tmp_path):
    client = SyntheticClient({ROOT + '/': (
        200, 'text/html;charset=gbk', b'<meta charset="utf-8"><p>Heading</p>',
    )})
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == 'text_charset_conflict'
    assert result.outcome == 'failed' and result.coverage == 'partial'
    assert not result.offline['available'] and len(client.calls) == 1


def test_download_controls_do_not_select_article_or_navigation(tmp_path):
    html = '''<html><a href="/">下载首页</a><a href="/articles/1.html">下载指南</a>
    <a href="/landing" download>下载</a><a href="/landing" download>下载</a>
    <script src="unused.js"></script></html>'''.encode()
    client = SyntheticClient({
        ROOT + '/': (200, 'text/html', html),
        ROOT + '/landing': (200, 'text/html', b'<a href="/app.apk">Download</a>'),
        ROOT + '/app.apk': (200, 'application/octet-stream', apk_bytes()),
    })
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == 'downloaded'
    assert [c[0] for c in client.calls] == [ROOT + '/', ROOT + '/landing', ROOT + '/app.apk']


def test_selection_contains_only_current_android_choices(tmp_path):
    client = SyntheticClient({ROOT + '/': (200, 'text/html', b'''
        <h1>Choices</h1><a href="/one.apk">One</a><a href="/two.apk">Two</a>
        <a href="/ios.ipa">iOS</a>''')})
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == 'candidate_selection_required'
    assert [c.url for c in result.selection_candidates] == [ROOT + '/one.apk', ROOT + '/two.apk']
    assert len(result.candidates) == 3 and len(client.calls) == 1
    assert result.offline['available']


def flutter_routes(main):
    return {
        ROOT + '/': (200, 'text/html', b'<base href="/web/"><script src="flutter_bootstrap.js"></script>'),
        ROOT + '/web/flutter_bootstrap.js': (200, 'text/javascript', b'{"mainJsPath":"main.js"}'),
        ROOT + '/web/main.js': (200, 'text/javascript', main),
    }


def test_flutter_literal_is_only_an_explicit_selection_even_if_single(tmp_path):
    client = SyntheticClient(flutter_routes(b'var u="https://cdn.synthetic.test/app.apk";'))
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == 'candidate_selection_required'
    assert result.selection_candidates[0].action == 'script_literal'
    assert result.landing['gaps'] == ['flutter_runtime_required']
    assert not result.artifacts and len(client.calls) == 3
    assert client.calls[-1][3].max_body_bytes == MAX_MAIN_BYTES
    assert all(call[2] is client.calls[0][2] for call in client.calls)


@pytest.mark.parametrize('reason,outcome', [
    ('download_limit', 'failed'), ('target_not_public', 'failed'),
    ('tls_verification_failed', 'failed'), ('http_access_control', 'blocked'),
])
def test_flutter_fetch_failure_keeps_original_boundary(tmp_path, reason, outcome):
    class Client(SyntheticClient):
        def fetch(self, url, destination, **kwargs):
            if url.endswith('/main.js'):
                self.calls.append((url, kwargs['user_agent'], kwargs['cookie_jar'], self.limits))
                raise FxfetchError(reason, 'Synthetic failure', outcome=outcome)
            return super().fetch(url, destination, **kwargs)
    client = Client(flutter_routes(b'never read'))
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == ('flutter_source_download_limit' if reason == 'download_limit' else reason)
    assert result.outcome == outcome
    assert result.coverage == 'partial' and not result.selection_candidates
    assert len(client.calls) == 3 and not result.artifacts


def test_workflow_keeps_large_compiled_source_on_disk(tmp_path, monkeypatch):
    main = b' ' * (17 * 1024 * 1024) + b'"https://cdn.synthetic.test/large.apk";'
    client = SyntheticClient(flutter_routes(main))
    read_bytes = Path.read_bytes

    def guarded_read(path):
        if path.name == '0002.landing':
            pytest.fail('Workflow must pass the compiled source path to the stream scanner')
        return read_bytes(path)

    monkeypatch.setattr(Path, 'read_bytes', guarded_read)
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == 'candidate_selection_required'
    assert result.landing['evidence'][-1]['size'] == len(main)
    assert result.selection_candidates[0].url.endswith('/large.apk')
    assert len(client.calls) == 3


def test_flutter_source_limit_never_exceeds_remaining_task_budget(tmp_path):
    routes = flutter_routes(b'// complete small script')
    client = SyntheticClient(routes)
    limits = replace(Limits(), max_web_bytes=1024)
    result = Workflow(client, limits).run(ROOT, tmp_path, threading.Event())
    expected = 1024 - len(routes[ROOT + '/'][2]) - len(routes[ROOT + '/web/flutter_bootstrap.js'][2])
    assert client.calls[-1][3].max_body_bytes == expected
    assert client.calls[-1][3].max_package_bytes == expected
    assert result.reason_code == 'flutter_runtime_required'
