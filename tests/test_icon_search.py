"""Synthetic icon-search acceptance; no provider or candidate network requests."""
from __future__ import annotations

import hashlib
import io
import json
import threading
import time
from pathlib import Path

import pytest
from PIL import Image

from fxfetch.core.errors import FxfetchError
from fxfetch.core.process_limits import ProcessResult
from fxfetch.icon_search import service as module
from fxfetch.icon_search.providers import Provider, candidate_url, candidates, load_config
from fxfetch.icon_search.service import IconSearchService
from fxfetch.icon_search.worker import execute, normalize, publish


def picture() -> bytes:
    buffer = io.BytesIO()
    Image.new('RGB', (300, 400), 'green').save(buffer, 'PNG')
    return buffer.getvalue()


def configure(root: Path) -> None:
    (root / 'icon-search.json').write_text(json.dumps({
        'vision_endpoint': 'https://model.synthetic.test/v1/chat/completions',
        'vision_model': 'synthetic', 'vision_key': 'test-secret-vision', 'serpapi_key': 'test-secret-search',
    }), encoding='utf-8')


class FakeProvider:
    def __init__(self, *, ambiguous=False, fail_second=False):
        self.calls = []
        self.ambiguous, self.fail_second = ambiguous, fail_second

    def quota(self):
        self.calls.append('quota')
        return 200

    def recognize(self, image):
        self.calls.append('recognize')
        assert image[:2] == b'\xff\xd8'
        return {'name': '示例阅读', 'confidence': 'high', 'ambiguous': self.ambiguous,
                'icon_box': [100, 100, 900, 700], 'requested_model': 'requested', 'returned_model': 'alias'}

    def upload(self, image):
        self.calls.append('upload')
        assert len(image) <= 500000
        return 'synthetic-image-id'

    def search(self, identifier, name=''):
        self.calls.append('search')
        if name and self.fail_second:
            raise FxfetchError('icon_provider_failed', 'test')
        return {'visual_matches': [{'title': '示例阅读 Android', 'link': 'https://app.synthetic.test/download'},
                                   {'title': 'unsafe', 'link': 'http://127.0.0.1/'}]}


def test_pipeline_crops_and_preserves_provenance_without_fetching_candidates(tmp_path):
    (tmp_path / 'input.image').write_bytes(picture())
    provider = FakeProvider()
    result = execute(tmp_path, tmp_path, provider)
    assert result['state'] == 'completed' and result['search_attempts'] == 2
    assert result['candidate_requests'] == 0 and len(result['candidates']) == 1
    assert result['candidates'][0]['verified'] is False
    assert result['candidates'][0]['evidence'] == ['android_text', 'name_in_title']
    assert result['recognition']['returned_model'] == 'alias'
    with Image.open(tmp_path / 'icon.jpg') as image:
        assert image.size == (240, 240) and not image.getexif()
    assert provider.calls == ['quota', 'recognize', 'upload', 'search', 'search']


@pytest.mark.parametrize('invalid', [b'<svg/>', b'<html>not an image</html>', b'\xff\xd8broken'])
def test_invalid_image_never_calls_provider(tmp_path, invalid):
    (tmp_path / 'input.image').write_bytes(invalid)
    provider = FakeProvider()
    result = execute(tmp_path, tmp_path, provider)
    assert result['state'] == 'failed' and result['error'] == 'invalid_image'
    assert provider.calls == []


def test_ambiguous_image_does_not_upload_to_search(tmp_path):
    (tmp_path / 'input.image').write_bytes(picture())
    provider = FakeProvider(ambiguous=True)
    result = execute(tmp_path, tmp_path, provider)
    assert result['error'] == 'icon_ambiguous'
    assert provider.calls == ['quota', 'recognize']


@pytest.mark.parametrize('box', [None, [0, 0, 1000, 1000], [1, 1, 1000, 1000]])
def test_missing_or_full_frame_icon_cannot_reach_search_provider(tmp_path, monkeypatch, box):
    (tmp_path / 'input.image').write_bytes(picture())
    provider = FakeProvider()
    recognize = provider.recognize
    monkeypatch.setattr(provider, 'recognize', lambda image: dict(recognize(image), icon_box=box))
    result = execute(tmp_path, tmp_path, provider)
    assert result['state'] == 'failed'
    assert result['error_detail'] == {'stage': 'recognizing', 'code': 'icon_recognition_invalid'}
    assert result['search_attempts'] == 0
    assert provider.calls == ['quota', 'recognize']
    assert not (tmp_path / 'icon.jpg').exists()


def test_partial_provider_failure_keeps_candidates(tmp_path):
    (tmp_path / 'input.image').write_bytes(picture())
    result = execute(tmp_path, tmp_path, FakeProvider(fail_second=True))
    assert result['state'] == 'partial' and len(result['candidates']) == 1
    assert result['error'] == 'icon_provider_failed'


@pytest.mark.parametrize('url', ['javascript:alert(1)', 'http://127.0.0.1/', 'http://[::1]/',
                                'http://10.0.0.1/', 'http://localhost/', 'https://user:pass@a.test/',
                                'https://a.test:99999/', 'https://a.local/', 'https://a.test/\n'])
def test_candidate_filter_is_offline_and_rejects_unsafe_urls(url):
    assert candidate_url(url) is None


def test_rank_is_text_evidence_not_identity():
    result = candidates([{'visual_matches': [
        {'title': 'unrelated logo', 'link': 'https://other.test/a'},
        {'title': '示例 Android', 'link': 'https://app.test/a'}]}], '示例')
    assert result[0]['url'] == 'https://app.test/a'
    assert result[0]['verified'] is False and result[0]['downloadable'] is None


def test_lens_organic_results_are_not_mislabeled_as_name_search():
    response = {'organic_results': [{'title': '示例 APK', 'link': 'https://app.test/a'}]}
    assert 'name_web_search' not in candidates([dict(response, _channel='lens')], '')[0]['evidence']
    assert 'name_web_search' in candidates([dict(response, _channel='name_web')], '示例')[0]['evidence']


def test_config_requires_https_and_keys(tmp_path):
    with pytest.raises(FxfetchError, match='icon_search_unconfigured'):
        load_config(tmp_path)
    configure(tmp_path)
    assert load_config(tmp_path)['vision_model'] == 'synthetic'
    path = tmp_path / 'icon-search.json'
    path.write_text(path.read_text().replace('https:', 'http:'), encoding='utf-8')
    with pytest.raises(FxfetchError):
        load_config(tmp_path)


def test_model_response_must_have_valid_box_and_json(tmp_path, monkeypatch):
    configure(tmp_path)
    provider = Provider(load_config(tmp_path))
    def respond(*args, **kwargs):
        return {'choices': [{'message': {'content': json.dumps({'name': 'sample', 'confidence': 'high',
                            'ambiguous': False, 'icon_box': [800, 0, 100, 1000]})}}]}
    monkeypatch.setattr(provider, 'request', respond)
    with pytest.raises(FxfetchError, match='icon_recognition_invalid'):
        provider.recognize(picture())


def test_free_only_quota_guard(tmp_path, monkeypatch):
    configure(tmp_path)
    provider = Provider(load_config(tmp_path))
    for response in ({'plan_monthly_price': 10, 'plan_searches_left': 100},
                     {'plan_monthly_price': 0, 'plan_searches_left': 1}):
        monkeypatch.setattr(provider, 'request', lambda *a, result=response, **k: result)
        with pytest.raises(FxfetchError, match='icon_free_quota_unavailable'):
            provider.quota()


def wait(service, owner, identifier):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        value = service.get(owner, identifier)
        if value['finished_at']:
            return value
        time.sleep(0.01)
    pytest.fail('search did not finish')


def test_service_idempotency_isolation_cancellation_and_retention(tmp_path, monkeypatch):
    configure(tmp_path)
    started = threading.Event()
    def runner(*args, **kwargs):
        started.set()
        kwargs['cancel'].wait(5)
        return ProcessResult(returncode=None, cancelled=True)
    monkeypatch.setattr(module, 'run_limited', runner)
    service = IconSearchService(tmp_path)
    service.start()
    try:
        first = service.submit('owner-a', 'same-key', picture())
        assert started.wait(2)
        assert service.submit('owner-a', 'same-key', picture())['id'] == first['id']
        with pytest.raises(FxfetchError, match='idempotency_conflict'):
            service.submit('owner-a', 'same-key', b'different')
        with pytest.raises(FxfetchError, match='not_found'):
            service.get('owner-b', first['id'])
        with pytest.raises(FxfetchError, match='icon_search_busy'):
            service.submit('owner-b', 'new-key', picture())
        assert service.cleanup(time.time() + 30 * 86400) == 0
        service.cancel('owner-a', first['id'])
        finished = wait(service, 'owner-a', first['id'])
        assert finished['state'] == 'cancelled'
        service.clear('owner-a')
        with pytest.raises(FxfetchError):
            service.get('owner-a', first['id'])
        assert service.cleanup(finished['finished_at'] + 7 * 86400 - 1) == 0
        assert service.cleanup(finished['finished_at'] + 7 * 86400) == 1
        assert not (service.directory / first['id']).exists()
        assert (tmp_path / 'icon-search.json').is_file()
    finally:
        service.close()


def test_worker_has_hard_deadline_and_never_retries_after_timeout(tmp_path, monkeypatch):
    configure(tmp_path)
    calls = []
    def runner(*args, **kwargs):
        calls.append(kwargs)
        return ProcessResult(returncode=None, timed_out=True)
    monkeypatch.setattr(module, 'run_limited', runner)
    service = IconSearchService(tmp_path)
    first = service.submit('owner', 'same-key', picture())
    value = wait(service, 'owner', first['id'])
    service.close()
    assert value['error'] == 'icon_timeout'
    assert len(calls) == 1 and calls[0]['timeout'] == 180
    assert calls[0]['memory_bytes'] == 768 * 1024 * 1024


def test_multiframe_image_is_rejected(tmp_path):
    path = tmp_path / 'input.image'
    Image.new('RGB', (20, 20), 'red').save(path, 'GIF', save_all=True,
                                         append_images=[Image.new('RGB', (20, 20), 'blue')])
    with pytest.raises(FxfetchError, match='icon_image_limit'):
        normalize(path)


@pytest.mark.parametrize('snapshot', [
    None, b'broken JSON', b'{"timing":{"total_seconds":1e999}}',
    b'{"recognition":{"name":"\\ud800"}}', b'{"x":' + b'[' * 1100 + b'0' + b']' * 1100 + b'}',
])
def test_restart_marks_interrupted_without_provider_call(tmp_path, monkeypatch, snapshot):
    monkeypatch.setattr(module, 'run_limited', lambda *a, **k: pytest.fail('restart launched a worker'))
    service = IconSearchService(tmp_path)
    if snapshot is not None:
        directory = service.directory / ('a' * 32)
        directory.mkdir()
        (directory / 'progress.json').write_bytes(snapshot)
    with service.db() as db:
        db.execute('INSERT INTO searches(id,owner,idem,digest,created,state,result) VALUES(?,?,?,?,?,?,?)',
                   ('a' * 32, 'owner', 'key', 'digest', time.time(), 'running', '{}'))
    service.start()
    try:
        result = service.get('owner', 'a' * 32)
        assert result['state'] == 'failed' and result['error'] == 'icon_interrupted'
        assert not service.active
    finally:
        service.close()


@pytest.mark.parametrize('valid_evidence', [True, False])
def test_restart_recovers_saved_search_evidence(tmp_path, monkeypatch, valid_evidence):
    service = IconSearchService(tmp_path)
    identifier = 'b' * 32
    directory = service.directory / identifier
    directory.mkdir()
    image = picture()
    (directory / 'input.image').write_bytes(image)
    snapshot = execute(tmp_path, directory, FakeProvider())
    assert snapshot['candidates']
    snapshot.update(state='running', stage='searching')
    publish(directory / 'progress.json', snapshot)
    if not valid_evidence:
        (directory / 'icon.jpg').write_bytes(b'changed icon bytes')
    with service.db() as db:
        db.execute('INSERT INTO searches(id,owner,idem,digest,created,state,result) VALUES(?,?,?,?,?,?,?)',
                   (identifier, 'owner', 'key', hashlib.sha256(image).hexdigest(), time.time(), 'running', '{}'))
    monkeypatch.setattr(module, 'run_limited', lambda *a, **k: pytest.fail('restart launched a worker'))
    service.start()
    try:
        result = service.get('owner', identifier)
        assert result['state'] == ('partial' if valid_evidence else 'failed')
        assert result['candidates'] == (snapshot['candidates'] if valid_evidence else [])
        assert result['recognition'] == snapshot['recognition']
        assert result['error_detail'] == {'stage': 'searching', 'code': 'icon_interrupted'}
        assert result['expires_at'] == result['finished_at'] + 7 * 86400
        assert not service.active
        with pytest.raises(FxfetchError, match='not_found'):
            service.get('different-owner', identifier)
    finally:
        service.close()


@pytest.mark.parametrize('cancel_search', [False, True])
def test_api_authenticated_upload_and_explicit_collect(running, monkeypatch, cancel_search):  # noqa: F811
    from test_api import login
    client, jobs, workflow, _ = running
    configure(jobs.store.root)
    calls = []
    saved = threading.Event()

    def runner(command, **kwargs):
        directory = Path(command[-1])
        calls.append(directory)
        execute(jobs.store.root, directory, FakeProvider())
        saved.set()
        if cancel_search and kwargs['cancel'].wait(5):
            return ProcessResult(returncode=None, cancelled=True)
        return ProcessResult(returncode=0)
    monkeypatch.setattr(module, 'run_limited', runner)
    assert client.post('/api/icon-searches', files={'file': ('x.png', picture())},
                       headers={'Origin': 'http://testserver'}).status_code == 401
    headers = login(client)
    assert client.post('/api/icon-searches', files={'file': ('x.png', picture())},
                       headers={'Origin': 'http://testserver'}).status_code == 403
    response = client.post('/api/icon-searches', files={'file': ('x.png', picture())},
                           headers={**headers, 'Idempotency-Key': 'search-key'})
    assert response.status_code == 202
    identifier = response.json()['id']
    search_path = f'/api/icon-searches/{identifier}'
    collect_headers = {**headers, 'Idempotency-Key': 'collect-key'}
    assert saved.wait(2)
    if cancel_search:
        in_progress = client.get(search_path).json()
        assert in_progress['state'] == 'running' and in_progress['finished_at'] is None
        assert client.post(search_path + '/collect', json={'candidate_id': '1'},
                           headers=collect_headers).status_code == 400
        response = client.post(search_path + '/cancel', headers=headers)
        assert response.status_code == 200 and response.json()['cancel_requested']
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = client.get('/api/icon-searches/' + identifier).json()
        if result['finished_at']:
            break
        time.sleep(0.02)
    assert result['state'] == ('cancelled' if cancel_search else 'completed')
    assert result['candidates']
    assert workflow.calls == []
    assert client.get(search_path + '/image/icon').status_code == 200
    if cancel_search:
        assert client.post(search_path + '/collect', json={'candidate_id': '1'},
                           headers={'Origin': 'http://testserver', 'Idempotency-Key': 'collect-key'}).status_code == 403
        assert client.post(search_path + '/collect', json={'candidate_id': '999'},
                           headers=collect_headers).status_code == 400
        icon = calls[0] / 'icon.jpg'
        saved_icon = icon.read_bytes()
        icon.write_bytes(b'changed icon bytes')
        assert client.post(search_path + '/collect', json={'candidate_id': '1'},
                           headers=collect_headers).status_code == 400
        icon.write_bytes(saved_icon)
        assert workflow.calls == []
    response = client.post(search_path + '/collect', json={'candidate_id': '1'}, headers=collect_headers)
    assert response.status_code == 202, response.text
    job = response.json()
    source = jobs.store.root / 'jobs' / job['id'] / 'source'
    assert (source / 'image.original').read_bytes() == picture()
    assert json.loads((source / 'input.json').read_text())['kind'] == 'icon_search'
    assert len(calls) == 1
    if cancel_search:
        icons = client.app.state.icon_search
        with icons.db() as db:
            db.execute('UPDATE searches SET finished=? WHERE id=?', (time.time() - 7 * 86400 - 1, identifier))
        assert client.post(search_path + '/collect', json={'candidate_id': '1'},
                           headers=collect_headers).status_code == 404
    assert client.delete('/api/jobs', headers=headers).status_code == 200
    assert client.get('/api/icon-searches/' + identifier).status_code == 404


# Reuse the synthetic service fixture; it never connects to an external target.
from test_api import encoded_password, running  # noqa: E402, F401
