"""Synthetic recognition/name-search regressions; no provider or target access."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from test_api import encoded_password, login, running  # noqa: F401
from test_icon_search import configure, picture, wait

from fxfetch.core.errors import FxfetchError
from fxfetch.core.process_limits import ProcessResult
from fxfetch.icon_search import service as service_module
from fxfetch.icon_search.providers import Provider, candidates, load_config
from fxfetch.icon_search.service import IconSearchService
from fxfetch.icon_search.worker import execute, publish

NAME = '合成阅读'
SEARCH_SECRET = 'synthetic-name-search-secret'
SAMPLE_URL = 'https://koodous.com/apks/' + 'a' * 64
DOWNLOAD_URL = 'https://download.synthetic.test/app.apk'


def search_configuration(root: Path) -> None:
    (root / 'icon-search.json').write_text(
        json.dumps({'serpapi_key': SEARCH_SECRET}), encoding='utf-8'
    )


def vision_configuration(root: Path) -> None:
    (root / 'icon-search.json').write_text(json.dumps({
        'vision_endpoint': 'https://vision.synthetic.test/v1/chat/completions',
        'vision_model': 'synthetic-image-model', 'vision_key': 'synthetic-recognition-secret',
    }), encoding='utf-8')


class DirectedProvider:
    def __init__(self, *, fail_second: bool = False):
        self.calls: list[tuple] = []
        self.fail_second = fail_second

    def quota(self):
        self.calls.append(('quota',))
        return 200

    def recognize(self, image):
        self.calls.append(('recognize',))
        assert image[:2] == b'\xff\xd8'
        return {'name': NAME, 'confidence': 'high', 'ambiguous': False,
                'icon_box': [100, 100, 900, 700],
                'requested_model': 'synthetic-image-model', 'returned_model': 'synthetic-image-model'}

    def upload(self, image):
        pytest.fail('New recognition and name search must not upload an image to SerpApi')

    def search(self, identifier, name=''):
        pytest.fail('New recognition and name search must not use legacy Lens search')

    def search_name(self, name, scope):
        self.calls.append(('search_name', name, scope))
        assert scope in {'sample_index', 'download_page'}
        if scope == 'download_page' and self.fail_second:
            raise FxfetchError('icon_provider_timeout', 'synthetic provider timeout')
        return {'_channel': 'sample_index' if scope == 'sample_index' else 'targeted_download',
                'organic_results': [{'title': name + ' Android APK',
                                     'link': SAMPLE_URL if scope == 'sample_index' else DOWNLOAD_URL}]}


def worker_runner(root: Path, provider: DirectedProvider):
    def run(command, **kwargs):
        directory = Path(command[-1])
        result = execute(root, directory, provider)
        publish(directory / 'progress.json', result)
        return ProcessResult(returncode=0)
    return run


def api_search_result(client, identifier: str) -> dict:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        response = client.get('/api/icon-searches/' + identifier)
        assert response.status_code == 200, response.text
        result = response.json()
        if result['finished_at']:
            return result
        time.sleep(0.01)
    pytest.fail('Synthetic search did not finish')


def test_split_configuration_does_not_require_the_unused_provider(tmp_path):
    search_configuration(tmp_path)
    config = load_config(tmp_path, require_vision=False)
    assert config['serpapi_key'] == SEARCH_SECRET
    assert 'vision_key' not in config
    with pytest.raises(FxfetchError):
        load_config(tmp_path)

    vision_configuration(tmp_path)
    config = load_config(tmp_path, require_search=False)
    assert config['vision_model'] == 'synthetic-image-model'
    assert 'serpapi_key' not in config
    with pytest.raises(FxfetchError):
        load_config(tmp_path)


def test_provider_search_only_public_projection_has_no_vision_dependency(monkeypatch):
    provider = Provider({'serpapi_key': SEARCH_SECRET})

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, maximum):
            return json.dumps({'echo': SEARCH_SECRET, 'organic_results': [
                {'link': DOWNLOAD_URL, 'title': SEARCH_SECRET},
                {'link': DOWNLOAD_URL + '?echo=' + SEARCH_SECRET, 'title': NAME},
            ]}).encode()[:maximum]

    class Opener:
        def open(self, *args, **kwargs):
            return Response()

    monkeypatch.setattr(provider, 'opener', Opener())
    result = provider.search_name(NAME, 'download_page')
    assert result == {'_channel': 'targeted_download',
                      'organic_results': [{'link': DOWNLOAD_URL, 'title': ''}]}
    assert SEARCH_SECRET not in json.dumps(result)
    assert provider.last_timing['route'] == 'direct'


def test_provider_builds_two_fixed_text_queries_without_image_identifiers(monkeypatch):
    provider = Provider({'serpapi_key': SEARCH_SECRET})
    requests = []

    def request(url, **kwargs):
        requests.append(parse_qs(urlsplit(url).query))
        return {'organic_results': []}

    monkeypatch.setattr(provider, 'request', request)
    first = provider.search_name(NAME, 'sample_index')
    second = provider.search_name(NAME, 'download_page')
    assert len(requests) == 2
    assert all(row['engine'] == ['google'] and 'image_id' not in row for row in requests)
    assert all('"' + NAME + '"' in row['q'][0] for row in requests)
    assert requests[0]['q'] != requests[1]['q']
    assert 'site:koodous.com' in requests[0]['q'][0]
    assert first['_channel'] == 'sample_index'
    assert second['_channel'] == 'targeted_download'


def test_sample_index_category_requires_real_source_not_query_scope():
    spoof = 'https://koodous.com.evil.synthetic.test/apks/' + 'b' * 64
    response = {'_channel': 'sample_index', 'organic_results': [
        {'title': NAME, 'link': SAMPLE_URL},
        {'title': NAME, 'link': spoof},
        {'title': NAME, 'link': 'https://unrelated.synthetic.test/article'},
        {'title': NAME + ' APK', 'link': DOWNLOAD_URL},
    ]}
    result = {item['url']: item for item in candidates([response], NAME)}
    assert result[SAMPLE_URL]['category'] == 'sample_index'
    assert result[spoof]['category'] != 'sample_index'
    assert result['https://unrelated.synthetic.test/article']['category'] != 'sample_index'
    assert result[DOWNLOAD_URL]['category'] == 'download_page'
    assert all(item['verified'] is False and item['downloadable'] is None for item in result.values())


def test_recognition_only_uses_vision_and_returns_name_for_user_confirmation(tmp_path, monkeypatch):
    vision_configuration(tmp_path)
    provider = DirectedProvider()
    monkeypatch.setattr(service_module, 'run_limited', worker_runner(tmp_path, provider))
    service = IconSearchService(tmp_path)
    try:
        first = service.submit_recognition('owner', 'recognition', picture())
        result = wait(service, 'owner', first['id'])
        assert result['state'] == 'completed' and result['mode'] == 'recognize'
        assert result['result'] == 'recognized' and result['recognition']['name'] == NAME
        assert result['candidates'] == [] and result['search_attempts'] == 0
        assert result['candidate_requests'] == 0
        assert provider.calls == [('recognize',)]
        directory = service.directory / first['id']
        assert (directory / 'input.image').read_bytes() == picture()
        assert (directory / 'preview.jpg').is_file() and (directory / 'icon.jpg').is_file()
    finally:
        service.close()


def test_name_search_needs_no_image_or_vision_and_does_not_fetch_candidates(tmp_path, monkeypatch):
    search_configuration(tmp_path)
    provider = DirectedProvider()
    monkeypatch.setattr(service_module, 'run_limited', worker_runner(tmp_path, provider))
    service = IconSearchService(tmp_path)
    try:
        first = service.submit_name('owner', 'name', NAME)
        result = wait(service, 'owner', first['id'])
        assert result['state'] == 'completed' and result['mode'] == 'name'
        assert result['query_name'] == NAME and result['search_attempts'] == 2
        assert result['candidate_requests'] == 0 and len(result['candidates']) == 2
        assert provider.calls == [('quota',), ('search_name', NAME, 'sample_index'),
                                  ('search_name', NAME, 'download_page')]
        directory = service.directory / first['id']
        assert not (directory / 'input.image').exists() and not (directory / 'icon.jpg').exists()
    finally:
        service.close()


def test_name_second_query_failure_preserves_first_query_candidates(tmp_path, monkeypatch):
    search_configuration(tmp_path)
    provider = DirectedProvider(fail_second=True)
    monkeypatch.setattr(service_module, 'run_limited', worker_runner(tmp_path, provider))
    service = IconSearchService(tmp_path)
    try:
        first = service.submit_name('owner', 'partial', NAME)
        result = wait(service, 'owner', first['id'])
        assert result['state'] == 'partial' and result['error'] == 'icon_provider_timeout'
        assert len(result['candidates']) == 1 and result['candidates'][0]['url'] == SAMPLE_URL
        assert result['candidate_requests'] == 0
        assert len([call for call in provider.calls if call[0] == 'search_name']) == 2
    finally:
        service.close()


def test_modes_share_single_slot_and_mode_bound_idempotency(tmp_path, monkeypatch):
    configure(tmp_path)
    started = threading.Event()

    def runner(command, **kwargs):
        started.set()
        kwargs['cancel'].wait(5)
        return ProcessResult(returncode=None, cancelled=True)

    monkeypatch.setattr(service_module, 'run_limited', runner)
    service = IconSearchService(tmp_path)
    try:
        first = service.submit_name('owner', 'same-key', NAME)
        assert started.wait(2)
        assert service.submit_name('owner', 'same-key', NAME)['id'] == first['id']
        for submit in [lambda: service.submit_name('owner', 'same-key', NAME + '二'),
                       lambda: service.submit_recognition('owner', 'same-key', picture()),
                       lambda: service.submit('owner', 'same-key', picture())]:
            with pytest.raises(FxfetchError, match='idempotency_conflict'):
                submit()
        with pytest.raises(FxfetchError, match='icon_search_busy'):
            service.submit_recognition('other-owner', 'new-recognition', picture())
        assert service.cleanup(time.time() + 30 * 86400) == 0
        service.cancel('owner', first['id'])
        assert wait(service, 'owner', first['id'])['state'] == 'cancelled'
    finally:
        service.close()


def test_modes_share_existing_twenty_submission_budget(tmp_path):
    configure(tmp_path)
    service = IconSearchService(tmp_path)
    try:
        with service.db() as db:
            for number in range(20):
                db.execute('INSERT INTO searches(id,owner,idem,digest,created,finished,state,result) '
                           'VALUES(?,?,?,?,?,?,?,?)',
                           (f'{number:032x}', 'old-owner', 'old-' + str(number), 'synthetic-digest',
                            time.time(), time.time(), 'completed', '{"state":"completed"}'))
        with pytest.raises(FxfetchError, match='icon_daily_limit'):
            service.submit_name('new-owner', 'new-name', NAME)
        with pytest.raises(FxfetchError, match='icon_daily_limit'):
            service.submit_recognition('new-owner', 'new-recognition', picture())
    finally:
        service.close()


@pytest.mark.parametrize('name', ['', '   ', '\n阅读', 'read\x00er', 'https://private.synthetic.test/a',
                                  '阅读 site:evil.synthetic.test', '阅读" OR site:evil.test', 'a' * 101])
def test_invalid_names_never_start_a_worker(tmp_path, monkeypatch, name):
    search_configuration(tmp_path)
    calls = []
    monkeypatch.setattr(service_module, 'run_limited', lambda *args, **kwargs: calls.append(args))
    service = IconSearchService(tmp_path)
    try:
        with pytest.raises(FxfetchError):
            service.submit_name('owner', 'invalid', name)
        assert calls == [] and not service.active
        with service.db() as db:
            assert db.execute('SELECT COUNT(*) FROM searches').fetchone()[0] == 0
    finally:
        service.close()


def test_api_name_search_auth_and_collect_are_text_only(running, monkeypatch):  # noqa: F811
    client, jobs, workflow, _ = running
    search_configuration(jobs.store.root)
    provider = DirectedProvider()
    monkeypatch.setattr(service_module, 'run_limited', worker_runner(jobs.store.root, provider))
    assert client.post('/api/name-searches', json={'name': NAME},
                       headers={'Origin': 'http://testserver'}).status_code == 401
    headers = login(client)
    assert client.post('/api/name-searches', json={'name': NAME},
                       headers={'Origin': 'http://testserver'}).status_code == 403
    response = client.post('/api/name-searches', json={'name': NAME},
                           headers={**headers, 'Idempotency-Key': 'synthetic-name'})
    assert response.status_code == 202, response.text
    result = api_search_result(client, response.json()['id'])
    assert result['query_name'] == NAME and workflow.calls == []
    record = next(c for c in result['candidates'] if c['category'] == 'sample_index')
    rejected = client.post(f"/api/icon-searches/{result['id']}/collect",
                           json={'candidate_id': record['id']},
                           headers={**headers, 'Idempotency-Key': 'synthetic-record-collect'})
    assert rejected.status_code == 400 and 'invalid_selection' in rejected.text
    assert workflow.calls == []
    download = next(c for c in result['candidates'] if c['category'] == 'download_page')
    accepted = client.post(f"/api/icon-searches/{result['id']}/collect",
                           json={'candidate_id': download['id']},
                           headers={**headers, 'Idempotency-Key': 'synthetic-name-collect'})
    assert accepted.status_code == 202, accepted.text
    source = jobs.store.root / 'jobs' / accepted.json()['id'] / 'source'
    assert json.loads((source / 'input.json').read_text(encoding='utf-8'))['kind'] == 'name_search'
    evidence = json.loads((source / 'name-search.json').read_text(encoding='utf-8'))
    assert evidence['query_name'] == NAME
    assert not (source / 'image.original').exists() and not (source / 'icon.jpg').exists()
    assert client.delete('/api/jobs', headers=headers).status_code == 200
    assert client.get('/api/icon-searches/' + result['id']).status_code == 404


def test_api_recognition_and_corrected_name_preserve_original_picture(running, monkeypatch):  # noqa: F811
    client, jobs, workflow, _ = running
    configure(jobs.store.root)
    provider = DirectedProvider()
    monkeypatch.setattr(service_module, 'run_limited', worker_runner(jobs.store.root, provider))
    headers = login(client)
    recognized = client.post('/api/icon-recognitions', files={'file': ('synthetic.png', picture())},
                             headers={**headers, 'Idempotency-Key': 'synthetic-recognition'})
    assert recognized.status_code == 202, recognized.text
    original = api_search_result(client, recognized.json()['id'])
    assert original['result'] == 'recognized' and provider.calls == [('recognize',)]
    corrected_name = NAME + '修正版'
    searched = client.post('/api/name-searches',
                           json={'name': corrected_name, 'recognition_id': original['id']},
                           headers={**headers, 'Idempotency-Key': 'synthetic-corrected-name'})
    assert searched.status_code == 202, searched.text
    result = api_search_result(client, searched.json()['id'])
    assert result['query_name'] == corrected_name
    download = next(c for c in result['candidates'] if c['category'] == 'download_page')
    accepted = client.post(f"/api/icon-searches/{result['id']}/collect",
                           json={'candidate_id': download['id']},
                           headers={**headers, 'Idempotency-Key': 'synthetic-corrected-collect'})
    assert accepted.status_code == 202, accepted.text
    source = jobs.store.root / 'jobs' / accepted.json()['id'] / 'source'
    evidence = json.loads((source / 'name-search.json').read_text(encoding='utf-8'))
    assert evidence['query_name'] == corrected_name
    assert evidence['recognition_id'] == original['id']
    assert evidence['recognition']['name'] == NAME
    assert (source / 'image.original').read_bytes() == picture()
    assert (source / 'icon.jpg').is_file()
    assert workflow.calls == [] or workflow.calls == [DOWNLOAD_URL]


def test_recognition_reference_must_be_owned_completed_and_visible(tmp_path, monkeypatch):
    configure(tmp_path)
    provider = DirectedProvider()
    monkeypatch.setattr(service_module, 'run_limited', worker_runner(tmp_path, provider))
    service = IconSearchService(tmp_path)
    try:
        first = service.submit_recognition('owner', 'recognition', picture())
        original = wait(service, 'owner', first['id'])
        assert original['result'] == 'recognized'
        with pytest.raises(FxfetchError):
            service.submit_name('other-owner', 'foreign', NAME, recognition_id=original['id'])
        failed = service.submit_recognition('owner', 'invalid-image', b'synthetic-invalid-image')
        assert wait(service, 'owner', failed['id'])['state'] == 'failed'
        with pytest.raises(FxfetchError):
            service.submit_name('owner', 'failed-source', NAME, recognition_id=failed['id'])
        service.clear('owner')
        with pytest.raises(FxfetchError):
            service.submit_name('owner', 'hidden-source', NAME, recognition_id=original['id'])
    finally:
        service.close()


@pytest.mark.parametrize('body', [{'name': 42}, {'name': NAME, 'recognition_id': '../escape'},
                                 {'name': NAME, 'unexpected': 'synthetic'}])
def test_api_name_input_is_strict(running, body):  # noqa: F811
    client, _, workflow, _ = running
    response = client.post('/api/name-searches', json=body,
                           headers={**login(client), 'Idempotency-Key': 'synthetic-invalid-name'})
    assert response.status_code == 422, response.text
    assert workflow.calls == []
