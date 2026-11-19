"""Durable name-search evidence and collection boundaries with synthetic providers only."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from test_api import encoded_password, login, running  # noqa: F401
from test_icon_search import configure, picture, wait
from test_name_search import NAME, DirectedProvider, api_search_result, worker_runner

from fxfetch.core.errors import FxfetchError
from fxfetch.icon_search import service as service_module
from fxfetch.icon_search.service import IconSearchService, saved_candidates
from fxfetch.icon_search.worker import publish


class RecoveryProvider(DirectedProvider):
    catalog_enabled = True
    web_enabled = True

    def quota(self, minimum=2):
        self.calls.append(('quota', minimum))
        return 200

    def recognize(self, image):
        result = super().recognize(image)
        result['icon_box'] = None
        return result

    def search_catalog(self, name):
        self.calls.append(('search_catalog', name))
        return {'records': [
            {'sha256': f'{number:064x}', 'app_name': name,
             'package_name': f'test.synthetic.app{number}', 'version': f'1.{number}',
             'url': f'https://koodous.com/apks/{number:064x}'}
            for number in range(1, 21)
        ], 'count': 20, 'returned': 20, 'next_page_available': False, 'coverage_complete': True}

    def search_name(self, name, scope):
        self.calls.append(('search_name', name, scope))
        assert scope == 'download_page'
        return {'organic_results': [
            {'title': f'{name} Android APK {number}',
             'link': f'https://download.synthetic.test/{number}.apk'}
            for number in range(1, 21)
        ]}


def configured_service(root: Path, monkeypatch) -> tuple[IconSearchService, RecoveryProvider]:
    configure(root)
    path = root / 'icon-search.json'
    config = json.loads(path.read_text(encoding='utf-8'))
    config['koodous_key'] = 'synthetic-recovery-catalog-key'
    path.write_text(json.dumps(config), encoding='utf-8')
    provider = RecoveryProvider()
    monkeypatch.setattr(service_module, 'run_limited', worker_runner(root, provider))
    return IconSearchService(root), provider


def leave_interrupted(service: IconSearchService, result: dict) -> None:
    """Keep real submitted request/digest but emulate a crash after a durable search snapshot."""
    snapshot = {key: value for key, value in result.items()
                if key not in ('id', 'created_at', 'finished_at', 'expires_at')}
    snapshot.update(state='running', stage='catalog_search')
    publish(service.directory / result['id'] / 'progress.json', snapshot)
    with service.db() as db:
        db.execute("UPDATE searches SET state='running',finished=NULL WHERE id=?", (result['id'],))
    service.close()


def restart(root: Path, monkeypatch) -> IconSearchService:
    def no_replay(*args, **kwargs):
        pytest.fail('Restart must not replay a provider search or acquisition')
    monkeypatch.setattr(service_module, 'run_limited', no_replay)
    service = IconSearchService(root)
    service.start()
    return service


def test_restart_preserves_name_query_all_forty_candidates_and_catalog_metadata(tmp_path, monkeypatch):
    service, provider = configured_service(tmp_path, monkeypatch)
    first = service.submit_name('owner', 'forty-candidates', NAME)
    original = wait(service, 'owner', first['id'])
    assert len(original['candidates']) == 40
    assert provider.calls == [('search_catalog', NAME), ('quota', 1),
                              ('search_name', NAME, 'download_page')]
    leave_interrupted(service, original)

    restored = restart(tmp_path, monkeypatch)
    try:
        result = restored.get('owner', first['id'])
        assert result['state'] == 'partial' and result['query_name'] == NAME
        assert result['error_detail'] == {'stage': 'catalog_search', 'code': 'icon_interrupted'}
        assert result['catalog_status'] == original['catalog_status']
        assert result['candidates'] == original['candidates']
        assert result['candidates'][-1]['id'] == '40'
        record = result['candidates'][0]
        assert record['category'] == 'sample_record' and record['channel'] == 'koodous_api'
        assert record['catalog'] == 'Koodous' and record['can_collect'] is False
        assert record['app_name'] == NAME and record['package_name'] == 'test.synthetic.app1'
        assert record['version'] == '1.1' and record['sha256'] == f'{1:064x}'
        assert record['verified'] is False and record['downloadable'] is None
        assert not restored.active
        with pytest.raises(FxfetchError, match='not_found'):
            restored.get('other-owner', first['id'])
    finally:
        restored.close()


@pytest.mark.parametrize('tamper', ['query', 'request', 'both'])
def test_restart_rejects_query_or_request_tampering_even_when_they_agree(tmp_path, monkeypatch, tamper):
    service, _ = configured_service(tmp_path, monkeypatch)
    first = service.submit_name('owner', 'tamper-name', NAME)
    original = wait(service, 'owner', first['id'])
    directory = service.directory / first['id']
    if tamper in ('query', 'both'):
        original['query_name'] = NAME + 'changed'
    if tamper in ('request', 'both'):
        path = directory / 'request.json'
        request = json.loads(path.read_text(encoding='utf-8'))
        request['name'] = NAME + 'changed'
        path.write_text(json.dumps(request), encoding='utf-8')
    leave_interrupted(service, original)

    restored = restart(tmp_path, monkeypatch)
    try:
        result = restored.get('owner', first['id'])
        assert result['state'] == 'failed' and result['candidates'] == []
        assert result['error'] == 'icon_interrupted' and not restored.active
    finally:
        restored.close()


@pytest.mark.parametrize('tamper', [None, 'input.image', 'icon.jpg', 'request_hash',
                                   'coordinated_hash', 'recognition_metadata'])
def test_restart_recognition_link_allows_uncropped_image_but_verifies_hashes(tmp_path, monkeypatch, tamper):
    service, _ = configured_service(tmp_path, monkeypatch)
    recognition = service.submit_recognition('owner', 'uncropped-recognition', picture())
    recognized = wait(service, 'owner', recognition['id'])
    assert recognized['result'] == 'recognized' and recognized['crop_applied'] is False
    first = service.submit_name('owner', 'linked-search', NAME, recognition_id=recognition['id'])
    original = wait(service, 'owner', first['id'])
    directory = service.directory / first['id']
    assert original['candidates'] and original['recognition_id'] == recognition['id']
    assert (directory / 'input.image').read_bytes() == picture()
    if tamper in ('input.image', 'icon.jpg'):
        (directory / tamper).write_bytes(b'changed-synthetic-image')
    elif tamper == 'request_hash':
        path = directory / 'request.json'
        request = json.loads(path.read_text(encoding='utf-8'))
        request['icon_sha256'] = 'f' * 64
        path.write_text(json.dumps(request), encoding='utf-8')
    elif tamper == 'coordinated_hash':
        changed = b'changed-synthetic-image-with-consistent-snapshot-hash'
        (directory / 'input.image').write_bytes(changed)
        original['input_sha256'] = hashlib.sha256(changed).hexdigest()
        path = directory / 'request.json'
        request = json.loads(path.read_text(encoding='utf-8'))
        request['input_sha256'] = original['input_sha256']
        path.write_text(json.dumps(request), encoding='utf-8')
    elif tamper == 'recognition_metadata':
        original['recognition'] = {**original['recognition'], 'name': 'changed synthetic visible name'}
    leave_interrupted(service, original)

    restored = restart(tmp_path, monkeypatch)
    try:
        result = restored.get('owner', first['id'])
        assert result['state'] == ('partial' if tamper is None else 'failed')
        assert result['candidates'] == (original['candidates'] if tamper is None else [])
        if tamper is None:
            restored.validate_evidence(first['id'], result)
            assert restored.evidence_files(first['id'], result)[0] == picture()
    finally:
        restored.close()


def test_api_rejects_catalog_record_collection_but_keeps_fortieth_web_candidate(running, monkeypatch):  # noqa: F811
    client, jobs, workflow, _ = running
    configured, provider = configured_service(jobs.store.root, monkeypatch)
    configured.close()
    headers = login(client)
    response = client.post('/api/name-searches', json={'name': NAME},
                           headers={**headers, 'Idempotency-Key': 'catalog-and-web'})
    assert response.status_code == 202, response.text
    result = api_search_result(client, response.json()['id'])
    record, tail = result['candidates'][0], result['candidates'][-1]
    assert len(result['candidates']) == 40 and tail['id'] == '40'
    assert record['category'] == 'sample_record' and record['can_collect'] is False
    rejected = client.post(f"/api/icon-searches/{result['id']}/collect",
                           json={'candidate_id': record['id']},
                           headers={**headers, 'Idempotency-Key': 'catalog-no-collect'})
    assert rejected.status_code == 400 and 'invalid_selection' in rejected.text
    assert workflow.calls == []
    icons = client.app.state.icon_search
    for number, url in enumerate((f'https://koodous.com/apks/{1:064x}',
                                  f'https://www.virustotal.com/gui/file/{1:064x}',
                                  f'https://bazaar.abuse.ch/sample/{1:064x}/')):
        legacy = {key: record[key] for key in
                  ('id', 'title', 'evidence', 'verified', 'downloadable')}
        legacy.update(url=url, source=url.split('/')[2])
        snapshot = {**result, 'candidates': [legacy]}
        recovered = saved_candidates(snapshot)
        assert len(recovered) == 1 and recovered[0]['category'] == 'sample_index'
        assert recovered[0]['can_collect'] is False
        with icons.db() as db:
            db.execute('UPDATE searches SET result=? WHERE id=?',
                       (json.dumps(snapshot), result['id']))
        rejected = client.post(f"/api/icon-searches/{result['id']}/collect",
                               json={'candidate_id': legacy['id']},
                               headers={**headers, 'Idempotency-Key': f'legacy-sample-{number}'})
        assert rejected.status_code == 400 and 'invalid_selection' in rejected.text
        assert workflow.calls == []
    with icons.db() as db:
        db.execute('UPDATE searches SET result=? WHERE id=?', (json.dumps(result), result['id']))
    accepted = client.post(f"/api/icon-searches/{result['id']}/collect",
                           json={'candidate_id': tail['id']},
                           headers={**headers, 'Idempotency-Key': 'web-tail-collect'})
    assert accepted.status_code == 202, accepted.text
    source = jobs.store.root / 'jobs' / accepted.json()['id'] / 'source' / 'name-search.json'
    evidence = json.loads(source.read_text(encoding='utf-8'))
    assert evidence['candidate']['id'] == '40' and evidence['candidate']['url'] == tail['url']
    assert evidence['query_name'] == NAME and provider.calls == [
        ('search_catalog', NAME), ('quota', 1), ('search_name', NAME, 'download_page')]
