"""Offline case-candidate lookup, retained sample downloads and lifecycle checks."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_bazaar_provider as bazaar_provider
from test_api import ORIGIN, encoded_password, login, running  # noqa: F401
from test_malshare_provider import Response, capture
from test_name_catalog import CatalogProvider, catalog_payload
from test_name_search import NAME, api_search_result, worker_runner
from test_workflow import apk_bytes

from fxfetch.core.process_limits import ProcessResult
from fxfetch.icon_search import service as search_module
from fxfetch.retention import SECONDS
from fxfetch.web import malshare_service, malshare_worker


@pytest.fixture
def case(running, monkeypatch):  # noqa: F811
    client, jobs, workflow, _ = running
    root = jobs.store.root
    root.joinpath('icon-search.json').write_text(json.dumps({
        'koodous_key': 'synthetic-catalog', 'malshare_key': 'synthetic-malshare',
        'malwarebazaar_key': bazaar_provider.KEY,
    }), encoding='utf-8')
    apk = apk_bytes()
    digest = hashlib.sha256(apk).hexdigest()
    provider = CatalogProvider(payload=catalog_payload(records=[{'sha256': digest, 'app_name': NAME}]))
    monkeypatch.setattr(search_module, 'run_limited', worker_runner(root, provider))
    calls = []

    def local_worker(command, **kwargs):
        assert command[1:3] == ['-m', 'fxfetch.web.malshare_worker']
        assert kwargs['timeout'] == 180 and kwargs['max_output_bytes'] == 4096
        provider, action, sha, destination = command[-4:]
        assert sha == digest
        calls.append(action if provider == 'malshare' else provider + '/' + action)
        value = malshare_worker.perform(root, action, sha, Path(destination), malshare_worker.SampleProvider(provider))
        return ProcessResult(0, stdout=json.dumps(value).encode())

    monkeypatch.setattr(malshare_service, 'run_limited', local_worker)
    headers = login(client)
    created = client.post('/api/name-searches', json={'name': NAME},
                          headers={**headers, 'Idempotency-Key': 'case-name-search'})
    assert created.status_code == 202
    identifier = created.json()['id']
    result = api_search_result(client, identifier)
    assert result['state'] == 'completed' and result['malshare'] == result['malwarebazaar'] == {} and calls == []
    base = f'/api/icon-searches/{identifier}/candidates/1/malshare'
    service = client.app.state.malshare

    def post(action, key, body=None, provider='malshare'):
        path = f'/api/icon-searches/{identifier}/candidates/1/{provider}/{action}'
        return client.post(path, json=body or {},
                           headers={**headers, 'Idempotency-Key': key})

    return SimpleNamespace(**locals())


def hit(case, monkeypatch):
    capture(monkeypatch, Response(json.dumps({'SHA256': case.digest}).encode()))
    res = case.post('lookup', 'check-fixture')
    assert res.status_code == 200 and res.json()['lookup']['status'] == 'hit', res.text
    return res.json()


def obtain(case, monkeypatch):
    hit(case, monkeypatch)
    capture(monkeypatch, Response(case.apk))
    response = case.post('download', 'download-fixture')
    assert response.status_code == 200 and response.json()['download']['status'] == 'downloaded', response.text
    return response.json()['file_url']


def test_explicit_distinct_actions_idempotent_and_independent_of_collection(case, monkeypatch):
    assert case.client.get('/api/capabilities').json()['icon_search']['malshare_enabled']
    assert case.client.get(case.base + '/file').status_code == 404
    assert case.post('download', 'download-too-soon').status_code == 409
    assert case.post('lookup', 'forged-digest', {'sha256': case.digest}).status_code == 422
    assert case.post('download', 'forged-url', {'url': 'https://example.invalid/x.apk'}).status_code == 422
    assert case.client.post(case.base + '/lookup', json={}, headers=ORIGIN).status_code == 403
    assert case.client.post(case.base + '/lookup', json={}, headers=case.headers).status_code == 400
    assert case.calls == []
    file_url = obtain(case, monkeypatch)
    assert file_url == case.base + '/file'
    for key in ('download-fixture', 'already-downloaded'):
        assert case.post('download', key).json()['file_url'] == file_url
    assert case.post('lookup', 'download-fixture').status_code == 409
    assert case.post('lookup', 'check-fixture').json()['file_url'] == file_url
    result = case.client.get('/api/icon-searches/' + case.identifier).json()
    assert result['malshare']['1']['download']['size'] == len(case.apk)
    assert result['candidates'] == case.result['candidates'] and result['candidate_requests'] == 0
    response = case.client.get(file_url)
    assert response.content == case.apk and case.digest in response.headers['content-disposition']
    assert case.calls == ['lookup', 'download'] and case.workflow.calls == []
    assert case.client.get('/api/jobs').json()['jobs'] == []


def test_no_record_failure_replay_and_manual_retry(case, monkeypatch):
    capture(monkeypatch, Response(b'Sample not found'))
    first = case.post('lookup', 'missing-sample').json()
    assert first['lookup']['status'] == 'no_record' and first['file_url'] is None
    assert case.post('download', 'no-hit-so-far').status_code == 409
    assert case.post('lookup', 'missing-sample').json() == first
    capture(monkeypatch, Response(b'private response', status=429))
    retry = case.post('lookup', 'another-check')
    receipt = retry.json()['lookup']
    assert receipt['status'] == 'failed' and receipt['code'] == 'malshare_quota' and receipt['http_status'] == 429
    assert 'private response' not in retry.text
    hit(case, monkeypatch)
    capture(monkeypatch, Response(b'incorrect bytes'))
    failed = case.post('download', 'attempt-download').json()
    assert failed['download']['code'] == 'malshare_hash_mismatch' and failed['file_url'] is None
    assert case.client.get(case.base + '/file').status_code == 404
    assert not list((case.root / 'icon-searches' / case.identifier).glob('malshare-*'))
    assert case.calls == ['lookup', 'lookup', 'lookup', 'download']


def test_stream_bound_to_owner_retention_and_same_file_digest(case, monkeypatch):
    file_url = obtain(case, monkeypatch)
    searches = case.service.searches
    with searches.db() as db:
        owner = db.execute('SELECT owner FROM searches WHERE id=?', (case.identifier,)).fetchone()[0]
    with case.service.open_file(owner, case.identifier, '1') as (stream, _, _):
        assert searches.cleanup(time.time() + SECONDS + 10) == 0
        assert stream.read() == case.apk
    [path] = (searches.directory / case.identifier).glob('malshare-*/sample.apk')
    path.write_bytes(bytes(len(case.apk)))
    response = case.client.get(file_url)
    assert response.status_code == 400 and response.json()['error']['code'] == 'malshare_hash_mismatch'
    invalidated = case.client.get('/api/icon-searches/' + case.identifier).json()['malshare']['1']
    assert invalidated['file_url'] is None and invalidated['download']['status'] == 'failed'
    capture(monkeypatch, Response(case.apk))
    repaired = case.post('download', 'explicit-repair').json()
    assert repaired['download']['status'] == 'downloaded' and case.client.get(file_url).content == case.apk
    assert not searches.retained and case.service.readers == 0
    other_headers = login(case.client)
    for method in ('lookup', 'download'):
        assert case.client.post(case.base + '/' + method, headers={**other_headers, 'Idempotency-Key': 'in-other-session'},
                                json={}).status_code == 404
    assert case.client.get(file_url).status_code == 404
    assert searches.cleanup(time.time() + SECONDS + 10) == 1
    assert not path.exists() and case.calls == ['lookup', 'download', 'download']
    with searches.db() as db:
        assert not db.execute('SELECT 1 FROM malshare_actions').fetchone()


@pytest.mark.parametrize('change', ['expired', 'hidden', 'name_evidence', 'bad_sha', 'web_record', 'missing_api_evidence'])
def test_invalid_or_unavailable_candidate_never_queries_provider(case, change):
    searches = case.service.searches
    with searches.db() as db:
        if change == 'expired':
            db.execute('UPDATE searches SET finished=?', (time.time() - SECONDS - 1,))
        elif change == 'hidden':
            db.execute('UPDATE searches SET hidden=1')
        elif change == 'name_evidence':
            (searches.directory / case.identifier / 'request.json').write_bytes(b'{}')
        else:
            result = json.loads(db.execute('SELECT result FROM searches').fetchone()[0])
            candidate = result['candidates'][0]
            if change == 'bad_sha':
                candidate['sha256'] = 'b' * 64
            elif change == 'web_record':
                candidate.update(category='sample_index', channel='sample_index')
            else:
                candidate['evidence'] = ['name_in_title']
            db.execute('UPDATE searches SET result=?', (json.dumps(result),))
    assert case.post('lookup', 'invalid-case').status_code in (400, 404)
    assert not case.calls


def test_single_flight_download_budget_and_interruption_cleanup(case, monkeypatch):
    hit(case, monkeypatch)
    monkeypatch.setattr(malshare_service, 'LIMITS', replace(malshare_service.LIMITS, max_task_bytes=1))
    assert case.post('download', 'disk-budget').status_code == 429
    monkeypatch.setattr(malshare_service, 'LIMITS', replace(malshare_service.LIMITS, max_task_bytes=1024**3))
    entered, release = threading.Event(), threading.Event()

    def interrupt(command, **kwargs):
        Path(command[-1]).with_suffix('.part').write_bytes(b'partial')
        entered.set()
        assert release.wait(5)
        return ProcessResult(None, timed_out=True)

    monkeypatch.setattr(malshare_service, 'run_limited', interrupt)
    with ThreadPoolExecutor(1) as executor:
        run = executor.submit(case.post, 'download', 'bounded-download')
        assert entered.wait(2)
        try:
            duplicate = case.post('download', 'bounded-download')
            assert duplicate.json()['download']['status'] == 'running'
            assert case.post('lookup', 'blocked-while-running').status_code == 409
            assert case.service.searches.cleanup(time.time() + SECONDS + 10) == 0
        finally:
            release.set()
        assert run.result().json()['download']['code'] == 'malshare_timeout'
    assert not list((case.root / 'icon-searches' / case.identifier).glob('malshare-*'))
    assert case.client.get(case.base + '/file').status_code == 404
    with case.service.searches.db() as db:
        db.execute("UPDATE malshare_actions SET status='running', bytes_reserved=123 WHERE action='download'")
    case.service.recover()
    receipt = case.post('download', 'bounded-download').json()
    assert receipt['download']['code'] == 'malshare_interrupted' and case.calls == ['lookup']


def test_clear_during_publication_discards_late_file_and_releases_slot(case, monkeypatch):
    hit(case, monkeypatch)
    published = threading.Event()

    def publish_then_cancel(command, **kwargs):
        Path(command[-1]).write_bytes(case.apk)
        published.set()
        assert kwargs['cancel'].wait(5)
        return ProcessResult(0, stdout=json.dumps({'status': 'downloaded', 'size': len(case.apk)}).encode())

    monkeypatch.setattr(malshare_service, 'run_limited', publish_then_cancel)
    with ThreadPoolExecutor(1) as executor:
        run = executor.submit(case.post, 'download', 'while-clearing')
        assert published.wait(3)
        assert case.client.delete('/api/jobs', headers=case.headers).status_code == 200
        assert run.result().status_code == 404
    assert case.post('lookup', 'after-clearing').status_code == 404
    assert case.client.get(case.base + '/file').status_code == 404
    assert not list((case.root / 'icon-searches' / case.identifier).glob('malshare-*'))
    with case.service.searches.db() as db:
        row = db.execute("SELECT status,code,bytes_reserved FROM malshare_actions WHERE action='download'").fetchone()
        assert tuple(row) == ('failed', 'malshare_interrupted', 0)
    assert case.service.operation is None and not case.service.searches.retained


def test_unexpected_worker_fault_frees_slot_without_replay(case, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError('synthetic private error detail')
    monkeypatch.setattr(malshare_service, 'run_limited', broken)
    failed = case.post('lookup', 'worker-fault')
    assert failed.json()['lookup']['code'] == 'malshare_worker_failed'
    assert 'private error detail' not in failed.text
    monkeypatch.setattr(malshare_service, 'run_limited', case.local_worker)
    hit(case, monkeypatch)
    assert case.calls == ['lookup']


def test_missing_local_sample_can_be_retried_by_explicit_request(case, monkeypatch):
    file_url = obtain(case, monkeypatch)
    [path] = (case.root / 'icon-searches' / case.identifier).glob('malshare-*/sample.apk')
    path.unlink()
    assert case.client.get(file_url).status_code in (400, 404)
    old = case.post('download', 'download-fixture').json()
    assert old['file_url'] is None and old['download']['code'] == 'artifact_missing'
    assert case.calls == ['lookup', 'download']
    capture(monkeypatch, Response(case.apk))
    assert case.post('download', 'explicit-recovery').json()['file_url'] == file_url
    assert case.client.get(file_url).content == case.apk


@pytest.fixture
def bazaar(case, monkeypatch):
    """Run the provider and archive validator against synthetic HTTPS responses."""
    lookup_result = {'sha256_hash': case.digest}
    archive = bazaar_provider.envelope(('synthetic.sample', case.apk))

    def post(action, key):
        record = {'query_status': 'ok', 'data': [lookup_result]} if lookup_result else {'query_status': 'hash_not_found'}
        body = json.dumps(record).encode() if action == 'lookup' else archive
        bazaar_provider.capture(monkeypatch, bazaar_provider.Response(body))
        return case.post(action, key, provider='malwarebazaar')

    return SimpleNamespace(post=post, lookup_result=lookup_result)


def test_provider_bound_hit_receipts_keys_and_retained_files(case, bazaar, monkeypatch):
    malshare_receipt = hit(case, monkeypatch)
    denied = bazaar.post('download', 'too-early')
    assert denied.status_code == 409 and denied.json()['error']['code'] == 'bazaar_lookup_required'
    bazaar.lookup_result.clear()
    absent = bazaar.post('lookup', 'check-fixture').json()
    assert absent['provider'] == 'MalwareBazaar' and absent['lookup']['status'] == 'no_record'
    assert absent['file_url'] is None and bazaar.post('download', 'still-too-early').status_code == 409
    bazaar.lookup_result.update(sha256_hash='0' * 64)
    mismatch = bazaar.post('lookup', 'different-hash').json()
    assert mismatch['lookup']['code'] == 'bazaar_response_invalid'
    bazaar.lookup_result.update(sha256_hash=case.digest)
    found = bazaar.post('lookup', 'exact-hash').json()
    assert found['lookup']['status'] == 'hit' and found['sha256'] == case.digest
    assert found['download'] is None and found['file_url'] is None
    assert case.post('lookup', 'check-fixture').json() == malshare_receipt
    received = bazaar.post('download', 'download-fixture').json()
    assert received['download']['status'] == 'downloaded'
    assert received['file_url'] == case.base.replace('malshare', 'malwarebazaar') + '/file'
    assert case.client.get(received['file_url']).content == case.apk
    assert bazaar.post('download', 'download-fixture').json() == received
    assert case.client.get(case.base + '/file').status_code == 404
    capture(monkeypatch, Response(case.apk))
    old_file = case.post('download', 'download-fixture').json()['file_url']
    [sample] = (case.service.searches.directory / case.identifier).glob('malwarebazaar-*/sample.apk')
    sample.write_bytes(bytes(len(case.apk)))
    assert case.client.get(received['file_url']).json()['error']['code'] == 'bazaar_hash_mismatch'
    assert case.client.get(old_file).content == case.apk
    result = case.client.get('/api/icon-searches/' + case.identifier).json()
    assert result['malshare']['1']['file_url'] == old_file and result['malwarebazaar']['1']['file_url'] is None
    assert case.calls == ['lookup', 'malwarebazaar/lookup', 'malwarebazaar/lookup', 'malwarebazaar/lookup',
                          'malwarebazaar/download', 'download']
    assert case.workflow.calls == []


def test_bazaar_eligibility_owner_config_and_budget(case, bazaar, monkeypatch):
    assert bazaar.post('lookup', 'selected').json()['lookup']['status'] == 'hit'
    assert case.post('download', 'other-source').status_code == 409
    monkeypatch.setattr(malshare_service, 'DAILY_ACTIONS', 1)
    assert bazaar.post('lookup', 'over-budget').json()['error']['code'] == 'bazaar_daily_limit'
    hit(case, monkeypatch)
    monkeypatch.setattr(malshare_service, 'DAILY_ACTIONS', 10)
    limits = malshare_service.LIMITS
    monkeypatch.setattr(malshare_service, 'LIMITS', replace(limits, max_task_bytes=2 * limits.max_package_bytes - 1))
    assert bazaar.post('download', 'scratch-budget').json()['error']['code'] == 'bazaar_storage_limit'
    monkeypatch.setattr(malshare_service, 'malwarebazaar_configured', lambda root: False)
    assert bazaar.post('download', 'missing-config').json()['error']['code'] == 'bazaar_unconfigured'
    base = case.base.replace('malshare', 'malwarebazaar')
    assert case.post('lookup', 'forged-sha', {'sha256': case.digest}, 'malwarebazaar').status_code == 422
    assert case.client.post(base + '/lookup', headers=ORIGIN, json={}).status_code == 403
    headers = {**login(case.client), 'Idempotency-Key': 'another-owner'}
    assert case.client.post(base + '/lookup', headers=headers, json={}).status_code == 404
    assert case.client.get(base + '/file').status_code == 404
    assert case.calls == ['malwarebazaar/lookup', 'lookup']


def test_migration_preserves_legacy_rows_file_and_idempotency(case, monkeypatch):
    legacy_file = obtain(case, monkeypatch)
    searches = case.service.searches
    with searches.db() as db:
        db.execute('ALTER TABLE malshare_actions DROP COLUMN provider')
        assert 'provider' not in [row[1] for row in db.execute('PRAGMA table_info(malshare_actions)')]
    malshare_service.SampleService(searches).recover()
    assert case.post('download', 'download-fixture').json()['file_url'] == legacy_file
    assert case.client.get(legacy_file).content == case.apk
    result = case.client.get('/api/icon-searches/' + case.identifier).json()
    assert result['malshare']['1']['file_url'] == legacy_file and result['malwarebazaar'] == {}
    assert case.calls == ['lookup', 'download']


def test_bazaar_interruption_cleans_only_its_files_and_expires_both_receipts(case, bazaar, monkeypatch):
    old_file = obtain(case, monkeypatch)
    bazaar.post('lookup', 'lookup-bazaar')
    published = threading.Event()

    def interrupted(command, **kwargs):
        Path(command[-1]).with_suffix('.archive').write_bytes(b'archive in progress')
        published.set()
        assert kwargs['cancel'].wait(5)
        return ProcessResult(None, cancelled=True)

    monkeypatch.setattr(malshare_service, 'run_limited', interrupted)
    with ThreadPoolExecutor(1) as executor:
        run = executor.submit(bazaar.post, 'download', 'clear-bazaar')
        assert published.wait(3)
        assert case.client.get(old_file).content == case.apk
        assert case.client.delete('/api/jobs', headers=case.headers).status_code == 200
        assert run.result().status_code == 404
    searches = case.service.searches
    assert not list((searches.directory / case.identifier).glob('malwarebazaar-*'))
    assert list((searches.directory / case.identifier).glob('malshare-*/sample.apk'))
    with searches.db() as db:
        row = db.execute("SELECT status,code,bytes_reserved FROM malshare_actions "
                         "WHERE action='download' AND provider='malwarebazaar'").fetchone()
        assert tuple(row) == ('failed', 'bazaar_interrupted', 0)
    assert searches.cleanup(time.time() + SECONDS + 10) == 1
    with searches.db() as db:
        assert not db.execute('SELECT 1 FROM malshare_actions').fetchone()
