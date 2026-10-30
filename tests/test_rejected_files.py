import copy
import hashlib
import io
import json
import struct
import threading
import zipfile
from dataclasses import asdict
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from test_workflow import ROOT, SyntheticClient

from fxfetch.config import Settings
from fxfetch.core.download import classify_package
from fxfetch.core.errors import FxfetchError
from fxfetch.core.workflow import Workflow
from fxfetch.rejected_files import open_rejected_file, rejected_files
from fxfetch.security import password_hash, token_hash
from fxfetch.service import JobService
from fxfetch.web.api import create_app


def bad_apk():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('AndroidManifest.xml', b'synthetic-manifest')
        archive.writestr('classes.dex', b'dex\n035\0synthetic-only')
    data = bytearray(buffer.getvalue())
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        offset = archive.getinfo('classes.dex').header_offset
    name_size, extra_size = struct.unpack_from('<HH', data, offset + 26)
    data[offset + 30 + name_size + extra_size] ^= 1
    return bytes(data)


def private_job(tmp_path, *, legacy=False, chrome=False):
    folder = tmp_path / 'jobs' / ('a' * 32)
    path = folder / 'network/direct' / ('partial/0001.package.partial' if chrome else 'web/0000.body')
    path.parent.mkdir(parents=True)
    payload = bad_apk()
    path.write_bytes(payload)
    reason, url = 'archive_invalid', ROOT + '/original.apk'
    body = {'path': str(path), 'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(),
            'complete': True, 'hash_scope': 'decoded_browser_response' if chrome else 'wire',
            'mode': 'android_chrome' if chrome else 'http', 'url': url, 'chain': 'android', 'request_id': 1}
    if not legacy:
        body.update(validation={'status': 'failed', 'reason_code': reason, 'kind': 'apk'}, status_code=200)
    result = {'outcome': 'failed', 'reason_code': reason, 'coverage': 'partial', 'artifacts': [],
              'bodies': [body],
              'attempts': [{'chain': 'android', 'url': url, 'outcome': 'failed', 'reason_code': reason}],
              'hops': [{'chain': 'android', 'url': url, 'request_id': 1, 'status': 200}]}
    return {'id': folder.name, 'state': 'completed', 'outcome': 'failed', 'reason_code': reason,
            'result': result}, folder, path, payload


@pytest.mark.parametrize('legacy,chrome', [(True, False), (False, False), (False, True)])
def test_complete_invalid_archive_bytes_preserved_without_success(tmp_path, legacy, chrome):
    job, folder, path, payload = private_job(tmp_path, legacy=legacy, chrome=chrome)
    original = copy.deepcopy(job)
    with pytest.raises(FxfetchError) as error:
        classify_package(path)
    assert error.value.code == 'archive_invalid'
    items = rejected_files(job, folder, 1024 * 1024)
    assert len(items) == 1
    assert set(items[0].metadata) == {'id', 'filename', 'kind', 'size', 'sha256', 'validation_status', 'reason_code'}
    assert items[0].metadata['validation_status'] == 'failed'
    assert str(folder) not in json.dumps(items[0].metadata)
    stream, metadata = open_rejected_file(job, folder, items[0].metadata['id'], 1024 * 1024)
    with stream:
        assert stream.read() == payload
    assert metadata['sha256'] == hashlib.sha256(payload).hexdigest()
    assert job == original and not job['result']['artifacts']


@pytest.mark.parametrize('change', [
    'cancelled', 'running', 'downloaded', 'timeout', 'partial', 'prefix_hash', 'html',
    'unknown_kind', 'wrong_size', 'bad_hash', 'successful_artifact', 'outside', 'other_job',
])
def test_ineligible_files_not_listed(tmp_path, change):
    job, folder, path, _ = private_job(tmp_path)
    body = job['result']['bodies'][0]
    if change in {'cancelled', 'running'}:
        job['state'] = change
    elif change == 'downloaded':
        job['outcome'] = 'downloaded'
    elif change == 'timeout':
        job['result']['reason_code'] = 'task_timeout'
    elif change == 'partial':
        body['complete'] = False
    elif change == 'prefix_hash':
        body['hash_scope'] = 'saved_prefix'
    elif change == 'html':
        payload = b'<html>not an APK</html>'
        path.write_bytes(payload)
        body.update(size=len(payload), sha256=hashlib.sha256(payload).hexdigest())
    elif change == 'unknown_kind':
        body['url'] = ROOT + '/download'
    elif change == 'wrong_size':
        body['size'] += 1
    elif change == 'bad_hash':
        body['sha256'] = 'not-a-hash'
    elif change == 'successful_artifact':
        job['result']['artifacts'] = [{'path': str(path)}]
    else:
        other = tmp_path / ('outside.apk' if change == 'outside' else 'jobs/other/source.apk')
        other.parent.mkdir(parents=True, exist_ok=True)
        other.write_bytes(path.read_bytes())
        body['path'] = str(other)
    assert not rejected_files(job, folder, 1024 * 1024)


@pytest.mark.parametrize('change', ['attempt_url', 'hop_status', 'hop_id', 'no_hops', 'old_chrome'])
def test_legacy_requires_strict_response_failure_association(tmp_path, change):
    job, folder, _, _ = private_job(tmp_path, legacy=True)
    if change == 'attempt_url':
        job['result']['attempts'][0]['url'] = ROOT + '/other.apk'
    elif change == 'hop_status':
        job['result']['hops'][0]['status'] = 403
    elif change == 'hop_id':
        job['result']['hops'][0]['request_id'] = 2
    elif change == 'no_hops':
        job['result']['hops'] = []
    else:
        job['result']['bodies'][0].update(mode='android_chrome', complete=False, hash_scope='saved_prefix')
    assert not rejected_files(job, folder, 1024 * 1024)


def test_list_does_not_rehash_large_file_but_download_checks_hash(tmp_path, monkeypatch):
    import fxfetch.rejected_files as module

    job, folder, path, payload = private_job(tmp_path)
    original_sha = hashlib.sha256

    def no_stream_hash(data=None):
        assert data is not None, 'listing must not stream a file hash'
        return original_sha(data)

    with monkeypatch.context() as scoped:
        scoped.setattr(module.hashlib, 'sha256', no_stream_hash)
        identifier = rejected_files(job, folder, 1024 * 1024)[0].metadata['id']
    path.write_bytes(payload[:-1] + bytes([payload[-1] ^ 1]))
    assert rejected_files(job, folder, 1024 * 1024)[0].metadata['id'] == identifier
    with pytest.raises(FxfetchError) as error:
        open_rejected_file(job, folder, identifier, 1024 * 1024)
    assert error.value.code == 'not_found'


def test_reparse_path_is_not_served(tmp_path, monkeypatch):
    import fxfetch.core.web_evidence_io as io_module

    job, folder, path, _ = private_job(tmp_path)
    original = io_module.is_reparse
    monkeypatch.setattr(io_module, 'is_reparse', lambda candidate: candidate == path or original(candidate))
    assert not rejected_files(job, folder, 1024 * 1024)


def test_native_symlink_is_not_served(tmp_path):
    job, folder, path, _ = private_job(tmp_path)
    link = path.with_name('linked.body')
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip('Host does not allow file symlinks')
    job['result']['bodies'][0]['path'] = str(link)
    assert not rejected_files(job, folder, 1024 * 1024)


@pytest.mark.parametrize('basename', ['CON.apk', 'con.extra.apk', 'PRN.apk', 'AUX.apk', 'NUL.apk', 'COM1.apk', 'LPT9.apk'])
def test_download_filename_avoids_windows_reserved_names(tmp_path, basename):
    job, folder, _, _ = private_job(tmp_path)
    job['result']['bodies'][0]['url'] = ROOT + '/' + basename
    metadata = rejected_files(job, folder, 1024 * 1024)[0].metadata
    assert metadata['filename'].startswith('_') and metadata['filename'].endswith('.apk')


def test_http_workflow_records_complete_validation_failure(tmp_path):
    payload = bad_apk()
    result = Workflow(SyntheticClient({ROOT + '/a.apk': (200, 'application/octet-stream', payload)})).run(
        ROOT + '/a.apk', tmp_path, threading.Event())
    assert result.outcome == 'failed' and result.reason_code == 'archive_invalid'
    assert result.bodies[0]['validation'] == {'status': 'failed', 'kind': 'apk', 'reason_code': 'archive_invalid'}
    assert result.bodies[0]['complete'] and not result.artifacts


def test_api_download_auth_owner_archive_and_build_remain_separate(tmp_path, monkeypatch):
    settings = Settings(tmp_path / 'service', password_hash('synthetic-password'), allowed_hosts=('testserver',))
    service = JobService(settings)
    monkeypatch.setattr(service, 'start', lambda: None)
    monkeypatch.setattr(service.builder, 'probe', lambda: SimpleNamespace(enabled=True, reasons=[]))
    with TestClient(create_app(settings, service=service), client=('127.0.0.1', 50000)) as client:
        origin = {'Origin': 'http://testserver'}
        login = client.post('/api/login', json={'password': 'synthetic-password'}, headers=origin)
        headers = {**origin, 'X-CSRF-Token': login.json()['csrf_token']}
        owner = service.store.session(token_hash(client.cookies['fxfetch_session']))['id']
        job, _ = service.store.create_job(owner, 'synthetic-rejected', {'entry_url': ROOT + '/'}, 10)
        folder = service.store.root / 'jobs' / job['id']
        payload = bad_apk()
        result = Workflow(SyntheticClient({ROOT + '/a.apk': (200, 'application/octet-stream', payload)})).run(
            ROOT + '/a.apk', folder / 'network/direct', threading.Event())
        stored = asdict(result)
        with service.store.connect() as db:
            db.execute("UPDATE jobs SET state='completed',outcome='failed',reason_code='archive_invalid',result=? WHERE id=?",
                       (json.dumps(stored), job['id']))
        endpoint = '/api/jobs/' + job['id']
        before = client.get(endpoint).json()
        item = before['rejected_files'][0]
        url = endpoint + '/rejected-files/' + item['id']
        response = client.get(url)
        assert response.status_code == 200 and response.content == payload
        assert response.headers['content-type'] == 'application/octet-stream'
        assert set(response.headers['cache-control'].split(', ')) == {'no-store'}
        assert response.headers['content-disposition'].startswith('attachment;')
        assert client.get(endpoint).json()['outcome'] == 'failed'
        assert client.get(endpoint).json()['artifacts'] == []
        assert client.get(endpoint + '/rejected-files/unknown').status_code == 404
        # A rejected download does not consume or disable the existing WebView action.
        assert before['web_candidates']
        created = client.post(endpoint + '/web-apk-builds', json={'candidate_id': before['web_candidates'][0]['id']},
                              headers={**headers, 'Idempotency-Key': 'synthetic-build'})
        assert created.status_code == 202
        assert client.get(endpoint).json()['outcome'] == 'failed'
        original_cookie = client.cookies['fxfetch_session']
        client.cookies.clear()
        assert client.get(url).status_code == 401
        client.post('/api/login', json={'password': 'synthetic-password'}, headers=origin)
        assert client.get(url).status_code == 404
        client.cookies.clear()
        client.cookies.set('fxfetch_session', original_cookie)
        with service.store.connect() as db:
            db.execute('UPDATE jobs SET archived=1 WHERE id=?', (job['id'],))
        assert client.get(url).status_code == 404
