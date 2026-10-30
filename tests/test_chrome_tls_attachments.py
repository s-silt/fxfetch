from __future__ import annotations

import copy
import hashlib
import json
import zipfile

import pytest
from test_task_attachments import MAX_BYTES, URL, build, certificate, rewrite, source

from fxfetch.core.task_evidence import finalize_package, package_metadata
from fxfetch.core.task_evidence_recorder import TaskEvidenceRecorder
from fxfetch.core.task_evidence_tls import (
    CHROME_CERTIFICATE_SOURCE,
    certificate_origin,
    tls_capture_summary,
)
from fxfetch.core.task_evidence_verify import verify_task_archive
from fxfetch.core.web_evidence_schema import EvidenceError


def chrome_source(tmp_path, *, indices=(0, 1), length=2, complete=True, gap=None):
    root = tmp_path / 'job'
    root.mkdir()
    recorder = TaskEvidenceRecorder(root)
    recorder.set_context('chrome', 'chrome-1')
    context = {'request_ref': 'browser:session:request', 'session_id': 'session', 'target_id': 'target', 'url': URL}
    observed_at = '2026-10-30T01:00:00.000Z'
    captured_at = '2026-10-30T01:00:00.010Z'
    recorder.observe_transport({'event': 'request_attempted', **context, 'method': 'GET'})
    recorder.observe_transport({'event': 'response_observed', **context, 'status': 200, 'observed_at': observed_at})
    originals = {}
    for index in indices:
        raw = certificate()
        digest = hashlib.sha256(raw).hexdigest()
        path = root / f'certificate-{index}.der'
        path.write_bytes(raw)
        originals[index] = raw
        recorder.observe_transport({
            'event': 'tls_certificate_saved', **context, 'path': path, 'source_url': URL,
            'size': len(raw), 'sha256': digest, 'tls_der_sha256': digest, 'complete': True,
            'representation': 'tls_certificate_der', 'capture_source': CHROME_CERTIFICATE_SOURCE,
            'association': 'origin_snapshot', 'request_association': 'observation_trigger_only',
            'origin': 'https://download.synthetic.test', 'observed_at': observed_at, 'captured_at': captured_at,
            'chain_index': index, 'chain_length': length, 'chain_complete': complete,
            'cert_role': 'leaf' if index == 0 else 'chain_member',
        })
    if gap:
        recorder.observe_transport({'event': 'gap', **context, 'code': 'tls_certificate_not_captured',
                                    'reason_code': gap})
    recorder.close()
    result = {'outcome': 'blocked', 'reason_code': 'challenge_detected', 'coverage': 'partial', 'artifacts': []}
    return root, result, originals


def test_chrome_chain_originals_preserve_origin_only_association_and_state(tmp_path):
    root, result, originals = chrome_source(tmp_path)
    before = copy.deepcopy(result)
    path, manifest = build(root, result)
    checked, _ = verify_task_archive(path, max_bytes=MAX_BYTES)
    assert checked == manifest and result == before
    assert manifest['files'] == [] and manifest['package_result']['outcome'] == 'blocked'
    assert manifest['tls_certificates'] == {
        'state': 'saved', 'http_certificates': 0, 'chrome_certificates': 2,
        'association_limited': True, 'reasons': [],
    }
    with zipfile.ZipFile(path) as archive:
        for item in manifest['attachments']:
            assert archive.read(item['path']) == originals[item['chain_index']]
            assert item['request_association'] == 'observation_trigger_only'
            assert item['association'] == 'origin_snapshot'
            assert item['validation']['status'] == 'not_performed'
    metadata = finalize_package(root, job_id='synthetic', entry_url=URL, terminal_result=result,
                                observation_path=root / 'task-observations.jsonl', max_bytes=MAX_BYTES)
    assert metadata['tls_certificates'] == manifest['tls_certificates']
    assert package_metadata(root, 'completed')['tls_certificates'] == manifest['tls_certificates']


def test_partial_chain_retains_original_index_and_bytes(tmp_path):
    root, result, originals = chrome_source(tmp_path, indices=(1,), length=3, complete=False)
    path, manifest = build(root, result)
    assert manifest['attachments'][0]['chain_index'] == 1
    assert manifest['attachments'][0]['cert_role'] == 'chain_member'
    assert manifest['tls_certificates']['state'] == 'partial'
    assert manifest['tls_certificates']['association_limited'] is True
    assert 'tls_certificate_chain_partial' in manifest['tls_certificates']['reasons']
    with zipfile.ZipFile(path) as archive:
        assert archive.read(manifest['attachments'][0]['path']) == originals[1]


@pytest.mark.parametrize('mutation', [
    'same_connection', 'origin', 'session', 'target', 'collector', 'attempt', 'observed_time',
    'captured_time', 'missing_response', 'missing_event', 'response_status', 'request_context',
    'duplicate_index', 'length_conflict', 'false_complete', 'summary',
])
def test_chrome_certificate_provenance_tampering_rejected(tmp_path, mutation):
    root, result, _ = chrome_source(tmp_path)
    path, _ = build(root, result)

    def mutate(manifest, members):
        item = manifest['attachments'][0]
        keys = {'origin': 'origin', 'session': 'session_id', 'target': 'target_id',
                'collector': 'collector_id', 'attempt': 'attempt_id'}
        if mutation in keys:
            item[keys[mutation]] = 'https://other.synthetic.test' if mutation == 'origin' else 'other'
        elif mutation == 'same_connection':
            item['association'] = 'same_connection'
        elif mutation == 'observed_time':
            item['observed_at'] = '2026-10-30T00:59:59.000Z'
        elif mutation == 'captured_time':
            item['captured_at'] = '2026-10-30T00:59:59.000Z'
        elif mutation == 'duplicate_index':
            manifest['attachments'][1].update(chain_index=0, cert_role='leaf')
        elif mutation == 'length_conflict':
            item['chain_length'] = 3
        elif mutation == 'false_complete':
            for entry in manifest['attachments']:
                entry['chain_length'] = 3
        elif mutation == 'summary':
            manifest['tls_certificates']['reasons'] = ['invented_gap']
            manifest['tls_certificates']['state'] = 'partial'
        else:
            rows = [json.loads(line) for line in members['observations.jsonl'][0].splitlines()]
            event = next(row for row in rows if row['kind'] == (
                'request_attempted' if mutation == 'request_context' else
                'tls_certificate_saved' if mutation == 'missing_event' else 'response_observed'))
            if mutation in {'missing_response', 'missing_event'}:
                event['kind'] = 'synthetic_omitted'
            elif mutation == 'response_status':
                event['fields']['status'] = 0
            else:
                event['fields']['target_id'] = 'other'
            raw = b''.join(json.dumps(row).encode() + b'\n' for row in rows)
            members['observations.jsonl'] = (raw, zipfile.ZIP_DEFLATED)
            manifest['observations'].update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())

    with pytest.raises(EvidenceError):
        verify_task_archive(rewrite(path, mutate), max_bytes=MAX_BYTES)


@pytest.mark.parametrize('reason', ['chrome_tls_empty_chain', 'chrome_tls_query_timeout', 'chrome_tls_query_failed'])
def test_no_originals_keeps_degraded_reason(tmp_path, reason):
    root, result, _ = chrome_source(tmp_path, indices=(), gap=reason)
    _, manifest = build(root, result)
    assert manifest['attachments'] == []
    assert manifest['tls_certificates']['state'] == 'not_captured'
    assert reason in manifest['tls_certificates']['reasons']


def test_historical_https_and_plain_http_summary_are_distinct(tmp_path):
    root, result, _ = source(tmp_path, tls=False)
    _, manifest = build(root, result)
    assert manifest['tls_certificates']['state'] == 'not_captured'
    assert 'tls_certificate_original_missing' in manifest['tls_certificates']['reasons']
    for rows in ([], [{'kind': 'response_observed', 'fields': {'url': 'http://synthetic.test/', 'request_ref': 'r'}}]):
        assert tls_capture_summary(rows, [], [])['state'] == 'not_applicable'
    assert tls_capture_summary([{'kind': 'request_attempted', 'fields': {'url': URL}}], [], [])['state'] == 'not_captured'


def test_old_v2_without_tls_summary_still_supported(tmp_path):
    root, result, _ = source(tmp_path)
    path, _ = build(root, result)
    old = rewrite(path, lambda manifest, members: manifest.pop('tls_certificates'))
    assert verify_task_archive(old, max_bytes=MAX_BYTES)[0]['schema_version'] == 'fxfetch.task-evidence.v2'


@pytest.mark.parametrize('url,expected', [
    ('https://SYNTHETIC.test:443/a', 'https://synthetic.test'),
    ('https://synthetic.test:8443/a', 'https://synthetic.test:8443'),
    ('https://[2001:4860:4860::8888]:443/a', 'https://[2001:4860:4860::8888]'),
])
def test_origin_normalization(url, expected):
    assert certificate_origin(url) == expected


@pytest.mark.parametrize('url', ['http://synthetic.test/', 'https://user:password@synthetic.test/'])
def test_non_https_or_credential_origin_rejected(url):
    with pytest.raises(EvidenceError):
        certificate_origin(url)


def test_certificate_bytes_still_use_archive_budget(tmp_path):
    root, result, _ = chrome_source(tmp_path)
    path, _ = build(root, result)
    with pytest.raises(EvidenceError):
        verify_task_archive(path, max_bytes=100)
