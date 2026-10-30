from __future__ import annotations

import asyncio
import hashlib
import json
import zipfile

import pytest
from test_browser_tls_evidence import FakeMux, collector
from test_task_attachments import MAX_BYTES, URL, build, certificate, rewrite

from fxfetch.core.task_evidence_recorder import TaskEvidenceRecorder
from fxfetch.core.task_evidence_tls import NETLOG_CERTIFICATE_SOURCE
from fxfetch.core.task_evidence_verify import verify_task_archive
from fxfetch.core.web_evidence_schema import EvidenceError


def netlog_source(tmp_path, *, partial=False):
    root = tmp_path / 'job'
    root.mkdir()
    recorder = TaskEvidenceRecorder(root)
    recorder.set_context('chrome', 'chrome-1')
    recorder.observe_transport({'event': 'request_attempted', 'url': URL, 'request_ref': 'unmapped',
                                'session_id': 'session', 'target_id': 'target'})
    recorder.observe_transport({'event': 'response_observed', 'url': URL, 'request_ref': 'unmapped',
                                'session_id': 'session', 'target_id': 'target', 'status': 200})
    context = {
        'capture_source': NETLOG_CERTIFICATE_SOURCE, 'association': 'browser_network_event',
        'request_association': 'unknown', 'source_url': '', 'trace_id': 'a' * 32,
        'trace_started_at': '2026-10-30T01:00:00.000Z', 'captured_at': '2026-10-30T01:00:01.000Z',
        'netlog_source_id': '0x1', 'netlog_source_type': 'SOCKET', 'netlog_pid': 1234,
        'netlog_event_name': 'SSL_CERTIFICATES_RECEIVED', 'netlog_timestamp': 12345678.5,
        'chain_length': 3 if partial else 2,
    }
    originals = [certificate(), certificate()]
    members = [{'chain_index': index, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
               for index, raw in enumerate(originals)]
    recorder.observe_transport({'event': 'tls_certificate_observed', **context, 'certificate_members': members})
    for member, raw in zip(members, originals, strict=True):
        path = root / f"certificate-{member['chain_index']}.der"
        path.write_bytes(raw)
        recorder.observe_transport({
            'event': 'tls_certificate_saved', **context, **member, 'path': path,
            'complete': True, 'representation': 'tls_certificate_der', 'tls_der_sha256': member['sha256'],
            'chain_complete': not partial, 'cert_role': 'leaf' if member['chain_index'] == 0 else 'chain_member',
        })
    recorder.close()
    return root, {'outcome': 'blocked', 'reason_code': 'challenge_detected', 'coverage': 'partial', 'artifacts': []}, originals


@pytest.mark.parametrize('partial', [False, True])
def test_netlog_originals_without_inventing_url_or_request_binding(tmp_path, partial):
    root, result, originals = netlog_source(tmp_path, partial=partial)
    path, manifest = build(root, result)
    checked, _ = verify_task_archive(path, max_bytes=MAX_BYTES)
    assert checked == manifest
    assert manifest['package_result']['outcome'] == 'blocked'
    assert manifest['files'] == []
    summary = manifest['tls_certificates']
    assert summary['state'] == ('partial' if partial else 'saved')
    assert summary['chrome_certificates'] == 2 and summary['http_certificates'] == 0
    assert summary['association_limited'] is True
    with zipfile.ZipFile(path) as archive:
        for item in manifest['attachments']:
            assert archive.read(item['path']) == originals[item['chain_index']]
            assert item['source_url'] == '' and item['request_association'] == 'unknown'
            assert item['association'] == 'browser_network_event'
            assert not {'request_ref', 'url', 'origin', 'session_id', 'target_id'}.intersection(item)


@pytest.mark.parametrize('mutation', [
    'same_connection', 'origin', 'request', 'source_url', 'pid', 'trace', 'source', 'timestamp',
    'role', 'missing_observation', 'missing_saved', 'member_hash', 'member_size', 'member_index',
    'observed_context', 'duplicate_member', 'observed_length', 'same_timestamp_other_trace',
])
def test_netlog_observation_and_saved_byte_proofs_required(tmp_path, mutation):
    root, result, _ = netlog_source(tmp_path)
    path, _ = build(root, result)

    def mutate(manifest, members):
        item = manifest['attachments'][0]
        if mutation == 'same_connection':
            item['association'] = 'same_connection'
        elif mutation == 'origin':
            item['origin'] = 'https://synthetic.test'
        elif mutation == 'request':
            item['request_ref'] = 'unmapped'
            item['request_association'] = 'known'
        elif mutation == 'source_url':
            item['source_url'] = URL
        elif mutation in {'pid', 'trace', 'source', 'timestamp'}:
            key = {'pid': 'netlog_pid', 'trace': 'trace_id', 'source': 'netlog_source_id', 'timestamp': 'netlog_timestamp'}[mutation]
            item[key] = {'pid': 5678, 'trace': 'b' * 32, 'source': '0x2', 'timestamp': 12345679.5}[mutation]
        elif mutation == 'role':
            item['cert_role'] = 'chain_member'
        else:
            rows = [json.loads(line) for line in members['observations.jsonl'][0].splitlines()]
            observation = next(row for row in rows if row['kind'] == 'tls_certificate_observed')
            observed = observation['fields']
            if mutation == 'missing_observation':
                observation['kind'] = 'synthetic_omitted'
            elif mutation == 'missing_saved':
                next(row for row in rows if row['kind'] == 'tls_certificate_saved')['kind'] = 'synthetic_omitted'
            elif mutation in {'member_hash', 'member_size', 'member_index'}:
                field = {'member_hash': 'sha256', 'member_size': 'size', 'member_index': 'chain_index'}[mutation]
                observed['certificate_members'][0][field] = {'member_hash': '0' * 64, 'member_size': 1, 'member_index': 1}[mutation]
            elif mutation == 'duplicate_member':
                observed['certificate_members'].append(observed['certificate_members'][0])
            elif mutation == 'observed_length':
                observed['chain_length'] = 3
            else:
                observed['trace_id' if mutation == 'same_timestamp_other_trace' else 'attempt_id'] = (
                    'b' * 32 if mutation == 'same_timestamp_other_trace' else 'other')
            raw = b''.join(json.dumps(row).encode() + b'\n' for row in rows)
            members['observations.jsonl'] = (raw, zipfile.ZIP_DEFLATED)
            manifest['observations'].update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())

    with pytest.raises(EvidenceError):
        verify_task_archive(rewrite(path, mutate), max_bytes=MAX_BYTES)


def test_no_valid_netlog_members_does_not_break_task_archive(tmp_path):
    root, result, _ = netlog_source(tmp_path)
    journal = root / 'task-observations.jsonl'
    rows = [json.loads(line) for line in journal.read_bytes().splitlines()]
    for row in rows:
        if row['kind'] == 'tls_certificate_observed':
            row['fields']['certificate_members'] = []
        elif row['kind'] == 'tls_certificate_saved':
            row['kind'] = 'gap'
            row['fields'] = {'code': 'tls_certificate_not_captured', 'reason_code': 'browser_tls_certificate_invalid'}
    journal.write_bytes(b''.join(json.dumps(row).encode() + b'\n' for row in rows))
    path, manifest = build(root, result)
    assert manifest['attachments'] == [] and manifest['tls_certificates']['state'] == 'not_captured'
    assert manifest['package_result']['outcome'] == 'blocked'
    assert verify_task_archive(path, max_bytes=MAX_BYTES)[0] == manifest


def test_capture_empty_netlog_members_finalize_as_missing_without_archive_failure(tmp_path):
    root, result, _ = netlog_source(tmp_path)
    fields = next(json.loads(line)['fields'] for line in (root / 'task-observations.jsonl').read_bytes().splitlines()
                  if json.loads(line)['kind'] == 'tls_certificate_observed')
    for key in ('certificate_members', 'chain_length', 'collector_id', 'attempt_id'):
        fields.pop(key)
    degraded = tmp_path / 'degraded'
    degraded.mkdir()
    recorder = TaskEvidenceRecorder(degraded)
    recorder.set_context('chrome', 'chrome-1')
    capture, _, _ = collector(degraded, FakeMux())
    capture.emit = lambda kind, value: recorder.observe_transport({'event': kind, **value})
    capture.preserve_network_event(fields, [], 2, ['browser_tls_certificate_invalid'])
    asyncio.run(capture.finish())
    recorder.close()
    path, manifest = build(degraded, result)
    assert manifest['attachments'] == []
    assert manifest['tls_certificates']['state'] == 'not_captured'
    assert 'browser_tls_certificate_invalid' in manifest['tls_certificates']['reasons']
    assert verify_task_archive(path, max_bytes=MAX_BYTES)[0]['package_result']['outcome'] == 'blocked'
