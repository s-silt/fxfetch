from __future__ import annotations

import copy
import hashlib
import json
import zipfile

import pytest
from pydantic import ValidationError
from test_task_attachments import MAX_BYTES, URL, certificate, rewrite

from fxfetch.core.task_evidence_io import build_task_archive
from fxfetch.core.task_evidence_recorder import TaskEvidenceRecorder
from fxfetch.core.task_evidence_tls_policy import validate_auto_tls_policy
from fxfetch.core.task_evidence_verify import verify_task_archive
from fxfetch.core.web_evidence_schema import EvidenceError
from fxfetch.web.api import ContinuationInput, JobInput


@pytest.mark.parametrize('model,payload', [(JobInput, {'url': URL}), (ContinuationInput, {'candidate_id': 'choice'})])
def test_new_api_policy_defaults_auto_and_maps_legacy_boolean(model, payload):
    assert model.model_validate(payload).tls_policy == 'auto'
    for legacy, canonical in ((True, 'auto'), (False, 'strict')):
        assert model.model_validate({**payload, 'ignore_tls_errors': legacy}).tls_policy == canonical
        assert model.model_validate({**payload, 'ignore_tls_errors': legacy, 'tls_policy': canonical}).tls_policy == canonical
        with pytest.raises(ValidationError):
            model.model_validate({**payload, 'ignore_tls_errors': legacy, 'tls_policy': 'strict' if legacy else 'auto'})


@pytest.mark.parametrize('value', [None, False, 0, 'ignore', 'AUTO', {}, []])
def test_policy_enum_has_no_truthy_coercion(value):
    with pytest.raises(ValidationError):
        JobInput.model_validate({'url': URL, 'tls_policy': value})


def mixed_archive(tmp_path, *, fallback=True, policy='auto'):
    root = tmp_path / 'job'
    root.mkdir()
    recorder = TaskEvidenceRecorder(root)
    recorder.set_context('http', 'http-1')
    recorder.append('task_tls_policy', {'tls_policy': policy})
    payloads = []
    for index in range(2 if fallback else 1):
        url, ref = URL + f'?part={index}', f'request-{index}'
        context = {'url': url, 'source_url': url, 'request_ref': ref, 'connection_ip': '192.0.2.5',
                   'tls_policy': policy, 'ignore_tls_errors': policy == 'auto'}
        recorder.observe_transport({'event': 'request_attempted', **context, 'tls_verification': 'required'})
        risk = {}
        if index:
            risk = {'tls_fallback_id': 'a' * 32, 'tls_verify_code': 18, 'tls_verify_reason': 'self_signed_certificate'}
            recorder.observe_transport({'event': 'tls_verification_failed', **context, **risk, 'tls_verification': 'required'})
            recorder.observe_transport({'event': 'tls_verification_fallback', **context, **risk, 'tls_verification': 'ignored'})
        verification = 'ignored' if index else 'verified'
        recorder.observe_transport({'event': 'response_observed', **context, **risk, 'status': 200,
                                    'tls_verification': verification})
        raw = certificate()
        payloads.append(raw)
        path = root / f'original-{index}.der'
        path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        recorder.observe_transport({'event': 'tls_certificate_saved', **context, **risk, 'path': path,
                                    'size': len(raw), 'sha256': digest, 'tls_der_sha256': digest,
                                    'complete': True, 'representation': 'tls_certificate_der', 'cert_role': 'leaf',
                                    'capture_source': 'unverified_tls_socket' if index else 'verified_tls_socket',
                                    'association': 'same_connection', 'tls_verification': verification})
    recorder.close()
    result = {'outcome': 'blocked', 'reason_code': 'challenge_detected', 'coverage': 'partial', 'artifacts': []}
    path = root / 'bundle.zip'
    manifest, _ = build_task_archive(root, path, job_id='synthetic', entry_url=URL, package_result=result,
                                     result=result, observation_path=recorder.path, max_bytes=MAX_BYTES, tls_policy=policy)
    return path, manifest, payloads


def test_auto_mixed_connections_keep_each_original_validation_and_fallback_proof(tmp_path):
    path, manifest, originals = mixed_archive(tmp_path)
    assert manifest['tls_policy'] == 'auto' and 'ignore_tls_errors' not in manifest
    assert manifest['tls_fallback'] == {'state': 'recorded', 'count': 1, 'observed': True,
                                        'reasons': ['self_signed_certificate']}
    first, second = manifest['attachments']
    assert first['tls_verification'] == 'verified' and 'tls_fallback_id' not in first
    assert second['tls_verification'] == 'ignored' and second['tls_fallback_id'] == 'a' * 32
    assert second['capture_source'] == 'unverified_tls_socket'
    assert manifest['package_result']['outcome'] == 'blocked'
    with zipfile.ZipFile(path) as archive:
        assert [archive.read(item['path']) for item in manifest['attachments']] == originals
    assert verify_task_archive(path, max_bytes=MAX_BYTES)[0] == manifest


@pytest.mark.parametrize('policy', ['auto', 'strict'])
def test_valid_certificate_never_claims_fallback(tmp_path, policy):
    path, manifest, _ = mixed_archive(tmp_path, fallback=False, policy=policy)
    assert manifest['tls_fallback'] == {'state': 'recorded', 'count': 0, 'observed': False, 'reasons': []}
    assert manifest['attachments'][0]['capture_source'] == 'verified_tls_socket'
    assert verify_task_archive(path, max_bytes=MAX_BYTES)[0] == manifest


@pytest.mark.parametrize('mutation', ['missing_failure', 'missing_request', 'wrong_ip', 'wrong_ref', 'wrong_id',
                                      'unsupported_reason', 'wrong_error_code', 'wrong_collector',
                                      'wrong_policy', 'missing_task_policy', 'hide_fallback', 'attachment_id'])
def test_auto_fallback_cannot_be_fabricated_or_hidden(tmp_path, mutation):
    path, _, _ = mixed_archive(tmp_path)

    def mutate(manifest, members):
        if mutation == 'hide_fallback':
            manifest['tls_fallback'].update(count=0, observed=False, reasons=[])
            return
        if mutation == 'attachment_id':
            manifest['attachments'][1]['tls_fallback_id'] = 'b' * 32
            return
        rows = [json.loads(line) for line in members['observations.jsonl'][0].splitlines()]
        fallback = next(row for row in rows if row['kind'] == 'tls_verification_fallback')
        if mutation == 'missing_failure':
            next(row for row in rows if row['kind'] == 'tls_verification_failed')['kind'] = 'synthetic_omitted'
        elif mutation == 'missing_request':
            next(row for row in rows if row['kind'] == 'request_attempted' and row['fields']['request_ref'] == 'request-1')['kind'] = 'synthetic_omitted'
        elif mutation == 'missing_task_policy':
            next(row for row in rows if row['kind'] == 'task_tls_policy')['kind'] = 'synthetic_omitted'
        else:
            key, value = {
                'wrong_ip': ('connection_ip', '192.0.2.9'), 'wrong_ref': ('request_ref', 'other'),
                'wrong_id': ('tls_fallback_id', 'b' * 32), 'unsupported_reason': ('tls_verify_reason', 'invented_error'),
                'wrong_error_code': ('tls_verify_code', 10), 'wrong_collector': ('collector_id', 'other'),
                'wrong_policy': ('tls_policy', 'strict'),
            }[mutation]
            fallback['fields'][key] = value
        raw = b''.join(json.dumps(row).encode() + b'\n' for row in rows)
        members['observations.jsonl'] = (raw, zipfile.ZIP_DEFLATED)
        manifest['observations'].update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())

    with pytest.raises(EvidenceError):
        verify_task_archive(rewrite(path, mutate), max_bytes=MAX_BYTES)


def chrome_rows():
    context = {'collector_id': 'browser', 'attempt_id': 'browser-1', 'session_id': 'session', 'tls_policy': 'auto'}
    error = {**context, 'source_url': URL, 'event_id': 1, 'chrome_error_type': 'ERR_CERT_AUTHORITY_INVALID',
             'tls_verify_reason': 'issuer_unverified', 'association': 'browser_certificate_event',
             'request_association': 'url_permission_only'}
    return [
        {'kind': 'task_tls_policy', 'fields': {'tls_policy': 'auto'}},
        {'kind': 'request_attempted', 'fields': {**context, 'request_ref': 'r', 'url': URL}},
        {'kind': 'request_permitted', 'fields': {**context, 'request_ref': 'r', 'url': URL, 'permitted': True}},
        {'kind': 'tls_certificate_error', 'fields': {**error, 'tls_verification': 'required'}},
        {'kind': 'tls_verification_fallback', 'fields': {**error, 'tls_fallback_id': 'c' * 32, 'tls_verification': 'ignored'}},
        {'kind': 'response_observed', 'fields': {**context, 'url': URL, 'tls_verification': 'unknown'}},
    ]


def test_chrome_fallback_has_permission_and_error_proof_but_not_certificate_binding():
    rows = chrome_rows()
    assert validate_auto_tls_policy(rows, 'auto') == {
        'state': 'recorded', 'count': 1, 'observed': True, 'reasons': ['issuer_unverified']}
    for index in (0, 2, 3, 4):
        modified = copy.deepcopy(rows)
        modified[index]['kind'] = 'synthetic_omitted'
        with pytest.raises(EvidenceError):
            validate_auto_tls_policy(modified, 'auto')
    modified = copy.deepcopy(rows)
    modified[-1]['fields']['tls_verification'] = 'ignored'
    with pytest.raises(EvidenceError):
        validate_auto_tls_policy(modified, 'auto')


def test_chrome_certificate_error_cannot_be_consumed_by_two_fallback_ids():
    rows = chrome_rows()
    duplicate = copy.deepcopy(rows[4])
    duplicate['fields']['tls_fallback_id'] = 'd' * 32
    rows.append(duplicate)
    with pytest.raises(EvidenceError, match='tls_fallback_unobserved'):
        validate_auto_tls_policy(rows, 'auto')


@pytest.mark.parametrize('code', ['tls_policy_continuation_unconfirmed', 'tls_policy_restore_failed'])
@pytest.mark.parametrize('confirmed', [False, True])
def test_uncertain_chrome_command_never_claims_no_fallback(code, confirmed):
    rows = chrome_rows() if confirmed else chrome_rows()[:4]
    rows.append({'kind': 'gap', 'fields': {'code': code, 'reason_code': code}})
    summary = validate_auto_tls_policy(rows, 'auto')
    assert summary['state'] == 'unavailable'
    assert summary['count'] == int(confirmed) and summary['observed'] is confirmed
    assert code in summary['reasons']
