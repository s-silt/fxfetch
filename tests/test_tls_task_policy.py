from __future__ import annotations

import hashlib
import json
import threading
import zipfile

import pytest
from pydantic import ValidationError
from test_candidate_continuation import parent
from test_task_attachments import MAX_BYTES, URL, certificate, rewrite

from fxfetch.config import Settings
from fxfetch.core.errors import FxfetchError
from fxfetch.core.http_client import HttpClient
from fxfetch.core.network import AcquisitionPolicy
from fxfetch.core.task_evidence_io import build_task_archive
from fxfetch.core.task_evidence_recorder import TaskEvidenceRecorder
from fxfetch.core.task_evidence_tls import validate_task_tls_policy
from fxfetch.core.task_evidence_verify import verify_task_archive
from fxfetch.core.web_evidence_schema import EvidenceError
from fxfetch.core.workflow import Workflow, WorkflowResult
from fxfetch.service import JobService
from fxfetch.web.api import ContinuationInput, JobInput


class PolicyWorkflow(Workflow):
    def __init__(self):
        super().__init__(HttpClient())
        self.policies = []

    def run(self, *args, **kwargs):
        self.policies.append(self.client.tls_policy)
        return WorkflowResult('failed', 'synthetic_finished', 'partial')


@pytest.fixture
def service(tmp_path):
    return JobService(Settings(tmp_path, 'unused'), workflow=PolicyWorkflow())


@pytest.mark.parametrize('value', [None, 0, 1, 'true', 'false', [], {}])
@pytest.mark.parametrize('model,payload', [(JobInput, {'url': URL}), (ContinuationInput, {'candidate_id': 'candidate'})])
def test_api_tls_choice_is_strict_boolean(model, payload, value):
    with pytest.raises(ValidationError):
        model.model_validate({**payload, 'ignore_tls_errors': value})
    assert model.model_validate(payload).tls_policy == 'auto'


def test_task_tls_policy_persists_and_resets_without_mutating_shared_client(service):
    for index, policy in enumerate(('auto', 'strict', 'auto')):
        payload = {'url': URL, **({'tls_policy': 'strict'} if policy == 'strict' else {})}
        job = service.create_job('owner', str(index), payload)
        assert job['tls_policy'] == policy and job['input']['tls_policy'] == policy
        assert 'ignore_tls_errors' not in job['input']
        claimed = service.store.claim_job()
        service._collect(claimed, threading.Event())
        root = service.store.root / 'jobs' / job['id']
        assert json.loads((root / 'source/input.json').read_text())['tls_policy'] == policy
        evidence = json.loads((root / 'evidence.json').read_text())
        assert evidence['run']['tls_policy'] == policy
        public = service.get_job('owner', job['id'])
        assert public['data_package']['state'] == 'ready'
        manifest, _ = verify_task_archive(root / 'data-package' / public['data_package']['filename'], max_bytes=MAX_BYTES)
        assert manifest['tls_policy'] == policy and 'ignore_tls_errors' not in manifest
        assert public['tls_fallback'] == {'state': 'recorded', 'count': 0, 'observed': False, 'reasons': []}
        assert public['outcome'] == 'failed'
    assert service.workflow.policies == ['auto', 'strict', 'auto']
    assert service.workflow.client.tls_policy == 'strict'


def test_policy_is_part_of_job_idempotency_and_invalid_direct_input_rejected(service):
    job = service.create_job('owner', 'key', {'url': URL})
    assert service.create_job('owner', 'key', {'url': URL, 'ignore_tls_errors': True})['id'] == job['id']
    assert service.create_job('owner', 'key', {'url': URL, 'tls_policy': 'auto'})['id'] == job['id']
    with pytest.raises(FxfetchError, match='different request'):
        service.create_job('owner', 'key', {'url': URL, 'ignore_tls_errors': False})
    with pytest.raises(FxfetchError):
        service.create_job('owner', 'invalid', {'url': URL, 'ignore_tls_errors': 1})


@pytest.mark.parametrize('choice', ['auto', 'strict'])
def test_candidate_never_inherits_parent_tls_exception(service, choice):
    original = parent(service, source={'entry_url': URL, 'tls_policy': 'strict'})
    candidate = original['download_candidates'][0]['id']
    child = service.continue_job('owner', original['id'], 'child', candidate, **({'tls_policy': 'strict'} if choice == 'strict' else {}))
    assert child['input']['tls_policy'] == choice
    assert service.continue_job('owner', original['id'], 'child', candidate, tls_policy=choice)['id'] == child['id']
    with pytest.raises(FxfetchError, match='different request'):
        service.continue_job('owner', original['id'], 'child', candidate, tls_policy='strict' if choice == 'auto' else 'auto')


def test_supervisor_worker_request_carries_only_current_task_choice(service, monkeypatch):
    service._isolated_collect = True
    requests = []
    monkeypatch.setattr(service, '_isolated', lambda request, *args: requests.append(request) or {
        'outcome': 'failed', 'reason_code': 'synthetic_finished', 'coverage': 'not_started'})
    for index, policy in enumerate(('auto', 'strict')):
        service.create_job('owner', str(index), {'url': URL, 'tls_policy': policy})
        service._collect(service.store.claim_job(), threading.Event())
    assert [request['tls_policy'] for request in requests] == ['auto', 'strict']
    assert all('ignore_tls_errors' not in request for request in requests)


def test_acquisition_policy_passes_tls_choice_to_http_and_browser_factory(tmp_path, monkeypatch):
    import fxfetch.core.android_worker as worker
    for flag in (True, False):
        policy = AcquisitionPolicy(ignore_tls_errors=flag)
        assert policy._collector(policy.limits, None).client.ignore_tls_errors is flag
        monkeypatch.setattr(worker, 'load_worker_config', lambda root: object())
        browser_policy = AcquisitionPolicy(browser_root=tmp_path, ignore_tls_errors=flag)
        browser = browser_policy._collector(browser_policy.limits, None)
        assert browser.tls_policy == ('auto' if flag else 'strict') and browser.static.client.ignore_tls_errors is flag
    with pytest.raises(ValueError):
        AcquisitionPolicy(ignore_tls_errors=1)


def test_worker_reads_tls_flag_and_records_policy_before_collection(tmp_path, monkeypatch):
    import fxfetch.task_worker as worker
    observed = []

    class Policy:
        def __init__(self, *args, **kwargs):
            observed.append(kwargs['tls_policy'])

        def run(self, *args):
            return WorkflowResult('failed', 'synthetic_finished', 'partial')

    monkeypatch.setattr(worker, 'AcquisitionPolicy', Policy)
    for index, flag in enumerate((True, False)):
        root = tmp_path / str(index)
        root.mkdir()
        request = root / 'worker-request.json'
        output = root / 'worker-result.json'
        request.write_text(json.dumps({'operation': 'collect', 'root': str(root), 'identifier': 'synthetic',
                                       'url': URL, 'output_dir': str(root), 'limits': {}, 'ignore_tls_errors': flag}))
        monkeypatch.setattr(worker.sys, 'argv', ['worker', str(request), str(output)])
        assert worker.main() == 0
        rows = [json.loads(line) for line in (root / 'task-observations.jsonl').read_bytes().splitlines()]
        assert rows[1]['kind'] == 'task_tls_policy' and rows[1]['fields']['tls_policy'] == ('auto' if flag else 'strict')
    assert observed == ['auto', 'strict']


def ignored_archive(tmp_path, *, policy_record=True, archive_policy=True):
    root = tmp_path / 'job'
    root.mkdir()
    recorder = TaskEvidenceRecorder(root)
    recorder.set_context('http', 'http-1')
    if policy_record:
        recorder.append('task_tls_policy', {'ignore_tls_errors': True})
    recorder.observe_transport({'event': 'request_attempted', 'url': URL, 'request_ref': 'r',
                                'tls_verification': 'ignored', 'ignore_tls_errors': True})
    der = certificate()
    digest = hashlib.sha256(der).hexdigest()
    path = root / 'original.der'
    path.write_bytes(der)
    recorder.observe_transport({'event': 'tls_certificate_saved', 'path': path, 'size': len(der),
                                'sha256': digest, 'tls_der_sha256': digest, 'complete': True,
                                'source_url': URL, 'request_ref': 'r', 'representation': 'tls_certificate_der',
                                'cert_role': 'leaf', 'capture_source': 'unverified_tls_socket',
                                'association': 'same_connection', 'tls_verification': 'ignored'})
    recorder.close()
    result = {'outcome': 'blocked', 'reason_code': 'challenge_detected', 'coverage': 'partial', 'artifacts': []}
    archive = root / 'bundle.zip'
    manifest, _ = build_task_archive(root, archive, job_id='synthetic', entry_url=URL, package_result=result,
                                     result=result, observation_path=recorder.path, max_bytes=MAX_BYTES,
                                     ignore_tls_errors=archive_policy)
    return archive, manifest


def test_ignored_tls_original_is_explicit_unverified_and_bytes_unchanged(tmp_path):
    path, manifest = ignored_archive(tmp_path)
    item = manifest['attachments'][0]
    assert item['capture_source'] == 'unverified_tls_socket' and item['tls_verification'] == 'ignored'
    assert item['validation']['status'] == 'not_performed' and manifest['ignore_tls_errors'] is True
    with zipfile.ZipFile(path) as archive:
        assert archive.read(item['path']) == (path.parent / 'original.der').read_bytes()
    assert verify_task_archive(path, max_bytes=MAX_BYTES)[0] == manifest


@pytest.mark.parametrize('policy_record,archive_policy', [(False, True), (True, False)])
def test_ignored_evidence_requires_recorded_task_choice(tmp_path, policy_record, archive_policy):
    with pytest.raises(EvidenceError, match='tls_policy'):
        ignored_archive(tmp_path, policy_record=policy_record, archive_policy=archive_policy)


@pytest.mark.parametrize('mutation', ['remove_policy', 'false_policy', 'verified_source', 'remove_verification'])
def test_archive_cannot_hide_ignored_tls_policy(tmp_path, mutation):
    path, _ = ignored_archive(tmp_path)

    def mutate(manifest, members):
        if mutation == 'remove_policy':
            manifest.pop('ignore_tls_errors')
        elif mutation == 'false_policy':
            manifest['ignore_tls_errors'] = False
        elif mutation == 'verified_source':
            manifest['attachments'][0].update(capture_source='verified_tls_socket', tls_verification='verified')
        else:
            manifest['attachments'][0].pop('tls_verification')

    with pytest.raises(EvidenceError):
        verify_task_archive(rewrite(path, mutate), max_bytes=MAX_BYTES)


@pytest.mark.parametrize('flag', [False, True])
def test_non_tls_http_observation_has_not_applicable_verification(flag):
    rows = [{'kind': 'task_tls_policy', 'fields': {'ignore_tls_errors': flag}},
            {'kind': 'response_observed', 'fields': {'url': 'http://capture.synthetic.test/',
              'ignore_tls_errors': flag, 'tls_verification': 'not_applicable'}}]
    validate_task_tls_policy(rows, flag)
    rows[1]['fields']['url'] = 'https://capture.synthetic.test/'
    with pytest.raises(EvidenceError, match='tls_policy_mismatch'):
        validate_task_tls_policy(rows, flag)
