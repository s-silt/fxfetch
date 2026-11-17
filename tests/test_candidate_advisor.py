"""Synthetic model responses and continuation lifecycle; never calls a provider."""
import hashlib
import json
import threading
import time
from dataclasses import asdict
from pathlib import Path

import pytest

from fxfetch.candidate_advisor import advise
from fxfetch.config import Settings
from fxfetch.core.discovery import Candidate
from fxfetch.core.process_limits import ProcessResult
from fxfetch.core.workflow import Artifact, Workflow, WorkflowResult
from fxfetch.icon_search.providers import Provider
from fxfetch.security import password_hash
from fxfetch.service import JobService


class FakeProvider(Provider):
    def __init__(self, value):
        self.config = {'vision_endpoint': 'https://provider.synthetic.test/v1/chat/completions',
                       'vision_key': 'synthetic', 'vision_model': 'requested'}
        self.value = value
        self.calls = []

    def request(self, url, **kwargs):
        self.calls.append(json.loads(kwargs['body']))
        return {'model': 'returned-alias', 'choices': [{'message': {'content': json.dumps(self.value)}}]}


def result():
    return WorkflowResult('failed', 'candidate_selection_required', 'partial', selection_candidates=[
        Candidate('https://cdn.synthetic.test/android.apk?token=PRIVATE#SECRET', 'direct_apk', '', 'Android'),
        Candidate('https://cdn.synthetic.test/ios.ipa', 'direct_ipa', '', 'iOS'),
        Candidate('https://cdn.synthetic.test/other', 'http', '', 'Unclear')])


@pytest.mark.parametrize('value,expected', [
    ({'id': 0, 'confidence': 'high'}, 'selected'),
    ({'id': 0, 'confidence': 'medium'}, 'manual'),
    ({'id': 1, 'confidence': 'high'}, 'manual'),
    ({'id': 2, 'confidence': 'high'}, 'manual'),
    ({'id': 999, 'confidence': 'high'}, 'manual'),
    ({'id': True, 'confidence': 'high'}, 'manual'),
    ({'id': None, 'confidence': 'low'}, 'manual'),
    ({'id': 0, 'confidence': 'high', 'url': 'https://invented.test/'}, 'manual'),
    (['invalid'], 'manual'),
])
def test_bounded_decision_and_redaction(tmp_path, value, expected):
    provider = FakeProvider(value)
    advice = advise(result(), tmp_path, provider)
    assert advice['state'] == expected
    assert len(provider.calls) == 1
    serialized = json.dumps(provider.calls)
    assert 'PRIVATE' not in serialized and 'SECRET' not in serialized and 'ios.ipa' not in serialized
    if expected == 'selected':
        assert advice['candidate_index'] == 0
        assert advice['returned_model'] == 'returned-alias'


@pytest.mark.parametrize('label', [
    'Android https://cdn.synthetic.test/app.apk?token=PRIVATE#SECRET',
    'Android cdn.synthetic.test/app.apk?token=PRIVATE',
    'Android #SECRET',
    'Android https://user:PRIVATE@cdn.synthetic.test/app.apk',
])
def test_model_request_omits_url_bearing_candidate_labels(tmp_path, label):
    value = result()
    original = value.selection_candidates[0]
    value.selection_candidates[0] = Candidate(original.url, original.kind, '', label)
    provider = FakeProvider({'id': 0, 'confidence': 'high'})
    assert advise(value, tmp_path, provider)['state'] == 'selected'
    rows = json.loads(provider.calls[0]['messages'][1]['content'])
    assert rows[0]['label'] == ''
    assert rows[0]['host'] == 'cdn.synthetic.test'
    assert rows[0]['path'] == '/android.apk'
    assert 'PRIVATE' not in json.dumps(provider.calls)
    assert 'SECRET' not in json.dumps(provider.calls)
    assert value.selection_candidates[0].url == original.url


def test_missing_config_or_non_selection_retains_manual_result(tmp_path):
    assert advise(result(), tmp_path)['state'] == 'manual'
    provider = FakeProvider({})
    assert advise(WorkflowResult('downloaded', 'package_verified', 'complete'), tmp_path, provider)['state'] == 'not_needed'
    assert not provider.calls


@pytest.mark.parametrize('opted,cancelled,archived', [(True, False, False), (False, False, False),
                                                   (True, True, False), (True, False, True)])
def test_auto_child_is_once_and_never_restarted_or_reapplied(tmp_path, opted, cancelled, archived):
    service = JobService(Settings(tmp_path, password_hash('synthetic')), workflow=Workflow())
    service.create_job('owner', 'synthetic-job', {'url': 'https://entry.synthetic.test/', 'gemini_select': opted})
    job = service.store.claim_job()
    value = asdict(result())
    value['candidate_advice'] = {'state': 'selected', 'candidate_index': 0}
    service.store.finish_job(job['id'], 'completed', value)
    terminal = service.store.get_job('owner', job['id'])
    if archived:
        service.store.clear_jobs('owner')
    cancel = threading.Event()
    if cancelled:
        cancel.set()
    service._auto_continue(job, terminal, cancel)
    service._auto_continue(job, terminal, cancel)
    children = service.store.continuation_children('owner', job['id'])
    assert len(children) == (1 if opted and not cancelled and not archived else 0)
    if children:
        child = service.store.get_job('owner', children[0]['child_id'])
        assert child['input']['entry_url'] == result().selection_candidates[0].url
        assert not child['input'].get('gemini_select')
        assert child['input']['cookies_inherited'] is False
        assert child['state'] == 'queued'


def test_collection_lifecycle_auto_child_keeps_original_result_and_bytes(tmp_path):
    class SyntheticWorkflow(Workflow):
        def run(self, url, output_dir, cancel, on_event=None):
            if 'entry.synthetic.test' in url:
                value = result()
                value.candidate_advice = {'state': 'selected', 'candidate_index': 0}
                return value
            path = output_dir / 'synthetic.apk'
            path.write_bytes(b'synthetic validated collector output')
            return WorkflowResult('downloaded', 'package_verified', 'complete', artifacts=[
                Artifact('apk', path, hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_size, url)])

    service = JobService(Settings(tmp_path, password_hash('synthetic')), workflow=SyntheticWorkflow())
    parent = service.create_job('owner', 'task', {'url': 'https://entry.synthetic.test/', 'gemini_select': True})
    service._collect(service.store.claim_job(), threading.Event())
    parent = service.get_job('owner', parent['id'])
    assert parent['outcome'] == 'failed'
    assert parent['result']['reason_code'] == 'candidate_selection_required'
    assert parent['result']['candidate_advice']['state'] == 'selected'
    child = service.store.claim_job()
    assert child['id'] == parent['continuation_child_job_id']
    assert child['input']['selection_method'] == 'ai'
    service._collect(child, threading.Event())
    completed = service.get_job('owner', child['id'])
    assert completed['outcome'] == 'downloaded'
    assert len(completed['artifacts']) == 1
    evidence = json.loads((tmp_path / 'jobs' / child['id'] / 'evidence.json').read_text(encoding='utf-8'))
    assert evidence['run']['authorized_by'] == 'ai_candidate_selection'
    assert service.get_job('owner', parent['id'])['outcome'] == 'failed'
    assert service.store.claim_job() is None


def test_private_worker_invokes_model_once_and_preserves_selection(tmp_path, monkeypatch):
    from fxfetch import candidate_advisor, task_worker

    service = JobService(Settings(tmp_path, password_hash('synthetic')), workflow=Workflow())
    service.create_job('owner', 'worker-test', {'url': 'https://entry.synthetic.test/', 'gemini_select': True})
    job = service.store.claim_job()
    folder = tmp_path / 'jobs' / job['id']
    request = {'root': str(tmp_path), 'identifier': job['id'], 'operation': 'collect',
               'url': job['input']['entry_url'], 'output_dir': str(folder),
               'limits': asdict(service.settings.limits), 'gemini_select': True,
               'deadline_monotonic': time.monotonic() + 60}
    request_path, output_path = tmp_path / 'request.json', tmp_path / 'result.json'
    request_path.write_text(json.dumps(request), encoding='utf-8')
    monkeypatch.setattr(task_worker.sys, 'argv', ['worker', str(request_path), str(output_path)])

    class Collector:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, *args):
            return result()

    provider = FakeProvider({'id': 0, 'confidence': 'high'})
    monkeypatch.setattr(task_worker, 'AcquisitionPolicy', Collector)
    monkeypatch.setattr(candidate_advisor, 'Provider', lambda config: provider)
    monkeypatch.setattr(candidate_advisor, 'load_config', lambda root: {})

    def bounded_model(command, **kwargs):
        payload = json.loads(Path(command[-1]).read_text(encoding='utf-8'))
        value = candidate_advisor._advise_rows(payload['rows'], Path(payload['root']))
        assert 0 < kwargs['timeout'] <= 30
        return ProcessResult(0, stdout=json.dumps(value).encode())

    monkeypatch.setattr(candidate_advisor, 'run_limited', bounded_model)
    assert task_worker.main() == 0
    value = json.loads(output_path.read_text(encoding='utf-8'))
    assert value['candidate_advice']['state'] == 'selected'
    assert value['reason_code'] == 'candidate_selection_required'
    assert len(provider.calls) == 1
    assert service.store.claim_job() is None  # Child enqueue belongs to the supervisor commit.
