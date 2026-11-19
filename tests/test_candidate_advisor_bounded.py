"""Candidate model budgets and process termination use synthetic inputs only."""
import ctypes
import json
import math
import os
import sys
import textwrap
import time
from dataclasses import asdict
from pathlib import Path

import pytest

from fxfetch import candidate_advisor as module
from fxfetch.config import Settings
from fxfetch.core.discovery import Candidate
from fxfetch.core.process_limits import ProcessResult, run_limited
from fxfetch.core.workflow import WorkflowResult
from fxfetch.icon_search.providers import ProviderRequestError
from fxfetch.security import password_hash
from fxfetch.store import Store


def selection():
    return WorkflowResult('failed', 'candidate_selection_required', 'partial', selection_candidates=[
        Candidate('https://cdn.synthetic.test/android.apk?ticket=PRIVATE#SECRET', 'direct_apk', '', 'Android'),
        Candidate('https://cdn.synthetic.test/other', 'http', '', 'Unclear')])


@pytest.mark.parametrize('remaining', [None, -1, 0, 4.9, 5, math.nan, math.inf])
def test_no_model_request_without_result_saving_budget(tmp_path, monkeypatch, remaining):
    calls = []
    monkeypatch.setattr(module, 'run_limited', lambda *args, **kwargs: calls.append(args))
    value = selection()
    before = asdict(value)
    deadline = None if remaining is None else time.monotonic() + remaining
    advice = module.advise_bounded(value, tmp_path, tmp_path, deadline=deadline)
    assert advice['reason'] == 'ai_budget_insufficient'
    assert advice['state'] == 'manual'
    assert not calls and asdict(value) == before
    assert not list(tmp_path.glob('.candidate-ai-*'))


def test_bounded_request_redacts_inputs_limits_process_and_keeps_one_call(tmp_path, monkeypatch):
    calls = []

    def process(command, **kwargs):
        request = Path(command[-1])
        raw = request.read_text(encoding='utf-8')
        payload = json.loads(raw)
        assert set(payload) == {'root', 'rows'}
        assert 'PRIVATE' not in raw and 'SECRET' not in raw
        assert 'vision_key' not in raw and 'serpapi_key' not in raw
        if os.name == 'posix':
            assert request.stat().st_mode & 0o777 == 0o600
        calls.append(kwargs)
        return ProcessResult(0, stdout=json.dumps({
            'state': 'selected', 'candidate_index': 0, 'reason': 'android_evidence',
            'requested_model': 'synthetic', 'returned_model': 'synthetic',
            'request_timing': {'route': 'direct', 'total_seconds': 0.4, 'url': 'PRIVATE'},
            'unknown_field': 'PRIVATE',
        }).encode())

    monkeypatch.setattr(module, 'run_limited', process)
    advice = module.advise_bounded(selection(), tmp_path, tmp_path, deadline=time.monotonic() + 600)
    assert advice['state'] == 'selected' and advice['candidate_index'] == 0
    assert len(calls) == 1
    assert calls[0] == {'timeout': 30.0, 'memory_bytes': 256 * 1024 * 1024, 'max_output_bytes': 16384}
    assert advice['timeout_seconds'] == 30
    assert advice['request_timing']['total_seconds'] == 0.4
    assert 'PRIVATE' not in json.dumps(advice)
    assert not list(tmp_path.glob('.candidate-ai-*'))


@pytest.mark.parametrize('process,reason', [
    (ProcessResult(-1, timed_out=True), 'ai_timeout'),
    (ProcessResult(-1), 'ai_worker_failed'),
    (ProcessResult(0, reason_code='process_limits_failed'), 'ai_worker_failed'),
    (ProcessResult(0, stdout=b'{}', output_truncated=True), 'ai_worker_failed'),
    (ProcessResult(0, stdout=b'not json'), 'invalid_model_response'),
    (ProcessResult(0, stdout=b'[]'), 'invalid_model_response'),
    (ProcessResult(0, stdout=b'{"state":"selected","reason":"android_evidence","candidate_index":1}'),
     'invalid_model_response'),
])
def test_model_failure_keeps_original_outcome_and_candidates(tmp_path, monkeypatch, process, reason):
    calls = []

    def invoke(*args, **kwargs):
        calls.append(kwargs['timeout'])
        return process

    monkeypatch.setattr(module, 'run_limited', invoke)
    original = selection()
    before = asdict(original)
    advice = module.advise_bounded(original, tmp_path, tmp_path, deadline=time.monotonic() + 9)
    assert advice['state'] == 'manual' and advice['reason'] == reason
    assert len(calls) == 1 and 0 < calls[0] <= 4
    assert asdict(original) == before
    assert not list(tmp_path.glob('.candidate-ai-*'))


def test_provider_failure_exposes_only_safe_error_and_timing(tmp_path):
    class FailedProvider:
        config = {'vision_endpoint': 'https://provider.synthetic.test/v1/chat/completions',
                  'vision_key': 'PRIVATE', 'vision_model': 'synthetic'}
        last_timing = {'route': 'direct', 'response_wait_seconds': 0.4, 'body_read_seconds': 0.0,
                       'total_seconds': 0.4, 'http_status': 403, 'error_code': 'icon_provider_forbidden',
                       'body': 'PRIVATE', 'endpoint': 'PRIVATE'}

        def request(self, *args, **kwargs):
            raise ProviderRequestError('icon_provider_forbidden', 403)

    advice = module.advise(selection(), tmp_path, FailedProvider())
    assert advice['state'] == 'manual' and advice['reason'] == 'icon_provider_forbidden'
    assert advice['error_detail'] == {'code': 'icon_provider_forbidden', 'http_status': 403}
    assert advice['request_timing']['total_seconds'] == 0.4
    assert 'PRIVATE' not in json.dumps(advice)


def _running(pid):
    if os.name == 'nt':
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel.OpenProcess(0x1000, 0, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            assert kernel.GetExitCodeProcess(handle, ctypes.byref(code))
            return code.value == 259
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        status = Path(f'/proc/{pid}/stat')
        if status.is_file() and status.read_text().rsplit(')', 1)[1].split()[0] == 'Z':
            return False
        return True
    except ProcessLookupError:
        return False


@pytest.mark.parametrize('outer_kill', [False, True])
def test_slow_model_is_killed_and_real_task_worker_saves_original_candidates(tmp_path, outer_kill):
    settings = Settings(tmp_path, password_hash('synthetic'))
    store = Store(tmp_path)
    job, _ = store.create_job('owner', 'synthetic-slow-model', {}, 20, {})
    root = Path(__file__).resolve().parents[1]
    marker, finished = tmp_path / 'model.pid', tmp_path / 'model.finished'
    model_bootstrap = tmp_path / 'synthetic_model.py'
    model_bootstrap.write_text(textwrap.dedent('''
        import os, sys, time
        from pathlib import Path
        from fxfetch import candidate_advisor as advisor
        class SlowModel:
            def __init__(self, config):
                self.config = {'vision_endpoint':'https://model.synthetic.test/v1/chat/completions',
                               'vision_model':'synthetic', 'vision_key':'synthetic'}
            def request(self, *args, **kwargs):
                Path(sys.argv[2]).write_text(str(os.getpid()))
                time.sleep(30)
                Path(sys.argv[3]).write_text('late')
        advisor.Provider = SlowModel
        advisor.load_config = lambda root, **kwargs: {}
        advisor.main()
    '''), encoding='utf-8')
    task_bootstrap = tmp_path / 'synthetic_task.py'
    task_bootstrap.write_text(textwrap.dedent('''
        import sys
        from fxfetch import candidate_advisor as advisor, task_worker as worker
        from fxfetch.core.discovery import Candidate
        from fxfetch.core.workflow import WorkflowResult
        model_script, model_pid, model_finished = sys.argv[3:6]
        class SyntheticCollector:
            def __init__(self, *args, **kwargs): pass
            def run(self, *args):
                return WorkflowResult('failed','candidate_selection_required','partial',
                    selection_candidates=[Candidate('https://cdn.synthetic.test/app.apk?ticket=PRIVATE',
                                                    'direct_apk','','Android')])
        original = advisor.run_limited
        def model_process(command, **kwargs):
            return original([sys.executable, model_script, command[-1], model_pid, model_finished], **kwargs)
        advisor.run_limited = model_process
        worker.AcquisitionPolicy = SyntheticCollector
        worker.sys.argv = ['worker', sys.argv[1], sys.argv[2]]
        raise SystemExit(worker.main())
    '''), encoding='utf-8')
    folder = tmp_path / 'task'
    request_path, result_path = tmp_path / 'request.json', tmp_path / 'result.json'
    request_path.write_text(json.dumps({
        'root': str(tmp_path), 'identifier': job['id'], 'operation': 'collect',
        'url': 'https://entry.synthetic.test/', 'output_dir': str(folder),
        'limits': asdict(settings.limits), 'gemini_select': True,
        'deadline_monotonic': time.monotonic() + (60 if outer_kill else 8),
    }), encoding='utf-8')
    started = time.monotonic()
    process = run_limited([sys.executable, str(task_bootstrap), str(request_path), str(result_path),
                           str(model_bootstrap), str(marker), str(finished)], timeout=4 if outer_kill else 12,
                          memory_bytes=512 * 1024 * 1024, max_output_bytes=16384, cwd=root)
    assert marker.is_file() and not finished.exists()
    assert not _running(int(marker.read_text()))
    if outer_kill:
        assert process.timed_out and not result_path.exists()
        return
    assert process.returncode == 0, process.stderr
    assert time.monotonic() - started < 8
    result = json.loads(result_path.read_text(encoding='utf-8'))
    assert result['outcome'] == 'failed' and result['reason_code'] == 'candidate_selection_required'
    assert result['selection_candidates'][0]['url'].endswith('?ticket=PRIVATE')
    assert result['candidate_advice']['state'] == 'manual'
    assert result['candidate_advice']['reason'] == 'ai_timeout'
    assert not list(folder.glob('.candidate-ai-*'))
