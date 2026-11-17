"""Search stage/request timing survives failures without provider private data."""
from __future__ import annotations

import copy
import io
import json
import threading

import pytest
from PIL import Image

from fxfetch.core.errors import FxfetchError
from fxfetch.core.process_limits import ProcessResult
from fxfetch.icon_search import service as service_module
from fxfetch.icon_search import worker
from fxfetch.icon_search.providers import ProviderRequestError
from fxfetch.icon_search.service import IconSearchService

PRIVATE = 'SYNTHETIC_PRIVATE_PROVIDER_DETAIL'


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def wall(self):
        return 1_800_000_000 + self.now

    def advance(self, elapsed):
        self.now += elapsed


def picture():
    buffer = io.BytesIO()
    Image.new('RGB', (100, 100), 'green').save(buffer, 'PNG')
    return buffer.getvalue()


class TimedProvider:
    def __init__(self, clock, *, failed_stage=None, failure=None):
        self.clock, self.failed_stage, self.failure = clock, failed_stage, failure
        self.calls = []
        self.last_timing = {}
        self.search_count = 0

    def request(self, stage, duration, result):
        self.calls.append(stage)
        self.clock.advance(duration)
        failed = stage == self.failed_stage
        error = self.failure if failed else None
        self.last_timing = {
            'route': 'configured_proxy' if stage == 'recognizing' else 'direct',
            'response_wait_seconds': duration * 0.25,
            'body_read_seconds': duration * 0.75, 'total_seconds': duration,
            'http_status': getattr(error, 'http_status', 200) if failed else 200,
            'error_code': getattr(error, 'code', None),
            # The worker must not copy arbitrary provider diagnostics into results.
            'url': 'https://private.synthetic.test/' + PRIVATE,
            'response_body': PRIVATE, 'credentials': PRIVATE,
        }
        if failed:
            raise error
        return result

    def quota(self):
        return self.request('quota', 1, 200)

    def recognize(self, image):
        return self.request('recognizing', 2, {
            'name': 'Synthetic reader', 'confidence': 'high', 'ambiguous': False,
            'icon_box': [100, 100, 900, 900], 'requested_model': 'synthetic/model',
            'returned_model': 'synthetic/model',
        })

    def upload(self, image):
        return self.request('uploading', 3, 'synthetic-image-id')

    def search(self, identifier, name=''):
        self.search_count += 1
        return self.request('searching' if self.search_count == 1 else 'searching-second',
                            3 + self.search_count, {'visual_matches': [{
                                'title': 'Synthetic reader Android',
                                'link': 'https://app.synthetic.test/download',
                            }]})


@pytest.fixture
def clock(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(worker.time, 'monotonic', clock.monotonic)
    monkeypatch.setattr(worker.time, 'time', clock.wall)
    return clock


@pytest.fixture
def progress(monkeypatch):
    snapshots = []
    publish = worker.publish

    def capture(path, state):
        snapshots.append(copy.deepcopy(state))
        publish(path, state)

    monkeypatch.setattr(worker, 'publish', capture)
    return snapshots


def assert_timing_safe(result):
    timing = result['timing']
    assert set(timing) == {'started_at', 'stage_started_at', 'stage_elapsed_seconds',
                           'total_seconds', 'stages', 'requests'}
    assert PRIVATE not in json.dumps(result)
    assert timing['stage_elapsed_seconds'] >= 0
    assert timing['total_seconds'] >= 0
    for item in timing['stages']:
        assert set(item) == {'stage', 'elapsed_seconds'}
        assert item['elapsed_seconds'] >= 0
    for item in timing['requests']:
        assert set(item) <= {'stage', 'route', 'response_wait_seconds', 'body_read_seconds',
                             'total_seconds', 'http_status', 'error_code'}


def test_success_records_every_request_and_completed_stage_elapsed_time(tmp_path, clock, progress):
    (tmp_path / 'input.image').write_bytes(picture())
    provider = TimedProvider(clock)
    result = worker.execute(tmp_path, tmp_path, provider)
    assert result['state'] == 'completed' and result['stage'] == 'completed'
    assert result['search_attempts'] == 2 and result['candidate_requests'] == 0
    assert provider.calls == ['quota', 'recognizing', 'uploading', 'searching', 'searching-second']
    assert result['timing']['started_at'] == 1_800_000_000
    assert result['timing']['total_seconds'] == 15.0
    stages = result['timing']['stages']
    assert sum(item['elapsed_seconds'] for item in stages) == 15.0
    by_stage = {name: sum(item['elapsed_seconds'] for item in stages if item['stage'] == name)
                for name in ('quota', 'recognizing', 'uploading', 'searching')}
    assert by_stage == {'quota': 1.0, 'recognizing': 2.0, 'uploading': 3.0, 'searching': 9.0}
    requests = result['timing']['requests']
    assert [item['stage'] for item in requests] == ['quota', 'recognizing', 'uploading', 'searching', 'searching']
    assert [item['total_seconds'] for item in requests] == [1, 2, 3, 4, 5]
    assert [item['route'] for item in requests] == ['direct', 'configured_proxy', 'direct', 'direct', 'direct']
    assert all('timing' in snapshot for snapshot in progress)
    assert [item['timing']['total_seconds'] for item in progress] == sorted(
        item['timing']['total_seconds'] for item in progress)
    assert json.loads((tmp_path / 'progress.json').read_text()) == result
    assert_timing_safe(result)


@pytest.mark.parametrize('failed_stage,error,total,state,detail_stage', [
    ('quota', ProviderRequestError('icon_provider_quota', 429), 1, 'failed', 'quota'),
    ('recognizing', ProviderRequestError('icon_provider_forbidden', 403), 3, 'failed', 'recognizing'),
    ('uploading', ProviderRequestError('icon_provider_connection'), 6, 'failed', 'uploading'),
    ('searching-second', ProviderRequestError('icon_provider_http', 503), 15, 'partial', 'searching'),
])
def test_provider_failure_preserves_stage_safe_status_and_time(
    tmp_path, clock, progress, failed_stage, error, total, state, detail_stage,
):
    (tmp_path / 'input.image').write_bytes(picture())
    result = worker.execute(tmp_path, tmp_path, TimedProvider(clock, failed_stage=failed_stage, failure=error))
    assert result['state'] == state and result['stage'] == 'finished'
    assert result['error'] == error.code
    detail = {'stage': detail_stage, 'code': error.code}
    if error.http_status is not None:
        detail['http_status'] = error.http_status
    assert result['error_detail'] == detail
    assert result['timing']['total_seconds'] == total
    assert sum(item['elapsed_seconds'] for item in result['timing']['stages']) == total
    assert result['timing']['requests'][-1]['stage'] == detail_stage
    assert result['timing']['requests'][-1]['error_code'] == error.code
    assert bool(result['candidates']) is (state == 'partial')
    assert progress[-1] == result
    assert_timing_safe(result)


def test_invalid_image_has_failure_stage_and_timing_without_provider_request(tmp_path, clock):
    (tmp_path / 'input.image').write_bytes(b'not-an-image')
    provider = TimedProvider(clock)
    result = worker.execute(tmp_path, tmp_path, provider)
    assert result['state'] == 'failed' and result['error'] == 'invalid_image'
    assert result['error_detail'] == {'stage': 'validating', 'code': 'invalid_image'}
    assert result['timing']['requests'] == [] and provider.calls == []
    assert result['timing']['stages'] == [{'stage': 'validating', 'elapsed_seconds': 0.0}]
    assert_timing_safe(result)


def test_unexpected_failure_keeps_stage_but_not_exception_text(tmp_path, clock):
    (tmp_path / 'input.image').write_bytes(picture())
    result = worker.execute(tmp_path, tmp_path, TimedProvider(
        clock, failed_stage='recognizing', failure=RuntimeError(PRIVATE)))
    assert result['state'] == 'failed' and result['error'] == 'icon_processing_failed'
    assert result['error_detail'] == {'stage': 'recognizing', 'code': 'icon_processing_failed'}
    assert result['error_type'] == 'RuntimeError'
    assert result['timing']['total_seconds'] == 3.0
    assert_timing_safe(result)


def test_provider_without_last_timing_is_backward_compatible(tmp_path):
    from test_icon_search import FakeProvider
    (tmp_path / 'input.image').write_bytes(picture())
    result = worker.execute(tmp_path, tmp_path, FakeProvider())
    assert result['state'] == 'completed'
    assert result['timing']['requests'] == []
    assert [item['stage'] for item in result['timing']['stages']] == [
        'validating', 'quota', 'recognizing', 'uploading', 'searching']
    assert_timing_safe(result)


def test_plain_domain_failure_does_not_publish_exception_message_or_invalid_status(tmp_path, clock):
    (tmp_path / 'input.image').write_bytes(picture())
    error = FxfetchError('icon_free_quota_unavailable', PRIVATE)
    error.http_status = 999
    result = worker.execute(tmp_path, tmp_path, TimedProvider(clock, failed_stage='quota', failure=error))
    assert result['error_detail'] == {'stage': 'quota', 'code': 'icon_free_quota_unavailable'}
    assert result['timing']['total_seconds'] == 1.0
    assert_timing_safe(result)


@pytest.mark.parametrize('cancelled,has_candidates,state,error', [
    (False, False, 'failed', 'icon_timeout'),
    (False, True, 'partial', 'icon_timeout'),
    (True, True, 'cancelled', 'cancelled'),
])
def test_service_hard_stop_finalizes_active_stage_and_preserves_candidates(
    tmp_path, clock, monkeypatch, cancelled, has_candidates, state, error,
):
    service = IconSearchService(tmp_path)
    identifier = 'a' * 32
    directory = service.directory / identifier
    directory.mkdir()
    candidates = [{'id': '1', 'title': 'Synthetic Android',
                   'url': 'https://app.synthetic.test/download'}] if has_candidates else []
    progress = {'state': 'running', 'stage': 'searching', 'candidates': candidates,
                'search_attempts': 1, 'candidate_requests': 0,
                'timing': {'started_at': clock.wall(), 'stage_started_at': clock.wall() + 4,
                           'stage_elapsed_seconds': 2.0, 'total_seconds': 6.0,
                           'stages': [{'stage': 'validating', 'elapsed_seconds': 1.0},
                                      {'stage': 'quota', 'elapsed_seconds': 1.0},
                                      {'stage': 'recognizing', 'elapsed_seconds': 2.0}],
                           'requests': [{'stage': 'recognizing', 'route': 'configured_proxy',
                                         'total_seconds': 2.0, 'http_status': 200, 'error_code': None}]}}
    worker.publish(directory / 'progress.json', progress)
    with service.db() as db:
        db.execute('INSERT INTO searches(id,owner,idem,digest,created,state,result) VALUES(?,?,?,?,?,?,?)',
                   (identifier, 'owner', 'synthetic-key', 'synthetic-digest', clock.wall(), 'running', '{}'))
    event = threading.Event()
    service.active[identifier] = event
    calls = []

    def limited(*args, **kwargs):
        calls.append(kwargs)
        clock.advance(180)
        return ProcessResult(returncode=None, cancelled=cancelled, timed_out=not cancelled)

    monkeypatch.setattr(service_module, 'run_limited', limited)
    service.run(identifier, event)
    result = service.get('owner', identifier)
    assert result['state'] == state and result['error'] == error
    assert result['stage'] == 'finished'
    assert result['error_detail'] == {'stage': 'searching', 'code': error}
    assert result['timing']['total_seconds'] == 180.0
    assert result['timing']['stage_elapsed_seconds'] == 0.0
    assert result['timing']['stages'][-1] == {'stage': 'searching', 'elapsed_seconds': 176.0}
    assert sum(item['elapsed_seconds'] for item in result['timing']['stages']) == 180.0
    assert result['timing']['requests'] == progress['timing']['requests']
    assert result['candidates'] == candidates
    assert result['finished_at'] == clock.wall()
    assert not service.active
    assert len(calls) == 1 and calls[0]['timeout'] == 180
    assert_timing_safe(result)
