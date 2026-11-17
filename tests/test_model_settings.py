"""Model-list and shared selection boundaries with synthetic providers only."""
from __future__ import annotations

import json
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from http.client import IncompleteRead
from pathlib import Path

import pytest

from fxfetch import model_settings as module
from fxfetch.core.errors import FxfetchError
from fxfetch.core.process_limits import ProcessResult
from fxfetch.icon_search.providers import Provider, load_config
from fxfetch.model_settings import ModelSettingsService

CURRENT = 'auto/synthetic-current'
ALTERNATE = 'group/synthetic-alternate'


def configure(root: Path) -> Path:
    path = root / 'icon-search.json'
    # Preserve BOM, formatting, unrelated fields and credentials when selecting.
    path.write_bytes(b'\xef\xbb\xbf' + json.dumps({
        'vision_endpoint': 'https://model.synthetic.test/prefix/v1/chat/completions',
        'vision_model': CURRENT,
        'vision_key': 'synthetic-vision-secret',
        'serpapi_key': 'synthetic-search-secret',
        'extension': {'keep': True},
    }, indent=2).encode())
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return path


@pytest.fixture
def configured(tmp_path):
    configure(tmp_path)
    return ModelSettingsService(tmp_path)


@pytest.fixture
def provider_calls(monkeypatch):
    calls = []

    def models(self):
        calls.append(self.current()['current_model'])
        return [ALTERNATE, CURRENT, ALTERNATE], self.fingerprint()

    monkeypatch.setattr(ModelSettingsService, 'fetch_models', models)
    return calls


def test_local_read_and_manual_selection_never_fetch_implicitly(configured, provider_calls):
    service = configured
    assert service.current() == {'current_model': CURRENT}
    assert service.current() == {'current_model': CURRENT}
    assert provider_calls == []
    with pytest.raises(FxfetchError, match='model_list_expired'):
        service.select('owner', ALTERNATE, 'made-up-token')
    assert provider_calls == []
    listing = service.refresh('owner')
    assert listing['models'] == sorted([CURRENT, ALTERNATE])
    assert listing['current_model'] == CURRENT
    assert provider_calls == [CURRENT]
    assert service.current()['current_model'] == CURRENT
    assert service.select('owner', ALTERNATE, listing['list_token']) == {'current_model': ALTERNATE}
    assert service.current()['current_model'] == ALTERNATE
    assert provider_calls == [CURRENT]
    # The list can be reused by its owner without another supplier request.
    assert service.select('owner', CURRENT, listing['list_token']) == {'current_model': CURRENT}
    assert provider_calls == [CURRENT]


def test_selection_preserves_private_fields_format_permissions_and_persists(configured, provider_calls):
    service = configured
    path = service.root / 'icon-search.json'
    before, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
    listing = service.refresh('owner')
    service.select('owner', ALTERNATE, listing['list_token'])
    assert path.read_bytes() == before.replace(CURRENT.encode(), ALTERNATE.encode())
    assert stat.S_IMODE(path.stat().st_mode) == mode
    assert not list(service.root.glob('.model-settings-*'))
    assert ModelSettingsService(service.root).current() == {'current_model': ALTERNATE}
    assert load_config(service.root)['vision_key'] == 'synthetic-vision-secret'


def test_list_token_is_bound_to_session_and_cannot_select_unlisted_model(configured, provider_calls):
    listing = configured.refresh('owner-a')
    before = (configured.root / 'icon-search.json').read_bytes()
    for owner, model, token, code in [
        ('owner-b', ALTERNATE, listing['list_token'], 'model_list_expired'),
        ('owner-a', ALTERNATE, 'other-token', 'model_list_expired'),
        ('owner-a', 'unlisted/synthetic', listing['list_token'], 'model_not_available'),
    ]:
        with pytest.raises(FxfetchError, match=code):
            configured.select(owner, model, token)
        assert (configured.root / 'icon-search.json').read_bytes() == before
    assert provider_calls == [CURRENT]


def test_expired_list_and_service_restart_require_explicit_refetch(configured, provider_calls, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(module.time, 'monotonic', lambda: clock[0])
    listing = configured.refresh('owner')
    clock[0] += 601
    with pytest.raises(FxfetchError, match='model_list_expired'):
        configured.select('owner', ALTERNATE, listing['list_token'])
    with pytest.raises(FxfetchError, match='model_list_expired'):
        ModelSettingsService(configured.root).select('owner', ALTERNATE, listing['list_token'])
    assert configured.current() == {'current_model': CURRENT}
    assert provider_calls == [CURRENT]


@pytest.mark.parametrize('field,value', [
    ('vision_model', 'another/synthetic-model'),
    ('vision_key', 'replacement-synthetic-secret'),
    ('vision_endpoint', 'https://other.synthetic.test/v1/chat/completions'),
])
def test_changed_provider_or_current_model_invalidates_issued_list(configured, provider_calls, field, value):
    listing = configured.refresh('owner')
    path = configured.root / 'icon-search.json'
    data = json.loads(path.read_text(encoding='utf-8-sig'))
    data[field] = value
    path.write_text(json.dumps(data), encoding='utf-8')
    before = path.read_bytes()
    with pytest.raises(FxfetchError, match='model_settings_changed'):
        configured.select('owner', ALTERNATE, listing['list_token'])
    assert path.read_bytes() == before


def test_other_session_cannot_overwrite_a_more_recent_model_choice(configured, provider_calls):
    first = configured.refresh('first')
    configured.next_refresh = 0
    second = configured.refresh('second')
    configured.select('first', ALTERNATE, first['list_token'])
    with pytest.raises(FxfetchError, match='model_settings_changed'):
        configured.select('second', CURRENT, second['list_token'])
    assert configured.current()['current_model'] == ALTERNATE


def test_refresh_failure_keeps_current_model_and_enforces_cooldown(configured, monkeypatch):
    calls = []

    def unavailable(self):
        calls.append('models')
        raise FxfetchError('icon_provider_auth', 'synthetic rejection')

    monkeypatch.setattr(ModelSettingsService, 'fetch_models', unavailable)
    before = (configured.root / 'icon-search.json').read_bytes()
    with pytest.raises(FxfetchError, match='synthetic rejection'):
        configured.refresh('owner')
    with pytest.raises(FxfetchError, match='model_list_cooldown'):
        configured.refresh('owner')
    assert configured.current()['current_model'] == CURRENT
    assert (configured.root / 'icon-search.json').read_bytes() == before
    assert calls == ['models']


def test_refresh_is_single_flight_and_rejects_mid_fetch_configuration_change(configured, monkeypatch):
    entered, release = threading.Event(), threading.Event()

    def delayed(self):
        fingerprint = self.fingerprint()
        entered.set()
        assert release.wait(5)
        return [CURRENT, ALTERNATE], fingerprint

    monkeypatch.setattr(ModelSettingsService, 'fetch_models', delayed)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(configured.refresh, 'owner-a')
        try:
            assert entered.wait(5)
            with pytest.raises(FxfetchError, match='model_list_busy'):
                configured.refresh('owner-b')
            path = configured.root / 'icon-search.json'
            path.write_bytes(path.read_bytes().replace(CURRENT.encode(), b'changed/synthetic'))
        finally:
            release.set()
        with pytest.raises(FxfetchError, match='model_settings_changed'):
            future.result(timeout=5)
    assert configured.busy is False
    assert configured.lists == {}


def test_atomic_write_failure_keeps_original_config_and_removes_scratch(configured, provider_calls, monkeypatch):
    listing = configured.refresh('owner')
    path = configured.root / 'icon-search.json'
    before = path.read_bytes()

    def denied(*args):
        raise OSError('synthetic permission denial')

    monkeypatch.setattr(module.os, 'replace', denied)
    with pytest.raises(FxfetchError, match='model_settings_unavailable'):
        configured.select('owner', ALTERNATE, listing['list_token'])
    assert path.read_bytes() == before
    assert not list(configured.root.glob('.model-settings-*'))


def test_provider_change_after_atomic_replace_does_not_rebind_existing_model_list(configured, provider_calls, monkeypatch):
    listing = configured.refresh('owner')
    path = configured.root / 'icon-search.json'
    before = json.loads(path.read_text(encoding='utf-8-sig'))
    written_fingerprint = module.config_fingerprint(dict(before, vision_model=ALTERNATE))
    original_replace = module.os.replace

    def replace_then_change_provider(source, destination):
        original_replace(source, destination)
        changed = json.loads(path.read_text(encoding='utf-8-sig'))
        changed['vision_endpoint'] = 'https://replacement.synthetic.test/v1/chat/completions'
        changed['vision_key'] = 'replacement-synthetic-secret'
        path.write_text(json.dumps(changed), encoding='utf-8')

    monkeypatch.setattr(module.os, 'replace', replace_then_change_provider)
    assert configured.select('owner', ALTERNATE, listing['list_token']) == {'current_model': ALTERNATE}
    assert configured.lists['owner'].fingerprint == written_fingerprint
    assert configured.lists['owner'].fingerprint != configured.fingerprint()
    after = path.read_bytes()
    with pytest.raises(FxfetchError, match='model_settings_changed'):
        configured.select('owner', CURRENT, listing['list_token'])
    assert path.read_bytes() == after
    assert provider_calls == [CURRENT]
    assert not list(configured.root.glob('.model-settings-*'))


def test_provider_lists_only_ids_from_fixed_authenticated_endpoint(configured, monkeypatch):
    provider = Provider(load_config(configured.root))
    calls = []

    def response(url, **kwargs):
        calls.append((url, kwargs))
        return {'data': [{'id': ALTERNATE, 'owned_by': 'private-provider-field'},
                         {'id': CURRENT}, {'id': ALTERNATE}],
                'private_metadata': 'never return this'}

    monkeypatch.setattr(provider, 'request', response)
    assert provider.models() == sorted([CURRENT, ALTERNATE])
    assert calls == [('https://model.synthetic.test/prefix/v1/models', {
        'headers': {'Authorization': 'Bearer synthetic-vision-secret'},
        'timeout': 15, 'max_response_bytes': 1024 * 1024,
    })]


@pytest.mark.parametrize('response,code', [
    ({}, 'model_list_invalid'),
    ({'data': {}}, 'model_list_invalid'),
    ({'data': []}, 'model_list_invalid'),
    ({'data': [None]}, 'model_list_invalid'),
    ({'data': [{}]}, 'model_list_invalid'),
    ({'data': [{'id': 12}]}, 'model_list_invalid'),
    ({'data': [{'id': ''}]}, 'model_list_invalid'),
    ({'data': [{'id': 'bad\nmodel'}]}, 'model_list_invalid'),
    ({'data': [{'id': 'bad model'}]}, 'model_list_invalid'),
    ({'data': [{'id': '\u202eevil'}]}, 'model_list_invalid'),
    ({'data': [{'id': 'x' * 201}]}, 'model_list_invalid'),
    ({'data': [{'id': CURRENT}] * 1001}, 'model_list_limit'),
])
def test_provider_rejects_malformed_or_oversized_lists(configured, monkeypatch, response, code):
    provider = Provider(load_config(configured.root))
    monkeypatch.setattr(provider, 'request', lambda *a, **k: response)
    with pytest.raises(FxfetchError, match=code):
        provider.models()


@pytest.mark.parametrize('models', [None, [], [CURRENT, 'bad\x00model'], [CURRENT, object()]])
def test_service_does_not_publish_invalid_provider_lists(configured, monkeypatch, models):
    monkeypatch.setattr(ModelSettingsService, 'fetch_models', lambda self: (models, self.fingerprint()))
    with pytest.raises(FxfetchError, match='model_list_invalid'):
        configured.refresh('owner')
    assert configured.lists == {}
    assert configured.current()['current_model'] == CURRENT


def test_list_worker_has_hard_deadline_memory_and_output_limits(configured, monkeypatch):
    calls = []
    fingerprint = configured.fingerprint()

    def limited(command, **kwargs):
        calls.append((command, kwargs))
        return ProcessResult(returncode=0, stdout=json.dumps({
            'models': [CURRENT, ALTERNATE], 'fingerprint': fingerprint}).encode())

    monkeypatch.setattr(module, 'run_limited', limited)
    assert configured.fetch_models() == (sorted([CURRENT, ALTERNATE]), fingerprint)
    command, limits = calls[0]
    assert command[1:3] == ['-m', 'fxfetch.model_settings']
    assert command[-1] == str(configured.root)
    assert limits == {'timeout': 30, 'memory_bytes': 256 * 1024 * 1024,
                      'max_output_bytes': 256 * 1024}
    assert 'synthetic-vision-secret' not in json.dumps(calls)


@pytest.mark.parametrize('result', [
    ProcessResult(returncode=1, stderr=b'private-provider-diagnostic'),
    ProcessResult(returncode=None, timed_out=True),
    ProcessResult(returncode=0, timed_out=True),
    ProcessResult(returncode=0, output_truncated=True),
])
def test_list_worker_failures_have_fixed_error_and_never_publish_partial_models(configured, monkeypatch, result):
    monkeypatch.setattr(module, 'run_limited', lambda *a, **k: result)
    with pytest.raises(FxfetchError) as error:
        configured.refresh('owner')
    code = 'icon_provider_timeout' if result.timed_out else 'icon_provider_failed'
    assert error.value.code == code
    assert str(error.value) == code
    assert configured.lists == {} and configured.busy is False
    assert configured.current()['current_model'] == CURRENT


@pytest.mark.parametrize('body,code', [
    (b'not-json', 'model_list_invalid'),
    (b'[]', 'model_list_invalid'),
    (b'{"error":"private-provider-error"}', 'model_list_invalid'),
    (b'{"error":"icon_provider_auth"}', 'icon_provider_auth'),
    (b'{"error":"icon_provider_quota"}', 'icon_provider_quota'),
    (b'{"error":"model_list_limit"}', 'model_list_limit'),
    (b'{"models":[],"fingerprint":"bad"}', 'model_list_invalid'),
])
def test_list_worker_output_is_validated_and_known_errors_are_mapped(configured, monkeypatch, body, code):
    monkeypatch.setattr(module, 'run_limited', lambda *a, **k: ProcessResult(returncode=0, stdout=body))
    with pytest.raises(FxfetchError) as error:
        configured.fetch_models()
    assert error.value.code == code
    assert str(error.value) == code


@pytest.mark.parametrize('status,expected', [(403, 403), ('403', None), (999, None), (True, None)])
def test_list_worker_passes_only_safe_numeric_http_status(configured, monkeypatch, status, expected):
    body = json.dumps({'error': 'icon_provider_forbidden', 'http_status': status,
                       'private': 'synthetic-private-provider-body'}).encode()
    monkeypatch.setattr(module, 'run_limited', lambda *a, **k: ProcessResult(returncode=0, stdout=body))
    with pytest.raises(FxfetchError) as error:
        configured.fetch_models()
    assert error.value.code == 'icon_provider_forbidden'
    assert error.value.http_status == expected
    assert str(error.value) == 'icon_provider_forbidden'


def test_list_worker_main_emits_safe_error_status_only(configured, monkeypatch, capsys):
    from fxfetch.icon_search.providers import ProviderRequestError

    def forbidden(self):
        raise ProviderRequestError('icon_provider_forbidden', 403)

    monkeypatch.setattr(Provider, 'models', forbidden)
    monkeypatch.setattr(module.sys, 'argv', ['fxfetch.model_settings', str(configured.root)])
    module.main()
    output = capsys.readouterr()
    assert json.loads(output.out) == {'error': 'icon_provider_forbidden', 'http_status': 403}
    assert output.err == ''
    assert 'synthetic-vision-secret' not in output.out
    assert 'synthetic-search-secret' not in output.out


def test_fetch_from_different_configuration_cannot_issue_selection_token(configured, monkeypatch):
    monkeypatch.setattr(configured, 'fetch_models', lambda: ([CURRENT, ALTERNATE], 'f' * 64))
    with pytest.raises(FxfetchError, match='model_settings_changed'):
        configured.refresh('owner')
    assert configured.lists == {}


def test_configuration_change_between_select_check_and_write_is_preserved(configured, provider_calls, monkeypatch):
    listing = configured.refresh('owner')
    original_write = configured.write_model
    path = configured.root / 'icon-search.json'

    def replace_before_write(model, fingerprint):
        path.write_bytes(path.read_bytes().replace(CURRENT.encode(), b'newer/synthetic'))
        original_write(model, fingerprint)

    monkeypatch.setattr(configured, 'write_model', replace_before_write)
    with pytest.raises(FxfetchError, match='model_settings_changed'):
        configured.select('owner', ALTERNATE, listing['list_token'])
    assert configured.current()['current_model'] == 'newer/synthetic'
    assert not list(configured.root.glob('.model-settings-*'))


def test_partial_http_response_maps_to_fixed_provider_error(configured, monkeypatch):
    provider = Provider(load_config(configured.root))

    class BrokenResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            raise IncompleteRead(b'private-partial-response', 100)

    monkeypatch.setattr(provider.opener, 'open', lambda *a, **k: BrokenResponse())
    with pytest.raises(FxfetchError) as error:
        provider.models()
    assert error.value.code == 'icon_provider_incomplete'
    assert str(error.value) == 'icon_provider_incomplete'


def test_api_requires_authentication_origin_and_csrf_before_provider_access(running, provider_calls):  # noqa: F811
    from test_api import ORIGIN, login
    client, jobs, workflow, builder = running
    configure(jobs.store.root)
    assert client.get('/api/model-settings').status_code == 401
    assert client.post('/api/model-settings/refresh', json={}, headers=ORIGIN).status_code == 401
    assert client.post('/api/model-settings', json={'model': ALTERNATE, 'list_token': 'fake'},
                       headers=ORIGIN).status_code == 401
    headers = login(client)
    assert client.post('/api/model-settings/refresh', json={}, headers=ORIGIN).status_code == 403
    assert client.post('/api/model-settings/refresh', json={}, headers={
        **headers, 'Origin': 'http://other.synthetic.test'}).status_code == 403
    assert client.post('/api/model-settings', json={'model': ALTERNATE, 'list_token': 'fake'},
                       headers=ORIGIN).status_code == 403
    assert client.get('/api/model-settings').json() == {'current_model': CURRENT}
    assert client.get('/api/model-settings').json() == {'current_model': CURRENT}
    assert provider_calls == [] and workflow.calls == [] and builder.calls == []


def test_api_explicit_fetch_then_save_is_shared_persistent_and_does_not_create_jobs(running, provider_calls):  # noqa: F811
    from test_api import login
    client, jobs, workflow, builder = running
    configure(jobs.store.root)
    headers = login(client)
    response = client.post('/api/model-settings/refresh', json={}, headers=headers)
    assert response.status_code == 200, response.text
    listing = response.json()
    assert set(listing) == {'current_model', 'models', 'list_token'}
    assert listing['current_model'] == CURRENT
    assert set(listing['models']) == {CURRENT, ALTERNATE}
    assert 'synthetic-vision-secret' not in response.text
    assert 'synthetic-search-secret' not in response.text
    assert client.get('/api/model-settings').json() == {'current_model': CURRENT}
    response = client.post('/api/model-settings', json={
        'model': ALTERNATE, 'list_token': listing['list_token']}, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json() == {'current_model': ALTERNATE}
    assert client.get('/api/capabilities').json()['icon_search']['model'] == ALTERNATE
    assert ModelSettingsService(jobs.store.root).current()['current_model'] == ALTERNATE
    assert provider_calls == [CURRENT] and workflow.calls == [] and builder.calls == []
    assert client.get('/api/jobs').json()['jobs'] == []


def test_api_foreign_list_token_and_extra_parameters_cannot_change_config(running, provider_calls):  # noqa: F811
    from test_api import login
    client, jobs, _, _ = running
    path = configure(jobs.store.root)
    headers = login(client)
    listing = client.post('/api/model-settings/refresh', json={}, headers=headers).json()
    # A second login creates another session and cannot reuse the first session's token.
    headers = login(client)
    before = path.read_bytes()
    response = client.post('/api/model-settings', json={
        'model': ALTERNATE, 'list_token': listing['list_token']}, headers=headers)
    assert response.status_code == 400
    assert response.json()['error']['code'] == 'model_list_expired'
    assert client.post('/api/model-settings/refresh', json={
        'endpoint': 'https://other.synthetic.test/models'}, headers=headers).status_code == 422
    assert client.post('/api/model-settings', json={
        'model': ALTERNATE, 'list_token': listing['list_token'], 'vision_key': 'new-synthetic-key'},
        headers=headers).status_code == 422
    assert path.read_bytes() == before
    assert provider_calls == [CURRENT]


# Reuse the real API with synthetic workflow/builder; never external transport.
from test_api import encoded_password, running  # noqa: E402, F401
