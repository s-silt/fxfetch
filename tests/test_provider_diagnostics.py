"""Provider timing and safe failure classification with synthetic HTTP only."""
from __future__ import annotations

import io
import json
import ssl
from http.client import IncompleteRead
from urllib.error import HTTPError, URLError

import pytest

from fxfetch.core.errors import FxfetchError
from fxfetch.icon_search import providers
from fxfetch.icon_search.providers import Provider, ProviderRequestError

ENDPOINT = 'https://provider.synthetic.test/v1/chat/completions'
PRIVATE = 'SYNTHETIC_PRIVATE_DIAGNOSTIC'


class Clock:
    def __init__(self):
        self.now = 100.0

    def monotonic(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class Response:
    status = 200

    def __init__(self, clock, body=b'{"ok":true}', error=None):
        self.clock, self.body, self.error = clock, body, error
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True
        return False

    def read(self, maximum):
        self.clock.advance(3)
        if self.error is not None:
            raise self.error
        return self.body[:maximum]


class Opener:
    def __init__(self, clock, response, error=None):
        self.clock, self.response, self.error = clock, response, error
        self.requests = []

    def open(self, request, **kwargs):
        self.requests.append(request)
        self.clock.advance(2)
        if self.error is not None:
            raise self.error
        return self.response


def synthetic_provider(monkeypatch, *, proxy=False, error=None, body=b'{"ok":true}', read_error=None):
    clock = Clock()
    monkeypatch.setattr(providers.time, 'monotonic', clock.monotonic)
    config = {'vision_endpoint': ENDPOINT, 'vision_model': 'synthetic/model',
              'vision_key': 'synthetic-vision-secret', 'serpapi_key': 'synthetic-search-secret'}
    if proxy:
        config['vision_proxy'] = 'http://127.0.0.1:7890'
    provider = Provider(config)
    response = Response(clock, body, read_error)
    opener = Opener(clock, response, error)
    monkeypatch.setattr(provider, 'opener', opener)
    return provider, opener, response


def assert_safe(error, timing):
    serialized = json.dumps({'code': error.code, 'message': str(error), 'timing': timing})
    for private in (PRIVATE, ENDPOINT, '127.0.0.1', 'synthetic-vision-secret', 'synthetic-search-secret'):
        assert private not in serialized
    assert set(timing) == {'route', 'response_wait_seconds', 'body_read_seconds',
                           'total_seconds', 'http_status', 'error_code'}
    assert all(timing[key] >= 0 for key in ('response_wait_seconds', 'body_read_seconds', 'total_seconds'))


@pytest.mark.parametrize('proxy,route', [(False, 'direct'), (True, 'configured_proxy')])
def test_success_separates_response_wait_body_read_and_total_without_sensitive_data(monkeypatch, proxy, route):
    provider, opener, response = synthetic_provider(monkeypatch, proxy=proxy)
    assert provider.request(ENDPOINT) == {'ok': True}
    assert provider.last_timing == {'route': route, 'response_wait_seconds': 2.0,
                                    'body_read_seconds': 3.0, 'total_seconds': 5.0,
                                    'http_status': 200, 'error_code': None}
    assert len(opener.requests) == 1 and response.closed is True
    assert ENDPOINT not in json.dumps(provider.last_timing)


def test_model_list_omits_ids_containing_decoded_credentials(monkeypatch):
    provider, _, _ = synthetic_provider(
        monkeypatch, body=br'{"data":[{"id":"safe/model"},{"id":"synthetic-vision-\u0073ecret"},'
                          br'{"id":"extra/synthetic-search-secret"}]}',
    )
    assert provider.models() == ['safe/model']


def test_search_omits_provider_echoes_from_candidates(monkeypatch):
    provider, _, _ = synthetic_provider(monkeypatch, body=br'{"visual_matches":['
        br'{"link":"https://safe.synthetic.test/download","title":"synthetic-vision-\u0073ecret"},'
        br'{"link":"https://safe.synthetic.test/download?ref=synthetic-search-%73ecret"}]}')
    assert provider.search('synthetic-image') == {
        '_channel': 'lens', 'visual_matches': [{'link': 'https://safe.synthetic.test/download', 'title': ''}],
    }


def test_provider_parsing_does_not_rewrite_json_field_names(monkeypatch):
    provider, _, _ = synthetic_provider(monkeypatch, body=b'{"data":[{"id":"unrelated/model"}]}')
    provider.config['vision_key'] = 'id'
    assert provider.models() == ['unrelated/model']


@pytest.mark.parametrize('status,code', [(401, 'icon_provider_auth'),
                                       (403, 'icon_provider_forbidden'),
                                       (429, 'icon_provider_quota'),
                                       (302, 'icon_provider_http'),
                                       (404, 'icon_provider_http'),
                                       (500, 'icon_provider_http'),
                                       (503, 'icon_provider_http')])
def test_http_failures_expose_only_status_and_safe_classification(monkeypatch, status, code):
    body = io.BytesIO(PRIVATE.encode())
    error = HTTPError(ENDPOINT, status, PRIVATE, {'X-Private': PRIVATE}, body)
    provider, opener, _ = synthetic_provider(monkeypatch, proxy=True, error=error)
    with pytest.raises(ProviderRequestError) as caught:
        provider.request(ENDPOINT)
    assert caught.value.code == code and caught.value.http_status == status
    assert str(caught.value) == code
    assert provider.last_timing == {'route': 'configured_proxy', 'response_wait_seconds': 2.0,
                                    'body_read_seconds': 0.0, 'total_seconds': 2.0,
                                    'http_status': status, 'error_code': code}
    assert len(opener.requests) == 1 and body.closed is True
    assert_safe(caught.value, provider.last_timing)


@pytest.mark.parametrize('error,code', [
    (TimeoutError(PRIVATE), 'icon_provider_timeout'),
    (URLError(TimeoutError(PRIVATE)), 'icon_provider_timeout'),
    (ssl.SSLCertVerificationError(PRIVATE), 'icon_provider_tls'),
    (URLError(ssl.SSLError(PRIVATE)), 'icon_provider_tls'),
])
def test_timeout_and_tls_failures_have_distinct_codes_without_retry(monkeypatch, error, code):
    provider, opener, _ = synthetic_provider(monkeypatch, proxy=True, error=error)
    with pytest.raises(ProviderRequestError) as caught:
        provider.request(ENDPOINT)
    assert caught.value.code == code and caught.value.http_status is None
    assert provider.last_timing['error_code'] == code
    assert provider.last_timing['response_wait_seconds'] == 2.0
    assert provider.last_timing['body_read_seconds'] == 0.0
    assert provider.last_timing['total_seconds'] == 2.0
    assert len(opener.requests) == 1
    assert_safe(caught.value, provider.last_timing)


@pytest.mark.parametrize('proxy,code', [(False, 'icon_provider_connection'), (True, 'icon_provider_proxy')])
@pytest.mark.parametrize('error', [URLError(PRIVATE), ConnectionRefusedError(PRIVATE)])
def test_connection_errors_distinguish_explicit_proxy_and_direct_route(monkeypatch, proxy, code, error):
    provider, opener, _ = synthetic_provider(monkeypatch, proxy=proxy, error=error)
    with pytest.raises(ProviderRequestError) as caught:
        provider.request(ENDPOINT)
    assert caught.value.code == code and caught.value.http_status is None
    assert provider.last_timing['route'] == ('configured_proxy' if proxy else 'direct')
    assert provider.last_timing['error_code'] == code
    assert len(opener.requests) == 1
    assert_safe(caught.value, provider.last_timing)


def test_serpapi_connection_failure_stays_direct_with_model_proxy_configured(monkeypatch):
    provider, opener, _ = synthetic_provider(monkeypatch, proxy=True, error=URLError(PRIVATE))
    with pytest.raises(ProviderRequestError) as caught:
        provider.request('https://serpapi.com/account.json?api_key=synthetic-search-secret')
    assert caught.value.code == 'icon_provider_connection'
    assert provider.last_timing['route'] == 'direct'
    assert len(opener.requests) == 1
    assert_safe(caught.value, provider.last_timing)


@pytest.mark.parametrize('body', [b'{"private":"' + PRIVATE.encode() + b'"', b'\xff\xfeinvalid-json'])
def test_invalid_json_or_utf8_is_response_failure_with_received_http_status(monkeypatch, body):
    provider, _, response = synthetic_provider(monkeypatch, body=body)
    with pytest.raises(ProviderRequestError) as caught:
        provider.request(ENDPOINT)
    assert caught.value.code == 'icon_provider_response_invalid'
    assert caught.value.http_status == 200
    assert provider.last_timing['response_wait_seconds'] == 2.0
    assert provider.last_timing['body_read_seconds'] == 3.0
    assert provider.last_timing['total_seconds'] == 5.0
    assert response.closed is True
    assert_safe(caught.value, provider.last_timing)


def test_incomplete_body_is_distinct_from_connection_and_timeout_failures(monkeypatch):
    provider, opener, response = synthetic_provider(monkeypatch, read_error=IncompleteRead(PRIVATE.encode(), 100))
    with pytest.raises(ProviderRequestError) as caught:
        provider.request(ENDPOINT)
    assert caught.value.code == 'icon_provider_incomplete' and caught.value.http_status == 200
    assert provider.last_timing['body_read_seconds'] == 3.0
    assert provider.last_timing['total_seconds'] == 5.0
    assert len(opener.requests) == 1 and response.closed is True
    assert_safe(caught.value, provider.last_timing)


def test_body_limit_failure_keeps_safe_timing_and_never_accepts_prefix(monkeypatch):
    provider, _, _ = synthetic_provider(monkeypatch, body=b'{"too_long":"' + PRIVATE.encode() + b'"}')
    with pytest.raises(FxfetchError) as caught:
        provider.request(ENDPOINT, max_response_bytes=8)
    assert caught.value.code == 'icon_provider_response_limit'
    assert provider.last_timing['error_code'] == 'icon_provider_response_limit'
    assert provider.last_timing['http_status'] == 200
    assert_safe(caught.value, provider.last_timing)


def test_later_success_replaces_previous_failure_timing(monkeypatch):
    provider, opener, _ = synthetic_provider(monkeypatch, error=TimeoutError(PRIVATE))
    with pytest.raises(ProviderRequestError):
        provider.request(ENDPOINT)
    opener.error = None
    assert provider.request(ENDPOINT) == {'ok': True}
    assert provider.last_timing['error_code'] is None
    assert provider.last_timing['http_status'] == 200
    assert provider.last_timing['total_seconds'] == 5.0
    assert len(opener.requests) == 2
