"""Explicit model-only proxy routing; all HTTP responses are synthetic."""
from __future__ import annotations

import io
import json
import os
import ssl
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler

import pytest

from fxfetch.core.errors import FxfetchError
from fxfetch.icon_search import providers
from fxfetch.icon_search.providers import NoRedirect, Provider, load_config
from fxfetch.model_settings import ModelSettingsService, config_fingerprint

ENDPOINT = 'https://model.synthetic.test/v1/chat/completions'
CURRENT = 'synthetic/current'
ALTERNATE = 'synthetic/alternate'
ABSENT = object()


def configure(root: Path, proxy=ABSENT) -> dict:
    config = {'vision_endpoint': ENDPOINT, 'vision_model': CURRENT,
              'vision_key': 'synthetic-vision-secret', 'serpapi_key': 'synthetic-search-secret'}
    if proxy is not ABSENT:
        config['vision_proxy'] = proxy
    (root / 'icon-search.json').write_text(json.dumps(config), encoding='utf-8')
    return config


class SyntheticOpener:
    def __init__(self, error=None):
        self.requests = []
        self.error = error

    def open(self, request, *, timeout):
        self.requests.append(request)
        if self.error:
            raise self.error
        return io.BytesIO(b'{"ok":true,"data":[{"id":"synthetic/current"}]}')


def provider_with_opener(tmp_path, monkeypatch, proxy=ABSENT, error=None):
    configure(tmp_path, proxy)
    provider = Provider(load_config(tmp_path))
    opener = SyntheticOpener(error)
    monkeypatch.setattr(provider, 'opener', opener)
    return provider, opener


@pytest.mark.parametrize('proxy', ['http://127.0.0.1:7890', 'http://localhost:7890',
                                  'http://[::1]:7890', 'http://host.docker.internal:7890'])
def test_only_explicit_local_http_proxy_addresses_are_accepted(tmp_path, proxy):
    configure(tmp_path, proxy)
    assert load_config(tmp_path)['vision_proxy'] == proxy


@pytest.mark.parametrize('proxy', [False, '', 'socks5://127.0.0.1:7890',
                                  'https://127.0.0.1:7890', 'http://proxy.synthetic.test:7890',
                                  'http://192.168.50.3:7890', 'http://127.1:7890',
                                  'http://127.0.0.1', 'http://127.0.0.1:0',
                                  'http://127.0.0.1:65536', 'http://user:secret@localhost:7890',
                                  'http://localhost:7890/', 'http://localhost:7890/path',
                                  'http://localhost:7890?x=1', 'http://localhost:7890#fragment'])
def test_invalid_proxy_configuration_fails_closed(tmp_path, proxy):
    configure(tmp_path, proxy)
    with pytest.raises(FxfetchError, match='icon_search_unconfigured'):
        load_config(tmp_path)


def test_omitted_proxy_preserves_legacy_four_field_configuration(tmp_path):
    expected = configure(tmp_path)
    assert load_config(tmp_path) == expected
    assert set(load_config(tmp_path)) == {'vision_endpoint', 'vision_model', 'vision_key', 'serpapi_key'}


def test_explicit_null_proxy_disables_routing(tmp_path, monkeypatch):
    provider, opener = provider_with_opener(tmp_path, monkeypatch, None)
    assert load_config(tmp_path)['vision_proxy'] is None
    provider.request(ENDPOINT)
    assert opener.requests[0].host == 'model.synthetic.test'
    assert getattr(opener.requests[0], '_tunnel_host', None) is None


def test_default_provider_ignores_environment_proxies_and_preserves_environment(tmp_path, monkeypatch):
    for key, value in {'HTTP_PROXY': 'http://proxy.synthetic.test:9999',
                       'HTTPS_PROXY': 'http://proxy.synthetic.test:9999',
                       'ALL_PROXY': 'socks5://proxy.synthetic.test:9999', 'NO_PROXY': '*'}.items():
        monkeypatch.setenv(key, value)
    environment = dict(os.environ)
    provider, opener = provider_with_opener(tmp_path, monkeypatch)
    assert provider.request(ENDPOINT) == {'ok': True, 'data': [{'id': CURRENT}]}
    request = opener.requests[0]
    assert request.host == 'model.synthetic.test'
    assert getattr(request, '_tunnel_host', None) is None
    assert dict(os.environ) == environment


def test_no_proxy_wildcard_does_not_bypass_explicit_model_proxy(tmp_path, monkeypatch):
    monkeypatch.setenv('NO_PROXY', '*')
    monkeypatch.setenv('no_proxy', '*')
    environment = dict(os.environ)
    provider, opener = provider_with_opener(tmp_path, monkeypatch, 'http://host.docker.internal:7890')
    assert provider.models() == [CURRENT]
    request = opener.requests[0]
    assert request.host == 'host.docker.internal:7890'
    assert request._tunnel_host == 'model.synthetic.test'
    assert request.type == 'https'
    assert request.full_url == 'https://model.synthetic.test/v1/models'
    assert request.get_header('Authorization') == 'Bearer synthetic-vision-secret'
    assert dict(os.environ) == environment


@pytest.mark.parametrize('url,use_proxy', [
    (ENDPOINT, True),
    ('https://model.synthetic.test/v1/models', True),
    ('https://model.synthetic.test:443/v1/models', True),
    ('https://MODEL.SYNTHETIC.TEST/v1/models', True),
    ('https://model.synthetic.test:444/v1/models', False),
    ('http://model.synthetic.test/v1/models', False),
    ('https://other.synthetic.test/v1/models', False),
    ('https://sub.model.synthetic.test/v1/models', False),
    ('https://model.synthetic.test/v1/models-extra', False),
    ('https://model.synthetic.test/v1/chat/completions/', False),
    ('https://user:pass@model.synthetic.test/v1/models', False),
    ('https://model.synthetic.test/v1/models?untrusted=query', False),
    ('https://model.synthetic.test/v1/models#fragment', False),
    ('https://serpapi.com/account.json?api_key=synthetic-search-secret', False),
    ('https://serpapi.com/image', False),
    ('https://serpapi.com/search.json?api_key=synthetic-search-secret', False),
])
def test_proxy_is_limited_to_same_origin_model_endpoints(tmp_path, monkeypatch, url, use_proxy):
    provider, opener = provider_with_opener(tmp_path, monkeypatch, 'http://127.0.0.1:7890')
    provider.request(url)
    assert len(opener.requests) == 1
    request = opener.requests[0]
    assert (request.host == '127.0.0.1:7890') is use_proxy
    assert (getattr(request, '_tunnel_host', None) is not None) is use_proxy


def test_explicit_default_endpoint_port_matches_unqualified_https_origin(tmp_path, monkeypatch):
    config = configure(tmp_path, 'http://127.0.0.1:7890')
    config['vision_endpoint'] = ENDPOINT.replace('.test/', '.test:443/')
    (tmp_path / 'icon-search.json').write_text(json.dumps(config), encoding='utf-8')
    provider = Provider(load_config(tmp_path))
    opener = SyntheticOpener()
    monkeypatch.setattr(provider, 'opener', opener)
    provider.request('https://model.synthetic.test/v1/models')
    assert opener.requests[0].host == '127.0.0.1:7890'
    assert opener.requests[0]._tunnel_host == 'model.synthetic.test'


@pytest.mark.parametrize('error,code', [
    (URLError('private proxy diagnostic'), 'icon_provider_proxy'),
    (ssl.SSLCertVerificationError('synthetic invalid certificate'), 'icon_provider_tls'),
    (HTTPError(ENDPOINT, 302, 'private redirect diagnostic', {}, None), 'icon_provider_http'),
])
def test_proxy_or_tls_failure_never_retries_directly(tmp_path, monkeypatch, error, code):
    provider, opener = provider_with_opener(tmp_path, monkeypatch, 'http://127.0.0.1:7890', error)
    with pytest.raises(FxfetchError) as caught:
        provider.models()
    assert caught.value.code == code
    assert str(caught.value) == code
    assert len(opener.requests) == 1
    assert opener.requests[0].host == '127.0.0.1:7890'


def test_strict_tls_and_no_redirect_handlers_remain_in_effect(tmp_path, monkeypatch):
    configure(tmp_path, 'http://127.0.0.1:7890')
    handlers = []

    def build(*supplied):
        handlers.extend(supplied)
        return SyntheticOpener()

    monkeypatch.setattr(providers, 'build_opener', build)
    Provider(load_config(tmp_path))
    proxy_handler = next(handler for handler in handlers if isinstance(handler, ProxyHandler))
    tls_handler = next(handler for handler in handlers if isinstance(handler, HTTPSHandler))
    redirect_handler = next(handler for handler in handlers if isinstance(handler, NoRedirect))
    assert proxy_handler.proxies == {}
    assert tls_handler._context.check_hostname is True
    assert tls_handler._context.verify_mode == ssl.CERT_REQUIRED
    assert redirect_handler.redirect_request(None, None, 302, 'redirect', {}, ENDPOINT) is None


def test_proxy_participates_in_fingerprint_and_model_save_preserves_it(tmp_path, monkeypatch):
    config = configure(tmp_path, 'http://127.0.0.1:7890')
    without_proxy = {key: value for key, value in config.items() if key != 'vision_proxy'}
    assert config_fingerprint(without_proxy) == config_fingerprint(dict(without_proxy, vision_proxy=None))
    assert config_fingerprint(config) != config_fingerprint(without_proxy)
    service = ModelSettingsService(tmp_path)
    monkeypatch.setattr(service, 'fetch_models', lambda: ([CURRENT, ALTERNATE], service.fingerprint()))
    listing = service.refresh('owner')
    assert service.select('owner', ALTERNATE, listing['list_token']) == {'current_model': ALTERNATE}
    expected = dict(config, vision_model=ALTERNATE)
    assert json.loads((tmp_path / 'icon-search.json').read_text()) == expected
    assert load_config(tmp_path)['vision_proxy'] == config['vision_proxy']


def test_changing_proxy_invalidates_existing_list_without_model_or_network_change(tmp_path, monkeypatch):
    config = configure(tmp_path, 'http://127.0.0.1:7890')
    service = ModelSettingsService(tmp_path)
    calls = []

    def fetched():
        calls.append('models')
        return [CURRENT, ALTERNATE], service.fingerprint()

    monkeypatch.setattr(service, 'fetch_models', fetched)
    listing = service.refresh('owner')
    config['vision_proxy'] = 'http://host.docker.internal:7890'
    path = tmp_path / 'icon-search.json'
    path.write_text(json.dumps(config), encoding='utf-8')
    before = path.read_bytes()
    with pytest.raises(FxfetchError, match='model_settings_changed'):
        service.select('owner', ALTERNATE, listing['list_token'])
    assert path.read_bytes() == before
    assert service.current()['current_model'] == CURRENT
    assert calls == ['models']
