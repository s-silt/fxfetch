"""Koodous name-only API contract; every response and credential is synthetic."""
from __future__ import annotations

import io
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import ProxyHandler

import pytest

from fxfetch.core.errors import FxfetchError
from fxfetch.icon_search.providers import NoRedirect, Provider, ProviderRequestError, load_config

NAME = '示例阅读'
KEY = 'synthetic-catalog-secret'
SHA = 'a' * 64


class SyntheticResponse(io.BytesIO):
    status = 200


class SyntheticOpener:
    def __init__(self, payload=None, *, error=None, raw=None):
        self.raw = raw if raw is not None else json.dumps(payload, ensure_ascii=False).encode('utf-8')
        self.error = error
        self.calls = []

    def open(self, request, *, timeout):
        self.calls.append((request, timeout))
        if self.error:
            raise self.error
        return SyntheticResponse(self.raw)


def page(records=None, *, count=None, next_page=None):
    records = [{'sha256': SHA, 'app': NAME, 'package_name': 'test.synthetic.reader', 'version': '1.0'}] \
        if records is None else records
    return {'results': records, 'count': len(records) if count is None else count,
            'next': next_page, 'previous': None}


def configured(tmp_path: Path, value: dict) -> None:
    (tmp_path / 'icon-search.json').write_text(json.dumps(value), encoding='utf-8')


def synthetic_provider(payload=None, *, error=None, raw=None):
    provider = Provider({'koodous_key': KEY})
    opener = SyntheticOpener(page() if payload is None else payload, error=error, raw=raw)
    provider.opener = opener
    return provider, opener


def test_catalog_only_configuration_needs_no_vision_or_web_key(tmp_path):
    configured(tmp_path, {'koodous_key': KEY, 'serpapi_key': '', 'vision_proxy': 'not-a-proxy',
                          'vision_endpoint': 'not-a-model', 'vision_key': None})
    config = load_config(tmp_path, require_vision=False, allow_catalog=True)
    assert config == {'koodous_key': KEY}
    provider = Provider(config)
    assert provider.catalog_enabled and not provider.web_enabled
    assert provider._model_proxy is None


def test_catalog_is_an_explicit_opt_in_and_keeps_legacy_config_requirement(tmp_path):
    configured(tmp_path, {'koodous_key': KEY})
    with pytest.raises(FxfetchError, match='icon_search_unconfigured'):
        load_config(tmp_path, require_vision=False)
    with pytest.raises(FxfetchError, match='icon_search_unconfigured'):
        load_config(tmp_path)


def test_catalog_and_web_configuration_preserves_both_actual_keys(tmp_path):
    configured(tmp_path, {'koodous_key': KEY, 'serpapi_key': 'synthetic-web-secret'})
    config = load_config(tmp_path, require_vision=False, allow_catalog=True)
    assert config == {'koodous_key': KEY, 'serpapi_key': 'synthetic-web-secret'}
    provider = Provider(config)
    assert provider.catalog_enabled and provider.web_enabled


@pytest.mark.parametrize('value', [{}, {'koodous_key': ''}, {'koodous_key': 'secret\nheader'},
                                 {'koodous_key': 42}, {'koodous_key': ' ' * 20}])
def test_no_usable_search_credential_is_not_silently_enabled(tmp_path, value):
    configured(tmp_path, value)
    with pytest.raises(FxfetchError, match='icon_search_unconfigured'):
        load_config(tmp_path, require_vision=False, allow_catalog=True)


def test_search_is_one_fixed_read_only_name_request_and_whitelisted_metadata():
    source = page([{'sha256': SHA.upper(), 'app': NAME, 'package_name': 'test.synthetic.reader',
                    'version': '1.0', 'url': 'http://127.0.0.1/private',
                    'image': 'https://evil.synthetic.test/preview', 'credential': 'not-public'}])
    provider, opener = synthetic_provider(source)
    result = provider.search_catalog(NAME)
    assert len(opener.calls) == 1
    request, timeout = opener.calls[0]
    target = urlsplit(request.full_url)
    assert target.scheme == 'https' and target.netloc == 'developer.koodous.com'
    assert target.path == '/apks/' and request.get_method() == 'GET' and request.data is None
    assert parse_qs(target.query) == {'search': [f'app: "{NAME}"']}
    assert request.get_header('Authorization') == 'Token ' + KEY
    assert KEY not in request.full_url and timeout == 15
    assert result['records'] == [{'sha256': SHA, 'app_name': NAME,
                                  'package_name': 'test.synthetic.reader', 'version': '1.0',
                                  'url': 'https://koodous.com/apks/' + SHA}]
    assert result['count'] == result['returned'] == 1
    assert result['coverage_complete'] and not result['next_page_available']
    assert result['page_returned'] == 1 and result['truncated'] is False
    assert 'credential' not in json.dumps(result) and 'evil.synthetic' not in json.dumps(result)


def test_next_url_is_only_a_flag_never_a_second_or_arbitrary_request():
    provider, opener = synthetic_provider(page(next_page='http://127.0.0.1/not-followed', count=100))
    result = provider.search_catalog(NAME)
    assert result['next_page_available'] and not result['coverage_complete']
    assert result['count'] == 100 and len(opener.calls) == 1


def test_only_twenty_records_are_exposed_and_unreturned_scope_stays_partial():
    entries = [{'sha256': f'{number:064x}', 'app': NAME} for number in range(25)]
    provider, opener = synthetic_provider(page(entries))
    result = provider.search_catalog(NAME)
    assert result['returned'] == result['page_limit'] == 20 and result['count'] == 25
    assert result['page_returned'] == 25 and result['truncated'] is True
    assert not result['coverage_complete'] and len(opener.calls) == 1


@pytest.mark.parametrize('length', [0, 1, 20, 44])
def test_cursor_page_without_total_count_keeps_unknown_total_and_actual_page_coverage(length):
    entries = [{'sha256': f'{number:064x}', 'app': NAME} for number in range(length)]
    provider, opener = synthetic_provider({'results': entries, 'next': None, 'previous': None})
    result = provider.search_catalog(NAME)
    assert result['count'] is None
    assert result['returned'] == min(length, 20) and result['page_returned'] == length
    assert result['truncated'] is (length > 20)
    assert result['coverage_complete'] is (length <= 20)
    assert result['next_page_available'] is False and result['rejected_records'] == 0
    assert len(opener.calls) == 1


def test_cursor_page_without_count_does_not_follow_next_or_claim_complete_coverage():
    provider, opener = synthetic_provider({'results': page()['results'],
                                          'next': 'https://evil.synthetic.test/?credential=' + KEY})
    result = provider.search_catalog(NAME)
    assert result['count'] is None and result['returned'] == result['page_returned'] == 1
    assert result['next_page_available'] is True and result['truncated'] is False
    assert result['coverage_complete'] is False and len(opener.calls) == 1
    assert KEY not in json.dumps(result) and 'evil.synthetic' not in json.dumps(result)


def test_unknown_count_with_only_invalid_records_cannot_claim_a_complete_empty_result():
    provider, _ = synthetic_provider({'results': [{'sha256': 'invalid'}], 'next': None})
    result = provider.search_catalog(NAME)
    assert result['count'] is None and result['records'] == []
    assert result['page_returned'] == result['rejected_records'] == 1
    assert result['coverage_complete'] is False


def test_invalid_or_duplicate_sha_is_not_an_apk_record_or_a_false_complete_empty_result():
    entries = [{'sha256': SHA, 'app': NAME}, {'sha256': SHA}, {'sha256': '../not-a-hash'},
               {'url': 'https://evil.synthetic.test/sample.apk'}, None]
    provider, _ = synthetic_provider(page(entries))
    result = provider.search_catalog(NAME)
    assert result['returned'] == 1 and result['count'] == 5
    assert result['rejected_records'] == 4 and not result['coverage_complete']
    provider, _ = synthetic_provider(page([{'sha256': 'invalid'}]))
    result = provider.search_catalog(NAME)
    assert result['records'] == [] and result['count'] == 1 and not result['coverage_complete']


@pytest.mark.parametrize('payload', [{}, {'results': {}, 'count': 0}, {'results': [], 'count': True},
                                   {'results': [], 'count': -1}, {'results': [], 'count': '0'},
                                   {'results': [{'sha256': SHA}], 'count': 0},
                                   {'results': [], 'count': 0, 'next': 42},
                                   {'results': [], 'next': ''}, {'results': [], 'next': '  '},
                                   {'results': []}, {'results': page()['results']},
                                   {'results': page()['results'], 'count': 0, 'next': None}])
def test_malformed_catalog_response_is_not_a_no_match(payload):
    provider, _ = synthetic_provider(payload)
    with pytest.raises(FxfetchError, match='koodous_response_invalid'):
        provider.search_catalog(NAME)


@pytest.mark.parametrize(('status', 'code'), [(401, 'icon_provider_auth'),
                                             (403, 'icon_provider_forbidden'),
                                             (429, 'icon_provider_quota')])
def test_auth_permission_and_quota_failures_remain_distinct_without_retry(status, code):
    provider, opener = synthetic_provider(error=HTTPError('https://developer.koodous.com/apks/',
        status, 'synthetic failure', {}, io.BytesIO(KEY.encode())))
    with pytest.raises(ProviderRequestError) as caught:
        provider.search_catalog(NAME)
    assert caught.value.code == code and caught.value.http_status == status
    assert KEY not in str(caught.value) and len(opener.calls) == 1


def test_secret_echoes_are_redacted_and_extra_provider_fields_never_exposed():
    provider, _ = synthetic_provider(page([{'sha256': SHA, 'app': 'x' * 95 + KEY,
                                           'package_name': KEY, 'version': KEY, 'extra': KEY}]))
    result = provider.search_catalog(NAME)
    serialized = json.dumps(result)
    assert KEY not in serialized and 'extra' not in serialized
    assert result['records'][0]['package_name'] == ''


def test_catalog_cannot_embed_a_hex_credential_into_its_public_sha_or_detail_url():
    token = 'f' * 40  # Synthetic hex credential; not a provider token.
    sha_with_token = 'a' * 12 + token + 'b' * 12
    provider = Provider({'koodous_key': token})
    provider.opener = SyntheticOpener(page([{'sha256': sha_with_token, 'app': NAME}]))
    result = provider.search_catalog(NAME)
    assert result['records'] == [] and result['rejected_records'] == 1
    assert token not in json.dumps(result) and not result['coverage_complete']


@pytest.mark.parametrize('method', ['legacy', 'name'])
def test_web_metadata_projection_drops_secret_links_and_titles_before_publication(method):
    provider = Provider({'koodous_key': KEY, 'serpapi_key': 'synthetic-web-secret'})
    provider.opener = SyntheticOpener({'organic_results': [
        {'link': 'https://sample.synthetic.test/?value=' + KEY, 'title': NAME},
        {'link': 'https://sample.synthetic.test/?value=' + ''.join(f'%{ord(c):02x}' for c in KEY), 'title': NAME},
        {'link': 'https://sample.synthetic.test/clean', 'title': 'prefix-' + KEY, 'extra': KEY},
    ], 'echo': KEY})
    result = provider.search('synthetic', NAME) if method == 'legacy' else provider.search_name(NAME, 'download_page')
    assert result['organic_results'] == [{'link': 'https://sample.synthetic.test/clean', 'title': ''}]
    assert KEY not in json.dumps(result) and 'echo' not in result


def test_transport_does_not_mutate_embedded_model_json_before_schema_projection():
    provider = Provider({'koodous_key': KEY})
    payload = {'nested': json.dumps({'app': KEY})}
    provider.opener = SyntheticOpener(payload)
    assert provider.request('https://developer.koodous.com/apks/') == payload


def test_provider_transport_remains_direct_and_refuses_redirects():
    provider = Provider({'koodous_key': KEY})
    assert any(isinstance(handler, NoRedirect) for handler in provider.opener.handlers)
    proxies = [handler for handler in provider.opener.handlers if isinstance(handler, ProxyHandler)]
    assert not proxies or all(not handler.proxies for handler in proxies)
    provider, opener = synthetic_provider(error=HTTPError('https://developer.koodous.com/apks/',
        302, 'synthetic redirect', {'Location': 'https://evil.synthetic.test/'}, io.BytesIO(b'')))
    with pytest.raises(ProviderRequestError, match='icon_provider_http'):
        provider.search_catalog(NAME)
    assert len(opener.calls) == 1


def test_response_reading_has_a_hard_size_limit():
    provider, opener = synthetic_provider(raw=b' ' * (1024 * 1024 + 1))
    with pytest.raises(FxfetchError, match='icon_provider_response_limit'):
        provider.search_catalog(NAME)
    assert len(opener.calls) == 1


@pytest.mark.parametrize('name', [' ', 'reader" OR app: other', 'reader site:evil.synthetic.test',
                                'reader\nother', 'https://evil.synthetic.test/'])
def test_invalid_name_cannot_change_the_fixed_query_scope(name):
    provider, opener = synthetic_provider()
    with pytest.raises(FxfetchError, match='search_name_invalid'):
        provider.search_catalog(name)
    assert opener.calls == []


def test_missing_catalog_key_does_not_fall_back_to_anonymous_or_web_requests():
    provider = Provider({'serpapi_key': 'synthetic-web-secret'})
    opener = SyntheticOpener(page())
    provider.opener = opener
    with pytest.raises(FxfetchError, match='koodous_unconfigured'):
        provider.search_catalog(NAME)
    assert opener.calls == []


def test_single_web_query_can_use_one_remaining_free_credit_and_legacy_still_needs_two():
    provider = Provider({'serpapi_key': 'synthetic-web-secret'})
    opener = SyntheticOpener({'plan_monthly_price': 0, 'plan_searches_left': 1})
    provider.opener = opener
    assert provider.quota(1) == 1
    with pytest.raises(FxfetchError, match='icon_free_quota_unavailable'):
        provider.quota()


@pytest.mark.parametrize('payload', [{'plan_monthly_price': False, 'plan_searches_left': 1},
                                   {'plan_monthly_price': 0, 'plan_searches_left': True},
                                   {'plan_monthly_price': 1, 'plan_searches_left': 10}])
def test_one_query_still_requires_provably_free_nonboolean_quota(payload):
    provider = Provider({'serpapi_key': 'synthetic-web-secret'})
    provider.opener = SyntheticOpener(payload)
    with pytest.raises(FxfetchError, match='icon_free_quota_unavailable'):
        provider.quota(1)
