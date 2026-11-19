"""Bounded sample-catalog orchestration and legacy-crop privacy regressions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_icon_search import picture

from fxfetch.core.errors import FxfetchError
from fxfetch.icon_search.providers import Provider, ProviderRequestError
from fxfetch.icon_search.worker import execute

NAME = '合成阅读'
PRIVATE = 'SYNTHETIC_PRIVATE_CATALOG_RESPONSE'
SHA = 'a' * 64


def catalog_payload(*, records=None, count=1, next_page=False, complete=True, rejected=0,
                    page_returned=None, truncated=False):
    if records is None:
        records = [{'sha256': SHA, 'app_name': NAME, 'package_name': 'org.synthetic.reader',
                    'version': '1.0', 'url': 'https://koodous.com/apks/' + SHA}]
    return {'records': records, 'count': count, 'returned': len(records),
            'next_page_available': next_page, 'coverage_complete': complete,
            'page_returned': len(records) if page_returned is None else page_returned,
            'truncated': truncated,
            'rejected_records': rejected, 'page_limit': 20, 'private_provider_echo': PRIVATE}


class CatalogProvider:
    def __init__(self, *, catalog=True, web=False, payload=None, catalog_error=None,
                 quota_error=None, web_error=None, web_entries=None):
        self.catalog_enabled, self.web_enabled = catalog, web
        self.payload = catalog_payload() if payload is None else payload
        self.catalog_error, self.quota_error, self.web_error = catalog_error, quota_error, web_error
        self.web_entries = web_entries if web_entries is not None else [
            {'title': NAME + ' APK', 'link': 'https://download.synthetic.test/app.apk'}]
        self.calls = []
        self.last_timing = {}

    def search_catalog(self, name):
        self.calls.append(('catalog', name))
        self.last_timing = {'route': 'direct', 'http_status': 200, 'total_seconds': 1,
                            'url': PRIVATE, 'response_body': PRIVATE}
        if self.catalog_error:
            raise self.catalog_error
        return self.payload

    def quota(self, minimum=2):
        self.calls.append(('quota', minimum))
        if self.quota_error:
            raise self.quota_error
        return 200

    def search_name(self, name, scope):
        self.calls.append(('web', name, scope))
        if self.web_error:
            raise self.web_error
        return {'organic_results': self.web_entries}

    def recognize(self, image):
        pytest.fail('Name search must not call the vision model')

    def upload(self, image):
        pytest.fail('Name search must not upload images')

    def search(self, image_id, name=''):
        pytest.fail('Name search must not call Lens')


def named_search(tmp_path: Path, provider):
    (tmp_path / 'request.json').write_text(json.dumps({'mode': 'name', 'name': NAME}), encoding='utf-8')
    return execute(tmp_path, tmp_path, provider)


def test_catalog_only_returns_real_api_identity_without_web_quota_or_file_requests(tmp_path):
    provider = CatalogProvider()
    result = named_search(tmp_path, provider)
    assert provider.calls == [('catalog', NAME)]
    assert result['state'] == 'completed' and result['search_attempts'] == 1
    assert result['candidate_requests'] == 0
    assert result['catalog_status'] == {
        'provider': 'Koodous', 'status': 'hit', 'count': 1, 'returned': 1,
        'next_page_available': False, 'coverage_complete': True, 'rejected_records': 0, 'page_limit': 20,
        'page_returned': 1, 'truncated': False,
    }
    candidate = result['candidates'][0]
    assert candidate['sha256'] == SHA and candidate['package_name'] == 'org.synthetic.reader'
    assert candidate['app_name'] == NAME and candidate['version'] == '1.0'
    assert candidate['category'] == 'sample_record' and candidate['channel'] == 'koodous_api'
    assert candidate['catalog'] == 'Koodous' and candidate['can_collect'] is False
    assert candidate['verified'] is False and candidate['downloadable'] is None
    assert result['library_queries'][0]['queried'] is True
    assert PRIVATE not in json.dumps(result)
    assert any(row['stage'] == 'catalog_search' for row in result['timing']['requests'])


def test_actual_worker_loads_catalog_only_configuration(tmp_path, monkeypatch):
    (tmp_path / 'icon-search.json').write_text(
        json.dumps({'koodous_key': 'synthetic-catalog-token'}), encoding='utf-8')
    (tmp_path / 'request.json').write_text(json.dumps({'mode': 'name', 'name': NAME}), encoding='utf-8')
    calls = []

    def search_catalog(self, name):
        calls.append(name)
        assert self.catalog_enabled is True and self.web_enabled is False
        return catalog_payload()

    def no_network(*args, **kwargs):
        pytest.fail('All external requests must be replaced by synthetic catalog responses')

    monkeypatch.setattr(Provider, 'search_catalog', search_catalog)
    monkeypatch.setattr(Provider, 'request', no_network)
    result = execute(tmp_path, tmp_path)
    assert result['state'] == 'completed' and calls == [NAME]


def test_only_valid_empty_catalog_response_is_no_record(tmp_path):
    provider = CatalogProvider(payload=catalog_payload(records=[], count=0))
    result = named_search(tmp_path, provider)
    assert result['state'] == 'completed' and result['result'] == 'no_match'
    assert result['catalog_status']['status'] == 'no_record'
    assert result['catalog_status']['count'] == 0 and result['catalog_status']['returned'] == 0
    assert result['candidates'] == [] and result['search_attempts'] == 1


def test_catalog_without_total_count_keeps_unknown_total_and_valid_hit(tmp_path):
    provider = CatalogProvider(payload=catalog_payload(count=None))
    result = named_search(tmp_path, provider)
    assert result['state'] == 'completed' and result['catalog_status']['status'] == 'hit'
    assert result['catalog_status']['count'] is None
    assert result['catalog_status']['returned'] == result['catalog_status']['page_returned'] == 1
    assert result['catalog_status']['coverage_complete'] is True
    assert result['catalog_status']['truncated'] is False
    assert provider.calls == [('catalog', NAME)]


def test_catalog_without_total_count_preserves_truncated_single_page(tmp_path):
    records = [{'sha256': f'{number:064x}', 'app_name': NAME} for number in range(20)]
    provider = CatalogProvider(payload=catalog_payload(records=records, count=None, complete=False,
                                                       page_returned=44, truncated=True))
    result = named_search(tmp_path, provider)
    assert result['state'] == 'completed' and result['catalog_status']['status'] == 'hit'
    assert len(result['candidates']) == result['catalog_status']['returned'] == 20
    assert result['catalog_status']['count'] is None
    assert result['catalog_status']['page_returned'] == 44
    assert result['catalog_status']['truncated'] is True
    assert result['catalog_status']['next_page_available'] is False
    assert result['catalog_status']['coverage_complete'] is False
    assert provider.calls == [('catalog', NAME)] and result['candidate_requests'] == 0


def test_valid_empty_catalog_without_total_count_is_no_record(tmp_path):
    provider = CatalogProvider(payload=catalog_payload(records=[], count=None))
    result = named_search(tmp_path, provider)
    assert result['state'] == 'completed' and result['result'] == 'no_match'
    assert result['catalog_status']['status'] == 'no_record'
    assert result['catalog_status']['count'] is None
    assert result['catalog_status']['returned'] == result['catalog_status']['page_returned'] == 0
    assert result['catalog_status']['coverage_complete'] is True
    assert provider.calls == [('catalog', NAME)]


@pytest.mark.parametrize('payload', [
    catalog_payload(records=[], count=4, complete=False, rejected=4),
    catalog_payload(records=[{'sha256': 'invalid'}], count=1, complete=False),
    catalog_payload(records=[], count=0, next_page=True, complete=False),
    catalog_payload(records=[], count=False),
    catalog_payload(records=[], count=None, complete=False),
    catalog_payload(records=[], count=None, rejected=1),
    catalog_payload(records=[], count=None, next_page=True),
    catalog_payload(records=[], count=None, page_returned=44, truncated=True, complete=False),
    catalog_payload(count=0),
    catalog_payload(count=None, page_returned=False),
    catalog_payload(count=None, truncated=1),
])
def test_invalid_or_fully_rejected_catalog_never_becomes_no_record(tmp_path, payload):
    result = named_search(tmp_path, CatalogProvider(payload=payload))
    assert result['state'] == 'failed' and result['error'] == 'koodous_response_invalid'
    assert result['catalog_status']['status'] == 'failed'
    assert result['catalog_status']['count'] is None
    assert result['candidates'] == []


def test_catalog_first_then_exactly_one_independent_web_search(tmp_path):
    provider = CatalogProvider(web=True)
    result = named_search(tmp_path, provider)
    assert provider.calls == [('catalog', NAME), ('quota', 1), ('web', NAME, 'download_page')]
    assert result['state'] == 'completed' and result['search_attempts'] == 2
    assert {item['category'] for item in result['candidates']} == {'sample_record', 'download_page'}
    assert result['candidate_requests'] == 0


def test_catalog_auth_failure_keeps_safe_status_and_independent_web_candidate(tmp_path):
    error = ProviderRequestError('icon_provider_auth', 401)
    error.message = PRIVATE
    provider = CatalogProvider(web=True, catalog_error=error)
    result = named_search(tmp_path, provider)
    assert provider.calls == [('catalog', NAME), ('quota', 1), ('web', NAME, 'download_page')]
    assert result['state'] == 'partial' and result['error'] == 'icon_provider_auth'
    assert result['catalog_status']['status'] == 'failed'
    assert result['catalog_status']['http_status'] == 401
    assert result['catalog_status']['count'] is None
    assert len(result['candidates']) == 1 and result['candidates'][0]['category'] == 'download_page'
    assert PRIVATE not in json.dumps(result)


def test_catalog_failure_and_empty_web_results_are_failure_not_no_match(tmp_path):
    provider = CatalogProvider(web=True, catalog_error=FxfetchError('icon_provider_timeout', PRIVATE),
                               web_entries=[])
    result = named_search(tmp_path, provider)
    assert result['state'] == 'failed' and result.get('result') != 'no_match'
    assert result['catalog_status']['status'] == 'failed' and result['candidates'] == []
    assert result['search_attempts'] == 2


@pytest.mark.parametrize('failure_stage', ['quota', 'web'])
def test_web_failure_keeps_successful_catalog_records(tmp_path, failure_stage):
    failure = FxfetchError('icon_provider_quota', PRIVATE)
    provider = CatalogProvider(web=True, **{failure_stage + '_error': failure})
    result = named_search(tmp_path, provider)
    assert result['state'] == 'partial' and result['error'] == 'icon_provider_quota'
    assert result['catalog_status']['status'] == 'hit'
    assert len(result['candidates']) == 1 and result['candidates'][0]['category'] == 'sample_record'
    assert len([call for call in provider.calls if call[0] == 'catalog']) == 1
    assert PRIVATE not in json.dumps(result)


def test_unconfigured_catalog_preserves_two_web_scope_contract(tmp_path):
    provider = CatalogProvider(catalog=False, web=True)
    result = named_search(tmp_path, provider)
    assert provider.calls == [('quota', 2), ('web', NAME, 'sample_index'), ('web', NAME, 'download_page')]
    assert result['state'] == 'completed' and result['search_attempts'] == 2
    assert result['catalog_status']['status'] == 'unconfigured'
    assert result['catalog_status']['count'] is None


def test_no_available_source_is_not_an_empty_success(tmp_path):
    provider = CatalogProvider(catalog=False, web=False)
    result = named_search(tmp_path, provider)
    assert result['state'] == 'failed' and result['error'] == 'icon_search_unconfigured'
    assert result['search_attempts'] == 0 and provider.calls == []


def test_catalog_page_is_bounded_and_never_followed(tmp_path):
    records = [{'sha256': f'{number:064x}', 'app_name': NAME, 'package_name': 'org.synthetic.reader',
                'version': str(number)} for number in range(20)]
    provider = CatalogProvider(payload=catalog_payload(records=records, count=88,
                                                       next_page=True, complete=False))
    result = named_search(tmp_path, provider)
    assert provider.calls == [('catalog', NAME)]
    assert len(result['candidates']) == 20
    assert result['catalog_status']['count'] == 88
    assert result['catalog_status']['next_page_available'] is True
    assert result['catalog_status']['coverage_complete'] is False


def test_catalog_and_web_results_have_global_stable_ids_and_maximum_forty(tmp_path):
    records = [{'sha256': f'{number:064x}', 'app_name': NAME} for number in range(20)]
    web = [{'title': NAME + ' APK', 'link': f'https://download.synthetic.test/{number}.apk'}
           for number in range(25)]
    provider = CatalogProvider(web=True, payload=catalog_payload(records=records, count=20), web_entries=web)
    result = named_search(tmp_path, provider)
    assert len(result['candidates']) == 40
    assert [row['id'] for row in result['candidates']] == [str(number) for number in range(1, 41)]
    assert len({row['url'] for row in result['candidates']}) == 40


def test_duplicate_web_reference_cannot_downgrade_api_identity(tmp_path):
    payload = catalog_payload()
    payload['records'][0]['url'] = 'https://untrusted.synthetic.test/not-the-catalog'
    provider = CatalogProvider(web=True, payload=payload,
                               web_entries=[{'title': NAME, 'link': 'https://koodous.com/apks/' + SHA}])
    result = named_search(tmp_path, provider)
    assert len(result['candidates']) == 1
    row = result['candidates'][0]
    assert row['url'] == 'https://koodous.com/apks/' + SHA
    assert row['category'] == 'sample_record' and row['channel'] == 'koodous_api'
    assert row['sha256'] == SHA and row['can_collect'] is False


class LegacyProvider:
    def __init__(self, box):
        self.box, self.calls = box, []

    def quota(self):
        self.calls.append('quota')
        return 200

    def recognize(self, image):
        self.calls.append('recognize')
        return {'name': NAME, 'confidence': 'high', 'ambiguous': False, 'icon_box': self.box}

    def upload(self, image):
        self.calls.append('upload')
        return 'synthetic-image-id'

    def search(self, image_id, name=''):
        self.calls.append('search')
        return {'visual_matches': []}


@pytest.mark.parametrize('box', [None, [0, 0, 1000, 1000], [500, 500, 500, 900]])
def test_legacy_image_never_uploads_missing_full_or_invalid_crop(tmp_path, box):
    (tmp_path / 'input.image').write_bytes(picture())
    provider = LegacyProvider(box)
    result = execute(tmp_path, tmp_path, provider)
    assert result['state'] == 'failed' and result['error'] == 'icon_recognition_invalid'
    assert provider.calls == ['quota', 'recognize']
    assert result['search_attempts'] == 0 and result['candidate_requests'] == 0


@pytest.mark.parametrize('box', [None, [0, 0, 1000, 1000]])
def test_recognition_only_name_read_is_not_blocked_by_unavailable_crop(tmp_path, box):
    (tmp_path / 'input.image').write_bytes(picture())
    (tmp_path / 'request.json').write_text('{"mode":"recognize"}', encoding='utf-8')
    provider = LegacyProvider(box)
    result = execute(tmp_path, tmp_path, provider)
    assert result['state'] == 'completed' and result['result'] == 'recognized'
    assert result['recognition']['name'] == NAME and result['crop_applied'] is False
    assert provider.calls == ['recognize']


def test_legacy_valid_crop_preserves_existing_two_search_sequence(tmp_path):
    (tmp_path / 'input.image').write_bytes(picture())
    provider = LegacyProvider([100, 100, 900, 700])
    result = execute(tmp_path, tmp_path, provider)
    assert result['state'] == 'completed' and result['crop_applied'] is True
    assert result['search_attempts'] == 2
    assert provider.calls == ['quota', 'recognize', 'upload', 'search', 'search']
