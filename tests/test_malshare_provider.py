import hashlib
import io
import json
import ssl
import zipfile
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from fxfetch.icon_search import malshare
from fxfetch.icon_search.providers import ProviderRequestError

SYNTHETIC_KEY = 'synthetic+value'
DIGEST = 'ab' * 32


class Response(io.BytesIO):
    def __init__(self, body=b'', *, status=200, headers=None):
        super().__init__(body)
        self.status = status
        self.headers = headers or {}

    def getheader(self, name):
        return self.headers.get(name)


@pytest.fixture
def client(tmp_path):
    (tmp_path / 'icon-search.json').write_text(json.dumps({'malshare_key': SYNTHETIC_KEY}), encoding='utf-8')
    return malshare.MalShareClient(tmp_path)


def capture(monkeypatch, response):
    calls = []

    class Connection:
        def __init__(self, host, *, timeout, context):
            assert host == 'malshare.com' and 0 < timeout <= 10
            assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname

        def request(self, method, url, *, headers):
            assert method == 'GET' and urlsplit(url).path == '/api.php'
            assert headers['Accept-Encoding'] == 'identity'
            calls.append(parse_qs(urlsplit(url).query))

        def getresponse(self):
            return response

        def close(self):
            pass

    monkeypatch.setattr(malshare, 'HTTPSConnection', Connection)
    return calls


def apk():
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as archive:
        archive.writestr('AndroidManifest.xml', b'manifest')
        archive.writestr('classes.dex', b'synthetic')
    return data.getvalue()


def test_lookup_projects_only_matching_digests(monkeypatch, client):
    record = {'SHA256': DIGEST.upper(), 'MD5': '11' * 16, 'SHA1': '22' * 20,
              'F_TYPE': 'arbitrary', 'SOURCES': [SYNTHETIC_KEY], 'F_NAME': SYNTHETIC_KEY}
    calls = capture(monkeypatch, Response(json.dumps(record).encode()))
    assert client.lookup(DIGEST.upper()) == {'sha256': DIGEST, 'md5': '11' * 16, 'sha1': '22' * 20}
    assert calls == [{'action': ['details'], 'hash': [DIGEST], 'api_key': [SYNTHETIC_KEY]}]


@pytest.mark.parametrize('value', ['https://example.invalid/file.apk', 'a' * 63, 'a' * 32, DIGEST + '?k=2'])
def test_invalid_hash_never_connects(monkeypatch, client, tmp_path, value):
    calls = capture(monkeypatch, Response())
    for method in (lambda: client.lookup(value), lambda: client.download(value, tmp_path / 'file.apk')):
        with pytest.raises(ProviderRequestError, match='malshare_invalid_hash'):
            method()
    assert not calls


@pytest.mark.parametrize('status', [200, 404])
@pytest.mark.parametrize('body', [b'Sample not found\n', b'{"ERROR":{"CODE":404,"MESSAGE":"Sample not found"}}'])
def test_only_explicit_missing_marker_returns_no_record(monkeypatch, client, status, body):
    capture(monkeypatch, Response(body, status=status))
    assert client.lookup(DIGEST) is None


@pytest.mark.parametrize('status', [200, 404])
@pytest.mark.parametrize('body', [
    b'{"ERROR":{"CODE":404.0,"MESSAGE":"Sample not found"}}',
    b'{"ERROR":{"CODE":"404","MESSAGE":"Sample not found"}}',
    b'{"ERROR":{"CODE":403,"MESSAGE":"Sample not found"}}',
    b'{"ERROR":{"CODE":404,"MESSAGE":"Sample not found elsewhere"}}',
    b'{"ERROR":{"CODE":404,"MESSAGE":"Sample not found","extra":0}}',
    b'{"ERROR":{"CODE":404,"MESSAGE":"Sample not found"},"SHA256":"unknown"}',
    b'{"ERROR":"Sample not found"}',
    b'{"ERROR":{"CODE":401,"CODE":404,"MESSAGE":"Sample not found"}}',
])
def test_ambiguous_json_is_not_a_missing_record(monkeypatch, client, status, body):
    capture(monkeypatch, Response(body, status=status))
    expected = 'malshare_http' if status == 404 else 'malshare_response_invalid'
    with pytest.raises(ProviderRequestError, match=expected):
        client.lookup(DIGEST)


@pytest.mark.parametrize(('status', 'body', 'code'), [
    (200, b'', 'malshare_response_invalid'),
    (200, b'{}', 'malshare_response_invalid'),
    (200, b'null', 'malshare_response_invalid'),
    (200, b'ERROR! => Account not activated', 'malshare_auth'),
    (200, json.dumps({'SHA256': '9' * 64}).encode(), 'malshare_response_invalid'),
    (200, json.dumps({'error': SYNTHETIC_KEY, 'SHA256': DIGEST}).encode(), 'malshare_response_invalid'),
    (200, json.dumps({'ERROR': 'Sample not found', 'SHA256': DIGEST}).encode(), 'malshare_response_invalid'),
    (401, b'Sample not found', 'malshare_auth'),
    (403, b'Sample not found', 'malshare_forbidden'),
    (403, b'{"ERROR":{"CODE":404,"MESSAGE":"Sample not found"}}', 'malshare_forbidden'),
    (403, b'ERROR! => Account not activated', 'malshare_auth'),
    (403, b'<html>ERROR! => Account not activated</html>', 'malshare_forbidden'),
    (404, b'<html>missing</html>', 'malshare_http'),
    (429, b'Sample not found', 'malshare_quota'),
    (502, SYNTHETIC_KEY.encode(), 'malshare_http'),
    (302, b'', 'malshare_http'),
    (206, b'', 'malshare_http'),
])
def test_fixed_provider_failures(monkeypatch, client, status, body, code):
    calls = capture(monkeypatch, Response(body, status=status, headers={'Location': 'https://invalid.invalid/'}))
    with pytest.raises(ProviderRequestError) as failure:
        client.lookup(DIGEST)
    assert str(failure.value) == code and failure.value.http_status == status
    assert len(calls) == 1


def test_denial_diagnostic_reads_no_more_than_256_bytes(monkeypatch, client):
    class Denied(Response):
        total = 0

        def read1(self, length):
            chunk = super().read1(length)
            self.total += len(chunk)
            return chunk

    response = Denied(b'ERROR! => Account not activated' + b' ' * 500, status=403)
    capture(monkeypatch, response)
    with pytest.raises(ProviderRequestError, match='malshare_forbidden'):
        client.lookup(DIGEST)
    assert response.total <= 256


def test_secret_shaped_candidate_never_transmitted(tmp_path, monkeypatch):
    (tmp_path / 'icon-search.json').write_text(json.dumps({'malshare_key': DIGEST}), encoding='utf-8')
    calls = capture(monkeypatch, Response())
    client = malshare.MalShareClient(tmp_path)
    with pytest.raises(ProviderRequestError, match='malshare_invalid_hash'):
        client.lookup(DIGEST.upper())
    assert not calls


@pytest.mark.parametrize(('body', 'headers', 'code'), [
    (b'12345', {'Content-Length': '6'}, 'malshare_incomplete'),
    (b'12345', {'Content-Length': '??'}, 'malshare_response_invalid'),
    (b'12345', {'Content-Encoding': 'gzip'}, 'malshare_response_invalid'),
    (b'12345', {'Transfer-Encoding': 'chunked', 'Content-Length': '5'}, 'malshare_response_invalid'),
    (b'12345', {'Content-Range': 'bytes 0-4/10'}, 'malshare_response_invalid'),
    (b'', {'Content-Length': '65537'}, 'malshare_size_limit'),
    (b'x' * 65537, {}, 'malshare_size_limit'),
])
def test_metadata_length_and_framing(monkeypatch, client, body, headers, code):
    capture(monkeypatch, Response(body, headers=headers))
    with pytest.raises(ProviderRequestError, match=code):
        client.lookup(DIGEST)


def test_download_verified_apk_once(monkeypatch, client, tmp_path):
    data = apk()
    digest = hashlib.sha256(data).hexdigest()
    path = tmp_path / 'selected.apk'
    calls = capture(monkeypatch, Response(data, headers={'Content-Length': str(len(data))}))
    assert client.download(digest, path) == len(data)
    assert path.read_bytes() == data and not list(tmp_path.glob('*.part'))
    with pytest.raises(ProviderRequestError, match='malshare_storage'):
        client.download(digest, path)
    assert calls == [{'action': ['getfile'], 'hash': [digest], 'api_key': [SYNTHETIC_KEY]}]


@pytest.mark.parametrize(('body', 'digest', 'headers', 'code'), [
    (apk(), DIGEST, {}, 'malshare_hash_mismatch'),
    (b'plain', hashlib.sha256(b'plain').hexdigest(), {}, 'malshare_invalid_apk'),
    (b'Sample not found', DIGEST, {}, 'malshare_no_record'),
    (b'zip', DIGEST, {'Content-Length': '120'}, 'malshare_incomplete'),
    (b'zip', DIGEST, {'Content-Length': str(512 * 1024 * 1024 + 1)}, 'malshare_size_limit'),
])
def test_failed_download_leaves_no_file(monkeypatch, client, tmp_path, body, digest, headers, code):
    path = tmp_path / 'selected.apk'
    capture(monkeypatch, Response(body, headers=headers))
    with pytest.raises(ProviderRequestError, match=code):
        client.download(digest, path)
    assert not path.exists() and not list(tmp_path.glob('*.part'))


@pytest.mark.parametrize('headers', [{}, {'Content-Length': '9'}])
def test_disk_bound_with_or_without_content_length(monkeypatch, client, tmp_path, headers):
    capture(monkeypatch, Response(b'123456789', headers=headers))
    monkeypatch.setattr(malshare.shutil, 'disk_usage', lambda _: SimpleNamespace(free=malshare._DISK_RESERVE + 8))
    path = tmp_path / 'selected.apk'
    with pytest.raises(ProviderRequestError, match='malshare_storage'):
        client.download(DIGEST, path)
    assert not path.exists() and not list(tmp_path.glob('*.part'))


def test_interrupted_socket_is_sanitized(monkeypatch, client, tmp_path):
    class Interrupted(Response):
        def read1(self, length):
            if self.tell() > 0:
                raise ConnectionResetError(SYNTHETIC_KEY)
            return self.read(length)

    capture(monkeypatch, Interrupted(b'fragment'))
    with pytest.raises(ProviderRequestError) as failure:
        client.download(DIGEST, tmp_path / 'partial.apk')
    assert str(failure.value) == 'malshare_incomplete'
    assert not (tmp_path / 'partial.apk').exists() and not list(tmp_path.glob('*.part'))


def test_capability_uses_only_local_private_config(tmp_path: Path):
    path = tmp_path / 'icon-search.json'
    for content in (None, '[]', '{}', '{', '{"malshare_key":7}', '{"malshare_key":"bad key"}', 'a' * 16385):
        if content is not None:
            path.write_text(content, encoding='utf-8')
        assert not malshare.malshare_configured(tmp_path)
        with pytest.raises(ProviderRequestError, match='malshare_unconfigured'):
            malshare.MalShareClient(tmp_path)
    path.write_text(json.dumps({'malshare_key': SYNTHETIC_KEY}), encoding='utf-8-sig')
    assert malshare.malshare_configured(tmp_path)
