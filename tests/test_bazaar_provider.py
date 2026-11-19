import hashlib
import io
import json
import ssl
import struct
import zipfile
from types import SimpleNamespace
from urllib.parse import parse_qs

import pytest
import pyzipper

from fxfetch.icon_search import bazaar
from fxfetch.icon_search.providers import ProviderRequestError

KEY = 'synthetic-bazaar+key'
DIGEST = 'af' * 32


class Response(io.BytesIO):
    def __init__(self, body, *, status=200, headers=None):
        super().__init__(body)
        self.status = status
        self.headers = headers or {}

    def getheader(self, name):
        return self.headers.get(name)


def capture(monkeypatch, response):
    calls = []

    class Connection:
        def __init__(self, host, *, timeout, context):
            assert host == 'mb-api.abuse.ch' and 0 < timeout <= 10
            assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname

        def request(self, method, url, *, body, headers):
            assert method == 'POST' and url == '/api/v1/'
            assert headers['Auth-Key'] == KEY and headers['Accept-Encoding'] == 'identity'
            assert headers['Content-Type'] == 'application/x-www-form-urlencoded'
            calls.append(parse_qs(body))

        def getresponse(self):
            return response

        def close(self):
            pass

    monkeypatch.setattr(bazaar, 'HTTPSConnection', Connection)
    return calls


@pytest.fixture
def client(tmp_path):
    (tmp_path / 'icon-search.json').write_text(json.dumps({'malwarebazaar_key': KEY}), encoding='utf-8-sig')
    assert bazaar.malwarebazaar_configured(tmp_path)
    return bazaar.MalwareBazaarClient(tmp_path)


def apk():
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as archive:
        archive.writestr('AndroidManifest.xml', b'synthetic manifest')
        archive.writestr('classes.dex', b'synthetic classes')
    return data.getvalue()


def envelope(*members, password=b'infected', compression=pyzipper.ZIP_DEFLATED):
    output = io.BytesIO()
    with pyzipper.AESZipFile(output, 'w', compression=compression, encryption=pyzipper.WZ_AES) as archive:
        archive.setpassword(password)
        archive.setencryption(pyzipper.WZ_AES, nbits=128)
        for name, data in members:
            archive.writestr(name, data)
    return output.getvalue()


def test_hit_projects_only_selected_sha_and_form(monkeypatch, client):
    record = {'query_status': 'ok', 'data': [{'sha256_hash': DIGEST.upper(), 'other': KEY}]}
    calls = capture(monkeypatch, Response(json.dumps(record).encode()))
    assert client.lookup(DIGEST.upper()) == {'sha256': DIGEST}
    assert calls == [{'query': ['get_info'], 'hash': [DIGEST]}]


def test_explicit_hash_not_found(monkeypatch, client):
    capture(monkeypatch, Response(b'{"query_status":"hash_not_found"}'))
    assert client.lookup(DIGEST) is None


@pytest.mark.parametrize(('status', 'body', 'code'), [
    (200, b'{}', 'response_invalid'),
    (200, b'{"query_status":"ok","data":[]}', 'response_invalid'),
    (200, b'{"query_status":"hash_not_found","data":[{}]}', 'response_invalid'),
    (200, b'{"query_status":"ok","query_status":"hash_not_found"}', 'response_invalid'),
    (200, b'{"query_status":"ok","data":[{"sha256_hash":"other"}]}', 'response_invalid'),
    (200, b'{"query_status":"file_not_found"}', 'response_invalid'),
    (200, KEY.encode(), 'response_invalid'),
    (200, b'x' * 65537, 'size_limit'),
    (401, b'', 'auth'), (403, b'', 'forbidden'), (429, b'', 'quota'),
    (404, b'{"query_status":"hash_not_found"}', 'http'), (302, b'', 'http'), (206, b'', 'http'),
])
def test_denials_and_ambiguous_replies_are_terminal(monkeypatch, client, status, body, code):
    calls = capture(monkeypatch, Response(body, status=status, headers={'Location': 'https://example.invalid/'}))
    with pytest.raises(ProviderRequestError) as error:
        client.lookup(DIGEST)
    assert error.value.code == 'bazaar_' + code and error.value.http_status == status
    assert len(calls) == 1


@pytest.mark.parametrize('headers, code', [
    ({'Content-Length': '500'}, 'incomplete'),
    ({'Content-Encoding': 'gzip'}, 'response_invalid'),
    ({'Content-Length': '9', 'Transfer-Encoding': 'chunked'}, 'response_invalid'),
    ({'Content-Range': 'bytes 0-4/10'}, 'response_invalid'),
])
def test_bad_http_framing(monkeypatch, client, headers, code):
    capture(monkeypatch, Response(b'short', headers=headers))
    with pytest.raises(ProviderRequestError, match='^bazaar_' + code + '$'):
        client.lookup(DIGEST)


def test_bad_hashes_and_key_are_local_errors(monkeypatch, client, tmp_path):
    calls = capture(monkeypatch, Response(b''))
    for value in (None, 'https://example.invalid/', 'f' * 63, KEY):
        with pytest.raises(ProviderRequestError, match='bazaar_invalid_hash'):
            client.lookup(value)
        with pytest.raises(ProviderRequestError, match='bazaar_invalid_hash'):
            client.download(value, tmp_path / 'selected.apk')
    (tmp_path / 'icon-search.json').write_text(json.dumps({'malwarebazaar_key': DIGEST}))
    with pytest.raises(ProviderRequestError, match='bazaar_invalid_hash'):
        bazaar.MalwareBazaarClient(tmp_path).lookup(DIGEST.upper())
    (tmp_path / 'icon-search.json').write_text(json.dumps({'malwarebazaar_key': 'x\ny'}))
    assert not bazaar.malwarebazaar_configured(tmp_path) and not calls


@pytest.mark.parametrize('compression', [pyzipper.ZIP_DEFLATED, pyzipper.ZIP_STORED])
def test_download_publishes_verified_raw_bytes(monkeypatch, client, tmp_path, compression):
    data = apk()
    digest = hashlib.sha256(data).hexdigest()
    wire = envelope(('untrusted.sample', data), compression=compression)
    calls = capture(monkeypatch, Response(wire, headers={'Content-Length': str(len(wire))}))
    destination = tmp_path / 'sample.apk'
    assert client.download(digest, destination) == len(data)
    assert destination.read_bytes() == data
    with pytest.raises(ProviderRequestError, match='bazaar_storage'):
        client.download(digest, destination)
    assert calls == [{'query': ['get_file'], 'sha256_hash': [digest]}]
    assert {p.name for p in tmp_path.iterdir()} == {'icon-search.json', 'sample.apk'}


def rejected(client, tmp_path, code, digest=DIGEST):
    destination = tmp_path / 'selected.apk'
    with pytest.raises(ProviderRequestError) as error:
        client.download(digest, destination)
    assert str(error.value) == 'bazaar_' + code
    assert {p.name for p in tmp_path.iterdir()} == {'icon-search.json'}


@pytest.mark.parametrize('make_wire,code', [
    (lambda: envelope(('a', b'a'), ('b', b'b')), 'invalid_archive'),
    (lambda: envelope(('../other', b'data')), 'invalid_archive'),
    (lambda: envelope(('directory/', b'')), 'invalid_archive'),
    (lambda: envelope(('one', b'data'), password=b'different'), 'invalid_archive'),
    (lambda: envelope(('one', b'data'))[:-1], 'invalid_archive'),
    (lambda: apk(), 'invalid_archive'),
    (lambda: envelope(('one', apk())), 'hash_mismatch'),
    (lambda: b'{"query_status":"file_not_found"}', 'no_record'),
    (lambda: b'{"query_status":"hash_not_found"}', 'response_invalid'),
    (lambda: b'{"query_status":"file_not_found","query_status":"file_not_found"}', 'response_invalid'),
])
def test_rejects_bad_envelopes_or_hash(monkeypatch, client, tmp_path, make_wire, code):
    capture(monkeypatch, Response(make_wire()))
    rejected(client, tmp_path, code)


def test_verifies_authentication_and_inner_package(monkeypatch, client, tmp_path):
    body = apk()
    wire = bytearray(envelope(('single', body)))
    wire[wire.index(b'PK\x01\x02') - 1] ^= 1
    capture(monkeypatch, Response(wire))
    rejected(client, tmp_path, 'invalid_archive', hashlib.sha256(body).hexdigest())
    bad_crc = bytearray(body)
    bad_crc[bad_crc.index(b'synthetic classes')] ^= 1
    for inner in (b'benign text', body[:-2], bytes(bad_crc)):
        capture(monkeypatch, Response(envelope(('single', inner))))
        rejected(client, tmp_path, 'invalid_apk', hashlib.sha256(inner).hexdigest())


def test_rejects_underdeclared_member(monkeypatch, client, tmp_path):
    body = apk()
    wire = bytearray(envelope(('single', body)))
    directory = wire.index(b'PK\x01\x02')
    struct.pack_into('<I', wire, directory + 24, len(body) - 1)
    capture(monkeypatch, Response(wire))
    rejected(client, tmp_path, 'size_limit', hashlib.sha256(body[:-1]).hexdigest())


def test_wire_disk_and_independent_expansion_limits(monkeypatch, client, tmp_path):
    body = apk() + b'\x00' * 65536
    wire = envelope(('single', body))
    assert len(wire) < len(body)
    monkeypatch.setattr(bazaar, '_PACKAGE_LIMIT', len(wire))
    capture(monkeypatch, Response(wire))
    rejected(client, tmp_path, 'size_limit')
    capture(monkeypatch, Response(wire + b'x'))
    rejected(client, tmp_path, 'size_limit')
    monkeypatch.setattr(bazaar.shutil, 'disk_usage', lambda _: SimpleNamespace(free=bazaar.DISK_RESERVE + 1))
    capture(monkeypatch, Response(wire))
    rejected(client, tmp_path, 'storage')


def test_disk_reserve_rechecked_for_raw_output(monkeypatch, client, tmp_path):
    wire = envelope(('single', apk()))
    remaining = iter((bazaar.DISK_RESERVE + len(wire), bazaar.DISK_RESERVE))
    monkeypatch.setattr(bazaar.shutil, 'disk_usage', lambda _: SimpleNamespace(free=next(remaining)))
    capture(monkeypatch, Response(wire))
    rejected(client, tmp_path, 'storage')


def test_read_timeout_and_truncated_wire_never_publish(monkeypatch, client, tmp_path):
    class Timeout(Response):
        def read1(self, length):
            raise TimeoutError(KEY)

    capture(monkeypatch, Timeout(b''))
    rejected(client, tmp_path, 'timeout')
    capture(monkeypatch, Response(b'few bytes', headers={'Content-Length': '20'}))
    rejected(client, tmp_path, 'incomplete')


def test_concurrent_publication_preserves_other_file(monkeypatch, client, tmp_path):
    data = apk()
    capture(monkeypatch, Response(envelope(('single', data))))
    destination = tmp_path / 'sample.apk'
    publish = bazaar.publish_sample

    def race(pending, path):
        path.write_bytes(b'existing')
        publish(pending, path)

    monkeypatch.setattr(bazaar, 'publish_sample', race)
    with pytest.raises(ProviderRequestError, match='bazaar_storage'):
        client.download(hashlib.sha256(data).hexdigest(), destination)
    assert destination.read_bytes() == b'existing'
    assert {p.name for p in tmp_path.iterdir()} == {'icon-search.json', 'sample.apk'}
