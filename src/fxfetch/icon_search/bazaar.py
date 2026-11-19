"""Single-hash lookups and authenticated sample envelopes from the MalwareBazaar API."""

from __future__ import annotations

import hashlib
import json
import shutil
import ssl
import stat
import struct
import tempfile
import time
import zlib
from collections.abc import Iterator
from contextlib import contextmanager
from copy import copy
from http.client import HTTPException, HTTPResponse, HTTPSConnection
from pathlib import Path
from urllib.parse import urlencode

import pyzipper

from ..core.download import classify_package
from ..core.errors import FxfetchError
from ..core.limits import Limits
from .providers import ProviderRequestError
from .sample_transport import (
    BLOCK,
    DISK_RESERVE,
    provider_key,
    publish_sample,
    response_chunks,
    response_length,
    sample_digest,
    unique_object,
)

_PACKAGE_LIMIT = Limits().max_package_bytes
_DETAILS_LIMIT = 64 * 1024


def malwarebazaar_configured(state_root: Path) -> bool:
    try:
        provider_key(state_root, 'malwarebazaar_key', 'bazaar')
    except ProviderRequestError:
        return False
    return True


def _json(body: bytes) -> dict:
    try:
        record = json.loads(body.decode('utf-8'), object_pairs_hook=unique_object)
    except (ValueError, RecursionError):
        raise ProviderRequestError('bazaar_response_invalid', 200) from None
    if not isinstance(record, dict):
        raise ProviderRequestError('bazaar_response_invalid', 200)
    return record


def _check_directory(wire: Path) -> None:
    # Bound central-directory allocation before the library constructs any ZipInfo objects.
    size = wire.stat().st_size
    with wire.open('rb') as stream:
        if stream.read(4) != b'PK\x03\x04':
            raise ProviderRequestError('bazaar_invalid_archive', 200)
        start = max(0, size - 65557)
        stream.seek(start)
        tail = stream.read(65557)
        pos = tail.rfind(b'PK\x05\x06')
        if pos < 0 or pos + 22 > len(tail):
            raise ProviderRequestError('bazaar_invalid_archive', 200)
        _, disk, cd_disk, local_count, count, cd_size, cd_offset, comment = struct.unpack_from('<4s4H2LH', tail, pos)
        if (disk or cd_disk or local_count != 1 or count != 1 or not 46 <= cd_size <= 65536
                or pos + 22 + comment != len(tail) or cd_offset + cd_size != start + pos):
            raise ProviderRequestError('bazaar_invalid_archive', 200)
        # An extra ZIP64 locator can override the simple end record inside ZIP readers.
        stream.seek(start + pos - 20)
        if stream.read(4) == b'PK\x06\x07':
            raise ProviderRequestError('bazaar_invalid_archive', 200)


def _extract(wire: Path, pending: Path, digest: str, deadline: float) -> int:
    _check_directory(wire)
    available = shutil.disk_usage(pending.parent).free - DISK_RESERVE
    try:
        with pyzipper.AESZipFile(str(wire)) as archive:
            members = archive.infolist()
            if len(members) != 1:
                raise ProviderRequestError('bazaar_invalid_archive', 200)
            member = members[0]
            name = member.orig_filename
            if (not name or name in ('.', '..') or any(c in name for c in '/\\:')
                    or not name.isprintable() or member.is_dir() or member.external_attr & 0x10
                    or stat.S_IFMT(member.external_attr >> 16) not in (0, stat.S_IFREG)
                    or member.header_offset != 0 or not member.flag_bits & 1
                    or member.wz_aes_vendor_id != b'AE' or member.wz_aes_version not in (1, 2)
                    or member.wz_aes_strength not in (1, 2, 3)
                    or member.compress_type not in (pyzipper.ZIP_DEFLATED, pyzipper.ZIP_STORED)):
                raise ProviderRequestError('bazaar_invalid_archive', 200)
            if member.file_size > _PACKAGE_LIMIT:
                raise ProviderRequestError('bazaar_size_limit', 200)
            if member.file_size > available:
                raise ProviderRequestError('bazaar_storage')
            hasher = hashlib.sha256()
            total = 0
            # The library normally truncates reads at the untrusted declared size. Allow one
            # extra byte so an undersized declaration cannot silently discard sample bytes.
            readable = copy(member)
            readable.file_size += 1
            # Reading to EOF checks the AES authentication code and CRC where the format supplies one.
            with archive.open(readable, pwd=b'infected') as source, pending.open('xb') as output:
                while block := source.read(BLOCK):
                    total += len(block)
                    if total > member.file_size or total > _PACKAGE_LIMIT:
                        raise ProviderRequestError('bazaar_size_limit', 200)
                    if time.monotonic() >= deadline:
                        raise ProviderRequestError('bazaar_timeout', 200)
                    hasher.update(block)
                    output.write(block)
            if not total or total != member.file_size:
                raise ProviderRequestError('bazaar_invalid_archive', 200)
    except (pyzipper.BadZipFile, ValueError, KeyError, IndexError, RuntimeError, EOFError, struct.error, zlib.error):
        raise ProviderRequestError('bazaar_invalid_archive', 200) from None
    if hasher.hexdigest() != digest:
        raise ProviderRequestError('bazaar_hash_mismatch', 200)
    try:
        package = classify_package(pending)
    except FxfetchError:
        raise ProviderRequestError('bazaar_invalid_apk', 200) from None
    if package != 'apk':
        raise ProviderRequestError('bazaar_invalid_apk', 200)
    if time.monotonic() >= deadline:
        raise ProviderRequestError('bazaar_timeout', 200)
    return total


class MalwareBazaarClient:
    def __init__(self, state_root: Path):
        self._key = provider_key(state_root, 'malwarebazaar_key', 'bazaar')

    @contextmanager
    def _response(self, action: str, digest: str) -> Iterator[HTTPResponse]:
        if self._key.lower() in digest:
            raise ProviderRequestError('bazaar_invalid_hash')
        field = 'hash' if action == 'get_info' else 'sha256_hash'
        headers = {'Auth-Key': self._key, 'Accept-Encoding': 'identity',
                   'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'fxfetch/0.1'}
        connection = HTTPSConnection('mb-api.abuse.ch', timeout=10, context=ssl.create_default_context())
        try:
            try:
                connection.request('POST', '/api/v1/', body=urlencode({'query': action, field: digest}),
                                   headers=headers)
                response = connection.getresponse()
            except TimeoutError:
                raise ProviderRequestError('bazaar_timeout') from None
            except ssl.SSLError:
                raise ProviderRequestError('bazaar_tls') from None
            except HTTPException:
                raise ProviderRequestError('bazaar_incomplete') from None
            except OSError:
                raise ProviderRequestError('bazaar_connection') from None
            with response:
                if response.status != 200:
                    codes = {401: 'bazaar_auth', 403: 'bazaar_forbidden', 429: 'bazaar_quota'}
                    raise ProviderRequestError(codes.get(response.status, 'bazaar_http'), response.status)
                yield response
        finally:
            connection.close()

    def lookup(self, sha256: str) -> dict | None:
        digest = sample_digest(sha256, 'bazaar')
        deadline = time.monotonic() + 30
        with self._response('get_info', digest) as response:
            size = response_length(response, _DETAILS_LIMIT, 'bazaar')
            record = _json(b''.join(response_chunks(response, _DETAILS_LIMIT, size, deadline, 'bazaar')))
        if record == {'query_status': 'hash_not_found'}:
            return None
        data = record.get('data')
        if (record.get('query_status') != 'ok' or not isinstance(data, list) or len(data) != 1
                or not isinstance(data[0], dict) or not isinstance(data[0].get('sha256_hash'), str)
                or data[0]['sha256_hash'].lower() != digest):
            raise ProviderRequestError('bazaar_response_invalid', 200)
        return {'sha256': digest}

    def download(self, sha256: str, destination: Path) -> int:
        digest = sample_digest(sha256, 'bazaar')
        deadline = time.monotonic() + 120
        try:
            if destination.exists() or destination.is_symlink():
                raise ProviderRequestError('bazaar_storage')
            available = shutil.disk_usage(destination.parent).free - DISK_RESERVE
            if available <= 0:
                raise ProviderRequestError('bazaar_storage')
            with tempfile.TemporaryDirectory(dir=destination.parent) as scratch:
                wire = Path(scratch) / 'response.zip'
                pending = Path(scratch) / 'sample.part'
                with self._response('get_file', digest) as response:
                    content_type = (response.getheader('Content-Type') or '').partition(';')[0].strip().lower()
                    limit = _DETAILS_LIMIT if content_type == 'application/json' else _PACKAGE_LIMIT
                    size = response_length(response, limit, 'bazaar')
                    if size is not None and size > available:
                        raise ProviderRequestError('bazaar_storage')
                    with wire.open('xb') as output:
                        for block in response_chunks(response, limit, size, deadline, 'bazaar'):
                            if output.tell() + len(block) > available:
                                raise ProviderRequestError('bazaar_storage')
                            output.write(block)
                if wire.stat().st_size <= _DETAILS_LIMIT:
                    body = wire.read_bytes()
                    if body.lstrip().startswith(b'{') or content_type == 'application/json':
                        if _json(body) == {'query_status': 'file_not_found'}:
                            raise ProviderRequestError('bazaar_no_record', 200)
                        raise ProviderRequestError('bazaar_response_invalid', 200)
                total = _extract(wire, pending, digest, deadline)
                publish_sample(pending, destination)
            return total
        except OSError:
            raise ProviderRequestError('bazaar_storage') from None
