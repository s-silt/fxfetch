"""Explicit single-digest MalShare requests for APK case evidence."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import ssl
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.client import HTTPException, HTTPResponse, HTTPSConnection
from pathlib import Path
from urllib.parse import urlencode

from ..core.download import classify_package
from ..core.errors import FxfetchError
from ..core.limits import Limits
from .providers import ProviderRequestError
from .sample_transport import (
    DISK_RESERVE as _DISK_RESERVE,
)
from .sample_transport import (
    provider_key,
    publish_sample,
    response_chunks,
    response_length,
    sample_digest,
    unique_object,
)

_PACKAGE_LIMIT = Limits().max_package_bytes
_DETAILS_LIMIT = 64 * 1024


def malshare_configured(state_root: Path) -> bool:
    try:
        provider_key(state_root, 'malshare_key', 'malshare')
    except ProviderRequestError:
        return False
    return True


def _missing_details(body: bytes) -> bool:
    if len(body) > 255 or not body.lstrip().startswith(b'{'):
        return False
    try:
        record = json.loads(body.decode('utf-8'), object_pairs_hook=unique_object)
    except (ValueError, RecursionError):
        return False
    expected = {'ERROR': {'CODE': 404, 'MESSAGE': 'Sample not found'}}
    return record == expected and type(record['ERROR']['CODE']) is int


def _check_marker(body: bytes, status: int, *, details: bool = False) -> None:
    marker = body.strip().lower()
    if status in (200, 404) and (marker == b'sample not found' or details and _missing_details(body)):
        raise ProviderRequestError('malshare_no_record', status)
    if marker == b'error! => account not activated':
        raise ProviderRequestError('malshare_auth', status)


def _check_error_response(response: HTTPResponse, deadline: float, *, details: bool) -> None:
    # A complete short provider marker can clarify the status. Other denial pages stay unclassified.
    try:
        size = response_length(response, 255, 'malshare')
        body = b''.join(response_chunks(response, 255, size, deadline, 'malshare'))
    except ProviderRequestError:
        return
    _check_marker(body, response.status, details=details)


class MalShareClient:
    def __init__(self, state_root: Path):
        self._key = provider_key(state_root, 'malshare_key', 'malshare')

    @contextmanager
    def _response(self, action: str, digest: str, deadline: float) -> Iterator[HTTPResponse]:
        if self._key.lower() in digest:
            raise ProviderRequestError('malshare_invalid_hash')
        # Direct TLS connection. No proxy, redirect handler, credential-bearing URL log or retry.
        connection = HTTPSConnection('malshare.com', timeout=10, context=ssl.create_default_context())
        try:
            query = urlencode({'api_key': self._key, 'action': action, 'hash': digest})
            connection.request('GET', '/api.php?' + query,
                               headers={'Accept-Encoding': 'identity', 'User-Agent': 'fxfetch/0.1'})
            with connection.getresponse() as response:
                if response.status in (403, 404):
                    _check_error_response(response, deadline, details=action == 'details')
                if response.status != 200:
                    code = {401: 'malshare_auth', 403: 'malshare_forbidden', 429: 'malshare_quota'}
                    raise ProviderRequestError(code.get(response.status, 'malshare_http'), response.status)
                yield response
        except TimeoutError:
            raise ProviderRequestError('malshare_timeout') from None
        except ssl.SSLError:
            raise ProviderRequestError('malshare_tls') from None
        except HTTPException:
            raise ProviderRequestError('malshare_incomplete') from None
        except OSError:
            raise ProviderRequestError('malshare_connection') from None
        finally:
            connection.close()

    def lookup(self, sha256: str) -> dict | None:
        digest = sample_digest(sha256, 'malshare')
        deadline = time.monotonic() + 30
        try:
            with self._response('details', digest, deadline) as response:
                size = response_length(response, _DETAILS_LIMIT, 'malshare')
                body = b''.join(response_chunks(response, _DETAILS_LIMIT, size, deadline, 'malshare'))
                _check_marker(body, response.status, details=True)
        except ProviderRequestError as exc:
            if exc.code == 'malshare_no_record':
                return None
            raise
        try:
            record = json.loads(body.decode('utf-8'), object_pairs_hook=unique_object)
        except (ValueError, RecursionError):
            raise ProviderRequestError('malshare_response_invalid', 200) from None
        if not isinstance(record, dict) or any(key.casefold() == 'error' for key in record):
            raise ProviderRequestError('malshare_response_invalid', 200)
        reported = record.get('SHA256')
        if not isinstance(reported, str) or reported.lower() != digest:
            raise ProviderRequestError('malshare_response_invalid', 200)
        public = {'sha256': digest}
        for field, length in (('MD5', 32), ('SHA1', 40)):
            value = record.get(field)
            if (isinstance(value, str) and re.fullmatch(rf'[a-fA-F0-9]{{{length}}}', value)
                    and self._key.lower() not in value.lower()):
                public[field.lower()] = value.lower()
        return public

    def download(self, sha256: str, destination: Path) -> int:
        digest = sample_digest(sha256, 'malshare')
        deadline = time.monotonic() + 120
        pending: Path | None = None
        try:
            if destination.exists() or destination.is_symlink():
                raise ProviderRequestError('malshare_storage')
            disk_limit = min(_PACKAGE_LIMIT, shutil.disk_usage(destination.parent).free - _DISK_RESERVE)
            if disk_limit <= 0:
                raise ProviderRequestError('malshare_storage')
            with self._response('getfile', digest, deadline) as response:
                size = response_length(response, _PACKAGE_LIMIT, 'malshare')
                if size is not None and size > disk_limit:
                    raise ProviderRequestError('malshare_storage')
                received = 0
                hasher = hashlib.sha256()
                try:
                    with tempfile.NamedTemporaryFile(dir=destination.parent, suffix='.part', delete=False) as output:
                        pending = Path(output.name)
                        for block in response_chunks(response, _PACKAGE_LIMIT, size, deadline, 'malshare'):
                            received += len(block)
                            if received > disk_limit:
                                raise ProviderRequestError('malshare_storage')
                            hasher.update(block)
                            output.write(block)
                except OSError:
                    raise ProviderRequestError('malshare_storage') from None
            if received <= 256:
                _check_marker(pending.read_bytes(), 200)
            if hasher.hexdigest() != digest:
                raise ProviderRequestError('malshare_hash_mismatch', 200)
            try:
                package = classify_package(pending)
            except FxfetchError:
                raise ProviderRequestError('malshare_invalid_apk', 200) from None
            if package != 'apk':
                raise ProviderRequestError('malshare_invalid_apk', 200)
            publish_sample(pending, destination)
            return received
        except OSError:
            raise ProviderRequestError('malshare_storage') from None
        finally:
            if pending is not None:
                pending.unlink(missing_ok=True)
