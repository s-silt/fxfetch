"""Request and file limits used by fixed-host, single-hash sample providers."""

from __future__ import annotations

import json
import os
import re
import ssl
import time
from collections.abc import Iterator
from http.client import HTTPException, HTTPResponse
from pathlib import Path

from .providers import ProviderRequestError

BLOCK = 64 * 1024
DISK_RESERVE = 16 * 1024 * 1024


def provider_key(root: Path, field: str, prefix: str) -> str:
    path = root / 'icon-search.json'
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError
        with path.open('rb') as stream:
            data = stream.read(16385)
        if len(data) > 16384:
            raise ValueError
        config = json.loads(data.decode('utf-8-sig'))
        key = config.get(field) if isinstance(config, dict) else None
        if not isinstance(key, str) or not re.fullmatch(r'[!-~]{1,1024}', key):
            raise ValueError
        return key
    except (OSError, ValueError, RecursionError):
        raise ProviderRequestError(f'{prefix}_unconfigured') from None


def sample_digest(value: str, prefix: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', value):
        raise ProviderRequestError(f'{prefix}_invalid_hash')
    return value.lower()


def response_length(response: HTTPResponse, limit: int, prefix: str) -> int | None:
    encoding = response.getheader('Content-Encoding') or 'identity'
    if response.getheader('Content-Range') is not None or encoding.lower() != 'identity':
        raise ProviderRequestError(f'{prefix}_response_invalid', response.status)
    value = response.getheader('Content-Length')
    transfer = response.getheader('Transfer-Encoding')
    if transfer is not None and (transfer.lower() != 'chunked' or value is not None):
        raise ProviderRequestError(f'{prefix}_response_invalid', response.status)
    if value is None:
        return None
    if re.fullmatch(r'[0-9]{1,20}', value) is None:
        raise ProviderRequestError(f'{prefix}_response_invalid', response.status)
    size = int(value)
    if size > limit:
        raise ProviderRequestError(f'{prefix}_size_limit', response.status)
    return size


def response_chunks(response: HTTPResponse, limit: int, expected: int | None, deadline: float,
                    prefix: str) -> Iterator[bytes]:
    total = 0
    while True:
        if time.monotonic() >= deadline:
            raise ProviderRequestError(f'{prefix}_timeout', response.status)
        try:
            block = response.read1(min(BLOCK, limit - total + 1))
        except TimeoutError:
            raise ProviderRequestError(f'{prefix}_timeout', response.status) from None
        except ssl.SSLError:
            raise ProviderRequestError(f'{prefix}_tls', response.status) from None
        except (HTTPException, OSError):
            raise ProviderRequestError(f'{prefix}_incomplete', response.status) from None
        if time.monotonic() >= deadline:
            raise ProviderRequestError(f'{prefix}_timeout', response.status)
        if not block:
            break
        total += len(block)
        if total > limit:
            raise ProviderRequestError(f'{prefix}_size_limit', response.status)
        yield block
    if expected is not None and total != expected:
        raise ProviderRequestError(f'{prefix}_incomplete', response.status)


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError('duplicate_json_key')
    return result


def publish_sample(pending: Path, destination: Path) -> None:
    # Windows rename and POSIX hard link both refuse to overwrite an existing file.
    if os.name == 'nt':
        pending.rename(destination)
    else:
        os.link(pending, destination)
