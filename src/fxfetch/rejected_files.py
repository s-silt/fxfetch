"""Read-only access to complete package bytes rejected by archive validation.

These files are never successful artifacts. Legacy HTTP evidence is accepted
only when its final failure, response and complete body identify the same file.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from urllib.parse import unquote, urlsplit

from .core.classify import classify_input
from .core.download import is_package_prefix
from .core.errors import FxfetchError
from .core.web_evidence_io import check_ancestors

VALIDATION_FAILURES = frozenset({'archive_invalid', 'archive_unsupported', 'archive_limit', 'archive_ambiguous'})
_SHA256 = re.compile(r'[0-9a-f]{64}')
MAX_REJECTED_FILES = 8


def validation_record(reason: str, url: str, content_type: str = '') -> dict[str, str] | None:
    if reason not in VALIDATION_FAILURES or not isinstance(url, str) or not isinstance(content_type, str):
        return None
    try:
        kind = {'direct_apk': 'apk', 'direct_ipa': 'ipa'}.get(classify_input(url).kind)
    except FxfetchError:
        return None
    if kind is None:
        kind = {'application/vnd.android.package-archive': 'apk', 'application/x-itunes-ipa': 'ipa'}.get(
            content_type.partition(';')[0].strip().lower())
    return {'status': 'failed', 'reason_code': reason, 'kind': kind} if kind else None


@dataclass(frozen=True)
class RejectedFile:
    path: Path
    metadata: dict


def _path(folder: Path, value: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        raise ValueError('absolute_evidence_path_required')
    candidate.relative_to(folder.absolute())
    check_ancestors(candidate)
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(folder.resolve(strict=True))
    info = candidate.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('regular_single_link_file_required')
    return candidate


def _legacy_http(body: dict, result: dict, reason: str) -> dict[str, str] | None:
    if body.get('mode') != 'http' or body.get('hash_scope') != 'wire' or str(body.get('path', '')).endswith('.partial'):
        return None
    attempts = result.get('attempts', [])
    if not isinstance(attempts, list) or not attempts or not isinstance(attempts[-1], dict):
        return None
    failure = attempts[-1]
    if any(failure.get(key) != expected for key, expected in {
        'outcome': 'failed', 'reason_code': reason, 'url': body.get('url'), 'chain': body.get('chain'),
    }.items()):
        return None
    hops = result.get('hops', [])
    if not isinstance(hops, list) or not any(
        isinstance(hop, dict) and hop.get('url') == body.get('url')
        and hop.get('chain') == body.get('chain') and hop.get('request_id') == body.get('request_id')
        and type(hop.get('status')) is int and 200 <= hop['status'] < 300
        for hop in hops
    ):
        return None
    return validation_record(reason, body.get('url', ''))


def rejected_files(job: dict, folder: Path, maximum_bytes: int) -> list[RejectedFile]:
    result = job.get('result') or {}
    if not isinstance(result, dict):
        return []
    if (
        job.get('state') != 'completed' or job.get('outcome') != 'failed'
        or result.get('outcome') != 'failed' or result.get('reason_code') not in VALIDATION_FAILURES
        or job.get('reason_code') != result.get('reason_code')
        or result.get('artifacts')
    ):
        return []
    reason = result['reason_code']
    bodies = result.get('bodies', [])
    if not isinstance(bodies, list):
        return []
    found: dict[str, RejectedFile] = {}
    for body in bodies[:1000]:
        if not isinstance(body, dict) or body.get('complete') is not True:
            continue
        size, digest = body.get('size'), body.get('sha256')
        if type(size) is not int or not 4 <= size <= maximum_bytes or not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            continue
        validation = body.get('validation')
        if isinstance(validation, dict):
            expected = validation_record(reason, body.get('url', ''), body.get('content_type', ''))
            if (
                validation != expected or expected is None
                or type(body.get('status_code')) is not int or not 200 <= body['status_code'] < 300
                or body.get('hash_scope') not in {'wire', 'decoded_browser_response'}
            ):
                continue
        else:
            validation = _legacy_http(body, result, reason)
        if not validation:
            continue
        try:
            path = _path(folder, body['path'])
            if path.stat().st_size != size:
                continue
            with path.open('rb') as stream:
                if not is_package_prefix(stream.read(4)):
                    continue
            relative = path.relative_to(folder.absolute()).as_posix()
            identifier = hashlib.sha256((job['id'] + '\0' + relative + '\0' + digest).encode()).hexdigest()[:32]
            basename = unquote(urlsplit(body.get('url', '')).path.rsplit('/', 1)[-1])
            stem = re.sub(r'[^A-Za-z0-9._-]', '_', basename.rsplit('.', 1)[0]).strip('._')[:80]
            if re.fullmatch(r'CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]', stem.split('.')[0], re.I):
                stem = '_' + stem
            filename = f"{stem or 'download-' + identifier[:12]}.{validation['kind']}"
            found.setdefault(identifier, RejectedFile(path, {
                'id': identifier, 'filename': filename, 'kind': validation['kind'], 'size': size,
                'sha256': digest, 'validation_status': 'failed', 'reason_code': reason,
            }))
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if len(found) >= MAX_REJECTED_FILES:
            break
    return list(found.values())


def open_rejected_file(job: dict, folder: Path, identifier: str, maximum_bytes: int) -> tuple[BinaryIO, dict]:
    stream: BinaryIO | None = None
    try:
        item = next((item for item in rejected_files(job, folder, maximum_bytes)
                     if item.metadata['id'] == identifier), None)
        if item is None:
            raise ValueError('unknown_file')
        path = _path(folder, str(item.path))
        before = path.stat()
        stream = path.open('rb')
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size) != (opened.st_dev, opened.st_ino, opened.st_size):
            raise ValueError('file_changed')
        _path(folder, str(path))
        digest = hashlib.sha256()
        remaining = item.metadata['size']
        while remaining:
            block = stream.read(min(65536, remaining))
            if not block:
                raise ValueError('file_truncated')
            digest.update(block)
            remaining -= len(block)
        after = os.fstat(stream.fileno())
        if (
            stream.read(1) or digest.hexdigest() != item.metadata['sha256']
            or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
        ):
            raise ValueError('file_changed')
        stream.seek(0)
        return stream, item.metadata
    except (OSError, ValueError, TypeError):
        if stream is not None:
            stream.close()
        raise FxfetchError('not_found', 'Rejected package bytes are unavailable') from None
