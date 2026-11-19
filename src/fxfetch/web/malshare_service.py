"""Owner-scoped receipts and retained APKs for explicit sample-provider actions."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import stat
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import BinaryIO

from starlette.concurrency import run_in_threadpool
from starlette.responses import Response, StreamingResponse
from starlette.types import Receive, Scope, Send

from ..core.errors import FxfetchError
from ..core.limits import Limits
from ..core.process_limits import run_limited
from ..icon_search.bazaar import malwarebazaar_configured
from ..icon_search.malshare import malshare_configured
from ..icon_search.service import IconSearchService, saved_candidates
from ..retention import _safe_tree
from ..security import contained_path
from .malshare_worker import SampleProvider

LIMITS = Limits()
DAILY_ACTIONS = 2000
log = logging.getLogger(__name__)
PROVIDER_ERRORS = {
    provider: {provider.error(code) for code in (
        'unconfigured', 'invalid_hash', 'auth', 'forbidden', 'quota', 'http', 'no_record',
        'response_invalid', 'size_limit', 'incomplete', 'timeout', 'connection', 'tls',
        'storage', 'hash_mismatch', 'invalid_apk',
    )} for provider in SampleProvider
}
PROVIDER_ERRORS[SampleProvider.MALWAREBAZAAR].add('bazaar_invalid_archive')


def _record_candidates(result: dict) -> dict[str, str]:
    catalog = result.get('catalog_status')
    if (result.get('mode') != 'name' or result['state'] not in ('completed', 'partial')
            or not isinstance(catalog, dict) or catalog.get('provider') != 'Koodous'
            or catalog.get('status') != 'hit'):
        return {}
    return {row['id']: row['sha256'] for row in saved_candidates(result)
            if row.get('category') == 'sample_record' and 'koodous_api_record' in row['evidence']}


def _directory(identifier: str, operation: int, provider: SampleProvider) -> str:
    if not re.fullmatch(r'[0-9a-f]{32}', identifier) or type(operation) is not int or operation <= 0:
        raise FxfetchError('unsafe_path', 'Invalid sample storage identity')
    return f'icon-searches/{identifier}/{provider.value}-{operation}'


class SampleService:
    def __init__(self, searches: IconSearchService):
        self.searches = searches
        self.readers = 0
        self.operation: tuple[str, threading.Event] | None = None
        self.closing = False
        with searches.db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('''CREATE TABLE IF NOT EXISTS malshare_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT, search_id TEXT NOT NULL, candidate TEXT NOT NULL,
                sha TEXT NOT NULL, owner TEXT NOT NULL, idem TEXT NOT NULL, action TEXT NOT NULL,
                created REAL NOT NULL, status TEXT NOT NULL, code TEXT, http_status INTEGER,
                bytes_reserved INTEGER NOT NULL, provider TEXT NOT NULL DEFAULT 'malshare', UNIQUE(owner,idem))''')
            if 'provider' not in {row[1] for row in db.execute('PRAGMA table_info(malshare_actions)')}:
                db.execute("ALTER TABLE malshare_actions ADD COLUMN provider TEXT NOT NULL DEFAULT 'malshare'")
            db.execute('''CREATE TRIGGER IF NOT EXISTS malshare_expiry AFTER DELETE ON searches BEGIN
                DELETE FROM malshare_actions WHERE search_id=OLD.id; END''')

    def recover(self) -> None:
        """Keep interrupted attempts terminal even when their worker published bytes before exit."""
        with self.searches.lock, self.searches.db() as db:
            for provider in SampleProvider:
                db.execute("UPDATE malshare_actions SET status='failed',code=? WHERE provider=? AND status='running'",
                           (provider.error('interrupted'), provider))
                for row in db.execute("""SELECT id,search_id FROM malshare_actions
                        WHERE provider=? AND status='failed' AND bytes_reserved>0""", (provider,)):
                    if self._remove_download(row['search_id'], row['id'], provider):
                        db.execute('UPDATE malshare_actions SET bytes_reserved=0 WHERE id=?', (row['id'],))

    def _remove_download(self, identifier: str, operation: int, provider: SampleProvider) -> bool:
        try:
            directory = _safe_tree(self.searches.root, _directory(identifier, operation, provider))
            if directory.exists():
                shutil.rmtree(directory)
            return True
        except (OSError, ValueError, FxfetchError):
            # Keep the reservation when cleanup cannot establish safe ownership or remove the file.
            return False

    def _check(self, owner: str, identifier: str, candidate: str) -> str:
        result = self.searches.get(owner, identifier)
        if result['expires_at'] is not None and result['expires_at'] <= time.time():
            raise FxfetchError('not_found', 'Search has expired')
        sha = _record_candidates(result).get(candidate)
        if sha is None or result['finished_at'] is None:
            raise FxfetchError('invalid_selection', 'Choose a retained Koodous sample record')
        self.searches.validate_evidence(identifier, result)
        return sha

    @staticmethod
    def _receipts(db: sqlite3.Connection, identifier: str, candidates: dict[str, str], provider: SampleProvider) -> dict:
        result: dict = {}
        for row in db.execute('SELECT * FROM malshare_actions WHERE search_id=? AND provider=? ORDER BY id',
                              (identifier, provider)):
            candidate, sha = row['candidate'], row['sha']
            if candidates.get(candidate) != sha:
                continue
            receipt = result.setdefault(candidate, {'provider': provider.label, 'candidate_id': candidate,
                                                    'sha256': sha, 'lookup': None, 'download': None,
                                                    'file_url': None})
            summary = {'status': row['status'], 'requested_at': row['created']}
            if row['code']:
                summary['code'] = row['code']
            if row['http_status'] is not None:
                summary['http_status'] = row['http_status']
            if row['status'] == 'downloaded':
                summary['size'] = row['bytes_reserved']
                receipt['file_url'] = f'/api/icon-searches/{identifier}/candidates/{candidate}/{provider.value}/file'
            receipt[row['action']] = summary
        return result

    def result(self, owner: str, identifier: str) -> dict:
        with self.searches.lock:
            result = self.searches.get(owner, identifier)
            if result.get('mode') == 'name':
                candidates = _record_candidates(result)
                with self.searches.db() as db:
                    for provider in SampleProvider:
                        result[provider.value] = self._receipts(db, identifier, candidates, provider) if (
                            candidates and result['expires_at'] and result['expires_at'] > time.time()) else {}
            return result

    def act(self, owner: str, identifier: str, candidate: str, action: str, key: str, provider: SampleProvider) -> dict:
        with self.searches.lock, self.searches.db() as db:
            db.execute('BEGIN IMMEDIATE')
            sha = self._check(owner, identifier, candidate)
            key_digest = hashlib.sha256(key.encode('ascii')).hexdigest()
            # Historical MalShare keys are plain digests in a UNIQUE(owner,idem) index.
            if provider is not SampleProvider.MALSHARE:
                key_digest = provider.value + ':' + key_digest
            old = db.execute('SELECT * FROM malshare_actions WHERE owner=? AND idem=? AND provider=?',
                             (owner, key_digest, provider)).fetchone()
            receipt = self._receipts(db, identifier, {candidate: sha}, provider).get(candidate)
            if old:
                if not receipt or (old['search_id'], old['candidate'], old['action'], old['sha']) != (
                        identifier, candidate, action, sha):
                    raise FxfetchError('idempotency_conflict', 'This action key was already used')
                return receipt
            if receipt and receipt['file_url']:
                return receipt
            if action == 'download' and (not receipt or (receipt['lookup'] or {}).get('status') != 'hit'):
                raise FxfetchError(provider.error('lookup_required'), f'An exact {provider.label} lookup hit is required')
            if (self.closing or self.searches.stop.is_set() or self.operation is not None
                    or db.execute("SELECT 1 FROM malshare_actions WHERE status='running'").fetchone()):
                raise FxfetchError(provider.error('busy'), 'Another sample action is running or the service is stopping')
            configured = malshare_configured if provider is SampleProvider.MALSHARE else malwarebazaar_configured
            if not configured(self.searches.root):
                raise FxfetchError(provider.error('unconfigured'), f'{provider.label} is not configured')
            now = time.time()
            if db.execute('SELECT count(*) FROM malshare_actions WHERE provider=? AND created>?',
                          (provider, now - 86400)).fetchone()[0] >= DAILY_ACTIONS:
                raise FxfetchError(provider.error('daily_limit'), f'Daily {provider.label} action budget exhausted')
            reserve = LIMITS.max_package_bytes if action == 'download' else 0
            if provider is SampleProvider.MALWAREBAZAAR:
                # The encrypted transport archive coexists with the extracted APK until validation.
                reserve *= 2
            if reserve:
                held = db.execute('SELECT coalesce(sum(bytes_reserved),0) FROM malshare_actions').fetchone()[0]
                if held + reserve > LIMITS.max_task_bytes:
                    raise FxfetchError(provider.error('storage_limit'), 'Retained sample storage limit reached')
            operation = db.execute('''INSERT INTO malshare_actions
                (search_id,candidate,sha,owner,idem,action,created,status,bytes_reserved,provider)
                VALUES(?,?,?,?,?,?,?,'running',?,?)''',
                (identifier, candidate, sha, owner, key_digest, action, now, reserve, provider)).lastrowid
            assert operation is not None
            db.commit()
            self.searches.retained[identifier] += 1
            cancel = threading.Event()
            self.operation = (owner, cancel)
        try:
            try:
                outcome = self._execute(action, sha, identifier, operation, cancel, provider)
            except Exception as exc:
                # A worker/supervisor fault must finish the durable running row without replaying the action.
                log.error('%s exception_type=%s', provider.error('worker_failed'), type(exc).__name__)
                outcome = {'status': 'failed', 'code': provider.error('worker_failed')}
            with self.searches.lock, self.searches.db() as db:
                if cancel.is_set():
                    outcome = {'status': 'failed', 'code': provider.error('interrupted')}
                size = outcome.get('size', 0)
                if reserve and outcome['status'] != 'downloaded' and not self._remove_download(identifier, operation, provider):
                    size = reserve
                db.execute('UPDATE malshare_actions SET status=?,code=?,http_status=?,bytes_reserved=? WHERE id=?',
                           (outcome['status'], outcome.get('code'), outcome.get('http_status'), size, operation))
                db.commit()
                self._check(owner, identifier, candidate)
                return self._receipts(db, identifier, {candidate: sha}, provider)[candidate]
        finally:
            with self.searches.lock:
                self.operation = None
                self._release(identifier)

    def clear(self, owner: str) -> None:
        with self.searches.lock:
            self.searches.clear(owner)
            if self.operation and self.operation[0] == owner:
                self.operation[1].set()

    def close(self) -> None:
        with self.searches.lock:
            self.closing = True
            if self.operation:
                self.operation[1].set()

    def _execute(self, action: str, sha: str, identifier: str, operation: int,
                 cancel: threading.Event, provider: SampleProvider) -> dict:
        try:
            directory = _directory(identifier, operation, provider)
            destination = contained_path(self.searches.root, directory + '/sample.apk', must_exist=False)
            if action == 'download':
                destination.parent.mkdir(mode=0o700)
            process = run_limited([sys.executable, '-m', 'fxfetch.web.malshare_worker',
                                   str(self.searches.root), provider.value, action, sha, str(destination)],
                                  timeout=180, memory_bytes=768 * 1024 * 1024,
                                  cancel=cancel, max_output_bytes=4096)
            if process.timed_out:
                return {'status': 'failed', 'code': provider.error('timeout')}
            if process.cancelled:
                return {'status': 'failed', 'code': provider.error('interrupted')}
            if process.returncode == 0 and not process.output_truncated:
                value = json.loads(process.stdout)
                if isinstance(value, dict):
                    status = value.get('status')
                    if action == 'lookup' and status in ('hit', 'no_record'):
                        return {'status': status}
                    if action == 'download' and status == 'downloaded':
                        size = value.get('size')
                        path = contained_path(self.searches.root, directory + '/sample.apk')
                        if type(size) is int and 0 < size <= LIMITS.max_package_bytes and path.stat().st_size == size:
                            return {'status': status, 'size': size}
                    if status == 'failed' and isinstance(value.get('code'), str) and value['code'] in PROVIDER_ERRORS[provider]:
                        result = {'status': status, 'code': value['code']}
                        http_status = value.get('http_status')
                        if type(http_status) is int and 100 <= http_status <= 599:
                            result['http_status'] = http_status
                        return result
        except (OSError, FxfetchError):
            return {'status': 'failed', 'code': provider.error('storage')}
        except (ValueError, RecursionError):
            pass
        return {'status': 'failed', 'code': provider.error('response_invalid')}

    def _release(self, identifier: str) -> None:
        with self.searches.lock:
            self.searches.retained[identifier] -= 1
            if not self.searches.retained[identifier]:
                del self.searches.retained[identifier]

    def _invalidate_file(self, identifier: str, operation: int, code: str, provider: SampleProvider) -> None:
        with self.searches.lock, self.searches.db() as db:
            row = db.execute("SELECT bytes_reserved FROM malshare_actions WHERE id=? AND status='downloaded'",
                             (operation,)).fetchone()
            if row:
                size = 0 if self._remove_download(identifier, operation, provider) else row['bytes_reserved']
                db.execute("UPDATE malshare_actions SET status='failed',code=?,bytes_reserved=? WHERE id=?",
                           (code, size, operation))

    @contextmanager
    def open_file(self, owner: str, identifier: str, candidate: str,
                  provider: SampleProvider = SampleProvider.MALSHARE) -> Iterator[tuple[BinaryIO, str, int]]:
        with self.searches.lock, self.searches.db() as db:
            sha = self._check(owner, identifier, candidate)
            row = db.execute("""SELECT id,bytes_reserved FROM malshare_actions
                WHERE search_id=? AND candidate=? AND sha=? AND provider=? AND status='downloaded' AND action='download'""",
                (identifier, candidate, sha, provider)).fetchone()
            if not row:
                raise FxfetchError('not_found', 'No verified local sample')
            if self.readers >= 2:
                raise FxfetchError(provider.error('busy'), 'Local sample downloads are busy')
            self.readers += 1
            self.searches.retained[identifier] += 1
        try:
            relative = _directory(identifier, row['id'], provider) + '/sample.apk'
            with contained_path(self.searches.root, relative).open('rb') as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= LIMITS.max_package_bytes
                        or info.st_size != row['bytes_reserved'] or hashlib.file_digest(stream, 'sha256').hexdigest() != sha):
                    raise FxfetchError(provider.error('hash_mismatch'), 'Local sample verification failed')
                stream.seek(0)
                yield stream, sha, info.st_size
        except FxfetchError as exc:
            if exc.code in ('unsafe_path', 'artifact_missing', provider.error('hash_mismatch')):
                self._invalidate_file(identifier, row['id'], exc.code, provider)
            raise
        except FileNotFoundError:
            self._invalidate_file(identifier, row['id'], 'artifact_missing', provider)
            raise FxfetchError('not_found', 'Local sample is missing') from None
        except OSError:
            raise FxfetchError(provider.error('storage'), 'Local sample is unavailable') from None
        finally:
            with self.searches.lock:
                self.readers -= 1
                self._release(identifier)


class SampleResponse(Response):
    """Hold the checked descriptor through ASGI disconnects and streaming failures."""

    def __init__(self, service: SampleService, owner: str, identifier: str, candidate: str, provider: SampleProvider):
        super().__init__()
        self.sample = service.open_file(owner, identifier, candidate, provider)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        stream, sha, size = await run_in_threadpool(self.sample.__enter__)
        try:
            response = StreamingResponse(iter(lambda: stream.read(256 * 1024), b''), media_type='application/octet-stream',
                                         headers={'Content-Disposition': f'attachment; filename="{sha}.apk"',
                                                  'Content-Length': str(size)})
            await response(scope, receive, send)
        finally:
            self.sample.__exit__(None, None, None)
