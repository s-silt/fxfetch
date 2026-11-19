"""Single-slot search lifecycle, owner isolation, idempotency and seven-day expiry."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import sqlite3
import sys
import threading
import time
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from ..core.errors import FxfetchError
from ..core.process_limits import run_limited
from ..retention import SECONDS, _safe_tree
from ..security import contained_path
from .bazaar import malwarebazaar_configured
from .malshare import malshare_configured
from .providers import candidate_url, fail, load_config, normalize_name

log = logging.getLogger(__name__)
SEARCH_STAGES = ('validating', 'quota', 'recognizing', 'uploading', 'searching', 'catalog_search')


def saved_candidates(result: dict) -> list[dict]:
    rows = result.get('candidates')
    if not isinstance(rows, list) or len(rows) > 40:
        return []
    valid = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        identifier, evidence = row.get('id'), row.get('evidence')
        url = candidate_url(row.get('url'))
        if (isinstance(identifier, str) and re.fullmatch(r'(?:[1-9]|[1-3][0-9]|40)', identifier)
                and url is not None
                and isinstance(row.get('title'), str) and len(row['title']) <= 300
                and row.get('source') == urlsplit(url).hostname
                and isinstance(evidence, list) and len(evidence) <= 7
                and all(item in ('name_in_title', 'android_text', 'provider_exact_match', 'name_web_search',
                                     'sample_index_search', 'targeted_download_search', 'koodous_api_record')
                        for item in evidence)
                and row.get('verified') is False and row.get('downloadable') is None):
            if identifier in seen:
                return []
            seen.add(identifier)
            safe = {key: row.get(key) for key in
                    ('id', 'url', 'title', 'source', 'evidence', 'verified', 'downloadable')}
            category = row.get('category')
            parsed = urlsplit(url)
            host, path = (parsed.hostname or '').lower(), parsed.path
            if category != 'sample_record' and (
                    host in ('koodous.com', 'www.koodous.com') and path.startswith('/apks')
                    or host in ('virustotal.com', 'www.virustotal.com') and path.startswith('/gui/file/')
                    or host == 'bazaar.abuse.ch' and path.startswith('/sample/')):
                category = 'sample_index'
            if category in ('sample_index', 'download_page', 'web_candidate'):
                safe.update(category=category, can_collect=category != 'sample_index')
                if row.get('channel') in ('sample_index', 'targeted_download'):
                    safe['channel'] = row['channel']
            elif category == 'sample_record':
                sha = row.get('sha256')
                if (not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{64}', sha)
                        or url != 'https://koodous.com/apks/' + sha
                        or row.get('channel') != 'koodous_api'):
                    continue
                safe.update(category='sample_record', channel='koodous_api',
                            catalog='Koodous', can_collect=False, sha256=sha)
                for key in ('app_name', 'package_name', 'version'):
                    if isinstance(row.get(key), str) and len(row[key]) <= 300:
                        safe[key] = row[key]
            valid.append(safe)
    return valid


class IconSearchService:
    def __init__(self, root: Path):
        self.root = root
        self.directory = root / 'icon-searches'
        self.directory.mkdir(exist_ok=True)
        self.lock = threading.RLock()
        self.active: dict[str, threading.Event] = {}
        self.retained: Counter[str] = Counter()
        self.threads: list[threading.Thread] = []
        self.stop = threading.Event()
        with self.db() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS searches (
                id TEXT PRIMARY KEY, owner TEXT NOT NULL, idem TEXT NOT NULL, digest TEXT NOT NULL,
                created REAL NOT NULL, finished REAL, state TEXT NOT NULL, hidden INTEGER DEFAULT 0,
                result TEXT NOT NULL, UNIQUE(owner,idem))''')
            if 'evidence_digest' not in {row[1] for row in db.execute('PRAGMA table_info(searches)')}:
                db.execute('ALTER TABLE searches ADD COLUMN evidence_digest TEXT')

    @contextmanager
    def db(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.root / 'icon-search.sqlite3', timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def capability(self) -> dict:
        result: dict = {'enabled': False, 'recognition_enabled': False, 'name_enabled': False,
                        'max_searches': 2, 'timeout_seconds': 180, 'retention_days': 7,
                        'daily_shared_tasks': 20, 'malshare_enabled': malshare_configured(self.root),
                        'malwarebazaar_enabled': malwarebazaar_configured(self.root)}
        for mode in ('recognize', 'name'):
            try:
                config = load_config(self.root, require_vision=mode == 'recognize',
                                     require_search=mode == 'name', allow_catalog=mode == 'name')
                result['recognition_enabled' if mode == 'recognize' else 'name_enabled'] = True
                if mode == 'recognize':
                    result['model'] = config['vision_model']
                else:
                    result['catalog_enabled'] = bool(config.get('koodous_key'))
                    result['web_enabled'] = bool(config.get('serpapi_key'))
            except FxfetchError:
                pass
        result['enabled'] = result['recognition_enabled'] and result['name_enabled']
        if not result['enabled']:
            result['reason_code'] = 'icon_search_unconfigured'
        return result

    def start(self) -> None:
        with self.lock, self.db() as db:
            rows = db.execute("SELECT id, digest FROM searches WHERE state='running'").fetchall()
            finished = time.time()
            for row in rows:
                result = self.interrupted_result(row['id'], row['digest'])
                db.execute("UPDATE searches SET state=?,finished=?,result=? WHERE id=?",
                           (result['state'], finished, json.dumps(result, ensure_ascii=False), row['id']))
        thread = threading.Thread(target=self.maintenance, daemon=True, name='icon-maintenance')
        self.threads.append(thread)
        thread.start()

    def close(self) -> None:
        with self.lock:
            self.stop.set()
            for event in self.active.values():
                event.set()
        for thread in self.threads:
            thread.join(timeout=15)

    def submit(self, owner: str, idem: str, data: bytes) -> dict:
        return self._submit(owner, idem, 'image', data=data)

    def submit_recognition(self, owner: str, idem: str, data: bytes) -> dict:
        return self._submit(owner, idem, 'recognize', data=data)

    def submit_name(self, owner: str, idem: str, name: str,
                    recognition_id: str | None = None) -> dict:
        return self._submit(owner, idem, 'name', name=normalize_name(name),
                            recognition_id=recognition_id)

    def _submit(self, owner: str, idem: str, mode: str, *, data: bytes = b'',
                name: str = '', recognition_id: str | None = None) -> dict:
        import secrets

        request: dict = {'mode': mode}
        if mode == 'name':
            request.update(name=name, recognition_id=recognition_id)
            payload = json.dumps(request, ensure_ascii=False, sort_keys=True).encode('utf-8')
        else:
            if not data or len(data) > 10 * 1024 * 1024:
                raise fail('icon_image_limit')
            payload = data
        digest = hashlib.sha256(payload if mode == 'image' else mode.encode() + b'\0' + payload).hexdigest()
        with self.lock, self.db() as db:
            row = db.execute('SELECT * FROM searches WHERE owner=? AND idem=?', (owner, idem)).fetchone()
            if row:
                if row['digest'] != digest or row['hidden']:
                    raise fail('idempotency_conflict')
                return self.get(owner, row['id'])
            load_config(self.root, require_vision=mode != 'name', require_search=mode != 'recognize',
                        allow_catalog=mode == 'name')
            source_files: dict[str, bytes] = {}
            if recognition_id is not None:
                source = self.get(owner, recognition_id)
                if (source.get('mode') != 'recognize' or source.get('state') != 'completed'
                        or source.get('result') != 'recognized'):
                    raise fail('recognition_unavailable')
                try:
                    for filename, maximum in (('input.image', 10 * 1024 * 1024),
                                              ('icon.jpg', 500000), ('preview.jpg', 500000)):
                        source_files[filename] = self.read_evidence_file(recognition_id, filename, maximum)
                    for filename, key in (('input.image', 'input_sha256'), ('icon.jpg', 'icon_sha256')):
                        if hashlib.sha256(source_files[filename]).hexdigest() != source.get(key):
                            raise ValueError
                except (FxfetchError, OSError, ValueError):
                    raise fail('recognition_unavailable') from None
                request.update(recognition=source.get('recognition'), input_sha256=source['input_sha256'],
                               icon_sha256=source['icon_sha256'])
            if self.active or self.stop.is_set():
                raise fail('icon_search_busy')
            if db.execute('SELECT COUNT(*) FROM searches WHERE created>?',
                          (time.time() - 86400,)).fetchone()[0] >= 20:
                raise fail('icon_daily_limit')
            identifier = secrets.token_hex(16)
            directory = self.directory / identifier
            directory.mkdir()
            if mode != 'name':
                (directory / 'input.image').write_bytes(data)
            for filename, content in source_files.items():
                (directory / filename).write_bytes(content)
            request_bytes = json.dumps(request, ensure_ascii=False).encode('utf-8')
            (directory / 'request.json').write_bytes(request_bytes)
            result = {'state': 'running', 'stage': 'validating', 'mode': mode, 'candidates': []}
            if mode == 'name':
                result['query_name'] = name
            db.execute('INSERT INTO searches(id,owner,idem,digest,created,state,result,evidence_digest) '
                       'VALUES(?,?,?,?,?,?,?,?)',
                       (identifier, owner, idem, digest, time.time(), 'running', json.dumps(result),
                        hashlib.sha256(request_bytes).hexdigest()))
            db.commit()
            event = threading.Event()
            self.active[identifier] = event
            thread = threading.Thread(target=self.run, args=(identifier, event), daemon=True,
                                      name='icon-search')
            self.threads = [t for t in self.threads if t.is_alive()]
            self.threads.append(thread)
            thread.start()
            return self.get(owner, identifier)

    def run(self, identifier: str, event: threading.Event) -> None:
        result: dict = {'state': 'failed', 'error': 'icon_processing_failed', 'candidates': []}
        started = time.monotonic()
        try:
            process = run_limited([sys.executable, '-m', 'fxfetch.icon_search.worker', str(self.root),
                                   str(self.directory / identifier)], timeout=180,
                                  memory_bytes=768 * 1024 * 1024, cancel=event, max_output_bytes=16384)
            result = self.progress(identifier) or result
            if process.cancelled or event.is_set():
                result.update(state='cancelled', error='cancelled')
            elif process.timed_out:
                result.update(state='partial' if result.get('candidates') else 'failed', error='icon_timeout')
            elif process.returncode != 0 or result.get('state') == 'running':
                result.update(state='failed', error='icon_processing_failed')
            if result.get('stage') not in ('completed', 'finished') and result.get('error'):
                failed_stage = result.get('stage', 'validating')
                timing = result.get('timing')
                if isinstance(timing, dict):
                    total = max(0.0, time.monotonic() - started)
                    elapsed = timing.get('stage_elapsed_seconds', 0) + max(
                        0.0, total - timing.get('total_seconds', 0))
                    timing.setdefault('stages', []).append({'stage': failed_stage,
                                                           'elapsed_seconds': round(elapsed, 3)})
                    timing.update(total_seconds=round(total, 3), stage_elapsed_seconds=0.0,
                                  stage_started_at=time.time())
                result.update(stage='finished', error_detail={'stage': failed_stage, 'code': result['error']})
        except Exception as exc:
            log.error('icon_worker_failed exception_type=%s', type(exc).__name__)
        finally:
            with self.lock, self.db() as db:
                db.execute('UPDATE searches SET state=?,finished=?,result=? WHERE id=?',
                           (result['state'], time.time(), json.dumps(result, ensure_ascii=False), identifier))
                self.active.pop(identifier, None)

    def read_evidence_file(self, identifier: str, name: str, limit: int) -> bytes:
        path = contained_path(self.root, f'icon-searches/{identifier}/{name}')
        with path.open('rb') as stream:
            data = stream.read(limit + 1)
        if not data or len(data) > limit:
            raise ValueError('invalid_icon_evidence_size')
        return data

    def progress(self, identifier: str) -> dict | None:
        if not re.fullmatch(r'[0-9a-f]{32}', identifier):
            return None
        try:
            value = json.loads(self.read_evidence_file(identifier, 'progress.json', 512 * 1024))
            if not isinstance(value, dict):
                return None
            # Worker snapshots are JSON objects. Reject non-finite numbers before persisting or serving them.
            json.dumps(value, ensure_ascii=False, allow_nan=False).encode('utf-8')
            return value
        except (FxfetchError, OSError, ValueError, RecursionError):
            return None

    def evidence_files(self, identifier: str, result: dict) -> tuple[bytes, bytes]:
        try:
            original = self.read_evidence_file(identifier, 'input.image', 10 * 1024 * 1024)
            icon = self.read_evidence_file(identifier, 'icon.jpg', 500_000)
        except (FxfetchError, OSError, ValueError):
            raise fail('invalid_selection') from None
        if ((result.get('mode', 'image') == 'image' and result.get('crop_applied') is not True)
                or hashlib.sha256(original).hexdigest() != result.get('input_sha256')
                or hashlib.sha256(icon).hexdigest() != result.get('icon_sha256')):
            raise fail('invalid_selection')
        return original, icon

    def validate_evidence(self, identifier: str, result: dict, digest: str | None = None) -> None:
        """Bind retained results to the submitted request and original image, when present."""
        mode = result.get('mode', 'image')
        try:
            if digest is None:
                with self.db() as db:
                    row = db.execute('SELECT digest FROM searches WHERE id=?', (identifier,)).fetchone()
                if row is None:
                    raise ValueError('missing_request')
                digest = row['digest']
            if mode == 'name':
                request_bytes = self.read_evidence_file(identifier, 'request.json', 16_384)
                with self.db() as db:
                    evidence_row = db.execute('SELECT evidence_digest FROM searches WHERE id=?',
                                              (identifier,)).fetchone()
                if (evidence_row is None or hashlib.sha256(request_bytes).hexdigest()
                        != evidence_row['evidence_digest']):
                    raise ValueError('invalid_request_evidence')
                request = json.loads(request_bytes)
                name = normalize_name(request['name'])
                recognition_id = request.get('recognition_id')
                if (request.get('mode') != 'name' or name != result.get('query_name')
                        or recognition_id != result.get('recognition_id')
                        or recognition_id is not None and (not isinstance(recognition_id, str)
                            or not re.fullmatch(r'[0-9a-f]{32}', recognition_id))):
                    raise ValueError('invalid_name_evidence')
                payload = json.dumps({'mode': 'name', 'name': name, 'recognition_id': recognition_id},
                                     ensure_ascii=False, sort_keys=True).encode('utf-8')
                actual_digest = hashlib.sha256(b'name\0' + payload).hexdigest()
                if recognition_id is not None:
                    self.evidence_files(identifier, result)
                    if any(request.get(key) != result.get(key) for key in
                           ('input_sha256', 'icon_sha256', 'recognition')):
                        raise ValueError('invalid_image_evidence')
            elif mode in ('image', 'recognize'):
                original, _ = self.evidence_files(identifier, result)
                actual_digest = hashlib.sha256(original if mode == 'image' else b'recognize\0' + original).hexdigest()
            else:
                raise ValueError('invalid_evidence_mode')
            if digest is not None and actual_digest != digest:
                raise ValueError('invalid_request_digest')
        except (FxfetchError, OSError, ValueError, TypeError, KeyError):
            raise fail('invalid_selection') from None

    def interrupted_result(self, identifier: str, digest: str) -> dict:
        snapshot = self.progress(identifier) or {}
        result = {key: snapshot[key] for key in
                  ('input_sha256', 'icon_sha256', 'crop_applied', 'quota_before', 'search_attempts',
                   'candidate_requests', 'recognition', 'timing') if key in snapshot}
        recognition = result.get('recognition')
        if (not isinstance(recognition, dict) or not isinstance(recognition.get('name'), str)
                or type(recognition.get('ambiguous')) is not bool
                or recognition.get('confidence') not in ('high', 'medium', 'low')):
            result.pop('recognition', None)
        for key in ('mode', 'query_name', 'recognition_id', 'catalog_status'):
            if key in snapshot:
                result[key] = snapshot[key]
        recovered = saved_candidates(snapshot)
        if recovered:
            try:
                self.validate_evidence(identifier, result, digest)
            except FxfetchError:
                recovered = []
        stage = snapshot.get('stage')
        if stage not in SEARCH_STAGES:
            detail = snapshot.get('error_detail')
            stage = detail.get('stage') if isinstance(detail, dict) else None
        if stage not in SEARCH_STAGES:
            stage = 'searching' if recovered else 'validating'
        timing = result.get('timing')
        if (not isinstance(timing, dict)
                or not all(type(timing.get(key)) in (float, int) and timing[key] >= 0 for key in
                           ('started_at', 'stage_started_at', 'total_seconds', 'stage_elapsed_seconds'))
                or not all(isinstance(timing.get(key), list) and all(isinstance(row, dict) for row in timing[key])
                           for key in ('stages', 'requests'))):
            result.pop('timing', None)
        elif snapshot.get('stage') == stage:
            # The last durable elapsed time is known. Downtime is not search time.
            timing['stages'].append({'stage': stage, 'elapsed_seconds': timing['stage_elapsed_seconds']})
            timing.update(stage_elapsed_seconds=0.0, stage_started_at=time.time())
        return {**result, 'state': 'partial' if recovered else 'failed', 'stage': 'finished',
                'error': 'icon_interrupted', 'error_detail': {'stage': stage, 'code': 'icon_interrupted'},
                'candidates': recovered}

    def get(self, owner: str, identifier: str) -> dict:
        if not re.fullmatch(r'[0-9a-f]{32}', identifier):
            raise fail('not_found')
        with self.lock, self.db() as db:
            row = db.execute('SELECT * FROM searches WHERE owner=? AND id=? AND hidden=0',
                             (owner, identifier)).fetchone()
            if row is None:
                raise fail('not_found')
            value = (self.progress(identifier) if row['state'] == 'running' else None) or json.loads(row['result'])
            return {**value, 'id': identifier, 'state': row['state'], 'created_at': row['created'],
                    'finished_at': row['finished'],
                    'expires_at': row['finished'] + SECONDS if row['finished'] else None}

    def cancel(self, owner: str, identifier: str) -> dict:
        with self.lock:
            self.get(owner, identifier)
            if identifier in self.active:
                self.active[identifier].set()
            return {'cancel_requested': identifier in self.active}

    def clear(self, owner: str) -> None:
        with self.lock, self.db() as db:
            for row in db.execute('SELECT id FROM searches WHERE owner=?', (owner,)):
                if row['id'] in self.active:
                    self.active[row['id']].set()
            db.execute('UPDATE searches SET hidden=1 WHERE owner=?', (owner,))

    def cleanup(self, now: float | None = None) -> int:
        count = 0
        with self.lock, self.db() as db:
            rows = db.execute('SELECT id FROM searches WHERE finished IS NOT NULL AND finished<=?',
                              ((time.time() if now is None else now) - SECONDS,)).fetchall()
            for row in rows:
                identifier = row['id']
                if identifier in self.active or self.retained[identifier] or not re.fullmatch(r'[0-9a-f]{32}', identifier):
                    continue
                path = _safe_tree(self.root, 'icon-searches/' + identifier)
                if path.exists():
                    shutil.rmtree(path)
                db.execute('DELETE FROM searches WHERE id=?', (identifier,))
                count += 1
        return count

    def maintenance(self) -> None:
        while not self.stop.wait(30):
            try:
                self.cleanup()
            except (OSError, ValueError, sqlite3.Error) as exc:
                log.error('icon_cleanup_failed exception_type=%s', type(exc).__name__)
