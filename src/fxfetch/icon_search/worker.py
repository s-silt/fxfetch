"""Disposable image/HTTP worker; parent enforces total wall time and memory."""

from __future__ import annotations

import hashlib
import io
import json
import re
import sys
import time
import warnings
from pathlib import Path

from ..core.errors import FxfetchError
from ..core.qr import IMAGE_FORMATS
from .providers import Provider, candidates, fail, load_config, normalize_name


def publish(path: Path, value: dict) -> None:
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding='utf-8')
    # Windows readers briefly prevent replacement; keep a bounded retry budget.
    for attempt in range(5):
        try:
            temporary.replace(path)
            break
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.02)


def image_bytes(image) -> bytes:
    image = image.copy()
    image.thumbnail((1280, 1280))
    for quality in (90, 80, 65, 45):
        buffer = io.BytesIO()
        image.save(buffer, 'JPEG', quality=quality)
        if buffer.tell() <= 500000:
            return buffer.getvalue()
    raise fail('icon_image_limit')


def normalize(path: Path):
    from PIL import Image, ImageOps, UnidentifiedImageError
    from pillow_heif import register_heif_opener

    register_heif_opener(thumbnails=False)
    Image.MAX_IMAGE_PIXELS = 25_000_000
    if path.stat().st_size > 10 * 1024 * 1024:
        raise fail('icon_image_limit')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(path, formats=list(IMAGE_FORMATS)) as source:
                if source.width * source.height > 25_000_000 or getattr(source, 'n_frames', 1) != 1:
                    raise fail('icon_image_limit')
                source.verify()
            with Image.open(path, formats=list(IMAGE_FORMATS)) as source:
                source.load()
                oriented = ImageOps.exif_transpose(source).convert('RGBA')
                image = Image.new('RGB', oriented.size, 'white')
                image.paste(oriented, mask=oriented.getchannel('A'))
                image.thumbnail((1280, 1280))
                return image
    except (OSError, ValueError, SyntaxError, UnidentifiedImageError,
            Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise fail('invalid_image') from None


def catalog_candidates(value: object, name: str) -> tuple[list[dict], dict]:
    """Publish bounded API identities, never URLs or extra fields from a response."""
    if not isinstance(value, dict):
        raise fail('koodous_response_invalid')
    rows, count = value.get('records'), value.get('count')
    next_page, complete = value.get('next_page_available'), value.get('coverage_complete')
    rejected = value.get('rejected_records', 0)
    page_returned = value.get('page_returned', len(rows) if isinstance(rows, list) else 0)
    truncated = value.get('truncated', False)
    if (not isinstance(rows, list) or len(rows) > 20
            or type(page_returned) is not int or page_returned < len(rows)
            or count is not None and (type(count) is not int or count < page_returned)
            or type(next_page) is not bool or type(complete) is not bool
            or type(rejected) is not int or rejected < 0
            or type(truncated) is not bool):
        raise fail('koodous_response_invalid')
    found: dict[str, dict] = {}
    for row in rows:
        sha = row.get('sha256') if isinstance(row, dict) else None
        if not isinstance(sha, str) or re.fullmatch(r'[0-9a-fA-F]{64}', sha) is None:
            rejected += 1
            continue
        sha = sha.lower()
        if sha in found:
            rejected += 1
            continue
        identity = {}
        for key, maximum in (('app_name', 100), ('package_name', 300), ('version', 100)):
            raw = row.get(key)
            identity[key] = ''.join(c for c in raw if c.isprintable())[:maximum] if isinstance(raw, str) else ''
        found[sha] = {
            'url': 'https://koodous.com/apks/' + sha,
            'title': identity['app_name'] or name, 'source': 'koodous.com',
            'evidence': ['koodous_api_record'], 'category': 'sample_record',
            'channel': 'koodous_api', 'catalog': 'Koodous', 'sha256': sha, **identity,
            'verified': False, 'downloadable': None, 'can_collect': False,
        }
    if not found and (count not in (None, 0) or page_returned or next_page
                      or not complete or rejected or truncated):
        raise fail('koodous_response_invalid')
    status = {'provider': 'Koodous', 'status': 'hit' if found else 'no_record',
              'count': count, 'returned': len(found), 'next_page_available': next_page,
              'coverage_complete': complete and not rejected and not next_page and not truncated
              and page_returned == len(found) and (count is None or count == len(found)),
              'page_returned': page_returned, 'truncated': truncated,
              'rejected_records': rejected, 'page_limit': 20}
    return list(found.values()), status


def merge_candidates(catalog: list[dict], web: list[dict]) -> list[dict]:
    """API records take precedence over web references to the same fixed URL."""
    found: dict[str, dict] = {}
    for item in [*catalog[:20], *web[:20]]:
        url = item['url']
        if url not in found:
            found[url] = dict(item)
        else:
            found[url]['evidence'] = sorted(set(found[url]['evidence'] + item.get('evidence', [])))
    return [dict(item, id=str(index + 1)) for index, item in enumerate(found.values())]


def execute(root: Path, directory: Path, provider: Provider | None = None) -> dict:
    state: dict = {'state': 'running', 'stage': 'validating', 'candidates': [],
                   'search_attempts': 0, 'candidate_requests': 0}
    started = time.monotonic()
    current_stage: str | None = None
    stage_started = started
    timing: dict = {'started_at': time.time(), 'stage_started_at': time.time(),
                    'stage_elapsed_seconds': 0.0, 'total_seconds': 0.0, 'stages': [], 'requests': []}
    state['timing'] = timing

    def stage(name: str) -> None:
        nonlocal current_stage, stage_started
        now = time.monotonic()
        if current_stage != name:
            if current_stage is not None:
                timing['stages'].append({'stage': current_stage,
                                         'elapsed_seconds': round(max(0.0, now - stage_started), 3)})
            current_stage, stage_started = name, now
            timing['stage_started_at'] = time.time()
        timing['total_seconds'] = round(max(0.0, now - started), 3)
        timing['stage_elapsed_seconds'] = round(max(0.0, now - stage_started), 3)
        state['stage'] = name
        publish(directory / 'progress.json', state)

    def call(api, name: str, *args):
        try:
            return getattr(api, name)(*args)
        finally:
            details = getattr(api, 'last_timing', None)
            if isinstance(details, dict) and details:
                fields = ('route', 'response_wait_seconds', 'body_read_seconds', 'total_seconds',
                          'http_status', 'error_code')
                timing['requests'].append({'stage': state['stage'],
                                           **{key: details[key] for key in fields if key in details}})

    try:
        stage('validating')
        request_path = directory / 'request.json'
        request = {}
        if request_path.exists():
            if request_path.stat().st_size > 16384:
                raise fail('icon_processing_failed')
            request = json.loads(request_path.read_text(encoding='utf-8'))
        mode = request.get('mode', 'image')
        if mode not in ('image', 'recognize', 'name'):
            raise fail('icon_processing_failed')
        state['mode'] = mode
        if mode == 'name':
            name = normalize_name(request.get('name'))
            state['query_name'] = name
            for key in ('recognition_id', 'recognition', 'input_sha256', 'icon_sha256'):
                if request.get(key) is not None:
                    state[key] = request[key]
            state['library_queries'] = [
                {'provider': 'Koodous', 'query': f'app: "{name}"', 'url': 'https://koodous.com/',
                 'queried': False, 'access': 'account_permissions_required'},
                {'provider': 'VirusTotal', 'query': f'type:apk androguard:"{name}"',
                 'url': 'https://www.virustotal.com/gui/home/search',
                 'queried': False, 'access': 'account_permissions_required'},
            ]
            api = provider or Provider(load_config(root, require_vision=False, allow_catalog=True))
            has_catalog = getattr(api, 'catalog_enabled', False) is True
            has_web = getattr(api, 'web_enabled', True) is True
            catalog: list[dict] = []
            source_errors: list[dict] = []

            def source_error(error: FxfetchError) -> dict:
                detail = {'stage': state['stage'], 'code': error.code}
                status = getattr(error, 'http_status', None)
                if type(status) is int and 100 <= status <= 599:
                    detail['http_status'] = status
                source_errors.append(detail)
                return detail

            if has_catalog:
                state['library_queries'][0].update(queried=True, access='configured_api')
                state['search_attempts'] += 1
                stage('catalog_search')
                try:
                    catalog, status = catalog_candidates(call(api, 'search_catalog', name), name)
                    state['catalog_status'] = status
                    state['candidates'] = merge_candidates(catalog, [])
                except FxfetchError as error:
                    detail = source_error(error)
                    state['catalog_status'] = {
                        'provider': 'Koodous', 'status': 'failed', 'count': None, 'returned': 0,
                        'next_page_available': None, 'coverage_complete': False,
                        'error_code': error.code,
                        **({'http_status': detail['http_status']} if 'http_status' in detail else {}),
                    }
            else:
                state['catalog_status'] = {'provider': 'Koodous', 'status': 'unconfigured',
                                           'count': None, 'returned': 0, 'coverage_complete': False}
            if not has_catalog and not has_web:
                raise fail('icon_search_unconfigured')
            if has_web:
                try:
                    stage('quota')
                    state['quota_before'] = call(api, 'quota', 1) if has_catalog else call(api, 'quota')
                    responses = []
                    for scope in (('download_page',) if has_catalog else ('sample_index', 'download_page')):
                        state['search_attempts'] += 1
                        state['query_scope'] = scope
                        stage('searching')
                        response = call(api, 'search_name', name, scope)
                        # The channel is our fixed query plan, never a provider-supplied claim.
                        response['_channel'] = 'sample_index' if scope == 'sample_index' else 'targeted_download'
                        responses.append(response)
                        state['candidates'] = merge_candidates(catalog, candidates(responses, name))
                        stage('searching')
                except FxfetchError as error:
                    source_error(error)
            if source_errors:
                detail = source_errors[-1]
                state.update(state='partial' if state['candidates'] else 'failed', error=detail['code'],
                             error_detail=detail, source_errors=source_errors)
            else:
                state.update(state='completed', result='candidates' if state['candidates'] else 'no_match')
        else:
            image = normalize(directory / 'input.image')
            clean = image_bytes(image)
            (directory / 'preview.jpg').write_bytes(clean)
            state['input_sha256'] = hashlib.sha256((directory / 'input.image').read_bytes()).hexdigest()
            api = provider or Provider(load_config(root, require_search=mode != 'recognize'))
            if mode == 'image':
                stage('quota')
                state['quota_before'] = call(api, 'quota')
            stage('recognizing')
            recognition = call(api, 'recognize', clean)
            state['recognition'] = recognition
            if recognition['ambiguous']:
                raise fail('icon_ambiguous')
            box = recognition.get('icon_box')
            width, height = image.size
            pixel_box = None
            if (isinstance(box, (tuple, list)) and len(box) == 4
                    and all(type(v) is int and 0 <= v <= 1000 for v in box)):
                left, top, right, bottom = (box[0] * width // 1000, box[1] * height // 1000,
                                            box[2] * width // 1000, box[3] * height // 1000)
                if left < right and top < bottom:
                    pixel_box = (left, top, right, bottom)
            crop_applied = pixel_box is not None and pixel_box != (0, 0, width, height)
            if mode == 'image' and not crop_applied:
                raise fail('icon_recognition_invalid')
            if pixel_box is not None:
                image = image.crop(pixel_box)
            icon = image_bytes(image)
            (directory / 'icon.jpg').write_bytes(icon)
            state['icon_sha256'] = hashlib.sha256(icon).hexdigest()
            state['crop_applied'] = crop_applied
            if mode == 'recognize':
                if not recognition['name']:
                    raise fail('icon_name_not_visible')
                state.update(state='completed', result='recognized')
            else:
                stage('uploading')
                image_id = call(api, 'upload', icon)
                responses = []
                name = recognition['name'] if recognition['confidence'] != 'low' else ''
                for query in (['', name] if name else ['']):
                    state['search_attempts'] += 1
                    stage('searching')
                    responses.append(call(api, 'search', image_id, query))
                    state['candidates'] = candidates(responses, name)
                    stage('searching')
                state.update(state='completed', result='candidates' if state['candidates'] else 'no_match')
    except FxfetchError as exc:
        detail = {'stage': state['stage'], 'code': exc.code}
        status = getattr(exc, 'http_status', None)
        if isinstance(status, int) and 100 <= status <= 599:
            detail['http_status'] = status
        state.update(state='partial' if state['candidates'] else 'failed', error=exc.code, error_detail=detail)
    except Exception as exc:
        # Worker boundary: no provider exception bodies or credentials enter logs/results.
        state.update(state='partial' if state['candidates'] else 'failed',
                     error='icon_processing_failed', error_type=type(exc).__name__,
                     error_detail={'stage': state['stage'], 'code': 'icon_processing_failed'})
    stage('completed' if state['state'] == 'completed' else 'finished')
    return state


if __name__ == '__main__':
    execute(Path(sys.argv[1]), Path(sys.argv[2]))
