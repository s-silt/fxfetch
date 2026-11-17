"""Disposable image/HTTP worker; parent enforces total wall time and memory."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import time
import warnings
from pathlib import Path

from ..core.errors import FxfetchError
from ..core.qr import IMAGE_FORMATS
from .providers import Provider, candidates, fail, load_config


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
        image = normalize(directory / 'input.image')
        clean = image_bytes(image)
        (directory / 'preview.jpg').write_bytes(clean)
        state['input_sha256'] = hashlib.sha256((directory / 'input.image').read_bytes()).hexdigest()
        api = provider or Provider(load_config(root))
        stage('quota')
        state['quota_before'] = call(api, 'quota')
        stage('recognizing')
        recognition = call(api, 'recognize', clean)
        state['recognition'] = recognition
        if recognition['ambiguous']:
            raise fail('icon_ambiguous')
        box = recognition['icon_box']
        if box is None:
            raise fail('icon_recognition_invalid')
        width, height = image.size
        left, top, right, bottom = (box[0] * width // 1000, box[1] * height // 1000,
                                    box[2] * width // 1000, box[3] * height // 1000)
        if left >= right or top >= bottom or (left, top, right, bottom) == (0, 0, width, height):
            raise fail('icon_recognition_invalid')
        icon = image_bytes(image.crop((left, top, right, bottom)))
        (directory / 'icon.jpg').write_bytes(icon)
        state['icon_sha256'] = hashlib.sha256(icon).hexdigest()
        state['crop_applied'] = True
        stage('uploading')
        image_id = call(api, 'upload', icon)
        responses = []
        name = recognition['name'] if recognition['confidence'] != 'low' else ''
        for query in (['', name] if name else ['']):
            state['search_attempts'] += 1
            stage('searching')
            responses.append(call(api, 'search', image_id, query))
            # Persist only allowlisted candidate metadata, never provider echoes/keys/image URLs.
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
