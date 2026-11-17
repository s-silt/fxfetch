"""Explicit provider-list retrieval and atomic, shared model selection."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .core.errors import FxfetchError
from .core.process_limits import run_limited
from .icon_search.providers import Provider, ProviderRequestError, fail, load_config, model_ids

CONFIG_KEYS = ('vision_endpoint', 'vision_key', 'vision_model', 'serpapi_key')
PROVIDER_ERRORS = {'icon_search_unconfigured', 'icon_provider_auth', 'icon_provider_quota',
                   'icon_provider_failed', 'icon_provider_response_limit',
                   'icon_provider_forbidden', 'icon_provider_timeout', 'icon_provider_tls',
                   'icon_provider_proxy', 'icon_provider_connection', 'icon_provider_response_invalid',
                   'icon_provider_incomplete', 'icon_provider_http',
                   'model_list_invalid', 'model_list_limit'}


def config_fingerprint(config: dict) -> str:
    values = {key: config[key] for key in CONFIG_KEYS}
    values['vision_proxy'] = config.get('vision_proxy')
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


@dataclass
class ModelList:
    token: str
    expires: float
    fingerprint: str
    models: list[str]


class ModelSettingsService:
    def __init__(self, root: Path):
        self.root = root
        self.lock = threading.RLock()
        self.busy = False
        self.next_refresh = 0.0
        self.lists: dict[str, ModelList] = {}

    def current(self) -> dict:
        return {'current_model': load_config(self.root)['vision_model']}

    def fingerprint(self) -> str:
        return config_fingerprint(load_config(self.root))

    def fetch_models(self) -> tuple[list[str], str]:
        process = run_limited([sys.executable, '-m', 'fxfetch.model_settings', str(self.root)],
                              timeout=30, memory_bytes=256 * 1024 * 1024, max_output_bytes=256 * 1024)
        if process.timed_out:
            raise fail('icon_provider_timeout')
        if process.returncode != 0 or process.output_truncated:
            raise fail('icon_provider_failed')
        try:
            value = json.loads(process.stdout)
            if value.get('error') in PROVIDER_ERRORS:
                status = value.get('http_status')
                raise ProviderRequestError(value['error'], status if type(status) is int and 100 <= status <= 599 else None)
            fingerprint = value['fingerprint']
            if not isinstance(fingerprint, str) or not re.fullmatch(r'[0-9a-f]{64}', fingerprint):
                raise ValueError
            return model_ids(value['models']), fingerprint
        except (ValueError, KeyError, TypeError, AttributeError):
            raise fail('model_list_invalid') from None

    def refresh(self, owner: str) -> dict:
        with self.lock:
            if self.busy:
                raise fail('model_list_busy')
            now = time.monotonic()
            if now < self.next_refresh:
                raise fail('model_list_cooldown')
            fingerprint = config_fingerprint(load_config(self.root))
            self.busy = True
            self.next_refresh = now + 10
        try:
            received, fetched_fingerprint = self.fetch_models()
            models = model_ids(received)
            with self.lock:
                if fetched_fingerprint != fingerprint or self.fingerprint() != fingerprint:
                    raise fail('model_settings_changed')
                now = time.monotonic()
                self.lists = {key: value for key, value in self.lists.items() if value.expires > now}
                if owner not in self.lists and len(self.lists) >= 32:
                    del self.lists[next(iter(self.lists))]
                listing = ModelList(secrets.token_urlsafe(32), now + 600, fingerprint, models)
                self.lists[owner] = listing
                return {**self.current(), 'models': models, 'list_token': listing.token}
        finally:
            with self.lock:
                self.busy = False

    def select(self, owner: str, model: str, list_token: str) -> dict:
        with self.lock:
            listing = self.lists.get(owner)
            if (listing is None or listing.expires <= time.monotonic()
                    or not secrets.compare_digest(listing.token, list_token)):
                raise fail('model_list_expired')
            if self.fingerprint() != listing.fingerprint:
                raise fail('model_settings_changed')
            if model not in listing.models:
                raise fail('model_not_available')
            listing.fingerprint = self.write_model(model, listing.fingerprint)
            return {'current_model': model}

    def write_model(self, model: str, expected_fingerprint: str) -> str:
        path = self.root / 'icon-search.json'
        temporary: str | None = None
        try:
            if path.is_symlink():
                raise ValueError
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > 16384:
                raise ValueError
            raw = path.read_bytes()
            before = json.loads(raw.decode('utf-8-sig'))
            if config_fingerprint(before) != expected_fingerprint:
                raise fail('model_settings_changed')
            updated, count = re.subn(rb'("vision_model"\s*:\s*)"(?:[^"\\]|\\.)*"',
                                    lambda match: match[1] + json.dumps(model).encode(), raw)
            if count != 1 or json.loads(updated.decode('utf-8-sig')) != dict(before, vision_model=model):
                raise ValueError
            descriptor, temporary = tempfile.mkstemp(prefix='.model-settings-', dir=self.root)
            with os.fdopen(descriptor, 'wb') as stream:
                os.chmod(temporary, stat.S_IMODE(info.st_mode))
                stream.write(updated)
                stream.flush()
                os.fsync(stream.fileno())
            if path.is_symlink() or path.read_bytes() != raw:
                raise fail('model_settings_changed')
            os.replace(temporary, path)
            return config_fingerprint(dict(before, vision_model=model))
        except (OSError, ValueError, TypeError, KeyError):
            raise fail('model_settings_unavailable') from None
        finally:
            if temporary is not None:
                Path(temporary).unlink(missing_ok=True)


def main() -> None:
    value: dict
    try:
        config = load_config(Path(sys.argv[1]))
        value = {'models': Provider(config).models(), 'fingerprint': config_fingerprint(config)}
    except FxfetchError as error:
        value = {'error': error.code if error.code in PROVIDER_ERRORS else 'icon_provider_failed'}
        status = getattr(error, 'http_status', None)
        if type(status) is int and 100 <= status <= 599:
            value['http_status'] = status
    print(json.dumps(value))


if __name__ == '__main__':
    main()
