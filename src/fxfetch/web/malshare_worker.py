"""One explicitly selected sample-provider operation in a resource-limited process."""

from __future__ import annotations

import json
import sys
from enum import StrEnum
from pathlib import Path

from ..core.errors import FxfetchError
from ..icon_search.bazaar import MalwareBazaarClient
from ..icon_search.malshare import MalShareClient


class SampleProvider(StrEnum):
    MALSHARE = 'malshare'
    MALWAREBAZAAR = 'malwarebazaar'

    @property
    def label(self) -> str:
        return 'MalShare' if self is SampleProvider.MALSHARE else 'MalwareBazaar'

    def error(self, suffix: str) -> str:
        prefix = 'malshare' if self is SampleProvider.MALSHARE else 'bazaar'
        return f'{prefix}_{suffix}'


def perform(root: Path, action: str, sha: str, destination: Path,
            provider: SampleProvider = SampleProvider.MALSHARE) -> dict:
    try:
        client = MalShareClient(root) if provider is SampleProvider.MALSHARE else MalwareBazaarClient(root)
        if action == 'lookup':
            record = client.lookup(sha)
            if record is None:
                return {'status': 'no_record'}
            if record.get('sha256') == sha:
                return {'status': 'hit'}
            return {'status': 'failed', 'code': provider.error('response_invalid')}
        if action == 'download':
            return {'status': 'downloaded', 'size': client.download(sha, destination)}
        return {'status': 'failed', 'code': provider.error('response_invalid')}
    except FxfetchError as exc:
        result: dict = {'status': 'failed', 'code': exc.code}
        status = getattr(exc, 'http_status', None)
        if type(status) is int and 100 <= status <= 599:
            result['http_status'] = status
        return result


if __name__ == '__main__':
    root, provider, action, digest, destination = sys.argv[1:]
    print(json.dumps(perform(Path(root), action, digest, Path(destination), SampleProvider(provider))))
