"""Exercise the installed Playwright driver under the real 2 GiB task boundary.

No browser is launched, no CDP endpoint is opened, and no target is contacted.
Run in an isolated --network=none container with the same aggregate cgroup limit.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict

from fxfetch.core.process_limits import run_limited

CHILD = """
import json, resource
from importlib.metadata import version
from playwright.sync_api import sync_playwright
with sync_playwright() as driver:
    assert driver.chromium.name == 'chromium'
    print(json.dumps({'playwright': version('playwright'),
                      'rlimit_as': resource.getrlimit(resource.RLIMIT_AS),
                      'driver_started': True, 'browser_launched': False,
                      'target_requests': 0}), flush=True)
"""


def main() -> int:
    result = run_limited(
        [sys.executable, "-c", CHILD],
        timeout=20,
        memory_bytes=2 * 1024**3,
        max_output_bytes=32768,
    )
    value = asdict(result)
    value["stdout"] = result.stdout.decode("utf-8", "replace")
    value["stderr"] = result.stderr.decode("utf-8", "replace")
    value["memory_bytes"] = 2 * 1024**3
    value["target_requests"] = 0
    value["browser_launched"] = False
    print(json.dumps(value), flush=True)
    return 0 if result.returncode == 0 and result.memory_limited and not result.timed_out else 1


if __name__ == "__main__":
    raise SystemExit(main())
