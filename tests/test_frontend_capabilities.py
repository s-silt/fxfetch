"""Optional Node check of real frontend functions with synthetic DOM/fetch."""

import shutil
import subprocess
from pathlib import Path

import pytest


def test_capability_failure_and_polling_never_prevent_session_cleanup():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is needed for this local frontend logic regression")
    result = subprocess.run(
        [node, str(Path(__file__).with_name("frontend_capabilities.cjs"))],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert '"passed":true' in result.stdout
