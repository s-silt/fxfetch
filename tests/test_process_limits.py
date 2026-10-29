import os
import sys
import time
from pathlib import Path
from threading import Event

import pytest

from fxfetch.core.process_limits import jvm_memory_options, run_limited


def test_real_boundary_and_capture():
    result = run_limited(
        [sys.executable, "-c", "print('synthetic')"], timeout=5, memory_bytes=512 * 1024 * 1024
    )
    assert result.memory_limited, result
    assert result.limit_method == ("windows_job_memory" if os.name == "nt" else "posix_rlimit_as")
    assert result.returncode == 0
    assert result.stdout.strip() == b"synthetic"


def test_timeout():
    result = run_limited(
        [sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.1, memory_bytes=512 * 1024 * 1024
    )
    assert result.timed_out
    assert result.returncode != 0


def test_output_bounded():
    result = run_limited(
        [sys.executable, "-c", "print('x'*1000000)"],
        timeout=5,
        memory_bytes=512 * 1024 * 1024,
        max_output_bytes=1000,
    )
    assert len(result.stdout) <= 1000
    assert result.output_truncated


def test_cancelled():
    event = Event()
    event.set()
    result = run_limited(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        timeout=5,
        memory_bytes=512 * 1024 * 1024,
        cancel=event,
    )
    assert result.cancelled


def test_memory_limit_is_enforced():
    result = run_limited(
        [sys.executable, "-c", "a=bytearray(400*1024*1024)"], timeout=5, memory_bytes=128 * 1024 * 1024
    )
    assert result.memory_limited
    assert result.returncode != 0


def test_timeout_kills_descendants(tmp_path: Path):
    marker = tmp_path / "escaped.txt"
    child = (
        "import time,pathlib; time.sleep(1); pathlib.Path(" + repr(str(marker)) + ").write_text('escaped')"
    )
    parent = (
        "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',"
        + repr(child)
        + "]); time.sleep(30)"
    )
    result = run_limited([sys.executable, "-c", parent], timeout=0.3, memory_bytes=512 * 1024 * 1024)
    assert result.timed_out
    time.sleep(1.1)
    assert not marker.exists()


def test_jvm_options_preserve_windows_and_bound_posix_reservations():
    options = jvm_memory_options()
    if os.name == "nt":
        assert options == jvm_memory_options(launcher=True) == []
    else:
        assert "-XX:+UseSerialGC" in options
        assert jvm_memory_options(launcher=True) == ["-J" + item for item in options]


@pytest.mark.skipif(os.name != "posix", reason="POSIX-only thread/exec regression")
def test_posix_limits_work_from_threads_without_preexec():
    from concurrent.futures import ThreadPoolExecutor

    def launch(index):
        return run_limited(
            [sys.executable, "-c", "import resource; print(resource.getrlimit(resource.RLIMIT_AS)[0])"],
            timeout=5,
            memory_bytes=256 * 1024**2,
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(launch, range(8)))
    assert all(result.returncode == 0 and result.stdout.strip() == b"268435456" for result in results)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux parent-death signal contract")
def test_linux_timeout_stops_nested_limited_session(tmp_path: Path):
    marker = tmp_path / "nested-escaped.txt"
    child = "import time,pathlib; time.sleep(1); pathlib.Path(" + repr(str(marker)) + ").write_text('escaped')"
    parent = (
        "import sys; from fxfetch.core.process_limits import run_limited; "
        "run_limited([sys.executable, '-c', " + repr(child) + "], timeout=10, memory_bytes=268435456)"
    )
    result = run_limited([sys.executable, "-c", parent], timeout=0.4, memory_bytes=512 * 1024**2)
    assert result.timed_out
    time.sleep(1.1)
    assert not marker.exists()
