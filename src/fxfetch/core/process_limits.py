"""Fail-closed, bounded subprocess execution (including Windows process trees)."""

from __future__ import annotations

import ctypes
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Any, cast

# A fresh interpreter applies limits before exec. Python's preexec_fn may deadlock
# when called from the web service's worker threads, even when the function is small.
_POSIX_EXEC = """
import ctypes, os, resource, signal, sys
try:
    expected_parent = int(sys.argv[2])
    if sys.platform == 'linux':
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
            raise OSError('parent-death boundary unavailable')
        if os.getppid() != expected_parent:
            raise OSError('supervisor exited')
    limit = int(sys.argv[1])
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    os.execvpe(sys.argv[3], sys.argv[3:], os.environ)
except (OSError, ValueError):
    sys.stderr.write('FXFETCH_PROCESS_LIMITS_FAILED\\n')
    raise SystemExit(125)
"""


def jvm_memory_options(*, launcher: bool = False) -> list[str]:
    """Bound HotSpot virtual reservations within the existing POSIX RLIMIT_AS.

    Windows retains its tested JVM options and aggregate Job Object memory limit.
    These options bound reservations, not total tree RSS; container cgroups impose
    the separate aggregate memory boundary on Linux deployments.
    """
    if os.name == "nt":
        return []
    values = [
        "-Xms16m", "-Xss512k", "-XX:+UseSerialGC", "-XX:ActiveProcessorCount=2",
        "-XX:CompressedClassSpaceSize=32m", "-XX:ReservedCodeCacheSize=32m",
        "-XX:MaxMetaspaceSize=192m",
    ]
    return ["-J" + value if launcher else value for value in values]


@dataclass
class ProcessResult:
    returncode: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    timed_out: bool = False
    memory_limited: bool = False
    limit_method: str = "unavailable"
    reason_code: str | None = None
    output_truncated: bool = False
    cancelled: bool = False


def _windows_job(memory_bytes: int) -> tuple[Any, Any]:
    from ctypes import wintypes

    class Basic(ctypes.Structure):
        _fields_ = [
            ("process_time", ctypes.c_int64),
            ("job_time", ctypes.c_int64),
            ("flags", wintypes.DWORD),
            ("min_ws", ctypes.c_size_t),
            ("max_ws", ctypes.c_size_t),
            ("active", wintypes.DWORD),
            ("affinity", ctypes.c_size_t),
            ("priority", wintypes.DWORD),
            ("scheduling", wintypes.DWORD),
        ]

    class IO(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_uint64)
            for name in ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")
        ]

    class Extended(ctypes.Structure):
        _fields_ = [
            ("basic", Basic),
            ("io", IO),
            ("process_memory", ctypes.c_size_t),
            ("job_memory", ctypes.c_size_t),
            ("peak_process", ctypes.c_size_t),
            ("peak_job", ctypes.c_size_t),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    info = Extended()
    info.basic.flags = 0x2000 | 0x200  # kill on close, aggregate job memory
    info.job_memory = memory_bytes
    if not kernel.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
        error = ctypes.WinError(ctypes.get_last_error())
        kernel.CloseHandle(job)
        raise error
    return kernel, job


def run_limited(
    command: list[str],
    *,
    timeout: float,
    memory_bytes: int,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    cancel: Event | None = None,
    max_output_bytes: int = 1024 * 1024,
) -> ProcessResult:
    """Apply memory limits before target exec; never use a shell.

    POSIX RLIMIT_AS is per process, inherited by descendants. It is not an
    aggregate tree memory quota. Linux wrapper parent-death signals also stop
    nested run_limited sessions when an outer task worker is killed.
    """
    if timeout <= 0 or memory_bytes <= 0 or max_output_bytes <= 0:
        raise ValueError("process limits must be positive")
    job = kernel = None
    process: subprocess.Popen[bytes] | None = None
    result = ProcessResult(None)
    kwargs: dict[str, Any] = {}
    try:
        if os.name == "nt":
            kernel, job = _windows_job(memory_bytes)
            kwargs["creationflags"] = 0x00000004 | subprocess.CREATE_NO_WINDOW
            result.limit_method = "windows_job_memory"
        elif os.name == "posix":
            # glibc otherwise reserves large per-thread malloc arenas, exhausting
            # RLIMIT_AS during bounded JVM/keytool work despite low resident usage.
            env = dict(os.environ if env is None else env)
            env["MALLOC_ARENA_MAX"] = "2"
            command = [sys.executable, "-I", "-c", _POSIX_EXEC, str(memory_bytes), str(os.getpid()), *command]
            kwargs["start_new_session"] = True
            result.limit_method = "posix_rlimit_as"
        else:
            result.reason_code = "process_limits_unavailable"
            return result
        process = cast(
            subprocess.Popen[bytes],
            subprocess.Popen(
                command,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **kwargs,
            ),
        )
        if os.name == "nt":
            assert kernel is not None
            if not kernel.AssignProcessToJobObject(job, int(process._handle)):  # type: ignore[attr-defined]
                raise ctypes.WinError(ctypes.get_last_error())
            native = ctypes.WinDLL("ntdll")
            native.NtResumeProcess.argtypes = [ctypes.c_void_p]
            native.NtResumeProcess.restype = ctypes.c_long
            if native.NtResumeProcess(int(process._handle)) != 0:  # type: ignore[attr-defined]
                raise OSError("cannot resume constrained process")
        result.memory_limited = True
        buffers = [bytearray(), bytearray()]
        output_limit = Event()

        def drain(stream: Any, buffer: bytearray) -> None:
            while block := stream.read(8192):
                remaining = max_output_bytes - len(buffer)
                buffer.extend(block[: max(0, remaining)])
                if len(block) > remaining:
                    output_limit.set()

        readers = [
            threading.Thread(target=drain, args=(stream, buffer), daemon=True)
            for stream, buffer in zip((process.stdout, process.stderr), buffers, strict=True)
        ]
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + timeout
        while process.poll() is None:
            result.cancelled = cancel is not None and cancel.is_set()
            result.timed_out = time.monotonic() >= deadline
            if result.cancelled or result.timed_out or output_limit.is_set():
                if kernel is not None:
                    if not kernel.TerminateJobObject(job, 1):
                        process.kill()
                else:
                    cast(Any, os).killpg(process.pid, cast(Any, signal).SIGKILL)
                break
            time.sleep(0.01)
        process.wait(timeout=2)
        # Kill surviving descendants before draining inherited pipe handles.
        if kernel is not None:
            kernel.CloseHandle(job)
            job = None
        elif os.name == "posix":
            try:
                cast(Any, os).killpg(process.pid, cast(Any, signal).SIGKILL)
            except ProcessLookupError:
                pass
        for reader in readers:
            reader.join(2)
        result.stdout, result.stderr = bytes(buffers[0]), bytes(buffers[1])
        result.returncode = process.returncode
        result.output_truncated = output_limit.is_set()
        if os.name == "posix" and result.returncode == 125 and result.stderr == b"FXFETCH_PROCESS_LIMITS_FAILED\n":
            result.memory_limited = False
            result.reason_code = "process_limits_failed"
            return result
        result.reason_code = (
            "cancelled"
            if result.cancelled
            else "timed_out"
            if result.timed_out
            else "output_limit"
            if result.output_truncated
            else None
        )
        return result
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        if process is not None:
            process.kill()
            process.wait()
        result.reason_code = "process_limits_failed" if not result.memory_limited else "process_failed"
        result.stderr = str(error).encode("utf-8")[:max_output_bytes]
        return result
    finally:
        if job is not None and kernel is not None:
            kernel.CloseHandle(job)
