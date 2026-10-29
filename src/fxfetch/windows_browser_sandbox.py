"""Windows AppContainer launcher POC: zero network capabilities and inherited CDP pipes.

This module does not issue a browser guard lease. Profile write containment still
requires a separate proven boundary before any target navigation is authorized.
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import threading
import uuid
from ctypes import wintypes as w
from pathlib import Path
from typing import Any


class _Startup(ctypes.Structure):
    _fields_ = [
        ("cb", w.DWORD),
        ("reserved", w.LPWSTR),
        ("desktop", w.LPWSTR),
        ("title", w.LPWSTR),
        ("x", w.DWORD),
        ("y", w.DWORD),
        ("xs", w.DWORD),
        ("ys", w.DWORD),
        ("xc", w.DWORD),
        ("yc", w.DWORD),
        ("fill", w.DWORD),
        ("flags", w.DWORD),
        ("show", w.WORD),
        ("reserved2_len", w.WORD),
        ("reserved2", ctypes.c_void_p),
        ("stdin", w.HANDLE),
        ("stdout", w.HANDLE),
        ("stderr", w.HANDLE),
    ]


class _StartupEx(ctypes.Structure):
    _fields_ = [("startup", _Startup), ("attributes", ctypes.c_void_p)]


class _Process(ctypes.Structure):
    _fields_ = [("process", w.HANDLE), ("thread", w.HANDLE), ("pid", w.DWORD), ("tid", w.DWORD)]


class _Capabilities(ctypes.Structure):
    _fields_ = [
        ("sid", ctypes.c_void_p),
        ("capabilities", ctypes.c_void_p),
        ("count", w.DWORD),
        ("reserved", w.DWORD),
    ]


class _Security(ctypes.Structure):
    _fields_ = [("size", w.DWORD), ("descriptor", ctypes.c_void_p), ("inherit", w.BOOL)]


def probe_chrome(
    executable: Path,
    root: Path,
    *,
    readonly: bool = False,
    diagnostic_no_sandbox: bool = False,
    _native_probe: bool = False,
) -> dict[str, Any]:
    """Only about:blank; no supplied URL or network capability can enter this POC."""
    if os.name != "nt":
        return {"status": "unsupported_platform"}
    from .core.process_limits import _windows_job

    root = root.absolute()
    root.mkdir(parents=True, exist_ok=True)
    profile = root / "chrome-profile"
    profile.mkdir()
    (profile / "Default").mkdir()
    (profile / "Temp").mkdir()
    name = "fxfetch.poc." + uuid.uuid4().hex
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    userenv.CreateAppContainerProfile.argtypes = [
        w.LPCWSTR,
        w.LPCWSTR,
        w.LPCWSTR,
        ctypes.c_void_p,
        w.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    userenv.CreateAppContainerProfile.restype = w.LONG
    userenv.DeleteAppContainerProfile.argtypes = [w.LPCWSTR]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(w.LPWSTR)]
    advapi.FreeSid.argtypes = [ctypes.c_void_p]
    advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    advapi.GetTokenInformation.argtypes = [
        w.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        w.DWORD,
        ctypes.POINTER(w.DWORD),
    ]
    kernel.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
    kernel.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CreatePipe.argtypes = [
        ctypes.POINTER(w.HANDLE),
        ctypes.POINTER(w.HANDLE),
        ctypes.POINTER(_Security),
        w.DWORD,
    ]
    kernel.SetHandleInformation.argtypes = [w.HANDLE, w.DWORD, w.DWORD]
    kernel.InitializeProcThreadAttributeList.argtypes = [
        ctypes.c_void_p,
        w.DWORD,
        w.DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel.UpdateProcThreadAttribute.argtypes = [
        ctypes.c_void_p,
        w.DWORD,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    kernel.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    kernel.CreateProcessW.argtypes = [
        w.LPCWSTR,
        w.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        w.BOOL,
        w.DWORD,
        ctypes.c_void_p,
        w.LPCWSTR,
        ctypes.POINTER(_StartupEx),
        ctypes.POINTER(_Process),
    ]
    kernel.ResumeThread.argtypes = [w.HANDLE]
    kernel.GetExitCodeProcess.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
    kernel.WriteFile.argtypes = [w.HANDLE, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.c_void_p]
    kernel.ReadFile.argtypes = [w.HANDLE, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD), ctypes.c_void_p]
    sid, sid_text = ctypes.c_void_p(), w.LPWSTR()
    handles: list[Any] = []
    job = None
    attributes = None
    pi = _Process()
    result: dict[str, Any] = {
        "readonly_profile": readonly,
        "capability_count": 0,
        "network_authorized": False,
    }
    hr = userenv.CreateAppContainerProfile(
        name, name, "fxfetch isolated local probe", None, 0, ctypes.byref(sid)
    )
    if hr < 0:
        return {**result, "status": "profile_create_failed", "hresult": hex(hr & 0xFFFFFFFF)}
    try:
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid_string = sid_text.value
        result["sid"] = sid_string
        for directory, rights in ((root, "RX"), (profile, "M")):
            acl = subprocess.run(
                ["icacls", str(directory), "/grant", f"*{sid_string}:(OI)(CI)({rights})"],
                capture_output=True,
                timeout=10,
            )
            if acl.returncode:
                return {**result, "status": "profile_acl_failed"}
        if readonly:
            denied = subprocess.run(
                ["icacls", str(profile), "/deny", f"*{sid_string}:(OI)(CI)(WD,AD,WEA,WA,DC,DE,WDAC,WO)"],
                capture_output=True,
                timeout=10,
            )
            if denied.returncode:
                return {**result, "status": "readonly_acl_failed"}
        child_read, parent_write, parent_read, child_write = w.HANDLE(), w.HANDLE(), w.HANDLE(), w.HANDLE()
        security = _Security(ctypes.sizeof(_Security), None, True)
        for left, right in ((child_read, parent_write), (parent_read, child_write)):
            if not kernel.CreatePipe(ctypes.byref(left), ctypes.byref(right), ctypes.byref(security), 0):
                raise ctypes.WinError(ctypes.get_last_error())
            handles.extend((left, right))
        for handle in (parent_write, parent_read):
            kernel.SetHandleInformation(handle, 1, 0)
        size = ctypes.c_size_t()
        kernel.InitializeProcThreadAttributeList(None, 2, 0, ctypes.byref(size))
        attributes = ctypes.create_string_buffer(size.value)
        if not kernel.InitializeProcThreadAttributeList(attributes, 2, 0, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        capabilities = _Capabilities(sid, None, 0, 0)
        inherited = (w.HANDLE * 2)(child_read.value, child_write.value)
        for attribute, value, length in (
            (0x20009, ctypes.byref(capabilities), ctypes.sizeof(capabilities)),
            (0x20002, inherited, ctypes.sizeof(inherited)),
        ):
            if not kernel.UpdateProcThreadAttribute(attributes, 0, attribute, value, length, None, None):
                raise ctypes.WinError(ctypes.get_last_error())
        startup = _StartupEx()
        startup.startup.cb = ctypes.sizeof(_StartupEx)
        startup.attributes = ctypes.cast(attributes, ctypes.c_void_p)
        flags = [
            str(executable),
            "--headless=new",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--disable-extensions",
            "--disable-breakpad",
            "--disable-crash-reporter",
            "--incognito",
            "--enable-logging",
            f"--log-file={profile / 'chrome-debug.log'}",
            f"--user-data-dir={profile}",
            "--remote-debugging-pipe",
            f"--remote-debugging-io-pipes={child_read.value},{child_write.value}",
            "about:blank",
        ]
        if diagnostic_no_sandbox:
            flags.append("--no-sandbox")
        if _native_probe:
            startup.startup.flags = 0x100
            startup.startup.stdin = child_read
            startup.startup.stdout = child_write
            startup.startup.stderr = child_write
            flags = [str(executable), "/d", "/c", 'echo {"native_probe":true}']
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline(flags))
        environment = dict(os.environ)
        environment.update(TEMP=str(profile / "Temp"), TMP=str(profile / "Temp"), LOCALAPPDATA=str(profile))
        env = ctypes.create_unicode_buffer(
            "\0".join(f"{key}={value}" for key, value in sorted(environment.items())) + "\0\0"
        )
        if not kernel.CreateProcessW(
            str(executable),
            command,
            None,
            None,
            True,
            0x80000 | 0x400 | 0x4 | 0x8000000,
            env,
            str(root),
            ctypes.byref(startup),
            ctypes.byref(pi),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        handles.extend((pi.process, pi.thread))
        token = w.HANDLE()
        if advapi.OpenProcessToken(pi.process, 8, ctypes.byref(token)):
            try:
                count, is_appcontainer = w.DWORD(), w.DWORD()
                if advapi.GetTokenInformation(
                    token,
                    29,
                    ctypes.byref(is_appcontainer),
                    ctypes.sizeof(is_appcontainer),
                    ctypes.byref(count),
                ):
                    result["token_is_appcontainer"] = bool(is_appcontainer.value)
                buffer = ctypes.create_string_buffer(4096)
                if advapi.GetTokenInformation(token, 30, buffer, len(buffer), ctypes.byref(count)):
                    result["token_capability_count"] = w.DWORD.from_buffer(buffer).value
            finally:
                kernel.CloseHandle(token)

        job_kernel, job = _windows_job(1024**3)
        if not job_kernel.AssignProcessToJobObject(job, pi.process):
            raise ctypes.WinError(ctypes.get_last_error())
        kernel.ResumeThread(pi.thread)
        kernel.CloseHandle(child_read)
        handles.remove(child_read)
        kernel.CloseHandle(child_write)
        handles.remove(child_write)
        payload = json.dumps({"id": 1, "method": "Browser.getVersion"}).encode() + b"\0"
        written = w.DWORD()
        if not kernel.WriteFile(parent_write, payload, len(payload), ctypes.byref(written), None):
            raise ctypes.WinError(ctypes.get_last_error())
        messages: list[bytes] = []

        def read() -> None:
            buffer, count = ctypes.create_string_buffer(65536), w.DWORD()
            if kernel.ReadFile(parent_read, buffer, len(buffer), ctypes.byref(count), None):
                messages.append(buffer.raw[: count.value])

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        reader.join(12)
        code = w.DWORD()
        kernel.GetExitCodeProcess(pi.process, ctypes.byref(code))
        if _native_probe:
            result.update(
                status="native_replied" if messages else "no_native_response",
                exit_code=code.value,
                native_output=b"".join(messages).decode("ascii", errors="replace")[:200],
            )
        else:
            result.update(
                status="cdp_replied" if messages else "no_cdp_response",
                exit_code=code.value,
                responses=[
                    json.loads(item.strip())
                    for data in messages
                    for item in data.split(b"\0")
                    if item.strip()
                ],
            )
    except OSError as error:
        result.update(status="launch_failed", winerror=error.winerror)
    finally:
        if job is not None:
            job_kernel.CloseHandle(job)
        elif pi.process:
            kernel.TerminateProcess(pi.process, 1)
        if pi.process:
            kernel.WaitForSingleObject(pi.process, 2000)
        for handle in handles:
            kernel.CloseHandle(handle)
        if attributes is not None:
            kernel.DeleteProcThreadAttributeList(attributes)
        if sid_text:
            kernel.LocalFree(sid_text)
        if sid:
            advapi.FreeSid(sid)
        result["profile_cleanup_hresult"] = hex(userenv.DeleteAppContainerProfile(name) & 0xFFFFFFFF)
    return result
