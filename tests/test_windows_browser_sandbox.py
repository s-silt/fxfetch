"""Offline contracts of the AppContainer diagnostic; not production acceptance."""

from __future__ import annotations

import ctypes
from pathlib import Path

from fxfetch import windows_browser_sandbox as sandbox


def test_probe_refuses_non_windows_without_side_effects(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox.os, "name", "posix")
    result = sandbox.probe_chrome(Path("synthetic-chrome"), tmp_path / "never-created")
    assert result == {"status": "unsupported_platform"}
    assert not (tmp_path / "never-created").exists()


def test_security_capabilities_default_has_no_network_capabilities():
    capabilities = sandbox._Capabilities()
    assert capabilities.count == 0
    assert not capabilities.capabilities


def test_native_structures_have_pointer_width_alignment():
    # The Windows STARTUPINFOEX attribute-list pointer must follow STARTUPINFO.
    assert sandbox._StartupEx.attributes.offset == ctypes.sizeof(sandbox._Startup)
    assert sandbox._Capabilities.count.offset == 2 * ctypes.sizeof(ctypes.c_void_p)
