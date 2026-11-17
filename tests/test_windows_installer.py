"""Fail-closed offline bundle tests with synthetic files and local subprocesses."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/windows-installer/install.py"
SPEC = importlib.util.spec_from_file_location("synthetic_windows_installer", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


def bundle_fixture(root: Path) -> dict:
    names = ["assets/docker-desktop-installer.exe", "assets/wsl.msi", "assets/docker-images.tar",
             "assets/ubuntu-prepared.qcow2", "assets/ubuntu-prepared.json", "runtime/python.exe",
             "app/scripts/windows-installer/prerequisites.ps1", "fxfetch.exe", "fxfetch-setup.exe",
             "assets/中文 空格.txt", "assets/android-sdk-linux/platforms/android-35/android.jar",
             "assets/android-sdk-linux/build-tools/37.0.0/aapt2", "assets/android-sdk-linux/build-tools/37.0.0/zipalign",
             "assets/android-sdk-linux/build-tools/37.0.0/apksigner", "assets/android-sdk-linux/build-tools/37.0.0/d8",
             "assets/fonts/NotoSansCJKsc-Regular-Sans2.004.otf", "assets/fonts/NotoSansCJKsc-Regular-Sans2.004.LICENSE.txt",
             "assets/licenses/Docker-LICENSE.rtf"]
    entries = []
    for name in names:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        data = ("合成文件：" + name).encode()
        path.write_bytes(data)
        entries.append({"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    document = {"schema": "fxfetch.offline-install.v1", "files": entries}
    write_manifest(root, document)
    return document


def write_manifest(root: Path, document: dict) -> None:
    (root / "manifest.json").write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8-sig")


def test_unicode_bundle_verified_offline(tmp_path: Path) -> None:
    root = tmp_path / "中文 离线包"
    document = bundle_fixture(root)
    assert installer.verify_bundle(root) == document


@pytest.mark.parametrize("name", ["../outside", "/absolute", "assets/../outside", "assets//x", "C:/outside", "assets\\x"])
def test_traversal_rejected(tmp_path: Path, name: str) -> None:
    document = bundle_fixture(tmp_path)
    document["files"][0]["path"] = name
    write_manifest(tmp_path, document)
    with pytest.raises(ValueError, match="payload_path"):
        installer.verify_bundle(tmp_path)


def test_tampered_file_and_duplicate_case_rejected(tmp_path: Path) -> None:
    document = bundle_fixture(tmp_path)
    (tmp_path / "fxfetch.exe").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="digest_mismatch"):
        installer.verify_bundle(tmp_path)
    document = bundle_fixture(tmp_path)
    document["files"].append({**document["files"][0], "path": "ASSETS/DOCKER-DESKTOP-INSTALLER.EXE"})
    write_manifest(tmp_path, document)
    with pytest.raises(ValueError, match="duplicate_payload_path"):
        installer.verify_bundle(tmp_path)


def test_unknown_private_directory_not_adopted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = tmp_path / "bundle"
    manifest = bundle_fixture(bundle)
    root = tmp_path / "installation"
    old = root / "private/guest/old-disk"
    old.parent.mkdir(parents=True)
    old.write_bytes(b"synthetic old state")
    monkeypatch.setattr(installer, "run", lambda *args, **kwargs: pytest.fail("must refuse before subprocess"))
    with pytest.raises(ValueError, match="installation_directory_not_empty"):
        installer.copy_payload(bundle, root, manifest)
    assert old.read_bytes() == b"synthetic old state"
    assert not (root / "private/installation.json").exists()


def make_directory_link(link: Path, target: Path) -> None:
    if os.name == "nt":
        result = subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
                                capture_output=True, timeout=10, check=False)
        if result.returncode:
            pytest.skip("junction creation unavailable")
    else:
        link.symlink_to(target, target_is_directory=True)


def test_reparse_bundle_and_installation_refused(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    manifest = bundle_fixture(bundle)
    alias = tmp_path / "bundle-alias"
    make_directory_link(alias, bundle)
    try:
        with pytest.raises(ValueError, match="reparse"):
            installer.verify_bundle(alias)
    finally:
        alias.rmdir() if os.name == "nt" else alias.unlink()
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "install-alias"
    make_directory_link(root, outside)
    try:
        with pytest.raises(ValueError, match="reparse"):
            installer.copy_payload(bundle, root, manifest)
        assert list(outside.iterdir()) == []
    finally:
        root.rmdir() if os.name == "nt" else root.unlink()


def test_explicit_utf8_overrides_gbk_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTHONIOENCODING", "cp936")
    monkeypatch.setenv("PYTHONUTF8", "0")
    script = tmp_path / "中文 子进程.py"
    script.write_text("import json,sys; value=json.load(sys.stdin); print(json.dumps(value,ensure_ascii=False))", encoding="utf-8")
    value = {"message": "中文路径 空格 $ ' 不乱码"}
    output = installer.run([sys.executable, str(script)], payload=value)
    assert json.loads(output.stdout) == value


def test_raw_utf8_bytes_decode_independent_of_host_locale() -> None:
    result = installer.run([sys.executable, "-c", "import sys;sys.stdout.buffer.write(bytes.fromhex('e4b8ade69687'))"])
    assert result.stdout == "中文"


def test_framework_utf8_bom_stdin_accepted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    secret = {"use_default": False, "password": "中文合成口令-12345"}
    received = []
    monkeypatch.setattr(installer.sys, "argv", [str(SCRIPT), "install", "--bundle", str(tmp_path), "--root", str(tmp_path / "root")])
    monkeypatch.setattr(installer.sys, "stdin", io.StringIO("\ufeff" + json.dumps(secret, ensure_ascii=False) + "\n"))
    monkeypatch.setattr(installer, "install", lambda args, value: received.append(value) or 0)
    assert installer.main() == 0
    assert received == [secret]


def test_acl_interruption_resumes_only_owned_empty_preparation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = tmp_path / "bundle"
    manifest = bundle_fixture(bundle)
    root = tmp_path / "中文 安装目录"
    failed = False

    def fake_run(arguments, *args, **kwargs):
        nonlocal failed
        if arguments[0] == "icacls.exe" and not failed:
            failed = True
            raise ValueError("synthetic_acl_failure")
        return subprocess.CompletedProcess(arguments, 0, "S-1-5-21-123-456-789-1001\n", "")

    monkeypatch.setattr(installer, "run", fake_run)
    with pytest.raises(ValueError, match="synthetic_acl_failure"):
        installer.copy_payload(bundle, root, manifest)
    assert (root / ".installation-preparing.json").is_file()
    assert not (root / "private/installation.json").exists()
    installer.copy_payload(bundle, root, manifest)
    assert not (root / ".installation-preparing.json").exists()
    assert (root / "private/installation.json").is_file()
    assert (root / "assets/中文 空格.txt").read_bytes() == (bundle / "assets/中文 空格.txt").read_bytes()
    # After a reboot, the already-copied Setup.exe is itself the bundle root.
    installer.copy_payload(root, root, manifest)


def test_resume_preserves_mismatched_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = tmp_path / "bundle"
    manifest = bundle_fixture(bundle)
    root = tmp_path / "installed"
    (root / "private").mkdir(parents=True)
    expected = installer.sha(bundle / "manifest.json")
    (root / "private/installation.json").write_text(json.dumps({"manifest_sha256": expected}), encoding="utf-8")
    target = root / "manifest.json"
    target.write_bytes(b"synthetic other manifest")
    monkeypatch.setattr(installer, "run", lambda *args, **kwargs: pytest.fail("must refuse before subprocess"))
    with pytest.raises(ValueError, match="existing_installed_manifest_changed"):
        installer.copy_payload(bundle, root, manifest)
    assert target.read_bytes() == b"synthetic other manifest"
    assert not (root / "assets").exists()


def test_unpacked_distribution_cannot_be_adopted_as_installed_root(tmp_path: Path) -> None:
    bundle_fixture(tmp_path)
    with pytest.raises(ValueError, match="payload_file_missing"):
        installer.copy_payload(tmp_path, tmp_path, {})
