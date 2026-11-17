"""Package reviewed offline inputs; never copy current databases or worker disks."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
TOP = ("AGENTS.md", "README.md", "TASKBOOK.md", "RESEARCH.md", "IMPLEMENTATION.md", "SOURCE_RELEASE.md",
       "API.md", "BROWSER_ISOLATION.md", "pyproject.toml", "requirements.lock", ".gitignore", ".dockerignore")
ASSETS = ("docker-desktop-installer.exe", "wsl.msi", "docker-images.tar", "ubuntu-prepared.qcow2",
          "ubuntu-prepared.json", "pycdlib-1.14.0-py2.py3-none-any.whl", "Chrome.apk", "TrichromeLibrary.apk")
REQUIRED_TREE_FILES = ("android-sdk-linux/platforms/android-35/android.jar",
                       "android-sdk-linux/build-tools/37.0.0/aapt2",
                       "android-sdk-linux/build-tools/37.0.0/zipalign",
                       "android-sdk-linux/build-tools/37.0.0/apksigner",
                       "android-sdk-linux/build-tools/37.0.0/d8",
                       "fonts/NotoSansCJKsc-Regular-Sans2.004.otf",
                       "fonts/NotoSansCJKsc-Regular-Sans2.004.LICENSE.txt", "licenses/Docker-LICENSE.rtf")


def validate_assets(assets: Path, receipt: dict) -> None:
    for name in (*ASSETS, *REQUIRED_TREE_FILES):
        path = assets / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError("required_offline_asset_missing_" + name)
    recorded = set()
    for item in receipt["files"]:
        name = item["path"]
        if not isinstance(name, str) or any(p in {"", ".", ".."} for p in name.split("/")) or "\\" in name or ":" in name:
            raise ValueError("invalid_asset_receipt_path")
        path = assets / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != item["size"]:
            raise ValueError("asset_inventory_size_mismatch")
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != item["sha256"]:
                raise ValueError("asset_inventory_digest_mismatch")
        recorded.add(name)
    if not set(REQUIRED_TREE_FILES[:-1]) <= recorded:
        raise ValueError("required_toolchain_not_in_verified_inventory")


def copy_regular(source: Path, target: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise ValueError("only_regular_inputs_allowed")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def copy_tree(source: Path, target: Path, *, source_only: bool = False) -> None:
    if source.is_symlink() or not source.is_dir():
        raise ValueError("required_input_directory_missing")
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ValueError("no_links_in_bundle")
        if not path.is_file():
            continue
        relative = path.relative_to(source)
        if any(item in {"__pycache__", ".pytest_cache", ".ruff_cache", ".runtime", ".venv"} for item in relative.parts):
            continue
        if source_only and (path.suffix.lower() in {".pyc", ".apk", ".ipa", ".exe", ".dll", ".p12", ".pem", ".db", ".sqlite3"} or path.name == ".env"):
            raise ValueError("non_source_input_rejected")
        copy_regular(path, target / relative)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("assets", "runtime", "binaries", "image_receipt", "output"):
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    parser.add_argument("--defaults", type=Path)
    args = parser.parse_args()
    output = args.output.absolute()
    if output.exists():
        raise ValueError("bundle_output_must_be_new")
    defaults = None
    if args.defaults:
        defaults = json.loads(args.defaults.read_text(encoding="utf-8-sig"))
        if set(defaults) != {"password_hash"} or not re.fullmatch(r"pbkdf2_sha256\$600000\$[0-9a-f]{32}\$[0-9a-f]{64}", defaults["password_hash"]):
            raise ValueError("defaults_must_only_contain_valid_hash")
    receipt = json.loads(args.image_receipt.read_text(encoding="utf-8"))
    images = {item["tag"]: item["image_id"] for item in receipt["images"]}
    if set(images) != {"fxfetch-android-qemu:local", "fxfetch-android-api-builder:local", "fxfetch-installer-acceptance:local"}:
        raise ValueError("reviewed_image_inventory_required")
    validate_assets(args.assets, receipt)
    output.mkdir(parents=True)
    for name in ASSETS:
        copy_regular(args.assets / name, output / "assets" / name)
    for name in ("android-sdk-linux", "fonts", "licenses"):
        copy_tree(args.assets / name, output / "assets" / name)
    copy_tree(args.runtime, output / "runtime")
    # Isolated embeddable Python: only bundled modules, no user's site-packages.
    path_files = list((output / "runtime").glob("python*._pth"))
    if len(path_files) != 1:
        raise ValueError("one_embedded_python_configuration_required")
    current = path_files[0].read_text(encoding="utf-8")
    path_files[0].write_text(current + "\n../app/scripts/windows-installer\n../app/src\n", encoding="utf-8")
    for name in ("fxfetch-setup.exe", "fxfetch.exe"):
        copy_regular(args.binaries / name, output / name)
    for name in TOP:
        copy_regular(PROJECT / name, output / "app" / name)
    for name in ("src", "scripts", "deploy", "tests"):
        copy_tree(PROJECT / name, output / "app" / name, source_only=True)
    instructions = (PROJECT / "deploy/windows-installer/README.md").read_text(encoding="utf-8")
    (output / "安装说明.txt").write_text(instructions, encoding="utf-8-sig")
    if defaults:
        (output / "defaults.json").write_text(json.dumps(defaults), encoding="utf-8")
    rows = []
    for path in sorted(output.rglob("*")):
        if path.is_file():
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            rows.append({"path": path.relative_to(output).as_posix(), "bytes": path.stat().st_size, "sha256": digest})
    manifest = {"schema": "fxfetch.offline-install.v1", "images": images, "files": rows}
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    # Execute only packaged verification, never dependency installation on build host.
    subprocess.run([str(output / "runtime/python.exe"), "-X", "utf8", str(output / "app/scripts/windows-installer/install.py"),
                    "verify", "--bundle", str(output), "--root", str(output.parent / "unused-verification-root")], check=True, timeout=600)
    print(json.dumps({"files": len(rows), "bytes": sum(row["bytes"] for row in rows), "verified": True}))


if __name__ == "__main__":
    main()
