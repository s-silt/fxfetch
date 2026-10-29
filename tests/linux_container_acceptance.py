"""Synthetic Linux SDK acceptance. Run in a container with --network none.

The SDK, optional font and test wheel directory are administrator-provisioned
read-only mounts. Output (including a synthetic signing identity) stays private.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
import zipfile
from dataclasses import asdict
from pathlib import Path

from fxfetch.build_setup import _FONT_PINS, load_builder, setup_build
from fxfetch.core.offline import OfflineBundle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--sdk", type=Path, default=Path("/opt/android-sdk"))
    parser.add_argument("--java-home", type=Path, default=Path("/opt/java"))
    parser.add_argument("--font-dir", type=Path)
    parser.add_argument("--wheels", type=Path)
    options = parser.parse_args()
    if sys.platform != "linux":
        raise RuntimeError("Linux acceptance requires Linux")
    root = options.out.resolve()
    root.mkdir(parents=True, exist_ok=True)
    # All package installation in this check is local, even before the tests run.
    if options.wheels is not None:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--no-index", "--no-deps", "--find-links",
             str(options.wheels), "--target", "/tmp/qa-deps", "pytest==9.2.0", "httpx==0.28.1",
             "qrcode==8.2", "httpcore==1.0.9", "iniconfig==2.3.1", "packaging==26.3",
             "pluggy==1.7.0", "Pygments==2.21.0"],
            check=True, stdout=subprocess.DEVNULL,
        )
        os.environ["PYTHONPATH"] = "/tmp/qa-deps:" + os.environ.get("PYTHONPATH", "")
        selected = [
            "test_process_limits.py", "test_container_deploy.py", "test_build_setup.py",
            "test_web_apk.py", "test_qr.py", "test_image_formats.py", "test_task_supervision.py",
        ]
        subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--tb=short", "-p", "no:cacheprovider",
             "--basetemp", str(root / "linux-pytest"),
             *[str(Path(__file__).parent / item) for item in selected]],
            check=True,
        )
    memory_path = Path("/sys/fs/cgroup/memory.max")
    memory_max = memory_path.read_text().strip() if memory_path.is_file() else "unavailable"
    assert memory_max.isdigit() and 0 < int(memory_max) <= 3 * 1024**3, "finite cgroup memory required"
    started = time.monotonic()
    setup = setup_build(root, options.sdk, options.sdk / "build-tools" / "37.0.0", options.java_home)
    assert setup.state == "ready", setup
    if options.font_dir is not None:
        (root / "offline-font.json").write_text(json.dumps({
            "path": str(options.font_dir / "NotoSansCJKsc-Regular-Sans2.004.otf"),
            "license_path": str(options.font_dir / "NotoSansCJKsc-Regular-Sans2.004.LICENSE.txt"),
            **_FONT_PINS,
        }), encoding="utf-8")
    offline = root / "synthetic-offline"
    source = root / "synthetic-source.html"
    source.write_text(
        '<!doctype html><meta charset="utf-8"><p>本地合成内容 Synthetic offline page 123</p>', encoding="utf-8"
    )
    snapshot = OfflineBundle().build(source, "https://example.test/", {}, offline)
    assert snapshot.available
    builder = load_builder(root)
    result = builder.build(
        "https://example.test/entry?value=synthetic#section", root / "artifacts", "test.example", 1,
        offline_dir=offline,
    )
    assert result.state == "built" and result.artifact_path is not None, result
    assert result.offline_content_kind == "site_snapshot", result
    with zipfile.ZipFile(result.artifact_path) as archive:
        assert "classes.dex" in archive.namelist() and "AndroidManifest.xml" in archive.namelist()
        assert archive.testzip() is None
        assert "本地合成内容" in archive.read("assets/site/index.html").decode("utf-8")
    if options.font_dir is not None:
        assert result.font_applied, result
    receipt = {
        "platform": platform.platform(), "machine": platform.machine(), "uid": os.getuid(),
        "memory_max": int(memory_max), "target_requests": 0, "network_namespace": "none_required_by_runner",
        "seconds": round(time.monotonic() - started, 3), "build": asdict(result),
        "runtime_validation": "not_run",
    }
    (root / "result.json").write_text(json.dumps(receipt, indent=2, default=str), encoding="utf-8")
    print(json.dumps(receipt, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
