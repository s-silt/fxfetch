"""Offline asset boundary tests; Android runtime acceptance remains separate."""

import hashlib
import json
from pathlib import Path

import pytest
from PIL import Image

from fxfetch.core.offline import OfflineBundle
from fxfetch.core.web_apk import WebApkBuilder, _BuildStopped


def snapshot(root: Path) -> tuple[Path, str]:
    root.mkdir()
    source, image = root / "source.html", root / "source.png"
    Image.new("RGB", (32, 32), "blue").save(image)
    source.write_text(
        '<h1>Static synthetic page</h1><p style="color:red">Content</p>'
        '<img src="/banner.png"><script>fetch("https://other.synthetic.test/")</script>',
        encoding="utf-8",
    )
    result = OfflineBundle().build(
        source,
        "https://entry.synthetic.test/",
        {"https://entry.synthetic.test/banner.png": image},
        root / "site",
    )
    assert result.available
    return root / "site", hashlib.sha256(image.read_bytes()).hexdigest() + ".png"


def test_sanitized_snapshot_copies_only_static_files(tmp_path: Path):
    source, filename = snapshot(tmp_path / "fixture")
    destination = tmp_path / "assets" / "site"
    WebApkBuilder._copy_offline(source, destination)
    assert (destination / "index.html").read_bytes() == (source / "index.html").read_bytes()
    assert (destination / "assets" / filename).read_bytes() == (source / "assets" / filename).read_bytes()
    assert (destination / "assets" / "style.css").is_file()
    assert not list(destination.rglob("*.js"))
    assert b"other.synthetic.test" not in (destination / "index.html").read_bytes()


@pytest.mark.parametrize(
    "bad_path", ["script.js", "assets/script.js", "assets/arbitrary.png", "nested/index.html"]
)
def test_unexpected_offline_layout_rejected(tmp_path: Path, bad_path: str):
    source, _ = snapshot(tmp_path / "fixture")
    path = source / bad_path
    path.parent.mkdir(exist_ok=True)
    path.write_text("synthetic", encoding="utf-8")
    with pytest.raises(_BuildStopped, match="offline_bundle_invalid"):
        WebApkBuilder._copy_offline(source, tmp_path / "destination")


def test_actual_image_format_is_checked(tmp_path: Path):
    source, filename = snapshot(tmp_path / "fixture")
    (source / "assets" / filename).write_bytes(b"not a PNG image")
    with pytest.raises(_BuildStopped, match="offline_bundle_invalid_image"):
        WebApkBuilder._copy_offline(source, tmp_path / "destination")


def test_offline_byte_and_file_limits(tmp_path: Path):
    source, _ = snapshot(tmp_path / "fixture")
    with (source / "index.html").open("wb") as stream:
        stream.truncate(28 * 1024 * 1024 + 1)
    with pytest.raises(_BuildStopped, match="offline_bundle_byte_limit"):
        WebApkBuilder._copy_offline(source, tmp_path / "destination")
    (source / "index.html").write_text("synthetic", encoding="utf-8")
    for index in range(30):
        (source / "assets" / (f"{index:064x}" + ".png")).write_bytes(b"synthetic")
    with pytest.raises(_BuildStopped, match="offline_bundle_file_limit"):
        WebApkBuilder._copy_offline(source, tmp_path / "destination2")


def test_linked_snapshot_rejected(tmp_path: Path):
    source, _ = snapshot(tmp_path / "fixture")
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(source, target_is_directory=True)
    except OSError:
        import os
        import subprocess

        if os.name != "nt":
            raise
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(linked), str(source)], capture_output=True, check=False
        )
        assert result.returncode == 0, result.stderr
    with pytest.raises(_BuildStopped, match="offline_bundle_unsafe_path"):
        WebApkBuilder._copy_offline(linked, tmp_path / "destination")


def test_no_snapshot_default_config_and_template_boundaries(tmp_path: Path):
    url = "https://entry.synthetic.test/full/path?signature=a%2Fb#fragment"
    WebApkBuilder._render(tmp_path, url, "entry.synth.test", "test.synth.entry", 1)
    assert json.loads((tmp_path / "assets" / "config.json").read_text()) == {"url": url, "offline": False}
    source = (tmp_path / "MainActivity.java").read_text(encoding="utf-8")
    assert "handler.cancel()" in source
    assert "request.isForMainFrame()" in source
    assert "ERROR_FAILED_SSL_HANDSHAKE" in source
    assert "setBlockNetworkLoads(true)" in source
    assert "setJavaScriptEnabled(false)" in source
    assert "setAllowFileAccess(false)" in source
    assert "setAllowContentAccess(false)" in source
    assert "WebResourceResponse" in source
    assert "addJavascriptInterface" not in source
    assert "file:///" not in source
