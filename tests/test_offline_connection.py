import hashlib
import json

import pytest

from fxfetch.core.offline import OfflineBundle
from fxfetch.core.web_apk import WebApkBuilder, WebApkSettings, _BuildStopped


def builder_with_font(tmp_path):
    font = tmp_path / "font.otf"
    license_path = tmp_path / "license.txt"
    raw = b"OTTOsynthetic-font-for-controlled-rendering"
    font.write_bytes(raw)
    license_path.write_text("SIL OPEN FONT LICENSE Version 1.1")
    return WebApkBuilder(WebApkSettings(
        offline_font_path=font, offline_font_license_path=license_path,
        offline_font_sha256=hashlib.sha256(raw).hexdigest(), offline_font_size=len(raw),
    ))


def test_missing_snapshot_has_ordinary_connection_content_and_actual_font(tmp_path):
    builder = builder_with_font(tmp_path)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    url = "https://long.example/path?synthetic=complete#fragment"
    result = builder._prepare_offline(scratch, url, None)
    kind, reason, font, byte_count, files = result
    assert kind == "connection_page" and reason == "snapshot_unavailable" and font.applied
    config = json.loads((scratch / "assets/config.json").read_text())
    assert config == {"url": url, "offline": True}
    page = (scratch / "assets/site/index.html").read_text(encoding="utf-8")
    assert "long.example" in page and "未保存网站内容" in page
    assert "synthetic=complete" not in page
    assert all(value not in page for value in ("fxfetch", "生成", "证据", "Cookie", str(tmp_path)))
    assert "font-family:OfflineSC,sans-serif" in (scratch / "assets/site/assets/style.css").read_text()
    assert (scratch / "assets/licenses/offline-sc.txt").is_file()
    assert byte_count > len(page.encode()) and files == 4


def test_valid_snapshot_has_priority_and_english_font(tmp_path):
    builder = builder_with_font(tmp_path)
    source = tmp_path / "source.html"
    source.write_text("<p>Actual saved English page</p>")
    saved = tmp_path / "saved"
    assert OfflineBundle().build(source, "https://page.example/", {}, saved).available
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    kind, reason, font, _, _ = builder._prepare_offline(scratch, "https://page.example/", saved)
    assert kind == "site_snapshot" and reason == "saved_static_content" and font.applied
    assert "Actual saved English page" in (scratch / "assets/site/index.html").read_text()


def test_invalid_snapshot_falls_back_without_target_content(tmp_path):
    source = tmp_path / "invalid"
    source.mkdir()
    (source / "index.html").write_text("<script>remoteBusiness()</script>")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    kind, reason, _, _, _ = WebApkBuilder()._prepare_offline(scratch, "https://page.example/", source)
    assert kind == "connection_page" and reason == "offline_snapshot_invalid"
    assert "remoteBusiness" not in (scratch / "assets/site/index.html").read_text()


def test_font_not_configured_is_explicit_and_no_network_is_needed(tmp_path):
    kind, _, font, byte_count, count = WebApkBuilder()._prepare_offline(tmp_path, "https://page.example/", None)
    assert kind == "connection_page" and not font.applied and font.reason == "font_not_configured"
    assert byte_count > 0 and count == 2


def test_generated_apk_budget_default_is_thirty_decimal_megabytes():
    assert WebApkSettings().max_apk_bytes == 30_000_000


@pytest.mark.parametrize("code", [
    "offline_bundle_unsafe_path", "offline_bundle_invalid", "offline_bundle_file_limit",
    "offline_bundle_byte_limit", "offline_bundle_invalid_image",
])
def test_snapshot_security_guards_never_fall_back(tmp_path, monkeypatch, code):
    def guarded(source, destination):
        raise _BuildStopped(code)

    monkeypatch.setattr(WebApkBuilder, "_copy_offline", staticmethod(guarded))
    with pytest.raises(_BuildStopped) as raised:
        WebApkBuilder()._prepare_offline(tmp_path, "https://page.example/", tmp_path / "source")
    assert raised.value.code == code
    assert not (tmp_path / "assets/site/index.html").exists()
