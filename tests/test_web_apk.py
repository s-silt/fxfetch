from __future__ import annotations

import json
import os
import time
import zipfile
from pathlib import Path
from threading import Event
from xml.etree import ElementTree as ET

import pytest

from fxfetch.core import web_apk
from fxfetch.core.process_limits import ProcessResult
from fxfetch.core.web_apk import WebApkBuilder, WebApkSettings, derive_names


def test_names_preserve_public_suffix_and_numbers() -> None:
    names = derive_names("https://m.123456789.com/path?token=a%26b#fragment")
    assert names.host == "m.123456789.com"
    assert names.display_name == "m.12345.com"
    assert names.filename == "m.12345.com.apk"
    assert names.package_base == "com.a12345.m"
    other = derive_names("http://download.longdomain.com.cn/")
    assert other.filename == "downl.longd.com.cn.apk"
    assert other.package_base == "cn.com.longd.downl"
    assert derive_names("https://longdomain.blogspot.com/").display_name == "longd.blogspot.com"


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "https://user:pass@example.com",
        "http://example.com:0",
        "https://a\\b.example/",
        "https://a..example/",
        "http://example.com/\nnext",
        "https://example.com:99999/",
    ],
)
def test_unsafe_names_rejected(url: str) -> None:
    with pytest.raises(ValueError):
        derive_names(url)


def test_idna_ip_and_windows_names() -> None:
    assert derive_names("https://例子.com/").host == "xn--fsqu00a.com"
    assert derive_names("http://192.0.2.1/").package_base == "ip.ac0000201"
    assert ":" not in derive_names("https://[2001:db8::1]/").filename
    assert derive_names("https://con.example/").filename.startswith("_con.")


def test_template_preserves_url_as_data_and_network_scope(tmp_path: Path) -> None:
    url = 'http://longdomain.example/a?q="<&x=$()#fragment'
    WebApkBuilder._render(tmp_path, url, "longd.examp", "example.app", 8)
    assert json.loads((tmp_path / "assets/config.json").read_text())["url"] == url
    source = (tmp_path / "MainActivity.java").read_text()
    assert url not in source
    assert "handler.cancel()" in source
    assert "addJavascriptInterface" not in source
    assert "setAllowFileAccess(false)" in source
    ns = {"a": "http://schemas.android.com/apk/res/android"}
    manifest = ET.parse(tmp_path / "AndroidManifest.xml").getroot()
    assert manifest.attrib["package"] == "example.app"
    app = manifest.find("application")
    assert app is not None
    assert app.attrib[f"{{{ns['a']}}}debuggable"] == "false"
    assert [p.attrib[f"{{{ns['a']}}}name"] for p in manifest.findall("uses-permission")] == [
        "android.permission.INTERNET"
    ]
    config = ET.parse(tmp_path / "res/xml/network_security_config.xml").getroot()
    assert config.find("base-config").attrib["cleartextTrafficPermitted"] == "false"  # type: ignore[union-attr]
    domain = config.find("domain-config/domain")
    assert domain is not None and domain.text == "longdomain.example"
    assert domain.attrib["includeSubdomains"] == "false"
    assert set(path.name for path in (tmp_path / "assets").iterdir()) == {"config.json"}


def test_https_no_cleartext_exception(tmp_path: Path) -> None:
    WebApkBuilder._render(tmp_path, "https://example.com/", "examp.com", "com.examp", 1)
    config = ET.parse(tmp_path / "res/xml/network_security_config.xml").getroot()
    assert config.find("domain-config") is None


def test_missing_toolchain_disabled_no_fake_apk(tmp_path: Path) -> None:
    builder = WebApkBuilder(WebApkSettings(sdk_root=tmp_path / "missing", java_home=tmp_path / "jdk"))
    capability = builder.probe()
    assert not capability.enabled
    assert "missing_android_jar" in capability.reasons
    assert capability.scratch_limit_method == "monitored_soft_budget"
    output = tmp_path / "output"
    result = builder.build("https://example.com/", output, "com.examp", 1)
    assert result.state == "disabled"
    assert result.artifact_path is None
    assert not output.exists()


def test_cancelled_before_build_does_not_probe(tmp_path: Path) -> None:
    cancel = Event()
    cancel.set()
    result = WebApkBuilder().build("https://example.com/", tmp_path, "com.examp", 1, cancel)
    assert result.state == "cancelled"


@pytest.mark.parametrize(
    "package,version",
    [("bad-package", 1), ("one", 1), ("com.1app", 1), ("com.app", 0), ("com.app", 2_100_000_001)],
)
def test_invalid_package_input_fails_before_tools(tmp_path: Path, package: str, version: int) -> None:
    with pytest.raises(ValueError):
        WebApkBuilder().build("https://example.com/", tmp_path, package, version)


@pytest.mark.parametrize("mode", ["bad_signature", "cancel", "scratch_budget", "success"])
def test_build_pipeline_requires_signature_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    sdk, jdk, scratch_root = tmp_path / "sdk", tmp_path / "jdk", tmp_path / "scratch"
    scratch_root.mkdir()
    suffix = ".exe" if os.name == "nt" else ""
    for path in [
        jdk / "bin" / ("java" + suffix),
        jdk / "bin" / ("javac" + suffix),
        sdk / "build-tools/37.0.0" / ("aapt2" + suffix),
        sdk / "build-tools/37.0.0" / ("zipalign" + suffix),
        sdk / "build-tools/37.0.0/lib/d8.jar",
        sdk / "build-tools/37.0.0/lib/apksigner.jar",
        sdk / "platforms/android-35/android.jar",
        tmp_path / "private.keystore",
        tmp_path / "password",
    ]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()

    commands: list[list[str]] = []
    cancel = Event()

    def run(command: list[str], **kwargs: object) -> ProcessResult:
        commands.append(command)
        cwd = kwargs["cwd"]
        assert isinstance(cwd, Path)
        if mode == "cancel":
            cancel.set()
        if mode == "scratch_budget":
            time.sleep(0.2)
        if "link" in command:
            with zipfile.ZipFile(cwd / "base.apk", "w") as archive:
                archive.writestr("AndroidManifest.xml", b"synthetic manifest")
        if Path(command[0]).stem == "javac":
            (cwd / "classes/MainActivity.class").write_bytes(b"synthetic class")
        if "com.android.tools.r8.D8" in command:
            (cwd / "dex/classes.dex").write_bytes(b"synthetic dex")
        if Path(command[0]).stem == "zipalign":
            (cwd / "aligned.apk").write_bytes((cwd / "base.apk").read_bytes())
        if "sign" in command:
            (cwd / "signed.apk").write_bytes((cwd / "aligned.apk").read_bytes())
        if "verify" in command:
            if mode == "success":
                return ProcessResult(0, stdout=b"certificate SHA-256 digest: " + b"a" * 64)
            return ProcessResult(1, stdout=b"not verified")
        return ProcessResult(0)

    monkeypatch.setattr(web_apk, "run_limited", run)
    builder = WebApkBuilder(
        WebApkSettings(
            sdk_root=sdk,
            java_home=jdk,
            scratch_root=scratch_root,
            signing_keystore=tmp_path / "private.keystore",
            signing_password_file=tmp_path / "password",
            max_scratch_bytes=64 if mode == "scratch_budget" else 8 * 1024**3,
        )
    )
    events: list[dict] = []
    result = builder.build(
        "https://example.com/", tmp_path / "output", "com.examp", 1, cancel, on_event=events.append
    )
    expected = {
        "bad_signature": ("failed", "signature_verification_failed"),
        "cancel": ("cancelled", "cancelled"),
        "scratch_budget": ("failed", "scratch_soft_budget_exceeded"),
        "success": ("built", None),
    }
    assert (result.state, result.reason_code) == expected[mode]
    if mode == "success":
        assert result.artifact_path is not None and result.artifact_path.is_file()
        assert [event["event"] for event in events] == [
            "build_preparing", "build_resources", "build_compiling", "build_signing",
            "build_verifying", "build_saving",
        ]
    else:
        assert not (tmp_path / "output").exists()
    assert not any(scratch_root.iterdir())
    if mode == "bad_signature":
        assert any("--release" in command for command in commands)
    assert all("https://example.com/" not in argument for command in commands for argument in command)
