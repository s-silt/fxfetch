"""Opt-in installed-Chrome acceptance of rejected originals and explicit builds.

All acquisition bytes and build output are synthetic. The API, workflow and
browser clicks are real; no target is resolved, APK installed or toolchain run.
"""

from __future__ import annotations

import hashlib
import io
import json
import secrets
import socket
import threading
import time
import zipfile
from pathlib import Path

import uvicorn
from playwright.sync_api import sync_playwright

from fxfetch.config import Settings
from fxfetch.core.http_client import FetchedResponse, Hop, HttpClient
from fxfetch.core.task_evidence_io import verify_task_archive
from fxfetch.core.web_apk import BuildCapability, BuildResult, WebApkBuilder
from fxfetch.core.workflow import Workflow
from fxfetch.security import password_hash
from fxfetch.service import JobService
from fxfetch.web.api import create_app

ENTRY = "https://entry.synthetic.invalid/"
DEX = b"dex\n035\x00synthetic-dex-content"


def package_bytes(*, corrupt: bool) -> bytes:
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("AndroidManifest.xml", b"synthetic-manifest")
        archive.writestr("classes.dex", DEX)
    data = target.getvalue()
    if corrupt:
        offset = data.index(DEX)
        data = data[:offset] + b"X" + data[offset + 1:]
    return data


class SyntheticClient(HttpClient):
    def __init__(self, raw: bytes):
        super().__init__()
        self.raw = raw
        self.calls: list[str] = []

    def fetch(self, url, destination, *, user_agent, cookie_jar, cancel, referer=None):
        self.calls.append(url)
        if url == ENTRY:
            body = b'<html><a href="/original.apk">Android download</a></html>'
            content_type = "text/html"
        elif url == ENTRY + "original.apk":
            body, content_type = self.raw, "application/vnd.android.package-archive"
        else:
            raise AssertionError("Unexpected synthetic acquisition URL")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)
        headers = {"content-type": content_type, "content-length": str(len(body))}
        return FetchedResponse(url, 200, headers, destination, len(body),
                               hashlib.sha256(body).hexdigest(),
                               (Hop(url, 200, headers, "192.0.2.1", None),))


class SyntheticBuilder(WebApkBuilder):
    def __init__(self):
        self.enabled = True
        self.calls = 0
        self.data = package_bytes(corrupt=False)

    def probe(self):
        return BuildCapability(self.enabled, () if self.enabled else ("synthetic_unavailable",), {})

    def build(self, url, output_dir, package, version, cancel, **options):
        self.calls += 1
        assert not cancel.is_set()
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / "synthetic-generated.apk"
        path.write_bytes(self.data)
        return BuildResult("built", artifact_path=path, filename="synthetic-generated.apk",
                           size=len(self.data), sha256=hashlib.sha256(self.data).hexdigest())


def main() -> None:
    output = Path(__file__).resolve().parents[1] / ".runtime/rejected-file-ui" / str(time.time_ns())
    output.mkdir(parents=True)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    password = secrets.token_urlsafe(24)
    settings = Settings(output / "state", password_hash(password), port=port,
                        allowed_hosts=(f"127.0.0.1:{port}",))
    raw = package_bytes(corrupt=True)
    transport, builder = SyntheticClient(raw), SyntheticBuilder()
    service = JobService(settings, workflow=Workflow(transport), builder=builder)
    server = uvicorn.Server(uvicorn.Config(create_app(settings, service=service),
                                           log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    summary: dict = {"passed": False, "scope": "synthetic bytes; real local API and installed Chrome"}
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert server.started
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel="chrome", headless=True, args=[
                "--disable-background-networking",
                "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
            ])
            try:
                context = browser.new_context(viewport={"width": 1280, "height": 1000}, accept_downloads=True)
                external, builds = [], []

                def route_request(route):
                    if route.request.url.startswith(origin + "/"):
                        return route.continue_()
                    external.append(route.request.url)
                    return route.abort()

                context.route("**/*", route_request)
                context.on("request", lambda request: builds.append(request.url)
                           if request.method == "POST" and request.url.endswith("/web-apk-builds") else None)
                page = context.new_page()
                page.set_default_timeout(15000)
                page.goto(origin)
                page.locator("#password").fill(password)
                page.locator("#login-form button[type=submit]").click()
                page.locator("#workspace").wait_for(state="visible")
                page.locator("#url").fill(ENTRY)
                with page.expect_response(lambda response: response.url == origin + "/api/jobs"
                                          and response.request.method == "POST") as submitted:
                    page.locator("#download-button").click()
                assert submitted.value.status == 202
                job_id = submitted.value.json()["id"]
                job_url = f"{origin}/api/jobs/{job_id}"
                rejected = page.get_by_role("link", name="下载原文件（校验失败）", exact=True)
                rejected.wait_for(state="visible")
                before = context.request.get(job_url).json()
                assert before["outcome"] == "failed" and before["reason_code"] == "archive_invalid"
                assert before["artifacts"] == [] and len(before["rejected_files"]) == 1
                assert before["rejected_files"][0]["validation_status"] == "failed"
                assert not builds and builder.calls == 0
                assert "已取得原包" not in page.locator("#job-content").inner_text()
                panel = page.locator(".build-panel")
                panel.wait_for(state="visible")
                assert panel.evaluate("p => !!(p.compareDocumentPosition(document.querySelector('.collection-progress')) & Node.DOCUMENT_POSITION_FOLLOWING)")
                action = panel.get_by_role("button", name="打包 APK", exact=True)
                assert action.is_enabled()
                for width, height, name in [(1280, 1000, "desktop-before-build"), (375, 812, "mobile-before-build")]:
                    page.set_viewport_size({"width": width, "height": height})
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                    page.screenshot(path=str(output / f"{name}.png"), full_page=True)
                with page.expect_download() as downloaded:
                    rejected.click()
                original_copy = output / "rejected-original.apk"
                downloaded.value.save_as(original_copy)
                assert original_copy.read_bytes() == raw
                assert hashlib.sha256(raw).hexdigest() == before["rejected_files"][0]["sha256"]
                assert not builds and builder.calls == 0
                assert context.request.get(job_url).json()["outcome"] == "failed"
                bundle_link = page.get_by_role("link", name="下载数据包", exact=True)
                bundle_link.wait_for(state="visible")
                assert "APK / IPA 1 个" in page.locator(".data-package").inner_text()
                with page.expect_download() as bundled:
                    bundle_link.click()
                bundle_copy = output / "task.zip"
                bundled.value.save_as(bundle_copy)
                manifest, _ = verify_task_archive(bundle_copy, max_bytes=16 * 1024 * 1024)
                originals = [item for item in manifest["attachments"] if item["kind"] == "package"]
                assert len(originals) == 1 and originals[0]["validation"]["status"] == "failed"
                with zipfile.ZipFile(bundle_copy) as archive:
                    assert archive.read(originals[0]["path"]) == raw
                with page.expect_response(lambda response: response.url.endswith("/web-apk-builds")
                                          and response.request.method == "POST") as built:
                    action.click()
                assert built.value.status == 202
                generated_files = page.locator(".download-files:not(.rejected-files)")
                generated = generated_files.locator("a.file-link")
                generated.wait_for(state="visible")
                after = context.request.get(job_url).json()
                assert after["outcome"] == "failed" and after["reason_code"] == "archive_invalid"
                assert len(after["artifacts"]) == 1 and after["artifacts"][0]["origin"] == "generated_webview"
                assert len(after["rejected_files"]) == 1 and len(builds) == builder.calls == 1
                assert rejected.is_visible() and "生成 APK" in generated_files.inner_text()
                assert "已取得原包" not in page.locator("#job-content").inner_text()
                assert generated.get_attribute("href") != rejected.get_attribute("href")
                with page.expect_download() as generated_download:
                    generated.click()
                generated_copy = output / "generated.apk"
                generated_download.value.save_as(generated_copy)
                assert generated_copy.read_bytes() == builder.data and generated_copy.read_bytes() != raw
                for width, height, name in [(375, 812, "mobile-after-build"), (1280, 1000, "desktop-after-build")]:
                    page.set_viewport_size({"width": width, "height": height})
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                    page.screenshot(path=str(output / f"{name}.png"), full_page=True)
                assert not external and transport.calls == [ENTRY, ENTRY + "original.apk"]
                assert len(builds) == builder.calls == 1
                summary.update(passed=True, original_outcome="failed", validation_reason="archive_invalid",
                               rejected_sha256=hashlib.sha256(raw).hexdigest(), rejected_bytes=len(raw),
                               generated_sha256=hashlib.sha256(builder.data).hexdigest(),
                               build_posts=1, synthetic_builds=1, external_browser_requests=0,
                               acquisition_requests=2, build_panel_before_progress=True,
                               bundled_original_identical=True, bundled_validation="failed",
                               viewport_widths=[1280, 375])
                context.close()
            finally:
                browser.close()
    finally:
        server.should_exit = True
        thread.join(30)
        listener.close()
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    assert not thread.is_alive()
    print(json.dumps({**summary, "output": str(output)}))


if __name__ == "__main__":
    main()
