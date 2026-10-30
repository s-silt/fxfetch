"""Opt-in installed-Chrome check; all collection is synthetic and local."""

from __future__ import annotations

import json
import secrets
import socket
import threading
import time
from pathlib import Path

import uvicorn
from browser_capture_acceptance import APK
from playwright.sync_api import sync_playwright

from fxfetch.config import Settings
from fxfetch.core.task_evidence_verify import verify_task_archive
from fxfetch.core.workflow import Workflow, WorkflowResult
from fxfetch.security import password_hash
from fxfetch.service import JobService
from fxfetch.web.api import create_app


class SyntheticWorkflow(Workflow):
    def __init__(self):
        self.entries = []

    def run(self, url, output_dir, cancel, on_event=None):
        self.entries.append(url)
        return WorkflowResult("failed", "synthetic_complete", "partial")


def main() -> None:
    output = Path(__file__).resolve().parents[1] / ".runtime/url-input-ui" / str(time.time_ns())
    output.mkdir(parents=True)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    password = secrets.token_urlsafe(24)
    settings = Settings(output / "state", password_hash(password), allowed_hosts=(f"127.0.0.1:{port}",))
    workflow = SyntheticWorkflow()
    service = JobService(settings, workflow=workflow)
    server = uvicorn.Server(uvicorn.Config(create_app(settings, service=service), log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert server.started
    cases = [
        ("entry.synthetic.invalid/path?a=%2F#x", "https://entry.synthetic.invalid/path?a=%2F#x"),
        ("www.entry.synthetic.invalid", "https://www.entry.synthetic.invalid"),
        ("//entry.synthetic.invalid/path", "https://entry.synthetic.invalid/path"),
        ("https:/entry.synthetic.invalid/path", "https://entry.synthetic.invalid/path"),
        ("http://entry.synthetic.invalid/path", "http://entry.synthetic.invalid/path"),
    ]
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel="chrome", headless=True, args=["--disable-background-networking"])
            context = browser.new_context(viewport={"width": 1100, "height": 850})
            direct_requests, downloads = [], []
            def route_request(route):
                if route.request.url.startswith(origin + "/"):
                    return route.continue_()
                if route.request.url == "https://files.synthetic.invalid/app.apk?ticket=once":
                    direct_requests.append(route.request.url)
                    return route.fulfill(status=200, body=APK, headers={
                        "Content-Type": "application/vnd.android.package-archive",
                        "Content-Disposition": 'attachment; filename="synthetic.apk"',
                    })
                return route.abort()
            context.route("**/*", route_request)
            context.on("page", lambda tab: tab.on("download", lambda item: downloads.append(item)))
            page = context.new_page()
            page.goto(origin)
            page.locator("#password").fill(password)
            page.locator("#login-form button[type=submit]").click()
            page.locator("#workspace").wait_for(state="visible")
            assert "域名或完整网址" in page.locator("#host-hint").inner_text()
            page.locator("#url").fill("files.synthetic.invalid/app.apk?ticket=once")
            page.locator("#direct-download-link").wait_for(state="visible")
            assert page.locator("#direct-download-link").get_attribute("href") == "https://files.synthetic.invalid/app.apk?ticket=once"
            assert workflow.entries == [] and direct_requests == []
            page.screenshot(path=str(output / "direct-desktop.png"), full_page=True)
            page.set_viewport_size({"width": 375, "height": 812})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(output / "direct-mobile.png"), full_page=True)
            page.locator("#direct-download-link").click()
            deadline = time.monotonic() + 10
            while not downloads and time.monotonic() < deadline:
                page.wait_for_timeout(50)
            assert len(downloads) == 1 and len(direct_requests) == 1 and workflow.entries == []
            target = output / "frontend-synthetic.apk"
            downloads[0].save_as(target)
            assert target.read_bytes() == APK
            page.set_viewport_size({"width": 1100, "height": 850})
            for index, (entered, expected) in enumerate(cases):
                page.locator("#url").fill(entered)
                assert len(workflow.entries) == index
                with page.expect_response(lambda response: response.url == origin + "/api/jobs" and response.request.method == "POST") as submitted:
                    page.locator("#download-button").click()
                response = submitted.value
                assert response.status == 202
                assert response.request.post_data_json["url"] == entered
                assert response.json()["input"]["entry_url"] == expected
                page.wait_for_function("value => document.querySelector('#url').value === value", arg=expected)
                page.wait_for_function("() => !document.querySelector('#download-button').disabled")
                deadline = time.monotonic() + 5
                while len(workflow.entries) <= index and time.monotonic() < deadline:
                    time.sleep(0.01)
                assert workflow.entries[index] == expected
            bundle_link = page.get_by_role("link", name="下载数据包", exact=True)
            bundle_link.wait_for(state="visible", timeout=15000)
            bundle_url = bundle_link.get_attribute("href")
            assert bundle_url and bundle_url.endswith("/data-package")
            with page.expect_download() as bundle_download:
                bundle_link.click()
            bundle_path = output / "task-data.zip"
            bundle_download.value.save_as(bundle_path)
            manifest, _ = verify_task_archive(bundle_path, max_bytes=16 * 1024 * 1024)
            assert manifest["package_result"]["outcome"] == "failed"
            assert len(workflow.entries) == len(cases)
            stranger = browser.new_context()
            try:
                assert stranger.request.get(origin + bundle_url).status == 401
            finally:
                stranger.close()
            page.locator("#url").fill("javascript:alert(1)")
            with page.expect_response(lambda response: response.url.endswith("/api/preview")) as rejected:
                page.locator("#download-button").click()
            assert rejected.value.status == 400
            page.wait_for_function("() => !document.querySelector('#download-button').disabled")
            assert len(workflow.entries) == len(cases)
            assert page.locator("#url").input_value() == "javascript:alert(1)"
            assert "不支持" in page.locator("#notice").inner_text()
            page.locator("#url").fill("entry.synthetic.invalid/path")
            page.screenshot(path=str(output / "desktop.png"), full_page=True)
            page.set_viewport_size({"width": 375, "height": 812})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(output / "mobile.png"), full_page=True)
            browser.close()
        receipt = {"passed": True, "normalized_cases": len(cases), "rejected_foreign_scheme": True, "target_requests": 0, "frontend_direct_download_verified": True, "data_package_download_verified": True, "data_package_unauthenticated_rejected": True, "synthetic_download_requests": 1, "collection": "injected_synthetic_workflow", "output": str(output)}
        (output / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt))
    finally:
        server.should_exit = True
        thread.join(10)
        listener.close()


if __name__ == "__main__":
    main()
