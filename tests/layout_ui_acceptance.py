"""Opt-in layout acceptance in installed Chrome, with a local synthetic workflow.

No Android VM, real destination, build toolchain or existing service is used.
"""

from __future__ import annotations

import faulthandler
import hashlib
import io
import json
import secrets
import socket
import threading
import time
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

import qrcode
import uvicorn
from playwright.sync_api import sync_playwright

from fxfetch.config import Settings
from fxfetch.core.workflow import Artifact, Attempt, Workflow, WorkflowResult
from fxfetch.security import password_hash
from fxfetch.service import JobService
from fxfetch.web.api import create_app


class LayoutWorkflow(Workflow):
    def __init__(self) -> None:
        self.entries: list[str] = []
        self.release = threading.Event()
        self.payload = b""

    def run(self, url, output_dir, cancel, on_event=None):
        assert urlsplit(url).hostname == "layout.synthetic.invalid"
        self.entries.append(url)
        if on_event:
            for event in ("browser_preparing", "browser_started", "page_received", "download_started"):
                on_event({"event": event, "url": url, "chain": "android", "network_mode": "direct"})
            on_event({"event": "download_progress", "url": url, "chain": "android", "received_bytes": 3145728, "total_bytes": 8388608})
        if not self.release.wait(40) or cancel.is_set():
            return WorkflowResult("failed", "cancelled", "partial")
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"synthetic UI artifact")
            archive.writestr("classes.dex", b"dex\n035\0synthetic UI artifact")
        self.payload = stream.getvalue()
        path = output_dir / "synthetic-original.apk"
        path.write_bytes(self.payload)
        digest = hashlib.sha256(self.payload).hexdigest()
        if on_event:
            on_event({"event": "file_verified", "url": url, "chain": "android", "sha256": digest, "size": len(self.payload)})
        return WorkflowResult(
            "downloaded", "package_verified", "complete",
            artifacts=[Artifact("apk", path, digest, len(self.payload), url)],
            attempts=[Attempt("android", url, "downloaded", "package_verified", "complete")],
            collector_mode="android_chrome",
        )


def main() -> None:
    output = Path(__file__).resolve().parents[1] / ".runtime/layout-ui" / str(time.time_ns())
    output.mkdir(parents=True)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    password = secrets.token_urlsafe(24)
    settings = Settings(output / "service", password_hash(password), allowed_hosts=(f"127.0.0.1:{port}",))
    workflow = LayoutWorkflow()
    service = JobService(settings, workflow=workflow)
    server = uvicorn.Server(uvicorn.Config(create_app(settings, service=service), log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    if not server.started:
        faulthandler.dump_traceback()
        server.should_exit = True
        raise AssertionError("Synthetic localhost service did not start within 10 seconds")
    sizes = {"desktop": {"width": 1280, "height": 900}, "mobile-375": {"width": 375, "height": 812}, "mobile-390": {"width": 390, "height": 844}}
    screenshots = []
    errors = []
    qr = output / "synthetic-qr.png"
    qrcode.make("https://layout.synthetic.invalid/qr").save(qr)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel="chrome", headless=True, args=["--disable-background-networking"])
            context = browser.new_context(viewport=sizes["desktop"], accept_downloads=True)
            context.route("**/*", lambda route: route.continue_() if route.request.url.startswith(origin + "/") else route.abort())
            page = context.new_page()
            page.on("pageerror", lambda error: errors.append(str(error)))

            def screenshot(state, viewport):
                page.set_viewport_size(sizes[viewport])
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
                for selector in ("#url", "#dropzone", "#download-button", "#job-picker"):
                    bounds = page.locator(selector).bounding_box()
                    assert bounds and 0 <= bounds["x"] and bounds["x"] + bounds["width"] <= sizes[viewport]["width"]
                button = page.locator("#download-button").bounding_box()
                assert button and button["height"] >= 44
                name = f"{viewport}-{state}.png"
                page.screenshot(path=str(output / name), full_page=True)
                screenshots.append(name)

            page.goto(origin)
            page.locator("#password").fill(password)
            page.locator("#login-form button[type=submit]").click()
            page.locator("#workspace").wait_for(state="visible")
            screenshot("empty", "desktop")
            screenshot("empty", "mobile-375")
            page.locator("#image-file").set_input_files(qr)
            page.wait_for_function("document.querySelector('#qr-status').textContent.startsWith('识别到')")
            assert workflow.entries == []
            screenshot("qr", "mobile-390")
            page.locator("#clear-image").click()
            entered = "layout.synthetic.invalid/download/path?source=mobile&token=" + "synthetic-" * 24
            page.locator("#url").fill(entered)
            assert workflow.entries == []
            page.locator("#download-button").click()
            page.locator(".collection-progress.is-active progress").wait_for()
            assert page.locator("#url").input_value() == "https://" + entered
            assert workflow.entries == ["https://" + entered]
            for viewport in sizes:
                screenshot("progress", viewport)
            workflow.release.set()
            page.locator(".download-files .file-link").wait_for(timeout=15000)
            assert page.locator(".download-files").bounding_box()["y"] < page.locator(".collection-progress").bounding_box()["y"]
            assert page.locator(".collection-progress.is-finished").count() == 1
            for viewport in sizes:
                screenshot("downloaded", viewport)
            with page.expect_download() as download:
                page.locator(".download-files .file-link").click()
            assert Path(download.value.path()).read_bytes() == workflow.payload
            page.locator("#refresh").click()
            page.locator("#job-empty").wait_for(state="visible")
            assert len(workflow.entries) == 1
            assert not errors, errors
            browser.close()
        receipt = {
            "status": "passed", "target_requests": 0, "vm_access": False,
            "scope": "installed_chrome_local_synthetic_workflow",
            "screenshots": screenshots, "widths": [1280, 375, 390],
            "checks": ["qr_does_not_submit", "bare_url_normalized", "long_url_no_overflow", "active_and_completed_progress", "file_precedes_history", "download_exact_bytes", "refresh_clears_without_revisit", "no_console_errors"],
        }
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        print(json.dumps({**receipt, "output": str(output)}))
    finally:
        workflow.release.set()
        server.should_exit = True
        thread.join(10)
        listener.close()


if __name__ == "__main__":
    main()
