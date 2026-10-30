"""Opt-in Chrome UI -> real installed fxapk, synthetic saved materials only.

Set FXAPK_EXECUTABLE to the installed executable. No acquisition transport is
used, no synthetic domain is resolved, and no APK is installed or executed.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import socket
import threading
import time
import zipfile
from pathlib import Path

import uvicorn
from playwright.sync_api import sync_playwright
from test_analysis_service import seed_job

from fxfetch.config import Settings
from fxfetch.core.workflow import WorkflowResult
from fxfetch.security import password_hash, token_hash
from fxfetch.service import JobService
from fxfetch.web.api import create_app


class SyntheticCollection:
    def __init__(self):
        self.entries = []

    def run(self, url, output_dir, cancel, on_event=None):
        self.entries.append(url)
        return WorkflowResult("failed", "synthetic_complete", "partial")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    executable = os.environ.get("FXAPK_EXECUTABLE")
    assert executable and shutil.which(executable), "Set FXAPK_EXECUTABLE to an installed fxapk"
    output = Path(__file__).resolve().parents[1] / ".runtime/upstream-sync-d78f5da/ui" / str(time.time_ns())
    output.mkdir(parents=True)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    password = secrets.token_urlsafe(24)
    settings = Settings(output / "state", password_hash(password), port=port,
                        allowed_hosts=(f"127.0.0.1:{port}",), fxapk_executable=executable)
    collection = SyntheticCollection()
    service = JobService(settings, workflow=collection)
    server = uvicorn.Server(uvicorn.Config(create_app(settings, service=service),
                                           log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    end = time.monotonic() + 10
    while not server.started and time.monotonic() < end:
        time.sleep(0.05)
    assert server.started
    summary = {"passed": False, "scope": "local Chrome and real offline fxapk; synthetic evidence only"}
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel="chrome", headless=True,
                args=["--disable-background-networking", "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"])
            context = browser.new_context(viewport={"width": 1280, "height": 900}, accept_downloads=True)
            external_requests = []
            analysis_posts = []

            def route_request(route):
                if route.request.url.startswith(origin + "/"):
                    return route.continue_()
                external_requests.append(route.request.url)
                return route.abort()

            context.route("**/*", route_request)
            context.on("request", lambda request: analysis_posts.append(request.url)
                       if request.method == "POST" and request.url.endswith("/analyses") else None)
            page = context.new_page()
            page.goto(origin)
            page.locator("#password").fill(password)
            with page.expect_response(lambda response: response.url == origin + "/api/jobs"
                                      and response.request.method == "DELETE"):
                page.locator("#login-form button[type=submit]").click()
            page.locator("#workspace").wait_for(state="visible")
            cookie = next(item for item in context.cookies() if item["name"] == "fxfetch_session")
            owner = service.store.session(token_hash(cookie["value"]))["id"]
            job = seed_job(service, output, owner, "analysis-ui")
            source, _ = service.data_package_file(owner, job["id"])
            source_hash = digest(source)
            assert service.analysis.list(owner, job["id"]) == []

            # A synthetic background collection exercises the ordinary list
            # refresh, then select the separately seeded saved-material task.
            page.locator("#url").fill("refresh.example.test/")
            with page.expect_response(lambda response: response.url == origin + "/api/jobs"
                                      and response.request.method == "POST"):
                page.locator("#download-button").click()
            page.locator(f'#job-picker option[value="{job["id"]}"]').wait_for(state="attached")
            page.locator("#job-picker").select_option(job["id"])
            action = page.get_by_role("button", name="离线分析数据包", exact=True)
            action.wait_for(state="visible")
            page.wait_for_function("() => [...document.querySelectorAll('button')].some(b=>b.textContent==='离线分析数据包'&&!b.disabled)")
            assert service.analysis.list(owner, job["id"]) == [] and analysis_posts == []
            assert len(collection.entries) == 1

            # Rendering and downloading saved evidence have no analysis side effect.
            with page.expect_download() as data_download:
                page.get_by_role("link", name="下载数据包", exact=True).click()
            data_copy = output / "source-download.zip"
            data_download.value.save_as(data_copy)
            assert digest(data_copy) == source_hash
            assert service.analysis.list(owner, job["id"]) == [] and analysis_posts == []
            page.screenshot(path=str(output / "desktop-before-analysis.png"), full_page=True)
            page.set_viewport_size({"width": 375, "height": 812})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(output / "mobile-375-before-analysis.png"), full_page=True)

            with page.expect_response(lambda response: response.request.method == "POST"
                                      and response.url.endswith(f"/jobs/{job['id']}/analyses")) as started:
                action.click()
            assert started.value.status == 202
            analysis_id = started.value.json()["id"]
            status_url = f"{origin}/api/jobs/{job['id']}/analyses/{analysis_id}"
            deadline = time.monotonic() + 180
            status = {}
            while time.monotonic() < deadline:
                status = context.request.get(status_url).json()
                if status["state"] not in {"queued", "running"}:
                    break
                page.wait_for_timeout(250)
            assert status.get("state") == "completed", status
            link = page.get_by_role("link", name="下载分析报告 ZIP", exact=True)
            link.wait_for(state="visible", timeout=15000)
            report_url = origin + link.get_attribute("href")
            with page.expect_download() as report_download:
                link.click()
            report = output / "analysis-report.zip"
            report_download.value.save_as(report)
            assert digest(report) == status["report_sha256"]
            with zipfile.ZipFile(report) as archive:
                assert sorted(archive.namelist()) == ["analysis.json", "report/input.json"]
                receipt = json.loads(archive.read("analysis.json"))
                native = json.loads(archive.read("report/input.json"))
                assert receipt["analysis"]["online"] is False
                assert native["meta"]["online"] is False
                assert native["meta"]["web_evidence"]["file_count"] > 0
                assert "command" not in receipt["analysis"] and "executable" not in receipt["analysis"]

            internal = json.loads((settings.root / "analyses" / analysis_id / "output/analysis.json").read_text())
            assert "--offline" in internal["analysis"]["command"]
            assert internal["analysis"]["returncode"] == 0
            assert Path(internal["analysis"]["command"][0]).samefile(executable)
            assert service.store.get_job(owner, job["id"])["outcome"] == "blocked"
            assert digest(source) == source_hash
            for _ in range(3):
                assert context.request.get(status_url).json()["id"] == analysis_id
                response = context.request.get(report_url)
                assert response.status == 200 and hashlib.sha256(response.body()).hexdigest() == digest(report)
            assert len(service.analysis.list(owner, job["id"])) == 1 and len(analysis_posts) == 1
            assert not external_requests and len(collection.entries) == 1
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(output / "mobile-375-analysis-completed.png"), full_page=True)
            page.locator(".analysis-panel").screenshot(path=str(output / "mobile-375-analysis-panel.png"))
            page.set_viewport_size({"width": 1280, "height": 900})
            page.screenshot(path=str(output / "desktop-analysis-completed.png"), full_page=True)
            page.locator(".analysis-panel").screenshot(path=str(output / "desktop-analysis-panel.png"))
            page.locator("#refresh").click()
            page.wait_for_function("() => document.querySelector('#job-picker').options.length===1 && document.querySelector('#job-picker').value===''")
            assert report.is_file() and source.is_file() and len(analysis_posts) == 1
            summary.update(passed=True, analysis_id=analysis_id, original_outcome="blocked",
                           analysis_state="completed", analysis_submissions=1, offline=True,
                           report_sha256=digest(report), source_sha256=source_hash,
                           report_size=report.stat().st_size, native_file_count=native["meta"]["web_evidence"]["file_count"],
                           external_browser_requests=0, synthetic_collections=1)
            context.close()
            browser.close()
    finally:
        server.should_exit = True
        thread.join(30)
        listener.close()
        (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    assert not thread.is_alive()
    print(json.dumps({**summary, "output": str(output)}))


if __name__ == "__main__":
    main()
