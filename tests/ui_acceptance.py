"""Opt-in Chrome UI acceptance against a loopback service and synthetic workflow.

Run explicitly: python tests/ui_acceptance.py. Never collected by pytest.
Uses installed Chrome only; never installs a browser or contacts target URLs.
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
from urllib.parse import urlsplit

import qrcode
import uvicorn
from PIL import Image
from pillow_heif import register_heif_opener
from playwright.sync_api import sync_playwright

from fxfetch.build_setup import load_builder
from fxfetch.config import Settings
from fxfetch.core.discovery import Candidate
from fxfetch.core.offline import OfflineBundle
from fxfetch.core.web_apk import derive_names
from fxfetch.core.workflow import Artifact, Attempt, Workflow, WorkflowResult
from fxfetch.security import password_hash
from fxfetch.service import JobService
from fxfetch.web.api import create_app

BASE = Path(__file__).resolve().parents[1]
QA = BASE / ".runtime" / "ui-qa"


class SyntheticWorkflow(Workflow):
    def __init__(self) -> None:
        self.entries: list[str] = []

    def run(self, url: str, output_dir: Path, cancel: threading.Event, on_event=None) -> WorkflowResult:
        if not (urlsplit(url).hostname or "").endswith(".invalid"):
            raise AssertionError("Only synthetic .invalid inputs are allowed")
        self.entries.append(url)
        output_dir.mkdir(parents=True, exist_ok=True)
        if "progress-demo" in url:

            def emit(event, **fields):
                if on_event:
                    on_event({"event": event, "url": url, "chain": "android", **fields})

            emit("request")
            emit("redirect", from_url=url, to_url=url + "?redirect=observed", mechanism="http")
            emit("page_received", status=200)
            emit(
                "download_candidate", label='<img src=x onerror="window.__progress_xss=1">', kind="direct_apk"
            )
            emit("download_started", received_bytes=1024, package_unverified=True)
            cancel.wait(5)
            emit("download_progress", received_bytes=2048, total_bytes=4096, percent=50, complete=False)
            cancel.wait(5)
            emit("file_verifying")
            return WorkflowResult("failed", "task_timeout", "partial", offline={"available": False})
        if "challenge-copy" in url:
            return WorkflowResult("blocked", "challenge_detected", "partial", offline={"available": False})
        if "script-budget-copy" in url:
            return WorkflowResult(
                "failed", "flutter_source_download_limit", "partial", offline={"available": False}
            )
        if "multi-choice" in url:
            choices = [
                Candidate(
                    "https://first.synthetic.invalid/app.apk",
                    "direct_apk",
                    url,
                    '<img src=x onerror="window.__candidate_xss=1">',
                ),
                Candidate(
                    "https://original-success.synthetic.invalid/app.apk?chosen=second",
                    "direct_apk",
                    url,
                    "第二个应用",
                ),
            ]
            return WorkflowResult(
                "failed",
                "candidate_selection_required",
                "partial",
                candidates=choices,
                selection_candidates=choices,
                offline={"available": False},
            )
        if "original-success" in url:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"synthetic manifest")
                archive.writestr("classes.dex", b"dex\n035\0synthetic")
            data = buffer.getvalue()
            package = output_dir / "synthetic-original.apk"
            package.write_bytes(data)
            return WorkflowResult(
                "downloaded",
                "package_verified",
                "complete",
                artifacts=[Artifact("apk", package, hashlib.sha256(data).hexdigest(), len(data), url)],
                attempts=[
                    Attempt("android", url, None, "landing_candidate_discovered", "partial"),
                    Attempt("android", url, "downloaded", "package_verified", "complete"),
                ],
                offline={"available": False},
            )
        if "resource-snapshot" in url:
            site = output_dir / "offline" / "site"
            original = output_dir / "saved-source.html"
            original.write_text(
                "<!doctype html><html><body><h1>Saved synthetic website</h1><p>Actual saved static page content.</p></body></html>",
                encoding="utf-8",
            )
            bundle = OfflineBundle().build(original, url, {}, site)
            assert bundle.available
            return WorkflowResult(
                "failed",
                "browser_required",
                "partial",
                attempts=[Attempt("android", url, "failed", "browser_required", "partial")],
                offline={
                    "available": True,
                    "entry": str(bundle.entry),
                    "bytes": bundle.bytes,
                    "coverage": "partial",
                    "reasons": ["static_snapshot_only"],
                },
            )
        if "slow" in url:
            cancel.wait(3)
        return WorkflowResult(
            "failed",
            "browser_required",
            "partial",
            attempts=[Attempt("android", url, "failed", "browser_required", "partial")],
            offline={"available": False},
        )


def qr_image(path: Path) -> None:
    values = [
        "https://first.synthetic.invalid/a",
        "https://second.synthetic.invalid/b",
        '<img src=x onerror="window.__xss=1">',
    ]
    images = [qrcode.make(value).convert("RGB").resize((310, 310)) for value in values]
    combined = Image.new("RGB", (970, 350), "white")
    for index, image in enumerate(images):
        combined.paste(image, (10 + index * 320, 20))
    combined.save(path)


def main() -> None:
    QA.mkdir(parents=True, exist_ok=True)
    screenshots = QA / "screenshots"
    screenshots.mkdir(exist_ok=True)
    run_root = QA / ("run-" + secrets.token_hex(5))
    workflow = SyntheticWorkflow()
    password = secrets.token_urlsafe(24)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    settings = Settings(run_root, password_hash(password), allowed_hosts=(f"127.0.0.1:{port}",))
    service = JobService(
        settings, workflow=workflow, builder=load_builder(BASE / ".runtime/build-acceptance")
    )
    app = create_app(settings, service=service)
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, access_log=False, log_level="error")
    )
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("loopback server did not start")
        time.sleep(0.05)
    results: list[str] = []
    requests: list[str] = []
    console_errors: list[str] = []
    qr = QA / "synthetic-multiple.png"
    qr_image(qr)
    phone = QA / "synthetic-phone.heic"
    register_heif_opener(thumbnails=False)
    phone_image = qrcode.make("https://phone.synthetic.invalid/app.apk?source=photo").convert("RGB")
    phone_exif = Image.Exif()
    phone_exif[270] = "synthetic private image metadata"
    phone_image.save(phone, format="HEIF", exif=phone_exif)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel="chrome", headless=True)
            context = browser.new_context(viewport={"width": 1440, "height": 1100}, accept_downloads=True)

            def guard(route) -> None:
                parsed = urlsplit(route.request.url)
                if parsed.scheme in {"http", "https"} and (
                    parsed.hostname != "127.0.0.1" or parsed.port != port
                ):
                    raise AssertionError("Browser attempted non-loopback access")
                requests.append(route.request.url)
                route.continue_()

            context.route("**/*", guard)
            page = context.new_page()
            page.on("pageerror", lambda error: console_errors.append(str(error)))
            page.goto(origin)
            page.locator("#login-panel").wait_for(state="visible")
            page.locator("#password").fill("synthetic-wrong-password")
            page.get_by_role("button", name="登录", exact=True).click()
            page.get_by_text("密码不正确，请重新输入。", exact=True).wait_for()
            page.locator("#password").fill(password)
            page.get_by_role("button", name="登录", exact=True).click()
            page.locator("#workspace").wait_for(state="visible")
            assert not workflow.entries
            results.append("login_and_error")
            page.screenshot(path=str(screenshots / "desktop-empty.png"), full_page=True)
            page.locator("#url").fill("https://download.synthetic.invalid/app?synthetic=1#fragment")

            # Abort before the first submission reaches the server, then retry the same operation.
            keys: list[str] = []

            def interrupted_submit(route) -> None:
                if route.request.method != "POST":
                    route.fallback()
                    return
                keys.append(route.request.headers.get("idempotency-key", ""))
                if len(keys) == 1:
                    route.abort("failed")
                else:
                    route.fallback()

            page.route("**/api/jobs", interrupted_submit)
            page.locator("#download-button").click()
            page.get_by_role("button", name="重试提交（同一次任务）").wait_for()
            assert not workflow.entries
            page.locator("#download-button").click()
            page.get_by_role("button", name="打包 APK", exact=True).wait_for(timeout=15000)
            assert len(keys) == 2 and keys[0] == keys[1] and keys[0]
            assert len(workflow.entries) == 1
            page.unroute("**/api/jobs", interrupted_submit)
            results.append("explicit_submit_idempotent_retry")
            page.get_by_role("button", name="打包 APK", exact=True).click()
            page.get_by_text("APK 已生成", exact=False).first.wait_for(timeout=60000)
            with page.expect_download() as download_info:
                page.get_by_role("link", name="下载", exact=True).click()
            download = download_info.value
            assert download.suggested_filename == derive_names("https://download.synthetic.invalid/").filename
            assert not download.failure()
            assert len(workflow.entries) == 1
            results.append("real_signed_apk_build_and_download")
            built_job = page.request.get(
                origin + "/api/jobs/" + page.locator("#job-picker").input_value()
            ).json()
            built_detail = built_job["builds"][-1]["result"]
            assert built_detail["offline_content_kind"] == "connection_page"
            assert built_detail["resource_files"] > 0 and built_detail["resource_bytes"] > 0
            build_status = page.locator(".build-status").filter(has_text="成品大小：")
            assert "仅含离线入口页，未取得网站离线内容；打开网站仍需联网。" in build_status.inner_text()
            assert f"已打包资源：{built_detail['resource_files']} 项" in build_status.inner_text()
            if built_detail["size"] < 10 * 1024 * 1024:
                assert "当前实际页面与资源较少，成品体积较小；体积随内容变化。" in build_status.inner_text()
            assert "signing_certificate" not in build_status.inner_text()
            page.screenshot(path=str(screenshots / "desktop-result.png"), full_page=True)
            old_job = page.locator("#job-picker").input_value()
            with page.expect_response(
                lambda response: response.request.method == "DELETE" and response.url.endswith("/api/jobs")
            ) as cleared:
                page.reload()
            assert cleared.value.status == 200
            page.locator("#job-empty").wait_for(state="visible")
            assert page.locator("#job-picker").input_value() == ""
            assert page.evaluate("localStorage.getItem('fxfetch.job-id')") is None
            assert page.request.get(origin + "/api/jobs").json() == {"jobs": []}
            assert page.request.get(origin + "/api/jobs/" + old_job).status == 404
            assert len(workflow.entries) == 1
            results.append("browser_reload_clears_without_recollection")
            page.screenshot(path=str(screenshots / "desktop-cleared.png"), full_page=True)
            baseline = len([url for url in requests if "/api/jobs" in url])
            page.wait_for_timeout(5500)
            assert len([url for url in requests if "/api/jobs" in url]) == baseline
            results.append("terminal_polling_stopped")

            page.locator("#image-file").set_input_files(qr)
            page.locator("#qr-candidates .candidate").nth(2).wait_for()
            assert page.locator("#qr-candidates input:checked").count() == 0
            assert len(workflow.entries) == 1
            assert page.locator("#qr-candidates img").count() == 0
            assert page.evaluate("window.__xss || 0") == 0
            page.locator("#qr-candidates input:not(:disabled)").nth(1).check()
            page.locator("#url").fill("https://edited.synthetic.invalid/changed?case=2")
            page.screenshot(path=str(screenshots / "desktop-qr.png"), full_page=True)
            page.set_viewport_size({"width": 390, "height": 844})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(screenshots / "mobile-qr.png"), full_page=True)
            page.locator("#download-button").click()
            page.locator("#job-content .job-url").filter(has_text="edited.synthetic.invalid").wait_for()
            assert workflow.entries[-1] == "https://edited.synthetic.invalid/changed?case=2"
            results.append("qr_file_multicode_selection_edit_and_xss")

            # Same synthetic PNG through DataTransfer drop and clipboard paste.
            file_data = list(qr.read_bytes())
            page.locator("#clear-image").click()
            page.evaluate(
                """(bytes) => { const transfer = new DataTransfer(); transfer.items.add(new File([new Uint8Array(bytes)], 'synthetic.png', {type:'image/png'})); document.querySelector('#dropzone').dispatchEvent(new DragEvent('drop', {bubbles:true,cancelable:true,dataTransfer:transfer})); }""",
                file_data,
            )
            page.locator("#qr-candidates .candidate").nth(2).wait_for()
            page.locator("#clear-image").click()
            page.evaluate(
                """(bytes) => { const transfer = new DataTransfer(); transfer.items.add(new File([new Uint8Array(bytes)], 'synthetic.png', {type:'image/png'})); document.querySelector('#url').dispatchEvent(new ClipboardEvent('paste', {bubbles:true,cancelable:true,clipboardData:transfer})); }""",
                file_data,
            )
            page.locator("#qr-candidates .candidate").nth(2).wait_for()
            assert len(workflow.entries) == 2
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            results.append("qr_drop_and_paste_no_target_access")
            page.screenshot(path=str(screenshots / "mobile-result.png"), full_page=True)
            # Phone image formats use an authenticated server-generated JPEG,
            # because Chrome cannot render the source HEIC itself.
            page.locator("#clear-image").click()
            page.set_viewport_size({"width": 375, "height": 812})
            count_before_upload = len(workflow.entries)
            with page.expect_response(
                lambda response: "/api/qr-images" in response.url and response.request.method == "POST"
            ) as upload_response:
                page.locator("#image-file").set_input_files(phone)
            phone_result = upload_response.value.json()
            assert upload_response.value.status == 200 and phone_result["format"] == "HEIF"
            page.locator("#qr-candidates .candidate").first.wait_for()
            page.wait_for_function(
                """() => { const image=document.querySelector('#image-preview'); return image.complete && image.naturalWidth > 0 && image.getAttribute('src').includes('/thumbnail'); }"""
            )
            preview_source = page.locator("#image-preview").get_attribute("src")
            assert preview_source == phone_result["thumbnail_url"]
            assert len(workflow.entries) == count_before_upload
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(screenshots / "mobile-375-heic-thumbnail.png"), full_page=True)
            results.append("mobile_375_heic_server_thumbnail_without_submission")

            # A plain non-image is rejected before upload; a forged JPEG reaches
            # content validation and is rejected without files, records or jobs.
            page.locator("#clear-image").click()
            upload_count = len([url for url in requests if "/api/qr-images" in url])
            page.locator("#image-file").set_input_files(
                {"name": "synthetic.txt", "mimeType": "text/plain", "buffer": b"plain text"}
            )
            page.get_by_text(
                "只允许上传图片：手机截图、PNG、JPEG、HEIC、WebP、AVIF、BMP、静态 GIF 或单页 TIFF。",
                exact=True,
            ).wait_for()
            assert len([url for url in requests if "/api/qr-images" in url]) == upload_count
            before_files = set((run_root / "images").iterdir())
            with service.store.connect() as database:
                before_records = database.execute("SELECT COUNT(*) FROM images").fetchone()[0]
            with page.expect_response(
                lambda response: "/api/qr-images" in response.url and response.request.method == "POST"
            ) as forged_response:
                page.locator("#image-file").set_input_files(
                    {"name": "synthetic-forged.jpg", "mimeType": "image/jpeg", "buffer": b"not a real JPEG"}
                )
            assert forged_response.value.status == 415
            assert not page.locator("#image-preview").is_visible()
            page.get_by_text("文件不是有效图片或不支持此格式。", exact=True).wait_for()
            assert set((run_root / "images").iterdir()) == before_files
            with service.store.connect() as database:
                assert database.execute("SELECT COUNT(*) FROM images").fetchone()[0] == before_records
            assert len(workflow.entries) == count_before_upload
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(screenshots / "mobile-375-invalid-image.png"), full_page=True)
            results.append("non_image_frontend_and_content_validation_no_submission")

            # The top-right refresh clears the form and persisted session history.
            clear_baseline = len(workflow.entries)
            with page.expect_response(
                lambda response: response.request.method == "DELETE" and response.url.endswith("/api/jobs")
            ) as cleared:
                page.locator("#refresh").click()
            assert cleared.value.status == 200
            page.get_by_text("当前会话记录已清空。原始文件保留在后端主机。", exact=True).wait_for()
            assert page.locator("#url").input_value() == ""
            assert page.locator("#job-picker").input_value() == ""
            assert not page.locator("#image-result").is_visible()
            assert page.evaluate("localStorage.getItem('fxfetch.job-id')") is None
            assert page.request.get(origin + "/api/jobs").json() == {"jobs": []}
            cleared_requests = len([url for url in requests if "/api/jobs" in url])
            page.wait_for_timeout(5500)
            assert len([url for url in requests if "/api/jobs" in url]) == cleared_requests
            assert len(workflow.entries) == clear_baseline
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(screenshots / "mobile-375-cleared.png"), full_page=True)
            results.append("refresh_clears_form_and_history_without_recollection")

            # A downloaded original must show successful verification and the
            # earlier discovery event without generic failure/offline warnings.
            page.locator("#url").fill("https://original-success.synthetic.invalid/app.apk")
            page.locator("#download-button").click()
            page.locator("#job-content .result-note").filter(
                has_text="已取得完整应用包，文件完整性检查通过。"
            ).wait_for()
            content = page.locator("#job-content")
            assert "已从页面下载配置找到真实地址，继续验证应用包。" in content.inner_text()
            assert "已发现下载地址" in content.inner_text()
            assert "处理未完成，请稍后重试或查看本机状态。" not in content.inner_text()
            assert "继续处理中" not in content.inner_text()
            assert "未取得可用离线页面" not in content.inner_text()
            assert content.locator(".offline-status").count() == 0
            assert content.get_by_role("button", name="打包 APK", exact=True).count() == 0
            with page.expect_download() as original_download:
                content.get_by_role("link", name="下载", exact=True).click()
            original = original_download.value
            assert not original.failure()
            with zipfile.ZipFile(original.path()) as archive:
                assert set(archive.namelist()) == {"AndroidManifest.xml", "classes.dex"}
            page.set_viewport_size({"width": 1440, "height": 1100})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(screenshots / "desktop-original-success.png"), full_page=True)
            page.set_viewport_size({"width": 375, "height": 812})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(screenshots / "mobile-375-original-success.png"), full_page=True)
            results.append("original_package_success_messages_and_download")

            # A real signed build with a saved synthetic website reports its
            # actual embedded resource count separately from an entry-only page.
            page.locator("#url").fill("https://resource-snapshot.synthetic.invalid/page")
            page.locator("#download-button").click()
            page.get_by_role("button", name="打包 APK", exact=True).wait_for()
            page.get_by_role("button", name="打包 APK", exact=True).click()
            page.get_by_text("APK 已生成", exact=False).first.wait_for(timeout=60000)
            snapshot_job = page.request.get(
                origin + "/api/jobs/" + page.locator("#job-picker").input_value()
            ).json()
            assert page.locator(".build-progress").count() >= 1
            assert "打包进度" in page.locator(".build-progress").last.inner_text()
            snapshot_build = snapshot_job["builds"][-1]["result"]
            assert snapshot_build["offline_content_kind"] == "site_snapshot"
            assert snapshot_build["resource_files"] >= 2 and snapshot_build["resource_bytes"] > 0
            snapshot_status = page.locator(".build-status").filter(has_text="成品大小：")
            assert (
                "已包含保存的网站离线内容，离线可用范围以实际保存内容为准。" in snapshot_status.inner_text()
            )
            assert f"已打包资源：{snapshot_build['resource_files']} 项" in snapshot_status.inner_text()
            assert "仅含离线入口页" not in snapshot_status.inner_text()
            with page.expect_download() as snapshot_download:
                page.locator("#job-content").get_by_role("link", name="下载", exact=True).click()
            with zipfile.ZipFile(snapshot_download.value.path()) as archive:
                assert b"Saved synthetic website" in archive.read("assets/site/index.html")
                assert archive.read("assets/site/assets/style.css")
            page.set_viewport_size({"width": 1440, "height": 1100})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(screenshots / "desktop-resource-build.png"), full_page=True)
            page.set_viewport_size({"width": 375, "height": 812})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(screenshots / "mobile-375-resource-build.png"), full_page=True)
            results.append("saved_website_build_size_and_resource_details")

            assert (
                "页面内容依赖脚本，当前静态采集尚未完成；Chrome 动态采集未启用。"
                in page.locator("#job-content").inner_text()
            )

            # Live events appear while the task is still running; bytes never imply success.
            page.locator("#url").fill("https://progress-demo.synthetic.invalid/page")
            page.locator("#download-button").click()
            live = page.locator(".collection-progress")
            live.get_by_text("总量未知", exact=False).wait_for()
            assert "预计剩余" in live.inner_text()
            assert "已耗时" in live.inner_text()
            assert "发现下载候选，尚未验证" in live.inner_text()
            assert live.locator("img").count() == 0
            assert page.evaluate("window.__progress_xss || 0") == 0
            assert live.locator("progress").count() == 0
            assert page.get_by_role("button", name="取消采集", exact=True).is_visible()
            page.evaluate(
                "window.__actualNow=Date.now; Date.now=()=>window.__actualNow()+700000; document.getElementById('job-picker').dispatchEvent(new Event('change'))"
            )
            live.get_by_text("已到时限，正在等待停止确认", exact=False).wait_for()
            assert page.get_by_role("button", name="取消采集", exact=True).is_visible()
            assert "采集已达到时间限制并停止" not in page.locator("#job-content").inner_text()
            page.evaluate(
                "Date.now=window.__actualNow; delete window.__actualNow; document.getElementById('job-picker').dispatchEvent(new Event('change'))"
            )
            results.append("deadline_estimate_waits_for_backend_stop_confirmation")
            live.get_by_text("50%", exact=False).wait_for()
            assert live.locator("progress").get_attribute("max") == "4096"
            assert live.locator("progress").get_attribute("value") == "2048"
            assert "传输字节不代表应用包已验证成功" in live.inner_text()
            page.set_viewport_size({"width": 375, "height": 812})
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
            page.screenshot(path=str(screenshots / "mobile-375-live-progress.png"), full_page=True)
            results.append("live_progress_before_completion_known_unknown_bytes_safe_text")
            page.locator("#job-content .result-note").filter(has_text="采集已达到时间限制并停止").wait_for()
            assert "结果不完整" in page.locator("#job-content").inner_text()
            assert "不能据此判断没有 APK" in page.locator("#job-content").inner_text()
            assert page.get_by_role("button", name="取消采集", exact=True).count() == 0
            page.screenshot(path=str(screenshots / "mobile-375-task-timeout.png"), full_page=True)
            results.append("collection_timeout_stopped_incomplete_preserves_events")

            # Script gaps and observed validation describe evidence, not site legitimacy.

            page.locator("#url").fill("https://challenge-copy.synthetic.invalid/page")
            page.locator("#download-button").click()
            page.locator("#job-content .result-note").filter(has_text="此状态不能判断网站性质").wait_for()
            assert (
                page.locator("#job-content .result-note").inner_text()
                == "观察到实际验证页面或访问控制，尚未取得原包；此状态不能判断网站性质。"
            )
            page.locator("#url").fill("https://script-budget-copy.synthetic.invalid/page")
            page.locator("#download-button").click()
            page.locator("#job-content .result-note").filter(has_text="本次脚本读取预算").wait_for()
            assert "16 MiB" not in page.locator("#job-content").inner_text()
            page.screenshot(path=str(screenshots / "mobile-script-budget-copy.png"), full_page=True)
            results.append("script_budget_and_validation_evidence_wording")

            # Candidate display and selection are local until explicit continuation.
            page.locator("#url").fill("https://multi-choice.synthetic.invalid/page")
            page.locator("#download-button").click()
            choices = page.locator(".continuation-candidates input")
            choices.first.wait_for()
            parent_id = page.locator("#job-picker").input_value()
            choice_baseline = list(workflow.entries)
            assert choices.count() == 2
            assert page.locator(".continuation-panel img").count() == 0
            assert page.evaluate("window.__candidate_xss || 0") == 0
            assert page.locator(".continuation-submit").is_disabled()
            page.wait_for_timeout(1800)
            assert workflow.entries == choice_baseline
            assert "不保留原页面的登录状态" in page.locator(".continuation-panel").inner_text()
            page.set_viewport_size({"width": 375, "height": 812})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.screenshot(path=str(screenshots / "mobile-375-download-candidates.png"), full_page=True)
            results.append("candidate_display_safe_no_automatic_access_mobile_375")

            continuation_keys = []

            def lost_continuation(route):
                continuation_keys.append(route.request.headers.get("idempotency-key", ""))
                if len(continuation_keys) == 1:
                    response = route.fetch()
                    assert response.status == 202
                    route.abort("failed")
                else:
                    route.fallback()

            page.route("**/api/jobs/*/continue", lost_continuation)
            choices.nth(1).check()
            page.locator(".continuation-submit").evaluate("button => {button.click(); button.click();}")
            page.get_by_text("可重试同一次提交，不会重复创建任务。", exact=False).wait_for()
            assert page.locator(".continuation-candidates input:disabled").count() == 2
            page.get_by_role("button", name="重试继续下载", exact=True).click()
            page.get_by_role("button", name="查看原任务", exact=True).wait_for()
            assert len(continuation_keys) == 2 and continuation_keys[0] == continuation_keys[1]
            child_id = page.locator("#job-picker").input_value()
            assert child_id != parent_id
            child_job = page.request.get(origin + "/api/jobs/" + child_id).json()
            assert child_job["input"]["parent_job_id"] == parent_id
            assert child_job["input"]["cookies_inherited"] is False
            assert (
                workflow.entries.count("https://original-success.synthetic.invalid/app.apk?chosen=second")
                == 1
            )
            assert "https://first.synthetic.invalid/app.apk" not in workflow.entries
            page.unroute("**/api/jobs/*/continue", lost_continuation)
            results.append("candidate_explicit_selection_same_key_lost_response_retry")

            page.get_by_role("button", name="查看原任务", exact=True).click()
            page.get_by_role("button", name="查看此地址的后续任务", exact=True).wait_for()
            assert page.locator("#job-picker").input_value() == parent_id
            assert page.locator(".continuation-candidates input:disabled").count() == 1
            assert page.locator(".continuation-candidates input:enabled").count() == 1
            page.set_viewport_size({"width": 1440, "height": 1100})
            page.screenshot(path=str(screenshots / "desktop-candidate-parent-child.png"), full_page=True)
            page.get_by_role("button", name="查看此地址的后续任务", exact=True).click()
            page.get_by_role("button", name="查看原任务", exact=True).wait_for()
            assert page.locator("#job-picker").input_value() == child_id
            results.append("candidate_parent_child_navigation_other_candidate_remains_available")

            page.locator("#url").fill("https://multi-choice.synthetic.invalid/refresh")
            page.locator("#download-button").click()
            page.locator(".continuation-candidates input").first.wait_for()
            page.locator(".continuation-candidates input").first.check()
            refresh_baseline = list(workflow.entries)
            page.locator("#refresh").click()
            page.get_by_text("当前会话记录已清空。原始文件保留在后端主机。", exact=True).wait_for()
            assert page.locator(".continuation-panel").count() == 0
            page.wait_for_timeout(1000)
            assert workflow.entries == refresh_baseline
            results.append("candidate_refresh_clears_selection_without_continuation")

            # Refresh while the response is held must ignore the late child.
            page.locator("#url").fill("https://multi-choice.synthetic.invalid/late-response")
            page.locator("#download-button").click()
            page.locator(".continuation-candidates input").nth(1).wait_for()
            page.locator(".continuation-candidates input").nth(1).check()
            held = {}

            def hold_continuation(route):
                held["response"] = route.fetch()
                held["route"] = route

            page.route("**/api/jobs/*/continue", hold_continuation)
            page.locator(".continuation-submit").click()
            page.wait_for_timeout(300)
            assert held and held["response"].status == 202
            page.locator("#refresh").click()
            held["route"].fulfill(response=held["response"])
            page.get_by_text("当前会话记录已清空。原始文件保留在后端主机。", exact=True).wait_for()
            assert page.locator("#job-empty").is_visible()
            assert page.locator(".continuation-panel").count() == 0
            assert len(page.request.get(origin + "/api/jobs").json()["jobs"]) == 0
            page.unroute("**/api/jobs/*/continue", hold_continuation)
            results.append("candidate_late_response_ignored_after_refresh")

            # Exercise visibility pause using the page's visibility event contract.
            page.locator("#url").fill("https://slow.synthetic.invalid/page")
            page.locator("#download-button").click()
            page.locator("#job-content .job-url").filter(has_text="slow.synthetic.invalid").wait_for()
            page.evaluate(
                "Object.defineProperty(document, 'hidden', {configurable:true,get:()=>true}); document.dispatchEvent(new Event('visibilitychange'))"
            )
            page.wait_for_timeout(250)
            hidden_baseline = len([url for url in requests if "/api/jobs" in url])
            page.wait_for_timeout(5500)
            assert len([url for url in requests if "/api/jobs" in url]) == hidden_baseline
            results.append("hidden_polling_paused")
            page.evaluate("delete document.hidden; document.dispatchEvent(new Event('visibilitychange'))")
            # Remove cookie, then a normal refresh must stop authenticated activity.
            context.clear_cookies()
            page.locator("#refresh").click()
            page.locator("#login-panel").wait_for(state="visible")
            assert not page.locator("#workspace").is_visible()
            results.append("expired_session_requires_login")
            assert not console_errors, console_errors
            browser.close()
        report = {
            "checks": results,
            "passed": len(results),
            "workflow": "synthetic_no_network",
            "builder": "real_sdk_signed_apk",
            "runtime_validation": "not_run",
            "screenshots": str(screenshots.relative_to(BASE)),
            "static_bytes": sum(path.stat().st_size for path in (BASE / "src/fxfetch/web/static").glob("*")),
        }
        (QA / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False))
    finally:
        server.should_exit = True
        thread.join(30)
        listener.close()


if __name__ == "__main__":
    main()
