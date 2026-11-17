"""Installed-Chrome workspace/scanner acceptance with synthetic localhost services.

Keyboard events simulate a HID reader; no physical reader or remote site is used.
"""

from __future__ import annotations

import json
import secrets
import socket
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import qrcode
import uvicorn
from desktop_ui_assertions import DESKTOP_SIZES, assert_desktop_workspace, assert_same_page
from playwright.sync_api import sync_playwright
from test_api import SyntheticBuilder

from fxfetch.config import Settings
from fxfetch.core.workflow import Workflow, WorkflowResult
from fxfetch.security import password_hash
from fxfetch.service import JobService
from fxfetch.web.api import create_app


class ScannerWorkflow(Workflow):
    def __init__(self) -> None:
        self.entries: list[str] = []

    def run(self, url, output_dir, cancel, on_event=None):
        assert urlsplit(url).hostname == 'reader.synthetic.invalid'
        self.entries.append(url)
        if on_event:
            on_event({'event': 'task_started', 'url': url, 'network_mode': 'direct'})
        return WorkflowResult('failed', 'synthetic_complete', 'partial')


def main() -> None:
    output = Path(__file__).resolve().parents[1] / '.runtime/workspace-ui' / str(time.time_ns())
    output.mkdir(parents=True)
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
    origin = f'http://127.0.0.1:{port}'
    password = secrets.token_urlsafe(24)
    settings = Settings(output / 'state', password_hash(password), allowed_hosts=(f'127.0.0.1:{port}',))
    workflow = ScannerWorkflow()
    service = JobService(settings, workflow=workflow, builder=SyntheticBuilder())
    server = uvicorn.Server(uvicorn.Config(create_app(settings, service=service),
                                         log_level='error', access_log=False))
    thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert server.started, 'Local synthetic service did not start within ten seconds'
    qr = output / 'synthetic-qr.png'
    qrcode.make('https://reader.synthetic.invalid/old-qr-source').save(qr)
    checks: list[str] = []
    screenshots: list[str] = []
    requests: list[dict] = []
    blocked: list[str] = []
    errors: list[str] = []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel='chrome', headless=True,
                                                args=['--disable-background-networking'])
            context = browser.new_context(viewport=DESKTOP_SIZES['desktop-1280'])

            def route_request(route):
                if route.request.url.startswith(origin + '/'):
                    route.continue_()
                else:
                    blocked.append(route.request.url)
                    route.abort()

            context.route('**/*', route_request)
            page = context.new_page()
            page.on('pageerror', lambda error: errors.append(str(error)))

            def record(request):
                path = urlsplit(request.url).path
                if request.method == 'POST' and path in ('/api/preview', '/api/jobs'):
                    requests.append({'path': path, 'body': request.post_data_json})

            page.on('request', record)

            def count(path: str, value: str | None = None) -> int:
                return sum(item['path'] == path and
                           (value is None or item['body'].get('url') == value) for item in requests)

            def scanner_mode() -> None:
                page.locator('#mode-scanner').click()
                page.locator('#scanner-input-panel').wait_for(state='visible')
                assert page.locator('#mode-scanner').get_attribute('aria-pressed') == 'true'

            def expect_scan_url(value: str) -> None:
                page.wait_for_function('(value) => document.querySelector("#url").value === value', arg=value)
                page.wait_for_function('() => !document.querySelector("#scanner-input").disabled')
                assert page.locator('#scanner-input').input_value() == ''
                assert '点击「开始采集」才会访问目标' in page.locator('#scanner-status').inner_text()

            def screenshot(name: str, viewport: str) -> None:
                page.set_viewport_size(DESKTOP_SIZES[viewport])
                width = DESKTOP_SIZES[viewport]['width']
                assert_desktop_workspace(page)
                for selector in ('#url', '#mode-scanner', '#download-button', '#job-picker'):
                    box = page.locator(selector).bounding_box()
                    assert box and box['x'] >= 0 and box['x'] + box['width'] <= width + 0.5, selector
                button = page.locator('#download-button').bounding_box()
                assert button and button['height'] >= 44
                filename = f'{viewport}-{name}.png'
                page.screenshot(path=str(output / filename), full_page=True)
                screenshots.append(filename)

            page.goto(origin)
            page.locator('#password').fill(password)
            page.locator('#login-form button[type=submit]').click()
            page.locator('#workspace').wait_for(state='visible')
            original_url = page.url
            assert_desktop_workspace(page)

            scanner_mode()
            assert page.locator('#scanner-input').evaluate('(element) => document.activeElement === element')
            entered = 'reader.synthetic.invalid/from-reader?source=keyboard#fragment'
            page.locator('#scanner-input').press_sequentially(entered, delay=2)
            page.locator('#scanner-input').press('Enter')
            expect_scan_url('https://' + entered)
            assert count('/api/preview', entered) == 1
            assert count('/api/jobs') == 0 and workflow.entries == []
            checks.append('hid_style_typing_and_enter_only_normalize_without_collection')

            page.locator('#scanner-input').fill('6901234567890')
            page.locator('#scanner-input').press('Enter')
            assert '不支持普通商品条码' in page.locator('#scanner-status').inner_text()
            assert page.locator('#url').input_value() == 'https://' + entered
            assert count('/api/preview', '6901234567890') == 0 and count('/api/jobs') == 0
            checks.append('numeric_product_barcode_is_rejected_offline')

            no_suffix = 'reader.synthetic.invalid/without-enter'
            page.locator('#scanner-input').fill(no_suffix)
            page.locator('#scanner-apply').click()
            expect_scan_url('https://' + no_suffix)
            assert count('/api/preview', no_suffix) == 1 and count('/api/jobs') == 0
            checks.append('reader_without_enter_suffix_uses_apply_button')

            doubled = 'reader.synthetic.invalid/double-enter'
            page.locator('#scanner-input').fill(doubled)
            page.locator('#scanner-input').evaluate('''element => {
                for (let i = 0; i < 2; i++) element.dispatchEvent(new KeyboardEvent('keydown', {
                    key:'Enter', code:'Enter', bubbles:true, cancelable:true
                }));
            }''')
            expect_scan_url('https://' + doubled)
            assert count('/api/preview', doubled) == 1 and count('/api/jobs') == 0
            checks.append('rapid_double_enter_does_not_duplicate_scan_or_submit')

            page.locator('#mode-url').click()
            manual = 'reader.synthetic.invalid/manual-entry'
            page.locator('#url').fill(manual)
            page.locator('#url').press('End')
            page.locator('#url').press('Enter')
            assert page.locator('#url').input_value() == manual + '\n'
            assert page.locator('#mode-url').get_attribute('aria-pressed') == 'true'
            assert count('/api/jobs') == 0
            checks.append('manual_textarea_enter_is_not_globally_intercepted')

            page.locator('#image-file').set_input_files(qr)
            page.wait_for_function('() => document.querySelector("#qr-status").textContent.startsWith("识别到")')
            assert page.locator('#qr-input-panel').is_visible()
            assert page.locator('#qr-candidates input:checked').count() == 1
            preview = page.locator('#image-preview').get_attribute('src')
            page.locator('#view-search').click()
            page.locator('#view-collect').click()
            assert page.locator('#image-preview').get_attribute('src') == preview
            assert page.locator('#qr-candidates input:checked').count() == 1
            assert count('/api/jobs') == 0
            assert_same_page(page, original_url)
            checks.append('workspace_switch_preserves_qr_preview_and_selected_source')
            scanner_mode()
            assert page.locator('#image-result').is_hidden()
            assert page.locator('#qr-candidates input').count() == 0
            checks.append('switching_from_qr_to_scanner_clears_previous_qr_source')

            final = 'reader.synthetic.invalid/final-from-reader'
            page.locator('#scanner-input').press_sequentially(final, delay=2)
            page.locator('#scanner-input').press('Enter')
            expect_scan_url('https://' + final)
            assert count('/api/jobs') == 0 and workflow.entries == []
            for viewport in DESKTOP_SIZES:
                screenshot('scanner-ready', viewport)

            buffer = 'reader.synthetic.invalid/preserved-buffer'
            page.locator('#scanner-input').fill(buffer)
            page.locator('#view-search').click()
            assert_desktop_workspace(page, 'search')
            page.locator('#view-search').press('ArrowLeft')
            assert page.locator('#view-collect').evaluate('(element) => document.activeElement === element')
            assert_desktop_workspace(page)
            assert page.locator('#scanner-input').input_value() == buffer
            assert page.locator('#url').input_value() == 'https://' + final
            page.locator('#view-collect').press('End')
            assert_desktop_workspace(page, 'search')
            page.locator('#show-tasks').click()
            assert_desktop_workspace(page)
            assert page.locator('#job-picker').evaluate('(element) => document.activeElement === element')
            page.locator('#service-status > summary').click()
            assert page.locator('#capabilities').is_visible()
            page.locator('#service-status > summary').click()
            assert_same_page(page, original_url)
            assert count('/api/jobs') == 0
            checks.append('desktop_tabs_keyboard_and_task_shortcut_preserve_inputs_without_navigation_or_collection')

            with page.expect_response(lambda response: response.url == origin + '/api/jobs'
                                      and response.request.method == 'POST') as submitted:
                page.locator('#download-button').click()
            assert submitted.value.status == 202
            body = submitted.value.request.post_data_json
            assert 'image_id' not in body and 'candidate_id' not in body
            deadline = time.monotonic() + 5
            while not workflow.entries and time.monotonic() < deadline:
                page.wait_for_timeout(20)
            assert count('/api/jobs') == 1 and workflow.entries == ['https://' + final]
            checks.append('only_explicit_start_collects_once_without_stale_qr_evidence')
            for viewport in DESKTOP_SIZES:
                screenshot('task-result', viewport)

            scanner_mode()
            page.locator('#scanner-input').fill('reader.synthetic.invalid/not-submitted')
            page.locator('#refresh').click()
            page.wait_for_function('() => document.querySelector("#scanner-input").value === "" && '
                                   'document.querySelector("#url").value === ""')
            assert page.locator('#mode-url').get_attribute('aria-pressed') == 'true'
            assert count('/api/jobs') == 1
            checks.append('refresh_clears_reader_buffer_without_resubmitting')

            scanner_mode()
            page.locator('#scanner-input').fill('reader.synthetic.invalid/logout-buffer')
            page.locator('#logout').click()
            page.locator('#login-panel').wait_for(state='visible')
            assert page.locator('#scanner-input').input_value() == ''
            assert count('/api/jobs') == 1
            checks.append('logout_clears_reader_buffer')
            assert not errors, errors
            assert not blocked, blocked
            browser.close()
        receipt = {
            'status': 'passed', 'scope': 'installed_chrome_synthetic_hid_keyboard_and_local_workflow',
            'physical_reader_tested': False, 'target_requests': 0, 'supplier_requests': 0,
            'synthetic_collections': len(workflow.entries), 'checks': checks,
            'screenshots': screenshots, 'widths': [1280, 1440, 1920], 'output': str(output),
        }
        (output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps(receipt, ensure_ascii=False))
    finally:
        server.should_exit = True
        thread.join(15)
        listener.close()


if __name__ == '__main__':
    main()
