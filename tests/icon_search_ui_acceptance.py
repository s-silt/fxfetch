"""Installed Chrome acceptance against synthetic local providers only."""
from __future__ import annotations

import json
import secrets
import socket
import threading
import time
from pathlib import Path
from unittest.mock import patch

import uvicorn
from desktop_ui_assertions import DESKTOP_SIZES, assert_desktop_workspace, assert_same_page
from playwright.sync_api import expect, sync_playwright
from test_api import SyntheticBuilder, SyntheticWorkflow
from test_icon_search import configure, picture
from test_name_search import DOWNLOAD_URL, NAME, DirectedProvider

from fxfetch.config import Settings
from fxfetch.core.process_limits import ProcessResult
from fxfetch.icon_search.worker import execute
from fxfetch.security import password_hash
from fxfetch.service import JobService
from fxfetch.web.api import create_app


class UIProvider(DirectedProvider):
    def recognize(self, image):
        result = super().recognize(image)
        return dict(result, requested_model='requested', returned_model='alias')


def main():
    output = Path(__file__).resolve().parents[1] / '.runtime/icon-search-ui' / str(time.time_ns())
    output.mkdir(parents=True)
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
    origin = f'http://127.0.0.1:{port}'
    password = secrets.token_urlsafe(24)
    settings = Settings(output / 'state', password_hash(password), allowed_hosts=(f'127.0.0.1:{port}',))
    workflow = SyntheticWorkflow()
    service = JobService(settings, workflow=workflow, builder=SyntheticBuilder())
    configure(settings.root)
    provider = UIProvider()
    provider_calls = provider.calls
    releases = {mode: threading.Event() for mode in ('recognize', 'name')}
    worker_modes = []

    def worker(command, **kwargs):
        assert command[-3] == 'fxfetch.icon_search.worker'
        directory = Path(command[-1])
        mode = json.loads((directory / 'request.json').read_text(encoding='utf-8'))['mode']
        assert mode in releases, 'Current UI must explicitly recognize or search by name'
        worker_modes.append(mode)
        assert releases[mode].wait(15), 'Synthetic operation was not released in time'
        execute(settings.root, directory, provider)
        return ProcessResult(returncode=0)

    app = create_app(settings, service=service)
    server = uvicorn.Server(uvicorn.Config(app, log_level='error', access_log=False))
    thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert server.started
    try:
        with patch('fxfetch.icon_search.service.run_limited', worker), sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel='chrome', headless=True,
                                                args=['--disable-background-networking'])
            context = browser.new_context(viewport=DESKTOP_SIZES['desktop-1440'])
            blocked, errors = [], []

            def route(request):
                if request.request.url.startswith(origin + '/'):
                    request.continue_()
                else:
                    blocked.append(request.request.url)
                    request.abort()

            context.route('**/*', route)
            page = context.new_page()
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(origin)
            page.locator('#password').fill(password)
            page.locator('#login-form button').click()
            page.locator('#workspace').wait_for(state='visible')
            entry = 'https://entry.synthetic.invalid/preserved'
            page.locator('#url').fill(entry)
            original_url = page.url
            page.locator('#view-search').click()
            assert_desktop_workspace(page, 'search')
            assert_same_page(page, original_url)
            page.locator('#icon-file').set_input_files({'name': 'sample.png', 'mimeType': 'image/png',
                                                       'buffer': picture()})
            assert provider_calls == [] and workflow.calls == []
            preview = page.locator('#icon-preview').get_attribute('src')
            page.locator('#view-collect').click()
            assert page.locator('#url').input_value() == entry
            page.locator('#view-search').click()
            assert page.locator('#icon-preview').get_attribute('src') == preview
            assert provider_calls == [] and workflow.calls == []
            with page.expect_response(lambda r: r.url.endswith('/api/icon-recognitions')) as recognition_response:
                page.locator('#icon-search-button').click()
            assert recognition_response.value.status == 202
            recognition_id = recognition_response.value.json()['id']
            page.wait_for_function("() => document.querySelector('#search-tab-status').textContent === '识别中'")
            assert page.locator('#icon-search-progress').is_visible()
            expect(page.locator('.search-progress-title')).to_have_text('识别中')
            assert page.locator('#icon-search-progress').inner_text().startswith('识别中')
            assert page.locator('#icon-result-empty').is_hidden()
            page.locator('#view-collect').click()
            assert page.locator('#url').input_value() == entry
            assert page.locator('#search-tab-status').inner_text() == '识别中'
            page.locator('#view-search').click()
            assert page.locator('#icon-preview').get_attribute('src') == preview
            releases['recognize'].set()
            page.wait_for_function("() => document.querySelector('#search-tab-status').textContent === '待确认名称'")
            assert page.locator('#name-search-name').input_value() == NAME
            assert page.locator('#icon-search-progress').inner_text().startswith('名称已识别，请确认后搜索')
            assert provider_calls == [('recognize',)] and worker_modes == ['recognize']
            assert page.locator('.icon-collect-button').count() == 0 and workflow.calls == []
            assert page.locator('.icon-model-details > summary').inner_text() == '模型返回有差异'
            assert page.locator('.icon-model-details').evaluate('(element) => !element.open')
            page.locator('.icon-model-details > summary').click()
            assert '请求：requested；返回：alias' in page.locator('.icon-model-details').inner_text()
            page.locator('.icon-model-details > summary').click()
            with page.expect_response(lambda r: r.url.endswith('/api/name-searches')) as name_response:
                page.locator('#name-search-button').click()
            assert name_response.value.status == 202
            assert name_response.value.request.post_data_json == {'name': NAME, 'recognition_id': recognition_id}
            page.wait_for_function("() => document.querySelector('#search-tab-status').textContent === '搜索中'")
            assert provider_calls == [('recognize',)] and workflow.calls == []
            page.locator('#view-collect').click()
            assert page.locator('#url').input_value() == entry
            page.locator('#view-search').click()
            assert page.locator('#name-search-name').input_value() == NAME
            releases['name'].set()
            page.locator('.icon-collect-button').wait_for(state='visible')
            assert page.locator('.icon-collect-button').count() == 1
            expected_calls = [('recognize',), ('quota',), ('search_name', NAME, 'sample_index'),
                              ('search_name', NAME, 'download_page')]
            assert provider_calls == expected_calls and worker_modes == ['recognize', 'name']
            assert workflow.calls == []
            assert page.locator('#icon-search-progress').inner_text().startswith('找到 2 条候选')
            assert NAME in page.locator('#icon-results').inner_text()
            results = page.locator('#icon-results').inner_text()
            page.locator('#view-collect').click()
            page.locator('#view-search').click()
            assert page.locator('#icon-results').inner_text() == results
            assert provider_calls == expected_calls and workflow.calls == []
            assert_same_page(page, original_url)
            for name, viewport in DESKTOP_SIZES.items():
                page.set_viewport_size(viewport)
                assert_desktop_workspace(page, 'search')
                page.screenshot(path=str(output / f'{name}-results.png'), full_page=True)
            with page.expect_response(lambda r: r.url.endswith('/collect')) as response:
                page.locator('.icon-collect-button').click()
            assert response.value.status == 202
            job_id = response.value.json()['id']
            source_directory = settings.root / 'jobs' / job_id / 'source'
            evidence = json.loads((source_directory / 'name-search.json').read_text(encoding='utf-8'))
            assert evidence['query_name'] == NAME and evidence['recognition_id'] == recognition_id
            assert (source_directory / 'image.original').read_bytes() == picture()
            assert (source_directory / 'icon.jpg').is_file()
            page.wait_for_function("() => document.querySelector('#icon-status').textContent.includes('已提交追踪任务')")
            assert workflow.calls == [DOWNLOAD_URL]
            assert_desktop_workspace(page)
            assert page.locator('#job-picker').evaluate('(element) => document.activeElement === element')
            assert_same_page(page, original_url)
            assert page.locator('#url').input_value() == entry
            page.locator('#view-search').click()
            assert page.locator('#icon-results').inner_text() == results
            page.locator('#show-tasks').click()
            assert_desktop_workspace(page)
            page.locator('#refresh').click()
            page.wait_for_function("() => document.querySelector('#icon-results').children.length === 0")
            page.reload()
            page.locator('#workspace').wait_for(state='visible')
            assert provider_calls == expected_calls and worker_modes == ['recognize', 'name']
            assert not errors and not blocked, (errors, blocked)
            browser.close()
        receipt = {'passed': True, 'provider_calls_synthetic': len(provider_calls),
                   'target_requests': 0, 'selected_collection_synthetic': len(workflow.calls),
                   'desktop_two_column_layout': True, 'viewport_widths': [1280, 1440, 1920],
                   'same_page_switching_preserves_input_search_and_results': True,
                   'recognition_requires_explicit_name_search': True,
                   'recognition_provenance_copied_to_collection': True,
                   'candidate_returns_to_collection': True, 'refresh_does_not_retry': True, 'output': str(output)}
        (output / 'result.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
        print(json.dumps(receipt))
    finally:
        for release in releases.values():
            release.set()
        server.should_exit = True
        thread.join(15)
        listener.close()


if __name__ == '__main__':
    main()
