"""Desktop input-card visibility only; no collection, search or build requests."""

from __future__ import annotations

import json
import secrets
import socket
import threading
import time
from pathlib import Path

import qrcode
import uvicorn
from desktop_ui_assertions import DESKTOP_SIZES, assert_desktop_workspace
from playwright.sync_api import sync_playwright
from test_api import SyntheticBuilder, SyntheticWorkflow
from test_icon_search import picture

from fxfetch.config import Settings
from fxfetch.security import password_hash
from fxfetch.service import JobService
from fxfetch.web.api import create_app


def main() -> None:
    output = Path(__file__).resolve().parents[1] / '.runtime/desktop-input-ui' / str(time.time_ns())
    output.mkdir(parents=True)
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
    origin = f'http://127.0.0.1:{port}'
    password = secrets.token_urlsafe(24)
    settings = Settings(output / 'state', password_hash(password), allowed_hosts=(f'127.0.0.1:{port}',))
    workflow, builder = SyntheticWorkflow(), SyntheticBuilder()
    service = JobService(settings, workflow=workflow, builder=builder)
    server = uvicorn.Server(uvicorn.Config(create_app(settings, service=service),
                                         log_level='error', access_log=False))
    thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
    thread.start()
    qr = output / 'qr.png'
    qrcode.make('https://input.synthetic.invalid/download').save(qr)
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert server.started
    measurements, external, errors, forbidden = [], [], [], []
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel='chrome', headless=True,
                                                args=['--disable-background-networking'])
            context = browser.new_context(viewport=DESKTOP_SIZES['desktop-1280'])

            def route(route):
                if route.request.url.startswith(origin + '/'):
                    route.continue_()
                else:
                    external.append(route.request.url)
                    route.abort()

            context.route('**/*', route)
            context.on('request', lambda request: forbidden.append(request.url)
                       if request.method == 'POST' and any(value in request.url for value in (
                           '/api/jobs', '/api/icon-searches', '/web-apk-builds')) else None)
            page = context.new_page()
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(origin)
            page.locator('#password').fill(password)
            page.locator('#login-form button').click()
            page.locator('#workspace').wait_for(state='visible')

            def capture(name, view, card, button, important, reset_scroll=True):
                if reset_scroll:
                    page.locator(card).evaluate('''element => {
                        element.scrollTop = 0;
                        const input = element.querySelector('.input-scroll');
                        if (input) input.scrollTop = 0;
                    }''')
                assert_desktop_workspace(page, view)
                measurement = page.evaluate('''([card, button, important]) => {
                    const rect = selector => document.querySelector(selector).getBoundingClientRect();
                    const bounds = rect(card), action = rect(button);
                    const title = document.querySelector(card + ' h2').getBoundingClientRect();
                    const visible = action.top >= bounds.top && action.bottom <= Math.min(bounds.bottom, innerHeight);
                    const hit = document.elementFromPoint(action.x + action.width / 2, action.y + action.height / 2);
                    const overlap = important.filter(selector => {
                        const element = document.querySelector(selector), raw = element.getBoundingClientRect();
                        const box = {top:raw.top, bottom:raw.bottom, left:raw.left, right:raw.right};
                        // Off-screen content inside a scrollport is clipped, not overlaid by the footer.
                        for (let parent = element.parentElement; parent; parent = parent.parentElement) {
                            const style = getComputedStyle(parent), clip = parent.getBoundingClientRect();
                            if (['auto','scroll','hidden','clip'].includes(style.overflowY)) {
                                box.top = Math.max(box.top, clip.top + parent.clientTop);
                                box.bottom = Math.min(box.bottom, clip.top + parent.clientTop + parent.clientHeight);
                            }
                            if (['auto','scroll','hidden','clip'].includes(style.overflowX)) {
                                box.left = Math.max(box.left, clip.left + parent.clientLeft);
                                box.right = Math.min(box.right, clip.left + parent.clientLeft + parent.clientWidth);
                            }
                        }
                        return box.right > box.left && box.bottom > box.top && box.top < action.bottom && box.bottom > action.top
                          && box.left < action.right && box.right > action.left;
                    });
                    return {button_visible:visible, button_clickable:hit === document.querySelector(button),
                      title_visible:title.top >= bounds.top && title.bottom <= bounds.bottom,
                      overlap, button_top:action.top, button_bottom:action.bottom, card_bottom:bounds.bottom};
                }''', [card, button, important])
                measurements.append({'state': name, **measurement})
                page.screenshot(path=str(output / f'1280-{name}.png'), full_page=True)

            page.locator('#url').fill('https://input.synthetic.invalid/download')
            capture('url', 'collect', '#collect-panel', '#download-button', ['#url', '#host-hint'])
            page.locator('#mode-scanner').click()
            capture('scanner', 'collect', '#collect-panel', '#download-button',
                    ['#scanner-input', '#scanner-help', '#scanner-status', '#url', '#host-hint'])
            page.locator('#image-file').set_input_files(qr)
            page.wait_for_function("() => document.getElementById('qr-status').textContent.startsWith('识别到')")
            capture('qr', 'collect', '#collect-panel', '#download-button',
                    ['#image-result', '#qr-candidates', '#url', '#host-hint'])
            page.locator('#url').scroll_into_view_if_needed()
            capture('qr-entry-scrolled', 'collect', '#collect-panel', '#download-button',
                    ['#qr-candidates', '#url', '#host-hint'], reset_scroll=False)
            page.locator('#view-search').click()
            page.locator('#icon-file').set_input_files({'name': 'synthetic.png', 'mimeType': 'image/png',
                                                       'buffer': picture()})
            capture('image-selected', 'search', '.search-input', '#icon-search-button',
                    ['#icon-preview', '.icon-actions', '.search-privacy'])
            context.close()
            browser.close()
        passed = all(item['button_visible'] and item['button_clickable'] and item['title_visible']
                     and not item['overlap'] for item in measurements)
        assert not external and not errors and not forbidden and not workflow.calls and not builder.calls
        receipt = {'passed': passed, 'viewport': DESKTOP_SIZES['desktop-1280'],
                   'measurements': measurements, 'external_requests': external,
                   'collection_search_build_requests': forbidden, 'page_errors': errors}
        (output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps({**receipt, 'output': str(output)}, ensure_ascii=False))
        assert passed, 'Primary input action is hidden or overlaps important content'
    finally:
        server.should_exit = True
        thread.join(15)
        listener.close()


if __name__ == '__main__':
    main()
