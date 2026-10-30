"""Installed Chrome UI acceptance with synthetic API responses, no target access."""

from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    output = root / '.runtime' / 'tls-option-ui' / str(time.time_ns())
    output.mkdir(parents=True)
    static = root / 'src/fxfetch/web/static'
    origin = 'http://127.0.0.1:18765'
    receipt = {'passed': False, 'scope': 'real Chrome UI with synthetic API; no acquisition', 'viewports': []}
    with sync_playwright() as driver:
        browser = driver.chromium.launch(channel='chrome', headless=True, args=[
            '--disable-background-networking', '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1',
        ])
        try:
            for width in (1280, 375):
                context = browser.new_context(viewport={'width': width, 'height': 1000})
                jobs: list[dict] = []
                submissions: list[dict] = []
                external: list[str] = []

                def route_request(route, *, jobs=jobs, submissions=submissions, external=external):
                    request = route.request
                    parsed = urlsplit(request.url)
                    if not request.url.startswith(origin + '/'):
                        external.append(request.url)
                        return route.abort()
                    path = parsed.path
                    if path == '/' or path.startswith('/static/'):
                        name = 'index.html' if path == '/' else path.removeprefix('/static/')
                        if name not in {'index.html', 'app.css', 'app.js', 'analysis.js', 'data-package.js'}:
                            return route.abort()
                        mime = 'text/html' if name.endswith('.html') else 'text/css' if name.endswith('.css') else 'application/javascript'
                        return route.fulfill(body=(static / name).read_bytes(), content_type=mime)
                    if path == '/api/session':
                        data = {'authenticated': True, 'csrf_token': 'synthetic'}
                    elif path == '/api/capabilities':
                        data = {'chrome': {'enabled': True}, 'web_apk': {'enabled': False}, 'web_analysis': {'enabled': False}}
                    elif path == '/api/preview':
                        data = {'url': 'https://synthetic.test/', 'request_url': 'https://synthetic.test/', 'kind': 'web'}
                    elif path == '/api/jobs' and request.method == 'DELETE':
                        jobs.clear()
                        data = {}
                    elif path == '/api/jobs' and request.method == 'POST':
                        submitted = request.post_data_json
                        submissions.append(submitted)
                        job = {'id': str(len(submissions)), 'created': time.time(), 'state': 'completed',
                               'outcome': 'downloaded', 'reason_code': 'package_verified',
                               'input': {'entry_url': submitted['url'], 'tls_policy': submitted['tls_policy']},
                               'tls_policy': submitted['tls_policy'],
                               'tls_fallback': {'state': 'recorded', 'observed': len(submissions) == 2, 'count': 1 if len(submissions) == 2 else 0},
                               'artifacts': [], 'result': {'coverage': 'partial'}}
                        jobs.append(job)
                        data = job
                    elif path == '/api/jobs':
                        data = {'jobs': jobs}
                    elif path.startswith('/api/jobs/'):
                        data = next(job for job in jobs if job['id'] == path.split('/')[3])
                    else:
                        raise AssertionError('Unexpected synthetic UI request')
                    return route.fulfill(json=data)

                context.route('**/*', route_request)
                page = context.new_page()
                page.set_default_timeout(10000)
                page.goto(origin)
                page.locator('#workspace').wait_for(state='visible')
                policy = page.locator('#tls-policy')
                advanced = page.locator('#advanced-settings')
                assert policy.input_value() == 'auto'
                assert not advanced.evaluate('(element) => element.open')
                assert not policy.is_visible()
                assert page.locator('#tls-policy-summary').inner_text() == '证书：自动处理'
                page.locator('#url').fill('https://synthetic.test/')
                assert not submissions
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                assert page.locator('#download-button').bounding_box()['y'] < 850
                page.screenshot(path=str(output / f'{width}-workspace.png'), full_page=True)
                page.locator('.input-card').screenshot(path=str(output / f'{width}-option.png'))
                page.locator('#download-button').click()
                page.wait_for_function("document.querySelector('#job-picker').value === '1'")
                assert submissions[-1]['tls_policy'] == 'auto' and policy.input_value() == 'auto'
                assert page.locator('#job-content .tls-warning').count() == 0
                page.locator('#download-button').click()
                page.wait_for_function("document.querySelector('#job-picker').options.length === 2")
                page.locator('#job-content .tls-warning').wait_for(state='visible')
                assert submissions[-1]['tls_policy'] == 'auto'
                assert '来源可信' in page.locator('.tls-warning').inner_text()
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                page.locator('#task-panel').screenshot(path=str(output / f'{width}-result.png'))
                advanced.locator('summary').click()
                assert policy.is_visible()
                page.locator('.input-card').screenshot(path=str(output / f'{width}-advanced.png'))
                policy.select_option('strict')
                assert page.locator('#tls-policy-summary').inner_text() == '证书：严格验证'
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                page.locator('#download-button').click()
                page.wait_for_function("document.querySelector('#job-picker').options.length === 3")
                assert submissions[-1]['tls_policy'] == 'strict'
                assert page.locator('#job-content .tls-warning').count() == 0
                assert policy.input_value() == 'auto'
                assert not advanced.evaluate('(element) => element.open')
                advanced.locator('summary').click()
                policy.select_option('strict')
                page.reload()
                page.locator('#workspace').wait_for(state='visible')
                assert policy.input_value() == 'auto'
                assert not advanced.evaluate('(element) => element.open')
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                assert not external
                receipt['viewports'].append({'width': width, 'submitted': len(submissions), 'default_restored': True,
                                             'advanced_collapsed': True, 'horizontal_overflow': False})
                context.close()
        finally:
            browser.close()
    receipt['passed'] = True
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(json.dumps({'passed': True, 'output': str(output)}))


if __name__ == '__main__':
    main()
