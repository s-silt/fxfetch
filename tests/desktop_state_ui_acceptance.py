"""Installed-Chrome desktop state regressions using real scripts and synthetic APIs.

No server, provider, target, browser download, or physical scanner is used.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

from playwright.sync_api import sync_playwright
from test_icon_search import picture


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    static = root / 'src/fxfetch/web/static'
    output = root / '.runtime/desktop-state-ui' / str(time.time_ns())
    output.mkdir(parents=True)
    html = (static / 'index.html').read_text(encoding='utf-8')
    html = re.sub(r'<script\b[^>]*>.*?</script>|<link\b[^>]*>', '', html, flags=re.DOTALL)
    checks: list[str] = []
    errors: list[str] = []
    blocked: list[str] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel='chrome', headless=True,
                                             args=['--disable-background-networking'])
        context = browser.new_context(viewport={'width': 1440, 'height': 1000})

        def reject(route):
            blocked.append(route.request.url)
            route.abort()

        context.route('**/*', reject)
        page = context.new_page()
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.set_content(html)
        page.add_style_tag(content='''
          [hidden] { display:none !important; }
          #job-content, #icon-results { height:220px; overflow:auto; width:600px; }
          .icon-candidate { min-height:100px; }
        ''')
        for name in ('workspace.js', 'icon-search.js'):
            page.add_script_tag(content=(static / name).read_text(encoding='utf-8'))
        page.evaluate('''() => {
          document.getElementById('workspace').hidden = false;
          document.getElementById('job-content').hidden = false;
          document.getElementById('job-content').innerHTML = '<div style="height:2000px">Synthetic task</div>';
          const test = window.test = {calls:[], timers:new Map(), nextResult:null, serial:0};
          window.setTimeout = fn => { const id = ++test.serial; test.timers.set(id, fn); return id; };
          window.clearTimeout = id => test.timers.delete(id);
          test.tick = async () => {
            const [id, fn] = test.timers.entries().next().value;
            test.timers.delete(id); await fn();
          };
          test.api = async (path, options = {}) => {
            test.calls.push({path, method:options.method || 'GET'});
            if (path === '/api/preview') return new Promise(resolve => { test.resolvePreview = resolve; });
            if (path === '/api/icon-searches') return {id:'synthetic-search'};
            if (path === '/api/icon-searches/synthetic-search') return structuredClone(test.nextResult);
            throw new Error('Unexpected synthetic API path: ' + path);
          };
          test.workspace = FxfetchWorkspace.create({api:test.api, canEdit:() => true,
            onScan:url => { document.getElementById('url').value = url; }});
          test.search = FxfetchIconSearch.create({api:test.api, key:() => 'synthetic-token',
            collected:() => {}, enabled:() => true});
          test.result = (state, error = '', count = 8) => ({id:'synthetic-search', state,
            stage:state === 'running' ? 'searching' : 'finished', error,
            recognition:{name:'Synthetic', confidence:'high', requested_model:'synthetic', returned_model:'synthetic'},
            candidates:Array.from({length:count}, (_, index) => ({id:'candidate-' + index,
              title:'Synthetic candidate ' + index, url:'https://candidate.synthetic.invalid/' + index,
              evidence:index < 4 ? ['name_in_title'] : []}))});
        }''')

        page.locator('#url').fill('https://entry.synthetic.invalid/')
        page.locator('#job-content').evaluate('(element) => { element.scrollTop = 160; }')
        page.locator('#view-collect').click()
        assert page.locator('#job-content').evaluate('(element) => element.scrollTop') == 160
        page.locator('#view-search').click()
        page.locator('#view-collect').click()
        assert page.locator('#job-content').evaluate('(element) => element.scrollTop') == 160
        assert page.locator('#url').input_value() == 'https://entry.synthetic.invalid/'
        assert page.evaluate('() => test.calls.length') == 0
        checks.append('same-tab and cross-tab scrolling preserve input without API calls')

        page.locator('#mode-scanner').click()
        page.locator('#scanner-input').fill('reader.synthetic.invalid')
        page.locator('#scanner-input').press('Enter')
        page.wait_for_function('() => !!test.resolvePreview')
        page.locator('#view-search').click()
        page.locator('#icon-upload').focus()
        page.evaluate('''() => test.resolvePreview({url:'https://reader.synthetic.invalid/',
          request_url:'https://reader.synthetic.invalid/', kind:'web'})''')
        page.wait_for_function("() => document.getElementById('url').value === 'https://reader.synthetic.invalid/'")
        assert page.evaluate('() => document.activeElement.id') == 'icon-upload'
        assert page.evaluate("() => test.calls.filter(call => call.path === '/api/preview').length") == 1
        checks.append('scanner completion updates input without stealing hidden-view focus')

        def select_image() -> None:
            page.locator('#icon-file').set_input_files({'name': 'synthetic.png', 'mimeType': 'image/png',
                                                       'buffer': picture()})

        select_image()
        preview = page.locator('#icon-preview').get_attribute('src')
        page.locator('#view-collect').click()
        page.locator('#view-search').click()
        assert page.locator('#icon-preview').get_attribute('src') == preview
        assert page.evaluate('() => test.calls.length') == 1
        checks.append('image selection and workspace switching make no search request')

        page.evaluate("() => { test.nextResult = test.result('running'); }")
        page.locator('#icon-search-button').click()
        page.wait_for_function("() => document.querySelectorAll('.icon-candidate').length === 8")
        assert page.locator('#search-tab-status').inner_text() == '搜索中'
        page.locator('.icon-weak-candidates').evaluate('(element) => { element.open = true; }')
        page.locator('.icon-weak-candidates > summary').focus()
        page.locator('#icon-results').evaluate('(element) => { element.scrollTop = 400; }')
        page.evaluate('() => test.tick()')
        assert page.locator('.icon-weak-candidates').evaluate('(element) => element.open')
        assert page.locator('#icon-results').evaluate('(element) => element.scrollTop') == 400
        assert page.evaluate('() => document.activeElement.dataset.focusKey') == 'weak-summary'
        checks.append('search polling preserves weak-candidate expansion, scrolling and keyboard focus')

        page.locator('#view-search').click()
        assert page.locator('#icon-results').evaluate('(element) => element.scrollTop') == 400
        page.locator('#view-collect').click()
        page.evaluate("() => { test.nextResult = test.result('completed'); }")
        page.evaluate('() => test.tick()')
        assert page.evaluate('() => document.activeElement.id') == 'view-collect'
        page.locator('#view-search').click()
        assert page.locator('#icon-results').evaluate('(element) => element.scrollTop') == 400
        assert page.locator('.icon-weak-candidates').evaluate('(element) => element.open')
        assert page.locator('#search-tab-status').inner_text() == '8 条候选'
        checks.append('hidden-view completion preserves view state and leaves active focus alone')

        page.evaluate('() => test.workspace.reset()')
        assert page.locator('#job-content').evaluate('(element) => element.scrollTop') == 0
        page.locator('#view-search').click()
        assert page.locator('#icon-results').evaluate('(element) => element.scrollTop') == 0
        assert page.locator('#scanner-input').input_value() == ''
        checks.append('workspace reset clears both scroll caches even when starting in search view')

        for state, error, count, expected in (
            ('completed', '', 0, '无候选'),
            ('failed', 'icon_provider_failed', 0, '失败'),
            ('partial', 'icon_timeout', 8, '8 条候选 · 未完成'),
            ('cancelled', 'cancelled', 0, '已取消'),
        ):
            page.evaluate('() => test.search.reset()')
            select_image()
            page.evaluate('([state, error, count]) => { test.nextResult = test.result(state, error, count); }',
                          [state, error, count])
            page.locator('#icon-search-button').click()
            page.wait_for_function('(expected) => document.getElementById("search-tab-status").textContent === expected',
                                   arg=expected)
        checks.append('completed-empty, failed, partial and cancelled searches have distinct honest labels')

        page.evaluate('() => { test.search.reset(); test.workspace.reset(); }')
        assert page.locator('#search-tab-status').inner_text() == ''
        assert page.locator('#icon-results').inner_text() == ''
        assert page.evaluate('() => test.timers.size') == 0
        assert page.evaluate("() => test.calls.filter(call => call.path.includes('/collect') || call.path === '/api/jobs').length") == 0
        assert not errors, errors
        assert not blocked, blocked
        checks.append('reset leaves no result, timer, implicit collection or external request')
        context.close()
        browser.close()
    receipt = {'passed': True, 'checks': checks, 'page_errors': errors, 'external_requests': blocked,
               'scope': 'Real desktop Chrome; synthetic DOM/API only; no layout or physical-scanner acceptance'}
    (output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'passed': True, 'checks': len(checks), 'receipt': str(output / 'receipt.json')},
                     ensure_ascii=False))


if __name__ == '__main__':
    main()
