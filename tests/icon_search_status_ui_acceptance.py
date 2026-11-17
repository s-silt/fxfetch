"""Live search feedback and outcome regressions with synthetic asynchronous APIs."""
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
    output = root / '.runtime/icon-search-status-ui' / str(time.time_ns())
    output.mkdir(parents=True)
    html = (static / 'index.html').read_text(encoding='utf-8')
    html = re.sub(r'<script\b[^>]*>.*?</script>|<link\b[^>]*>', '', html, flags=re.DOTALL)
    errors: list[str] = []
    external: list[str] = []
    checks: list[str] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel='chrome', headless=True,
                                             args=['--disable-background-networking'])
        context = browser.new_context(viewport={'width': 1440, 'height': 900})

        def reject(route):
            external.append(route.request.url)
            route.abort()

        context.route('**/*', reject)
        page = context.new_page()
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.set_content(html)
        page.add_style_tag(content=(static / 'app.css').read_text(encoding='utf-8'))
        for name in ('workspace.js', 'icon-search.js'):
            page.add_script_tag(content=(static / name).read_text(encoding='utf-8'))
        page.evaluate('''() => {
          document.getElementById('workspace').hidden = false;
          document.getElementById('login-panel').hidden = true;
          const test = window.test = {calls:[], timers:new Map(), serial:0, nextResult:null};
          window.setTimeout = fn => { const id = ++test.serial; test.timers.set(id, fn); return id; };
          window.clearTimeout = id => test.timers.delete(id);
          test.tick = async () => {
            const [id, fn] = test.timers.entries().next().value;
            test.timers.delete(id); await fn();
          };
          test.api = async (path, options = {}) => {
            test.calls.push({path, method:options.method || 'GET', key:options.headers?.['Idempotency-Key']});
            if (path === '/api/icon-searches') return new Promise((resolve, reject) => {
              test.resolveSubmit = resolve; test.rejectSubmit = reject;
            });
            if (path.endsWith('/cancel')) return new Promise((resolve, reject) => {
              test.resolveCancel = resolve; test.rejectCancel = reject;
            });
            if (test.pollError) throw test.pollError;
            if (path === '/api/icon-searches/synthetic-search') return structuredClone(test.nextResult);
            throw new Error('Unexpected synthetic API path: ' + path);
          };
          test.workspace = FxfetchWorkspace.create({api:test.api, canEdit:() => true, onScan:() => {}});
          test.search = FxfetchIconSearch.create({api:test.api, key:() => 'synthetic-token-' + ++test.serial,
            collected:() => {}, enabled:() => true});
          test.result = (state, stage, count = 0, error = '') => ({id:'synthetic-search', state, stage, error,
            recognition: {name:'Synthetic App', confidence:'high', requested_model:'requested', returned_model:'alias'},
            candidates:Array.from({length:count}, (_, index) => ({id:'candidate-' + index,
              title:'Synthetic visual match ' + index, url:'https://candidate.synthetic.invalid/' + index,
              evidence:[]}))});
        }''')
        page.locator('#view-search').click()

        def select_and_submit() -> None:
            page.locator('#icon-file').set_input_files({'name': 'synthetic.png', 'mimeType': 'image/png',
                                                       'buffer': picture()})
            page.locator('#icon-search-button').click()
            page.wait_for_function('() => !!test.resolveSubmit')

        select_and_submit()
        assert page.locator('#icon-search-progress').is_visible()
        assert page.locator('.search-progress-title').inner_text() == '搜索中'
        assert '正在提交截图' in page.locator('.search-progress-note').inner_text()
        assert page.locator('#icon-result-empty').is_hidden()
        assert page.locator('#icon-results').get_attribute('aria-busy') == 'true'
        assert page.locator('#icon-cancel').is_hidden()
        checks.append('right pane displays submission before the create API resolves')
        page.evaluate("() => { test.nextResult = test.result('queued', 'validating'); test.resolveSubmit({id:'synthetic-search'}); }")
        page.wait_for_function("() => document.querySelector('.search-progress-title').textContent === '等待搜索'")
        for stage, phrase in (('validating', '检查图片'), ('quota', '检查免费搜索额度'),
                              ('recognizing', '识别名称和图标'), ('uploading', '提交图标搜图'),
                              ('searching', '搜索 Android 候选')):
            page.evaluate("stage => { test.nextResult = test.result('running', stage); }", stage)
            page.evaluate('() => test.tick()')
            assert page.locator('.search-progress-title').inner_text() == '搜索中'
            assert phrase in page.locator('.search-progress-note').inner_text()
            assert page.locator('#icon-cancel').is_visible()
        page.screenshot(path=str(output / 'searching.png'), full_page=True)
        checks.append('queued and actual running stages remain visible in the right pane')

        page.evaluate("() => { test.nextResult = test.result('running', 'searching', 3); }")
        page.evaluate('() => test.tick()')
        assert page.locator('.icon-weak-candidates').evaluate('(element) => element.open')
        assert page.locator('.icon-candidate').count() == 3
        assert all(page.locator('.icon-collect-button').nth(i).is_disabled() for i in range(3))
        assert page.locator('.icon-model-details').evaluate('(element) => !element.open')
        page.locator('.icon-model-details > summary').click()
        assert '请求：requested；返回：alias' in page.locator('.icon-model-details').inner_text()
        page.locator('.icon-weak-candidates > summary').click()
        page.evaluate('() => test.tick()')
        assert page.locator('.icon-weak-candidates').evaluate('(element) => !element.open')
        assert page.locator('.icon-model-details').evaluate('(element) => element.open')
        checks.append('new weak candidates open automatically; later user collapse and model expansion survive polling')

        page.evaluate("() => { test.nextResult = test.result('completed', 'completed', 3); }")
        page.evaluate('() => test.tick()')
        assert page.locator('.search-progress-title').inner_text() == '找到 3 条弱相关候选'
        assert page.locator('.search-progress-note').inner_text() == '候选未核实，尚未访问目标网站。'
        assert page.locator('#icon-results').get_attribute('aria-busy') == 'false'
        assert page.locator('#search-tab-status').inner_text() == '3 条候选'
        assert page.locator('.icon-weak-candidates').evaluate('(element) => !element.open')
        assert page.locator('#icon-cancel').is_hidden()
        page.locator('.icon-weak-candidates > summary').click()
        page.locator('.icon-model-details > summary').click()
        assert page.locator('.icon-collect-button').first.is_enabled()
        page.screenshot(path=str(output / 'weak-candidates.png'), full_page=True)
        checks.append('completed search emphasizes candidate count, concise caveat, and usable expanded results')

        # Repeat with the same selected file: the old completed ID must not remain cancellable.
        page.locator('#icon-search-button').click()
        assert page.locator('#icon-cancel').is_hidden()
        assert page.locator('#icon-results').inner_text() == ''
        assert page.locator('.search-progress-title').inner_text() == '搜索中'
        repeated_key = page.evaluate('() => test.calls.at(-1).key')
        assert page.evaluate("() => test.calls.filter(call => call.path.endsWith('/cancel')).length") == 0
        page.evaluate('() => test.rejectSubmit(new Error("Synthetic repeated submission failed"))')
        page.wait_for_function('() => document.querySelector(".search-progress-title").textContent === "搜索提交未确认"')
        assert page.locator('#icon-search-button').inner_text() == '重试本次提交'
        assert page.locator('#icon-cancel').is_hidden()
        page.locator('#icon-search-button').click()
        assert page.evaluate('() => test.calls.at(-1).key') == repeated_key
        assert page.locator('#icon-cancel').is_hidden()
        page.evaluate("() => { test.nextResult = test.result('completed', 'completed', 3); test.resolveSubmit({id:'synthetic-search'}); }")
        page.wait_for_function('() => document.querySelector(".search-progress-title").textContent === "找到 3 条弱相关候选"')
        checks.append('repeat search on the same image clears the old task ID and retains the new submission retry key')

        # Exercise clipboard capability/permission branches without touching the OS clipboard.
        page.evaluate('''() => {
          test.copyCalls = []; test.clipboardMode = 'secure';
          Object.defineProperty(window, 'isSecureContext', {configurable:true, value:true});
          Object.defineProperty(navigator, 'clipboard', {configurable:true, value:{writeText:async value => {
            if (test.clipboardMode !== 'secure') throw new Error('Synthetic clipboard permission denied');
            test.copyCalls.push(['secure', value]);
          }}});
          document.execCommand = command => {
            test.copyCalls.push([command, document.activeElement.value]);
            return test.clipboardMode !== 'denied';
          };
        }''')
        copy = page.locator('.icon-copy-button').first
        await_label = "() => document.querySelector('.icon-copy-button').textContent === '已复制'"
        copy.click()
        page.wait_for_function(await_label)
        assert page.evaluate('() => test.copyCalls.at(-1)') == ['secure', 'https://candidate.synthetic.invalid/0']
        page.evaluate("() => { test.clipboardMode = 'fallback'; }")
        copy.click()
        page.wait_for_function("() => test.copyCalls.at(-1)[0] === 'copy'")
        assert page.evaluate('() => test.copyCalls.at(-1)[1]') == 'https://candidate.synthetic.invalid/0'
        page.evaluate("() => { Object.defineProperty(window, 'isSecureContext', {value:false}); test.clipboardMode = 'http'; }")
        copy.click()
        assert page.evaluate('() => test.copyCalls.at(-1)[0]') == 'copy'
        page.evaluate("() => { test.clipboardMode = 'denied'; }")
        copy.click()
        page.wait_for_function("() => document.querySelector('.icon-copy-feedback').textContent.includes('Ctrl+C')")
        assert page.evaluate('() => getSelection().toString()') == 'https://candidate.synthetic.invalid/0'
        assert page.locator('textarea[readonly]').count() == 0
        checks.append('copy preserves full URLs with HTTPS, HTTP fallback, permission denial and manual selection; no collection')

        for state, error, count, expected in (
            ('partial', 'icon_timeout', 2, '找到 2 条弱相关候选'),
            ('completed', '', 0, '本次未找到候选'),
            ('failed', 'icon_provider_failed', 0, '搜索失败'),
            ('failed', 'icon_timeout', 0, '搜索超时'),
        ):
            page.evaluate('() => test.search.reset()')
            select_and_submit()
            page.evaluate('''([state, error, count]) => {
              test.nextResult = test.result(state, 'finished', count, error);
              test.resolveSubmit({id:'synthetic-search'});
            }''', [state, error, count])
            page.wait_for_function('(title) => document.querySelector(".search-progress-title").textContent === title', arg=expected)
            if state == 'partial':
                assert '时限' in page.locator('.search-progress-note').inner_text()
                assert page.locator('.icon-weak-candidates').evaluate('(element) => element.open')
            if state == 'completed':
                assert '不代表没有 Android 版本' in page.locator('.search-progress-note').inner_text()
        checks.append('partial, empty, provider failure and timeout preserve distinct outcome meanings')

        page.evaluate('() => test.search.reset()')
        select_and_submit()
        page.evaluate("() => { test.nextResult = test.result('running', 'searching'); test.resolveSubmit({id:'synthetic-search'}); }")
        page.wait_for_function('() => !document.getElementById("icon-cancel").hidden')
        page.locator('#icon-cancel').click()
        assert page.locator('.search-progress-title').inner_text() == '正在取消搜索'
        assert page.locator('#icon-cancel').is_disabled()
        page.evaluate('() => test.resolveCancel({cancel_requested:true})')
        page.wait_for_function('() => document.getElementById("icon-status").textContent.includes("等待后台确认")')
        assert page.locator('.search-progress-title').inner_text() == '正在取消搜索'
        page.evaluate("() => { test.nextResult = test.result('cancelled', 'finished', 0, 'cancelled'); }")
        page.evaluate('() => test.tick()')
        assert page.locator('.search-progress-title').inner_text() == '搜索已取消'
        assert page.locator('#search-tab-status').inner_text() == '已取消'
        checks.append('cancel request does not claim completion before backend confirmation')

        page.evaluate('() => test.search.reset()')
        select_and_submit()
        page.evaluate('() => { test.search.reset(); test.resolveSubmit({id:"synthetic-search"}); }')
        assert page.locator('#icon-search-progress').is_hidden()
        assert page.locator('#icon-result-empty').is_visible()
        assert page.locator('#icon-results').inner_text() == ''
        assert page.evaluate('() => test.timers.size') == 0
        checks.append('late submission after reset cannot restore progress or start polling')

        select_and_submit()
        page.evaluate('() => test.rejectSubmit(new Error("Synthetic connection failed"))')
        page.wait_for_function('() => document.querySelector(".search-progress-title").textContent === "搜索提交未确认"')
        assert page.locator('#icon-search-button').inner_text() == '重试本次提交'
        previous = page.evaluate('() => test.calls.at(-1).key')
        page.locator('#icon-search-button').click()
        assert page.evaluate('() => test.calls.at(-1).key') == previous
        page.evaluate("() => { test.nextResult = test.result('running', 'searching'); test.resolveSubmit({id:'synthetic-search'}); }")
        page.wait_for_function('() => test.timers.size === 1')
        page.evaluate('() => { test.pollError = new Error("Synthetic poll failed"); }')
        page.evaluate('() => test.tick()')
        assert page.locator('.search-progress-title').inner_text() == '暂时无法更新进度'
        assert '尚不能确认搜索是否结束' in page.locator('.search-progress-note').inner_text()
        assert page.evaluate('() => test.timers.size') == 1
        page.evaluate('() => { test.pollError = null; test.search.reset(); }')
        assert page.evaluate('() => test.timers.size') == 0
        assert not errors, errors
        assert not external, external
        assert page.evaluate("() => test.calls.filter(call => call.path.includes('/collect') || call.path === '/api/jobs').length") == 0
        checks.append('uncertain submission reuses its key; poll failures are not presented as search completion')
        context.close()
        browser.close()
    receipt = {'passed': True, 'checks': checks, 'page_errors': errors, 'external_requests': external,
               'scope': 'Installed desktop Chrome; synthetic asynchronous APIs; no real providers or targets'}
    (output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'passed': True, 'checks': len(checks), 'output': str(output)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
