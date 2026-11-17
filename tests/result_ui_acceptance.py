"""Result-first desktop display with synthetic records and all network blocked."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from desktop_ui_assertions import DESKTOP_SIZES, assert_desktop_workspace
from playwright.sync_api import sync_playwright


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    static = root / "src/fxfetch/web/static"
    output = root / ".runtime/result-ui" / str(time.time_ns())
    output.mkdir(parents=True)
    html = re.sub(r'<script\b[^>]*>.*?</script>|<link\b[^>]*>', '',
                  (static / 'index.html').read_text(encoding='utf-8'), flags=re.DOTALL)
    source = (static / 'app.js').read_text(encoding='utf-8')
    source = re.sub(r'^\s*api\("/api/session"\).*$', '', source, flags=re.MULTILINE)
    source = re.sub(r'\}\)\(\);\s*$',
                    'globalThis.resultTest = {state, renderJob};})();', source)
    errors: list[str] = []
    requests: list[str] = []
    screenshots: list[str] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel='chrome', headless=True,
                                             args=['--disable-background-networking'])
        for name, size in DESKTOP_SIZES.items():
            context = browser.new_context(viewport=size)

            def reject(route):
                requests.append(route.request.url)
                route.abort()

            context.route('**/*', reject)
            page = context.new_page()
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.set_content(html)
            page.add_style_tag(content=(static / 'app.css').read_text(encoding='utf-8'))
            for module in ('data-package.js', 'analysis.js', 'workspace.js', 'icon-search.js'):
                page.add_script_tag(content=(static / module).read_text(encoding='utf-8'))
            page.add_script_tag(content=source)
            page.evaluate('''() => {
              document.getElementById('workspace').hidden = false;
              resultTest.state.authenticated = true;
              resultTest.state.job = {id:'synthetic-result', state:'completed', outcome:'failed',
                input:{entry_url:'https://download.synthetic.invalid/'},
                result:{reason_code:'candidate_selection_required', coverage:'partial'},
                progress:{events:[{event:'task_completed', at:1}]},
                download_candidates:[
                  {id:'a', label:'Android 主下载', url:'https://download.synthetic.invalid/a.apk'},
                  {id:'b', label:'Android 备用下载', url:'https://download.synthetic.invalid/b.apk'}]};
              resultTest.renderJob();
            }''')
            assert page.title() == '应用采集工作台'
            assert_desktop_workspace(page)
            banner = page.locator('.package-result')
            assert banner.inner_text() == '原包结果：发现多个下载候选'
            assert page.locator('.continuation-candidates input').count() == 2
            assert page.evaluate('''() => {
              const result = document.querySelector('.package-result');
              const url = document.querySelector('#job-content > .job-url');
              const choices = document.querySelector('.continuation-panel');
              const history = document.querySelector('.collection-progress');
              return result.getBoundingClientRect().bottom <= url.getBoundingClientRect().top &&
                Boolean(choices.compareDocumentPosition(history) & Node.DOCUMENT_POSITION_FOLLOWING);
            }''')
            page.screenshot(path=str(output / f'{name}-candidates.png'), full_page=True)
            screenshots.append(f'{name}-candidates.png')
            context.close()
        browser.close()
    assert not errors and not requests
    receipt = {'passed': True, 'screenshots': screenshots, 'page_errors': errors,
               'requests': requests, 'scope': 'Installed Chrome; synthetic records; all network blocked'}
    (output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({**receipt, 'output': str(output)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
