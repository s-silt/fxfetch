"""Model-save reconciliation and elapsed feedback with synthetic APIs only."""
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
    output = root / '.runtime/model-feedback-ui' / str(time.time_ns())
    output.mkdir(parents=True)
    html = re.sub(r'<script\b[^>]*>.*?</script>|<link\b[^>]*>', '',
                  (static / 'index.html').read_text(encoding='utf-8'), flags=re.DOTALL)
    errors: list[str] = []
    external: list[str] = []
    checks: list[str] = []
    provider_errors = {
        'icon_provider_forbidden': 'HTTP 403', 'icon_provider_timeout': '响应超时',
        'icon_provider_tls': 'TLS', 'icon_provider_proxy': '模型代理连接失败',
        'icon_provider_connection': '无法连接', 'icon_provider_response_invalid': '格式无效',
        'icon_provider_incomplete': '未完整接收', 'icon_provider_http': '异常 HTTP',
    }
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel='chrome', headless=True,
                                             args=['--disable-background-networking'])
        context = browser.new_context(viewport={'width': 1440, 'height': 900})

        def reject(route):
            external.append(route.request.url)
            route.abort()

        context.route('**/*', reject)

        def page_for(module: str):
            page = context.new_page()
            page.set_default_timeout(8000)
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.set_content(html)
            page.add_style_tag(content=(static / 'app.css').read_text(encoding='utf-8'))
            page.add_script_tag(content=(static / module).read_text(encoding='utf-8'))
            page.evaluate("""() => {
              document.getElementById('workspace').hidden = false;
              document.getElementById('login-panel').hidden = true;
            }""")
            return page

        def model_page(*, writes: bool = True, read_failure: bool = False):
            page = page_for('model-settings.js')
            page.evaluate("""options => {
              const t = window.test = {calls:[], actual:'synthetic/current', allowed:true,
                writes:options.writes, readFailure:false};
              t.api = async (path, options={}) => {
                t.calls.push({path, method:options.method || 'GET'});
                if (path.endsWith('/refresh')) {
                  if (t.listError) throw {code:t.listError,status:400,httpStatus:t.listErrorHttp};
                  return {current_model:t.actual, models:['synthetic/alternate'], list_token:'synthetic-token'};
                }
                if (options.method === 'POST') {
                  if (t.writes) t.actual=options.body.model;
                  t.readFailure=options.readFailureAfterSave;
                  throw {code:'network_error'};
                }
                if (t.deferRead) return new Promise(resolve => {t.resolveRead=resolve;});
                if (t.readFailure) throw {code:'network_error'};
                return {current_model:t.actual};
              };
              const api=(path,options={}) => t.api(path,{...options,readFailureAfterSave:options.method==='POST' && !path.endsWith('/refresh') && t.failReconcile});
              t.failReconcile=options.read_failure;
              t.settings=FxfetchModelSettings.create({api,enabled:()=>t.allowed,changed:model=>{t.confirmed=model;}});
            }""", {'writes': writes, 'read_failure': read_failure})
            page.locator('#model-settings > summary').click()
            page.wait_for_function("document.querySelector('#model-current').textContent==='synthetic/current'")
            page.locator('#model-refresh').click()
            page.wait_for_function("document.querySelector('#model-list-count').textContent.includes('1')")
            page.locator('#model-choice').select_option('synthetic/alternate')
            return page

        page = model_page()
        page.locator('#model-save').click()
        page.wait_for_function("document.querySelector('#model-settings-status').textContent.includes('确认保存成功')")
        assert page.locator('#model-current').inner_text() == 'synthetic/alternate'
        calls = page.evaluate('test.calls')
        assert sum(call['method'] == 'POST' and call['path'] == '/api/model-settings' for call in calls) == 1
        assert calls[-1] == {'path': '/api/model-settings', 'method': 'GET'}
        checks.append('lost acknowledgement after write reconciles through one local GET without another POST')
        page.close()

        page = model_page(writes=False)
        page.locator('#model-save').click()
        page.wait_for_function("document.querySelector('#model-settings-status').textContent.includes('未生效')")
        assert page.locator('#model-current').inner_text() == 'synthetic/current'
        assert page.locator('#model-choice').input_value() == 'synthetic/alternate'
        assert page.locator('#model-save').is_enabled()
        checks.append('different actual value is displayed while the uncommitted choice is preserved')
        page.close()

        page = model_page(read_failure=True)
        page.locator('#model-save').click()
        page.wait_for_function("document.querySelector('#model-recheck').hidden===false && !document.querySelector('#model-recheck').disabled")
        assert '待核对' in page.locator('#model-current').inner_text()
        assert page.locator('#model-save').is_disabled() and page.locator('#model-refresh').is_disabled()
        page.screenshot(path=str(output / 'desktop-save-unconfirmed.png'), full_page=True)
        page.set_viewport_size({'width': 390, 'height': 844})
        page.screenshot(path=str(output / 'narrow-save-unconfirmed.png'))
        for selector in ('#model-settings > summary', '#model-settings-content', '#model-recheck'):
            box = page.locator(selector).bounding_box()
            assert box and box['x'] >= 0 and box['x'] + box['width'] <= 391
        page.evaluate('test.readFailure=false')
        page.locator('#model-recheck').click()
        page.wait_for_function("document.querySelector('#model-settings-status').textContent.includes('确认保存成功')")
        assert page.evaluate("test.calls.filter(c=>c.method==='POST' && c.path==='/api/model-settings').length") == 1
        checks.append('failed reconciliation locks mutations and the explicit retry only reads local settings')
        page.close()

        page = model_page()
        page.evaluate('test.deferRead=true')
        page.locator('#model-save').click()
        page.wait_for_function("typeof test.resolveRead==='function'")
        page.evaluate("() => {test.allowed=false;test.settings.reset();test.resolveRead({current_model:'synthetic/alternate'});}")
        page.wait_for_timeout(40)
        assert page.locator('#model-current').text_content() == '尚未读取'
        assert page.locator('#model-recheck').is_hidden()
        checks.append('reset and logout ignore a late reconciliation result')
        page.close()

        for code, text in provider_errors.items():
            page = model_page()
            page.evaluate('value=>{test.listError=value}', code)
            page.locator('#model-refresh').click()
            page.wait_for_function('text=>document.querySelector("#model-settings-status").textContent.includes(text)', arg=text)
            page.close()
        checks.append('all new supplier errors have specific model-list messages')
        page = model_page()
        page.evaluate("() => {test.listError='icon_provider_http';test.listErrorHttp=502;}")
        page.locator('#model-refresh').click()
        page.wait_for_function("document.querySelector('#model-settings-status').textContent.includes('HTTP 502')")
        page.close()

        page = page_for('icon-search.js')
        page.evaluate("""() => {
          document.getElementById('collect-workspace').hidden=true;
          document.getElementById('icon-search-panel').hidden=false;
          const t=window.test={calls:[],clock:10000,timers:new Map(),intervals:new Map(),serial:0};
          Object.defineProperty(performance,'now',{value:()=>t.clock});
          window.setTimeout=fn=>{const id=++t.serial;t.timers.set(id,fn);return id;};
          window.clearTimeout=id=>t.timers.delete(id);
          window.setInterval=(fn,ms)=>{if(ms!==1000)throw new Error('Unexpected interval');const id=++t.serial;t.intervals.set(id,fn);return id;};
          window.clearInterval=id=>t.intervals.delete(id);
          t.tick=async()=>{const [id,fn]=t.timers.entries().next().value;t.timers.delete(id);await fn();};
          t.api=async(path,options={})=>{t.calls.push({path,method:options.method||'GET'});return path==='/api/icon-searches'?{id:'synthetic-search'}:structuredClone(t.result);};
          t.result={id:'synthetic-search',state:'running',stage:'recognizing',candidates:[],timing:{
            started_at:9000000000,stage_started_at:9000000000,total_seconds:20,stage_elapsed_seconds:17,
            stages:[],requests:[]}};
          t.search=FxfetchIconSearch.create({api:t.api,key:()=>'synthetic-key',collected:()=>{},enabled:()=>true});
        }""")

        def start_search():
            page.locator('#icon-file').set_input_files({'name': 'synthetic.png', 'mimeType': 'image/png', 'buffer': picture()})
            page.locator('#icon-search-button').click()

        start_search()
        page.wait_for_function("document.querySelector('.search-timing-total')?.textContent.includes('0:20')")
        initial_calls = page.evaluate('test.calls.length')
        page.evaluate('() => {test.clock+=2500;for(const tick of test.intervals.values())tick();}')
        assert '0:22' in page.locator('.search-timing-total').inner_text()
        assert '0:19' in page.locator('.search-timing-stage').inner_text()
        assert page.evaluate('test.calls.length') == initial_calls
        page.evaluate("() => {test.result.timing.total_seconds=179;test.result.timing.stage_elapsed_seconds=80;}")
        page.evaluate('test.tick()')
        page.evaluate('() => {test.clock+=2500;for(const tick of test.intervals.values())tick();}')
        assert '等待后台确认状态' in page.locator('.search-timing-total').inner_text()
        assert page.locator('.search-progress-title').inner_text() == '搜索中'
        assert page.locator('#icon-cancel').is_visible()
        page.screenshot(path=str(output / 'search-running-timing.png'), full_page=True)
        checks.append('one-second monotonic elapsed display makes no API calls and never declares a local timeout terminal')

        page.evaluate("""() => {test.result={id:'synthetic-search',state:'completed',stage:'completed',candidates:[],timing:{
          total_seconds:123.4,stage_elapsed_seconds:0,stages:[{stage:'recognizing',elapsed_seconds:98.5},{stage:'searching',elapsed_seconds:20.5}],
          requests:[{stage:'recognizing',route:'direct',response_wait_seconds:97,body_read_seconds:1.5,total_seconds:98.5,http_status:200}]}};}""")
        page.evaluate('test.tick()')
        assert '总耗时 2:03' in page.locator('.search-timing-total').inner_text()
        page.locator('.search-timing-details > summary').click()
        summary = page.locator('.search-timing-details').inner_text()
        assert '98.5 秒' in summary and '等待响应 97.0 秒' in summary and '读取响应 1.5 秒' in summary
        assert '不能据此计算纯模型推理时间' in summary
        assert page.evaluate('test.intervals.size') == 0
        page.screenshot(path=str(output / 'search-final-timing.png'), full_page=True)
        checks.append('terminal duration is frozen and the stage/request summary separates response wait and body read')

        for code, text in provider_errors.items():
            page.evaluate("code=>{test.result={id:'synthetic-search',state:'failed',stage:'finished',candidates:[],error:code};}", code)
            start_search()
            page.wait_for_function('text=>document.querySelector("#icon-search-progress").textContent.includes(text)', arg=text)
            assert page.locator('.search-timing-total').count() == 0
        page.evaluate("() => {test.result={id:'synthetic-search',state:'failed',stage:'finished',candidates:[],error:'icon_provider_http',error_detail:{stage:'recognizing',http_status:502}};}")
        start_search()
        page.wait_for_function("document.querySelector('#icon-search-progress').textContent.includes('HTTP 502')")
        assert '识别名称和图标阶段' in page.locator('#icon-search-progress').inner_text()
        checks.append('old records without timing remain compatible and each new supplier failure has specific feedback')
        page.evaluate('test.search.reset()')
        assert page.evaluate('test.intervals.size') == 0

        page = page_for('data-package.js')
        page.add_script_tag(content=(static / 'analysis.js').read_text(encoding='utf-8'))
        app_source = (static / 'app.js').read_text(encoding='utf-8')
        startup = next(line for line in app_source.splitlines() if line.startswith('  api("/api/session").then('))
        # Only the test copy exposes the renderer and replaces the startup API call.
        app_source = app_source.replace(startup, '  globalThis.feedbackJob = {set:job=>{state.job=job;renderJob();}};')
        page.add_script_tag(content=app_source)
        page.evaluate("""() => {window.syntheticJob={id:'synthetic-job',state:'completed',outcome:'failed',
          input:{entry_url:'https://entry.synthetic.invalid/'},
          result:{reason_code:'candidate_selection_required',coverage:'partial',candidate_advice:{state:'not_needed'}},
          download_candidates:[{id:'synthetic-candidate',kind:'direct_apk',label:'Synthetic Android',url:'https://candidate.synthetic.invalid/app.apk'}],
          web_candidates:[],artifacts:[],builds:[]};feedbackJob.set(syntheticJob);}""")
        original_outcome = page.locator('.package-result').inner_text()
        advice_errors = {
            'ai_timeout': '达到限时', 'ai_budget_insufficient': '剩余时间不足',
            'ai_worker_failed': '判断未能完成', 'invalid_model_response': '返回内容格式无效',
            **provider_errors,
        }
        # HTTP 403 is carried separately from the provider error code.
        advice_errors['icon_provider_forbidden'] = '拒绝访问'
        for code, text in advice_errors.items():
            page.evaluate("""code=>{syntheticJob.result.candidate_advice={state:'manual',reason:code,
              elapsed_seconds:2.125,error_detail:{http_status:403}};feedbackJob.set(syntheticJob);}""", code)
            assert text in page.locator('.candidate-advice').inner_text()
            assert 'HTTP 403' in page.locator('.candidate-advice').inner_text()
            assert page.locator('.candidate-advice-timing').inner_text() == 'AI 判断耗时 2.1 秒。'
            assert page.locator('.package-result').inner_text() == original_outcome
            assert page.locator('.continuation-candidates input').count() == 1
        for value in ('403', -1, 999, None):
            page.evaluate("value=>{syntheticJob.result.candidate_advice.error_detail.http_status=value;feedbackJob.set(syntheticJob);}", value)
            assert '上游 HTTP' not in page.locator('.candidate-advice').inner_text()
        for value in ('2.5', -1, None):
            page.evaluate("value=>{syntheticJob.result.candidate_advice.elapsed_seconds=value;feedbackJob.set(syntheticJob);}", value)
            assert page.locator('.candidate-advice-timing').count() == 0
        page.evaluate("() => {syntheticJob.result.candidate_advice={state:'manual',reason:'ai_timeout',elapsed_seconds:45};feedbackJob.set(syntheticJob);}")
        page.screenshot(path=str(output / 'candidate-ai-timeout.png'), full_page=True)
        checks.append('candidate AI timeout, budget, worker and provider feedback preserve the original outcome and candidates; numeric timing/status are bounded')
        assert not errors and not external, (errors, external)
        browser.close()
    receipt = {'passed': True, 'checks': checks, 'supplier_requests': 0, 'target_requests': 0, 'output': str(output)}
    (output / 'result.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
