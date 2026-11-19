"""Installed-Chrome name/recognition UI acceptance with synthetic APIs only."""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright
from test_icon_search import picture


def timing_check() -> None:
    """Poll delayed, unchanged timing snapshots in Chrome without resetting elapsed time."""
    root = Path(__file__).resolve().parents[1]
    static = root / 'src/fxfetch/web/static'
    output = root / '.runtime/name-search-timing-ui' / str(time.time_ns())
    output.mkdir(parents=True)
    html = re.sub(r'<script\b[^>]*>.*?</script>|<link\b[^>]*>', '',
                  (static / 'index.html').read_text(encoding='utf-8'), flags=re.DOTALL)
    errors: list[str] = []
    external: list[str] = []
    checks: list[str] = []
    samples: list[dict] = []
    state: dict = {'id': 'a' * 32, 'gets': 0, 'posts': 0, 'response_delay_seconds': 0.15,
                   'result': {'id': 'a' * 32, 'mode': 'recognize', 'state': 'running',
                              'stage': 'validating', 'candidates': [], 'timing': {
                                  'started_at': 1000, 'stage_started_at': 1000,
                                  'total_seconds': 0.25, 'stage_elapsed_seconds': 0.05,
                                  'stages': [], 'requests': []}}}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel='chrome', headless=True,
                                             args=['--disable-background-networking'], timeout=20000)
        context = browser.new_context(viewport={'width': 1440, 'height': 1000})

        def intercept(route):
            url, method = route.request.url, route.request.method
            if url == 'http://synthetic.test/' and method == 'GET':
                route.fulfill(status=200, content_type='text/html', body=html)
            elif url == 'http://synthetic.test/api/icon-recognitions' and method == 'POST':
                state['posts'] += 1
                route.fulfill(status=202, content_type='application/json', body=json.dumps({'id': state['id']}))
            elif re.fullmatch(r'http://synthetic\.test/api/icon-searches/[ab]{32}', url) and method == 'GET':
                state['gets'] += 1
                time.sleep(state['response_delay_seconds'])
                route.fulfill(status=200, content_type='application/json', body=json.dumps(state['result']))
            else:
                external.append(url)
                route.abort()

        context.route('**/*', intercept)
        page = context.new_page()
        page.set_default_timeout(8000)
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.goto('http://synthetic.test/')
        page.add_style_tag(content=(static / 'app.css').read_text(encoding='utf-8'))
        for module in ['workspace.js', 'icon-search.js']:
            page.add_script_tag(content=(static / module).read_text(encoding='utf-8'))
        page.evaluate('''() => {
          document.getElementById('workspace').hidden=false;
          const t=window.timingTest={lastReceived:null,serial:0};
          t.api=async(path,options={})=>{
            const response=await fetch(path,{method:options.method||'GET',body:options.body,
              headers:options.headers});
            const value=await response.json();t.lastReceived=value;return value;
          };
          t.search=FxfetchIconSearch.create({api:t.api,key:()=>`synthetic-timing-${++t.serial}`,
            enabled:()=>true,capabilities:()=>({recognition_enabled:true,name_enabled:true}),collected:()=>{}});
          t.workspace=FxfetchWorkspace.create({api:t.api,canEdit:()=>true,onMode:()=>{},onScan:()=>{}});
          t.workspace.showView('search');
        }''')

        def sample(label: str) -> dict:
            total_text = page.locator('.search-timing-total').inner_text()
            total_match = re.search(r'(\d+):(\d+)', total_text)
            assert total_match is not None
            stage_text = page.locator('.search-timing-stage').inner_text() if page.locator('.search-timing-stage').count() else ''
            stage_match = re.search(r'(\d+):(\d+)', stage_text)
            value = {'label': label, 'total_seconds': int(total_match[1]) * 60 + int(total_match[2]),
                     'stage_seconds': int(stage_match[1]) * 60 + int(stage_match[2]) if stage_match else None,
                     'total_text': total_text, 'stage_text': stage_text, 'get_responses': state['gets']}
            samples.append(value)
            return value

        page.locator('#icon-file').set_input_files({'name': 'synthetic.png', 'mimeType': 'image/png', 'buffer': picture()})
        page.locator('#icon-search-button').click()
        page.wait_for_selector('.search-timing-total')
        repeated = []
        for index, delay in enumerate([1200, 2200, 2200]):
            page.wait_for_timeout(delay)
            repeated.append(sample(f'identical_snapshot_{index + 1}'))
        assert repeated[-1]['get_responses'] >= 3
        assert repeated[-1]['total_seconds'] >= 5 and repeated[-1]['stage_seconds'] >= 5
        assert all(a['total_seconds'] <= b['total_seconds'] and a['stage_seconds'] <= b['stage_seconds']
                   for a, b in zip(repeated, repeated[1:], strict=False))
        checks.append('delayed repeated identical snapshots keep total and phase counters increasing across two-second polls')

        state['result']['timing'].update(total_seconds=2.0, stage_elapsed_seconds=1.8)
        page.wait_for_function('timingTest.lastReceived?.timing?.total_seconds===2')
        advanced = sample('server_snapshot_advanced_behind_estimate')
        assert advanced['total_seconds'] >= repeated[-1]['total_seconds']
        assert advanced['stage_seconds'] >= repeated[-1]['stage_seconds']
        state['result']['timing'].update(total_seconds=1.0, stage_elapsed_seconds=0.8)
        page.wait_for_function('timingTest.lastReceived?.timing?.total_seconds===1')
        stale = sample('stale_snapshot_ignored')
        assert stale['total_seconds'] >= advanced['total_seconds'] and stale['stage_seconds'] >= advanced['stage_seconds']
        checks.append('advanced but delayed snapshots and stale snapshots cannot make running estimates go backwards')

        state['result'].update(stage='recognizing')
        state['result']['timing'].update(total_seconds=5.0, stage_elapsed_seconds=0.2, stage_started_at=1005)
        page.wait_for_function("timingTest.lastReceived?.stage==='recognizing'")
        changed = sample('new_stage_server_anchor')
        assert changed['total_seconds'] >= stale['total_seconds'] and changed['stage_seconds'] <= 1
        assert '识别名称和图标' in changed['stage_text']
        page.wait_for_timeout(2200)
        phase_later = sample('new_stage_repeated_snapshot')
        assert phase_later['total_seconds'] >= changed['total_seconds'] + 2 and phase_later['stage_seconds'] >= 2
        page.screenshot(path=str(output / 'recognition-timing-running.png'), full_page=True)
        checks.append('phase switch resets its phase duration from server while total continues; repeated new-phase snapshot still advances')

        state['result'].update(state='completed', stage='completed', result='recognized',
                               recognition={'name': '示例应用', 'confidence': 'high',
                                            'requested_model': 'synthetic', 'returned_model': 'synthetic'})
        state['result']['timing'].update(total_seconds=8.4, stage_elapsed_seconds=0,
                                         stages=[{'stage': 'validating', 'elapsed_seconds': 5.0},
                                                 {'stage': 'recognizing', 'elapsed_seconds': 3.4}])
        page.wait_for_function("document.querySelector('.search-timing-total')?.textContent.startsWith('总耗时 ')")
        final = sample('authoritative_terminal_duration')
        assert final['total_seconds'] == 8 and final['stage_seconds'] is None
        assert '本地估算' not in final['total_text']
        page.wait_for_timeout(1200)
        assert page.locator('.search-timing-total').inner_text() == final['total_text']
        page.screenshot(path=str(output / 'recognition-timing-finished.png'), full_page=True)
        checks.append('completion stops the local clock and displays authoritative final server duration even below the estimate')

        state['id'] = 'b' * 32
        state['result'] = {'id': state['id'], 'mode': 'recognize', 'state': 'running',
                           'stage': 'validating', 'candidates': [], 'timing': {
                               'started_at': 2000, 'stage_started_at': 2000,
                               'total_seconds': 0.2, 'stage_elapsed_seconds': 0.1,
                               'stages': [], 'requests': []}}
        page.locator('#icon-search-button').click()
        page.wait_for_function("timingTest.lastReceived?.id==='b'.repeat(32)&&!!timingTest.lastReceived?.timing")
        fresh = sample('new_job_fresh_clock')
        assert fresh['total_seconds'] == 0 and fresh['stage_seconds'] == 0
        assert state['posts'] == 2 and not errors and not external
        checks.append('new job clears prior anchors and starts with its own server duration')
        browser.close()
    receipt = {'passed': len(checks), 'checks': checks, 'samples': samples,
               'mock_response_delay_seconds': state['response_delay_seconds'],
               'external_requests': external, 'browser_errors': errors, 'output': str(output)}
    (output / 'result.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(receipt, ensure_ascii=False))


def catalog_check() -> None:
    """Check real-catalog metadata/error presentation using synthetic responses."""
    root = Path(__file__).resolve().parents[1]
    static = root / 'src/fxfetch/web/static'
    output = root / '.runtime/name-search-catalog-ui' / str(time.time_ns())
    output.mkdir(parents=True)
    html = re.sub(r'<script\b[^>]*>.*?</script>|<link\b[^>]*>', '',
                  (static / 'index.html').read_text(encoding='utf-8'), flags=re.DOTALL)
    errors: list[str] = []
    external: list[str] = []
    checks: list[str] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel='chrome', headless=True,
                                             args=['--disable-background-networking'], timeout=20000)
        context = browser.new_context(viewport={'width': 1440, 'height': 1000})

        def reject(route):
            external.append(route.request.url)
            route.abort()

        context.route('**/*', reject)
        page = context.new_page()
        page.set_default_timeout(8000)
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.set_content(html)
        page.add_style_tag(content=(static / 'app.css').read_text(encoding='utf-8'))
        for module in ['workspace.js', 'icon-search.js']:
            page.add_script_tag(content=(static / module).read_text(encoding='utf-8'))
        page.evaluate('''() => {
          document.getElementById('workspace').hidden=false;
          const t=window.catalogTest={calls:[],serial:0};
          t.api=async(path,options={})=>{
            t.calls.push({path,method:options.method||'GET'});
            return path==='/api/name-searches'?{id:'c'.repeat(32)}:structuredClone(t.result);
          };
          t.base=()=>({id:'c'.repeat(32),mode:'name',query_name:'Synthetic Messenger',
            state:'completed',stage:'completed',candidates:[]});
          t.search=FxfetchIconSearch.create({api:t.api,key:()=>`synthetic-catalog-${++t.serial}`,
            enabled:()=>true,capabilities:()=>({recognition_enabled:false,name_enabled:true}),collected:()=>{}});
          t.workspace=FxfetchWorkspace.create({api:t.api,canEdit:()=>true,onMode:()=>{},onScan:()=>{}});
          t.workspace.showView('search');
          t.result={...t.base(),catalog_status:{provider:'Koodous',status:'hit',count:2,returned:1,next_page_available:true},
            candidates:[{id:'1',category:'sample_record',channel:'koodous_api',catalog:'Koodous',
              title:'Synthetic Messenger',url:'https://koodous.com/apks/'+ 'b'.repeat(64),source:'Koodous',
              app_name:'Synthetic Messenger',package_name:'org.example.syntheticapp',version:'1.2.3',
              sha256:'b'.repeat(64),evidence:['name_in_title','koodous_api'],verified:false,downloadable:null},
             {id:'2',category:'download_page',title:'Synthetic Messenger Android',url:'https://download.example.test/app',
              source:'download.example.test',evidence:['name_in_title','android_text'],verified:false,downloadable:null}]};
        }''')
        page.locator('#search-mode-name').click()
        page.locator('#name-search-name').fill('Synthetic Messenger')
        page.locator('#name-search-button').click()
        page.wait_for_function("document.querySelectorAll('.icon-candidate').length===2")
        assert '库返回 2 条记录，本次展示 1 条' in page.locator('.catalog-status').inner_text()
        assert '本次未翻页' in page.locator('.catalog-status').inner_text()
        assert 'org.example.syntheticapp' in page.locator('.sample-record-metadata').inner_text()
        assert 'SHA-256：' in page.locator('.sample-record-metadata').inner_text()
        assert page.get_by_text('查看样本记录 ↗', exact=True).count() == 1
        assert page.locator('.icon-collect-button').count() == 1
        assert page.locator('.sample-library-links').count() == 0
        page.screenshot(path=str(output / 'catalog-api-hit.png'), full_page=True)
        checks.append('API hit shows sample metadata and unqueried-page gap; sample record cannot collect as APK')

        page.evaluate('''() => {
          catalogTest.search.reset();
          catalogTest.result.catalog_status={provider:'Koodous',status:'hit',count:2,returned:1,
            next_page_available:false,coverage_complete:false};
        }''')
        page.locator('#search-mode-name').click()
        page.locator('#name-search-name').fill('Synthetic Messenger')
        page.locator('#name-search-button').click()
        page.wait_for_function("document.querySelector('.catalog-status')?.textContent.includes('结果覆盖不完整')")
        assert '本次未翻页' not in page.locator('.catalog-status').inner_text()
        assert '不能视为库内全部记录' in page.locator('.catalog-status').inner_text()
        page.screenshot(path=str(output / 'catalog-incomplete.png'), full_page=True)
        checks.append('incomplete catalog coverage is explicit even without a next-page flag')

        page.evaluate('''() => {
          catalogTest.search.reset();
          catalogTest.result.catalog_status={provider:'Koodous',status:'hit',count:null,page_returned:44,
            returned:20,next_page_available:false,truncated:true,coverage_complete:false};
        }''')
        page.locator('#search-mode-name').click()
        page.locator('#name-search-name').fill('Synthetic Messenger')
        page.locator('#name-search-button').click()
        page.wait_for_function("document.querySelector('.catalog-status')?.textContent.includes('总数未提供')")
        assert '本页返回 44 条，本次展示 20 条，总数未提供' in page.locator('.catalog-status').inner_text()
        assert '库返回 0 条' not in page.locator('.catalog-status').inner_text()
        assert '结果覆盖不完整' in page.locator('.catalog-status').inner_text()
        page.screenshot(path=str(output / 'catalog-unknown-count.png'), full_page=True)
        checks.append('unknown catalog total preserves returned-page count and truncation without inventing zero')

        page.evaluate('''() => {
          catalogTest.search.reset();catalogTest.result={...catalogTest.base(),state:'partial',
            catalog_status:{provider:'Koodous',status:'failed',http_status:401,
              error_code:'synthetic-private-value-never-display'},
            candidates:[{id:'2',category:'download_page',title:'Synthetic Messenger Android',
              url:'https://download.example.test/app',source:'download.example.test',
              evidence:['name_in_title','android_text'],verified:false,downloadable:null}]};
        }''')
        page.locator('#search-mode-name').click()
        page.locator('#name-search-name').fill('Synthetic Messenger')
        page.locator('#name-search-button').click()
        page.wait_for_function("document.querySelector('.catalog-status')?.textContent.includes('HTTP 401')")
        assert '无法判断是否收录' in page.locator('.catalog-status').inner_text()
        assert '无记录' not in page.locator('.catalog-status').inner_text()
        assert 'synthetic-private-value-never-display' not in page.locator('body').inner_text()
        assert page.locator('.icon-collect-button').count() == 1
        page.screenshot(path=str(output / 'catalog-unauthorized.png'), full_page=True)
        checks.append('unauthorized API is not no-record; safe fixed error text preserves other-source candidate')

        page.evaluate('''() => {
          catalogTest.search.reset();catalogTest.result={...catalogTest.base(),
            catalog_status:{provider:'Koodous',status:'no_record',count:0,returned:0,next_page_available:false}};
        }''')
        page.locator('#search-mode-name').click()
        page.locator('#name-search-name').fill('Synthetic Messenger')
        page.locator('#name-search-button').click()
        page.wait_for_function("document.querySelector('.catalog-status')?.textContent.includes('本次名称查询无记录')")
        assert '不代表不存在' in page.locator('.catalog-status').inner_text()
        checks.append('successful zero-result catalog response has limited no-record wording')

        page.evaluate('''() => {
          catalogTest.search.reset();catalogTest.result={...catalogTest.base(),
            catalog_status:{provider:'Koodous',status:'unconfigured'}};
        }''')
        page.locator('#search-mode-name').click()
        page.locator('#name-search-name').fill('Synthetic Messenger')
        page.locator('#name-search-button').click()
        page.wait_for_function("document.querySelectorAll('.sample-library-row').length===2")
        assert '接口未配置' in page.locator('.catalog-status').inner_text()
        assert not errors and not external
        checks.append('unconfigured catalog keeps truthful website fallback and manual official entry points')
        browser.close()
    receipt = {'passed': len(checks), 'checks': checks, 'external_requests': external,
               'browser_errors': errors, 'output': str(output)}
    (output / 'result.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(receipt, ensure_ascii=False))


def layout_check() -> None:
    """One small-desktop layout check; does not repeat the state regression suite."""
    root = Path(__file__).resolve().parents[1]
    static = root / 'src/fxfetch/web/static'
    output = root / '.runtime/name-search-ui-layout' / str(time.time_ns())
    output.mkdir(parents=True)
    html = re.sub(r'<script\b[^>]*>.*?</script>|<link\b[^>]*>', '',
                  (static / 'index.html').read_text(encoding='utf-8'), flags=re.DOTALL)
    errors: list[str] = []
    external: list[str] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel='chrome', headless=True,
                                             args=['--disable-background-networking'], timeout=20000)
        context = browser.new_context(viewport={'width': 1280, 'height': 800})

        def reject(route):
            external.append(route.request.url)
            route.abort()

        context.route('**/*', reject)
        page = context.new_page()
        page.set_default_timeout(8000)
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.set_content(html)
        page.add_style_tag(content=(static / 'app.css').read_text(encoding='utf-8'))
        for module in ['workspace.js', 'icon-search.js']:
            page.add_script_tag(content=(static / module).read_text(encoding='utf-8'))
        page.evaluate('''() => {
          document.getElementById('workspace').hidden=false;
          const t=window.layoutTest={calls:[]};
          t.api=async(path,options={})=>{
            t.calls.push({path,method:options.method||'GET'});
            return path==='/api/icon-recognitions'?{id:'a'.repeat(32)}:
              {id:'a'.repeat(32),mode:'recognize',result:'recognized',state:'completed',
               stage:'completed',search_attempts:0,candidates:[],recognition:{name:'示例应用名称',
                confidence:'high',requested_model:'synthetic',returned_model:'synthetic'}};
          };
          t.search=FxfetchIconSearch.create({api:t.api,key:()=> 'synthetic-layout-key',
            enabled:()=>true,capabilities:()=>({recognition_enabled:true,name_enabled:true}),collected:()=>{}});
          t.workspace=FxfetchWorkspace.create({api:t.api,canEdit:()=>true,onMode:()=>{},onScan:()=>{}});
          t.workspace.showView('search');
        }''')
        page.locator('#icon-file').set_input_files({'name': 'synthetic.png', 'mimeType': 'image/png', 'buffer': picture()})
        page.locator('#icon-search-button').click()
        page.wait_for_function("document.querySelector('#name-search-name').value==='示例应用名称'")
        page.locator('#name-search-button').scroll_into_view_if_needed()
        measurements = page.evaluate('''() => {
          const card=document.querySelector('.search-input'),c=card.getBoundingClientRect();
          const controls=Object.fromEntries(['name-search-name','name-search-button'].map(id=>{
            const r=document.getElementById(id).getBoundingClientRect();
            return [id,{left:r.left,right:r.right,top:r.top,bottom:r.bottom,
              inCard:r.left>=c.left&&r.right<=c.right&&r.top>=c.top&&r.bottom<=c.bottom,
              inViewport:r.top>=0&&r.bottom<=innerHeight}];
          }));
          return {viewport:{width:innerWidth,height:innerHeight},card:{top:c.top,bottom:c.bottom,
            height:c.height,scrollTop:card.scrollTop,scrollHeight:card.scrollHeight,clientHeight:card.clientHeight},controls};
        }''')
        assert all(control['inCard'] and control['inViewport'] for control in measurements['controls'].values()), measurements
        assert page.evaluate("layoutTest.calls.filter(c=>c.path==='/api/name-searches').length") == 0
        assert not errors and not external
        page.screenshot(path=str(output / 'recognition-confirmation-1280x800.png'), full_page=True)
        browser.close()
    receipt = {'passed': True, 'check': 'recognition confirmation controls remain reachable inside 1280x800 input card',
               'measurements': measurements, 'external_requests': external, 'browser_errors': errors,
               'output': str(output)}
    (output / 'result.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(receipt, ensure_ascii=False))


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    static = root / 'src/fxfetch/web/static'
    output = root / '.runtime/name-search-ui' / str(time.time_ns())
    output.mkdir(parents=True)
    html = re.sub(r'<script\b[^>]*>.*?</script>|<link\b[^>]*>', '',
                  (static / 'index.html').read_text(encoding='utf-8'), flags=re.DOTALL)
    html = html.replace('<head>', '<head><base href="http://synthetic.test/">')
    errors: list[str] = []
    external: list[str] = []
    checks: list[str] = []
    print('Starting installed Chrome synthetic UI acceptance', flush=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel='chrome', headless=True,
                                             args=['--disable-background-networking'], timeout=20000)
        context = browser.new_context(viewport={'width': 1440, 'height': 1000})

        def intercept(route):
            if re.fullmatch(r'http://synthetic\.test/api/icon-searches/[ab]{32}/image/icon', route.request.url):
                route.fulfill(status=200, content_type='image/png', body=picture())
            else:
                external.append(route.request.url)
                route.abort()

        context.route('**/*', intercept)
        page = context.new_page()
        page.set_default_timeout(8000)
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.set_content(html)
        page.add_style_tag(content=(static / 'app.css').read_text(encoding='utf-8'))
        for module in ['workspace.js', 'icon-search.js']:
            page.add_script_tag(content=(static / module).read_text(encoding='utf-8'))
        page.evaluate('''() => {
          document.getElementById('workspace').hidden=false;
          const t=window.test={calls:[], serial:0, timers:new Map(), allowed:true,
            cap:{recognition_enabled:false,name_enabled:true}, result:null, collects:[], submitted:[]};
          window.setTimeout=fn=>{const id=++t.serial;t.timers.set(id,fn);return id;};
          window.clearTimeout=id=>t.timers.delete(id);
          t.tick=async()=>{const row=t.timers.entries().next().value;if(row){t.timers.delete(row[0]);await row[1]();}};
          t.api=async(path,options={})=>{
            const call={path,method:options.method||'GET',key:options.headers?.['Idempotency-Key'],
              body:options.body instanceof FormData ? {image:true} : options.body};t.calls.push(call);
            if(path==='/api/name-searches'||path==='/api/icon-recognitions'){
              t.submitted.push(call);
              if(t.deferSubmit)return await new Promise((resolve,reject)=>{t.resolveSubmit=resolve;t.rejectSubmit=reject;});
              if(t.failSubmit){t.failSubmit=false;throw {code:'network_error',message:'synthetic disconnected'};}
              return {id:path==='/api/icon-recognitions'?'a'.repeat(32):'b'.repeat(32)};
            }
            if(path.endsWith('/collect')){t.collects.push(call);return {id:'synthetic-job'};}
            if(path.endsWith('/cancel'))return {cancel_requested:true};
            return structuredClone(t.result);
          };
          t.completeName=(candidates=[])=>({id:'b'.repeat(32),mode:'name',query_name:'示例应用',
            state:'completed',stage:'completed',candidates,search_attempts:2});
          t.completeRecognition=(name='示例应用')=>({id:'a'.repeat(32),mode:'recognize',result:'recognized',
            state:'completed',stage:'completed',search_attempts:0,candidates:[],
            recognition:{name,confidence:'high',requested_model:'synthetic',returned_model:'synthetic'}});
          t.search=FxfetchIconSearch.create({api:t.api,key:()=>`synthetic-${++t.serial}`,
            enabled:()=>t.allowed,capabilities:()=>t.cap,collected:job=>{t.collected=job;}});
          t.workspace=FxfetchWorkspace.create({api:t.api,canEdit:()=>true,onMode:()=>{},onScan:()=>{}});
          t.workspace.showView('search');
        }''')
        page.locator('#search-mode-name').click()
        assert page.locator('#icon-recognition-input').is_hidden()
        page.locator('#name-search-name').fill('示例应用')
        assert page.locator('#name-search-button').is_enabled()
        page.locator('#name-search-name').dispatch_event('keydown', {'key': 'Enter', 'isComposing': True})
        assert not page.evaluate('test.calls.length')
        page.evaluate('test.result=test.completeName()')
        page.locator('#name-search-button').click()
        page.wait_for_function('test.submitted.length===1')
        assert page.evaluate('test.submitted[0].body') == {'name': '示例应用'}
        assert page.evaluate('test.submitted[0].path') == '/api/name-searches'
        assert page.locator('.sample-library-row').count() == 2
        assert '不表示本服务已取得库内结果' in page.locator('.sample-library-links').inner_text()
        assert not page.evaluate("test.calls.some(c=>c.path.includes('/image/'))")
        assert not page.evaluate("test.calls.some(c=>c.path==='/api/icon-recognitions')")
        checks.append('name-only search works without a file or vision capability; input alone makes no request')

        page.evaluate('''() => {
          test.search.reset();test.cap={recognition_enabled:true,name_enabled:true};test.search.update();
          test.result={id:'a'.repeat(32),mode:'recognize',state:'running',stage:'recognizing',candidates:[]};
        }''')
        page.locator('#icon-file').set_input_files({'name': 'synthetic.png', 'mimeType': 'image/png', 'buffer': picture()})
        page.locator('#icon-search-button').click()
        page.wait_for_function("test.calls.some(c=>c.path==='/api/icon-recognitions')")
        calls_before_switch = page.evaluate('test.calls.length')
        page.locator('#search-mode-name').click()
        page.locator('#search-mode-image').click()
        assert page.evaluate('test.calls.length') == calls_before_switch
        checks.append('switching input modes preserves running task and makes no extra submit')
        page.locator('#name-search-name').fill('人工改名')
        page.evaluate("test.result=test.completeRecognition('识别结果');test.tick()")
        page.wait_for_function("document.querySelector('.search-progress-title').textContent.includes('名称已识别')")
        assert page.locator('#name-search-name').input_value() == '人工改名'
        assert page.evaluate("test.submitted.filter(c=>c.path==='/api/name-searches').length") == 1
        page.evaluate('test.result=test.completeName()')
        page.locator('#name-search-button').click()
        page.wait_for_function("test.submitted.filter(c=>c.path==='/api/name-searches').length===2")
        assert page.evaluate('test.submitted.at(-1).body') == {'name': '人工改名', 'recognition_id': 'a' * 32}
        checks.append('recognition does not auto-search; late recognition preserves manual name and explicit search binds image provenance')

        page.evaluate('''() => {
          test.search.reset();test.result=test.completeRecognition('识别名称');
        }''')
        page.locator('#icon-file').set_input_files({'name': 'synthetic.png', 'mimeType': 'image/png', 'buffer': picture()})
        page.locator('#icon-search-button').click()
        page.wait_for_function("document.querySelector('#name-search-name').value==='识别名称'")
        page.locator('#name-search-name').fill('校正名称')
        page.screenshot(path=str(output / 'recognition-confirmation-desktop.png'), full_page=True)
        page.locator('#icon-remove').click()
        assert page.locator('#name-search-name').input_value() == '校正名称'
        assert page.locator('#icon-recognition-input').is_hidden()
        checks.append('recognition fills editable name; removing image keeps user name and switches to independent name input')

        page.evaluate('''() => {
          test.result=test.completeName([
            {id:'1',url:'https://koodous.com/apks/synthetic',title:'示例应用 APK',source:'koodous.com',
             category:'sample_index',evidence:['name_in_title','sample_index_search'],verified:false,downloadable:null},
            {id:'2',url:'https://downloads.example.test/app',title:'示例应用 Android 下载',source:'downloads.example.test',
             category:'download_page',evidence:['name_in_title','android_text','targeted_download_search'],verified:false,downloadable:null},
            {id:'3',url:'https://notes.example.test/app',title:'示例应用资料',source:'notes.example.test',
             category:'web_candidate',evidence:['name_in_title'],verified:false,downloadable:null}]);
        }''')
        page.locator('#name-search-button').click()
        page.wait_for_function("document.querySelectorAll('.icon-candidate').length===3")
        assert page.locator('.icon-collect-button').count() == 1
        assert page.locator('.icon-candidate a').count() == 2
        assert page.evaluate('test.collects.length') == 0
        assert page.evaluate('''() => Array.from(document.querySelectorAll('.icon-candidate a')).every(a =>
          a.target==='_blank'&&a.rel.includes('noopener')&&a.rel.includes('noreferrer')&&a.referrerPolicy==='no-referrer')''')
        page.screenshot(path=str(output / 'name-results-desktop.png'), full_page=True)
        page.locator('.icon-collect-button').click()
        page.wait_for_function('test.collects.length===1')
        checks.append('sample-library/index and ordinary pages are reference links only; only explicit download candidate can collect')

        page.evaluate('''() => {test.search.reset();test.result=test.completeName();test.failSubmit=true;}''')
        page.locator('#search-mode-name').click()
        page.locator('#name-search-name').fill('第一次名称')
        page.locator('#name-search-button').click()
        page.wait_for_function("document.querySelector('#name-search-button').textContent==='重试本次提交'")
        assert page.locator('#name-search-name').is_disabled()
        before = page.evaluate('test.submitted.at(-1)')
        page.locator('#name-search-button').click()
        page.wait_for_function("document.querySelector('#name-search-button').textContent==='定向搜索'")
        after = page.evaluate('test.submitted.at(-1)')
        assert before['key'] == after['key'] and before['body'] == after['body']
        checks.append('unconfirmed name submission retries the same key and frozen name; no cross-mode re-submit')

        page.evaluate('''() => {
          test.search.reset();test.result={id:'b'.repeat(32),mode:'name',state:'running',stage:'searching',candidates:[]};
        }''')
        page.locator('#search-mode-name').click()
        page.locator('#name-search-name').fill('示例应用')
        page.locator('#name-search-button').click()
        page.wait_for_function("!document.querySelector('#icon-cancel').hidden")
        page.locator('#icon-cancel').click()
        page.evaluate("() => {test.result={id:'b'.repeat(32),mode:'name',state:'cancelled',stage:'finished',error:'cancelled',candidates:[]};test.tick();}")
        page.wait_for_function("document.querySelector('.search-progress-title').textContent==='搜索已取消'")
        assert page.evaluate("test.calls.filter(c=>c.path.endsWith('/cancel')).length") == 1
        checks.append('name task cancellation waits for backend state and stops without replaying searches')

        page.evaluate('''() => {
          test.search.reset();
          test.result={...test.completeName([{id:'1',url:'https://downloads.example.test/app',
            title:'示例应用 Android 下载',source:'downloads.example.test',category:'download_page',
            evidence:['name_in_title','android_text'],verified:false,downloadable:null}]),state:'partial',
            error:'icon_provider_timeout',error_detail:{stage:'searching',code:'icon_provider_timeout'},
            library_queries:[{provider:'Koodous',url:'https://koodous.com/',query:'app: "示例应用"',queried:false},
              {provider:'Injected',url:'javascript:alert(1)',query:'synthetic-invalid'}]};
        }''')
        page.locator('#search-mode-name').click()
        page.locator('#name-search-name').fill('示例应用')
        page.locator('#name-search-button').click()
        page.wait_for_function("document.querySelectorAll('.icon-candidate').length===1")
        assert '响应超时' in page.locator('.search-progress-note').inner_text()
        assert page.locator('.icon-collect-button').count() == 1
        assert page.locator('.sample-library-row').count() == 1
        assert page.locator('a[href^="javascript:"]').count() == 0
        checks.append('partial provider failure preserves candidates and allowlisted library-entry text without presenting an API match')

        page.evaluate('''() => {test.search.reset();test.deferSubmit=true;test.result=test.completeRecognition('迟到名称');}''')
        page.locator('#icon-file').set_input_files({'name': 'synthetic.png', 'mimeType': 'image/png', 'buffer': picture()})
        page.locator('#icon-search-button').click()
        page.wait_for_function('!!test.resolveSubmit')
        page.evaluate("() => {test.search.reset();test.deferSubmit=false;test.resolveSubmit({id:'a'.repeat(32)});}")
        page.wait_for_timeout(20)
        assert page.locator('#name-search-name').input_value() == ''
        assert page.locator('#icon-results').is_hidden()
        assert page.locator('#icon-search-progress').is_hidden()
        checks.append('clear/reset ignores late recognition and cannot restore fields or results')

        page.evaluate('''() => {test.cap={recognition_enabled:false,name_enabled:true};test.search.update();}''')
        page.locator('#search-mode-name').click()
        page.locator('#name-search-name').fill('示例应用')
        assert page.locator('#name-search-button').is_enabled()
        assert '可直接输入名称搜索' in page.locator('#search-capability-note').inner_text()
        assert page.evaluate('''() => {
          const card=document.querySelector('.search-input').getBoundingClientRect();
          return ['name-search-name','name-search-button'].every(id=>{const r=document.getElementById(id).getBoundingClientRect();return r.left>=card.left&&r.right<=card.right;});
        }''')
        page.screenshot(path=str(output / 'name-input-desktop.png'), full_page=True)
        checks.append('name controls remain usable and inside input card when recognition is unconfigured')
        assert not external, external
        assert not errors, errors
        browser.close()
    receipt = {'checks': checks, 'passed': len(checks), 'external_requests': external,
               'browser_errors': errors, 'output': str(output)}
    (output / 'result.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(receipt, ensure_ascii=False))


if __name__ == '__main__':
    if '--timing-only' in sys.argv:
        timing_check()
    elif '--catalog-only' in sys.argv:
        catalog_check()
    elif '--layout-only' in sys.argv:
        layout_check()
    else:
        main()
