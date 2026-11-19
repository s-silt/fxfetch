"""Exercise the production page and request layer with synthetic, intercepted data."""
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit

from playwright.sync_api import Route, expect, sync_playwright


def exercise_provider(provider: str, peer: str, error_prefix: str) -> None:
    static = Path(__file__).resolve().parents[1] / 'src/fxfetch/web/static'
    sample = b'synthetic attachment for the UI delivery check'
    digest = sha256(sample).hexdigest()
    identifier = 'b' * 32
    search = '/api/icon-searches/' + identifier
    source = provider.lower()
    base = f'{search}/candidates/1/{source}/'
    peer_base = f'{search}/candidates/1/{peer.lower()}/'
    csrf = 'synthetic-csrf-only'
    candidate = {
        'id': '1', 'category': 'sample_record', 'channel': 'koodous_api',
        'url': 'https://koodous.com/apks/' + digest, 'sha256': digest,
        'source': 'koodous.com', 'title': 'Synthetic record', 'evidence': ['name_in_title', 'koodous_api_record'],
    }
    receipt: dict = {'provider': provider, 'candidate_id': '1', 'sha256': digest,
                     'lookup': None, 'download': None, 'file_url': None}
    peer_receipt = dict(receipt, provider=peer, lookup={'status': 'no_record'})
    peer_calls: list[str] = []
    state: dict = {'ready': True, 'mode': 'no_record', 'published': None, 'calls': [], 'file_reads': 0}
    errors: list[str] = []
    unexpected: list[str] = []
    held: list[Route] = []

    class Attachment(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != base + 'file':
                unexpected.append(self.path)
                self.send_error(404)
                return
            state['file_reads'] += 1
            self.send_response(200)
            self.send_header('Content-Disposition', f'attachment; filename="{digest}.apk"')
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(sample)))
            self.end_headers()
            self.wfile.write(sample)

        def log_message(self, format: str, *args: object) -> None:
            pass

    def route_mock(route: Route) -> None:
        request = route.request
        path = urlsplit(request.url).path
        if not request.url.startswith(origin + '/'):
            unexpected.append(request.url)
            route.abort()
        elif path == '/' or path.startswith('/static/'):
            filename = 'index.html' if path == '/' else Path(path).name
            route.fulfill(path=static / filename)
        elif path == '/api/session':
            route.fulfill(json={'authenticated': True, 'csrf_token': csrf})
        elif path == '/api/capabilities':
            route.fulfill(json={'chrome': {'checking': False}, 'icon_search': {
                'name_enabled': True, source + '_enabled': state['ready'], peer.lower() + '_enabled': True}})
        elif path == '/api/jobs' and request.method == 'DELETE':
            state['cleared'] = True
            route.fulfill(json={})
        elif path == '/api/name-searches' and request.method == 'POST':
            route.fulfill(json={'id': identifier})
        elif path == search and request.method == 'GET':
            route.fulfill(json={'id': identifier, 'query_name': 'Synthetic', 'mode': 'name',
                                'stage': 'finished', 'state': 'partial',
                                'catalog_status': {'provider': 'Koodous', 'status': 'hit'},
                                'candidates': [candidate, dict(candidate, category='sample_index', id='2'),
                                               dict(candidate, channel='web', id='3')],
                                source: {'1': state['published']}, peer.lower(): {'1': peer_receipt if peer_calls else None}})
        elif path == peer_base + 'lookup' and request.method == 'POST':
            assert request.headers.get('x-csrf-token') == csrf and request.post_data_json == {}
            peer_calls.append(request.headers['idempotency-key'])
            route.fulfill(json=peer_receipt)
        elif path == base + 'file' and request.method == 'GET':
            route.continue_()
        elif path in (base + 'lookup', base + 'download') and request.method == 'POST':
            state['calls'].append((path, request.headers.get('idempotency-key')))
            assert request.headers.get('x-csrf-token') == csrf
            assert request.post_data_json == {}
            mode = state['mode']
            if mode == 'disconnect':
                route.abort()
                return
            if mode == 'hold':
                held.append(route)
                return
            if mode == 'unconfigured':
                route.fulfill(status=503, json={'error': {'code': error_prefix + 'unconfigured'}})
                return
            if path.endswith('/lookup'):
                receipt.update(lookup={'status': mode}, download=None, file_url=None)
                if mode == 'failed':
                    receipt['lookup']['code'] = error_prefix + 'quota'
            else:
                receipt.update(download={'status': mode}, file_url=None)
                if mode == 'failed':
                    receipt['download']['code'] = error_prefix + state.get('download_error', 'hash_mismatch')
                else:
                    receipt['file_url'] = base + 'file'
            state['published'] = receipt.copy()
            route.fulfill(json=receipt)
        else:
            unexpected.append(request.url)
            route.abort()

    with ThreadingHTTPServer(('127.0.0.1', 0), Attachment) as server, sync_playwright() as playwright:
        origin = f'http://127.0.0.1:{server.server_port}'
        Thread(target=server.serve_forever, daemon=True).start()
        browser = playwright.chromium.launch(channel='chrome', headless=True,
                                             args=['--disable-background-networking'])
        context = browser.new_context(service_workers='block', viewport={'width': 390, 'height': 844})
        context.route('**/*', route_mock)
        page = context.new_page()
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.goto(origin)

        def submit() -> None:
            page.locator('#view-search').click()
            page.locator('#search-mode-name').click()
            page.locator('#name-search-name').fill('Synthetic')
            page.locator('#name-search-button').click()
            expect(page.locator('.icon-candidate')).to_have_count(3)

        submit()
        panel = page.get_by_role('group', name=provider, exact=True)
        peer_panel = page.get_by_role('group', name=peer, exact=True)
        expect(panel).to_have_count(1)
        expect(peer_panel).to_have_count(1)
        button = panel.get_by_role('button')
        file = panel.get_by_role('link')
        assert not peer_calls and state['calls'] == [] and state['file_reads'] == 0
        expect(button).to_have_text(f'向 {provider} 查询 SHA-256')
        state['mode'] = 'unconfigured'
        button.click()
        expect(panel).to_contain_text(f'服务端未配置 {provider}')
        expect(button).to_have_text(f'向 {provider} 查询 SHA-256')
        state['mode'] = 'no_record'
        button.click()
        expect(panel).to_contain_text('本次未查到该 SHA-256')
        expect(file).to_have_count(0)
        state['mode'] = 'failed'
        button.click()
        expect(panel).to_contain_text(f'{provider} 查询失败。{provider} 额度不足')
        assert len({row[1] for row in state['calls']}) == 3

        state.update(mode='disconnect', published=None)
        button.click()
        expect(button).to_have_text('刷新本地状态')
        button.click()
        expect(button).to_have_text(f'向 {provider} 查询 SHA-256')
        assert len(state['calls']) == 4
        state['mode'] = 'hit'
        button.click()
        expect(button).to_have_text(f'从 {provider} 下载 APK')
        assert state['calls'][-1][1] == state['calls'][-2][1]
        assert all(path == base + 'lookup' and token for path, token in state['calls'])
        expect(file).to_have_count(0)
        assert not peer_calls
        peer_panel.get_by_role('button').click()
        expect(peer_panel).to_contain_text(f'{peer} 本次未查到该 SHA-256')
        expect(button).to_have_text(f'从 {provider} 下载 APK')
        assert len(peer_calls) == 1 and peer_calls[0] not in [row[1] for row in state['calls']]
        state['mode'] = 'failed'
        button.click()
        expect(panel).to_contain_text(f'{provider} 下载失败。文件 SHA-256 与该样本不符')
        expect(file).to_have_count(0)
        if source == 'malwarebazaar':
            state['download_error'] = 'invalid_archive'
            button.click()
            expect(panel).to_contain_text('下载的压缩包未通过校验')
            expect(file).to_have_count(0)
        state['mode'] = 'downloaded'
        button.click()
        expect(file).to_have_attribute('href', base + 'file')
        expect(panel).to_contain_text('APK 结构校验通过')
        assert state['file_reads'] == 0
        with page.expect_download() as download_info:
            file.click()
        download_path = download_info.value.path()
        assert download_path and sha256(download_path.read_bytes()).hexdigest() == digest
        assert state['file_reads'] == 1

        previous_calls = state['calls'].copy()
        page.reload()
        submit()
        expect(file).to_be_visible()
        expect(peer_panel).to_contain_text(f'{peer} 本次未查到该 SHA-256')
        assert state['calls'] == previous_calls and state['file_reads'] == 1
        state['published'] = dict(receipt, file_url='https://synthetic.invalid/sample.apk')
        page.reload()
        submit()
        expect(button).to_have_text('刷新本地状态')
        expect(panel.locator('a[href]')).to_have_count(0)
        state['published'] = dict(receipt, provider=peer)
        button.click()
        expect(button).to_have_text('刷新本地状态')
        expect(panel.locator('a[href]')).to_have_count(0)
        state.update(ready=False, published=None)
        page.reload()
        submit()
        expect(button).to_be_disabled()
        expect(panel).to_contain_text(f'服务端未配置 {provider}')
        expect(peer_panel.get_by_role('button')).to_be_enabled()
        assert state['calls'] == previous_calls and state['file_reads'] == 1
        state.update(ready=True, mode='hold')
        page.reload()
        submit()
        state['cleared'] = False
        button.click()
        expect(button).to_be_disabled()
        assert len(held) == 1
        page.locator('#view-collect').click()
        page.locator('#refresh').click()
        expect(page.locator('#notice')).to_contain_text('记录已清空')
        assert state['cleared']
        held[0].fulfill(json=receipt)
        page.locator('#view-search').click()
        expect(panel).to_have_count(0)
        expect(peer_panel).to_have_count(0)
        assert len(peer_calls) == 1
        assert not errors and not unexpected, (errors, unexpected)
        browser.close()
        server.shutdown()
    print(f'PASS {provider}: manual lookup, retry, attachment, CSRF, clear, isolated provider states and zero external requests')


if __name__ == '__main__':
    exercise_provider('MalShare', 'MalwareBazaar', 'malshare_')
    exercise_provider('MalwareBazaar', 'MalShare', 'bazaar_')
