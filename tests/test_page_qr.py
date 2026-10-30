import base64
import io
import threading

import pytest
import qrcode
from test_workflow import ROOT, SyntheticClient, apk_bytes, ipa_bytes

from fxfetch.core.errors import FxfetchError
from fxfetch.core.page_qr import discover_images
from fxfetch.core.workflow import ANDROID_UA, IPHONE_UA, Workflow


def qr_bytes(text):
    output = io.BytesIO()
    qrcode.make(text).save(output, format="PNG")
    return output.getvalue()


@pytest.mark.parametrize("inline", [False, True])
def test_page_qr_download(tmp_path, inline):
    image = qr_bytes(ROOT + "/a.apk?token=a%2Fb")
    src = "data:image/png;base64," + base64.b64encode(image).decode() if inline else "/qr.png"
    client = SyntheticClient(
        {
            ROOT + "/": (200, "text/html", f'<html><img src="{src}"></html>'.encode()),
            ROOT + "/qr.png": (200, "image/png", image),
            ROOT + "/a.apk?token=a%2Fb": (200, "application/octet-stream", apk_bytes()),
        }
    )
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == "downloaded"
    assert result.page_qr["status"] == "decoded"
    assert len(client.calls) == (2 if inline else 3)
    assert all(call[2] is client.calls[0][2] for call in client.calls)
    assert all(call[1] == ANDROID_UA for call in client.calls)
    assert result.page_qr["sources"][0]["decode"]["candidates"][0]["text"].endswith("?token=a%2Fb")


def test_multiple_page_qr_stop(tmp_path):
    client = SyntheticClient(
        {
            ROOT + "/": (200, "text/html", b'<img src="/one"><img src="/two">'),
            ROOT + "/one": (200, "image/png", qr_bytes(ROOT + "/a.apk")),
            ROOT + "/two": (200, "image/png", qr_bytes(ROOT + "/b.apk")),
        }
    )
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == "candidate_selection_required"
    assert len(client.calls) == 3
    assert len(result.candidates) == 2


@pytest.mark.parametrize("status,expected", [(403, "blocked"), (500, "failed"), (200, "failed")])
def test_unscanned_image_never_no_package(tmp_path, status, expected):
    client = SyntheticClient(
        {
            ROOT + "/": (200, "text/html", b'<img src="/one">'),
            ROOT + "/one": (status, "image/png", b"not an image"),
        }
    )
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == expected
    assert len(client.calls) == 2
    assert result.coverage == "partial"


@pytest.mark.parametrize("code", ["dns_unsafe_answer", "dns_tls_verification_failed"])
def test_qr_resource_dns_security_rejection_preserves_failure(tmp_path, code):
    class RejectedImageClient(SyntheticClient):
        def fetch(self, url, *args, **kwargs):
            if url.endswith("/one"):
                raise FxfetchError(code, "Synthetic DNS security rejection")
            return super().fetch(url, *args, **kwargs)

    client = RejectedImageClient({ROOT + "/": (200, "text/html", b'<img src="/one">')})
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert (result.outcome, result.reason_code, result.coverage) == ("failed", code, "partial")


def test_tracking_skip_and_limit():
    result = discover_images(b'<img width="1" height="1" src="https://tracker.synthetic.test/x">', ROOT)
    assert result.images[0].skip_reason == "tracking_image_skipped"
    assert not result.gaps
    result = discover_images(("".join(f'<img src="/{i}">' for i in range(9))).encode(), ROOT)
    assert len(result.images) == 8
    assert "page_qr_image_limit" in result.gaps


def test_qr_itms_manifest_preserves_original(tmp_path):
    import plistlib

    text = f"itms-services://?action=download-manifest&url={ROOT}/m.plist"
    image = base64.b64encode(qr_bytes(text)).decode()
    manifest = plistlib.dumps(
        {"items": [{"assets": [{"kind": "software-package", "url": ROOT + "/binary"}]}]}
    )
    client = SyntheticClient(
        {
            ROOT + "/": (200, "text/html", f'<img src="data:image/png;base64,{image}">'.encode()),
            ROOT + "/m.plist": (200, "application/xml", manifest),
            ROOT + "/binary": (200, "application/octet-stream", ipa_bytes()),
        }
    )
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == "downloaded"
    assert result.artifacts[0].kind == "ipa"
    assert client.calls[1][1] == IPHONE_UA
    assert result.page_qr["sources"][0]["decode"]["candidates"][0]["text"] == text


def test_scan_gap_blocks_even_unique_qr(tmp_path):
    client = SyntheticClient(
        {
            ROOT + "/": (200, "text/html", b'<img src="/valid"><img src="/broken">'),
            ROOT + "/valid": (200, "image/png", qr_bytes(ROOT + "/a.apk")),
            ROOT + "/broken": (200, "image/png", b"invalid"),
        }
    )
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == "page_qr_incomplete"
    assert len(result.candidates) == 1
    assert len(client.calls) == 3


def test_duplicate_qr_targets_can_follow(tmp_path):
    image = qr_bytes(ROOT + "/a.apk")
    client = SyntheticClient(
        {
            ROOT + "/": (200, "text/html", b'<img src="/one"><img src="/two">'),
            ROOT + "/one": (200, "image/png", image),
            ROOT + "/two": (200, "image/png", image),
            ROOT + "/a.apk": (200, "application/octet-stream", apk_bytes()),
        }
    )
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == "downloaded"
    assert len(result.page_qr["sources"]) == 2


def test_image_request_budget_not_reset(tmp_path):
    from dataclasses import replace

    from fxfetch.core.limits import Limits

    client = SyntheticClient(
        {
            ROOT + "/": (200, "text/html", b'<img src="/one">'),
            ROOT + "/one": (200, "image/png", qr_bytes(ROOT + "/a.apk")),
        }
    )
    result = Workflow(client, replace(Limits(), max_requests=2)).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == "failed"
    assert result.reason_code == "workflow_limit"
    assert len(client.calls) == 2


def test_invalid_inline_and_base_have_explicit_gaps():
    assert discover_images(b'<img src="data:image/svg+xml;base64,AAAA">', ROOT).gaps
    assert discover_images(b'<img src="data:image/png;base64,A">', ROOT).gaps
    result = discover_images(b'<base href="/elsewhere/"><img src="qr.png">', ROOT)
    assert result.gaps == ["page_qr_base_unsupported"]
    assert not result.images


def test_duplicates_do_not_exhaust_image_budget():
    html = ''.join(f'<img src="/{i}.png">' for i in range(8)) + '<img src="/0.png">'
    result = discover_images(html.encode(), ROOT)
    assert len(result.images) == 8 and not result.gaps
    inline = base64.b64encode(qr_bytes(ROOT + '/a.apk')).decode()
    result = discover_images((f'<img src="data:image/png;base64,{inline}">' * 9).encode(), ROOT)
    assert len(result.images) == 1 and not result.gaps


@pytest.mark.parametrize('hint', ['alt="二维码"', 'title="QR code"', 'class="qrcode"', 'id="qr-code"'])
def test_late_qr_hint_is_selected_before_decorative_images(hint):
    html = ''.join(f'<img src="/{i}.webp">' for i in range(20))
    result = discover_images((html + f'<img {hint} src="/last.webp">').encode(), ROOT)
    assert len(result.images) == 8 and result.images[0].index == 21
    assert result.images[0].url == ROOT + '/last.webp'
    assert result.gaps == ['page_qr_image_limit']


def test_duplicate_later_hint_promotes_first_reference():
    html = ''.join(f'<img src="/{i}.png">' for i in range(10))
    result = discover_images((html + '<img alt="二维码" src="/9.png">').encode(), ROOT)
    assert result.images[0].index == 10 and result.images[0].url == ROOT + '/9.png'
    assert len(result.images) == 8 and result.gaps == ['page_qr_image_limit']


def test_unhinted_images_remain_partial_without_guessing():
    result = discover_images(''.join(f'<img src="/{i}.png">' for i in range(20)).encode(), ROOT)
    assert [image.index for image in result.images] == list(range(1, 9))
    assert result.gaps == ['page_qr_image_limit']


@pytest.mark.parametrize('dynamic', [False, True])
@pytest.mark.parametrize('decode_status', ['no_code', 'invalid'])
def test_qr_gap_dynamic_handoff_marker_is_narrow(tmp_path, monkeypatch, dynamic, decode_status):
    from fxfetch.core.qr import QRResult

    html = ''.join(f'<img src="/{i}.png">' for i in range(10))
    if dynamic:
        html += '<button onclick="beginDownload()">Download</button>'
    routes = {ROOT + '/': (200, 'text/html', html.encode())}
    routes.update({ROOT + f'/{i}.png': (200, 'image/png', b'fixture') for i in range(10)})
    monkeypatch.setattr('fxfetch.core.workflow.decode_saved_image', lambda *args: QRResult(decode_status))
    result = Workflow(SyntheticClient(routes)).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == 'page_qr_incomplete' and result.coverage == 'partial'
    assert (result.page_qr.get('browser_required') is True) == (dynamic and decode_status == 'no_code')
    assert len(result.page_qr['sources']) == 8


def test_explicit_package_skips_all_page_qr_work(tmp_path, monkeypatch):
    html = '<a href="/a.apk">Download</a>' + ''.join(f'<img src="/{i}.png">' for i in range(20))
    client = SyntheticClient({ROOT + '/': (200, 'text/html', html.encode()),
                              ROOT + '/a.apk': (200, 'application/octet-stream', apk_bytes())})
    monkeypatch.setattr('fxfetch.core.workflow.decode_saved_image', lambda *args: pytest.fail('No QR decode'))
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == 'downloaded' and len(client.calls) == 2
    assert result.page_qr['status'] == 'not_started'


def test_inline_discovery_retained_bytes_bounded_by_html_input(monkeypatch):
    import fxfetch.core.page_qr as module

    # Exercise many distinct inline payloads, with a late semantic QR image.
    # No pixel decoder runs during discovery; retained bytes are base64 bytes.
    limit = 64 * 1024
    monkeypatch.setattr(module, 'MAX_HTML_INPUT_BYTES', limit)
    tags = []
    for index in range(32):
        payload = bytes([index]) * 1024
        hint = 'alt="QR code"' if index == 31 else ''
        tags.append(f'<img {hint} src="data:image/png;base64,{base64.b64encode(payload).decode()}">')
    data = ''.join(tags).encode()
    assert len(data) < limit
    original_parser = module._Images
    parsers = []

    def observe_parser(source):
        parser = original_parser(source)
        parsers.append(parser)
        return parser

    monkeypatch.setattr(module, '_Images', observe_parser)
    result = module.discover_images(data, ROOT)
    retained = sum(len(item[0].data or b'') for item in parsers[0].unique.values())
    assert retained == 32 * 1024 and retained <= len(data) * 3 // 4
    assert len(result.images) == 8 and result.images[0].index == 32
    assert result.gaps == ['page_qr_image_limit']


def test_oversized_inline_html_rejected_before_base64_decode(monkeypatch):
    import fxfetch.core.page_qr as module
    from fxfetch.core.errors import FxfetchError

    monkeypatch.setattr(module, 'MAX_HTML_INPUT_BYTES', 1024)
    data = ('<img src="data:image/png;base64,' + 'A' * 1024 + '">').encode()
    monkeypatch.setattr(module.base64, 'b64decode', lambda *args, **kwargs: pytest.fail('Input must be rejected first'))
    with pytest.raises(FxfetchError, match='byte limit') as error:
        module.discover_images(data, ROOT)
    assert error.value.code == 'page_qr_html_limit'
