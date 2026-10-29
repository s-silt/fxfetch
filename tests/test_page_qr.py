import base64
import io
import threading

import pytest
import qrcode
from test_workflow import ROOT, SyntheticClient, apk_bytes, ipa_bytes

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
