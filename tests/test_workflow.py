import hashlib
import io
import plistlib
import threading
import zipfile
from dataclasses import replace

from fxfetch.core.errors import FxfetchError
from fxfetch.core.http_client import FetchedResponse, Hop, HttpClient
from fxfetch.core.limits import Limits
from fxfetch.core.workflow import ANDROID_UA, IPHONE_UA, Workflow, metadata_reserve

ROOT = "https://synthetic.test"


def apk_bytes():
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex\n035\0")
    return data.getvalue()


def ipa_bytes():
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr(
            "Payload/Test.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "test.synthetic"})
        )
    return data.getvalue()


class SyntheticClient(HttpClient):
    def __init__(self, routes):
        super().__init__()
        self.routes = routes
        self.calls = []

    def fetch(self, url, destination, *, user_agent, cookie_jar, cancel, referer=None):
        self.calls.append((url, user_agent, cookie_jar, self.limits))
        status, content_type, body = self.routes[url]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(body)
        return FetchedResponse(
            url,
            status,
            {"content-type": content_type},
            destination,
            len(body),
            hashlib.sha256(body).hexdigest(),
            (),
        )


def test_apk_first_and_same_chain_cookie(tmp_path):
    client = SyntheticClient(
        {
            ROOT + "/": (
                200,
                "text/html",
                b'<html><a href="/ios.ipa">iOS</a><a href="/android.apk">Android</a></html>',
            ),
            ROOT + "/android.apk": (200, "application/octet-stream", apk_bytes()),
        }
    )
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == "downloaded"
    assert result.artifacts[0].kind == "apk"
    assert len(client.calls) == 2
    assert result.attempts[0].outcome is None
    assert all(call[1] == ANDROID_UA for call in client.calls)
    assert client.calls[0][2] is client.calls[1][2]


def test_static_fallback_separate_jars(tmp_path):
    client = SyntheticClient({ROOT + "/": (200, "text/html", b"<html>No downloads</html>")})
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == "not_found"
    assert [call[1] for call in client.calls] == [ANDROID_UA, IPHONE_UA]
    assert client.calls[0][2] is not client.calls[1][2]
    assert [body["chain"] for body in result.bodies] == ["android", "iphone"]
    assert [body["request_id"] for body in result.bodies] == [1, 2]
    assert [body["user_agent"] for body in result.bodies] == [ANDROID_UA, IPHONE_UA]


def test_script_does_not_fallback(tmp_path):
    client = SyntheticClient({ROOT + "/": (200, "text/html", b'<html><script>fetch("/api")</script></html>')})
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == "failed"
    assert result.reason_code == "browser_required"
    assert len(client.calls) == 1


def test_blocked_and_candidate_failure_no_fallback(tmp_path):
    for name, routes, expected in [
        ("blocked", {ROOT + "/": (403, "text/html", b"Forbidden")}, "blocked"),
        (
            "bad",
            {
                ROOT + "/": (200, "text/html", b'<a href="/a.apk">Download</a>'),
                ROOT + "/a.apk": (200, "text/html", b"not a package"),
            },
            "failed",
        ),
    ]:
        client = SyntheticClient(routes)
        result = Workflow(client).run(ROOT, tmp_path / name, threading.Event())
        assert result.outcome == expected
        assert all(call[1] == ANDROID_UA for call in client.calls)


def test_task_partial_bytes_reduce_budget(tmp_path):
    (tmp_path / "prior.partial").write_bytes(b"x" * 100)
    client = SyntheticClient({ROOT + "/": (200, "text/html", b"<html>No downloads</html>")})
    result = Workflow(client, replace(Limits(), max_task_bytes=metadata_reserve(Limits()) + 120)).run(
        ROOT, tmp_path, threading.Event()
    )
    assert client.calls[0][3].max_package_bytes == 20
    assert result.outcome == "failed"


def test_manifest_dispatches_iphone_only(tmp_path):
    manifest = plistlib.dumps(
        {"items": [{"assets": [{"kind": "software-package", "url": ROOT + "/binary"}]}]}
    )
    client = SyntheticClient(
        {
            ROOT + "/m.plist": (200, "application/xml", manifest),
            ROOT + "/binary": (200, "application/octet-stream", ipa_bytes()),
        }
    )
    result = Workflow(client).run(ROOT + "/m.plist", tmp_path, threading.Event())
    assert result.outcome == "downloaded"
    assert result.artifacts[0].kind == "ipa"
    assert all(call[1] == IPHONE_UA for call in client.calls)


def test_ambiguous_candidates_no_download(tmp_path):
    client = SyntheticClient(
        {ROOT + "/": (200, "text/html", b'<a href="/a.apk">A</a><a href="/b.apk">B</a>')}
    )
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == "candidate_selection_required"
    assert len(client.calls) == 1


def test_explicit_no_suffix_download(tmp_path):
    client = SyntheticClient(
        {
            ROOT + "/": (200, "text/html", b'<a href="/binary">Download Android</a>'),
            ROOT + "/binary": (200, "application/octet-stream", apk_bytes()),
        }
    )
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == "downloaded"
    assert len(result.bodies) == 2
    assert result.bodies[-1]["hash_scope"] == "wire"
    assert result.bodies[-1]["path"] == str(result.artifacts[0].path)


def test_failed_prefix_evidence(tmp_path):
    class FailingClient(HttpClient):
        def fetch(self, url, destination, **kwargs):
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.with_name(destination.name + ".partial").write_bytes(b"prefix")
            error = FxfetchError("length_mismatch", "Synthetic interrupted body")
            error.__dict__["hops"] = (Hop(url, 200, {"content-length": "99"}, "127.0.0.1", None),)
            raise error

    result = Workflow(FailingClient()).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == "failed"
    assert not result.artifacts
    assert result.hops[0]["connection_ip"] == "127.0.0.1"
    assert result.hops[0]["chain"] == "android"
    assert result.hops[0]["request_id"] == 1
    assert result.hops[0]["mode"] == "http"
    assert result.bodies[0]["hash_scope"] == "saved_prefix"
    assert result.bodies[0]["chain"] == "android" and result.bodies[0]["request_id"] == 1
    assert result.bodies[0]["complete"] is False
    assert result.bodies[0]["sha256"] == hashlib.sha256(b"prefix").hexdigest()


def test_browser_required_snapshot_same_chain_and_bound_resources(tmp_path):
    from PIL import Image

    image = io.BytesIO()
    Image.new("RGB", (8, 8), "blue").save(image, format="PNG")
    client = SyntheticClient(
        {
            ROOT + "/": (
                200,
                "text/html",
                b'<html><h1>Snapshot</h1><img src="/logo"><img width="1" height="1" src="https://other.synthetic.test/never"><script src="/js"></script></html>',
            ),
            ROOT + "/logo": (200, "image/png", image.getvalue()),
        }
    )
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == "failed" and result.reason_code == "browser_required"
    assert result.offline["available"]
    assert [call[0] for call in client.calls] == [ROOT + "/", ROOT + "/logo"]
    assert client.calls[0][2] is client.calls[1][2]
    assert client.calls[1][1] == ANDROID_UA
    assert client.calls[1][3].max_package_bytes == 10 * 1024 * 1024
    assert result.bodies[-1]["purpose"] == "page_qr_image"


def test_blocked_does_not_collect_offline_resources(tmp_path):
    for status, body in [
        (403, b'<img src="/never">'),
        (200, b'<h1>Verify you are human</h1><input name="captcha"><button>Verify</button><img src="/never">'),
    ]:
        client = SyntheticClient({ROOT + "/": (status, "text/html", body)})
        result = Workflow(client).run(ROOT, tmp_path / str(status), threading.Event())
        assert result.outcome == "blocked"
        assert not result.offline["available"]
        assert len(client.calls) == 1


def test_qr_resource_access_control_prevents_absence_and_fallback(tmp_path):
    client = SyntheticClient(
        {
            ROOT + "/": (200, "text/html", b'<html>No package<img src="/logo"></html>'),
            ROOT + "/logo": (403, "text/html", b"Forbidden"),
        }
    )
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == "blocked"
    assert result.reason_code == "page_qr_access_control"
    assert [call[1] for call in client.calls] == [ANDROID_UA, ANDROID_UA]


def test_html_parser_limit_never_becomes_not_found_or_fallback(tmp_path):
    client = SyntheticClient({ROOT + "/": (200, "text/html", b"<div>" * 257)})
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == "failed"
    assert result.reason_code == "html_parse_limit"
    assert result.coverage == "partial"
    assert len(client.calls) == 1


def test_workflow_events_follow_explicit_control_then_verify_actual_file(tmp_path):
    client = SyntheticClient({
        ROOT + "/": (200, "text/html", b'<a href="/payload" download>Get</a>'),
        ROOT + "/payload": (200, "application/octet-stream", apk_bytes()),
    })
    events = []
    result = Workflow(client).run(ROOT, tmp_path, threading.Event(), on_event=events.append)
    assert result.outcome == "downloaded"
    names = [e["event"] for e in events]
    assert names.index("page_received") < names.index("download_candidate") < names.index("redirect")
    assert names.index("download_started") < names.index("file_verifying") < names.index("file_verified")
    assert events[-1]["event"] == "file_verified"
    assert events[-1]["sha256"] == result.artifacts[0].sha256
    assert all(e["chain"] == "android" for e in events)
    redirect = next(e for e in events if e["event"] == "redirect")
    assert redirect["mechanism"] == "static"
    assert redirect["from_url"] == ROOT + "/"
    assert redirect["to_url"] == ROOT + "/payload"


def test_workflow_events_package_suffix_does_not_claim_download_or_verification(tmp_path):
    client = SyntheticClient({ROOT + "/fake.apk": (200, "text/html", b"not a package")})
    events = []
    result = Workflow(client).run(ROOT + "/fake.apk", tmp_path, threading.Event(), events.append)
    assert result.reason_code == "candidate_not_package"
    assert not any(e["event"] in ("download_started", "file_verified") for e in events)


def test_workflow_challenge_and_browser_events_have_accurate_terminal_reason(tmp_path):
    for name, body, status, expected in [
        ("challenge", b'<form id="challenge-form">Verify you are human<input name="captcha"></form>', 200, "challenge_detected"),
        ("access", b"<html>Forbidden</html>", 403, "http_access_control"),
        ("browser", b'<script src="/unknown.js"></script>', 200, "browser_required"),
    ]:
        client = SyntheticClient({ROOT + "/": (status, "text/html", body)})
        events = []
        result = Workflow(client).run(ROOT, tmp_path / name, threading.Event(), events.append)
        terminal = [e for e in events if e["event"] in ("challenge_detected", "browser_required")]
        assert terminal[-1]["reason_code"] == expected
        assert result.reason_code == expected
        assert not any(e["event"] == "file_verified" for e in events)


def test_workflow_static_redirect_budget_and_cycles_stop_before_replay(tmp_path):
    routes = {ROOT + f"/{i}": (200, "text/html",
              f'<meta http-equiv="refresh" content="0;url=/{i + 1}">'.encode()) for i in range(12)}
    client = SyntheticClient(routes)
    result = Workflow(client).run(ROOT + "/0", tmp_path / "budget", threading.Event())
    assert result.reason_code == "redirect_limit"
    assert len(client.calls) == 11
    cycle = SyntheticClient({
        ROOT + "/a": (200, "text/html", b'<meta http-equiv="refresh" content="0;url=/b">'),
        ROOT + "/b": (200, "text/html", b'<meta http-equiv="refresh" content="0;url=/a">'),
    })
    result = Workflow(cycle).run(ROOT + "/a", tmp_path / "cycle", threading.Event())
    assert result.reason_code == "discovery_cycle"
    assert len(cycle.calls) == 2
