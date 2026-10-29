"""Purely synthetic public-configuration landing workflow integration."""

import threading
from dataclasses import replace

import pytest
from test_landing_adapter import synthetic_landing
from test_workflow import SyntheticClient, apk_bytes

from fxfetch.core.errors import FxfetchError
from fxfetch.core.http_client import Hop
from fxfetch.core.limits import Limits
from fxfetch.core.workflow import ANDROID_UA, Workflow

ENTRY = "https://landing.example/"
FIRST = "https://one.example/release/app.apk"
SECOND = "https://two.example/release/app.apk"


def routes_for_landing():
    html, resources = synthetic_landing()
    # A failed tracking/QR image must never preempt verified download mirrors.
    html = html.replace(b"</html>", b'<img src="/unrelated-tracking-pixel"></html>')
    routes = {ENTRY: (200, "text/html", html), ENTRY + "unrelated-tracking-pixel": (404, "image/png", b"")}
    routes.update({url: (200, "application/javascript", body) for url, body in resources.items()})
    return routes


class FailingMirrorClient(SyntheticClient):
    def fetch(self, url, destination, **kwargs):
        route = self.routes[url]
        if isinstance(route, FxfetchError):
            self.calls.append((url, kwargs["user_agent"], kwargs["cookie_jar"], self.limits))
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.with_name(destination.name + ".partial").write_bytes(b"prefix")
            route.__dict__["hops"] = (Hop(url, 200, {}, "93.184.216.34", None),)
            raise route
        return super().fetch(url, destination, **kwargs)


def test_landing_mirror_timeout_then_valid_package_retains_prefix(tmp_path):
    routes = routes_for_landing()
    routes[FIRST] = FxfetchError("network_timeout", "Synthetic timeout")
    routes[SECOND] = (200, "application/octet-stream", apk_bytes())
    client = FailingMirrorClient(routes)
    original_limits = client.limits
    result = Workflow(client).run(ENTRY, tmp_path, threading.Event())
    assert result.outcome == "downloaded" and result.artifacts[0].url == SECOND
    assert [call[0] for call in client.calls][-2:] == [FIRST, SECOND]
    assert len(client.calls) == 7
    assert all(call[1] == ANDROID_UA for call in client.calls)
    assert all(call[2] is client.calls[0][2] for call in client.calls)
    assert all(call[3].max_redirects == 0 for call in client.calls[1:5])
    assert client.limits is original_limits
    assert [(a.url, a.reason_code) for a in result.attempts][-2:] == [
        (FIRST, "network_timeout"),
        (SECOND, "package_verified"),
    ]
    prefix = next(body for body in result.bodies if body.get("hash_scope") == "saved_prefix")
    assert prefix["complete"] is False and prefix["size"] == 6 and prefix["request_id"] == 6
    assert result.bodies[-1]["request_id"] == 7
    assert result.landing["supported"] and result.landing["mirror_group"]
    assert result.page_qr["status"] == "not_started"


@pytest.mark.parametrize(
    "reason", ["target_not_public", "tls_verification_failed", "peer_mismatch", "download_limit"]
)
def test_security_and_budget_errors_do_not_try_another_mirror(tmp_path, reason):
    routes = routes_for_landing()
    routes[FIRST] = FxfetchError(reason, "Synthetic terminal failure")
    routes[SECOND] = (200, "application/octet-stream", apk_bytes())
    client = FailingMirrorClient(routes)
    result = Workflow(client).run(ENTRY, tmp_path, threading.Event())
    assert result.outcome == "failed" and result.reason_code == reason
    assert SECOND not in [call[0] for call in client.calls]
    assert not result.artifacts


def test_blocked_mirror_is_not_absence_and_does_not_retry_or_fallback(tmp_path):
    routes = routes_for_landing()
    routes[FIRST] = (403, "text/html", b"blocked")
    client = FailingMirrorClient(routes)
    result = Workflow(client).run(ENTRY, tmp_path, threading.Event())
    assert result.outcome == "blocked" and result.coverage == "partial"
    assert [call[0] for call in client.calls][-1] == FIRST
    assert all(call[1] == ANDROID_UA for call in client.calls)


def test_tls_connection_failure_can_use_declared_mirror_without_disabling_tls(tmp_path):
    routes = routes_for_landing()
    routes[FIRST] = FxfetchError("tls_handshake_failed", "Synthetic closed handshake")
    routes[SECOND] = (200, "application/octet-stream", apk_bytes())
    client = FailingMirrorClient(routes)
    result = Workflow(client).run(ENTRY, tmp_path, threading.Event())
    assert result.outcome == "downloaded"
    assert [(a.url, a.reason_code) for a in result.attempts][-2:] == [
        (FIRST, "tls_handshake_failed"),
        (SECOND, "package_verified"),
    ]
    assert all(call[0].startswith("https://") for call in client.calls)


def test_all_mirrors_failed_keeps_attempts_and_does_not_try_ipa(tmp_path):
    routes = routes_for_landing()
    routes[FIRST] = FxfetchError("network_timeout", "synthetic")
    routes[SECOND] = (404, "text/html", b"missing")
    client = FailingMirrorClient(routes)
    result = Workflow(client).run(ENTRY, tmp_path, threading.Event())
    assert (result.outcome, result.reason_code, result.coverage) == (
        "failed",
        "landing_mirrors_failed",
        "partial",
    )
    assert [(a.url, a.reason_code) for a in result.attempts if a.url in (FIRST, SECOND)][:2] == [
        (FIRST, "network_timeout"),
        (SECOND, "http_status"),
    ]
    assert all(call[1] == ANDROID_UA for call in client.calls)
    assert len(client.calls) == 8


def test_mirror_attempts_share_metadata_request_and_web_budgets(tmp_path):
    routes = routes_for_landing()
    routes[FIRST] = FxfetchError("network_timeout", "synthetic")
    routes[SECOND] = (200, "application/octet-stream", apk_bytes())
    client = FailingMirrorClient(routes)
    limits = replace(Limits(), max_requests=6)
    result = Workflow(client, limits).run(ENTRY, tmp_path, threading.Event())
    assert result.reason_code == "workflow_limit"
    assert len(client.calls) == 6 and SECOND not in [call[0] for call in client.calls]
    assert [call[3].max_requests for call in client.calls] == [6, 5, 4, 3, 2, 1]


def test_mirror_partial_prefix_consumes_remaining_web_budget(tmp_path):
    routes = routes_for_landing()
    metadata = sum(len(body) for status, content_type, body in routes.values())
    routes[FIRST] = FxfetchError("network_timeout", "synthetic")
    routes[SECOND] = (200, "application/octet-stream", apk_bytes())
    client = FailingMirrorClient(routes)
    result = Workflow(client, replace(Limits(), max_web_bytes=metadata + 6)).run(
        ENTRY, tmp_path, threading.Event()
    )
    assert result.reason_code == "workflow_limit"
    assert SECOND not in [call[0] for call in client.calls]


def test_four_verified_mirrors_keep_configuration_order_and_stop_on_first_valid(tmp_path):
    html, resources = synthetic_landing(
        {
            "CDN1": ",".join("https://mirror" + str(i) + ".example" for i in range(4)),
            "loadSource": "@CDN/app.apk",
            "loadMethord": "linkSelf",
        }
    )
    routes = {ENTRY: (200, "text/html", html)}
    routes.update({url: (200, "application/javascript", body) for url, body in resources.items()})
    mirrors = ["https://mirror" + str(i) + ".example/app.apk" for i in range(4)]
    for url in mirrors:
        routes[url] = (404, "text/html", b"missing")
    routes[mirrors[2]] = (200, "application/octet-stream", apk_bytes())
    client = FailingMirrorClient(routes)
    result = Workflow(client).run(ENTRY, tmp_path, threading.Event())
    assert result.outcome == "downloaded"
    assert [call[0] for call in client.calls][-3:] == mirrors[:3]
    assert mirrors[3] not in [call[0] for call in client.calls]


def test_adapter_callback_security_failure_never_reaches_mirrors(tmp_path):
    routes = routes_for_landing()
    routes["https://landing.example/js/index.abcdef.js"] = FxfetchError("target_not_public", "synthetic")
    client = FailingMirrorClient(routes)
    result = Workflow(client).run(ENTRY, tmp_path, threading.Event())
    assert result.reason_code == "target_not_public"
    assert len(client.calls) == 2 and not result.artifacts


def test_cancellation_between_mirrors_stops_next_request(tmp_path):
    cancel = threading.Event()
    routes = routes_for_landing()
    routes[FIRST] = FxfetchError("network_timeout", "synthetic")
    routes[SECOND] = (200, "application/octet-stream", apk_bytes())

    class CancelAfterFirst(FailingMirrorClient):
        def fetch(self, url, destination, **kwargs):
            if url == FIRST:
                cancel.set()
            return super().fetch(url, destination, **kwargs)

    client = CancelAfterFirst(routes)
    result = Workflow(client).run(ENTRY, tmp_path, cancel)
    assert result.reason_code == "cancelled"
    assert SECOND not in [call[0] for call in client.calls]


def test_challenge_html_mirror_blocks_instead_of_trying_next(tmp_path):
    routes = routes_for_landing()
    routes[FIRST] = (
        200, "text/html",
        b'<h1>Verify you are human</h1><input name="captcha"><button>Verify</button>',
    )
    routes[SECOND] = (200, "application/octet-stream", apk_bytes())
    client = FailingMirrorClient(routes)
    result = Workflow(client).run(ENTRY, tmp_path, threading.Event())
    assert result.outcome == "blocked" and result.reason_code == "challenge_detected"
    assert SECOND not in [call[0] for call in client.calls]
