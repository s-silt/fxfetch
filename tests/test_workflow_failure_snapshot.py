"""Failure snapshots preserve actual collected content without changing outcomes."""

import io
import threading
from dataclasses import replace

import pytest
from PIL import Image
from test_workflow import ROOT, SyntheticClient, apk_bytes

from fxfetch.core.errors import FxfetchError
from fxfetch.core.limits import Limits
from fxfetch.core.workflow import Workflow


def page_routes():
    image = io.BytesIO()
    Image.new("RGB", (8, 8), "blue").save(image, format="PNG")
    return {
        ROOT + "/": (
            200,
            "text/html",
            b'<html><h1>Collected heading</h1><p>Collected description</p><link rel="stylesheet" href="/style.css"><img src="/logo.png"><a href="/app.apk">Download</a></html>',
        ),
        ROOT + "/style.css": (200, "text/css", b"h1{color:blue}"),
        ROOT + "/logo.png": (200, "image/png", image.getvalue()),
    }


class ErrorClient(SyntheticClient):
    def fetch(self, url, destination, **kwargs):
        if isinstance(self.routes[url], FxfetchError):
            self.calls.append((url, kwargs["user_agent"], kwargs["cookie_jar"], self.limits))
            raise self.routes[url]
        return super().fetch(url, destination, **kwargs)


def test_failed_package_collects_declared_resources_and_preserves_failure(tmp_path):
    routes = page_routes()
    routes[ROOT + "/app.apk"] = FxfetchError("network_timeout", "synthetic")
    client = ErrorClient(routes)
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == "network_timeout" and result.coverage == "partial" and not result.artifacts
    assert result.offline["available"] and result.offline["coverage"] == "partial"
    html = result.offline["entry"].read_text()
    assert "Collected heading" in html and "Collected description" in html and "<img" in html
    assert len(result.offline["files"]) >= 3
    assert [call[0] for call in client.calls] == [
        ROOT + "/",
        ROOT + "/app.apk",
        ROOT + "/style.css",
        ROOT + "/logo.png",
    ]
    assert [body["request_id"] for body in result.bodies] == [1, 3, 4]
    assert all(call[2] is client.calls[0][2] for call in client.calls)


@pytest.mark.parametrize(
    "reason",
    [
        "target_not_public",
        "peer_mismatch",
        "tls_verification_failed",
        "tls_handshake_failed",
        "download_limit",
        "workflow_limit",
        "request_limit",
    ],
)
def test_security_and_budget_failures_only_use_collected_html(tmp_path, reason):
    routes = page_routes()
    routes[ROOT + "/app.apk"] = FxfetchError(reason, "synthetic")
    client = ErrorClient(routes)
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == reason and result.offline["available"]
    assert len(client.calls) == 2
    assert "offline_network_disabled_after_failure" in result.offline["reasons"]
    assert "<img" not in result.offline["entry"].read_text()


def test_access_control_body_never_becomes_snapshot(tmp_path):
    routes = page_routes()
    routes[ROOT + "/app.apk"] = (403, "text/html", b"<html>Forbidden secret body</html>")
    client = ErrorClient(routes)
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == "blocked" and result.offline["available"]
    assert len(client.calls) == 2
    rendered = result.offline["entry"].read_text()
    assert "Collected heading" in rendered and "Forbidden secret body" not in rendered


def test_cancelled_failure_has_no_snapshot_fetch(tmp_path):
    cancel = threading.Event()
    routes = page_routes()
    routes[ROOT + "/app.apk"] = FxfetchError("network_timeout", "synthetic")

    class CancelClient(ErrorClient):
        def fetch(self, url, destination, **kwargs):
            if url.endswith("app.apk"):
                cancel.set()
            return super().fetch(url, destination, **kwargs)

    client = CancelClient(routes)
    result = Workflow(client).run(ROOT, tmp_path, cancel)
    assert len(client.calls) == 2 and not result.offline["available"]


def test_successful_original_package_does_not_collect_extra_resources(tmp_path):
    routes = page_routes()
    routes[ROOT + "/app.apk"] = (200, "application/octet-stream", apk_bytes())
    client = ErrorClient(routes)
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.outcome == "downloaded" and len(client.calls) == 2
    assert not result.offline["available"]


def test_snapshot_resource_failure_keeps_original_error(tmp_path):
    routes = page_routes()
    routes[ROOT + "/app.apk"] = FxfetchError("network_timeout", "synthetic")
    routes[ROOT + "/style.css"] = FxfetchError("target_not_public", "synthetic")
    client = ErrorClient(routes)
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == "network_timeout" and result.offline["available"]
    assert len(client.calls) == 3 and "offline_target_not_public" in result.offline["reasons"]


def test_no_remaining_request_budget_means_html_only(tmp_path):
    routes = page_routes()
    routes[ROOT + "/app.apk"] = FxfetchError("network_timeout", "synthetic")
    client = ErrorClient(routes)
    result = Workflow(client, replace(Limits(), max_requests=2)).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == "network_timeout" and result.offline["available"]
    assert len(client.calls) == 2 and "offline_collection_limit" in result.offline["reasons"]


def test_latest_successful_html_is_preserved_after_later_candidate_failure(tmp_path):
    routes = page_routes()
    routes[ROOT + "/"] = (
        200,
        "text/html",
        b'<html><h1>Older page</h1><a href="/second" download>Next</a><link rel="stylesheet" href="/old.css"></html>',
    )
    routes[ROOT + "/second"] = (
        200,
        "text/html",
        b'<html><h1>Latest page</h1><a href="/app.apk">Get</a><link rel="stylesheet" href="/style.css"></html>',
    )
    routes[ROOT + "/app.apk"] = FxfetchError("network_timeout", "synthetic")
    client = ErrorClient(routes)
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.offline["available"]
    html = result.offline["entry"].read_text()
    assert "Latest page" in html and "Older page" not in html
    assert ROOT + "/old.css" not in [call[0] for call in client.calls]


def test_optional_missing_stylesheet_does_not_hide_other_declared_images(tmp_path):
    routes = page_routes()
    routes[ROOT + "/app.apk"] = FxfetchError("network_timeout", "synthetic")
    routes[ROOT + "/style.css"] = (404, "text/css", b"missing")
    client = ErrorClient(routes)
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == "network_timeout" and result.offline["available"]
    assert client.calls[-1][0] == ROOT + "/logo.png"
    assert "<img" in result.offline["entry"].read_text()


def test_qr_security_error_is_not_relabelled_as_retryable_coverage_gap(tmp_path):
    routes = page_routes()
    routes[ROOT + "/"] = (
        200,
        "text/html",
        b'<html><h1>Collected heading</h1><img src="/logo.png"><link rel="stylesheet" href="/style.css"></html>',
    )
    routes[ROOT + "/logo.png"] = FxfetchError("target_not_public", "synthetic")
    client = ErrorClient(routes)
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == "target_not_public" and result.offline["available"]
    assert len(client.calls) == 2


def test_unavailable_snapshot_does_not_refetch_resources_on_final_failure(tmp_path):
    routes = {
        ROOT + "/": (
            200,
            "text/html",
            b'<html><script>renderApp()</script><link rel="stylesheet" href="/style.css"></html>',
        ),
        ROOT + "/style.css": (200, "text/css", b"body{color:blue}"),
    }
    client = ErrorClient(routes)
    result = Workflow(client).run(ROOT, tmp_path, threading.Event())
    assert result.reason_code == "browser_required" and not result.offline["available"]
    assert [call[0] for call in client.calls] == [ROOT + "/", ROOT + "/style.css"]
