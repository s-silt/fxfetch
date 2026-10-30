"""HTTP success never needs Android; dynamic handoff retains shared budgets."""

from threading import Event

import pytest

import fxfetch.core.browser_workflow as module
from fxfetch.core.errors import FxfetchError
from fxfetch.core.limits import Limits
from fxfetch.core.workflow import Attempt, WorkflowResult


@pytest.mark.parametrize("outcome,reason", [
    ("downloaded", "package_verified"), ("not_found", "static_scope_complete"),
    ("failed", "candidate_selection_required"), ("failed", "target_not_public"),
    ("failed", "network_timeout"), ("blocked", "http_access_control"),
    ("failed", "page_qr_incomplete"),
])
def test_http_final_result_never_starts_android(tmp_path, monkeypatch, outcome, reason):
    calls = []

    class Static:
        def run(self, url, folder, cancel, on_event):
            calls.append(url)
            return WorkflowResult(outcome, reason, "partial")

    monkeypatch.setattr(module, "BrowserGateway", lambda **kwargs: pytest.fail("Android must stay off"))
    result = module.BrowserWorkflow(Static(), None, Limits(), http_first=True).run("https://entry.test/", tmp_path, Event())
    assert (result.outcome, result.reason_code) == (outcome, reason) and len(calls) == 1


@pytest.mark.parametrize("reason,status", [("browser_required", 200), ("http_status", 502), ("http_access_control", 403),
                                           ("page_qr_incomplete", 200)])
def test_dynamic_handoff_keeps_http_evidence_and_deducts_budget(tmp_path, monkeypatch, reason, status):
    events, budgets = [], []

    class Static:
        def run(self, url, folder, cancel, on_event):
            folder.mkdir()
            (folder / "page").write_bytes(b"x" * 20)
            on_event({"event": "request", "url": url})
            return WorkflowResult("failed", reason, "partial",
                                  attempts=[Attempt("android", url, "failed", reason, "partial")],
                                  hops=[{"url": url, "status": status}], bodies=[{"size": 20}],
                                  page_qr={"status": "partial", "browser_required": True,
                                           "gaps": ["page_qr_image_limit"]})

    class Guard:
        def __init__(self, **kwargs):
            budgets.append(kwargs)
        def __enter__(self):
            raise FxfetchError("browser_guard_unavailable", "Synthetic denial")
        def __exit__(self, *args):
            pass

    monkeypatch.setattr(module, "BrowserGateway", Guard)
    limits = Limits(max_requests=5, max_web_bytes=200, max_task_bytes=1000)
    result = module.BrowserWorkflow(Static(), None, limits, http_first=True).run(
        "https://entry.test/", tmp_path, Event(), events.append)
    assert result.reason_code == "browser_guard_unavailable"
    assert budgets[0]["max_connections"] == 4 and budgets[0]["max_wire_bytes"] == 980
    assert result.bodies == [{"size": 20}] and result.hops[0]["mode"] == "http"
    assert len(result.attempts) == 2
    assert result.landing["http_resolution"]["cookies_inherited"] is False
    assert result.landing["http_resolution"]["page_qr"]["gaps"] == ["page_qr_image_limit"]
    assert any(event.get("new_request_session") is True for event in events)


@pytest.mark.parametrize('reason', ['browser_required', 'page_qr_incomplete'])
def test_http_cannot_reset_task_deadline_before_browser(tmp_path, monkeypatch, reason):
    now = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])

    class Static:
        def run(self, *args):
            now[0] = 11.0
            return WorkflowResult("failed", reason, "partial", page_qr={"browser_required": True})

    monkeypatch.setattr(module, "BrowserGateway", lambda **kwargs: pytest.fail("Deadline already expired"))
    result = module.BrowserWorkflow(Static(), None, Limits(chain_timeout=10), http_first=True).run(
        "https://entry.test/", tmp_path, Event())
    assert result.reason_code == "task_timeout"


def test_qr_handoff_cannot_reset_request_budget(tmp_path, monkeypatch):
    class Static:
        def run(self, url, folder, cancel, on_event):
            on_event({'event': 'request'})
            return WorkflowResult('failed', 'page_qr_incomplete', 'partial',
                                  page_qr={'browser_required': True})

    monkeypatch.setattr(module, 'BrowserGateway', lambda **kwargs: pytest.fail('No requests remain'))
    result = module.BrowserWorkflow(Static(), None, Limits(max_requests=1), http_first=True).run(
        'https://entry.test/', tmp_path, Event())
    assert result.reason_code == 'request_limit'


@pytest.mark.parametrize('browser_outcome', ['downloaded', 'blocked'])
def test_qr_dynamic_continuation_once_preserves_partial_http_evidence(tmp_path, monkeypatch, browser_outcome):
    from types import SimpleNamespace

    from fxfetch.core.browser_capture import BrowserCaptureResult

    observed = []

    class Static:
        client = SimpleNamespace(transport_observer=None)

        def run(self, url, folder, cancel, on_event):
            observed.append('http')
            on_event({'event': 'request'})
            return WorkflowResult('failed', 'page_qr_incomplete', 'partial',
                                  attempts=[Attempt('android', url, 'failed', 'page_qr_incomplete', 'partial')],
                                  page_qr={'status': 'partial', 'browser_required': True,
                                           'gaps': ['page_qr_image_limit']})

    class Guard:
        errors = []

        def __init__(self, **kwargs):
            assert kwargs['max_connections'] == 9

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class Lease(Guard):
        def __init__(self, *args, **kwargs):
            pass

    async def capture(*args, **kwargs):
        observed.append('chrome')
        assert kwargs['limits'].max_requests == 9
        return BrowserCaptureResult(outcome=browser_outcome, reason_code='synthetic_result', coverage='partial')

    monkeypatch.setattr(module, 'BrowserGateway', Guard)
    monkeypatch.setattr(module, 'AndroidWorker', lambda config: None)
    monkeypatch.setattr(module, 'AndroidLease', Lease)
    monkeypatch.setattr(module, 'capture_browser', capture)
    result = module.BrowserWorkflow(Static(), None, Limits(max_requests=10), http_first=True).run(
        'https://entry.test/', tmp_path, Event())
    assert observed == ['http', 'chrome']
    assert result.outcome == browser_outcome
    assert [attempt.reason_code for attempt in result.attempts] == ['page_qr_incomplete', 'synthetic_result']
    prior = result.landing['http_resolution']
    assert prior['coverage'] == 'partial' and prior['page_qr']['gaps'] == ['page_qr_image_limit']
    assert prior['cookies_inherited'] is False
