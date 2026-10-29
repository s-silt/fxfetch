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


@pytest.mark.parametrize("reason,status", [("browser_required", 200), ("http_status", 502), ("http_access_control", 403)])
def test_dynamic_handoff_keeps_http_evidence_and_deducts_budget(tmp_path, monkeypatch, reason, status):
    events, budgets = [], []

    class Static:
        def run(self, url, folder, cancel, on_event):
            folder.mkdir()
            (folder / "page").write_bytes(b"x" * 20)
            on_event({"event": "request", "url": url})
            return WorkflowResult("failed", reason, "partial",
                                  attempts=[Attempt("android", url, "failed", reason, "partial")],
                                  hops=[{"url": url, "status": status}], bodies=[{"size": 20}])

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
    assert any(event.get("new_request_session") is True for event in events)


def test_http_cannot_reset_task_deadline_before_browser(tmp_path, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])

    class Static:
        def run(self, *args):
            now[0] = 11.0
            return WorkflowResult("failed", "browser_required", "partial")

    monkeypatch.setattr(module, "BrowserGateway", lambda **kwargs: pytest.fail("Deadline already expired"))
    result = module.BrowserWorkflow(Static(), None, Limits(chain_timeout=10), http_first=True).run(
        "https://entry.test/", tmp_path, Event())
    assert result.reason_code == "task_timeout"
