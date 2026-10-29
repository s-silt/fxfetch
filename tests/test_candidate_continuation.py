"""Explicit server-owned candidate continuation; synthetic URLs, no target access."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fxfetch.config import Settings
from fxfetch.core.errors import FxfetchError
from fxfetch.core.workflow import Workflow, WorkflowResult
from fxfetch.security import password_hash, token_hash
from fxfetch.service import JobService
from fxfetch.web.api import create_app


class RecordingWorkflow(Workflow):
    def __init__(self):
        self.calls: list[str] = []

    def run(self, url, output_dir, cancel, on_event=None):
        self.calls.append(url)
        return WorkflowResult("failed", "synthetic_end", "partial")


@pytest.fixture
def service(tmp_path: Path) -> JobService:
    return JobService(
        Settings(tmp_path, password_hash("synthetic-password"), allowed_hosts=("testserver",)),
        workflow=RecordingWorkflow(),
    )


def parent(
    service: JobService,
    *,
    owner="owner",
    url="https://entry.synthetic.test/start",
    candidates=None,
    state="completed",
    outcome="failed",
    source=None,
) -> dict:
    value = source or {"entry_url": url}
    job, _ = service.store.create_job(owner, "parent-" + str(len(service.store.list_jobs(owner))), value, 20)
    assert service.store.claim_job()["id"] == job["id"]
    service.store.finish_job(
        job["id"],
        state,
        {
            "outcome": outcome,
            "reason_code": "candidate_selection_required",
            "selection_candidates": candidates
            or [
                {
                    "url": "https://cdn.synthetic.test/one.apk",
                    "kind": "direct_apk",
                    "source_url": url,
                    "label": "Android",
                },
                {"url": "https://cdn.synthetic.test/two.apk", "kind": "direct_apk", "source_url": url},
            ],
        },
    )
    return service.get_job(owner, job["id"])


def test_selected_child_is_traced_independent_and_idempotent(service):
    original = parent(service)
    selected = original["download_candidates"][0]
    child = service.continue_job("owner", original["id"], "selection-one", selected["id"])
    assert child["input"]["entry_url"] == selected["url"]
    assert child["input"]["parent_entry_url"] == original["input"]["entry_url"]
    assert child["input"]["session_continuity"] == "independent_request_session"
    assert child["input"]["cookies_inherited"] is False
    assert selected["label"] == "Android"
    assert service.continue_job("owner", original["id"], "selection-one", selected["id"])["id"] == child["id"]
    refreshed = service.get_job("owner", original["id"])
    assert refreshed["continuation_child_job_id"] == child["id"]
    assert refreshed["download_candidates"][0]["child_job_id"] == child["id"]
    assert refreshed["result"] == original["result"]
    with pytest.raises(FxfetchError, match="active"):
        service.continue_job(
            "owner", original["id"], "selection-two", original["download_candidates"][1]["id"]
        )
    claimed = service.store.claim_job()
    service._collect(claimed, threading.Event())
    assert service.workflow.calls == [selected["url"]]


def test_selection_rejects_unowned_arbitrary_input_and_cancelled_parent(service):
    original = parent(service)
    with pytest.raises(FxfetchError) as error:
        service.continue_job(
            "other", original["id"], "selection-key", original["download_candidates"][0]["id"]
        )
    assert error.value.code == "not_found"
    with pytest.raises(FxfetchError) as error:
        service.continue_job(
            "owner", original["id"], "selection-key", "https://arbitrary.synthetic.test/evil.apk"
        )
    assert error.value.code == "invalid_selection"
    assert not parent(service, state="cancelled")["download_candidates"]
    assert not parent(service, outcome="downloaded")["download_candidates"]


def test_fragment_cycles_and_depth_are_bounded(service):
    original = parent(
        service, candidates=[{"url": "https://entry.synthetic.test/start#other", "kind": "http"}]
    )
    with pytest.raises(FxfetchError) as error:
        service.continue_job(
            "owner", original["id"], "selection-key", original["download_candidates"][0]["id"]
        )
    assert error.value.code == "continuation_cycle"
    current = parent(service, url="https://entry.synthetic.test/start?q=one")
    for index in range(4):
        chosen = current["download_candidates"][0]
        child = service.continue_job("owner", current["id"], f"depth-key-{index}", chosen["id"])
        claimed = service.store.claim_job()
        assert claimed["id"] == child["id"]
        service.store.finish_job(
            child["id"],
            "completed",
            {
                "outcome": "failed",
                "reason_code": "candidate_selection_required",
                "selection_candidates": [
                    {"url": f"https://cdn.synthetic.test/{index + 1}.apk", "kind": "direct_apk"}
                ],
            },
        )
        current = service.get_job("owner", child["id"])
    with pytest.raises(FxfetchError) as error:
        service.continue_job("owner", current["id"], "depth-key-end", current["download_candidates"][0]["id"])
    assert error.value.code == "continuation_limit"


def test_clear_hides_parent_and_child_and_cancels_queue(service):
    original = parent(service)
    child = service.continue_job(
        "owner", original["id"], "selection-key", original["download_candidates"][0]["id"]
    )
    service.clear_jobs("owner")
    for identifier in (original["id"], child["id"]):
        with pytest.raises(FxfetchError):
            service.get_job("owner", identifier)
    assert service.store.claim_job() is None


def test_api_requires_origin_csrf_owner_idempotency_and_candidate_only(service):
    session = service.store.new_session(token_hash("synthetic-token"), 300)
    original = parent(service, owner=session["id"])
    app = create_app(service.settings, service=service)
    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        client.cookies.set("fxfetch_session", "synthetic-token")
        path = f"/api/jobs/{original['id']}/continue"
        body = {"candidate_id": original["download_candidates"][0]["id"]}
        headers = {
            "Origin": "http://testserver",
            "X-CSRF-Token": session["csrf"],
            "Idempotency-Key": "selection-key",
        }
        assert client.post(path, json=body).status_code == 403
        assert client.post(path, json=body, headers={"Origin": "http://testserver"}).status_code == 403
        assert (
            client.post(
                path, json=body, headers={k: v for k, v in headers.items() if k != "Idempotency-Key"}
            ).status_code
            == 400
        )
        assert (
            client.post(
                path, json={**body, "url": "https://arbitrary.synthetic.test"}, headers=headers
            ).status_code
            == 422
        )
        response = client.post(path, json=body, headers=headers)
        assert response.status_code == 202, response.text
        assert client.post(path, json=body, headers=headers).json()["id"] == response.json()["id"]


def test_candidate_validation_and_query_identity(service):
    original = parent(
        service,
        url="https://entry.synthetic.test/start?q=one",
        candidates=[
            {"url": "javascript:alert(1)", "kind": "http"},
            {"url": "https://entry.synthetic.test/start?q=two", "kind": "http"},
            {"url": "https://apps.apple.com/example", "kind": "http"},
            {"url": "https://entry.synthetic.test/start?q=two", "kind": "http"},
        ],
    )
    assert len(original["download_candidates"]) == 1
    child = service.continue_job(
        "owner", original["id"], "selection-key", original["download_candidates"][0]["id"]
    )
    assert child["input"]["entry_url"].endswith("?q=two")


def test_source_persistence_failure_never_runs_child(service, monkeypatch):
    original = parent(service)

    def fail(*args):
        raise OSError("synthetic-disk-error")

    monkeypatch.setattr("fxfetch.service.atomic_json", fail)
    with pytest.raises(OSError):
        service.continue_job(
            "owner", original["id"], "selection-key", original["download_candidates"][0]["id"]
        )
    assert service.store.claim_job() is None
    child_id = service.get_job("owner", original["id"])["download_candidates"][0]["child_job_id"]
    assert service.get_job("owner", child_id)["state"] == "interrupted"


def test_concurrent_selection(service):
    from concurrent.futures import ThreadPoolExecutor

    original = parent(service)
    selected = original["download_candidates"][0]["id"]
    with ThreadPoolExecutor(max_workers=4) as pool:
        values = list(
            pool.map(
                lambda _: service.continue_job("owner", original["id"], "selection-key", selected), range(4)
            )
        )
    assert len({value["id"] for value in values}) == 1
    with pytest.raises(FxfetchError) as error:
        service.continue_job(
            "owner", original["id"], "selection-key", original["download_candidates"][1]["id"]
        )
    assert error.value.code == "idempotency_conflict"


def test_queue_full_does_not_consume_parent_selection(service):
    original = parent(service)
    with pytest.raises(FxfetchError) as error:
        service.store.create_continuation(
            "owner",
            original["id"],
            "synthetic-id",
            "selection-key",
            {"entry_url": "https://cdn.synthetic.test/one.apk"},
            0,
        )
    assert error.value.code == "queue_full"
    assert service.store.continuation_child("owner", original["id"]) is None
    child = service.continue_job(
        "owner", original["id"], "selection-key", original["download_candidates"][0]["id"]
    )
    assert child["state"] == "queued"


def test_failed_child_allows_other_candidate_but_never_replays_selected(service):
    original = parent(service)
    first, second = original["download_candidates"]
    child = service.continue_job("owner", original["id"], "first-choice-key", first["id"])
    with pytest.raises(FxfetchError) as error:
        service.continue_job("owner", original["id"], "second-choice-key", second["id"])
    assert error.value.code == "continuation_active"
    claimed = service.store.claim_job()
    service._collect(claimed, threading.Event())
    refreshed = service.get_job("owner", original["id"])
    assert refreshed["continuation_active_child_job_id"] is None
    assert refreshed["download_candidates"][0]["child_job_id"] == child["id"]
    other = service.continue_job("owner", original["id"], "second-choice-key", second["id"])
    assert other["input"]["entry_url"] == second["url"]
    with pytest.raises(FxfetchError) as error:
        service.continue_job("owner", original["id"], "first-again-key", first["id"])
    assert error.value.code == "candidate_already_selected"


def test_concurrent_distinct_choices_start_only_one_child(service):
    from concurrent.futures import ThreadPoolExecutor

    original = parent(service)

    def choose(item):
        try:
            return service.continue_job("owner", original["id"], "concurrent-" + item["id"], item["id"])[
                "state"
            ]
        except FxfetchError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(choose, original["download_candidates"]))
    assert sorted(results) == ["continuation_active", "queued"]
    assert len(service.store.continuation_children("owner", original["id"])) == 1


def test_legacy_history_without_exact_selection_is_unavailable(service):
    job, _ = service.store.create_job(
        "owner", "legacy-history-key", {"entry_url": "https://entry.synthetic.test/start"}, 20
    )
    service.store.claim_job()
    service.store.finish_job(
        job["id"],
        "completed",
        {
            "outcome": "failed",
            "reason_code": "candidate_selection_required",
            "candidates": [
                {"url": "https://intermediate.synthetic.test/consumed", "kind": "http"},
                {"url": "https://cdn.synthetic.test/app.apk", "kind": "direct_apk"},
            ],
        },
    )
    value = service.get_job("owner", job["id"])
    assert value["download_candidates"] == []
    assert value["download_selection_unavailable"] is True
    assert value["result"]["candidates"]
    with pytest.raises(FxfetchError) as error:
        service.continue_job("owner", job["id"], "legacy-select-key", "invented-id")
    assert error.value.code == "invalid_selection"
