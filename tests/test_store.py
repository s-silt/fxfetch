"""SQLite ownership, restart and concurrent idempotency contract tests."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from fxfetch.core.errors import FxfetchError
from fxfetch.core.web_apk import derive_names
from fxfetch.security import token_hash
from fxfetch.store import Store


def finished(store: Store, owner="owner-a", key="synthetic-job", outcome="failed") -> dict:
    job, _ = store.create_job(owner, key, {"entry_url": "https://entry.synthetic.test/"}, 20)
    assert store.claim_job()["state"] == "running"
    store.finish_job(job["id"], "completed", {"outcome": outcome, "reason_code": "synthetic"})
    return store.get_job(owner, job["id"])


def test_concurrent_same_key_is_one_transaction(tmp_path: Path):
    stores = [Store(tmp_path), Store(tmp_path)]

    def submit(index):
        return stores[index % 2].create_job(
            "owner-a", "shared-key", {"entry_url": "https://entry.synthetic.test/"}, 20
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(submit, range(20)))
    assert sum(created for _, created in results) == 1
    assert len({job["id"] for job, _ in results}) == 1
    assert len(stores[0].list_jobs("owner-a")) == 1
    with pytest.raises(FxfetchError, match="different request"):
        stores[1].create_job("owner-a", "shared-key", {"entry_url": "https://other.synthetic.test/"}, 20)


def test_queue_limit_and_session_scoped_idempotency(tmp_path: Path):
    store = Store(tmp_path)
    first, _ = store.create_job("owner-a", "same-key", {"entry_url": "https://a.synthetic.test/"}, 1)
    replay, created = store.create_job("owner-a", "same-key", {"entry_url": "https://a.synthetic.test/"}, 1)
    assert replay["id"] == first["id"] and not created
    with pytest.raises(FxfetchError) as caught:
        store.create_job("owner-b", "same-key", {"entry_url": "https://b.synthetic.test/"}, 1)
    assert caught.value.code == "queue_full"
    store.cancel_queued_job("owner-a", first["id"])
    second, _ = store.create_job("owner-b", "same-key", {"entry_url": "https://b.synthetic.test/"}, 1)
    assert second["id"] != first["id"]
    assert second["outcome"] is None


@pytest.mark.parametrize("mode", ["orphan", "other_owner", "running", "downloaded"])
def test_build_requires_eligible_owned_parent(tmp_path: Path, mode: str):
    store = Store(tmp_path)
    owner = "owner-a"
    if mode == "orphan":
        identifier = "nonexistent"
    elif mode == "running":
        job, _ = store.create_job(owner, "job-key", {"entry_url": "https://entry.synthetic.test/"}, 20)
        identifier = job["id"]
        store.claim_job()
    else:
        job = finished(store, outcome="downloaded" if mode == "downloaded" else "failed")
        identifier = job["id"]
        if mode == "other_owner":
            owner = "owner-b"
    url = "https://entry.synthetic.test/"
    with pytest.raises(FxfetchError) as caught:
        store.create_build(owner, identifier, "build-key", url, derive_names(url), 10)
    assert caught.value.code == "invalid_build_source"


def test_build_collision_version_and_idempotency_survive_reopen(tmp_path: Path):
    store = Store(tmp_path)
    job = finished(store)
    first_url = "https://alphabet-one.synthetic.test/open?x=1"
    second_url = "https://alphabet-two.synthetic.test/open?x=2"
    first_names, second_names = derive_names(first_url), derive_names(second_url)
    assert first_names.package_base == second_names.package_base
    first = store.create_build("owner-a", job["id"], "build-first", first_url, first_names, 10)
    replay = store.create_build("owner-a", job["id"], "build-first", first_url, first_names, 10)
    assert replay["id"] == first["id"] and replay["version"] == 1
    second = store.create_build("owner-a", job["id"], "build-second", second_url, second_names, 10)
    assert second["package"] != first["package"]
    reopened = Store(tmp_path)
    third = reopened.create_build("owner-a", job["id"], "build-third", first_url, first_names, 10)
    assert third["package"] == first["package"]
    assert third["version"] == 2
    with pytest.raises(FxfetchError) as caught:
        reopened.create_build("owner-a", job["id"], "build-first", second_url, second_names, 10)
    assert caught.value.code == "idempotency_conflict"


def test_build_version_allocation_is_atomic(tmp_path: Path):
    stores = [Store(tmp_path), Store(tmp_path)]
    job = finished(stores[0])
    url = "https://entry.synthetic.test/"
    names = derive_names(url)

    def create(index):
        return stores[index % 2].create_build("owner-a", job["id"], f"build-{index}", url, names, 20)

    with ThreadPoolExecutor(max_workers=4) as executor:
        builds = list(executor.map(create, range(10)))
    assert sorted(build["version"] for build in builds) == list(range(1, 11))
    assert len({build["package"] for build in builds}) == 1


def test_restart_interrupts_running_and_queued_without_outcome_invention(tmp_path: Path):
    store = Store(tmp_path)
    complete = finished(store)
    url = "https://entry.synthetic.test/"
    build = store.create_build("owner-a", complete["id"], "build-key", url, derive_names(url), 10)
    assert store.claim_build()["state"] == "running"
    first, _ = store.create_job("owner-a", "running-job", {"entry_url": url}, 20)
    assert store.claim_job()["state"] == "running"
    second, _ = store.create_job("owner-a", "queued-job", {"entry_url": url}, 20)
    Store(tmp_path).restart_interrupt()
    for job in (first, second):
        current = store.get_job("owner-a", job["id"])
        assert current["state"] == "interrupted" and current["outcome"] is None
    assert store.get_build("owner-a", complete["id"], build["id"])["state"] == "interrupted"
    assert store.get_job("owner-a", complete["id"])["outcome"] == "failed"
    assert store.claim_job() is None and store.claim_build() is None


def test_finish_and_cancel_cannot_reopen_terminal_records(tmp_path: Path):
    store = Store(tmp_path)
    job = finished(store)
    store.finish_job(job["id"], "completed", {"outcome": "downloaded"})
    assert store.get_job("owner-a", job["id"])["outcome"] == "failed"
    with pytest.raises(ValueError):
        store.finish_job(job["id"], "queued", {})
    url = "https://entry.synthetic.test/"
    build = store.create_build("owner-a", job["id"], "build-key", url, derive_names(url), 10)
    store.cancel_queued_build("owner-a", job["id"], build["id"])
    store.finish_build(build["id"], "built", {})
    assert store.get_build("owner-a", job["id"], build["id"])["state"] == "cancelled"
    with pytest.raises(ValueError):
        store.finish_build(build["id"], "queued", {})


def test_sessions_expiry_logout_and_image_ownership(tmp_path: Path):
    store = Store(tmp_path)
    active = store.new_session(token_hash("synthetic-session-token"), 3600)
    assert store.session(token_hash("synthetic-session-token"))["id"] == active["id"]
    store.new_session(token_hash("expired-synthetic-token"), -1)
    assert store.session(token_hash("expired-synthetic-token")) is None
    image = store.add_image(active["id"], "images/synthetic.png", {"status": "decoded"}, 3600, 1)
    with pytest.raises(FxfetchError):
        store.image("other-session", image)
    with pytest.raises(FxfetchError) as caught:
        store.add_image(active["id"], "images/second.png", {}, 3600, 1)
    assert caught.value.code == "image_queue_full"
    store.logout(active["id"])
    assert store.session(token_hash("synthetic-session-token")) is None


def test_archived_jobs_stay_hidden_after_worker_completion_and_reopen(tmp_path):
    store = Store(tmp_path)
    source = {"entry_url": "https://entry.synthetic.test/"}
    active, _ = store.create_job("owner-a", "active-key", source, 20)
    store.claim_job()
    queued, _ = store.create_job("owner-a", "queued-key", source, 20)
    other, _ = store.create_job("owner-b", "other-key", source, 20)
    count, active_ids = store.clear_jobs("owner-a")
    assert count == 2 and active_ids == [active["id"]]
    store.finish_job(active["id"], "cancelled", {"outcome": "failed", "reason_code": "cancelled"})
    reopened = Store(tmp_path)
    assert reopened.list_jobs("owner-a") == []
    assert reopened.list_jobs("owner-b")[0]["id"] == other["id"]
    for job in (active, queued):
        with pytest.raises(FxfetchError) as caught:
            reopened.get_job("owner-a", job["id"])
        assert caught.value.code == "not_found"
        assert reopened.get_job("owner-a", job["id"], include_archived=True)["state"] == "cancelled"
    with pytest.raises(FxfetchError):
        reopened.replay_job("owner-a", "active-key", source)
    with pytest.raises(FxfetchError):
        reopened.create_job("owner-a", "active-key", source, 20)
    assert reopened.claim_job()["id"] == other["id"]


def test_clear_keeps_completed_private_artifact_and_hides_build_access(tmp_path):
    store = Store(tmp_path)
    job = finished(store)
    url = "https://entry.synthetic.test/"
    build = store.create_build("owner-a", job["id"], "queued-build", url, derive_names(url), 10)
    private = tmp_path / "private.apk"
    private.write_bytes(b"synthetic preserved bytes")
    artifact = store.add_artifact(
        job_id=job["id"],
        owner="owner-a",
        path="private.apk",
        filename="private.apk",
        kind="apk",
        sha256="0" * 64,
        size=private.stat().st_size,
        origin="synthetic",
    )
    assert store.clear_jobs("owner-a")[0] == 1
    assert private.is_file()
    assert store.claim_build() is None
    with pytest.raises(FxfetchError):
        store.artifact("owner-a", job["id"], artifact)
    with pytest.raises(FxfetchError):
        store.get_build("owner-a", job["id"], build["id"])
    with pytest.raises(FxfetchError):
        store.create_build("owner-a", job["id"], "new-build", url, derive_names(url), 10)
