"""Replay must survive temporary evidence cleanup and capability changes."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from fxfetch.config import Settings
from fxfetch.core.errors import FxfetchError
from fxfetch.core.web_apk import BuildCapability, WebApkBuilder
from fxfetch.core.workflow import Workflow
from fxfetch.security import token_hash
from fxfetch.service import JobService
from fxfetch.web.api import create_app

ENTRY = "https://entry.synthetic.test/open?source=qr#section"


class NeverRunWorkflow(Workflow):
    def run(self, *args, **kwargs):
        pytest.fail("Replay tests must never execute collection")


class ChangingBuilder(WebApkBuilder):
    def __init__(self):
        self.enabled = True
        self.probes = 0

    def probe(self):
        self.probes += 1
        return BuildCapability(self.enabled, () if self.enabled else ("synthetic_toolchain_missing",), {})

    def build(self, *args, **kwargs):
        pytest.fail("Replay tests must never execute a build")


@pytest.fixture
def service(tmp_path: Path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Replay/input persistence performed target DNS or network access")

    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("socket.socket.connect", forbidden)
    settings = Settings(tmp_path, "not-used-with-direct-session", allowed_hosts=("testserver",))
    instance = JobService(settings, workflow=NeverRunWorkflow(), builder=ChangingBuilder())
    # Deliberately do not start workers: the tests exercise durable admission,
    # then use Store.claim/finish to model an owned terminal collection.
    yield instance
    assert not instance._threads


def add_qr_image(service: JobService, owner: str, suffix: str = "first") -> tuple[str, bytes]:
    original = b"synthetic-image-original-" + suffix.encode()
    path = service.store.root / "images" / f"{suffix}.bin"
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(original)
    result = {
        "status": "decoded",
        "sha256": hashlib.sha256(original).hexdigest(),
        "truncated": False,
        "candidates": [{"id": "candidate-1", "kind": "http", "text": ENTRY, "url": ENTRY}],
    }
    identifier = service.store.add_image(owner, str(path.relative_to(service.store.root)), result, 3600, 10)
    return identifier, original


@pytest.mark.parametrize("cleanup", [False, True], ids=["expired", "cleaned"])
def test_qr_job_replay_precedes_expired_image_lookup_and_conflict_is_409(service, monkeypatch, cleanup):
    token = "synthetic-replay-session"
    session = service.store.new_session(token_hash(token), 3600)
    owner = session["id"]
    image_id, original = add_qr_image(service, owner)
    payload = {"url": None, "image_id": image_id, "candidate_id": "candidate-1"}
    first = service.create_job(owner, "same-qr-key", payload)
    with service.store.connect() as db:
        db.execute("UPDATE images SET expires=0 WHERE id=?", (image_id,))
    if cleanup:
        service.cleanup_images()
        with service.store.connect() as db:
            assert db.execute("SELECT count(*) FROM images WHERE id=?", (image_id,)).fetchone()[0] == 0

    monkeypatch.setattr(
        service.store, "image", lambda *a, **kw: pytest.fail("Replay looked up expired QR image")
    )
    assert service.create_job(owner, "same-qr-key", payload)["id"] == first["id"]
    assert (service.store.root / "jobs" / first["id"] / "source" / "image.original").read_bytes() == original
    assert service.store.get_job(owner, first["id"])["input"]["image_id"] == image_id

    with pytest.raises(FxfetchError) as error:
        service.create_job(owner, "same-qr-key", {**payload, "url": "https://changed.synthetic.test/"})
    assert error.value.code == "idempotency_conflict"
    # Exercise the registered error-to-HTTP mapping directly. This handler has
    # no await points; driving it once avoids even Windows asyncio's internal
    # socketpair and does not start a service or target transport.
    handler = create_app(service.settings, service=service).exception_handlers[FxfetchError]
    response_coroutine = handler(None, error.value)
    try:
        with pytest.raises(StopIteration) as completed:
            response_coroutine.send(None)
        assert completed.value.value.status_code == 409
        assert b"idempotency_conflict" in completed.value.value.body
    finally:
        response_coroutine.close()
    assert len(service.store.list_jobs(owner)) == 1


def test_build_replay_precedes_probe_and_does_not_allocate_version(service):
    owner = "owner-build"
    parent = service.create_job(owner, "owned-parent", {"url": ENTRY})
    claimed = service.store.claim_job()
    assert claimed["id"] == parent["id"]
    service.store.finish_job(
        parent["id"],
        "completed",
        {"outcome": "failed", "reason_code": "synthetic_static_gap", "coverage": "partial"},
    )
    candidate = service.get_job(owner, parent["id"])["web_candidates"][0]
    first = service.create_build(owner, parent["id"], "same-build-key", candidate["id"])
    builder = service.builder
    assert isinstance(builder, ChangingBuilder)
    assert first["version"] == 1 and builder.probes == 1
    builder.enabled = False
    replay = service.create_build(owner, parent["id"], "same-build-key", candidate["id"])
    assert replay["id"] == first["id"] and replay["version"] == 1
    assert builder.probes == 1
    with service.store.connect() as db:
        assert db.execute("SELECT count(*) FROM builds").fetchone()[0] == 1
        assert db.execute("SELECT version FROM names").fetchone()[0] == 1
    with pytest.raises(FxfetchError) as error:
        service.create_build(owner, parent["id"], "different-build-key", candidate["id"])
    assert error.value.code == "build_unavailable"
    assert builder.probes == 2
    with service.store.connect() as db:
        assert db.execute("SELECT version FROM names").fetchone()[0] == 1


def test_used_qr_image_releases_pending_slot_and_retains_source(service):
    owner = "owner-images"
    ids = [add_qr_image(service, owner, str(index))[0] for index in range(10)]
    with pytest.raises(FxfetchError) as error:
        add_qr_image(service, owner, "overflow")
    assert error.value.code == "image_queue_full"
    job = service.create_job(
        owner, "consume-first-image", {"url": None, "image_id": ids[0], "candidate_id": "candidate-1"}
    )
    replacement, _ = add_qr_image(service, owner, "replacement")
    assert service.store.image(owner, replacement)["id"] == replacement
    assert service.store.image(owner, ids[0])["used"] == 1
    with service.store.connect() as db:
        assert (
            db.execute("SELECT count(*) FROM images WHERE owner=? AND used=0", (owner,)).fetchone()[0] == 10
        )
        assert db.execute("SELECT count(*) FROM images WHERE owner=?", (owner,)).fetchone()[0] == 11
    source = service.store.root / "jobs" / job["id"] / "source"
    assert source.joinpath("image.original").read_bytes() == b"synthetic-image-original-0"
    assert service.store.get_job(owner, job["id"])["input"]["image_id"] == ids[0]
    assert source.joinpath("qr.json").is_file()
