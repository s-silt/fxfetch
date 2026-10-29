"""Synthetic API acceptance: real service threads, no target transport or toolchain."""

from __future__ import annotations

import hashlib
import io
import json
import socket
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest
import qrcode
from fastapi.testclient import TestClient

from fxfetch.config import Settings
from fxfetch.core.web_apk import BuildCapability, BuildResult, WebApkBuilder
from fxfetch.core.workflow import Artifact, Workflow, WorkflowResult
from fxfetch.security import password_hash, token_hash
from fxfetch.service import JobService
from fxfetch.web.api import create_app

PASSWORD = "synthetic-api-password"
ORIGIN = {"Origin": "http://testserver"}


class SyntheticWorkflow(Workflow):
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.started = threading.Event()
        self.release = threading.Event()
        self.release.set()
        self.downloaded = False

    def run(self, url, output_dir, cancel, on_event=None):
        self.calls.append(url)
        self.started.set()
        while not self.release.wait(0.01):
            if cancel.is_set():
                return WorkflowResult("failed", "cancelled", "partial")
        if cancel.is_set():
            return WorkflowResult("failed", "cancelled", "partial")
        if self.downloaded:
            path = output_dir / "artifacts" / "synthetic.apk"
            path.parent.mkdir(parents=True, exist_ok=True)
            data = b"synthetic-original-artifact"
            path.write_bytes(data)
            return WorkflowResult(
                "downloaded",
                "package_validated",
                "complete",
                artifacts=[Artifact("apk", path, hashlib.sha256(data).hexdigest(), len(data), url)],
            )
        return WorkflowResult("failed", "synthetic_unavailable", "partial")


class SyntheticBuilder(WebApkBuilder):
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, int]] = []
        self.started = threading.Event()
        self.release = threading.Event()
        self.release.set()

    def probe(self):
        return BuildCapability(True, (), {})

    def build(self, url, output_dir, package, version, cancel):
        self.calls.append((url, package, version))
        self.started.set()
        while not self.release.wait(0.01):
            if cancel.is_set():
                return BuildResult("cancelled", "cancelled")
        if cancel.is_set():
            return BuildResult("cancelled", "cancelled")
        path = output_dir / "synthetic.apk"
        path.parent.mkdir(parents=True, exist_ok=True)
        data = b"synthetic-generated-artifact"
        path.write_bytes(data)
        return BuildResult(
            "built",
            artifact_path=path,
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
            filename="entry.apk",
        )


@pytest.fixture(scope="module")
def encoded_password() -> str:
    return password_hash(PASSWORD)


@pytest.fixture
def running(
    tmp_path: Path, encoded_password: str
) -> Iterator[tuple[TestClient, JobService, SyntheticWorkflow, SyntheticBuilder]]:
    settings = Settings(tmp_path, encoded_password, allowed_hosts=("testserver",))
    workflow, builder = SyntheticWorkflow(), SyntheticBuilder()
    service = JobService(settings, workflow=workflow, builder=builder)
    app = create_app(settings, service=service)
    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        yield client, service, workflow, builder


def login(client: TestClient) -> dict[str, str]:
    result = client.post("/api/login", json={"password": PASSWORD}, headers=ORIGIN)
    assert result.status_code == 200, result.text
    return {**ORIGIN, "X-CSRF-Token": result.json()["csrf_token"]}


def submit(
    client: TestClient,
    headers: dict[str, str],
    *,
    key="synthetic-key-1",
    url="https://entry.synthetic.test/open?q=one#fragment",
) -> dict:
    response = client.post("/api/jobs", json={"url": url}, headers={**headers, "Idempotency-Key": key})
    assert response.status_code == 202, response.text
    return response.json()


def wait_job(client: TestClient, identifier: str, state="completed") -> dict:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = client.get(f"/api/jobs/{identifier}")
        assert result.status_code == 200, result.text
        if result.json()["state"] == state:
            return result.json()
        time.sleep(0.01)
    pytest.fail(f"job did not become {state}: {result.text}")


def test_login_origin_host_csrf_and_logout(running):
    client, _, workflow, builder = running
    assert client.get("/api/capabilities").status_code == 401
    assert client.post("/api/login", json={"password": PASSWORD}).status_code == 403
    assert (
        client.post(
            "/api/login", json={"password": PASSWORD}, headers={"Origin": "https://other.synthetic.test"}
        ).status_code
        == 403
    )
    assert client.get("/api/session", headers={"Host": "evil.synthetic.test"}).status_code == 400
    headers = login(client)
    assert client.get("/api/capabilities").status_code == 200
    assert (
        client.post("/api/preview", json={"url": "https://entry.synthetic.test/"}, headers=ORIGIN).status_code
        == 403
    )
    preview = client.post("/api/preview", json={"url": "https://entry.synthetic.test/"}, headers=headers)
    assert preview.status_code == 200, preview.text
    assert preview.json()["network_requests"] == 0
    assert not workflow.calls and not builder.calls
    assert client.post("/api/logout", headers=headers).status_code == 200
    assert client.get("/api/capabilities").status_code == 401


def test_entry_preview_and_submit_use_one_normalizer_without_preview_access(running):
    client, service, workflow, _ = running
    headers = login(client)
    original = "  entry.synthetic.test/app?a=%2F#fragment  "
    expected = "https://entry.synthetic.test/app?a=%2F#fragment"
    preview = client.post("/api/preview", json={"url": original}, headers=headers)
    assert preview.status_code == 200
    assert preview.json()["url"] == expected
    assert preview.json()["original_input"] == original
    assert preview.json()["normalized"] is True and preview.json()["network_requests"] == 0
    assert workflow.calls == []
    job = submit(client, headers, key="bare-domain", url=original)
    wait_job(client, job["id"])
    assert workflow.calls == [expected]
    assert job["input"]["entry_url"] == expected and job["input"]["original_input"] == original
    replay = submit(client, headers, key="bare-domain", url=original)
    assert replay["id"] == job["id"] and workflow.calls == [expected]
    source = service.store.root / "jobs" / job["id"] / "source" / "input.json"
    assert json.loads(source.read_text())["original_input"] == original


def test_unsupported_explicit_scheme_is_never_completed_as_https(running):
    client, _, workflow, _ = running
    headers = login(client)
    for index, url in enumerate(("javascript:alert(1)", "data:text/plain,test", "file:///tmp/test", "ftp://entry.test/")):
        preview = client.post("/api/preview", json={"url": url}, headers=headers)
        job = client.post("/api/jobs", json={"url": url}, headers={**headers, "Idempotency-Key": f"bad-scheme-{index}"})
        assert preview.status_code == job.status_code == 400
    assert workflow.calls == []


def test_qr_upload_and_preview_never_start_target_job(running, monkeypatch):
    client, service, workflow, builder = running
    headers = login(client)
    dns_targets = []
    original = socket.getaddrinfo

    def no_target_dns(host, *args, **kwargs):
        if isinstance(host, str) and host.endswith(".synthetic.test"):
            dns_targets.append(host)
            raise AssertionError("target DNS forbidden during upload")
        return original(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", no_target_dns)
    data = io.BytesIO()
    url = "https://qr.synthetic.test/open?signature=a%2Fb#fragment"
    qrcode.make(url).save(data, format="PNG")
    response = client.post(
        "/api/qr-images", files={"file": ("synthetic.png", data.getvalue(), "image/png")}, headers=headers
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["status"] == "decoded"
    assert result["candidates"][0]["url"] == url
    assert not workflow.calls and not builder.calls and not dns_targets
    owner = service.store.session(token_hash(client.cookies["fxfetch_session"]))["id"]
    assert service.store.image(owner, result["id"])["result"]["sha256"] == result["sha256"]
    assert client.get("/api/jobs").json()["jobs"] == []


def test_idempotency_requires_click_and_runs_once(running):
    client, _, workflow, builder = running
    headers = login(client)
    first = submit(client, headers)
    again = submit(client, headers)
    assert again["id"] == first["id"]
    conflicting = client.post(
        "/api/jobs",
        json={"url": "https://different.synthetic.test/"},
        headers={**headers, "Idempotency-Key": "synthetic-key-1"},
    )
    assert conflicting.status_code == 409
    assert conflicting.json()["error"]["code"] == "idempotency_conflict"
    wait_job(client, first["id"])
    assert workflow.calls == ["https://entry.synthetic.test/open?q=one#fragment"]
    assert not builder.calls
    assert (
        client.post("/api/jobs", json={"url": "https://entry.synthetic.test/"}, headers=headers).status_code
        == 400
    )


def test_cross_session_job_image_and_artifact_are_private(running):
    client, service, workflow, _ = running
    first_headers = login(client)
    workflow.downloaded = True
    job = wait_job(client, submit(client, first_headers)["id"])
    artifact_id = job["artifacts"][0]["id"]
    owner = service.store.session(token_hash(client.cookies["fxfetch_session"]))["id"]
    image_id = service.store.add_image(owner, "images/synthetic.png", {"candidates": []}, 3600, 10)
    second_headers = login(client)
    assert client.get(f"/api/jobs/{job['id']}").status_code == 404
    assert client.get(f"/api/jobs/{job['id']}/artifacts/{artifact_id}").status_code == 404
    result = client.post(
        "/api/jobs",
        json={"image_id": image_id, "candidate_id": "qr-1"},
        headers={**second_headers, "Idempotency-Key": "other-session-key"},
    )
    assert result.status_code == 404
    assert client.get("/api/jobs").json()["jobs"] == []


def test_build_click_only_keeps_original_outcome_and_is_idempotent(running):
    client, _, workflow, builder = running
    headers = login(client)
    job = wait_job(client, submit(client, headers)["id"])
    assert job["outcome"] == "failed"
    assert not builder.calls
    assert len(job["web_candidates"]) == 1
    path = f"/api/jobs/{job['id']}/web-apk-builds"
    payload = {"candidate_id": job["web_candidates"][0]["id"]}
    request_headers = {**headers, "Idempotency-Key": "synthetic-build-key"}
    response = client.post(path, json=payload, headers=request_headers)
    assert response.status_code == 202, response.text
    build = response.json()
    assert client.post(path, json=payload, headers=request_headers).json()["id"] == build["id"]
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = client.get(f"{path}/{build['id']}").json()
        if result["state"] == "built":
            break
        time.sleep(0.01)
    assert result["state"] == "built", result
    assert len(builder.calls) == 1
    after = client.get(f"/api/jobs/{job['id']}").json()
    assert after["outcome"] == "failed"
    artifact = after["artifacts"][0]
    assert artifact["origin"] == "generated_webview"
    download = client.get(f"/api/jobs/{job['id']}/artifacts/{artifact['id']}")
    assert download.status_code == 200
    assert download.content == b"synthetic-generated-artifact"
    assert len(workflow.calls) == 1
    login(client)
    assert client.get(f"{path}/{build['id']}").status_code == 404
    assert client.get(f"/api/jobs/{job['id']}/artifacts/{artifact['id']}").status_code == 404


def test_downloaded_original_never_offers_web_build(running):
    client, _, workflow, builder = running
    workflow.downloaded = True
    headers = login(client)
    job = wait_job(client, submit(client, headers)["id"])
    assert job["outcome"] == "downloaded"
    assert job["web_candidates"] == []
    result = client.post(
        f"/api/jobs/{job['id']}/web-apk-builds",
        json={"candidate_id": "invented"},
        headers={**headers, "Idempotency-Key": "invalid-build-key"},
    )
    assert result.status_code == 409
    assert not builder.calls


def test_cancel_running_and_queued_jobs(running):
    client, _, workflow, _ = running
    workflow.release.clear()
    headers = login(client)
    first = submit(client, headers, key="running-cancel-key")
    assert workflow.started.wait(3)
    second = submit(client, headers, key="queued-cancel-key")
    assert client.post(f"/api/jobs/{second['id']}/cancel", headers=headers).status_code == 200
    assert wait_job(client, second["id"], "cancelled")["outcome"] is None
    assert client.post(f"/api/jobs/{first['id']}/cancel", headers=headers).status_code == 200
    assert wait_job(client, first["id"], "cancelled")["outcome"] != "not_found"
    assert len(workflow.calls) == 1


def test_artifact_path_guard_rejects_database_traversal(running):
    client, service, _, _ = running
    headers = login(client)
    job = wait_job(client, submit(client, headers)["id"])
    owner = service.store.session(token_hash(client.cookies["fxfetch_session"]))["id"]
    artifact_id = service.store.add_artifact(
        job_id=job["id"],
        owner=owner,
        path="../outside.synthetic",
        filename="outside.apk",
        kind="apk",
        sha256="0" * 64,
        size=1,
        origin="synthetic",
    )
    result = client.get(f"/api/jobs/{job['id']}/artifacts/{artifact_id}")
    assert result.status_code == 400
    assert result.json()["error"]["code"] == "unsafe_path"


def test_restart_marks_queued_interrupted_without_replaying(tmp_path: Path, encoded_password: str):
    settings = Settings(tmp_path, encoded_password, allowed_hosts=("testserver",))
    workflow, builder = SyntheticWorkflow(), SyntheticBuilder()
    service = JobService(settings, workflow=workflow, builder=builder)
    completed, _ = service.store.create_job(
        "synthetic-owner", "finished-key", {"entry_url": "https://entry.synthetic.test/"}, 20
    )
    service.store.claim_job()
    service.store.finish_job(completed["id"], "completed", {"outcome": "failed"})
    from fxfetch.core.web_apk import derive_names

    url = "https://entry.synthetic.test/"
    build = service.store.create_build(
        "synthetic-owner", completed["id"], "build-pending-key", url, derive_names(url), 10
    )
    pending, _ = service.store.create_job(
        "synthetic-owner", "restart-key", {"entry_url": "https://entry.synthetic.test/"}, 20
    )
    with TestClient(create_app(settings, service=service), client=("127.0.0.1", 50000)) as client:
        assert client.get("/api/session").status_code == 200
        job = service.store.get_job("synthetic-owner", pending["id"])
        assert job["state"] == "interrupted"
        assert job["outcome"] is None
        assert job["reason_code"] == "service_restarted"
        assert (
            service.store.get_build("synthetic-owner", completed["id"], build["id"])["state"] == "interrupted"
        )
        assert not workflow.calls and not builder.calls


def test_running_and_queued_build_cancellation_preserves_collection(running):
    client, _, _, builder = running
    headers = login(client)
    job = wait_job(client, submit(client, headers)["id"])
    path = f"/api/jobs/{job['id']}/web-apk-builds"
    payload = {"candidate_id": job["web_candidates"][0]["id"]}
    builder.release.clear()
    first = client.post(
        path, json=payload, headers={**headers, "Idempotency-Key": "build-cancel-first"}
    ).json()
    assert builder.started.wait(3)
    second = client.post(
        path, json=payload, headers={**headers, "Idempotency-Key": "build-cancel-second"}
    ).json()
    assert client.post(f"{path}/{second['id']}/cancel", headers=headers).json()["state"] == "cancelled"
    assert client.post(f"{path}/{first['id']}/cancel", headers=headers).status_code == 200
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = client.get(f"{path}/{first['id']}").json()
        if result["state"] == "cancelled":
            break
        time.sleep(0.01)
    assert result["state"] == "cancelled"
    assert len(builder.calls) == 1
    assert client.get(f"/api/jobs/{job['id']}").json()["outcome"] == "failed"


@pytest.mark.parametrize("declared_length", [None, "1", "4096"])
def test_upload_wire_limit_precedes_multipart_parser(
    tmp_path: Path, encoded_password: str, monkeypatch, declared_length
):
    from starlette.formparsers import MultiPartParser

    limits = replace(Settings(tmp_path, encoded_password).limits, max_upload_bytes=1024, max_image_bytes=512)
    settings = Settings(tmp_path, encoded_password, allowed_hosts=("testserver",), limits=limits)
    service = JobService(settings, workflow=SyntheticWorkflow(), builder=SyntheticBuilder())
    parser_called = []
    original = MultiPartParser.parse

    async def tracked_parse(self):
        parser_called.append(True)
        return await original(self)

    monkeypatch.setattr(MultiPartParser, "parse", tracked_parse)
    with TestClient(create_app(settings, service=service), client=("127.0.0.1", 50000)) as client:
        headers = login(client)
        payload = (
            b'--synthetic\r\nContent-Disposition: form-data; name="file"; filename="synthetic.png"\r\n'
            b"Content-Type: image/png\r\n\r\n" + b"x" * 2048 + b"\r\n--synthetic--\r\n"
        )
        request_headers = {**headers, "Content-Type": "multipart/form-data; boundary=synthetic"}
        if declared_length is not None:
            request_headers["Content-Length"] = declared_length
        result = client.post(
            "/api/qr-images",
            content=(payload[index : index + 256] for index in range(0, len(payload), 256)),
            headers=request_headers,
        )
        assert result.status_code == 413, result.text
        assert not parser_called
        assert not list((tmp_path / "images").glob("*"))


def test_unauthenticated_upload_does_not_parse_or_create_files(running, monkeypatch):
    from starlette.formparsers import MultiPartParser

    client, service, _, _ = running
    parser_called = []
    original = MultiPartParser.parse

    async def tracked_parse(self):
        parser_called.append(True)
        return await original(self)

    monkeypatch.setattr(MultiPartParser, "parse", tracked_parse)
    result = client.post("/api/qr-images", files={"file": ("synthetic.png", b"synthetic")}, headers=ORIGIN)
    assert result.status_code == 401
    assert not parser_called
    assert not list((service.store.root / "images").glob("*"))


def test_login_attempt_rate_limit(running):
    client, _, _, _ = running
    for _ in range(5):
        assert client.post("/api/login", json={"password": "incorrect"}, headers=ORIGIN).status_code == 401
    assert client.post("/api/login", json={"password": PASSWORD}, headers=ORIGIN).status_code == 429


def test_selected_qr_evidence_survives_temporary_image_expiry(running):
    client, service, workflow, _ = running
    headers = login(client)
    data = io.BytesIO()
    qrcode.make("https://qr.synthetic.test/original?x=1").save(data, format="PNG")
    uploaded = client.post(
        "/api/qr-images", files={"file": ("synthetic.png", data.getvalue())}, headers=headers
    ).json()
    response = client.post(
        "/api/jobs",
        json={
            "image_id": uploaded["id"],
            "candidate_id": "qr-1",
            "url": "https://edited.synthetic.test/actual?token=a%2Fb#fragment",
        },
        headers={**headers, "Idempotency-Key": "edited-qr-evidence"},
    )
    assert response.status_code == 202, response.text
    job = wait_job(client, response.json()["id"])
    source = service.store.root / "jobs" / job["id"] / "source"
    assert hashlib.sha256((source / "image.original").read_bytes()).hexdigest() == uploaded["sha256"]
    assert (source / "qr.json").is_file()
    assert job["input"]["kind"] == "edited_qr"
    assert job["input"]["qr_original"] == "https://qr.synthetic.test/original?x=1"
    assert workflow.calls == ["https://edited.synthetic.test/actual?token=a%2Fb#fragment"]
    with service.store.connect() as db:
        db.execute("UPDATE images SET expires=0 WHERE id=?", (uploaded["id"],))
    service.cleanup_images()
    assert (source / "image.original").is_file()


def test_source_persistence_failure_does_not_start_collection(running, monkeypatch):
    import fxfetch.service as service_module

    client, service, workflow, _ = running
    headers = login(client)
    original = service_module.atomic_json

    def fail_input(path, value):
        if path.name == "input.json":
            raise OSError("synthetic disk unavailable")
        return original(path, value)

    monkeypatch.setattr(service_module, "atomic_json", fail_input)
    failed_client = TestClient(client.app, raise_server_exceptions=False, client=("127.0.0.1", 50000))
    failed_client.cookies.update(client.cookies)
    result = failed_client.post(
        "/api/jobs",
        json={"url": "https://entry.synthetic.test/"},
        headers={**headers, "Idempotency-Key": "source-failure-key"},
    )
    assert result.status_code >= 400
    service._wake.set()
    time.sleep(0.2)
    assert not workflow.calls
    listed = client.get("/api/jobs").json()["jobs"]
    assert len(listed) == 1 and listed[0]["state"] == "interrupted"
    assert client.get(f"/api/jobs/{listed[0]['id']}").json()["reason_code"] == "input_persistence_failed"
    monkeypatch.setattr(service_module, "atomic_json", original)
    replay = client.post(
        "/api/jobs",
        json={"url": "https://entry.synthetic.test/"},
        headers={**headers, "Idempotency-Key": "source-failure-key"},
    )
    assert replay.status_code == 202
    assert replay.json()["id"] == listed[0]["id"]
    assert replay.json()["state"] == "interrupted"
    assert not workflow.calls


def test_concurrent_upload_is_rejected_while_decoder_runs(running, monkeypatch):
    import fxfetch.web.api as api_module
    from fxfetch.core.qr import QRResult

    client, _, _, _ = running
    headers = login(client)
    started, release = threading.Event(), threading.Event()

    def blocked_decoder(path, limits, *, thumbnail_path=None):
        started.set()
        assert release.wait(3)
        return QRResult("no_code")

    monkeypatch.setattr(api_module, "decode_image", blocked_decoder)

    def upload():
        return client.post("/api/qr-images", files={"file": ("synthetic.png", b"synthetic")}, headers=headers)

    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(upload)
        assert started.wait(3)
        try:
            result = upload()
            assert result.status_code == 429, result.text
        finally:
            release.set()
        assert first.result(timeout=5).status_code == 200


def test_service_root_lock_prevents_second_instance(running):
    from filelock import Timeout

    _, service, workflow, builder = running
    other = JobService(service.settings, workflow=workflow, builder=builder)
    with pytest.raises(Timeout):
        other.start()


@pytest.mark.parametrize("peer", ["192.168.99.8", "203.0.113.7", "::1"])
def test_non_allowed_peer_and_forwarded_headers_cannot_bypass(running, peer):
    client, _, workflow, builder = running
    untrusted = TestClient(client.app, client=(peer, 50000))
    for headers in (
        {},
        {"X-Forwarded-For": "127.0.0.1", "Forwarded": "for=127.0.0.1", "X-Real-IP": "127.0.0.1"},
    ):
        response = untrusted.get("/api/session", headers=headers)
        assert response.status_code == 403
    trusted = client.get("/api/session", headers={"X-Forwarded-For": "203.0.113.7"})
    assert trusted.status_code == 200
    assert not workflow.calls and not builder.calls


@pytest.mark.parametrize(
    "data",
    [b"plain text", b"%PDF-1.7 fake", b"PK\x03\x04 fake", b'<svg xmlns="http://www.w3.org/2000/svg"></svg>'],
)
def test_forged_image_upload_rejected_without_retained_file_or_record(running, data):
    client, service, workflow, builder = running
    headers = login(client)
    response = client.post(
        "/api/qr-images", files={"file": ("pretend.jpg", data, "image/jpeg")}, headers=headers
    )
    assert response.status_code == 415, response.text
    assert not list((service.store.root / "images").glob("*"))
    with service.store.connect() as database:
        assert database.execute("SELECT COUNT(*) FROM images").fetchone()[0] == 0
        assert database.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0] == 0
    assert not workflow.calls and not builder.calls


def test_heic_upload_private_clean_thumbnail_and_unchanged_original(running):
    from PIL import Image
    from pillow_heif import register_heif_opener

    register_heif_opener(thumbnails=False)
    client, service, workflow, builder = running
    headers = login(client)
    image = qrcode.make("https://heic.synthetic.test/app.apk?token=a%2Fb").convert("RGB")
    exif = Image.Exif()
    exif[270] = "synthetic metadata must not enter thumbnail"
    exif[274] = 6
    data = io.BytesIO()
    image.save(data, format="HEIF", exif=exif)
    original = data.getvalue()
    # The decoder must recognize the actual content despite misleading MIME/name.
    response = client.post(
        "/api/qr-images", files={"file": ("image.bin", original, "application/octet-stream")}, headers=headers
    )
    assert response.status_code == 200, response.text
    uploaded = response.json()
    assert uploaded["format"] == "HEIF"
    assert uploaded["status"] == "decoded"
    assert uploaded["sha256"] == hashlib.sha256(original).hexdigest()
    assert uploaded["thumbnail_available"]
    assert "thumbnail_path" not in uploaded
    owner = service.store.session(token_hash(client.cookies["fxfetch_session"]))["id"]
    record = service.store.image(owner, uploaded["id"])
    assert (service.store.root / record["path"]).read_bytes() == original
    url = uploaded["thumbnail_url"]
    thumbnail = client.get(url)
    assert thumbnail.status_code == 200
    assert thumbnail.headers["content-type"] == "image/jpeg"
    with Image.open(io.BytesIO(thumbnail.content)) as preview:
        assert max(preview.size) <= 640
        assert not preview.getexif()
        assert "icc_profile" not in preview.info
    anonymous = TestClient(client.app, client=("127.0.0.1", 50000))
    assert anonymous.get(url).status_code == 401
    login(client)
    assert client.get(url).status_code == 404
    assert not workflow.calls and not builder.calls


def test_clear_jobs_requires_auth_origin_and_csrf(running):
    client, _, _, _ = running
    assert client.delete("/api/jobs", headers=ORIGIN).status_code == 401
    headers = login(client)
    job = wait_job(client, submit(client, headers)["id"])
    assert client.delete("/api/jobs", headers=ORIGIN).status_code == 403
    assert client.delete("/api/jobs", headers={"X-CSRF-Token": headers["X-CSRF-Token"]}).status_code == 403
    assert client.get(f"/api/jobs/{job['id']}").status_code == 200
    assert client.delete("/api/jobs", headers=headers).json() == {"cleared": 1}
    assert client.delete("/api/jobs", headers=headers).json() == {"cleared": 0}


def test_clear_hides_files_and_old_idempotency_without_deleting_private_evidence(running):
    client, service, workflow, _ = running
    headers = login(client)
    workflow.downloaded = True
    job = wait_job(client, submit(client, headers)["id"])
    artifact = job["artifacts"][0]
    owner = service.store.session(token_hash(client.cookies["fxfetch_session"]))["id"]
    private = service.store.root / service.store.artifact(owner, job["id"], artifact["id"])["path"]
    assert client.delete("/api/jobs", headers=headers).status_code == 200
    for _ in range(3):
        assert client.get("/api/jobs").json() == {"jobs": []}
        assert client.get(f"/api/jobs/{job['id']}").status_code == 404
        assert client.get(f"/api/jobs/{job['id']}/artifacts/{artifact['id']}").status_code == 404
    replay = client.post(
        "/api/jobs",
        json={"url": "https://entry.synthetic.test/open?q=one#fragment"},
        headers={**headers, "Idempotency-Key": "synthetic-key-1"},
    )
    assert replay.status_code == 404
    assert private.is_file()
    assert len(workflow.calls) == 1


def test_clear_is_current_session_only(running):
    client, service, workflow, _ = running
    headers = login(client)
    first = wait_job(client, submit(client, headers)["id"])
    other = TestClient(client.app, client=("127.0.0.1", 50001))
    other_headers = login(other)
    second = wait_job(other, submit(other, other_headers)["id"])
    assert client.delete("/api/jobs", headers=headers).json() == {"cleared": 1}
    assert client.get("/api/jobs").json() == {"jobs": []}
    assert other.get("/api/jobs").json()["jobs"][0]["id"] == second["id"]
    assert other.get(f"/api/jobs/{second['id']}").status_code == 200
    assert other.get(f"/api/jobs/{first['id']}").status_code == 404
    assert len(workflow.calls) == 2


def test_clear_cancels_running_and_queued_collections_and_builds(running):
    client, service, workflow, builder = running
    headers = login(client)
    parent = wait_job(client, submit(client, headers, key="clear-parent")["id"])
    build_url = f"/api/jobs/{parent['id']}/web-apk-builds"
    payload = {"candidate_id": parent["web_candidates"][0]["id"]}
    builder.release.clear()
    active_build = client.post(
        build_url, json=payload, headers={**headers, "Idempotency-Key": "clear-active-build"}
    ).json()
    assert builder.started.wait(3)
    queued_build = client.post(
        build_url, json=payload, headers={**headers, "Idempotency-Key": "clear-queued-build"}
    ).json()
    workflow.started.clear()
    workflow.release.clear()
    active_job = submit(client, headers, key="clear-active-job")
    assert workflow.started.wait(3)
    queued_job = submit(client, headers, key="clear-queued-job")
    assert client.delete("/api/jobs", headers=headers).json() == {"cleared": 3}
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with service.store.connect() as database:
            states = [
                row[0]
                for row in database.execute(
                    "SELECT state FROM jobs WHERE id IN (?,?)", (active_job["id"], queued_job["id"])
                )
            ]
            states += [
                row[0]
                for row in database.execute(
                    "SELECT state FROM builds WHERE id IN (?,?)", (active_build["id"], queued_build["id"])
                )
            ]
        if states == ["cancelled"] * 4:
            break
        time.sleep(0.02)
    assert states == ["cancelled"] * 4
    for identifier in (active_build["id"], queued_build["id"]):
        assert client.get(f"{build_url}/{identifier}").status_code == 404
    for _ in range(3):
        assert client.get("/api/jobs").json() == {"jobs": []}
    assert len(workflow.calls) == 2 and len(builder.calls) == 1


def test_removed_demo_endpoints_are_not_exposed(running):
    client, _, _, _ = running
    login(client)
    assert client.get("/api/demo").status_code == 404
    assert client.get("/api/demo/file").status_code == 404


def test_clear_releases_image_quota_preserves_other_session_images_and_job_source(running):
    client, service, _, _ = running
    headers = login(client)
    image = io.BytesIO()
    qrcode.make("https://qr.synthetic.test/preserved").save(image, format="PNG")
    first = client.post(
        "/api/qr-images", files={"file": ("first.png", image.getvalue())}, headers=headers
    ).json()
    submitted = client.post(
        "/api/jobs",
        json={"image_id": first["id"], "candidate_id": "qr-1"},
        headers={**headers, "Idempotency-Key": "clear-image-source"},
    )
    job = wait_job(client, submitted.json()["id"])
    source = service.store.root / "jobs" / job["id"] / "source" / "image.original"
    assert source.is_file()
    owner = service.store.session(token_hash(client.cookies["fxfetch_session"]))["id"]
    other = TestClient(client.app, client=("127.0.0.1", 50001))
    other_headers = login(other)
    second = other.post(
        "/api/qr-images", files={"file": ("second.png", image.getvalue())}, headers=other_headers
    ).json()
    other_owner = service.store.session(token_hash(other.cookies["fxfetch_session"]))["id"]
    other_path = service.store.root / service.store.image(other_owner, second["id"])["path"]
    for index in range(service.settings.limits.max_pending_images):
        path = service.store.root / "images" / f"pending-{index}.image"
        path.write_bytes(b"synthetic unused image")
        service.store.add_image(
            owner,
            str(path.relative_to(service.store.root)),
            {},
            3600,
            service.settings.limits.max_pending_images,
        )
    assert client.delete("/api/jobs", headers=headers).status_code == 200
    assert source.is_file() and other_path.is_file()
    assert other.get(second["thumbnail_url"]).status_code == 200
    with service.store.connect() as database:
        assert database.execute("SELECT COUNT(*) FROM images WHERE owner=?", (owner,)).fetchone()[0] == 0
        assert (
            database.execute("SELECT COUNT(*) FROM images WHERE owner=?", (other_owner,)).fetchone()[0] == 1
        )
    assert not list((service.store.root / "images").glob("pending-*"))
    uploaded = client.post(
        "/api/qr-images", files={"file": ("after-clear.png", image.getvalue())}, headers=headers
    )
    assert uploaded.status_code == 200, uploaded.text
