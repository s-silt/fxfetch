from __future__ import annotations

import secrets
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient
from test_analysis_service import completed_runner, seed_job

from fxfetch.config import Settings
from fxfetch.security import password_hash, token_hash
from fxfetch.service import JobService
from fxfetch.web.api import create_app

PASSWORD = "synthetic-analysis-password"
ORIGIN = {"Origin": "http://testserver"}


def test_analysis_api_capability_routes_and_private_report(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("fxfetch.analysis_service.run_limited", completed_runner)
    settings = Settings(
        tmp_path,
        password_hash(PASSWORD),
        allowed_hosts=("testserver",),
        fxapk_executable=sys.executable,
    )
    service = JobService(settings)
    app = create_app(settings, service=service)
    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        login = client.post("/api/login", json={"password": PASSWORD}, headers=ORIGIN)
        headers = {**ORIGIN, "X-CSRF-Token": login.json()["csrf_token"]}
        owner = service.store.session(token_hash(client.cookies["fxfetch_session"]))["id"]
        job = seed_job(service, tmp_path, owner, "api")
        capability = client.get("/api/capabilities").json()["web_analysis"]
        assert capability == {
            "enabled": True,
            "reason_code": None,
            "online": False,
            "timeout_seconds": 360.0,
            "queue_timeout_seconds": 600.0,
        }
        endpoint = f"/api/jobs/{job['id']}/analyses"
        missing_key = client.post(endpoint, headers=headers)
        assert missing_key.status_code == 400
        rejected = client.post(
            endpoint,
            json={"executable": "caller-controlled"},
            headers={**headers, "Idempotency-Key": "bad-body"},
        )
        assert rejected.status_code == 422
        created = client.post(
            endpoint, headers={**headers, "Idempotency-Key": "analysis-api"}
        )
        assert created.status_code == 202
        value = created.json()
        assert set(value).isdisjoint({"output_path", "report_path", "command", "executable"})
        replay = client.post(
            endpoint, headers={**headers, "Idempotency-Key": "analysis-api"}
        )
        assert replay.json()["id"] == value["id"]
        deadline = time.monotonic() + 5
        status_endpoint = f"{endpoint}/{value['id']}"
        while time.monotonic() < deadline:
            status = client.get(status_endpoint)
            if status.json()["state"] == "completed":
                break
            time.sleep(0.01)
        assert status.json()["report_ready"] is True
        detail = client.get(f"/api/jobs/{job['id']}").json()
        assert detail["analyses"][0]["id"] == value["id"]
        listed = client.get("/api/jobs").json()["jobs"][0]
        assert listed["active_analyses"] == 0
        report = client.get(f"{status_endpoint}/report.zip")
        assert report.status_code == 200
        assert set(report.headers["cache-control"].split(", ")) == {"no-store"}
        assert f"analysis-{value['id']}.zip" in report.headers["content-disposition"]
        other_token = secrets.token_urlsafe(32)
        service.store.new_session(token_hash(other_token), settings.session_seconds)
        other_headers = {**ORIGIN, "Cookie": f"fxfetch_session={other_token}"}
        assert client.get(status_endpoint, headers=other_headers).status_code == 404
        assert client.get(f"{status_endpoint}/report.zip", headers=other_headers).status_code == 404


def test_analysis_api_disabled_and_cancel(tmp_path: Path):
    settings = Settings(tmp_path, password_hash(PASSWORD), allowed_hosts=("testserver",))
    service = JobService(settings)
    app = create_app(settings, service=service)
    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        login = client.post("/api/login", json={"password": PASSWORD}, headers=ORIGIN)
        headers = {**ORIGIN, "X-CSRF-Token": login.json()["csrf_token"]}
        owner = service.store.session(token_hash(client.cookies["fxfetch_session"]))["id"]
        job = seed_job(service, tmp_path, owner, "disabled-api")
        response = client.post(
            f"/api/jobs/{job['id']}/analyses",
            headers={**headers, "Idempotency-Key": "disabled"},
        )
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "analysis_unavailable"
