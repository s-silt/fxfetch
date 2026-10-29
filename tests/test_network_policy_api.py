"""Synthetic service/API integration for the direct-first policy; no target networking."""

import json
import time
from threading import Event

from fastapi.testclient import TestClient

from fxfetch.config import Settings
from fxfetch.core.network import AcquisitionPolicy
from fxfetch.core.proxy import LocalConnectProxy
from fxfetch.core.workflow import WorkflowResult
from fxfetch.security import password_hash
from fxfetch.service import JobService
from fxfetch.web.api import create_app


def test_api_retains_direct_failure_proxy_attempt_and_events(tmp_path):
    calls = []

    def factory(limits, proxy):
        calls.append(proxy)

        class SyntheticCollector:
            def run(self, url, output_dir, cancel, on_event=None):
                return WorkflowResult("failed", "proxy_failed" if proxy else "dns_failed", "partial")

        return SyntheticCollector()

    settings = Settings(
        tmp_path,
        password_hash("synthetic-policy-password"),
        allowed_hosts=("testserver",),
        proxy_host="127.0.0.1",
    )
    policy = AcquisitionPolicy(
        settings.limits, LocalConnectProxy("127.0.0.1", 7890), collector_factory=factory
    )
    service = JobService(settings, workflow=policy)
    with TestClient(create_app(settings, service=service), client=("127.0.0.1", 50000)) as client:
        origin = {"Origin": "http://testserver"}
        login = client.post(
            "/api/login", json={"password": "synthetic-policy-password"}, headers=origin
        ).json()
        headers = {**origin, "X-CSRF-Token": login["csrf_token"], "Idempotency-Key": "network-policy-api"}
        cap = client.get("/api/capabilities").json()["network_policy"]
        assert cap["default_mode"] == "direct" and cap["proxy_fallback_configured"]
        job = client.post(
            "/api/jobs", json={"url": "https://entry.synthetic.invalid/"}, headers=headers
        ).json()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            job = client.get("/api/jobs/" + job["id"]).json()
            if job["state"] == "completed":
                break
            Event().wait(0.01)
        assert job["state"] == "completed"
        assert job["result"]["reason_code"] == "proxy_failed"
        attempts = job["result"]["network_attempts"]
        assert [row["network_mode"] for row in attempts] == ["direct", "proxy"]
        assert attempts[0]["result"]["reason_code"] == "dns_failed"
        events = job["progress"]["events"]
        assert any(
            row["event"] == "network_fallback" and row["from_mode"] == "direct" and row["to_mode"] == "proxy"
            for row in events
        )
        assert any(
            row.get("network_mode") == "proxy" and row.get("cookies_inherited") is False for row in events
        )
        evidence = json.loads((tmp_path / "jobs" / job["id"] / "evidence.json").read_text(encoding="utf-8"))
        private_attempts = evidence["summary"]["network_attempts"]
        assert len(private_attempts) == len(attempts)
        for private, public in zip(private_attempts, attempts, strict=True):
            assert private["attempt_id"] == public["attempt_id"]
            assert private["result"]["reason_code"] == public["result"]["reason_code"]
            assert "bodies" not in public["result"] and "hops" not in public["result"]
    assert calls == [None, LocalConnectProxy("127.0.0.1", 7890)]
