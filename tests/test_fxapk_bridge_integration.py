"""Opt-in real CLI interoperability; synthetic input and blocked socket audit events."""

from __future__ import annotations

import hashlib
import io
import json
import os
import time
import zipfile

import pytest
from analysis_browser_fixtures import browser_archive
from analysis_fixtures import analysis_archive
from fastapi.testclient import TestClient
from test_analysis_service import seed_job

from fxfetch.config import Settings
from fxfetch.core.analysis_runner import analyze_archive
from fxfetch.security import password_hash, token_hash
from fxfetch.service import JobService
from fxfetch.web.api import create_app

pytestmark = pytest.mark.skipif(not os.environ.get("FXAPK_EXECUTABLE"), reason="FXAPK_EXECUTABLE not configured")


@pytest.fixture
def network_audit(tmp_path, monkeypatch):
    guard = tmp_path / "network-guard"
    guard.mkdir()
    marker = tmp_path / "network-attempted"
    ready = tmp_path / "network-guard-loaded"
    (guard / "sitecustomize.py").write_text(
        "import os, sys\n"
        "with open(os.environ['FXAPK_NETWORK_GUARD_READY'], 'w') as f: f.write('ready')\n"
        "def guard(event, args):\n"
        "    if event in {'socket.connect', 'socket.getaddrinfo', 'socket.gethostbyname', 'socket.gethostbyaddr', 'socket.sendto'}:\n"
        "        with open(os.environ['FXAPK_NETWORK_TRIPWIRE'], 'a') as f: f.write(event + '\\n')\n"
        "        raise RuntimeError('offline integration network forbidden')\n"
        "sys.addaudithook(guard)\n", encoding="utf-8",
    )
    monkeypatch.setenv("PYTHONPATH", str(guard) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    monkeypatch.setenv("FXAPK_NETWORK_TRIPWIRE", str(marker))
    monkeypatch.setenv("FXAPK_NETWORK_GUARD_READY", str(ready))
    monkeypatch.setenv("PYTHONUTF8", "1")
    yield
    assert ready.read_text() == "ready", "subprocess network audit hook did not load"
    assert not marker.exists(), marker.read_text() if marker.exists() else ""


def test_real_fxapk_cli_is_offline_and_retains_material_and_redirect_refs(tmp_path, network_audit):
    archive = analysis_archive(tmp_path / "source")
    output = tmp_path / "analysis"
    receipt = analyze_archive(archive, output, max_bytes=16 * 1024 * 1024,
                              executable=os.environ["FXAPK_EXECUTABLE"], timeout=180)
    assert receipt["state"] == "completed", receipt["analysis"]
    report = json.loads((output / "report" / "input.json").read_bytes())
    meta = report["meta"]
    assert meta["online"] is False and not meta["web_evidence"]["load_errors"]
    records = meta["web_har_records"]
    assert len(records) == 2
    assert records[0]["redirect_url"] == "https://content.example.test/page"
    assert records[0]["status"] == 302 and records[1]["status"] == 200
    assert records[0]["entry_ref"] == receipt["har"]["entries"][0]["analysis_location"]
    values = {endpoint["value"] for endpoint in report["endpoints"]}
    assert "https://api.example.test/v1" in values
    assert "https://unvisited.example.test/metadata-only" not in values
    assert all(not record["target_app_attribution_verified"] for record in records)


def test_real_analysis_api_download_preserves_source_and_session_boundary(tmp_path, network_audit):
    password = "synthetic-linux-analysis-password"
    settings = Settings(
        tmp_path / "service", password_hash(password), allowed_hosts=("testserver",),
        fxapk_executable=os.environ["FXAPK_EXECUTABLE"],
    )
    service = JobService(settings)
    app = create_app(settings, service=service)
    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        origin = {"Origin": "http://testserver"}
        login = client.post("/api/login", json={"password": password}, headers=origin)
        assert login.status_code == 200
        headers = {**origin, "X-CSRF-Token": login.json()["csrf_token"]}
        owner = service.store.session(token_hash(client.cookies["fxfetch_session"]))["id"]
        job = seed_job(service, tmp_path, owner, "real-api")
        endpoint = f"/api/jobs/{job['id']}"
        source = client.get(f"{endpoint}/data-package")
        assert source.status_code == 200
        (tmp_path / "api-source.zip").write_bytes(source.content)
        created = client.post(
            f"{endpoint}/analyses", json={},
            headers={**headers, "Idempotency-Key": "real-api-analysis"},
        )
        assert created.status_code == 202
        status_url = f"{endpoint}/analyses/{created.json()['id']}"
        deadline = time.monotonic() + 60
        while True:
            response = client.get(status_url)
            assert response.status_code == 200
            status = response.json()
            if status["state"] not in {"queued", "running"} or time.monotonic() >= deadline:
                break
            time.sleep(0.05)
        assert status["state"] == "completed", status
        assert status["report_ready"]
        report = client.get(f"{status_url}/report.zip")
        assert report.status_code == 200
        assert set(report.headers["cache-control"].split(", ")) == {"no-store"}
        assert hashlib.sha256(report.content).hexdigest() == status["report_sha256"]
        assert len(report.content) == status["report_size"]
        (tmp_path / "api-report.zip").write_bytes(report.content)
        with zipfile.ZipFile(io.BytesIO(report.content)) as bundle:
            assert bundle.namelist() == ["analysis.json", "report/input.json"]
            receipt = json.loads(bundle.read("analysis.json"))
            native = json.loads(bundle.read("report/input.json"))
        assert receipt["source_archive"]["sha256"] == hashlib.sha256(source.content).hexdigest()
        assert receipt["coverage"] == "partial"
        assert "command" not in receipt["analysis"] and "executable" not in receipt["analysis"]
        assert native["meta"]["online"] is False
        assert not native["meta"]["web_evidence"]["load_errors"]
        assert "https://api.example.test/v1" in {item["value"] for item in native["endpoints"]}
        assert client.get(f"{endpoint}/data-package").content == source.content
        assert client.get(endpoint).json()["outcome"] == "blocked"
        client.cookies.clear()
        other_login = client.post("/api/login", json={"password": password}, headers=origin)
        assert other_login.status_code == 200
        assert client.get(status_url).status_code == 404
        assert client.get(f"{status_url}/report.zip").status_code == 404


@pytest.mark.parametrize("scenario", ["ordinary", "blocked", "package"])
def test_mixed_browser_materials_keep_evidence_semantics(tmp_path, network_audit, scenario):
    archive = browser_archive(tmp_path / "source", scenario=scenario)
    output = tmp_path / "analysis"
    receipt = analyze_archive(archive, output, max_bytes=16 * 1024 * 1024,
                              executable=os.environ["FXAPK_EXECUTABLE"], timeout=180)
    assert receipt["state"] == "completed", receipt["analysis"]
    report = json.loads((output / "report/input.json").read_bytes())
    records = {row["request_url"]: row for row in report["meta"]["web_har_records"]}
    assert "https://metrics.example.test/collect" in records
    assert records["https://failed.example.test/no-response"]["response_recorded"] is False
    for url in ("https://candidate-only.example.test/", "https://unassociated.example.test/",
                "https://denied.example.test/", "https://static-next.example.test/landing"):
        assert url not in records
    sources = {item["source"]["path"]: item for item in receipt["materials"]}
    script = sources["script.body"]
    assert script["analysis_path"].endswith(".js") and script["type_basis"] == "response_media_type"
    chains = report["meta"]["web_redirect_chain"]
    assert any(chain["location"] == script["analysis_location_prefix"] and any(
        hop["target"] == "https://static-next.example.test/landing" for hop in chain["hops"]
    ) for chain in chains)
    values = {endpoint["value"] for endpoint in report["endpoints"]}
    assert "https://service.example.test/v2" in values
    assert "https://candidate-only.example.test/" not in values
    assert sources["partial.body"]["source"]["complete"] is False
    assert sources["rendered.body"]["type_basis"] == "rendered_dom"
    assert sources["rendered.body"]["source"]["request_association"] == "unknown"
    assert receipt["source_manifest"]["package_result"]["outcome"] == {
        "ordinary": "not_found", "blocked": "blocked", "package": "downloaded"}[scenario]
    assert receipt["coverage"] == "partial" and not report["meta"]["web_evidence"]["load_errors"]
    assert all(not row["target_app_attribution_verified"] for row in records.values())
    with zipfile.ZipFile(output / "source.zip") as bundle:
        rows = {row["seq"]: row for row in map(json.loads, bundle.read("observations.jsonl").splitlines())}
        for item in receipt["materials"]:
            raw = (output / item["analysis_path"]).read_bytes()
            assert raw == bundle.read(item["source"]["path"])
            assert hashlib.sha256(raw).hexdigest() == item["source"]["sha256"]
            for observation in item["provenance"]["observations"]:
                original = rows[observation["seq"]]
                assert original["fields"]["path"] == item["source"]["path"]
                assert original["kind"] == observation["kind"]
        if scenario == "package":
            assert receipt["source_manifest"]["external_packages"]
            assert "package.body" not in bundle.namelist() and "package.body" not in sources
            assert not receipt["external_packages_verified"]
