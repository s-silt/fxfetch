"""DNS rejection evidence survives sealing without exposing raw records in progress."""

import json
import zipfile
from pathlib import Path

import pytest

from fxfetch.core.task_evidence import finalize_package
from fxfetch.core.task_evidence_io import verify_task_archive
from fxfetch.core.task_evidence_recorder import TaskEvidenceRecorder
from fxfetch.store import Store


def dns_record() -> dict:
    return {
        "provider": "dnspod", "query_type": "AAAA", "host": "entry.synthetic.test",
        "status": "rejected", "reason_code": "dns_unsafe_answer", "rcode": 0,
        "addresses": ["::1"],
        "answers": [{"name": "entry.synthetic.test", "type": 28, "data": "::1",
                     "classification": "non_public", "selected": True}],
    }


@pytest.mark.parametrize("collector", ["http", "gateway"])
def test_dns_rejection_is_preserved_in_verified_task_zip(tmp_path: Path, collector: str):
    recorder = TaskEvidenceRecorder(tmp_path)
    recorder.set_context("http", "direct-1")
    event = {"event": "dns_resolution_observed", "url": "http://entry.synthetic.test/",
             "dns_record": dns_record()}
    if collector == "http":
        recorder.observe_transport(event)
    else:
        recorder.observe_progress(event)
    recorder.close()
    result = {"outcome": "failed", "reason_code": "dns_unsafe_answer",
              "coverage": "partial", "artifacts": [], "attempts": []}
    metadata = finalize_package(
        tmp_path, job_id="synthetic-dns", entry_url="http://entry.synthetic.test/",
        terminal_result=result, observation_path=recorder.path, max_bytes=1024 * 1024,
    )
    assert metadata["state"] == "ready"
    archive = tmp_path / "data-package" / metadata["filename"]
    verify_task_archive(archive, max_bytes=1024 * 1024)
    with zipfile.ZipFile(archive) as bundle:
        rows = [json.loads(line) for line in bundle.read("observations.jsonl").splitlines()]
    observed = next(row for row in rows if row["fields"].get("dns_record"))
    assert observed["fields"]["dns_record"] == dns_record()
    assert not any(row["kind"] == "response_observed" for row in rows)
    assert result["outcome"] == "failed"


@pytest.mark.parametrize("nested", [True, False])
def test_public_dns_progress_contains_only_safe_summary(tmp_path: Path, nested: bool):
    store = Store(tmp_path)
    job, _ = store.create_job("owner", "dns-progress", {"entry_url": "http://entry.synthetic.test/"}, 5)
    record = dns_record()
    event = {"event": "dns_resolution_observed", "label": "raw diagnostic must stay private",
             "status": 0, "dns_record": record} if nested else {"event": "dns_resolution_failed", **record}
    store.progress(job["id"], event)
    progress = store.get_job("owner", job["id"])["progress"]
    item = progress["events"][-1]
    assert item["provider"] == "dnspod" and item["query_type"] == "AAAA"
    assert item["reason_code"] == "dns_unsafe_answer"
    assert set(item) == {"event", "provider", "query_type", "reason_code", "seq", "at"}
    assert "::1" not in json.dumps(progress)
    assert "answers" not in json.dumps(progress)


def test_gateway_transport_phase_is_not_a_public_address_rejection(tmp_path: Path):
    store = Store(tmp_path)
    job, _ = store.create_job("owner", "gateway-progress", {"entry_url": "http://entry.synthetic.test/"}, 5)
    store.progress(job["id"], {"event": "browser_transport_failed",
                               "connection_phase": "established", "reason_code": "browser_transport_failed"})
    event = store.get_job("owner", job["id"])["progress"]["events"][-1]
    assert event["event"] == "browser_transport_failed"
    assert event["connection_phase"] == "established"


@pytest.mark.parametrize("reason", [
    "dns_nxdomain", "dns_no_addresses", "dns_invalid_response", "dns_diagnostics_unavailable",
    "task_timeout", "chain_timeout", "arbitrary-provider-text",
])
def test_dns_fixed_reasons_are_preserved_but_arbitrary_text_is_not(tmp_path: Path, reason: str):
    store = Store(tmp_path)
    job, _ = store.create_job("owner", "dns-reason", {"entry_url": "http://entry.synthetic.test/"}, 5)
    store.progress(job["id"], {"event": "dns_resolution_failed", "reason_code": reason})
    event = store.get_job("owner", job["id"])["progress"]["events"][-1]
    if reason == "arbitrary-provider-text":
        assert "reason_code" not in event
    else:
        assert event["reason_code"] == reason
