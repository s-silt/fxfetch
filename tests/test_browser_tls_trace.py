"""Passive trace parser/lifecycle checks, with no browser or network."""

import asyncio
import base64
import json
import time
from threading import Event

import pytest
from test_browser_tls_evidence import FakeMux, chain, collector, response

from fxfetch.core.browser_tls_trace import SOURCE, BrowserTLSTrace
from fxfetch.core.task_evidence import finalize_package
from fxfetch.core.task_evidence_recorder import TaskEvidenceRecorder
from fxfetch.core.task_evidence_verify import verify_task_archive

__all__ = ["chain"]


def certificate_event(chain, *, pid=123, source="0x1", old=False, timestamp=1):
    pems = ["-----BEGIN CERTIFICATE-----\n" + base64.b64encode(der).decode() +
            "\n-----END CERTIFICATE-----\n" for der in chain]
    return {"cat": "netlog", "name": "SSL_CERTIFICATES_RECEIVED", "pid": pid, "ts": timestamp,
            **({"id": source} if old else {"id2": {"local": source}}),
            "args": {"source_type": "SOCKET", "params": {"certificates": pems,
                                                           "ignored_secret": "must-not-export"}}}


def trace_fixture(events, *, start_error=False):
    calls, gaps, preserved = [], [], []
    trace = None

    async def send(session, method, params):
        assert session is None
        calls.append((method, params))
        if method == "Tracing.start":
            if start_error:
                raise RuntimeError("already tracing with secret")
            assert params["traceConfig"]["includedCategories"] == ["netlog"]
            assert params["traceConfig"]["traceBufferSizeInKb"] == 4096
        elif method == "Tracing.end":
            trace.event("Tracing.tracingComplete", {"stream": "owned-stream"})
        elif method == "IO.read":
            return {"data": json.dumps({"traceEvents": events}), "eof": True}
        else:
            assert method == "IO.close" and params == {"handle": "owned-stream"}
        return {}

    trace = BrowserTLSTrace(deadline=time.monotonic() + 10, cancel=Event(), send=send,
                            emit=lambda kind, fields: gaps.append({"kind": kind, **fields}),
                            preserve=lambda *args: preserved.append(args))
    trace.expected = True
    return trace, calls, gaps, preserved


def run_trace(trace):
    async def exercise():
        await trace.start()
        await trace.finish(time.monotonic() + 5)
        await trace.finish(time.monotonic() + 5)
    asyncio.run(exercise())


def test_original_der_145_and_156_id_and_pid_scope_are_preserved(chain):
    event = certificate_event(chain)
    trace, calls, gaps, saved = trace_fixture([
        event, event, certificate_event(chain, old=True, pid=124),
        {"cat": "netlog", "name": "SSL_CERTIFICATES_RECEIVED_OTHER", "args": {"secret": "no"}},
    ])
    run_trace(trace)
    assert not gaps and len(saved) == 2
    assert [item[0]["netlog_pid"] for item in saved] == [123, 124]
    assert all(item[1] == list(enumerate(chain)) for item in saved)
    for fields, _, length, reasons in saved:
        assert fields["capture_source"] == SOURCE and fields["source_url"] == ""
        assert fields["association"] == "browser_network_event" and fields["request_association"] == "unknown"
        assert not any(key in fields for key in ("url", "request_ref", "session_id", "origin"))
        assert length == 3 and reasons == [] and "secret" not in json.dumps(fields)
    assert [method for method, _ in calls] == ["Tracing.start", "Tracing.end", "IO.read", "IO.close"]


def test_existing_foreign_trace_is_never_ended():
    trace, calls, gaps, saved = trace_fixture([], start_error=True)
    run_trace(trace)
    assert [method for method, _ in calls] == ["Tracing.start"] and not saved
    assert gaps[0]["reason_code"] == "browser_tls_trace_unavailable"
    assert "secret" not in json.dumps(gaps)


def test_valid_members_survive_invalid_pem_and_chain_limit(chain):
    event = certificate_event(chain * 4)
    event["args"]["params"]["certificates"][1] = "bad PEM"
    trace, _, _, saved = trace_fixture([event])
    run_trace(trace)
    assert [index for index, _ in saved[0][1]] == [0, 2, 3, 4, 5, 6, 7]
    assert saved[0][2] == 12
    assert set(saved[0][3]) == {"browser_tls_chain_limit", "browser_tls_certificate_invalid"}


@pytest.mark.parametrize("field,value", [("pid", True), ("ts", float("inf")), ("id2", {"global": "1"})])
def test_invalid_identity_is_never_exported(chain, field, value):
    event = certificate_event(chain)
    event[field] = value
    trace, _, gaps, saved = trace_fixture([event])
    run_trace(trace)
    assert not saved and any(gap["reason_code"] == "browser_tls_trace_event_invalid" for gap in gaps)


def test_cancel_only_ends_own_trace_and_closes_stream_without_read():
    trace, calls, gaps, saved = trace_fixture([])
    async def exercise():
        await trace.start()
        trace.cancel.set()
        await trace.finish(time.monotonic() + 5)
    asyncio.run(exercise())
    assert [method for method, _ in calls] == ["Tracing.start", "Tracing.end", "IO.close"]
    assert not saved and gaps[0]["reason_code"] == "browser_tls_trace_budget"


def test_raw_trace_byte_cap_and_http_only_empty_do_not_claim_missing_tls(monkeypatch):
    monkeypatch.setattr("fxfetch.core.browser_tls_trace.MAX_TRACE_BYTES", 1)
    trace, calls, gaps, saved = trace_fixture([])
    run_trace(trace)
    assert not saved and gaps[0]["reason_code"] == "browser_tls_trace_size_limit"
    assert calls[-1][0] == "IO.close"
    trace, _, gaps, _ = trace_fixture([])
    trace.expected = False
    run_trace(trace)
    assert not gaps


def test_network_originals_suppress_only_empty_origin_gap_and_share_disk_budget(tmp_path, chain):
    capture, events, charged = collector(tmp_path, FakeMux({"tableNames": []}, {"tableNames": []}))
    capture.observe_response(response())
    trace, _, _, _ = trace_fixture([certificate_event(chain)])
    trace.preserve = capture.preserve_network_event
    run_trace(trace)
    asyncio.run(capture.finish())
    saved = [event for event in events if event["kind"] == "tls_certificate_saved"]
    assert len(saved) == 3 and all(event["chain_complete"] for event in saved)
    assert sum(charged) == sum(map(len, chain))
    assert all((tmp_path / event["path"]).read_bytes() == chain[event["chain_index"]] for event in saved)
    assert not [event for event in events if event["kind"] == "gap"]
    assert any(event["kind"] == "tls_certificate_origin_query_unavailable" for event in events)
    assert {path.suffix for path in tmp_path.rglob("*") if path.is_file()} == {".der"}


def test_trace_memory_and_event_caps_preserve_bounded_valid_subset(chain, monkeypatch):
    monkeypatch.setattr("fxfetch.core.browser_tls_trace.MAX_CERTIFICATE_TOTAL", len(chain[0]) + 5)
    monkeypatch.setattr("fxfetch.core.browser_tls_trace.MAX_TLS_EVENTS", 1)
    trace, _, gaps, saved = trace_fixture([certificate_event(chain), certificate_event(chain, pid=456)])
    run_trace(trace)
    assert len(saved) == 1 and saved[0][1] == [(0, chain[0])]
    assert "browser_tls_certificate_limit" in saved[0][3]
    assert any(gap["reason_code"] == "browser_tls_trace_event_limit" for gap in gaps)


@pytest.mark.parametrize("mode", ["invalid", "budget"])
def test_zero_retained_members_remain_gap_and_package_still_seals(tmp_path, chain, monkeypatch, mode):
    recorder = TaskEvidenceRecorder(tmp_path)
    capture, events, _ = collector(tmp_path, FakeMux())
    original_emit = capture.emit

    def emit(kind, fields):
        original_emit(kind, fields)
        recorder.observe_transport({"event": kind, **fields})

    capture.emit = emit
    event = certificate_event(chain)
    if mode == "invalid":
        event["args"]["params"]["certificates"] = ["invalid"]
    else:
        monkeypatch.setattr("fxfetch.core.browser_tls_evidence.MAX_CERTIFICATE_TOTAL", 0)
    trace, _, _, _ = trace_fixture([event])
    trace.preserve = capture.preserve_network_event
    run_trace(trace)
    asyncio.run(capture.finish())
    recorder.close()
    assert [event["kind"] for event in events] == ["gap"]
    metadata = finalize_package(
        tmp_path, job_id="synthetic-no-cert", entry_url="https://synthetic.test/",
        terminal_result={"outcome": "failed", "reason_code": "synthetic", "coverage": "partial"},
        observation_path=recorder.path, max_bytes=16 * 1024 * 1024,
    )
    assert metadata["state"] == "ready", metadata
    manifest, _ = verify_task_archive(tmp_path / "data-package" / metadata["filename"], max_bytes=16 * 1024 * 1024)
    assert not manifest["attachments"]


def test_trace_data_loss_is_explicit_and_does_not_erase_valid_der(chain):
    trace, _, gaps, saved = trace_fixture([certificate_event(chain)])
    trace.data_loss = True
    original_event = trace.event
    trace.event = lambda method, data: original_event(method, {**data, "dataLossOccurred": True})
    run_trace(trace)
    assert saved and any(gap["reason_code"] == "browser_tls_trace_data_loss" for gap in gaps)


def test_capture_gap_not_hidden_by_other_network_event_originals(tmp_path, chain):
    capture, events, _ = collector(tmp_path, FakeMux({"tableNames": ["bad DER"]}))
    capture.observe_response(response())
    trace, _, _, _ = trace_fixture([certificate_event(chain)])
    trace.preserve = capture.preserve_network_event
    run_trace(trace)
    asyncio.run(capture.finish())
    assert any(event["kind"] == "gap" and event["reason_code"] == "browser_tls_certificate_invalid" for event in events)


def test_origin_timeout_cannot_erase_already_observed_network_originals(tmp_path, chain):
    mux = FakeMux()
    mux.blocked = True
    capture, events, _ = collector(tmp_path, mux)
    capture.observe_response(response())
    trace, _, _, _ = trace_fixture([certificate_event(chain)])
    trace.preserve = capture.preserve_network_event
    run_trace(trace)
    asyncio.run(capture.finish(time.monotonic() + .15))
    saved = [event for event in events if event["kind"] == "tls_certificate_saved"]
    assert len(saved) == 3 and all(event["chain_complete"] for event in saved)
    assert len(mux.calls) == 1
