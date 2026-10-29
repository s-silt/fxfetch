from dataclasses import asdict
from threading import Event

import pytest

from fxfetch.core.limits import Limits
from fxfetch.core.network import AcquisitionPolicy
from fxfetch.core.proxy import LocalConnectProxy
from fxfetch.core.workflow import WorkflowResult

URL = "https://entry.synthetic.invalid/"
PROXY = LocalConnectProxy("127.0.0.1", 7890)


def factory_for(results, observed, *, events=(), clock=None, cancel_after=False):
    def factory(limits, proxy):
        index = len(observed)
        observed.append({"limits": limits, "proxy": proxy})

        class SyntheticCollector:
            def run(self, url, output_dir, cancel, on_event=None):
                observed[index]["output_dir"] = output_dir
                output_dir.mkdir(parents=True, exist_ok=True)
                (output_dir / "retained.txt").write_text("synthetic receipt")
                for event in events:
                    if on_event:
                        on_event(event)
                if clock is not None:
                    clock[0] += 3
                if cancel_after:
                    cancel.set()
                return results[index]

        return SyntheticCollector()

    return factory


def test_direct_first_even_when_proxy_configured(tmp_path):
    calls = []
    result = AcquisitionPolicy(
        proxy=PROXY,
        collector_factory=factory_for([WorkflowResult("downloaded", "package_verified", "complete")], calls),
    ).run(URL, tmp_path, Event())
    assert [c["proxy"] for c in calls] == [None]
    assert result.network_mode == "direct"
    assert asdict(result)["network_attempts"][0]["result"]["outcome"] == "downloaded"


def test_initial_failure_one_fresh_proxy_attempt_retains_original(tmp_path, monkeypatch):
    import fxfetch.core.network as network

    clock = [100.0]
    monkeypatch.setattr(network.time, "monotonic", lambda: clock[0])
    calls = []
    events = []
    result = AcquisitionPolicy(
        Limits(chain_timeout=10),
        PROXY,
        collector_factory=factory_for(
            [
                WorkflowResult("failed", "dns_failed", "partial"),
                WorkflowResult("downloaded", "package_verified", "complete"),
            ],
            calls,
            clock=clock,
        ),
    ).run(URL, tmp_path, Event(), events.append)
    assert [c["proxy"] for c in calls] == [None, PROXY]
    assert calls[1]["limits"].chain_timeout == 7
    assert calls[1]["limits"].max_requests == 299
    assert calls[1]["limits"].max_task_bytes < calls[0]["limits"].max_task_bytes
    assert calls[0]["output_dir"] != calls[1]["output_dir"]
    assert result.outcome == "downloaded" and result.network_mode == "proxy"
    assert result.network_attempts[0]["result"]["reason_code"] == "dns_failed"
    assert all(item["cookies_inherited"] is False for item in result.network_attempts)
    assert [event["event"] for event in events] == [
        "network_attempt_started",
        "network_attempt_completed",
        "network_fallback",
        "network_attempt_started",
        "network_attempt_completed",
    ]


@pytest.mark.parametrize(
    "reason,outcome",
    [
        ("target_not_public", "failed"),
        ("tls_verification_failed", "failed"),
        ("challenge_detected", "blocked"),
        ("http_access_control", "blocked"),
        ("http_status", "failed"),
        ("browser_required", "failed"),
        ("flutter_runtime_required", "failed"),
        ("static_scope_complete", "not_found"),
        ("invalid_framing", "failed"),
        ("download_limit", "failed"),
        ("chain_timeout", "failed"),
    ],
)
def test_guards_challenge_and_coverage_never_trigger_proxy(tmp_path, reason, outcome):
    calls = []
    result = AcquisitionPolicy(
        proxy=PROXY, collector_factory=factory_for([WorkflowResult(outcome, reason, "partial")], calls)
    ).run(URL, tmp_path, Event())
    assert len(calls) == 1 and result.reason_code == reason


@pytest.mark.parametrize(
    "event",
    [
        "response_received",
        "redirect",
        "download_started",
        "download_progress",
        "file_verifying",
        "page_received",
    ],
)
def test_observed_session_never_changes_egress(tmp_path, event):
    calls = []
    result = AcquisitionPolicy(
        proxy=PROXY,
        collector_factory=factory_for(
            [WorkflowResult("failed", "transfer_failed", "partial")], calls, events=[{"event": event}]
        ),
    ).run(URL, tmp_path, Event())
    assert len(calls) == 1 and result.network_mode == "direct"


@pytest.mark.parametrize("field", ["hops", "bodies", "candidates", "artifacts", "selection_candidates"])
def test_saved_evidence_blocks_fallback_without_callback(tmp_path, field):
    first = WorkflowResult("failed", "network_timeout", "partial")
    setattr(first, field, [{"synthetic": True}])
    calls = []
    AcquisitionPolicy(proxy=PROXY, collector_factory=factory_for([first], calls)).run(URL, tmp_path, Event())
    assert len(calls) == 1


def test_proxy_failure_does_not_bounce_back_to_direct(tmp_path):
    calls = []
    result = AcquisitionPolicy(
        proxy=PROXY,
        collector_factory=factory_for(
            [
                WorkflowResult("failed", "dns_timeout", "partial"),
                WorkflowResult("failed", "proxy_failed", "partial"),
            ],
            calls,
        ),
    ).run(URL, tmp_path, Event())
    assert len(calls) == 2 and result.reason_code == "proxy_failed"
    assert [item["network_mode"] for item in result.network_attempts] == ["direct", "proxy"]


def test_cancel_or_exhausted_shared_deadline_never_starts_proxy(tmp_path, monkeypatch):
    import fxfetch.core.network as network

    clock = [1.0]
    monkeypatch.setattr(network.time, "monotonic", lambda: clock[0])
    calls = []
    result = AcquisitionPolicy(
        Limits(chain_timeout=2),
        PROXY,
        collector_factory=factory_for(
            [WorkflowResult("failed", "dns_failed", "partial")], calls, clock=clock
        ),
    ).run(URL, tmp_path, Event())
    assert len(calls) == 1 and result.reason_code == "task_timeout"
    assert result.network_attempts[0]["result"]["reason_code"] == "dns_failed"


def test_disabled_fallback_and_cancelled_before_start(tmp_path):
    calls = []
    result = AcquisitionPolicy(
        collector_factory=factory_for([WorkflowResult("failed", "dns_failed", "partial")], calls)
    ).run(URL, tmp_path, Event())
    assert len(calls) == 1 and result.network_mode == "direct"
    cancel = Event()
    cancel.set()
    result = AcquisitionPolicy(proxy=PROXY, collector_factory=factory_for([], calls)).run(
        URL, tmp_path / "cancelled", cancel
    )
    assert result.reason_code == "cancelled" and not result.network_attempts


def test_request_budget_shared_across_attempts(tmp_path):
    calls = []
    result = AcquisitionPolicy(
        Limits(max_requests=1),
        PROXY,
        collector_factory=factory_for([WorkflowResult("failed", "dns_failed", "partial")], calls),
    ).run(URL, tmp_path, Event())
    assert len(calls) == 1 and len(result.network_attempts) == 1
