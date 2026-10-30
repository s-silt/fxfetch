"""Gateway DNS evidence uses synthetic resolver injection, never real DNS."""

import time

import pytest

from fxfetch.core import browser_gateway
from fxfetch.core.browser_workflow import apply_gateway_errors
from fxfetch.core.errors import FxfetchError
from fxfetch.core.workflow import WorkflowResult


@pytest.mark.parametrize("reject", [False, True])
def test_gateway_keeps_dns_answer_before_public_guard_failure(monkeypatch, reject):
    events = []

    class Resolver:
        last_records = []

        def resolve(self, host, port):
            assert (host, port) == ("download.synthetic.invalid", 443)
            self.last_records = [{
                "host": host, "provider": "alidns", "query_type": "AAAA",
                "status": "rejected" if reject else 0,
                "answers": [{"name": host, "type": "AAAA", "data": "::1" if reject else "2606:4700::1111",
                             "classification": "non_public" if reject else "public"}],
                "reason_code": "dns_unsafe_answer" if reject else "dns_answer_accepted",
            }]
            if reject:
                raise FxfetchError("dns_unsafe_answer", "Synthetic unsafe answer")
            return ("2606:4700::1111",)

    monkeypatch.setattr(browser_gateway, "DefaultPublicDNSResolver", Resolver)
    with browser_gateway.BrowserGateway(port=0, on_event=events.append) as gate:
        gate.arm("a" * 32)
        if reject:
            with pytest.raises(FxfetchError, match="Synthetic unsafe answer"):
                gate._destination("https://download.synthetic.invalid/")
        else:
            assert gate._destination("https://download.synthetic.invalid/") == ("2606:4700::1111", 443)
    observed = [event for event in events if event["event"] == "dns_resolution_observed"]
    assert len(observed) == 1
    assert observed[0]["dns_record"]["answers"][0]["data"] == ("::1" if reject else "2606:4700::1111")
    failures = [event for event in events if event["event"] == "dns_resolution_failed"]
    assert len(failures) == int(reject)
    if reject:
        assert failures[0]["reason_code"] == "dns_unsafe_answer"
        assert "answers" not in failures[0] and "dns_record" not in failures[0]


def test_literal_ip_does_not_invent_dns_observation(monkeypatch):
    def forbidden():
        raise AssertionError("Literal IP must not invoke DNS")

    monkeypatch.setattr(browser_gateway, "DefaultPublicDNSResolver", forbidden)
    events = []
    with browser_gateway.BrowserGateway(port=0, on_event=events.append) as gate:
        gate.arm("b" * 32)
        assert gate._destination("https://1.1.1.1/") == ("1.1.1.1", 443)
    assert not any(event["event"].startswith("dns_") for event in events)


def test_unsafe_dns_never_becomes_complete_not_found():
    result = WorkflowResult("not_found", "no_package", "complete")
    apply_gateway_errors(result, [{"reason_code": "dns_unsafe_answer"}])
    assert (result.outcome, result.reason_code, result.coverage) == ("failed", "dns_unsafe_answer", "partial")


@pytest.mark.parametrize("stop", ["deadline", "cancel", "close"])
def test_late_gateway_dns_never_reports_usable_answer(monkeypatch, stop):
    events = []

    class Resolver:
        last_records = [{"host": "download.synthetic.invalid", "provider": "alidns", "query_type": "A",
                         "status": 0, "reason_code": "dns_answer_accepted", "addresses": ("1.1.1.1",)}]

        def resolve(self, host, port):
            if stop == "deadline":
                gate.deadline = time.monotonic() - 1
            elif stop == "cancel":
                gate.cancel.set()
            else:
                gate.close()
            return ("1.1.1.1",)

    monkeypatch.setattr(browser_gateway, "DefaultPublicDNSResolver", Resolver)
    with browser_gateway.BrowserGateway(port=0, on_event=events.append) as gate:
        gate.arm("c" * 32)
        with pytest.raises(FxfetchError) as caught:
            gate._destination("https://download.synthetic.invalid/")
    assert caught.value.code == ("task_timeout" if stop == "deadline" else "cancelled")
    dns_events = [event for event in events if event["event"].startswith("dns_")]
    if stop == "close":
        assert dns_events == []
    else:
        observed = next(event["dns_record"] for event in dns_events if "dns_record" in event)
        assert observed["status"] == "discarded" and observed["late_answer_discarded"]
        assert observed["reason_code"] == caught.value.code
