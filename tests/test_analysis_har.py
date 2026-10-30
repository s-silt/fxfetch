from __future__ import annotations

import json

from fxfetch.core import analysis_har


def row(seq, kind, *, attempt="first", ref="same", **fields):
    return {"seq": seq, "observed_at": "2026-01-01T00:00:00+00:00", "kind": kind,
            "fields": {"collector_id": "http", "attempt_id": attempt, "request_ref": ref, **fields}}


def test_explicit_identity_only_and_no_invented_cross_attempt_response():
    url = "https://entry.example.test/"
    rows = [row(1, "request_attempted", url=url, method="GET", frame_id="frame-a"),
            row(2, "response_observed", url=url, status=302, location_raw="/next"),
            row(3, "request_attempted", url=url, method="POST", attempt="second"),
            row(4, "response_observed", url=url, status=200, attempt="second"),
            row(5, "request_attempted", ref="failed", url=url + "failed", method="GET"),
            row(6, "acquisition_event", url="https://candidate.example.test/"),
            row(7, "network_request_observed", url="https://unknown.example.test/", ref=None)]
    raw, references, omitted = analysis_har.project_har(rows)
    entries = json.loads(raw)["log"]["entries"]
    assert [entry["response"]["status"] for entry in entries] == [302, 200, 0]
    assert entries[0]["response"]["redirectURL"] == url + "next"
    assert "redirectURL" not in entries[1]["response"]
    assert b"candidate.example.test" not in raw and b"unknown.example.test" not in raw
    assert references[0]["context"]["frame_id"] == "frame-a"
    assert references[1]["observation_sequences"] == [3, 4]
    assert omitted["network_request_observed"] == 1


def test_denied_and_ambiguous_requests_do_not_become_observed_traffic():
    url = "https://entry.example.test/"
    rows = [row(1, "request_attempted", url=url), row(2, "request_attempted", url=url),
            row(3, "response_observed", url=url, status=200),
            row(4, "request_attempted", url=url, ref="denied", permitted=False),
            row(5, "response_observed", url=url, status=200, ref="orphan")]
    raw, refs, omitted = analysis_har.project_har(rows)
    assert not json.loads(raw)["log"]["entries"] and not refs
    assert omitted["request_identity_ambiguous_or_missing"] == 2
    assert omitted["request_not_permitted"] == 1


def test_projection_budget_is_explicit_and_sensitive_headers_are_not_copied(monkeypatch):
    monkeypatch.setattr(analysis_har, "MAX_HAR_ENTRIES", 1)
    rows = [row(1, "request_attempted", url="https://entry.example.test/", method="GET",
                headers={"Authorization": "synthetic-sensitive"}, postData="synthetic-sensitive"),
            row(2, "request_attempted", ref="other", url="https://other.example.test/")]
    raw, refs, omitted = analysis_har.project_har(rows)
    assert len(refs) == 1 and omitted["har_projection_budget"] == 1
    assert b"synthetic-sensitive" not in raw and "headers" not in refs[0]["context"]


def test_conflicting_redirects_are_not_guessed():
    url = "https://entry.example.test/"
    raw, _, gaps = analysis_har.project_har([
        row(1, "request_attempted", url=url),
        row(2, "response_observed", url=url, status=302, location_raw="/a"),
        row(3, "redirect_observed", from_url=url, resolved_target=url + "b"),
    ])
    assert "redirectURL" not in json.loads(raw)["log"]["entries"][0]["response"]
    assert gaps["redirect_observations_conflict"] == 1
