from __future__ import annotations

import hashlib

import pytest

from fxfetch.core.analysis_materials import MaterialSources, analysis_suffix


def facts(*, mime="application/javascript; charset=utf-8", complete=True, representation="browser_response_body"):
    body = b'window.location.href="https://static.example.test/next";'
    context = {"collector_id": "browser", "attempt_id": "browser-one", "request_ref": "browser:session:one",
               "session_id": "session", "frame_id": "main", "target_id": "page"}
    url = "https://assets.example.test/bootstrap"
    saved = {"path": "response-0001.body", "size": len(body), "sha256": hashlib.sha256(body).hexdigest(),
             "representation": representation, "complete": complete, "url": url, **context}
    record = {key: saved[key] for key in ("path", "size", "sha256", "representation", "complete", "request_ref")}
    record.update(source_url=url, request_association="known")
    rows = [
        {"seq": 1, "kind": "request_attempted", "fields": {**context, "url": url}},
        {"seq": 2, "kind": "response_observed", "fields": {**context, "url": url, "status": 200,
                                                            "headers": {"content-type": mime}}},
        {"seq": 3, "kind": "response_body_saved" if complete else "response_prefix_saved", "fields": saved},
    ]
    return record, rows


@pytest.mark.parametrize("mime,suffix", [("application/javascript; charset=utf-8", ".js"),
                                       ("application/problem+json", ".json"), ("text/html", ".html")])
def test_observed_mime_drives_parser_not_generic_body_filename(mime, suffix):
    record, rows = facts(mime=mime)
    source = MaterialSources(rows).describe(record)
    assert analysis_suffix(record, source) == (suffix, "response_media_type")
    assert source["response_observation_sequence"] == 2
    assert source["observations"][0]["seq"] == 3
    assert source["observations"][0]["frame_id"] == "main"


@pytest.mark.parametrize("mode", ["duplicate", "different_attempt", "different_url", "wrong_order"])
def test_ambiguous_or_unrelated_response_does_not_supply_mime(mode):
    record, rows = facts()
    if mode == "duplicate":
        rows.insert(2, {**rows[1], "seq": 2})
    elif mode == "different_attempt":
        rows[1]["fields"]["attempt_id"] = "another-attempt"
    elif mode == "different_url":
        rows[1]["fields"]["url"] = "https://unrelated.example.test/"
    else:
        rows[1]["seq"] = 4
    source = MaterialSources(rows).describe(record)
    assert source["media_type"] is None and source["response_observation_sequence"] is None
    assert analysis_suffix(record, source) == (".body", "content_sniff")


def test_partial_body_is_not_promoted_to_complete_and_dom_is_not_server_body():
    record, rows = facts(complete=False)
    source = MaterialSources(rows).describe(record)
    assert source["observations"][0]["kind"] == "response_prefix_saved"
    assert record["complete"] is False
    dom = {**record, "representation": "browser_rendered_dom"}
    assert analysis_suffix(dom, source) == (".html", "rendered_dom")


@pytest.mark.parametrize("mode", ["absent", "different_attempt"])
def test_missing_response_is_explicit_even_with_script_filename(mode):
    record, rows = facts()
    record["path"] = rows[-1]["fields"]["path"] = "bootstrap.js"
    if mode == "absent":
        del rows[1]
    else:
        rows[1]["fields"]["attempt_id"] = "another-attempt"
    source = MaterialSources(rows).describe(record)
    assert source["gaps"] == ["response_observation_missing"]
    assert source["response_observation_sequence"] is None
    assert source["media_type"] is None
    assert analysis_suffix(record, source) == (".body", "content_sniff")


def test_conflicting_mime_fields_and_unhashable_unrelated_log_fields_are_safe():
    record, rows = facts()
    rows[1]["fields"]["content_type"] = "application/json"
    rows.append({"seq": 4, "kind": "response_body_saved", "fields": {"path": [], "size": {}, "sha256": []}})
    source = MaterialSources(rows).describe(record)
    assert source["gaps"] == ["response_media_type_conflict"]
    assert analysis_suffix(record, source) == (".body", "content_sniff")
