"""Secret publication requires complete source-bound literals; entirely synthetic."""

from __future__ import annotations

import copy
import hashlib
import json
import socket
import zipfile
from pathlib import Path

import pytest
from analysis_fixtures import analysis_archive

from fxfetch.analysis_report import build_analysis_report
from fxfetch.core import analysis_runner
from fxfetch.core.analysis_evidence_filter import filter_report
from fxfetch.core.process_limits import ProcessResult
from fxfetch.core.web_evidence_schema import EvidenceError

VALUE = "synthetic-credential-123456"
LOCATION = "web/material-0001.js"


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("secret publication attempted networking")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


def prepared(tmp_path, text=None):
    output = tmp_path / "output"
    (output / "input").mkdir(parents=True)
    raw = (text or f'const api_key = "{VALUE}";').encode()
    (output / "input" / "material-0001.js").write_bytes(raw)
    receipt = {
        "state": "completed",
        "analysis": {"state": "completed"},
        "materials": [
            {
                "analysis_path": "input/material-0001.js",
                "analysis_location_prefix": LOCATION,
                "source": {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
            }
        ],
    }
    return output, receipt


def finding(
    identifier="CRYPTO-HARDCODED-KEY", snippet="key words with unrelated constants", location=LOCATION
):
    return {
        "id": identifier,
        "title": "疑似硬编码密钥 / IV",
        "category": "crypto",
        "description": "possible key",
        "evidences": [{"source": "js", "location": location, "snippet": snippet, "verified": True}],
    }


def report(*items):
    return {
        "meta": {
            "online": False,
            "web_evidence": {"file_count": 1, "load_errors": []},
            "crypto": {"findings": len(items), "finding_ids": [item["id"] for item in items]},
            "summary": {"findings": copy.deepcopy(list(items))},
        },
        "findings": list(items),
        "endpoints": [{"url": "https://synthetic.invalid/api"}],
    }


@pytest.mark.parametrize(
    "snippet,location",
    [
        ("aeskey in module; unrelated checksum 0123456789abcdef", LOCATION),
        ("api_key=synthetic-cred…", LOCATION),
        (f"api_key={VALUE}", "web/../../private.txt"),
        (f"api_key={VALUE}", "web/material-9999.js"),
        (f"api_key={VALUE}", "web/material-0001.js:99"),
        ("api_key=synthetic-wrong-credential", LOCATION),
    ],
)
def test_unbacked_hints_and_repeated_summaries_are_removed(tmp_path, snippet, location):
    output, receipt = prepared(tmp_path)
    original = report(finding(snippet=snippet, location=location))
    before = copy.deepcopy(original)
    published, stats = filter_report(original, output, receipt)
    assert published["findings"] == []
    assert published["meta"]["crypto"] == {"findings": 0, "finding_ids": []}
    assert published["meta"]["summary"]["findings"] == []
    assert stats["suppressed_findings"] == 1
    assert original == before and published["endpoints"] == original["endpoints"]


def test_complete_assignment_retains_only_supported_evidence_and_limited_claim(tmp_path):
    output, receipt = prepared(tmp_path)
    item = finding("JS-HARDCODED-AES-KEY", f"api_key={VALUE}")
    item["evidences"].append({"source": "js", "location": "web/unknown.js", "snippet": "not-supported"})
    published, stats = filter_report(report(item), output, receipt)
    kept = published["findings"][0]
    assert len(kept["evidences"]) == 1 and kept["decryption_verified"] is False
    assert "verified" not in kept["evidences"][0]
    assert kept["description"].endswith("不确认真实用途、凭据有效性或解密成功。")
    assert published["meta"]["summary"]["findings"][0] == kept
    assert stats["retained_static_secret_findings"] == 1


def test_input_binding_checks_hash_size_and_does_not_accept_verified_flag(tmp_path):
    output, receipt = prepared(tmp_path)
    (output / "input" / "material-0001.js").write_text(f'const api_key="{VALUE}"; // changed')
    published, stats = filter_report(report(finding(snippet=f"api_key={VALUE}")), output, receipt)
    assert not published["findings"] and stats["input_source_files"] == 0


def test_unknown_hardcoded_key_filtered_but_appid_and_endpoint_untouched(tmp_path):
    output, receipt = prepared(tmp_path)
    unknown = finding("FUTURE-KEY-HINT", "unlocated")
    appid = {"id": "JS-HARDCODED-APPID", "title": "硬编码 AppID / AppKey", "evidences": []}
    endpoint = {"id": "JS-ENDPOINT", "title": "endpoint", "evidences": []}
    published, _ = filter_report(report(unknown, appid, endpoint), output, receipt)
    assert published["findings"] == [appid, endpoint]
    assert published["meta"]["crypto"]["findings"] == 2


def test_meta_only_heuristic_id_is_removed(tmp_path):
    output, receipt = prepared(tmp_path)
    source = report()
    source["meta"]["crypto"] = {"findings": 1, "finding_ids": ["CRYPTO-HARDCODED-KEY"]}
    published, _ = filter_report(source, output, receipt)
    assert published["meta"]["crypto"] == {"findings": 0, "finding_ids": []}


def test_recipe_requires_source_value_and_call_not_decryption_claim(tmp_path):
    text = (
        f'const wl="{VALUE}"; var key=CryptoJS.enc.Utf8.parse(wl); '
        'var secret="unbacked-iv-1234"; CryptoJS.AES.decrypt(data, key);'
    )
    output, receipt = prepared(tmp_path, text)
    item = finding("CRYPTO-RECIPE-AES", "CryptoJS.AES.decrypt(data, key)")
    source = report(item)
    source["meta"]["crypto_recipe"] = {
        "key": VALUE,
        "source": LOCATION,
        "iv_value": "unbacked-iv-1234",
        "iv_derive": "fixed",
    }
    source["leads"] = [
        {
            "category": "crypto_recipe",
            "source_refs": [{"source": "js", "location": LOCATION}],
            "notes": "可离线解密全部流量",
        }
    ]
    published, _ = filter_report(source, output, receipt)
    assert len(published["findings"]) == 1
    assert published["meta"]["crypto_recipe"]["decryption_verified"] is False
    assert published["meta"]["crypto_recipe"]["iv_value"] is None
    assert "全部流量" not in json.dumps(published, ensure_ascii=False)
    source["meta"]["crypto_recipe"]["key"] = "made-up-recipe-value"
    published, _ = filter_report(source, output, receipt)
    assert not published["findings"] and not published["leads"]
    assert "crypto_recipe" not in published["meta"]


def test_old_publication_filters_copy_after_hash_check_and_updates_zip_receipt(tmp_path):
    output, receipt = prepared(tmp_path)
    path = output / "report" / "input.json"
    path.parent.mkdir()
    original = json.dumps(report(finding())).encode()
    path.write_bytes(original)
    receipt["analysis"]["report"] = {
        "path": "report/input.json",
        "sha256": hashlib.sha256(original).hexdigest(),
    }
    (output / "analysis.json").write_text(json.dumps(receipt))
    pending = tmp_path / "report.zip"
    assert build_analysis_report(output, pending)["state"] == "completed"
    with zipfile.ZipFile(pending) as bundle:
        assert bundle.namelist() == ["analysis.json", "report/input.json"]
        payload = bundle.read("report/input.json")
        assert not json.loads(payload)["findings"]
        exported = json.loads(bundle.read("analysis.json"))
        assert exported["analysis"]["report"]["sha256"] == hashlib.sha256(payload).hexdigest()
        assert exported["analysis"]["evidence_filter"]["suppressed_findings"] == 1
    assert path.read_bytes() == original
    path.write_bytes(original + b" ")
    with pytest.raises(EvidenceError, match="analysis_report_invalid"):
        build_analysis_report(output, tmp_path / "tampered.zip")


def test_runner_preserves_original_private_json_and_filters_before_hash(tmp_path, monkeypatch):
    archive = analysis_archive(tmp_path / "source")
    output = tmp_path / "analysis"
    original = json.dumps(report(finding())).encode()
    monkeypatch.setattr(analysis_runner.shutil, "which", lambda _: "C:/synthetic/fxapk.exe")

    def run(command, **kwargs):
        directory = Path(command[-1])
        directory.mkdir()
        (directory / "input.json").write_bytes(original)
        (directory / "input.json.sha256").write_text(hashlib.sha256(original).hexdigest())
        return ProcessResult(0)

    monkeypatch.setattr(analysis_runner, "run_limited", run)
    receipt = analysis_runner.analyze_archive(archive, output, max_bytes=16 * 1024 * 1024)
    assert receipt["state"] == "completed"
    assert (output / "native-report" / "input.json").read_bytes() == original
    assert (output / "native-report" / "input.json.sha256").read_text() == hashlib.sha256(
        original
    ).hexdigest()
    assert not (output / "report" / "input.json.sha256").exists()
    raw = (output / "report" / "input.json").read_bytes()
    assert not json.loads(raw)["findings"]
    assert receipt["analysis"]["report"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert receipt["analysis"]["native_report"]["sha256"] == hashlib.sha256(original).hexdigest()
    assert receipt["analysis"]["evidence_filter"]["suppressed_findings"] == 1


@pytest.mark.parametrize("explicit_iv", [False, True])
def test_recipe_iv_needs_iv_role_not_just_equal_secret_value(tmp_path, explicit_iv):
    text = f'const aes_key="{VALUE}"; const parsed=CryptoJS.enc.Utf8.parse(aes_key); CryptoJS.AES.decrypt(data, parsed);'
    if explicit_iv:
        text += f' const iv="{VALUE}";'
    output, receipt = prepared(tmp_path, text)
    source = report(finding("CRYPTO-RECIPE-AES", "CryptoJS.AES.decrypt(data, parsed)"))
    source["meta"]["crypto_recipe"] = {
        "key": VALUE,
        "source": LOCATION,
        "iv_value": VALUE,
        "iv_derive": "fixed",
    }
    published, _ = filter_report(source, output, receipt)
    recipe = published["meta"]["crypto_recipe"]
    assert recipe["iv_value"] == (VALUE if explicit_iv else None)
    assert recipe["iv_derive"] == ("fixed" if explicit_iv else "unknown")
    assert recipe["decryption_verified"] is False
