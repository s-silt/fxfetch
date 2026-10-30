from __future__ import annotations

import hashlib
import json
import socket
import zipfile
from pathlib import Path

import pytest
from analysis_fixtures import analysis_archive

from fxfetch.cli import main
from fxfetch.core import analysis_package, analysis_runner
from fxfetch.core.process_limits import ProcessResult
from fxfetch.core.web_evidence_schema import EvidenceError

LIMIT = 16 * 1024 * 1024


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail("offline adapter attempted networking")
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)


def test_projection_keeps_manifest_outside_input_and_binds_bytes(tmp_path):
    archive = analysis_archive(tmp_path / "source")
    output = tmp_path / "analysis"
    receipt = analysis_package.prepare_analysis(archive, output, max_bytes=LIMIT)
    assert receipt["source_archive"]["sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert (output / "source.zip").read_bytes() == archive.read_bytes()
    assert len(list((output / "input").iterdir())) == 2
    assert not (output / "input" / "manifest.json").exists()
    assert b"unvisited.example.test" not in (output / "input" / "observed.har").read_bytes()
    item = receipt["materials"][0]
    assert hashlib.sha256((output / item["analysis_path"]).read_bytes()).hexdigest() == item["source"]["sha256"]
    assert receipt["coverage"] == "partial" and not receipt["authenticity_claimed"]
    assert not receipt["external_packages_verified"]
    assert json.loads((output / "analysis.json").read_bytes())["state"] == "prepared"


def test_missing_response_keeps_material_and_reports_gap(tmp_path):
    archive = analysis_archive(tmp_path / "source", response_records=False)
    output = tmp_path / "analysis"
    receipt = analysis_package.prepare_analysis(archive, output, max_bytes=LIMIT)
    material = receipt["materials"][0]
    assert material["provenance"]["gaps"] == ["response_observation_missing"]
    assert material["provenance"]["response_observation_sequence"] is None
    assert material["analysis_path"].endswith(".body")
    assert hashlib.sha256((output / material["analysis_path"]).read_bytes()).hexdigest() == material["source"]["sha256"]


def test_existing_output_is_never_overwritten(tmp_path):
    archive = analysis_archive(tmp_path / "source")
    output = tmp_path / "analysis"
    output.mkdir()
    (output / "keep").write_text("existing")
    with pytest.raises(EvidenceError, match="analysis_output_exists"):
        analysis_package.prepare_analysis(archive, output, max_bytes=LIMIT)
    assert (output / "keep").read_text() == "existing"


def test_tampered_archive_fails_before_analysis(tmp_path, monkeypatch):
    archive = analysis_archive(tmp_path / "source")
    with zipfile.ZipFile(archive) as original:
        files = {name: original.read(name) for name in original.namelist()}
    material = next(name for name in files if name not in {"manifest.json", "observations.jsonl"})
    files[material] = b"tampered"
    with zipfile.ZipFile(archive, "w") as modified:
        for name, raw in files.items():
            modified.writestr(name, raw)
    monkeypatch.setattr(analysis_runner, "run_limited", lambda *a, **k: pytest.fail("unverified analysis"))
    output = tmp_path / "analysis"
    assert main(["analyze-data", str(archive), "--out", str(output)]) == 1
    assert not (output / "input").exists()
    assert json.loads((output / "analysis.json").read_bytes())["analysis"]["state"] == "not_run"


def test_material_budget_is_visible_without_changing_original(tmp_path, monkeypatch):
    archive = analysis_archive(tmp_path / "source")
    monkeypatch.setattr(analysis_package, "MAX_INPUT_FILE_BYTES", 1)
    receipt = analysis_package.prepare_analysis(archive, tmp_path / "analysis", max_bytes=LIMIT)
    assert receipt["materials"][0]["omitted_reason"] == "analysis_file_budget"
    assert receipt["materials"][0]["analysis_path"] is None


def test_empty_failure_package_does_not_become_successful_analysis(tmp_path, monkeypatch):
    archive = analysis_archive(tmp_path / "source", empty=True)
    monkeypatch.setattr(analysis_runner, "run_limited", lambda *a, **k: pytest.fail("empty analysis"))
    receipt = analysis_runner.analyze_archive(archive, tmp_path / "analysis", max_bytes=LIMIT)
    assert receipt["state"] == "not_analyzed"
    assert receipt["analysis"]["reason_code"] == "no_analyzable_web_material"


@pytest.mark.parametrize("timeout,code", [(False, "fxapk_analysis_failed"), (True, "fxapk_timeout")])
def test_failed_subprocess_keeps_prepared_evidence(tmp_path, monkeypatch, timeout, code):
    archive = analysis_archive(tmp_path / "source")
    monkeypatch.setattr(analysis_runner.shutil, "which", lambda value: "C:/trusted/fxapk.exe")
    monkeypatch.setattr(analysis_runner, "run_limited", lambda *a, **k: ProcessResult(1, timed_out=timeout))
    output = tmp_path / "analysis"
    receipt = analysis_runner.analyze_archive(archive, output, max_bytes=LIMIT)
    assert receipt["state"] == "failed" and receipt["analysis"]["reason_code"] == code
    assert (output / "source.zip").exists() and (output / "input").exists()


def test_runner_uses_offline_argv_and_requires_report(tmp_path, monkeypatch):
    archive = analysis_archive(tmp_path / "source")
    output = tmp_path / "analysis"
    monkeypatch.setattr(analysis_runner.shutil, "which", lambda value: "C:/trusted/fxapk.exe")

    def run(command, **kwargs):
        assert command[1] == "analyze-web" and "--offline" in command and "--online" not in command
        report_dir = Path(command[-1])
        assert report_dir != Path(command[2])
        report_dir.mkdir()
        (report_dir / "input.json").write_text(json.dumps({"meta": {
            "online": False, "web_evidence": {"file_count": 2, "load_errors": ["synthetic gap"]}}}))
        return ProcessResult(0)

    monkeypatch.setattr(analysis_runner, "run_limited", run)
    receipt = analysis_runner.analyze_archive(archive, output, max_bytes=LIMIT)
    assert receipt["state"] == "completed" and receipt["coverage"] == "partial"
    assert receipt["analysis"]["report"]["load_errors"] == ["synthetic gap"]


def test_missing_fxapk_is_explicit_and_does_not_lose_export(tmp_path, monkeypatch):
    archive = analysis_archive(tmp_path / "source")
    monkeypatch.setattr(analysis_runner.shutil, "which", lambda value: None)
    receipt = analysis_runner.analyze_archive(archive, tmp_path / "analysis", max_bytes=LIMIT)
    assert receipt["analysis"]["reason_code"] == "fxapk_executable_unavailable"


def test_prepare_cli_does_not_require_fxapk(tmp_path):
    archive = analysis_archive(tmp_path / "source")
    assert main(["prepare-analysis", str(archive), "--out", str(tmp_path / "analysis")]) == 0
