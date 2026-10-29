import hashlib
from threading import Event

import pytest

from fxfetch.core.errors import FxfetchError
from fxfetch.core.flutter_adapter import MAX_MAIN_BYTES, discover_flutter

HTML = b'<base href="/web/"><script src="flutter_bootstrap.js"></script>'
SOURCE = "https://synthetic.test/web/"


def test_flutter_follows_only_explicit_references_and_retains_gap():
    calls = []
    def fetch(url, cap):
        calls.append((url, cap))
        if url.endswith("flutter_bootstrap.js"):
            return b'config={"mainJsPath":"main.custom.js"};'
        return b'var a="https://cdn.synthetic.test/app.apk"; A.apk.prototype={};'
    result = discover_flutter(HTML, SOURCE, "android", fetch)
    assert result.supported
    assert result.gaps == ["flutter_runtime_required"]
    assert [c.url for c in result.candidates] == ["https://cdn.synthetic.test/app.apk"]
    assert result.candidates[0].action == "script_literal"
    assert calls[-1] == (SOURCE + "main.custom.js", MAX_MAIN_BYTES)
    assert len(result.evidence) == 2


def test_flutter_limit_preserves_unknown_without_guessing():
    calls = []
    def fetch(url, cap):
        calls.append(url)
        if url.endswith("flutter_bootstrap.js"):
            return b'{"mainJsPath":"main.dart.js"}'
        raise FxfetchError("download_limit", "bounded")
    result = discover_flutter(HTML, SOURCE, "android", fetch)
    assert result.gaps == ["flutter_source_download_limit"]
    assert result.candidates == []
    assert len(calls) == 2


def test_flutter_missing_or_external_main_is_not_guessed():
    for bootstrap, reason in [
        (b'{}', "flutter_main_reference_unknown"),
        (b'{"mainJsPath":"https://other.synthetic.test/main.js"}', "flutter_resource_not_same_origin"),
    ]:
        calls = []
        def fetch(url, cap, calls=calls, bootstrap=bootstrap):
            calls.append(url)
            return bootstrap
        result = discover_flutter(HTML, SOURCE, "android", fetch)
        assert result.gaps == [reason]
        assert len(calls) == 1


def test_unrelated_html_has_zero_resource_access():
    def fetch(url, cap):
        raise AssertionError("unexpected network")
    result = discover_flutter(b'<script src="app.js"></script>', SOURCE, "android", fetch)
    assert not result.supported


def _file_fetch(path):
    def fetch(url, cap):
        if url.endswith("flutter_bootstrap.js"):
            return b'{"mainJsPath":"main.dart.js"}'
        assert cap == 64 * 1024 * 1024
        return path
    return fetch


def test_flutter_scans_file_larger_than_previous_limit_without_read_bytes(tmp_path, monkeypatch):
    from pathlib import Path
    main = tmp_path / "large.js"
    digest = hashlib.sha256()
    block = b" " * (64 * 1024)
    with main.open("wb") as stream:
        for _ in range(257):
            stream.write(block)
            digest.update(block)
        ending = b'const p="https://cdn.synthetic.test/large.apk";'
        stream.write(ending)
        digest.update(ending)
    def forbidden(*args, **kwargs):
        raise AssertionError("whole-file read is forbidden")
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    result = discover_flutter(HTML, SOURCE, "android", _file_fetch(main))
    assert result.candidates[0].url.endswith("/large.apk")
    assert result.evidence[-1]["sha256"] == digest.hexdigest()
    assert result.evidence[-1]["size"] > 16 * 1024 * 1024
    assert result.gaps == ["flutter_runtime_required"]


@pytest.mark.parametrize("padding", [65520, 65535, 65536])
def test_flutter_cross_chunk_literal_and_utf8(tmp_path, padding):
    main = tmp_path / "split.js"
    main.write_bytes(b" " * padding + '中'.encode() +
                     b'const p="https://cdn.synthetic.test/split.apk";')
    result = discover_flutter(HTML, SOURCE, "android", _file_fetch(main))
    assert [c.url for c in result.candidates] == ["https://cdn.synthetic.test/split.apk"]


@pytest.mark.parametrize("ending,reason", [
    (b"\xff", "flutter_source_encoding_unsupported"),
    (b"\xe4\xb8", "flutter_source_encoding_unsupported"),
])
def test_flutter_bad_tail_does_not_publish_earlier_candidates(tmp_path, ending, reason):
    main = tmp_path / "bad.js"
    main.write_bytes(b'"https://cdn.synthetic.test/early.apk";' + b" " * 65536 + ending)
    result = discover_flutter(HTML, SOURCE, "android", _file_fetch(main))
    assert result.candidates == []
    assert result.gaps == [reason]
    assert all(e["role"] != "flutter_main" for e in result.evidence)


def test_flutter_oversize_file_does_not_publish_earlier_candidates(tmp_path):
    main = tmp_path / "oversize.js"
    with main.open("wb") as stream:
        stream.write(b'"https://cdn.synthetic.test/early.apk";')
        stream.seek(MAX_MAIN_BYTES)
        stream.write(b" ")
    result = discover_flutter(HTML, SOURCE, "android", _file_fetch(main))
    assert result.candidates == []
    assert result.gaps == ["flutter_source_limit"]


def test_flutter_cancel_scan_propagates_without_partial_result(tmp_path):
    main = tmp_path / "cancel.js"
    main.write_bytes(b'"https://cdn.synthetic.test/early.apk";')
    cancel = Event()
    original = _file_fetch(main)
    def fetch(url, cap):
        resource = original(url, cap)
        if url.endswith("main.dart.js"):
            cancel.set()
        return resource
    with pytest.raises(FxfetchError) as error:
        discover_flutter(HTML, SOURCE, "android", fetch, cancel=cancel)
    assert error.value.code == "cancelled"


def test_flutter_mid_scan_cancellation_after_candidate(tmp_path, monkeypatch):
    main = tmp_path / "cancel-mid.js"
    main.write_bytes(b'"https://cdn.synthetic.test/early.apk";' + b" " * (3 * 65536))
    cancel = Event()
    checks = 0
    def is_set():
        nonlocal checks
        checks += 1
        return checks >= 12
    monkeypatch.setattr(cancel, "is_set", is_set)
    with pytest.raises(FxfetchError) as error:
        discover_flutter(HTML, SOURCE, "android", _file_fetch(main), cancel=cancel)
    assert error.value.code == "cancelled"
    assert checks == 12


def test_flutter_deadline_before_fetch_has_zero_resource_access(monkeypatch):
    from fxfetch.core import flutter_adapter
    monkeypatch.setattr(flutter_adapter.time, "monotonic", lambda: 5.0)
    def fetch(url, cap):
        raise AssertionError("expired scan must not fetch")
    with pytest.raises(FxfetchError) as error:
        discover_flutter(HTML, SOURCE, "android", fetch, deadline=5.0)
    assert error.value.code == "chain_timeout"


def test_flutter_mid_scan_deadline_after_candidate(tmp_path, monkeypatch):
    from fxfetch.core import flutter_adapter
    main = tmp_path / "timeout-mid.js"
    main.write_bytes(b'"https://cdn.synthetic.test/early.apk";' + b" " * (3 * 65536))
    checks = 0
    def monotonic():
        nonlocal checks
        checks += 1
        return 5.0 if checks >= 12 else 1.0
    monkeypatch.setattr(flutter_adapter.time, "monotonic", monotonic)
    with pytest.raises(FxfetchError) as error:
        discover_flutter(HTML, SOURCE, "android", _file_fetch(main), deadline=5.0)
    assert error.value.code == "chain_timeout"
    assert checks == 12


def test_flutter_cancel_precedes_deadline(monkeypatch):
    from fxfetch.core import flutter_adapter
    cancel = Event()
    cancel.set()
    def forbidden():
        raise AssertionError("cancel must precede deadline")
    monkeypatch.setattr(flutter_adapter.time, "monotonic", forbidden)
    with pytest.raises(FxfetchError) as error:
        discover_flutter(HTML, SOURCE, "android", lambda url, cap: b"", cancel=cancel, deadline=0)
    assert error.value.code == "cancelled"


def test_flutter_ignores_unrelated_invalid_url_constants_and_invalid_package_literals():
    script = (b'const a="http://"; const b="https://[bad";'
              b'const c="https://name:secret@synthetic.test/invalid.apk";'
              b'const d="https://bad_host.synthetic.test/invalid.apk";'
              b'const e="https://cdn.synthetic.test/good.apk";')
    def fetch(url, cap):
        if url.endswith("flutter_bootstrap.js"):
            return b'{"mainJsPath":"main.dart.js"}'
        return script
    result = discover_flutter(HTML, SOURCE, "android", fetch)
    assert [c.url for c in result.candidates] == ["https://cdn.synthetic.test/good.apk"]
    assert result.gaps == ["flutter_runtime_required"]


def test_flutter_transport_invalid_url_is_never_swallowed():
    def fetch(url, cap):
        raise FxfetchError("invalid_url", "transport guard rejected resource")
    with pytest.raises(FxfetchError) as error:
        discover_flutter(HTML, SOURCE, "android", fetch)
    assert error.value.code == "invalid_url"
