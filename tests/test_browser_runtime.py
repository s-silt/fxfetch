import json

import pytest

from fxfetch.core.browser_runtime import RuntimeDiagnostics, runtime_exception_category


@pytest.mark.parametrize("message,category", [
    ("Error: Unable to create WebGL context", "webgl_unavailable"),
    ("WebAssembly.CompileError: invalid bytes", "wasm_compile_error"),
    ("WebAssembly.instantiate(): LinkError", "wasm_compile_error"),
    ("TypeError: undefined is not a function", "script_exception"),
])
def test_runtime_exception_fixed_categories(message, category):
    assert runtime_exception_category({"exception": {"description": message}}) == category


def test_runtime_observation_is_bounded_and_does_not_keep_page_text(tmp_path):
    recorder = RuntimeDiagnostics(tmp_path)
    data = {"exceptionDetails": {
        "text": "Uncaught private-secret", "url": "https://private.example/token",
        "lineNumber": 3, "columnNumber": 4,
        "exception": {"description": "Error: WebGL unavailable private-secret", "value": "token=private-secret"},
    }}
    for _ in range(50):
        recorder.observe_exception(data)
    content = (tmp_path / "runtime-diagnostic.json").read_text()
    result = json.loads(content)
    assert len(result["exceptions"]) == 16 and len(content) < 2048
    assert result["exceptions"][0] == {"category": "webgl_unavailable", "line": 3, "column": 4}
    assert "private" not in content and "token" not in content


def test_runtime_malformed_details_and_write_failure_do_not_raise(tmp_path):
    blocked = tmp_path / "file"
    blocked.write_text("preserve")
    recorder = RuntimeDiagnostics(blocked)
    recorder.observe_exception({"exceptionDetails": "invalid"})
    recorder.observe_exception({"exceptionDetails": {"exception": [], "lineNumber": "secret", "columnNumber": -1}})
    assert recorder.entries == [{"category": "script_exception"}]
    assert blocked.read_text() == "preserve"
