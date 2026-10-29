"""Versioned Trichrome proof regressions with no guest imports or external calls."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/android-worker/guest_session.py"
CONTAINER = "a" * 64
LIBRARY = "com.google.android.trichromelibrary"
VERSION = "123456"
DIRECTORY = "/data/app/synthetic-library"
PIN = "1" * 64


def chrome_description(path: str = DIRECTORY + "/base.apk") -> str:
    return (
        "Package [com.android.chrome]:\n"
        "  usesStaticLibraries:\n"
        f"    {LIBRARY} version:{VERSION}\n"
        "  usesLibraryFiles:\n"
        f"    {path}\n"
        "  userId=10001\n"
    )


def provider_description(version: str = VERSION) -> str:
    return (
        f"Package [{LIBRARY}_{VERSION}]:\n"
        f"  codePath={DIRECTORY}\n"
        "  static library:\n"
        f"    name:{LIBRARY} version:{version}\n"
        "  userId=10002\n"
    )


@pytest.fixture
def proof():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"), filename=str(SCRIPT))
    functions = {
        item.name: item for item in tree.body if isinstance(item, ast.FunctionDef)
    }
    library_assignment = next(
        item for item in tree.body
        if isinstance(item, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "LIBRARY" for target in item.targets)
    )
    calls = []
    responses = {
        ("dumpsys", "package", LIBRARY): "",  # Canonical name is absent for this valid versioned provider.
        ("dumpsys", "package", LIBRARY + "_" + VERSION): provider_description(),
        ("sha256sum", DIRECTORY + "/base.apk"): PIN + "  " + DIRECTORY + "/base.apk\n",
    }

    def run(*args):
        assert args[:3] == ("docker", "exec", CONTAINER)
        calls.append(args[3:])
        assert args[3:] in responses, f"Unexpected external operation: {args!r}"
        return responses[args[3:]]

    namespace = {"re": re, "env": SimpleNamespace(run=run)}
    selected = ast.Module(
        body=[library_assignment, functions["package_section"], functions["installed_trichrome"]],
        type_ignores=[],
    )
    exec(compile(selected, str(SCRIPT), "exec"), namespace)

    # Exercise the actual live guard comparison and aggregation as well as the
    # provider resolver. Other independent guard requirements are held true.
    checks = next(
        item.value for item in ast.walk(functions["inspect_status"])
        if isinstance(item, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "checks" for target in item.targets)
    )
    assert isinstance(checks, ast.Dict)
    keys = [ast.literal_eval(key) for key in checks.keys]
    hash_check = compile(ast.Expression(checks.values[keys.index("trichrome_hash")]), str(SCRIPT), "eval")
    ready_assignment = next(
        item for item in ast.walk(functions["inspect_status"])
        if isinstance(item, ast.Assign)
        and any(
            isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
            and target.value.id == "result" and isinstance(target.slice, ast.Constant)
            and target.slice.value == "guard_ready" for target in item.targets
        )
    )
    ready_code = compile(ast.Module(body=[ready_assignment], type_ignores=[]), str(SCRIPT), "exec")

    def guard_accepts(result):
        values = dict.fromkeys(keys, True)
        values["trichrome_hash"] = eval(hash_check, {"result": result, "receipt": {"trichrome_sha256": PIN}})
        state = {"result": {}, "checks": values}
        exec(ready_code, state)
        return state["result"]["guard_ready"]

    return SimpleNamespace(resolve=namespace["installed_trichrome"], calls=calls,
                           responses=responses, guard_accepts=guard_accepts)


def test_versioned_provider_resolves_when_canonical_dumpsys_is_empty(proof):
    result = proof.resolve(chrome_description(), CONTAINER)
    assert result == {
        "trichrome_dependency_present": True,
        "trichrome_package": LIBRARY + "_" + VERSION,
        "trichrome_library_version": VERSION,
        "trichrome_installed_sha256": PIN,
    }
    assert proof.calls == [
        ("dumpsys", "package", LIBRARY + "_" + VERSION),
        ("sha256sum", DIRECTORY + "/base.apk"),
    ]
    assert proof.guard_accepts(result) is True


def test_registered_library_version_mismatch_is_rejected_before_hash(proof):
    proof.responses[("dumpsys", "package", LIBRARY + "_" + VERSION)] = provider_description("123457")
    result = proof.resolve(chrome_description(), CONTAINER)
    assert result == {"trichrome_dependency_present": False}
    assert proof.calls == [("dumpsys", "package", LIBRARY + "_" + VERSION)]
    assert proof.guard_accepts(result) is False


def test_chrome_resolved_library_path_mismatch_never_hashes_provider(proof):
    result = proof.resolve(chrome_description("/data/app/other-synthetic-library/base.apk"), CONTAINER)
    assert result == {"trichrome_dependency_present": False}
    assert proof.calls == [("dumpsys", "package", LIBRARY + "_" + VERSION)]
    assert proof.guard_accepts(result) is False


def test_installed_hash_mismatch_fails_actual_live_guard(proof):
    wrong_hash = "2" * 64
    proof.responses[("sha256sum", DIRECTORY + "/base.apk")] = wrong_hash + "  " + DIRECTORY + "/base.apk\n"
    result = proof.resolve(chrome_description(), CONTAINER)
    assert result["trichrome_dependency_present"] is True
    assert result["trichrome_installed_sha256"] == wrong_hash
    assert proof.guard_accepts(result) is False
