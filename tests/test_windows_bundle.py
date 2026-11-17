"""Offline release assembly rejects incomplete toolchains before publication."""
import hashlib
import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("bundle_builder", Path(__file__).resolve().parents[1] / "scripts/windows-installer/build_bundle.py")
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def assets(root):
    rows = []
    for name in (*builder.ASSETS, *builder.REQUIRED_TREE_FILES):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"synthetic-component")
        rows.append({"path": name, "size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return {"files": rows}


@pytest.mark.parametrize("missing", builder.REQUIRED_TREE_FILES)
def test_missing_toolchain_font_or_license_stops_assembly(tmp_path, missing):
    receipt = assets(tmp_path)
    (tmp_path / missing).unlink()
    with pytest.raises(ValueError, match="required_offline_asset_missing"):
        builder.validate_assets(tmp_path, receipt)


def test_recorded_asset_bytes_cannot_be_changed(tmp_path):
    receipt = assets(tmp_path)
    builder.validate_assets(tmp_path, receipt)
    (tmp_path / "Chrome.apk").write_bytes(b"a" * len(b"synthetic-component"))
    with pytest.raises(ValueError, match="digest_mismatch"):
        builder.validate_assets(tmp_path, receipt)


def test_missing_directory_not_silently_skipped(tmp_path):
    with pytest.raises(ValueError, match="required_input_directory_missing"):
        builder.copy_tree(tmp_path / "absent", tmp_path / "output")
    assert not (tmp_path / "output").exists()
