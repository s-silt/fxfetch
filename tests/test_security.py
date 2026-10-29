import os
from pathlib import Path

import pytest

from fxfetch.core.errors import FxfetchError
from fxfetch.security import contained_path, password_hash, password_matches


@pytest.mark.parametrize(
    "relative",
    [
        "../outside",
        "C:/outside",
        "file.txt:stream",
        "nested/../file",
        "NUL",
        "CON.txt",
        "trailing.",
        "trailing ",
    ],
)
def test_storage_rejects_traversal_ads_and_ambiguous_windows_paths(tmp_path: Path, relative: str):
    with pytest.raises(FxfetchError):
        contained_path(tmp_path, relative, must_exist=False)


def test_file_must_exist_and_plain_file_is_allowed(tmp_path: Path):
    path = tmp_path / "nested" / "artifact.apk"
    path.parent.mkdir()
    path.write_bytes(b"synthetic")
    assert contained_path(tmp_path, "nested/artifact.apk") == path
    with pytest.raises(FxfetchError):
        contained_path(tmp_path, "missing.apk")


def test_reparse_or_symlink_never_follows_target(tmp_path: Path):
    target = tmp_path / "actual"
    target.mkdir()
    (target / "artifact.apk").write_bytes(b"synthetic")
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(target, target_is_directory=True)
    except OSError:
        if os.name == "nt":
            import subprocess

            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(linked), str(target)], capture_output=True, check=False
            )
            assert result.returncode == 0, result.stderr
        else:
            raise
    with pytest.raises(FxfetchError):
        contained_path(tmp_path, "linked/artifact.apk")
    assert (target / "artifact.apk").read_bytes() == b"synthetic"


def test_password_hash_has_random_salt_and_constant_format():
    first, second = password_hash("synthetic-password"), password_hash("synthetic-password")
    assert first != second
    assert password_matches("synthetic-password", first)
    assert not password_matches("incorrect", first)
    assert not password_matches("synthetic-password", "invalid")
