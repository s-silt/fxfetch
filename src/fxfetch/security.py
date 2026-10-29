"""Local credentials, opaque sessions and storage path boundaries."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import stat
from pathlib import Path

from .core.errors import FxfetchError


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return f"pbkdf2_sha256$600000${salt.hex()}${digest.hex()}"


def password_matches(password: str, encoded: str) -> bool:
    try:
        method, rounds, salt, digest = encoded.split("$")
        if method != "pbkdf2_sha256" or not 100_000 <= int(rounds) <= 1_000_000:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(actual.hex(), digest)
    except (ValueError, TypeError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def contained_path(root: Path, relative: str, *, must_exist: bool = True) -> Path:
    """Reject traversal AND Windows reparse points, including intermediate dirs."""
    root = root.absolute()
    part = Path(relative)
    devices = {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *[f"COM{i}" for i in range(1, 10)],
        *[f"LPT{i}" for i in range(1, 10)],
    }
    if (
        part.is_absolute()
        or part.drive
        or ".." in part.parts
        or any(
            ":" in item or item.endswith((" ", ".")) or item.split(".")[0].upper() in devices
            for item in part.parts
        )
    ):
        raise FxfetchError("unsafe_path", "Invalid storage path")
    path = root / part
    if not path.resolve().is_relative_to(root.resolve()):
        raise FxfetchError("unsafe_path", "Storage path escapes root")
    current = root
    for item in (None, *part.parts):
        if item is not None:
            current /= item
        if current.exists() or current.is_symlink():
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise FxfetchError("unsafe_path", "Linked storage paths are forbidden")
    if must_exist and not path.is_file():
        raise FxfetchError("artifact_missing", "Stored file is unavailable")
    return path
