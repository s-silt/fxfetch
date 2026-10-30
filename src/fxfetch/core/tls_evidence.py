"""Save leaf bytes obtained from an already verified TLS socket, without I/O to origins."""

from __future__ import annotations

import hashlib
import os
import stat
import time
from pathlib import Path

from .web_evidence_io import check_ancestors, is_reparse
from .web_evidence_schema import EvidenceError

MAX_CERTIFICATE_BYTES = 128 * 1024
MAX_CERTIFICATE_TOTAL = 4 * 1024 * 1024
MAX_CERTIFICATE_CONNECTIONS = 300


def _usage(root: Path, deadline: float) -> int:
    """Bound traversal; a path or inventory failure cannot grant extra disk budget."""
    total = visited = 0
    deadline = min(deadline, time.monotonic() + 1.0)
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                visited += 1
                if visited > 10_000 or time.monotonic() >= deadline:
                    raise EvidenceError("tls_certificate_inventory_limit")
                path = Path(entry.path)
                if is_reparse(path):
                    raise EvidenceError("tls_certificate_path_invalid")
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append(path)
                elif stat.S_ISREG(metadata.st_mode):
                    total += metadata.st_size
                else:
                    raise EvidenceError("tls_certificate_path_invalid")
    return total


def save_certificate_der(
    directory: Path,
    certificate: bytes,
    *,
    root: Path,
    max_task_bytes: int,
    remaining_bytes: int,
    deadline: float | None = None,
) -> tuple[dict[str, object], int]:
    """Store bounded original DER bytes; caller supplies their observation scope."""
    if not certificate or len(certificate) > MAX_CERTIFICATE_BYTES:
        raise EvidenceError("tls_certificate_size_limit")
    deadline = deadline if deadline is not None else time.monotonic() + 1.0
    if time.monotonic() >= deadline:
        raise EvidenceError("tls_certificate_capture_deadline")
    directory, root = directory.absolute(), root.absolute()
    directory.relative_to(root)
    check_ancestors(directory)
    check_ancestors(root)
    digest = hashlib.sha256(certificate).hexdigest()
    path = directory / (digest + ".der")
    written = 0
    if path.exists():
        if is_reparse(path) or not path.is_file() or path.stat().st_size != len(certificate):
            raise EvidenceError("tls_certificate_existing_mismatch")
        if path.read_bytes() != certificate:
            raise EvidenceError("tls_certificate_existing_mismatch")
    else:
        root.mkdir(parents=True, exist_ok=True)
        used = _usage(root, deadline)
        certificate_used = _usage(directory, deadline) if directory.exists() else 0
        if (len(certificate) > remaining_bytes or used + len(certificate) > max_task_bytes
                or certificate_used + len(certificate) > MAX_CERTIFICATE_TOTAL):
            raise EvidenceError("tls_certificate_storage_limit")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        check_ancestors(directory)
        if time.monotonic() >= deadline:
            raise EvidenceError("tls_certificate_capture_deadline")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(certificate)
            if path.read_bytes() != certificate:
                raise EvidenceError("tls_certificate_write_mismatch")
            written = len(certificate)
        except (OSError, ValueError):
            path.unlink(missing_ok=True)
            raise
    return {
        "path": path, "size": len(certificate), "sha256": digest, "tls_der_sha256": digest,
        "representation": "tls_certificate_der", "complete": True,
    }, written


def save_leaf_der(directory: Path, certificate: bytes, *, root: Path, max_task_bytes: int,
                  remaining_bytes: int, deadline: float | None = None,
                  tls_verification: str = "verified") -> tuple[dict[str, object], int]:
    """Bind a stored original to its socket and explicit verification policy."""
    if tls_verification not in {"verified", "ignored"}:
        raise ValueError("Unsupported TLS verification state")
    metadata, written = save_certificate_der(directory, certificate, root=root,
                                              max_task_bytes=max_task_bytes,
                                              remaining_bytes=remaining_bytes, deadline=deadline)
    return {**metadata, "cert_role": "leaf",
            "capture_source": "unverified_tls_socket" if tls_verification == "ignored" else "verified_tls_socket",
            "association": "same_connection", "tls_verification": tls_verification}, written
