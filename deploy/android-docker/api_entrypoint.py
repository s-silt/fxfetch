"""Prepare private SSH files and recover the guest once before starting the API."""

from __future__ import annotations

import json
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Any

from container_entrypoint import clear_proxy_environment, deployment
from container_entrypoint import main as base_main

from fxfetch.core.android_worker import PROBE_ID, AndroidWorker, AndroidWorkerConfig
from fxfetch.core.errors import FxfetchError

DIGEST_FIELDS = {
    "helper_sha256", "chrome_source_sha256", "trichrome_source_sha256", "environment_sha256",
}
CONFIG_FIELDS = DIGEST_FIELDS | {"key_path", "known_hosts_path"}


def read_regular(path: Path, directory: Path, limit: int) -> bytes:
    # Mount sources may appear as mode 0777 on Windows. Read only the selected
    # direct children, then establish restrictive modes on the Linux volume.
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("worker_source_must_be_regular")
    if path.parent.resolve() != directory.resolve():
        raise ValueError("worker_source_outside_configuration_directory")
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    if not value or len(value) > limit:
        raise ValueError("worker_source_size_invalid")
    return value


def atomic_private(path: Path, value: bytes) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("worker_destination_must_be_regular")
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".new")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def prepare_worker(root: Path, source: Path = Path("/run/fxfetch-worker")) -> dict[str, Any]:
    document = json.loads(read_regular(source / "android-worker.json", source, 8192))
    if not isinstance(document, dict) or set(document) != CONFIG_FIELDS:
        raise ValueError("worker_configuration_fields_invalid")
    if any(not isinstance(value, str) for value in document.values()):
        raise ValueError("worker_configuration_values_invalid")
    if any(not re.fullmatch(r"[0-9a-f]{64}", document[field]) for field in DIGEST_FIELDS):
        raise ValueError("worker_configuration_digest_invalid")
    identity = read_regular(Path(document["key_path"]), source, 16384)
    known_hosts = read_regular(Path(document["known_hosts_path"]), source, 65536)
    private = root / "android-control"
    if root.is_symlink() or private.is_symlink():
        raise ValueError("worker_private_directory_invalid")
    private.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(private, 0o700)
    published = root / "android-worker.json"
    if published.is_symlink() or (published.exists() and not published.is_file()):
        raise ValueError("worker_configuration_destination_invalid")
    atomic_private(private / "identity", identity)
    atomic_private(private / "known_hosts", known_hosts)
    document["key_path"] = str(private / "identity")
    document["known_hosts_path"] = str(private / "known_hosts")
    config = AndroidWorkerConfig(
        key_path=private / "identity", known_hosts_path=private / "known_hosts",
        **{field: document[field] for field in DIGEST_FIELDS},
    )
    # Presence selects the mandatory browser route; readiness is checked live.
    # Keep this configuration even when recovery fails, or generic pages could
    # incorrectly fall back to HTTP as though no Android worker were configured.
    atomic_private(published, json.dumps(document, sort_keys=True).encode("utf-8"))
    worker = AndroidWorker(config)
    try:
        status = worker.call("recover-idle", PROBE_ID)
        worker.validate(status, readiness=True)
        if status.get("state") != "idle" or status.get("deployment_verified") is not True:
            raise FxfetchError("browser_guard_unavailable", "Worker recovery did not verify idle state")
    except FxfetchError as error:
        return {"state": "unavailable", "reason_code": error.code}
    return {"state": "ready", "reason_code": None}


def main() -> int:
    clear_proxy_environment()
    args = sys.argv[1:]
    if args in ([], ["serve"]):
        config = deployment(os.environ)
        result = prepare_worker(config.root)
        # Only bounded state/reason metadata; never paths, key bytes or SSH output.
        print(json.dumps({"event": "android_worker_startup", **result}), flush=True)
    return base_main(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError):
        print(json.dumps({"state": "failed", "reason_code": "invalid_container_configuration"}))
        raise SystemExit(1) from None
