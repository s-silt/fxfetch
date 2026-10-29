"""Destructive-to-own-probe-file only: verify the actual Android /data limit."""

from __future__ import annotations

import errno
import json
import os
import time

import guest_environment as env


def main() -> None:
    env.validate_vm()
    running = env.run("docker", "ps", "-q", "--filter", f"name=^/{env.NAME}$")
    if running:
        raise RuntimeError("Android must be stopped before the quota probe")
    mount = json.loads(env.run("findmnt", "--json", "--target", str(env.ROOT / "data")))["filesystems"][0]
    if mount["target"] != str(env.ROOT / "data"):
        raise RuntimeError("Actual Android data volume is not mounted")
    capacity = int(env.run("blockdev", "--getsize64", mount["source"]))
    if capacity != env.DATA_BYTES:
        raise RuntimeError("Data block device capacity changed")
    destination = env.ROOT / "data/.fxfetch-capacity-probe"
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("Refusing to overwrite a previous capacity probe")
    before = os.statvfs(env.ROOT / "data")
    written = 0
    full = False
    started = time.monotonic()
    try:
        with destination.open("xb", buffering=0) as output:
            while written <= env.DATA_BYTES:
                if time.monotonic() - started > 120:
                    raise RuntimeError("Quota probe timeout")
                try:
                    written += output.write(bytes(1024 * 1024))
                except OSError as failure:
                    if failure.errno != errno.ENOSPC:
                        raise
                    full = True
                    break
            try:
                os.fsync(output.fileno())
            except OSError as failure:
                if failure.errno != errno.ENOSPC:
                    raise
                full = True
        if not full:
            raise RuntimeError("Expected ENOSPC was not observed")
    finally:
        if destination.exists():
            destination.unlink()
        directory = os.open(env.ROOT / "data", os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    result = {"probe": "actual_android_data_enospc", "passed": full, "capacity_bytes": capacity,
              "bytes_written_before_failure": written, "available_before": before.f_bavail * before.f_frsize,
              "mount_source": mount["source"], "elapsed_seconds": round(time.monotonic() - started, 3),
              "probe_file_removed": not destination.exists(), "production_enabled": False}
    (env.ROOT / "disk-acceptance.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
