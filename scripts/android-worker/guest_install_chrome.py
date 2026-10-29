"""Install the two pinned Google SDK browser artifacts in the offline worker."""

from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path

import guest_environment as env

ARTIFACTS = {
    "TrichromeLibrary.apk": "5266ae77797dc67fd77394e96de2e3e8ad124c58e21cfff91ee46d040680041c",
    "Chrome.apk": "e19853ab32bb80fb99e5aa4fa511e75193c690cf2f37922a3e9eb5894e03b6dc",
}


def main() -> None:
    env.validate_vm()
    for filename, expected in ARTIFACTS.items():
        with (Path("/home/worker") / filename).open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != expected:
                raise RuntimeError(f"Official artifact checksum mismatch: {filename}")
    env.firewall()
    container_id = env.run("docker", "inspect", "--format", "{{.Id}}", env.NAME)
    env.run("docker", "update", "--pids-limit", "4096", container_id)
    env.run("systemd-run", f"--unit=fxfetch-chrome-upgrade-{int(time.time())}", "--on-active=600", "--timer-property=AccuracySec=1", "/usr/bin/docker", "stop", "--time", "5", container_id)
    env.run("docker", "start", container_id, timeout=60)
    env.namespace_firewall(expected_container_id=container_id)
    env.wait_for_boot(container_id=container_id)
    env.run("adb", "connect", "127.0.0.1:15600")
    for filename in ARTIFACTS:
        output = env.run("adb", "-s", "127.0.0.1:15600", "install", "-r", str(Path("/home/worker") / filename), timeout=120)
        if "Success" not in output:
            raise RuntimeError(f"Browser install was not confirmed: {output}")
        shutil.copyfile(Path("/home/worker") / filename, env.ROOT / "assets" / filename)
    installed = env.run("docker", "exec", env.NAME, "dumpsys", "package", "com.android.chrome")
    print(json.dumps({"installed": [line.strip() for line in installed.splitlines() if "versionName=" in line or "versionCode=" in line], "production_enabled": False}))


if __name__ == "__main__":
    main()
