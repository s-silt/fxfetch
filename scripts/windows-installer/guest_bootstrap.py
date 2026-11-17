"""Fresh dedicated guest installation; fixed official assets, synthetic probes only.

This is invoked by the installer through pinned SSH before any API publication.
No previously downloaded target files, profiles or acceptance receipts are used.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import uuid
from pathlib import Path

sys.path.insert(0, "/opt/fxfetch")
import guest_bootstrap_chrome  # type: ignore[import-not-found]  # noqa: E402
import guest_disk_acceptance  # type: ignore[import-not-found]  # noqa: E402
import guest_environment as env  # type: ignore[import-not-found]  # noqa: E402
import guest_install_chrome  # type: ignore[import-not-found]  # noqa: E402
import guest_session  # type: ignore[import-not-found]  # noqa: E402

CHROME = "e19853ab32bb80fb99e5aa4fa511e75193c690cf2f37922a3e9eb5894e03b6dc"
TRICHROME = "5266ae77797dc67fd77394e96de2e3e8ad124c58e21cfff91ee46d040680041c"


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def copy_baseline(active: Path, base: Path) -> None:
    """Durable exclusive copy of the unmounted, freshly cleared Android data."""
    with active.open("rb") as source, base.open("xb") as target:
        base.chmod(0o600)
        shutil.copyfileobj(source, target, 1024 * 1024)
        target.flush()
        os.fsync(target.fileno())


def main() -> None:
    env.validate_vm()
    root = env.ROOT
    if (root / "acceptance.json").exists():
        receipt = guest_session.acceptance()
        if not receipt or not guest_session.verified_base(receipt) or receipt.get("chrome_sha256") != CHROME or receipt.get("trichrome_sha256") != TRICHROME:
            raise RuntimeError("existing_baseline_integrity_failed")
        status = guest_session.recover_idle()
        if status.get("state") != "idle" or status.get("deployment_verified") is not True:
            raise RuntimeError("existing_baseline_recovery_not_verified")
        print(json.dumps({"state": "existing_baseline_verified", "production_enabled": False}))
        return
    if any(root.iterdir()):
        # Interrupted first installation only: preserve partial state, refuse any
        # session/container rather than clearing work that could still be active.
        if (root / "session.json").exists():
            raise RuntimeError("partial_install_has_session")
        partial_id = env.run("docker", "ps", "-aq", "--filter", f"name=^/{env.NAME}$")
        if partial_id:
            partial = json.loads(env.run("docker", "inspect", partial_id))[0]
            expected_image = json.loads(env.run("docker", "image", "inspect", env.IMAGE))[0]["Id"]
            if partial["State"]["Running"] or partial["Config"]["Labels"].get("io.fxfetch.lease") != "offline" or partial["Image"] != expected_image:
                raise RuntimeError("partial_install_container_not_owned_and_stopped")
            env.run("docker", "rm", partial["Id"])
        mounted = env.run("findmnt", "-rn", "-o", "TARGET")
        if str(root / "data") in mounted.splitlines():
            env.run("umount", str(root / "data"))
        root.rename(root.with_name("fxfetch-worker.partial-" + uuid.uuid4().hex))
        root.mkdir(mode=0o700)
    for name, expected in (("Chrome.apk", CHROME), ("TrichromeLibrary.apk", TRICHROME)):
        if digest(Path("/home/worker") / name) != expected:
            raise RuntimeError("pinned_browser_asset_mismatch")
    # The sealed clean template already has the image and repository digest.
    # The second machine never downloads environment components.
    image = json.loads(env.run("docker", "image", "inspect", env.IMAGE))[0]
    env.prepare(announce=False)
    (root / "assets").mkdir(mode=0o700)
    container = ""
    completed = False
    try:
        container = env.start_offline(announce=False, deadline=False)
        env.run("systemd-run", "--unit=fxfetch-installer-offline-" + uuid.uuid4().hex,
                "--on-active=600", "--timer-property=AccuracySec=1", "/usr/bin/docker", "stop", "--time", "5", container)
        env.wait_for_boot(timeout=180, container_id=container)
        guest_install_chrome.main()
        guest_bootstrap_chrome.main()
        pid = str(json.loads(env.run("docker", "inspect", container))[0]["State"]["Pid"])
        namespace = json.loads(env.run("nsenter", "-t", pid, "-n", "python3", "/opt/fxfetch/android_namespace_probe.py", timeout=40))
        if namespace.get("status") != "passed" or len(namespace.get("rows", [])) != 8:
            raise RuntimeError("fresh_namespace_gate_failed")
        # Baseline retains the installed browser but no browsing profile/history.
        clean = env.run("adb", "-s", "127.0.0.1:15600", "shell", "pm", "clear", "com.android.chrome")
        if clean.strip() != "Success":
            raise RuntimeError("fresh_profile_clear_failed")
        env.run("docker", "stop", "--time", "10", container, timeout=40)
        guest_disk_acceptance.main()
        disk = json.loads((root / "disk-acceptance.json").read_text(encoding="utf-8"))
        if disk.get("passed") is not True or disk.get("probe_file_removed") is not True:
            raise RuntimeError("fresh_disk_gate_failed")
        env.run("docker", "rm", container)
        env.firewall(deny_established=True)
        deny_rules = env.run("nft", "-s", "list", "table", "inet", "fxfetch_android")
        env.run("sync")
        env.run("umount", str(root / "data"))
        try:
            base = root / "accepted-base.ext4"
            copy_baseline(root / "android-data.ext4", base)
        finally:
            env.run("mount", "-o", "loop,nodev,nosuid", str(root / "android-data.ext4"), str(root / "data"))
        receipt = {"accepted": True, "acceptance_scope": "fresh_guest_offline_bootstrap",
                   "production_enabled": False, "pending": ["outer_guard", "production_lease", "native_deadline"],
                   "image_digest": env.IMAGE, "image_id": image["Id"],
                   "base_sha256": digest(base), "chrome_sha256": CHROME,
                   "trichrome_sha256": TRICHROME, "chrome_version": "145.0.7632.218",
                   "environment_sha256": digest(Path("/opt/fxfetch/guest_environment.py")),
                   "helper_sha256": digest(Path("/opt/fxfetch/guest_session.py")),
                   "deny_firewall_sha256": hashlib.sha256(deny_rules.encode()).hexdigest(),
                   "namespace_connection_matrix": namespace, "disk_acceptance": disk}
        destination = root / "acceptance.json"
        destination.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
        destination.chmod(0o600)
        completed = True
        print(json.dumps({"state": "fresh_guest_baseline_prepared", "production_enabled": False}))
    finally:
        if not completed:
            # Exact immutable container only. Keep failed receipts/disks for diagnosis.
            if not container:
                candidate = env.run("docker", "ps", "-aq", "--filter", f"name=^/{env.NAME}$")
                if candidate:
                    details = json.loads(env.run("docker", "inspect", candidate))[0]
                    expected = json.loads(env.run("docker", "image", "inspect", env.IMAGE))[0]["Id"]
                    if details["Config"]["Labels"].get("io.fxfetch.lease") != "offline" or details["Image"] != expected:
                        raise RuntimeError("failed_bootstrap_container_identity_changed")
                    container = details["Id"]
            if container:
                env.run("docker", "stop", "--time", "5", container, timeout=30)
            env.firewall(deny_established=True)


if __name__ == "__main__":
    main()
