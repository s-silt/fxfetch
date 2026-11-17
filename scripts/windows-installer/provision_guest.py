"""Create a new worker disk and first-connection identities, never clone a worker.

Called only by the local installer. No target URLs or old runtime directories are
accepted. The clean official Ubuntu source is checksum pinned.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

UBUNTU_SHA256 = "9a1e3959c9f4ad9d4752101fd4ff9a43191fb7d72e61fa20e033f9fd235ce794"
WHEEL_SHA256 = "a905827335f0066af3fd416c5cf9b1f29dffaf4d0914b714555213d1809f38d4"


def run(arguments: list[str], timeout: int = 120) -> str:
    result = subprocess.run(arguments, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        # Command output can contain seed content or local keys.
        raise RuntimeError(f"provision_command_failed:{Path(arguments[0]).name}:{result.returncode}")
    return result.stdout.strip()


def verify(path: Path, expected: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("provision_asset_missing_or_link")
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
            raise RuntimeError("provision_asset_hash_mismatch")


def cloud_config(client_public: str, host_private: str, host_public: str, *, offline: bool = False) -> str:
    """JSON is valid YAML; this avoids interpolation into cloud-init shell code."""
    config = {
        "hostname": "fxfetch-android-worker", "manage_etc_hosts": True,
        "disable_root": True, "ssh_pwauth": False,
        "ssh_keys": {"ed25519_private": host_private, "ed25519_public": host_public},
        "users": [{"name": "worker", "lock_passwd": True, "groups": ["sudo"],
                   "sudo": ["ALL=(ALL) NOPASSWD:ALL"], "shell": "/bin/bash",
                   "ssh_authorized_keys": [client_public]}],
        "package_update": True, "package_upgrade": False,
        "packages": ["openssh-server", "python3", "python3-venv", "docker.io", "adb",
                     "curl", "ca-certificates", "nftables", "iproute2"],
        "write_files": [
            {"path": "/etc/apt/apt.conf.d/20auto-upgrades", "permissions": "0644",
             "content": 'APT::Periodic::Enable "0";\nAPT::Periodic::Update-Package-Lists "0";\nAPT::Periodic::Download-Upgradeable-Packages "0";\nAPT::Periodic::Unattended-Upgrade "0";\n'},
            {"path": "/etc/apt/apt.conf.d/99fxfetch-direct", "permissions": "0644",
             "content": 'Acquire::http::Proxy "false";\nAcquire::https::Proxy "false";\nAcquire::Retries "0";\nAcquire::ForceIPv4 "true";\nAcquire::http::Timeout "30";\nAcquire::https::Timeout "30";\nAcquire::Languages "none";\nAcquire::IndexTargets::deb::DEP-11::DefaultEnabled "false";\nAcquire::IndexTargets::deb::CNF::DefaultEnabled "false";\nAPT::Update::Error-Mode "any";\n'},
            {"path": "/etc/docker/daemon.json", "permissions": "0644",
             "content": json.dumps({"log-driver": "local", "log-opts": {"max-size": "10m", "max-file": "2"}, "live-restore": False})},
            {"path": "/etc/ssh/sshd_config.d/90-fxfetch.conf", "permissions": "0644",
             "content": "PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\nAllowUsers worker\nHostKey /etc/ssh/ssh_host_ed25519_key\n"},
            {"path": "/etc/fxfetch-worker-status", "permissions": "0644",
             "content": "fresh_install\nproduction_browser_guard_not_accepted\n"}],
        "runcmd": [["systemctl", "mask", "--now", "apt-daily.timer", "apt-daily-upgrade.timer", "apt-daily.service", "apt-daily-upgrade.service"],
                    ["systemctl", "enable", "--now", "ssh"],
                    ["systemctl", "enable", "--now", "docker"],
                    ["install", "-d", "-m", "0700", "/var/lib/fxfetch-worker"],
                    ["install", "-d", "-m", "0755", "/opt/fxfetch"]],
    }
    if not offline:
        config["apt"] = {"primary": [{"arches": ["default"], "uri": "https://archive.ubuntu.com/ubuntu"}],
                         "security": [{"arches": ["default"], "uri": "https://security.ubuntu.com/ubuntu"}]}
    if offline:
        config.pop("packages")
        config["package_update"] = False
    return "#cloud-config\n" + json.dumps(config, ensure_ascii=True) + "\n"


def write_seed(path: Path, config: str, instance_id: str, wheel: Path) -> None:
    verify(wheel, WHEEL_SHA256)
    sys.path.insert(0, str(wheel))
    module = importlib.import_module("pycdlib")
    iso = module.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident="cidata")
    for name, value in (("user-data", config), ("meta-data", json.dumps({"instance-id": instance_id, "local-hostname": "fxfetch-android-worker"}))):
        raw = value.encode()
        iso.add_fp(io.BytesIO(raw), len(raw), iso_path="/" + name.upper().replace("-", "_") + ";1", rr_name=name, joliet_path="/" + name)
    iso.write(str(path))
    iso.close()


def private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    protect_directory(path)


def protect_directory(path: Path) -> None:
    if os.name == "nt":
        identity = run(["whoami", "/user", "/fo", "csv", "/nh"])
        sid = re.search(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+", identity)
        if sid is None:
            raise RuntimeError("operator_sid_unavailable")
        run(["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid.group()}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"])


def require_unused_state(state: Path) -> None:
    identifiers = run(["docker", "ps", "-q"]).splitlines()
    if len(identifiers) > 128:
        raise RuntimeError("container_inventory_limit")
    if not identifiers:
        return
    containers = json.loads(run(["docker", "inspect", *identifiers]))
    expected = os.path.normcase(str(state.resolve()))
    for container in containers:
        for mount in container.get("Mounts", []):
            if mount.get("Type") == "bind" and os.path.normcase(str(Path(mount.get("Source", "")).resolve())) == expected:
                raise RuntimeError("owned_partial_state_is_still_in_use")


def prepare(assets: Path, state: Path, worker_image: str = "fxfetch-android-qemu:local") -> None:
    assets = assets.resolve(strict=True)
    state = state.absolute()
    owner_path = state.with_name(state.name + ".prepare-owner.json")
    owner = None
    if owner_path.exists():
        if owner_path.is_symlink():
            raise RuntimeError("prepare_owner_journal_is_link")
        owner = json.loads(owner_path.read_text(encoding="utf-8"))
        if owner.get("schema") != "fxfetch.prepare-owner.v1" or owner.get("state_path") != str(state):
            raise RuntimeError("prepare_owner_journal_invalid")
    previous = None
    if state.exists() or state.is_symlink():
        marker_path = state / "provision.json"
        if state.is_symlink() or marker_path.is_symlink() or (not marker_path.is_file() and owner is None):
            raise RuntimeError("fresh_guest_state_must_not_exist")
        if marker_path.is_file():
            previous = json.loads(marker_path.read_text(encoding="utf-8"))
            if previous.get("schema") != "fxfetch.fresh-guest.v1" or previous.get("source_sha256") != UBUNTU_SHA256 or previous.get("state") not in {"fresh_disk_prepared", "synthetic_acceptance_passed"}:
                raise RuntimeError("fresh_guest_state_must_not_exist")
    source = assets / "noble-server-cloudimg-amd64.vmdk"
    template = assets / "ubuntu-prepared.qcow2"
    offline = template.exists()
    if offline:
        receipt = json.loads((assets / "ubuntu-prepared.json").read_text(encoding="utf-8"))
        if receipt.get("source_sha256") != UBUNTU_SHA256 or receipt.get("scope") != "fresh_software_only_template" or receipt.get("free_space_trimmed") is not True:
            raise RuntimeError("fresh_template_receipt_required")
        verify(template, receipt["template_sha256"])
        source = template
    else:
        verify(source, UBUNTU_SHA256)
    wheel = assets / "pycdlib-1.14.0-py2.py3-none-any.whl"
    verify(wheel, WHEEL_SHA256)
    if previous is not None:
        identity = json.loads((state / "identity.json").read_text(encoding="utf-8"))
        if identity.get("uuid") != previous.get("instance_id") or previous.get("offline_template") != offline:
            raise RuntimeError("existing_guest_identity_or_template_mismatch")
        if str(uuid.UUID(identity["uuid"])) != identity["uuid"] or not re.fullmatch(r"02(?::[0-9a-f]{2}){5}", identity.get("mac", "")):
            raise RuntimeError("existing_guest_identity_format_invalid")
        if offline and previous.get("template_sha256") != receipt["template_sha256"]:
            raise RuntimeError("existing_guest_template_hash_mismatch")
        for name in ("root.qcow2", "seed.iso", "known_hosts", "worker_ed25519", "ssh_host_ed25519_key"):
            path = state / name
            if path.is_symlink() or not path.is_file():
                raise RuntimeError("existing_guest_asset_missing_or_link")
        print(json.dumps({"phase": "existing_owned_guest_reused", "production_enabled": False}), flush=True)
        return
    expected_source = receipt["template_sha256"] if offline else UBUNTU_SHA256
    if owner is None:
        owner = {"schema": "fxfetch.prepare-owner.v1", "state_path": str(state),
                 "source_sha256": expected_source, "offline_template": offline,
                 "instance_id": str(uuid.uuid4()),
                 "mac": ":".join(f"{value:02x}" for value in bytes([2]) + secrets.token_bytes(5))}
        owner_path.parent.mkdir(parents=True, exist_ok=True)
        with owner_path.open("x", encoding="utf-8") as stream:
            json.dump(owner, stream)
            stream.flush()
            os.fsync(stream.fileno())
    elif owner.get("source_sha256") != expected_source or owner.get("offline_template") != offline:
        raise RuntimeError("partial_prepare_source_changed")
    if state.exists():
        require_unused_state(state)
        allowed = {"root.qcow2", "seed.iso", "identity.json", "known_hosts", "worker_ed25519", "worker_ed25519.pub", "ssh_host_ed25519_key", "ssh_host_ed25519_key.pub"}
        if any(path.name not in allowed or path.is_symlink() or not path.is_file() for path in state.iterdir()):
            raise RuntimeError("owned_partial_prepare_contains_unknown_files")
        protect_directory(state)
        for name in ("root.qcow2", "seed.iso"):
            (state / name).unlink(missing_ok=True)
        print(json.dumps({"phase": "owned_partial_prepare_resumed"}), flush=True)
    else:
        private_directory(state)
    identifier, mac = owner["instance_id"], owner["mac"]
    for filename in ("worker_ed25519", "ssh_host_ed25519_key"):
        key = state / filename
        keygen = ["docker", "run", "--rm", "--network", "none", "--pull", "never", "--read-only",
                  "--mount", f"type=bind,source={state},target=/state", "--entrypoint", "ssh-keygen", worker_image]
        if key.exists():
            permissions = keygen.copy()
            permissions[-2] = "chmod"
            run([*permissions, "600", "/state/" + filename])
            derived = run([*keygen, "-y", "-f", "/state/" + filename])
            if not derived.startswith("ssh-ed25519 "):
                raise RuntimeError("partial_prepare_key_invalid")
            key.with_suffix(".pub").write_text(derived + "\n", encoding="utf-8")
        else:
            key.with_suffix(".pub").unlink(missing_ok=True)
            run([*keygen, "-q", "-t", "ed25519", "-N", "", "-C", "fxfetch-fresh-install", "-f", "/state/" + filename])
        (state / filename).chmod(0o600)
    public = (state / "worker_ed25519.pub").read_text(encoding="utf-8").strip()
    host_public = (state / "ssh_host_ed25519_key.pub").read_text(encoding="utf-8").strip()
    host_private = (state / "ssh_host_ed25519_key").read_text(encoding="utf-8")
    write_seed(state / "seed.iso", cloud_config(public, host_private, host_public, offline=offline), identifier, wheel)
    (state / "seed.iso").chmod(0o600)
    (state / "known_hosts").write_text("[127.0.0.1]:12222 " + host_public + "\n", encoding="ascii")
    (state / "identity.json").write_text(json.dumps({"uuid": identifier, "mac": mac}) + "\n", encoding="utf-8")
    # Use only the already-loaded, fixed local image. No pull, network or VM boot.
    prefix = ["docker", "run", "--rm", "--network", "none", "--pull", "never",
              "--mount", f"type=bind,source={assets},target=/assets,readonly",
              "--mount", f"type=bind,source={state},target=/state", "--entrypoint", "qemu-img", worker_image]
    print(json.dumps({"phase": "fresh_guest_disk_copy_started", "offline_template": offline}), flush=True)
    if offline:
        # A standalone qcow2 remains independently writable after a normal file
        # copy. Avoid slow decompression through a Windows/Docker bind mount.
        shutil.copyfile(source, state / "root.qcow2")
        verify(state / "root.qcow2", receipt["template_sha256"])
    else:
        run([*prefix, "convert", "-f", "vmdk", "-O", "qcow2", "/assets/" + source.name, "/state/root.qcow2"], 600)
    run([*prefix, "resize", "/state/root.qcow2", "24G"])
    (state / "provision.json").write_text(json.dumps({"schema": "fxfetch.fresh-guest.v1", "source_sha256": UBUNTU_SHA256,
        "instance_id": identifier, "state": "fresh_disk_prepared", "offline_template": offline,
        "template_sha256": receipt["template_sha256"] if offline else None, "production_enabled": False}) + "\n", encoding="utf-8")
    print(json.dumps({"state": "fresh_disk_prepared", "production_enabled": False}))


def bootstrap(assets: Path, state: Path, api_worker: Path, worker_container: str,
              source_root: Path, api_image: str = "fxfetch-installer-acceptance:local") -> None:
    """Provision only the named new worker, then run all serial synthetic gates.

    The caller must keep API/LAN unpublished until this returns successfully.
    The source must be a freshly prepared offline template. No downloads occur.
    """
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", worker_container):
        raise ValueError("invalid_new_worker_container")
    assets, state, source_root = assets.resolve(strict=True), state.resolve(strict=True), source_root.resolve(strict=True)
    marker = json.loads((state / "provision.json").read_text(encoding="utf-8"))
    if marker.get("schema") != "fxfetch.fresh-guest.v1" or marker.get("source_sha256") != UBUNTU_SHA256 or marker.get("state") not in {"fresh_disk_prepared", "synthetic_acceptance_passed"}:
        raise RuntimeError("fresh_disk_marker_required")
    if marker.get("offline_template") is not True:
        raise RuntimeError("offline_prepared_template_required")
    inspect = json.loads(run(["docker", "inspect", worker_container]))[0]
    mounts = [row for row in inspect["Mounts"] if row["Destination"] == "/state"]
    if len(mounts) != 1 or os.path.normcase(str(Path(mounts[0]["Source"]).resolve())) != os.path.normcase(str(state)):
        raise RuntimeError("bootstrap_container_state_mismatch")
    networks = list(inspect.get("NetworkSettings", {}).get("Networks", {}))
    if len(networks) != 1 or inspect.get("HostConfig", {}).get("PortBindings"):
        raise RuntimeError("bootstrap_requires_unpublished_isolated_worker")
    if json.loads(run(["docker", "network", "inspect", networks[0]]))[0].get("Internal") is not True:
        raise RuntimeError("bootstrap_requires_internal_offline_network")
    run(["docker", "exec", worker_container, "chmod", "600", "/state/worker_ed25519"])
    owner = api_worker / "install-owner.json"
    owner_journal = api_worker.with_name(api_worker.name + ".install-owner.json")
    sibling_owner = None
    if owner_journal.exists():
        if owner_journal.is_symlink():
            raise RuntimeError("api_worker_owner_journal_is_link")
        sibling_owner = json.loads(owner_journal.read_text(encoding="utf-8"))
        if sibling_owner.get("schema") != "fxfetch.api-worker-owner.v1" or sibling_owner.get("instance_id") != marker.get("instance_id") or sibling_owner.get("state_path") != str(api_worker.absolute()):
            raise RuntimeError("api_worker_owner_journal_invalid")
    if api_worker.exists():
        if api_worker.is_symlink() or owner.is_symlink() or (sibling_owner is None and (not owner.is_file() or json.loads(owner.read_text(encoding="utf-8")).get("instance_id") != marker.get("instance_id"))):
            raise RuntimeError("api_worker_directory_not_owned_by_this_install")
        protect_directory(api_worker)
    else:
        if sibling_owner is None:
            owner_journal.parent.mkdir(parents=True, exist_ok=True)
            with owner_journal.open("x", encoding="utf-8") as stream:
                json.dump({"schema": "fxfetch.api-worker-owner.v1", "instance_id": marker["instance_id"],
                           "state_path": str(api_worker.absolute())}, stream)
                stream.flush()
                os.fsync(stream.fileno())
        private_directory(api_worker)
    owner.write_text(json.dumps({"instance_id": marker["instance_id"]}) + "\n", encoding="utf-8")
    ssh = ["docker", "exec", worker_container, "ssh", "-T", "-p", "12222", "-i", "/state/worker_ed25519",
           "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
           "-o", "UserKnownHostsFile=/state/known_hosts", "-o", "ConnectTimeout=5",
           "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3", "worker@127.0.0.1"]
    # Bounded first boot wait. Never accept ssh-keyscan/TOFU or a changed key.
    import time
    deadline = time.monotonic() + 1200
    while True:
        try:
            run([*ssh, "true"], 15)
            break
        except (RuntimeError, subprocess.TimeoutExpired):
            if time.monotonic() >= deadline:
                raise RuntimeError("fresh_guest_ssh_deadline") from None
            time.sleep(3)
    run([*ssh, "sudo", "cloud-init", "status", "--wait"], 1200)
    run([*ssh, "sudo", "systemctl", "mask", "--now", "apt-daily.timer", "apt-daily-upgrade.timer", "apt-daily.service", "apt-daily-upgrade.service"])
    print(json.dumps({"phase": "guest_cloud_init_completed"}), flush=True)
    # Kernel and Binder modules were installed/boot-checked on the build PC.
    # Target cloud-init is offline and changes no kernel, so its first boot is
    # sufficient. QEMU intentionally exits on guest reboot (-no-reboot).
    print(json.dumps({"phase": "guest_first_boot_ready"}), flush=True)
    stage = "/state/fxfetch-install-" + uuid.uuid4().hex
    run(["docker", "exec", worker_container, "mkdir", "-m", "0700", stage])
    files = [source_root / "scripts/android-worker" / name for name in (
        "guest_environment.py", "guest_session.py", "guest_install_chrome.py",
        "guest_bootstrap_chrome.py", "guest_disk_acceptance.py")]
    files += [source_root / "tests/android_namespace_probe.py", Path(__file__).with_name("guest_bootstrap.py")]
    files += [assets / name for name in ("Chrome.apk", "TrichromeLibrary.apk")]
    for source in files:
        if source.is_symlink() or not source.is_file():
            raise RuntimeError("fresh_guest_payload_missing_or_link")
        run(["docker", "cp", str(source), f"{worker_container}:{stage}/{source.name}"], 600)
        run(["docker", "exec", worker_container, "scp", "-P", "12222", "-i", "/state/worker_ed25519",
             "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
             "-o", "UserKnownHostsFile=/state/known_hosts", stage + "/" + source.name,
             "worker@127.0.0.1:/home/worker/" + source.name], 600)
        print(json.dumps({"phase": "guest_payload_copied", "asset": source.name}), flush=True)
    # All remotely interpreted shell tokens below are fixed repository literals.
    run([*ssh, "sudo install -m 0644 /home/worker/guest_*.py /home/worker/android_namespace_probe.py /opt/fxfetch/"], 30)
    run([*ssh, "sudo", "python3", "/opt/fxfetch/guest_bootstrap.py"], 1500)
    print(json.dumps({"phase": "guest_offline_baseline_completed"}), flush=True)
    for name in ("worker_ed25519", "known_hosts"):
        (api_worker / name).write_bytes((state / name).read_bytes())
        (api_worker / name).chmod(0o600)
    def file_hash(path: Path) -> str:
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()
    config = {"key_path": "/run/fxfetch-worker/worker_ed25519", "known_hosts_path": "/run/fxfetch-worker/known_hosts",
              "helper_sha256": file_hash(source_root / "scripts/android-worker/guest_session.py"),
              "environment_sha256": file_hash(source_root / "scripts/android-worker/guest_environment.py"),
              "chrome_source_sha256": file_hash(assets / "Chrome.apk"),
              "trichrome_source_sha256": file_hash(assets / "TrichromeLibrary.apk")}
    pending_config = api_worker / ".pending-acceptance"
    pending_config.mkdir(exist_ok=True)
    (pending_config / "android-worker.json").write_text(json.dumps(config) + "\n", encoding="utf-8")
    acceptance = api_worker / "acceptance"
    acceptance.mkdir(exist_ok=True)
    command = ["docker", "run", "--rm", "--pull", "never", "--user", "0:0",
               "--memory", "3g", "--memory-swap", "3g", "--cpus", "2", "--pids-limit", "256",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
               "--network", "container:" + worker_container,
               "--mount", f"type=bind,source={api_worker.resolve()},target=/run/fxfetch-worker",
               "--mount", f"type=bind,source={source_root / 'src'},target=/acceptance/src,readonly",
               "--mount", f"type=bind,source={source_root / 'tests'},target=/acceptance/tests,readonly",
               "--env", "PYTHONPATH=/acceptance/src:/acceptance/tests", "--workdir", "/acceptance",
               "--entrypoint", "python", api_image, "-c",
               "import os,runpy,sys; os.chmod('/run/fxfetch-worker/worker_ed25519',0o600); "
               "sys.argv=sys.argv[1:]; runpy.run_path(sys.argv[0],run_name='__main__')"]
    for script, extra, timeout in (
        ("android_browser_acceptance.py", ["--cases", "cookie", "click"], 900),
        ("android_lease_acceptance.py", [], 1200),
        ("android_deadline_acceptance.py", ["--duration", "210"], 600),
    ):
        output = "/run/fxfetch-worker/acceptance/" + script.removesuffix(".py") + "-" + uuid.uuid4().hex
        print(json.dumps({"phase": "guest_synthetic_gate_started", "gate": script}), flush=True)
        run([*command, "/acceptance/tests/" + script, "--worker-config-root", "/run/fxfetch-worker/.pending-acceptance",
             "--output", output, *extra], timeout)
        print(json.dumps({"phase": "guest_synthetic_gate_passed", "gate": script}), flush=True)
    idle_probe = """import os,json
from pathlib import Path
from fxfetch.core.android_worker import AndroidWorker,load_worker_config,PROBE_ID
os.chmod('/run/fxfetch-worker/worker_ed25519',0o600)
config=load_worker_config(Path('/run/fxfetch-worker/.pending-acceptance'))
assert config is not None
worker=AndroidWorker(config)
status=worker.call('recover-idle',PROBE_ID)
worker.validate(status,readiness=True)
assert status.get('state')=='idle' and status.get('deployment_verified') is True
print(json.dumps({'status':'passed','state':'idle','deployment_verified':True,'base_sha256_verified':status.get('base_sha256_verified'),'chrome_asset_verified':status.get('chrome_asset_verified'),'trichrome_asset_verified':status.get('trichrome_asset_verified')}))
"""
    print(json.dumps({"phase": "guest_idle_readiness_started"}), flush=True)
    idle = json.loads(run([*command[:-2], "-c", idle_probe], 120))
    if idle.get("status") != "passed" or idle.get("deployment_verified") is not True:
        raise RuntimeError("factory_idle_readiness_failed")
    (acceptance / "idle-readiness.json").write_text(json.dumps(idle) + "\n", encoding="utf-8")
    print(json.dumps({"phase": "guest_idle_readiness_passed"}), flush=True)
    (pending_config / "android-worker.json").replace(api_worker / "android-worker.json")
    pending_config.rmdir()
    marker.update(state="synthetic_acceptance_passed", production_enabled=False,
                  acceptance_scope="independent_fresh_guest_serial_synthetic_only")
    (state / "provision.json").write_text(json.dumps(marker) + "\n", encoding="utf-8")
    (api_worker / "provision-acceptance.json").write_text(json.dumps(marker) + "\n", encoding="utf-8")
    print(json.dumps({"state": "synthetic_acceptance_passed", "production_enabled": False}))


def prepare_template(assets: Path, state: Path, worker_container: str) -> None:
    """Build-machine only: prepare and seal a NEW official Ubuntu guest.

    The caller starts a unique temporary worker bound to exactly this fresh
    state directory. It must wait for the guest/container to stop before calling
    export_template. This never reads or changes a production guest.
    """
    import shlex
    import time

    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", worker_container):
        raise ValueError("invalid_template_container")
    state = state.resolve(strict=True)
    marker = json.loads((state / "provision.json").read_text(encoding="utf-8"))
    if marker.get("state") != "fresh_disk_prepared" or marker.get("offline_template") is not False:
        raise RuntimeError("new_official_cloud_guest_required")
    inspect = json.loads(run(["docker", "inspect", worker_container]))[0]
    mounts = [row for row in inspect["Mounts"] if row["Destination"] == "/state"]
    if len(mounts) != 1 or os.path.normcase(str(Path(mounts[0]["Source"]).resolve())) != os.path.normcase(str(state)):
        raise RuntimeError("template_container_state_mismatch")
    run(["docker", "exec", worker_container, "chmod", "600", "/state/worker_ed25519"])
    ssh = ["docker", "exec", worker_container, "ssh", "-T", "-p", "12222", "-i", "/state/worker_ed25519",
           "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
           "-o", "UserKnownHostsFile=/state/known_hosts", "-o", "ConnectTimeout=5", "worker@127.0.0.1"]
    deadline = time.monotonic() + 1500
    while True:
        try:
            run([*ssh, "true"], 15)
            break
        except (RuntimeError, subprocess.TimeoutExpired):
            if time.monotonic() >= deadline:
                raise RuntimeError("template_cloud_boot_deadline") from None
            time.sleep(3)
    try:
        run([*ssh, "sudo", "cloud-init", "status", "--wait"], 1500)
    except RuntimeError:
        # A failed signed-repository package operation is recoverable only on
        # this confirmed new build guest. Explicit apt commands below must pass.
        run([*ssh, "test", "-e", "/var/lib/cloud/instance/boot-finished"])
        print(json.dumps({"phase": "template_cloud_package_recovery"}), flush=True)
    kernel = run([*ssh, "uname", "-r"])
    if not re.fullmatch(r"[0-9][a-zA-Z0-9.+-]{1,90}", kernel):
        raise RuntimeError("unexpected_cloud_kernel_version")
    print(json.dumps({"phase": "template_signed_packages_started"}), flush=True)
    run([*ssh, "sudo", "apt-get", "update"], 900)
    cache_script = Path(__file__).with_name("guest_deb_cache.py")
    package_cache = assets / "ubuntu-official-deb-cache.tar"
    if package_cache.is_file():
        for source in (package_cache, cache_script):
            run(["docker", "cp", str(source.resolve()), f"{worker_container}:/state/{source.name}"], 120)
            run(["docker", "exec", worker_container, "scp", "-P", "12222", "-i", "/state/worker_ed25519",
                 "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                 "-o", "UserKnownHostsFile=/state/known_hosts", "/state/" + source.name,
                 "worker@127.0.0.1:/home/worker/" + source.name], 300)
        run([*ssh, "sudo", "python3", "/home/worker/guest_deb_cache.py"], 180)
        print(json.dumps({"phase": "template_deb_cache_signed_metadata_checked"}), flush=True)
    run([*ssh, "sudo", "apt-get", "install", "--no-install-recommends", "-y",
         "openssh-server", "python3", "python3-venv", "docker.io", "adb", "curl",
         "ca-certificates", "nftables", "iproute2", "linux-modules-extra-" + kernel], 1200)
    run([*ssh, "sudo", "install", "-d", "-m", "0700", "/var/lib/fxfetch-worker"])
    run([*ssh, "sudo", "systemctl", "enable", "--now", "docker"])
    print(json.dumps({"phase": "template_signed_packages_completed"}), flush=True)
    image = "redroid/redroid@sha256:11d58a64bfbde2253d1cce81bff409ff58174980222d1bada232d9ef59181191"
    image_cache = assets / "redroid-official-cache.tar"
    if image_cache.is_file():
        run(["docker", "cp", str(image_cache.resolve()), f"{worker_container}:/state/redroid-official-cache.tar"], 180)
        run(["docker", "exec", worker_container, "scp", "-P", "12222", "-i", "/state/worker_ed25519",
             "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
             "-o", "UserKnownHostsFile=/state/known_hosts", "/state/redroid-official-cache.tar",
             "worker@127.0.0.1:/home/worker/redroid-official-cache.tar"], 300)
        run([*ssh, "sudo", "docker", "load", "--input", "/home/worker/redroid-official-cache.tar"], 300)
    run([*ssh, "sudo", "docker", "pull", image], 1200)
    print(json.dumps({"phase": "template_pinned_android_image_prepared"}), flush=True)
    if package_cache.is_file():
        proof = run([*ssh, "sudo", "cat", "/home/worker/package-cache-verification.json"])
        json.loads(proof)
        (state / "package-cache-verification.json").write_text(proof + "\n", encoding="utf-8")
    probe = """import json,subprocess,pathlib
import shutil
def call(*a): return subprocess.check_output(a,text=True).strip()
root=pathlib.Path('/var/lib/fxfetch-worker')
assert root.is_dir() and not any(root.iterdir()), 'template_contains_worker_state'
assert not call('docker','ps','-aq'), 'template_contains_container'
image=json.loads(call('docker','image','inspect',IMAGE))[0]
assert IMAGE in image['RepoDigests'], 'pinned_image_digest_missing'
subprocess.run(['apt-get','clean'],check=True)
for name in ('redroid-official-cache.tar','ubuntu-official-deb-cache.tar','ubuntu-official-universe-index.tar.gz','guest_deb_cache.py','package-cache-verification.json'):
    pathlib.Path('/home/worker',name).unlink(missing_ok=True)
cache=pathlib.Path('/home/worker/fxfetch-package-cache')
if cache.exists():
    assert cache.is_dir() and not cache.is_symlink()
    shutil.rmtree(cache)
lists=pathlib.Path('/var/lib/apt/lists')
assert lists.is_dir() and not lists.is_symlink()
shutil.rmtree(lists)
lists.mkdir(mode=0o755)
subprocess.run(['systemctl','stop','docker.service','docker.socket'],check=True)
subprocess.run(['cloud-init','clean','--logs','--machine-id','--seed'],check=True)
for p in pathlib.Path('/etc/ssh').glob('ssh_host_*'): p.unlink()
pathlib.Path('/home/worker/.ssh/authorized_keys').unlink(missing_ok=True)
for name in ('/var/lib/docker/engine-id','/etc/docker/key.json','/var/lib/docker/network/files/local-kv.db'):
    pathlib.Path(name).unlink(missing_ok=True)
subprocess.run(['fstrim','-v','/'],check=True,capture_output=True,timeout=120)
subprocess.run(['sync'],check=True)
subprocess.run(['systemd-run','--unit=fxfetch-template-seal','--on-active=5','/usr/bin/systemctl','poweroff'],check=True)
print('FXFETCH_CLEAN_TEMPLATE_SEALED')
""".replace("IMAGE", repr(image))
    # shlex is used only for the fixed program above, never case/user inputs.
    if not run([*ssh, "sudo python3 -c " + shlex.quote(probe)], 120).endswith("FXFETCH_CLEAN_TEMPLATE_SEALED"):
        raise RuntimeError("template_seal_proof_missing")
    deadline = time.monotonic() + 120
    while True:
        info = json.loads(run(["docker", "inspect", worker_container]))[0]
        if info["State"]["Running"] is False:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("template_seal_shutdown_not_confirmed")
        time.sleep(2)
    marker["state"] = "clean_template_sealed_stopped"
    marker["free_space_trimmed"] = True
    marker["container_id"] = inspect["Id"]
    (state / "provision.json").write_text(json.dumps(marker) + "\n", encoding="utf-8")
    print(json.dumps({"state": "clean_template_sealed_stopped"}))


def export_template(assets: Path, state: Path, worker_container: str,
                    worker_image: str = "fxfetch-android-qemu:local") -> None:
    """Convert only the newly sealed, confirmed stopped builder disk."""
    state, assets = state.resolve(strict=True), assets.resolve(strict=True)
    marker = json.loads((state / "provision.json").read_text(encoding="utf-8"))
    info = json.loads(run(["docker", "inspect", worker_container]))[0]
    if marker.get("state") != "clean_template_sealed_stopped" or marker.get("free_space_trimmed") is not True or info["State"]["Running"] is not False or info["Id"] != marker.get("container_id"):
        raise RuntimeError("sealed_stopped_new_template_required")
    target = assets / "ubuntu-prepared.qcow2"
    if target.exists():
        raise RuntimeError("template_export_destination_exists")
    run(["docker", "run", "--rm", "--pull", "never", "--network", "none",
         "--mount", f"type=bind,source={state},target=/source,readonly",
         "--mount", f"type=bind,source={assets},target=/assets", "--entrypoint", "qemu-img", worker_image,
         "convert", "-c", "-f", "qcow2", "-O", "qcow2", "/source/root.qcow2", "/assets/ubuntu-prepared.qcow2"], 1200)
    with target.open("rb") as stream:
        checksum = hashlib.file_digest(stream, "sha256").hexdigest()
    receipt = {"scope": "fresh_software_only_template", "source_sha256": UBUNTU_SHA256,
               "template_sha256": checksum, "template_bytes": target.stat().st_size,
               "free_space_trimmed": True,
               "contains_target_material": False, "contains_old_acceptance": False,
               "requires_fresh_identity_and_acceptance": True}
    (assets / "ubuntu-prepared.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"state": "clean_template_exported", "bytes": target.stat().st_size}))


def trim_sealed_builder(assets: Path, state: Path, worker_container: str) -> None:
    """Repair a software-only builder sealed before discard sanitation existed.

    This never accepts a production or Android-bearing guest. All identities
    remain specific to this temporary builder and are deleted before discard.
    """
    import shlex
    import time

    state, assets = state.resolve(strict=True), assets.resolve(strict=True)
    marker = json.loads((state / "provision.json").read_text(encoding="utf-8"))
    info = json.loads(run(["docker", "inspect", worker_container]))[0]
    if marker.get("state") != "clean_template_sealed_stopped" or info["State"]["Running"] or info["Id"] != marker.get("container_id") or info["HostConfig"].get("PortBindings"):
        raise RuntimeError("stopped_private_builder_required_for_trim")
    mounts = [row for row in info["Mounts"] if row["Destination"] == "/state"]
    if len(mounts) != 1 or os.path.normcase(str(Path(mounts[0]["Source"]).resolve())) != os.path.normcase(str(state)):
        raise RuntimeError("trim_builder_state_mismatch")
    candidate = state / "seed.trim.iso"
    candidate.unlink(missing_ok=True)
    write_seed(candidate, cloud_config((state / "worker_ed25519.pub").read_text(encoding="utf-8").strip(),
                (state / "ssh_host_ed25519_key").read_text(encoding="utf-8"),
                (state / "ssh_host_ed25519_key.pub").read_text(encoding="utf-8").strip(), offline=True),
                marker["instance_id"], assets / "pycdlib-1.14.0-py2.py3-none-any.whl")
    candidate.replace(state / "seed.iso")
    run(["docker", "start", worker_container])
    run(["docker", "exec", worker_container, "chmod", "600", "/state/worker_ed25519"])
    ssh = ["docker", "exec", worker_container, "ssh", "-T", "-p", "12222", "-i", "/state/worker_ed25519",
           "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
           "-o", "UserKnownHostsFile=/state/known_hosts", "-o", "ConnectTimeout=5", "worker@127.0.0.1"]
    deadline = time.monotonic() + 300
    while True:
        try:
            run([*ssh, "true"], 15)
            break
        except (RuntimeError, subprocess.TimeoutExpired):
            if time.monotonic() >= deadline:
                raise RuntimeError("trim_builder_boot_deadline") from None
            time.sleep(3)
    run([*ssh, "sudo", "cloud-init", "status", "--wait"], 300)
    code = """import pathlib,subprocess,json,re
def call(*a): return subprocess.check_output(a,text=True)
root=pathlib.Path('/var/lib/fxfetch-worker')
assert root.is_dir() and not any(root.iterdir()), 'trim_refuses_android_state'
assert not call('docker','ps','-aq').strip(), 'trim_refuses_containers'
call('modprobe','binder_linux')
call('systemctl','stop','docker.service','docker.socket')
call('cloud-init','clean','--logs','--machine-id','--seed')
for p in pathlib.Path('/etc/ssh').glob('ssh_host_*'): p.unlink()
pathlib.Path('/home/worker/.ssh/authorized_keys').unlink(missing_ok=True)
for name in ('/var/lib/docker/engine-id','/etc/docker/key.json','/var/lib/docker/network/files/local-kv.db'):
 pathlib.Path(name).unlink(missing_ok=True)
trim=call('fstrim','-v','/')
match=re.search(r'\\(([0-9]+) bytes\\)',trim)
assert match and int(match[1])>0, 'root_discard_not_proven'
call('sync')
call('systemd-run','--unit=fxfetch-template-trim-seal','--on-active=5','/usr/bin/systemctl','poweroff')
print(json.dumps({'state':'trimmed_clean_builder','trimmed_bytes':int(match[1]),'binder_module_loaded':True}))
"""
    receipt = json.loads(run([*ssh, "sudo python3 -c " + shlex.quote(code)], 180))
    deadline = time.monotonic() + 120
    while json.loads(run(["docker", "inspect", worker_container]))[0]["State"]["Running"]:
        if time.monotonic() >= deadline:
            raise RuntimeError("trim_builder_shutdown_deadline")
        time.sleep(2)
    marker["free_space_trimmed"] = True
    marker["trimmed_bytes"] = receipt["trimmed_bytes"]
    (state / "provision.json").write_text(json.dumps(marker) + "\n", encoding="utf-8")
    (state / "trim-sanitation.json").write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    print(json.dumps(receipt), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--worker-image", default="fxfetch-android-qemu:local")
    args = parser.parse_args()
    prepare(args.assets, args.state, args.worker_image)


if __name__ == "__main__":
    main()
