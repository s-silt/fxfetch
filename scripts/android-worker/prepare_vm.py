"""Prepare the project's Ubuntu VM. Never installs or runs a target APK.

The default command only reports state. Downloads and VM creation are explicit
deployment actions; this is not a browser authorization or production lease.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / ".runtime" / "android-worker"
DOWNLOADS = STATE / "downloads"
VM_NAME = "fxfetch-android-worker"
VBOX = Path(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")
IMAGE_NAME = "noble-server-cloudimg-amd64.vmdk"
IMAGE_URL = "https://cloud-images.ubuntu.com/noble/20261017/" + IMAGE_NAME
IMAGE_SHA256 = "9a1e3959c9f4ad9d4752101fd4ff9a43191fb7d72e61fa20e033f9fd235ce794"
WHEEL_NAME = "pycdlib-1.14.0-py2.py3-none-any.whl"
WHEEL_URL = (
    "https://files.pythonhosted.org/packages/0c/dd/"
    "95557c0e3bad0e8ba10c0f17d9deffb139b106eda528a744e544799cbbfb/" + WHEEL_NAME
)
WHEEL_SHA256 = "a905827335f0066af3fd416c5cf9b1f29dffaf4d0914b714555213d1809f38d4"


def digest(path: Path, algorithm: str = "sha256") -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def command(args: list[str], timeout: int = 90) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {result.stderr[-3000:]}")
    return result.stdout.strip()


def vbox(*args: str, timeout: int = 90) -> str:
    return command([str(VBOX), *args], timeout)


def download(url: str, filename: str, expected: str, max_bytes: int, algorithm: str = "sha256", resume: bool = False) -> None:
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    destination = DOWNLOADS / filename
    if destination.exists():
        if digest(destination, algorithm) != expected:
            raise RuntimeError(f"Existing artifact has wrong checksum: {filename}")
        print(json.dumps({"artifact": filename, "status": "verified_existing"}), flush=True)
        return
    partial = destination.with_suffix(destination.suffix + ".partial")
    if partial.exists() and not resume:
        raise RuntimeError(f"Retained partial download must be reviewed before retry: {partial}")
    # Intentionally ignore all system/environment proxies for project deployment.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    count = partial.stat().st_size if partial.exists() else 0
    if count > max_bytes:
        raise RuntimeError("Retained partial exceeds the source limit")
    started = time.monotonic()
    next_report = count + 32 * 1024 * 1024
    headers = {"Range": f"bytes={count}-"} if count else {}
    request = urllib.request.Request(url, headers=headers)
    with opener.open(request, timeout=60) as response:
        if not response.url.startswith("https://"):
            raise RuntimeError("Artifact redirected away from HTTPS")
        if count and (response.status != 206 or not response.headers.get("Content-Range", "").startswith(f"bytes {count}-")):
            raise RuntimeError("Source did not honor the exact resume offset")
        with partial.open("ab" if count else "xb") as output:
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > max_bytes or time.monotonic() - started > 1800:
                    raise RuntimeError("Deployment artifact exceeded size/time limit")
                output.write(chunk)
                if count >= next_report:
                    print(json.dumps({"artifact": filename, "received_mib": count // 1048576}), flush=True)
                    next_report += 32 * 1024 * 1024
    actual = digest(partial, algorithm)
    if actual != expected:
        raise RuntimeError(f"Artifact checksum mismatch: {filename}; retained partial")
    partial.replace(destination)
    receipt = {"url": url, "file": filename, "bytes": count, "publisher_checksum_algorithm": algorithm, "publisher_checksum": actual, "sha256": digest(destination)}
    (DOWNLOADS / (filename + ".receipt.json")).write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"artifact": filename, "status": "downloaded_verified", "bytes": count}), flush=True)


def download_chrome_image(resume: bool) -> None:
    """One request per 64 MiB range, no automatic retries or proxy fallback."""
    filename = "google-apis-x86_64-34_r14.zip"
    url = "https://dl.google.com/android/repository/sys-img/google_apis/x86_64-34_r14.zip"
    expected = "e0f6c9a0691aa27bd597d0deb1bcfdc943ac8ca7"
    total = 1563721130
    path = DOWNLOADS / filename
    partial = path.with_suffix(path.suffix + ".partial")
    if path.exists():
        if digest(path, "sha1") != expected:
            raise RuntimeError("Existing Google image checksum mismatch")
        print(json.dumps({"artifact": filename, "status": "verified_existing"}), flush=True)
        return
    if partial.exists() and not resume:
        raise RuntimeError("Use --resume only after reviewing the earlier failure")
    offset = partial.stat().st_size if partial.exists() else 0
    if offset > total:
        raise RuntimeError("Partial exceeds exact official image length")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    started = time.monotonic()
    while offset < total:
        end = min(offset + 64 * 1048576, total) - 1
        request = urllib.request.Request(url, headers={"Range": f"bytes={offset}-{end}"})
        with opener.open(request, timeout=30) as response:
            if response.status != 206 or response.headers.get("Content-Range") != f"bytes {offset}-{end}/{total}":
                raise RuntimeError("Source did not return the exact requested range")
            with partial.open("ab" if offset else "xb") as output:
                received = 0
                while chunk := response.read(min(1048576, end - offset + 1)):
                    received += len(chunk)
                    if offset + received > end + 1 or time.monotonic() - started > 1200:
                        raise RuntimeError("Segment/total deployment budget exceeded")
                    output.write(chunk)
                if received != end - offset + 1:
                    raise RuntimeError("Truncated deployment image segment")
        offset = end + 1
        print(json.dumps({"artifact": filename, "received_mib": offset // 1048576}), flush=True)
    if digest(partial, "sha1") != expected:
        raise RuntimeError("Google image checksum mismatch; partial retained")
    partial.replace(path)
    receipt = {"url": url, "file": filename, "bytes": total, "publisher_sha1": expected, "sha256": digest(path)}
    (DOWNLOADS / (filename + ".receipt.json")).write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"artifact": filename, "status": "downloaded_verified", "bytes": total}), flush=True)


def seed() -> Path:
    wheel = DOWNLOADS / WHEEL_NAME
    if not wheel.is_file() or digest(wheel) != WHEEL_SHA256:
        raise RuntimeError("Verified pycdlib wheel is required")
    sys.path.insert(0, str(wheel))
    import pycdlib  # type: ignore[import-not-found]

    key = STATE / "worker_ed25519"
    if not key.exists():
        command(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", VM_NAME, "-f", str(key)])
    public_key = key.with_suffix(".pub").read_text().strip()
    if not public_key.startswith("ssh-ed25519 "):
        raise RuntimeError("Unexpected worker public key format")
    user_data = """#cloud-config
hostname: fxfetch-android-worker
manage_etc_hosts: true
disable_root: true
ssh_pwauth: false
users:
  - name: worker
    lock_passwd: true
    groups: [sudo]
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    shell: /bin/bash
    ssh_authorized_keys:
      - PUBLIC_KEY
package_update: true
package_upgrade: false
packages: [openssh-server, python3, python3-venv, docker.io, adb, curl, ca-certificates, nftables, linux-generic]
write_files:
  - path: /etc/apt/apt.conf.d/99fxfetch-direct
    permissions: '0644'
    content: |
      Acquire::http::Proxy "false";
      Acquire::https::Proxy "false";
  - path: /etc/docker/daemon.json
    permissions: '0644'
    content: |
      {"log-driver":"local","log-opts":{"max-size":"10m","max-file":"2"},"live-restore":false}
  - path: /etc/ssh/sshd_config.d/90-fxfetch.conf
    permissions: '0644'
    content: |
      PasswordAuthentication no
      KbdInteractiveAuthentication no
      PermitRootLogin no
      AllowUsers worker
  - path: /etc/fxfetch-worker-status
    permissions: '0644'
    content: |
      prepared_only
      android_not_installed
      production_browser_guard_not_accepted
runcmd:
  - [systemctl, enable, --now, ssh]
  - [systemctl, enable, --now, docker]
  - [sh, -c, 'mkdir -p /var/lib/fxfetch-worker; chmod 700 /var/lib/fxfetch-worker']
final_message: "fxfetch VM bootstrap finished; Android collection remains disabled"
""".replace("PUBLIC_KEY", public_key)
    meta_data = "instance-id: fxfetch-worker-20261028\nlocal-hostname: fxfetch-android-worker\n"
    target = STATE / "seed.iso"
    if target.exists():
        raise RuntimeError("Refusing to overwrite an existing seed ISO")
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident="cidata")
    for name, content in (("user-data", user_data), ("meta-data", meta_data)):
        raw = content.encode()
        iso.add_fp(io.BytesIO(raw), len(raw), iso_path="/" + name.upper().replace("-", "_") + ";1", rr_name=name, joliet_path="/" + name)
    iso.write(str(target))
    iso.close()
    return target


def prepare() -> None:
    if not VBOX.is_file():
        raise RuntimeError("VirtualBox is not installed; this script will not install host virtualization")
    image = DOWNLOADS / IMAGE_NAME
    if not image.exists() or digest(image) != IMAGE_SHA256:
        raise RuntimeError("Verified official Ubuntu image is required")
    if '"' + VM_NAME + '"' in vbox("list", "vms"):
        raise RuntimeError("Project VM already registered; refusing to overwrite or reconfigure it")
    vm_dir = STATE / VM_NAME
    if vm_dir.exists():
        raise RuntimeError("Project VM directory exists; inspect it before retry")
    iso = seed()
    vbox("createvm", "--name", VM_NAME, "--ostype", "Ubuntu_64", "--basefolder", str(STATE), "--register")
    disk = vm_dir / "root.vdi"
    vbox("clonemedium", "disk", str(image), str(disk), "--format", "VDI", timeout=600)
    vbox("modifymedium", "disk", str(disk), "--resize", "16384")
    vbox("modifyvm", VM_NAME, "--memory", "4096", "--cpus", "2", "--ioapic", "on", "--firmware", "efi", "--graphicscontroller", "vmsvga", "--vram", "16", "--nic1", "nat", "--nictype1", "virtio", "--nic2", "none", "--natpf1", "ssh,tcp,127.0.0.1,12222,,22", "--clipboard-mode", "disabled", "--drag-and-drop", "disabled", "--usb", "off", "--usbehci", "off", "--usbxhci", "off", "--vrde", "off", "--audio-enabled", "off", "--boot1", "disk", "--boot2", "none", "--boot3", "none", "--boot4", "none")
    vbox("storagectl", VM_NAME, "--name", "SATA", "--add", "sata", "--controller", "IntelAhci", "--portcount", "2")
    vbox("storageattach", VM_NAME, "--storagectl", "SATA", "--port", "0", "--device", "0", "--type", "hdd", "--medium", str(disk))
    vbox("storageattach", VM_NAME, "--storagectl", "SATA", "--port", "1", "--device", "0", "--type", "dvddrive", "--medium", str(iso))
    inventory = {"vm_name": VM_NAME, "vm_uuid": vbox("showvminfo", VM_NAME, "--machinereadable"), "production_enabled": False}
    (STATE / "vm-prepared.json").write_text(json.dumps(inventory, indent=2) + "\n")
    print(json.dumps({"vm_name": VM_NAME, "state": "prepared_stopped", "production_enabled": False}))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["status", "download", "download-chrome-image", "prepare", "start", "stop"], nargs="?", default="status")
    parser.add_argument("--resume", action="store_true", help="Explicitly resume a reviewed partial deployment download")
    args = parser.parse_args()
    if args.action == "download":
        download(IMAGE_URL, IMAGE_NAME, IMAGE_SHA256, 800 * 1024 * 1024)
        download(WHEEL_URL, WHEEL_NAME, WHEEL_SHA256, 1024 * 1024)
    elif args.action == "download-chrome-image":
        # Metadata: Google's sys-img2-3.xml; no third-party Chrome APK mirror.
        download_chrome_image(args.resume)
    elif args.action == "prepare":
        prepare()
    elif args.action in {"start", "stop"}:
        if not (STATE / "vm-prepared.json").is_file():
            raise RuntimeError("No VM created by this script is registered in project state")
        if args.action == "start":
            print(vbox("startvm", VM_NAME, "--type", "headless"))
        else:
            print(vbox("controlvm", VM_NAME, "acpipowerbutton"))
    else:
        print(json.dumps({"vm_name": VM_NAME, "state_dir": str(STATE), "vbox_available": VBOX.is_file(), "prepared": (STATE / "vm-prepared.json").is_file(), "production_enabled": False}))


if __name__ == "__main__":
    main()
