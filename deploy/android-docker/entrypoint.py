"""Run one pre-provisioned Ubuntu worker in KVM. No guest downloads or fallback."""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import time
import uuid
from pathlib import Path


class QMPProtocolError(ValueError):
    """A fixed reason code, never guest-controlled response text."""


def request_powerdown(path: str = "/run/fxfetch/qmp.sock", timeout: float = 5.0) -> None:
    """Wait for the matching powerdown acknowledgement before closing QMP.

    QMP emits asynchronous events among replies. The total handshake/command
    budget is fixed even when the peer keeps sending events or partial lines.
    An acknowledgement means QEMU accepted the ACPI request, not guest exit.
    """
    deadline = time.monotonic() + timeout
    pending = bytearray()
    messages = 0
    with socket.socket(socket.AF_UNIX) as control:
        def remaining() -> float:
            value = deadline - time.monotonic()
            if value <= 0:
                raise TimeoutError("qmp_deadline")
            return value

        def receive() -> dict[str, object]:
            nonlocal messages
            messages += 1
            if messages > 32:
                raise QMPProtocolError("qmp_message_limit")
            while b"\n" not in pending:
                control.settimeout(remaining())
                chunk = control.recv(min(4096, 8193 - len(pending)))
                if not chunk:
                    raise QMPProtocolError("qmp_unexpected_eof")
                pending.extend(chunk)
                if len(pending) > 8192 and b"\n" not in pending:
                    raise QMPProtocolError("qmp_frame_limit")
            line, _, rest = pending.partition(b"\n")
            pending[:] = rest
            if len(line) > 8192:
                raise QMPProtocolError("qmp_frame_limit")
            try:
                document = json.loads(line)
            except (ValueError, UnicodeError) as error:
                raise QMPProtocolError("qmp_invalid_json") from error
            if not isinstance(document, dict):
                raise QMPProtocolError("qmp_invalid_document")
            return document

        def command(name: str, identifier: str) -> None:
            control.settimeout(remaining())
            control.sendall(json.dumps({"execute": name, "id": identifier}).encode() + b"\n")
            while True:
                remaining()
                response = receive()
                if response.get("id") != identifier:
                    continue
                if "error" in response:
                    raise QMPProtocolError("qmp_command_rejected")
                if "return" not in response:
                    raise QMPProtocolError("qmp_invalid_response")
                return

        control.settimeout(remaining())
        control.connect(path)
        if not isinstance(receive().get("QMP"), dict):
            raise QMPProtocolError("qmp_invalid_greeting")
        command("qmp_capabilities", "fxfetch-capabilities")
        command("system_powerdown", "fxfetch-powerdown")


class ShutdownHandler:
    """Request ACPI once; a QMP error must not abandon the supervised process."""

    def __init__(self, child: subprocess.Popen[bytes]) -> None:
        self.child = child
        self.requested = False

    def __call__(self, signum: int, _frame: object) -> None:
        if self.requested or self.child.poll() is not None:
            return
        self.requested = True  # Set before I/O so a second signal cannot reenter.
        print(json.dumps({"event": "guest_acpi_shutdown_requested", "signal": signum}), flush=True)
        try:
            request_powerdown()
        except (OSError, ValueError) as error:
            reason = str(error) if isinstance(error, QMPProtocolError) else type(error).__name__
            print(json.dumps({"event": "guest_acpi_shutdown_failed", "reason_code": reason}), flush=True)
        else:
            print(json.dumps({"event": "guest_acpi_shutdown_acknowledged"}), flush=True)


def main() -> None:
    state = Path("/state")
    disk = state / "root.qcow2"
    if disk.is_symlink() or not disk.is_file():
        raise RuntimeError("The independent pre-provisioned root.qcow2 is required")
    identity_path = state / "identity.json"
    if identity_path.is_symlink() or not identity_path.is_file() or identity_path.stat().st_size > 512:
        raise RuntimeError("A private regular identity.json is required")
    identity = json.loads(identity_path.read_text())
    if not isinstance(identity, dict) or set(identity) != {"uuid", "mac"}:
        raise RuntimeError("Identity must contain exactly uuid and mac")
    identifier, mac = identity["uuid"], identity["mac"]
    if not isinstance(identifier, str) or str(uuid.UUID(identifier)) != identifier:
        raise RuntimeError("Identity UUID must use canonical lowercase form")
    if not isinstance(mac, str) or not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac):
        raise RuntimeError("Identity MAC must use canonical lowercase form")
    subprocess.run(["python", "/opt/fxfetch/kvm_probe.py"], check=True, timeout=8)
    firmware = Path("/usr/share/OVMF/OVMF_CODE_4M.fd")
    variables = state / "OVMF_VARS_4M.fd"
    if variables.is_symlink():
        raise RuntimeError("EFI variables must be a regular private file")
    if not variables.exists():
        with variables.open("xb") as target:
            with Path("/usr/share/OVMF/OVMF_VARS_4M.fd").open("rb") as source:
                shutil.copyfileobj(source, target)
            target.flush()
            os.fsync(target.fileno())
    # Fixed PCI 00:03.0 and MAC preserve the accepted guest's enp0s3 network.
    # Control listeners are internal loopback only. API joins this net namespace.
    arguments = [
        "qemu-system-x86_64",
        "-name", "fxfetch-android-docker",
        "-machine", "q35,accel=kvm",
        "-cpu", "host",
        "-smp", "2",
        "-m", "4096",
        "-uuid", identifier,
        "-nodefaults",
        "-display", "none",
        "-serial", "stdio",
        "-monitor", "none",
        "-qmp", "unix:/run/fxfetch/qmp.sock,server=on,wait=off",
        "-drive", f"if=pflash,format=raw,readonly=on,file={firmware}",
        "-drive", f"if=pflash,format=raw,file={variables}",
        "-drive", f"if=none,id=root,format=qcow2,file={disk},cache=none,discard=unmap",
        "-device", "virtio-blk-pci,drive=root,addr=0x4",
        "-netdev", "user,id=control,net=10.0.2.0/24,host=10.0.2.2,dhcpstart=10.0.2.15,ipv6=off,hostfwd=tcp:127.0.0.1:12222-10.0.2.15:22",
        "-device", f"virtio-net-pci,netdev=control,mac={mac},addr=0x3",
        "-rtc", "base=utc,clock=host",
        "-boot", "order=c,strict=on",
        "-no-reboot",
    ]
    seed = state / "seed.iso"
    if seed.exists():
        if seed.is_symlink() or not seed.is_file() or seed.stat().st_size > 1048576:
            raise RuntimeError("Retained cloud-init seed must be a small regular file")
        # Preserve the existing cloud-init instance identity on a migrated disk.
        # This is the retained provisioning seed, never a target-provided image.
        arguments.extend([
            "-device", "virtio-scsi-pci,id=seedbus,addr=0x5",
            "-drive", f"if=none,id=seed,format=raw,readonly=on,file={seed}",
            "-device", "scsi-cd,drive=seed,bus=seedbus.0",
        ])
    Path("/run/fxfetch").mkdir(mode=0o700, exist_ok=True)
    child = subprocess.Popen(arguments)

    shutdown = ShutdownHandler(child)
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    raise SystemExit(child.wait())


if __name__ == "__main__":
    main()
