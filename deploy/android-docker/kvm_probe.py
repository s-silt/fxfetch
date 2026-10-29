"""Bounded x86 KVM execution probe; no disk, network or guest operating system."""

from __future__ import annotations

import ctypes
import fcntl
import json
import mmap
import os
import signal
import struct
import time


def main() -> None:
    signal.alarm(5)
    started = time.monotonic()
    kvm = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
    api = fcntl.ioctl(kvm, 0xAE00, 0)
    if api != 12:
        raise RuntimeError(f"Unsupported KVM API {api}")
    vm = fcntl.ioctl(kvm, 0xAE01, 0)
    memory = mmap.mmap(-1, 4096, flags=mmap.MAP_SHARED)
    memory[:4] = bytes.fromhex("b8 2a 00 f4")  # mov ax,42; hlt
    address = ctypes.addressof(ctypes.c_char.from_buffer(memory))
    fcntl.ioctl(vm, 0x4020AE46, struct.pack("IIQQQ", 0, 0, 0, 4096, address))
    size = fcntl.ioctl(kvm, 0xAE04, 0)
    results = []
    for cpu_id in range(2):
        cpu = fcntl.ioctl(vm, 0xAE41, cpu_id)
        state = bytearray(312)
        fcntl.ioctl(cpu, 0x8138AE83, state)
        struct.pack_into("Q", state, 0, 0)  # CS base
        struct.pack_into("H", state, 12, 0)  # CS selector
        fcntl.ioctl(cpu, 0x4138AE84, state)
        registers = bytearray(144)
        struct.pack_into("Q", registers, 17 * 8, 2)  # RFLAGS
        fcntl.ioctl(cpu, 0x4090AE82, registers)
        with mmap.mmap(cpu, size, flags=mmap.MAP_SHARED) as run:
            fcntl.ioctl(cpu, 0xAE80, 0)
            reason = struct.unpack_from("I", run, 8)[0]
        fcntl.ioctl(cpu, 0x8090AE81, registers)
        ax = struct.unpack_from("Q", registers, 0)[0]
        if reason != 5 or ax != 42:
            raise RuntimeError(f"KVM execution failed: exit={reason}, ax={ax}")
        results.append({"cpu_id": cpu_id, "exit": "HLT", "rax": ax})
        os.close(cpu)
    memory.close()
    os.close(vm)
    os.close(kvm)
    signal.alarm(0)
    print(json.dumps({"kvm_api": api, "executed": results, "elapsed_seconds": round(time.monotonic() - started, 6)}))


if __name__ == "__main__":
    main()
