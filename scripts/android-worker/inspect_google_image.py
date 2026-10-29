"""Read-only GPT/liblp geometry inspection for the pinned official SDK image.

Format reference: AOSP system/core/fs_mgr/liblp/include/liblp/metadata_format.h.
Only linear, single-device extents are accepted; no downloaded code executes.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

IMAGE = Path(__file__).resolve().parents[2] / ".runtime/android-worker/downloads/google-system.img"
SIZE = 4306501632
EXPECTED = "156534aa2c707edfb57026f7b573a561e513433d7643d9ce3230ae6d65804c7a"


def main() -> None:
    if IMAGE.stat().st_size != SIZE:
        raise ValueError("Unexpected official image size")
    with IMAGE.open("rb") as image:
        if hashlib.file_digest(image, "sha256").hexdigest() != EXPECTED:
            raise ValueError("Unexpected official image hash")
        image.seek(512)
        gpt = image.read(512)
        if gpt[:8] != b"EFI PART":
            raise ValueError("GPT header missing")
        table_sector, count, entry_size = struct.unpack_from("<QII", gpt, 72)
        if not 2 <= count <= 128 or entry_size != 128:
            raise ValueError("Unsupported GPT table")
        image.seek(table_sector * 512 + entry_size)
        second = image.read(entry_size)
        first_lba, last_lba = struct.unpack_from("<QQ", second, 32)
        super_offset = first_lba * 512
        super_size = (last_lba - first_lba + 1) * 512
        if super_offset + super_size > SIZE:
            raise ValueError("Invalid GPT partition bounds")
        image.seek(super_offset + 4096)
        geometry = bytearray(image.read(52))
        if struct.unpack_from("<II", geometry) != (0x616C4467, 52):
            raise ValueError("Unsupported liblp geometry")
        checksum = geometry[8:40]
        geometry[8:40] = bytes(32)
        if hashlib.sha256(geometry).digest() != checksum:
            raise ValueError("liblp geometry checksum mismatch")
        maximum, slots, block_size = struct.unpack_from("<III", geometry, 40)
        if maximum > 1024 * 1024 or not 1 <= slots <= 4 or block_size != 4096:
            raise ValueError("Unsupported liblp metadata budget")
        image.seek(super_offset + 12288)
        data = image.read(maximum)
        magic, major, minor, header_size = struct.unpack_from("<IHHI", data)
        if magic != 0x414C5030 or major != 10 or minor > 2 or header_size not in (128, 256):
            raise ValueError("Unsupported liblp header")
        header = bytearray(data[:header_size])
        expected_header = header[12:44]
        header[12:44] = bytes(32)
        if hashlib.sha256(header).digest() != expected_header:
            raise ValueError("liblp header checksum mismatch")
        table_size = struct.unpack_from("<I", header, 44)[0]
        tables = data[header_size:header_size + table_size]
        if len(tables) != table_size or hashlib.sha256(tables).digest() != header[48:80]:
            raise ValueError("liblp tables checksum mismatch")
        part_offset, part_count, part_size = struct.unpack_from("<III", header, 80)
        extent_offset, extent_count, extent_size = struct.unpack_from("<III", header, 92)
        if part_size != 52 or extent_size != 24 or part_count > 32 or extent_count > 128:
            raise ValueError("Unsupported liblp table entries")
        output = []
        for index in range(part_count):
            partition = tables[part_offset + index * part_size:part_offset + (index + 1) * part_size]
            name = partition[:36].split(b"\0", 1)[0].decode("ascii")
            _, first_extent, num_extents, _ = struct.unpack_from("<IIII", partition, 36)
            if first_extent + num_extents > extent_count:
                raise ValueError("Invalid extent range")
            extents = []
            for extent_index in range(first_extent, first_extent + num_extents):
                sectors, target_type, target_data, target_source = struct.unpack_from("<QIQI", tables, extent_offset + extent_index * extent_size)
                if target_type != 0 or target_source != 0 or (target_data + sectors) * 512 > super_size:
                    raise ValueError("Only bounded single-device linear extents are supported")
                extents.append({"absolute_offset": super_offset + target_data * 512, "bytes": sectors * 512})
            output.append({"name": name, "extents": extents})
        print(json.dumps({"image_sha256": EXPECTED, "partitions": output}, indent=2))


if __name__ == "__main__":
    main()
