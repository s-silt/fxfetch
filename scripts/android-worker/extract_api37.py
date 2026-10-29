"""Offline extraction of system/product from the pinned official API37 archive."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DOWNLOADS = ROOT / ".runtime/android-worker/downloads"
ARCHIVE = DOWNLOADS / "google-apis-x86_64-37.0_r08.zip"
IMAGE = DOWNLOADS / "google-system-37.0-r08.img"
PRODUCT = DOWNLOADS / "google-product-37.0-r08.img"
ARCHIVE_BYTES = 2143899425
EXPECTED_SHA1 = "a266cfbcf4d6c769b166c0af4d68eff0e4f4a5e3"
IMAGE_BYTES = 5498732544
IMAGE_SHA256 = "1803fe79a90a9d5e070ff203581e1001770d71ee82ffaf1a26277480de7188c8"
PRODUCT_BYTES = 2547605504
PRODUCT_SHA256 = "5e0dd177e8f5e5d75a88e75170bc7fc1710d834db0cbc883168ddbc2af732812"


def digest(path: Path, algorithm: str = "sha256") -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, algorithm).hexdigest()


def verify_image(path: Path, size: int, expected: str) -> None:
    if path.stat().st_size != size or digest(path) != expected:
        raise RuntimeError("extracted image checksum/length mismatch")


def inspect_partitions() -> dict[str, Any]:
    script = Path(__file__).with_name("inspect_google_image.py")
    spec = importlib.util.spec_from_file_location("api37_inspector", script)
    if spec is None or spec.loader is None:
        raise RuntimeError("local image inspector is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.__dict__.update(IMAGE=IMAGE, SIZE=IMAGE_BYTES, EXPECTED=IMAGE_SHA256)
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        module.main()
    return json.loads(output.getvalue())


def extract() -> dict[str, Any]:
    if ARCHIVE.stat().st_size != ARCHIVE_BYTES:
        raise RuntimeError("archive size mismatch")
    if digest(ARCHIVE, "sha1") != EXPECTED_SHA1:
        raise RuntimeError("official archive checksum mismatch")
    with zipfile.ZipFile(ARCHIVE) as bundle:
        members = [item for item in bundle.infolist() if item.filename == "x86_64/system.img"]
        if len(members) != 1 or members[0].file_size != IMAGE_BYTES:
            raise RuntimeError("system image entry missing, ambiguous or outside pinned size")
        member = members[0]
        if not IMAGE.exists():
            if shutil.disk_usage(DOWNLOADS).free < member.file_size + PRODUCT_BYTES + 1024**3:
                raise RuntimeError("insufficient extraction capacity")
            pending = IMAGE.with_suffix(".img.partial")
            count = 0
            with bundle.open(member) as source, pending.open("xb") as output:
                while block := source.read(1024 * 1024):
                    count += len(block)
                    if count > member.file_size:
                        raise RuntimeError("system image exceeds declared size")
                    output.write(block)
            verify_image(pending, IMAGE_BYTES, IMAGE_SHA256)
            pending.replace(IMAGE)
    verify_image(IMAGE, IMAGE_BYTES, IMAGE_SHA256)
    metadata = inspect_partitions()
    candidates = [item for item in metadata["partitions"] if item["name"] in ("product", "product_a")]
    if len(candidates) != 1:
        raise RuntimeError("product partition is not unambiguous")
    extents = candidates[0]["extents"]
    size = sum(item["bytes"] for item in extents)
    if size != PRODUCT_BYTES:
        raise RuntimeError("product partition size differs from pinned image")
    for extent in extents:
        if (
            extent["absolute_offset"] < 0
            or extent["bytes"] <= 0
            or extent["absolute_offset"] + extent["bytes"] > IMAGE_BYTES
        ):
            raise RuntimeError("product extent outside system image")
    if not PRODUCT.exists():
        pending = PRODUCT.with_suffix(".img.partial")
        with IMAGE.open("rb") as source, pending.open("xb") as target:
            for extent in extents:
                source.seek(extent["absolute_offset"])
                remaining = extent["bytes"]
                while remaining:
                    block = source.read(min(1024 * 1024, remaining))
                    if not block:
                        raise RuntimeError("product partition truncated")
                    target.write(block)
                    remaining -= len(block)
        verify_image(pending, PRODUCT_BYTES, PRODUCT_SHA256)
        pending.replace(PRODUCT)
    verify_image(PRODUCT, PRODUCT_BYTES, PRODUCT_SHA256)
    with PRODUCT.open("rb") as source:
        source.seek(1024)
        superblock = source.read(1024)
    if superblock[56:58] != b"\x53\xef":
        raise RuntimeError("product ext4 magic mismatch")
    receipt = {
        "archive_sha1": EXPECTED_SHA1,
        "system_image": str(IMAGE),
        "system_bytes": IMAGE_BYTES,
        "system_sha256": IMAGE_SHA256,
        "product_image": str(PRODUCT),
        "product_bytes": size,
        "product_sha256": PRODUCT_SHA256,
        "ext4_magic": superblock[56:58].hex(),
        "partitions": metadata["partitions"],
    }
    (DOWNLOADS / "api37-extraction.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    return receipt


def main() -> None:
    print(json.dumps(extract()), flush=True)


if __name__ == "__main__":
    main()
