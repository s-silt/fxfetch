"""Build guest only: admit cached Ubuntu debs through signed APT metadata."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tarfile
from pathlib import Path


def call(*arguments: str) -> bytes:
    return subprocess.run(arguments, check=True, capture_output=True, timeout=90).stdout


def fields(paragraph: str) -> dict[str, str]:
    return dict(line.split(": ", 1) for line in paragraph.splitlines() if ": " in line and not line.startswith(" "))


def main() -> None:
    root = Path("/home/worker/fxfetch-package-cache")
    root.mkdir(mode=0o700, exist_ok=True)
    targets: dict[tuple[str, str, str], Path] = {}
    with tarfile.open("/home/worker/ubuntu-official-deb-cache.tar") as archive:
        members = archive.getmembers()
        if len(members) > 200 or sum(row.size for row in members) > 400 * 1024**2:
            raise RuntimeError("official_package_cache_limit")
        for member in members:
            if not member.isfile() or not re.fullmatch(r"[A-Za-z0-9_.+%~:-]+\.deb", member.name) or member.size > 128 * 1024**2:
                raise RuntimeError("official_package_cache_member_invalid")
            destination = root / member.name
            stream = archive.extractfile(member)
            if stream is None:
                raise RuntimeError("official_package_cache_member_missing")
            with stream, destination.open("wb") as output:
                shutil.copyfileobj(stream, output, 1024**2)
            info = fields(call("dpkg-deb", "--field", str(destination), "Package", "Version", "Architecture").decode("utf-8"))
            targets[(info["Package"], info["Version"], info["Architecture"])] = destination
    lists = Path("/var/lib/apt/lists")
    releases: dict[str, dict[str, str]] = {}
    for release in lists.glob("*_InRelease"):
        if release.is_symlink() or release.stat().st_size > 4 * 1024**2:
            raise RuntimeError("apt_release_file_invalid")
        call("gpgv", "--keyring", "/usr/share/keyrings/ubuntu-archive-keyring.gpg", str(release))
        content = release.read_text(encoding="utf-8")
        section = content.split("\nSHA256:\n", 1)[1].split("\nSHA512:", 1)[0]
        checksums = {}
        for line in section.splitlines():
            match = re.fullmatch(r" ([0-9a-f]{64})\s+([0-9]+)\s+(.+)", line)
            if match:
                checksums[match[3]] = match[1]
        releases[release.name.removesuffix("_InRelease")] = checksums
    verified: set[tuple[str, str, str]] = set()
    indexes = []
    for index in lists.glob("*_Packages*"):
        if not index.is_file() or index.is_symlink() or not re.search(r"_Packages(?:\.(?:lz4|gz|xz))?$", index.name):
            continue
        prefix = next((value for value in releases if index.name.startswith(value + "_")), None)
        if prefix is None:
            continue
        relative = re.sub(r"\.(?:lz4|gz|xz)$", "", index.name[len(prefix) + 1:]).replace("_", "/")
        expected = releases[prefix].get(relative)
        if expected is None:
            continue
        content = call("/usr/lib/apt/apt-helper", "cat-file", str(index))
        if len(content) > 256 * 1024**2 or hashlib.sha256(content).hexdigest() != expected:
            raise RuntimeError("apt_signed_package_index_mismatch")
        indexes.append(index.name)
        for paragraph in content.decode("utf-8").split("\n\n"):
            info = fields(paragraph)
            key = (info.get("Package", ""), info.get("Version", ""), info.get("Architecture", ""))
            path = targets.get(key)
            if path is None or key in verified:
                continue
            with path.open("rb") as stream:
                actual = hashlib.file_digest(stream, "sha256").hexdigest()
            if actual != info.get("SHA256"):
                raise RuntimeError("cached_deb_signed_hash_mismatch")
            shutil.copyfile(path, Path("/var/cache/apt/archives") / path.name)
            verified.add(key)
    receipt = {"scope": "ubuntu_cache_verified_against_gpgv_release_and_signed_package_indexes",
               "verified_packages": [list(key) for key in sorted(verified)],
               "unverified_packages": [list(key) for key in sorted(targets.keys() - verified)],
               "verified_indexes": indexes, "executed_packages": 0}
    Path("/home/worker/package-cache-verification.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"verified_packages": len(verified), "unverified_packages": len(targets) - len(verified), "executed_packages": 0}))


if __name__ == "__main__":
    main()
