"""Download one pinned official SDK image; no implicit retries or system proxy."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

URL = "https://dl.google.com/android/repository/sys-img/google_apis/x86_64-37.0_r08.zip"
TOTAL = 2143899425
SHA1 = "a266cfbcf4d6c769b166c0af4d68eff0e4f4a5e3"
ROOT = Path(__file__).resolve().parents[2] / ".runtime/android-worker/downloads"
DEST = ROOT / "google-apis-x86_64-37.0_r08.zip"


class HttpsRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        if urlsplit(newurl).scheme != "https":
            raise RuntimeError("official source redirect must remain HTTPS")
        return super().redirect_request(request, response, code, message, headers, newurl)


def hashes(path: Path) -> tuple[str, str]:
    sha1, sha256 = hashlib.sha1(), hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            sha1.update(block)
            sha256.update(block)
    return sha1.hexdigest(), sha256.hexdigest()


def download(*, resume: bool = False) -> dict[str, object]:
    ROOT.mkdir(parents=True, exist_ok=True)
    if DEST.exists():
        actual, sha256 = hashes(DEST)
        if DEST.stat().st_size != TOTAL or actual != SHA1:
            raise RuntimeError("existing artifact differs from official checksum/length")
        return {"state": "verified_existing", "path": str(DEST), "sha256": sha256}
    partial = DEST.with_suffix(".zip.partial")
    if partial.exists() and not resume:
        raise RuntimeError("retained partial requires explicit reviewed --resume")
    offset = partial.stat().st_size if partial.exists() else 0
    if offset > TOTAL:
        raise RuntimeError("partial exceeds official length")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), HttpsRedirect())
    started = time.monotonic()
    while offset < TOTAL:
        end = min(offset + 64 * 1024 * 1024, TOTAL) - 1
        request = urllib.request.Request(URL, headers={"Range": f"bytes={offset}-{end}"})
        with opener.open(request, timeout=30) as response:
            if (
                urlsplit(response.url).scheme != "https"
                or response.status != 206
                or response.headers.get("Content-Range") != f"bytes {offset}-{end}/{TOTAL}"
            ):
                raise RuntimeError("official source did not honor exact HTTPS range")
            received = 0
            with partial.open("ab" if partial.exists() else "xb") as output:
                while block := response.read(min(1024 * 1024, end - offset + 2 - received)):
                    received += len(block)
                    if offset + received > end + 1 or time.monotonic() - started > 1200:
                        raise RuntimeError("segment byte/time limit exceeded; partial retained")
                    output.write(block)
                if received != end - offset + 1:
                    raise RuntimeError("truncated segment; partial retained")
        offset = end + 1
        print(
            json.dumps({"state": "receiving", "received_mib": offset // 1048576, "total_bytes": TOTAL}),
            flush=True,
        )
    actual, sha256 = hashes(partial)
    if partial.stat().st_size != TOTAL or actual != SHA1:
        raise RuntimeError("official checksum/length mismatch; partial retained")
    partial.replace(DEST)
    receipt = {
        "url": URL,
        "path": str(DEST),
        "bytes": TOTAL,
        "publisher_sha1": actual,
        "sha256": sha256,
        "seconds": round(time.monotonic() - started, 3),
    }
    DEST.with_suffix(".zip.receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    return {"state": "downloaded_verified", **receipt}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--resume", action="store_true", help="Resume a retained partial after reviewing its failure"
    )
    arguments = parser.parse_args()
    print(json.dumps(download(resume=arguments.resume)), flush=True)


if __name__ == "__main__":
    main()
