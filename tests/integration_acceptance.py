"""Manual local SDK acceptance; never imported by the default pytest suite.

Run with the project interpreter: python tests/integration_acceptance.py
Only the test-only HttpClient below supplies target responses. The actual Workflow,
JobService, SQLite, API download adapter, Android build and signing checks run intact.
No APK is installed or executed.
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import secrets
import socket
import sys
import threading
import time
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any
from unittest.mock import patch

from fastapi.testclient import TestClient
from PIL import Image

from fxfetch.build_setup import load_builder
from fxfetch.config import Settings
from fxfetch.core.http_client import FetchedResponse, Hop, HttpClient
from fxfetch.core.workflow import Workflow
from fxfetch.security import contained_path, password_hash, token_hash
from fxfetch.service import JobService
from fxfetch.store import Store
from fxfetch.web.api import create_app

ENTRY = "https://entry.synthetic.test/page?signature=a%2Fb#fragment"
REQUEST_ENTRY = ENTRY.partition("#")[0]
IMAGE_URL = "https://entry.synthetic.test/assets/banner.png"
CSS_URL = "https://entry.synthetic.test/assets/theme.css"
TITLE = "Synthetic integration offline content"
HEADER_MARKER = "synthetic-private-header-do-not-embed"
SCRIPT_MARKER = "synthetic-script-do-not-embed"


class FixtureClient(HttpClient):
    """Test-only response injection. No production guard switch or connection exists."""

    def __init__(self) -> None:
        super().__init__()
        image = io.BytesIO()
        Image.new("RGB", (48, 32), "blue").save(image, format="PNG")
        self.image = image.getvalue()
        self.css = b"h1{color:#123456}p{font-weight:bold}"
        self.html = (
            '<!doctype html><html><head><link rel="stylesheet" href="/assets/theme.css">'
            "<script>fetch('https://remote.synthetic.test/api');/*" + SCRIPT_MARKER + "*/</script>"
            "</head><body><h1>" + TITLE + "</h1><p>Saved static paragraph</p>"
            '<img src="/assets/banner.png" alt="Synthetic banner">'
            '<img width="1" height="1" src="https://external.synthetic.test/not-fetched.png" alt="Unavailable image">'
            "</body></html>"
        ).encode("utf-8")
        self.routes = {
            REQUEST_ENTRY: ("text/html; charset=utf-8", self.html),
            IMAGE_URL: ("image/png", self.image),
            CSS_URL: ("text/css", self.css),
        }
        self.calls: list[dict[str, object]] = []

    def _resolve(self, host: str, port: int) -> tuple[str, ...]:
        raise AssertionError("Fixture transport must never resolve a target")

    def _connect(self, *args: Any, **kwargs: Any) -> socket.socket:
        raise AssertionError("Fixture transport must never connect to a target")

    def fetch(
        self,
        url: str,
        destination: Path,
        *,
        user_agent: str,
        cookie_jar: CookieJar,
        cancel: threading.Event,
        referer: str | None = None,
    ) -> FetchedResponse:
        assert not cancel.is_set()
        assert url in self.routes, "Unexpected fixture target request"
        mime, body = self.routes[url]
        assert len(body) <= self.limits.max_body_bytes
        self.calls.append(
            {"url": url, "cookie_jar": id(cookie_jar), "referer": referer, "user_agent": user_agent}
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as output:
            output.write(body)
        headers = {"content-type": mime, "x-synthetic-private-header": HEADER_MARKER}
        # Empty peer data explicitly means no connection occurred in this fixture.
        hop = Hop(url, 200, headers, "", None)
        return FetchedResponse(
            url, 200, headers, destination, len(body), hashlib.sha256(body).hexdigest(), (hop,)
        )


@contextmanager
def forbid_target_network() -> Iterator[dict[str, int]]:
    counts = {"target_dns_attempts": 0, "target_tcp_attempts": 0}
    original_dns, original_connect = socket.getaddrinfo, socket.socket.connect

    def loopback(value: Any) -> bool:
        try:
            return ipaddress.ip_address(value).is_loopback
        except ValueError:
            return False

    def dns(host: Any, *args: Any, **kwargs: Any) -> Any:
        if not loopback(host):
            counts["target_dns_attempts"] += 1
            raise AssertionError("Real target DNS is forbidden in integration acceptance")
        return original_dns(host, *args, **kwargs)

    def connect(sock: socket.socket, address: Any) -> Any:
        if not isinstance(address, tuple) or not loopback(address[0]):
            counts["target_tcp_attempts"] += 1
            raise AssertionError("Real target TCP is forbidden in integration acceptance")
        return original_connect(sock, address)

    # Loopback is only for Windows asyncio's internal socketpair; target fetches use no sockets.
    with patch.object(socket, "getaddrinfo", dns), patch.object(socket.socket, "connect", connect):
        yield counts


def wait_value(read: Any, *, field: str, terminal: set[str], timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = read()
        if value[field] in terminal:
            return value
        time.sleep(0.025)
    raise AssertionError("Integration worker exceeded its bounded wait")


def run() -> int:
    repository = Path(__file__).resolve().parents[1]
    qa = repository / ".runtime" / "integration-qa"
    qa.mkdir(parents=True, exist_ok=True)
    run_root = qa / (time.strftime("run-%Y%m%d-%H%M%S-") + secrets.token_hex(4))
    started = time.monotonic()
    receipt: dict[str, Any] = {
        "status": "failed",
        "stage": "prepare",
        "scope": "synthetic_transport_local_sdk",
        "runtime_validation": "not_run",
        "installed_or_executed": False,
    }
    try:
        builder = load_builder(repository / ".runtime" / "build-acceptance")
        assert builder.probe().enabled, "Configured local Android toolchain is required"
        fixture = FixtureClient()
        password = "synthetic-integration-password"
        settings = Settings(run_root, password_hash(password), allowed_hosts=("testserver",))
        service = JobService(settings, workflow=Workflow(fixture), builder=builder)
        with (
            forbid_target_network() as network_counts,
            TestClient(create_app(settings, service=service), client=("127.0.0.1", 50000)) as web,
        ):
            login = web.post(
                "/api/login", json={"password": password}, headers={"Origin": "http://testserver"}
            )
            assert login.status_code == 200
            headers = {"Origin": "http://testserver", "X-CSRF-Token": login.json()["csrf_token"]}
            owner = service.store.session(token_hash(web.cookies["fxfetch_session"]))["id"]
            receipt["stage"] = "collect"
            submitted = web.post(
                "/api/jobs",
                json={"url": ENTRY},
                headers={**headers, "Idempotency-Key": "integration-download-action"},
            )
            assert submitted.status_code == 202
            job_id = submitted.json()["id"]
            job = wait_value(
                lambda: service.store.get_job(owner, job_id),
                field="state",
                terminal={"completed", "interrupted", "cancelled"},
                timeout=15,
            )
            assert job["state"] == "completed"
            assert job["outcome"] == "failed" and job["reason_code"] == "browser_required"
            assert job["input"]["entry_url"] == ENTRY
            offline = job["result"]["offline"]
            assert offline["available"] and offline["coverage"] == "partial"
            entry = Path(offline["entry"])
            assert entry.is_relative_to(service.store.root)
            assert entry == service.store.root / "jobs" / job_id / "offline" / "site" / "index.html"
            assert entry.is_file()
            assert len(fixture.calls) == 3 and {item["url"] for item in fixture.calls} == set(fixture.routes)
            assert len({item["cookie_jar"] for item in fixture.calls}) == 1
            assert not job["artifacts"] and not job["builds"]
            collected_seconds = time.monotonic() - started

            # This explicit action, rather than collection completion or polling, queues the real build.
            receipt["stage"] = "explicit_build"
            candidate = service.get_job(owner, job_id)["web_candidates"][0]
            build = service.create_build(owner, job_id, "integration-explicit-build", candidate["id"])
            build = wait_value(
                lambda: service.store.get_build(owner, job_id, build["id"]),
                field="state",
                terminal={"built", "failed", "disabled", "cancelled", "interrupted"},
                timeout=120,
            )
            assert build["state"] == "built", build["result"].get("reason_code")
            assert build["result"]["signing_certificate_sha256"]
            assert build["result"]["runtime_validation"] == "not_run"
            after = service.store.get_job(owner, job_id)
            assert after["outcome"] == "failed" and after["reason_code"] == "browser_required"
            assert len(fixture.calls) == 3
            assert len(after["artifacts"]) == 1
            artifact_id = after["artifacts"][0]["id"]
            artifact = service.store.artifact(owner, job_id, artifact_id)
            assert artifact["origin"] == "generated_webview" and artifact["build_id"] == build["id"]
            path = contained_path(service.store.root, artifact["path"])
            assert path.parent == service.store.root / "jobs" / job_id / "generated" / build["id"]

            receipt["stage"] = "registered_download_and_assets"
            response = web.get(f"/api/jobs/{job_id}/artifacts/{artifact_id}")
            assert response.status_code == 200
            assert response.content == path.read_bytes()
            assert hashlib.sha256(response.content).hexdigest() == artifact["sha256"]
            assert len(response.content) == artifact["size"]
            with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
                assert archive.testzip() is None
                config = json.loads(archive.read("assets/config.json"))
                assert config == {"url": ENTRY, "offline": True}
                saved_html = archive.read("assets/site/index.html")
                saved_css = archive.read("assets/site/assets/style.css")
                assert saved_html == entry.read_bytes() and TITLE.encode() in saved_html
                assert b"<script" not in saved_html.lower() and SCRIPT_MARKER.encode() not in saved_html
                assert (
                    b"remote.synthetic.test" not in saved_html
                    and b"external.synthetic.test" not in saved_html
                )
                assert b"#123456" in saved_css and b"font-weight:bold" in saved_css
                image_name = hashlib.sha256(fixture.image).hexdigest() + ".png"
                assert archive.read("assets/site/assets/" + image_name) == fixture.image
                assets = [name for name in archive.namelist() if name.startswith("assets/")]
                assert len(assets) == 4
                assert all(HEADER_MARKER.encode() not in archive.read(name) for name in assets)
                assert not any(
                    name.endswith((".p12", ".keystore", ".har", ".js")) for name in archive.namelist()
                )
            assert network_counts == {"target_dns_attempts": 0, "target_tcp_attempts": 0}
            receipt.update(
                {
                    "status": "passed",
                    "stage": "complete",
                    "job_id": job_id,
                    "build_id": build["id"],
                    "original_outcome": after["outcome"],
                    "original_reason_code": after["reason_code"],
                    "offline_metadata_matches_stored_entry": True,
                    "registered_download_matches_apk": True,
                    "signature_verified_by_builder": True,
                    "sanitized_html_image_css_verified": True,
                    "counts": {
                        "fixture_responses": len(fixture.calls),
                        "html": 1,
                        "images": 1,
                        "css": 1,
                        "original_artifacts": 0,
                        "generated_apks": 1,
                        "apk_assets": len(assets),
                        **network_counts,
                    },
                    "elapsed_collect_seconds": round(collected_seconds, 3),
                    "apk": {
                        "path": str(path.relative_to(repository)),
                        "size": artifact["size"],
                        "sha256": artifact["sha256"],
                    },
                }
            )
        persisted = Store(run_root).get_job(owner, job_id)
        assert persisted["outcome"] == "failed" and len(persisted["artifacts"]) == 1
        receipt["persistence_after_service_close"] = True
    except Exception as error:
        receipt.update(status="failed", exception_type=type(error).__name__)
    receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
    (qa / "result.json").write_text(json.dumps(receipt, ensure_ascii=True, indent=2), encoding="utf-8")
    print(json.dumps(receipt, ensure_ascii=True, separators=(",", ":")))
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(run())
