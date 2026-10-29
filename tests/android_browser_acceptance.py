"""Explicit Android Chrome acceptance through the production lease and a test gate.

Only capture.test/frame.test resolve, and only to the in-process synthetic
origin. All other destinations are rejected without DNS. This test-only class
is never imported by application code and adds no production bypass option.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import threading
import time
import uuid
from collections import Counter
from contextlib import contextmanager
from dataclasses import asdict
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from browser_capture_acceptance import APK, Handler

from fxfetch.core.android_worker import AndroidLease, AndroidWorker, load_worker_config
from fxfetch.core.browser_capture import BrowserLaunchProof, capture_browser
from fxfetch.core.browser_gateway import BrowserGateway
from fxfetch.core.cdp_transport import CDPMux, resolve_endpoint
from fxfetch.core.errors import FxfetchError
from fxfetch.core.limits import Limits

CASES = {
    "js": "/js",
    "cookie": "/api-page",
    "click": "/click",
    "popup": "/popup",
    "iframe": "/iframe",
    "qr": "/qr-page",
    "offline": "/offline",
}

# One non-production identity per explicit test process. Repeated prepared
# cases share the same isolated synthetic gateway, never a production lease.
SYNTHETIC_LEASE_ID = uuid.uuid4().hex


class OriginHandler(Handler):
    def do_GET(self):
        # BrowserGateway preserves Host but converts proxy absolute-form into
        # normal origin-form. Reuse the same synthetic handler after conversion.
        if self.path.startswith("/"):
            self.path = "http://" + self.headers.get("Host", "") + self.path
        super().do_GET()


@contextmanager
def origin():
    server = ThreadingHTTPServer(("127.0.0.1", 0), OriginHandler)
    server.counts = Counter()
    server.stopped = threading.Event()
    server.package_started = threading.Event()
    server.payload = APK
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.stopped.set()
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_gate(origin_port: int, cancel: threading.Event) -> BrowserGateway:
    class SyntheticGateway(BrowserGateway):
        def _destination(self, url: str) -> tuple[str, int]:
            parsed = urlsplit(url)
            if (
                parsed.scheme != "http"
                or parsed.hostname not in {"capture.test", "frame.test"}
                or parsed.port not in {None, 80}
            ):
                raise FxfetchError(
                    "synthetic_destination_denied", "Synthetic gate never resolves or connects upstream"
                )
            self._check()
            return "127.0.0.1", origin_port

    return SyntheticGateway(
        port=18767, timeout=90, max_connections=150, max_wire_bytes=64 * 1024 * 1024, cancel=cancel
    )


@contextmanager
def prepared_synthetic_lease(gateway: BrowserGateway, cancel: threading.Event):
    """One fixed synthetic case before deployment acceptance/config creation.

    The environment owner prepares its isolated Android, deadline and precise
    broker-only firewall rule. This local test never starts or changes that VM.
    It cannot accept a URL, domain, proxy address or arbitrary CDP endpoint.
    """
    endpoint = "http://127.0.0.1:19222"
    control = asyncio.run(probe(endpoint))
    if control.get("status") != "controls_supported" or "Android" not in str(control.get("user_agent", "")):
        raise FxfetchError(
            "synthetic_android_not_ready", "Expected prepared Android Chrome with supported controls"
        )

    class PreparedSyntheticLease:
        def verify_before_launch(self):
            if not gateway.active or gateway.port != 18767 or cancel.is_set():
                raise FxfetchError("synthetic_gate_unavailable", "Fixed synthetic gate is unavailable")
            gateway.arm(SYNTHETIC_LEASE_ID)
            return BrowserLaunchProof(
                Path("unused-by-remote-test"),
                Path("unused-by-remote-test"),
                "http://10.0.2.2:18767",
                cdp_endpoint=endpoint,
                permit_request=lambda url, method: gateway.permit_request(SYNTHETIC_LEASE_ID, url, method),
            )

    yield PreparedSyntheticLease()


async def probe(endpoint: str) -> dict:
    deadline = time.monotonic() + 12

    def check():
        if time.monotonic() >= deadline:
            raise FxfetchError("probe_timeout", "Android CDP probe budget exhausted")

    controls = {}
    mux = await CDPMux.connect(resolve_endpoint(Path("unused"), endpoint), lambda *_: None, check, 3)
    attached = None
    try:
        version = await mux.send(None, "Browser.getVersion")
        targets = await mux.send(None, "Target.getTargets")
        blanks = [
            target
            for target in targets["targetInfos"]
            if target.get("type") == "page" and target.get("url") == "about:blank"
        ]
        result = {
            "product": version.get("product"),
            "protocol_version": version.get("protocolVersion"),
            "user_agent": version.get("userAgent"),
            "blank_pages": len(blanks),
            "controls": controls,
        }
        for method, params in [("Browser.setDownloadBehavior", {"behavior": "deny", "eventsEnabled": True})]:
            try:
                await mux.send(None, method, params)
                controls[method] = "supported"
            except FxfetchError as error:
                controls[method] = error.code
        if len(blanks) != 1:
            result["status"] = "blank_target_unavailable"
            return result
        attached = (
            await mux.send(
                None, "Target.attachToTarget", {"targetId": blanks[0]["targetId"], "flatten": True}
            )
        )["sessionId"]
        for method, params in [
            ("Page.enable", {}),
            ("Network.enable", {}),
            ("Network.setBypassServiceWorker", {"bypass": True}),
            ("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Response"}]}),
        ]:
            try:
                await mux.send(attached, method, params)
                controls[method] = "supported"
            except FxfetchError as error:
                controls[method] = error.code
        await mux.send(attached, "Fetch.disable")
        await mux.send(None, "Target.detachFromTarget", {"sessionId": attached})
        attached = None
        result["status"] = (
            "controls_supported"
            if all(value == "supported" for value in controls.values())
            else "unsupported_control"
        )
        return result
    finally:
        # No navigation has occurred. Detaching removes this probe's interceptors.
        if attached is not None:
            try:
                await mux.send(None, "Target.detachFromTarget", {"sessionId": attached})
            except FxfetchError:
                controls["detach"] = "failed"
        await mux.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe-only", action="store_true")
    parser.add_argument(
        "--prepared-synthetic-endpoint",
        action="store_true",
        help="Run exactly one fixed synthetic case against the environment-owner prepared Android",
    )
    parser.add_argument("--cdp-endpoint", default="http://127.0.0.1:19222")
    parser.add_argument("--worker-config-root", type=Path, default=Path(".runtime/service"))
    parser.add_argument("--output", type=Path, default=Path(".runtime/android-browser-acceptance"))
    parser.add_argument(
        "--cases", nargs="+", choices=CASES, default=["js", "cookie", "click", "popup", "iframe"]
    )
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.probe_only:
        try:
            result = asyncio.run(probe(args.cdp_endpoint))
        except FxfetchError as error:
            result = {
                "status": "failed",
                "reason_code": error.code,
                "cause_type": type(error.__cause__).__name__ if error.__cause__ else None,
            }
        (args.output / "probe.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result))
        if result["status"] != "controls_supported":
            raise SystemExit(1)
        return
    if args.prepared_synthetic_endpoint and (
        len(args.cases) != 1 or args.cdp_endpoint != "http://127.0.0.1:19222"
    ):
        raise SystemExit(
            "Prepared synthetic acceptance requires one case and the fixed Android control endpoint"
        )
    config = None if args.prepared_synthetic_endpoint else load_worker_config(args.worker_config_root)
    if config is None and not args.prepared_synthetic_endpoint:
        raise SystemExit("No independently prepared Android worker configuration")
    worker = AndroidWorker(config) if config is not None else None
    rows = []
    with origin() as server:
        for name in args.cases:
            cancel = threading.Event()
            server.counts.clear()
            events = []
            started = time.monotonic()
            with test_gate(server.server_port, cancel) as gateway:
                lease_manager = (
                    AndroidLease(worker, gateway, cancel, 75)
                    if worker is not None
                    else prepared_synthetic_lease(gateway, cancel)
                )
                with lease_manager as lease:
                    result = asyncio.run(
                        capture_browser(
                            "http://capture.test" + CASES[name],
                            args.output / name,
                            cancel,
                            lease=lease,
                            limits=Limits(chain_timeout=60, read_timeout=10),
                            on_event=events.append,
                        )
                    )
                connections, wire_bytes = gateway.connections, gateway.wire_bytes
            outcome = "downloaded" if name != "offline" else "failed"
            passed = result.outcome == outcome and (
                bool(result.artifacts) if name != "offline" else result.offline.get("available") is True
            )
            if result.artifacts:
                passed = passed and result.artifacts[0].sha256 == hashlib.sha256(APK).hexdigest()
            row = {
                "case": name,
                "environment": "production_lease" if worker is not None else "prepared_synthetic_only",
                "passed": passed,
                "seconds": round(time.monotonic() - started, 3),
                "outcome": result.outcome,
                "reason_code": result.reason_code,
                "origin_requests": dict(server.counts),
                "gateway_connections": connections,
                "gateway_wire_bytes": wire_bytes,
            }
            rows.append(row)
            (args.output / f"{name}.json").write_text(
                json.dumps(
                    {"summary": row, "result": asdict(result), "events": events},
                    indent=2,
                    default=str,
                ),
                encoding="utf-8",
            )
            print(json.dumps(row), flush=True)
            if not passed:
                break
    (args.output / "result.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    if not all(row["passed"] for row in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
