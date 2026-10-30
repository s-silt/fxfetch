"""Installed Chrome + synthetic local TLS: errors stay enforced, no invented peer DER."""

from __future__ import annotations

import asyncio
import json
import os
import threading
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from browser_tls_profile import CHROME_ARGS
from playwright.async_api import async_playwright
from test_tls_evidence import tls_server as tls_server

from fxfetch.core.browser_capture import BrowserLaunchProof, capture_browser
from fxfetch.core.limits import Limits
from fxfetch.core.web_journal import EvidenceJournal


def test_chrome_rejects_untrusted_local_tls_without_saving_origin_certificate(tls_server, tmp_path):
    port, _, original_der, counts = tls_server
    chrome = Path(os.environ.get("FXFETCH_TEST_CHROME", r"C:\Program Files\Google\Chrome\Application\chrome.exe"))
    if not chrome.is_file():
        pytest.skip("Installed Chrome required; no browser download")
    origin = f"https://localhost:{port}"
    requests = []

    def permit(url, method):
        value = urlsplit(url)
        assert value.scheme == "https" and value.hostname == "localhost" and value.port == port
        assert method in {"GET", "HEAD"}
        requests.append(url)

    async def run():
        profile = tmp_path / "profile"
        journal = EvidenceJournal(tmp_path / "observations.jsonl", "browser", "synthetic-tls")
        async with async_playwright() as driver:
            context = await driver.chromium.launch_persistent_context(
                str(profile), executable_path=str(chrome), headless=True,
                accept_downloads=False, service_workers="block",
                args=CHROME_ARGS,
            )
            control_port = (profile / "DevToolsActivePort").read_text().splitlines()[0]

            class SyntheticLease:
                def verify_before_launch(self):
                    return BrowserLaunchProof(chrome, profile, "unused-with-local-cdp",
                                              cdp_endpoint=f"http://127.0.0.1:{control_port}",
                                              permit_request=permit)

            try:
                result = await capture_browser(origin + "/body", tmp_path / "capture", threading.Event(),
                                               lease=SyntheticLease(), journal=journal,
                                               limits=Limits(chain_timeout=10, read_timeout=3))
                # This origin-only query is observational and never promoted to
                # a connection-bound evidence file, even if Chrome retains DER.
                page = context.pages[-1]
                cdp = await context.new_cdp_session(page)
                chain = await cdp.send("Network.getCertificate", {"origin": origin})
                version = await cdp.send("Browser.getVersion")
                return result, len(chain.get("tableNames", [])), version.get("product")
            finally:
                journal.close()
                await context.close()

    result, origin_chain_count, version = asyncio.run(run())
    rows = [json.loads(line) for line in (tmp_path / "observations.jsonl").read_text().splitlines()]
    assert requests and not counts  # TLS fails before the HTTP handler receives a request.
    assert result.outcome == "failed" and not result.artifacts
    saved = [row["fields"] for row in rows if row["kind"] == "tls_certificate_saved"]
    # A refused TLS handshake may still expose the certificate the server sent.
    # Passive network events never become origin/request-bound TLS proof.
    if saved:
        for item in saved:
            assert item["capture_source"] == "chrome_netlog_ssl_certificates_received"
            assert item["association"] == "browser_network_event" and item["request_association"] == "unknown"
            assert not item.get("source_url") and not item.get("request_ref") and not item.get("origin")
            assert (tmp_path / item["path"]).read_bytes() == original_der
    else:
        assert "tls_certificate_not_captured" in result.gaps
        assert any(row["kind"] == "gap" and row["fields"].get("code") == "tls_certificate_not_captured" for row in rows)
    (tmp_path / "chrome-tls-receipt.json").write_text(json.dumps({
        "passed": True, "chrome": version, "tls_errors_ignored": False,
        "system_trust_modified": False, "http_requests_received": 0,
        "origin_query_chain_count": origin_chain_count,
        "connection_bound_certificates_saved": 0, "passive_certificate_records": len(saved),
        "capture_gaps": result.gaps,
        "outcome": result.outcome, "reason_code": result.reason_code,
    }, indent=2) + "\n", encoding="utf-8")
