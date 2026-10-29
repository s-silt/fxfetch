"""Deterministic CDP/Playwright doubles for browser evidence tests."""

from __future__ import annotations

import asyncio
import base64
import re
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from fxfetch.core import browser_capture
from fxfetch.core.browser_capture import BrowserLaunchProof
from fxfetch.core.cdp_transport import CDPCommandError
from fxfetch.core.limits import Limits


class RecordingJournal:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.failed = False
        self.gaps: list[str] = []
        self.rows: list[tuple[str, dict[str, object]]] = []

    def append(self, kind: str, fields: dict[str, object]) -> bool:
        self.rows.append((kind, fields))
        return True


class _Frame:
    def __init__(self, url: str, html: str) -> None:
        self.url = url
        self.html = html

    async def evaluate(self, *_: object) -> dict[str, object]:
        return {
            "html": self.html,
            "visible": "",
            "base": self.url,
            "ready": "complete",
            "links": [],
        }

    def locator(self, *_: object) -> _Locator:
        return _Locator()


class _Locator:
    async def count(self) -> int:
        return 0

    async def element_handles(self) -> list[object]:
        return []


class _Page:
    def __init__(self, url: str, html: str) -> None:
        self.url = url
        self.frames = [_Frame(url, html)]
        self.context: _Context

    def is_closed(self) -> bool:
        return False

    def on(self, *_: object) -> None:
        pass

    async def evaluate(self, expression: str, *_: object) -> str:
        if "outerHTML" in expression:
            return self.frames[0].html
        if "innerText" in expression:
            visible = re.sub(
                r"(?is)<(?:script|style|noscript)\b[^>]*>.*?</(?:script|style|noscript)>",
                " ",
                self.frames[0].html,
            )
            return re.sub(r"(?s)<[^>]*>", " ", visible)
        return ""


class _SnapshotCDP:
    def __init__(self, target_id: str, counters: dict[str, dict[str, int]]) -> None:
        self.target_id = target_id
        self.counters = counters

    async def send(self, method: str, *_: object) -> dict[str, object]:
        if method != "Target.getTargetInfo":
            raise AssertionError(f"unexpected snapshot CDP method: {method}")
        values = self.counters["snapshot_target_info"]
        values["count"] = values.get("count", 0) + 1
        return {"targetInfo": {"targetId": self.target_id}}

    async def detach(self) -> None:
        values = self.counters["snapshot_detach"]
        values["count"] = values.get("count", 0) + 1


class _Context:
    def __init__(self, page: _Page, counters: dict[str, dict[str, int]]) -> None:
        self.pages = [page]
        self.counters = counters
        page.context = self

    def on(self, *_: object) -> None:
        pass

    async def new_cdp_session(self, page: _Page) -> _SnapshotCDP:
        if page is not self.pages[0]:
            raise AssertionError("snapshot CDP session requested for unknown page")
        values = self.counters["snapshot_session"]
        values["count"] = values.get("count", 0) + 1
        return _SnapshotCDP("target-1", self.counters)

    async def route(self, *_: object) -> None:
        pass

    async def close(self) -> None:
        pass


class _Browser:
    def __init__(self, context: _Context) -> None:
        self.contexts = [context]

    async def close(self) -> None:
        pass


class _Playwright:
    def __init__(self, browser: _Browser) -> None:
        self.chromium = _Chromium(browser)


class _Chromium:
    def __init__(self, browser: _Browser) -> None:
        self.browser = browser

    async def connect_over_cdp(self, *_: object, **__: object) -> _Browser:
        return self.browser


class _PlaywrightManager:
    def __init__(self, browser: _Browser) -> None:
        self.browser = browser

    async def __aenter__(self) -> _Playwright:
        return _Playwright(self.browser)

    async def __aexit__(self, *_: object) -> None:
        pass


class _Mux:
    def __init__(
        self,
        callback,
        *,
        entry_url: str,
        final_url: str,
        body: bytes,
        headers: dict[str, str],
        redirect: bool,
        chunk_sizes: Sequence[int],
        stream_failure_after: int | None,
        counters: dict[str, dict[str, int]],
    ) -> None:
        self.callback = callback
        self.entry_url = entry_url
        self.final_url = final_url
        self.body = body
        self.headers = headers
        self.redirect = redirect
        self.chunk_sizes = tuple(chunk_sizes)
        self.stream_failure_after = stream_failure_after
        self.counters = counters
        self.response_seen: set[str] = set()
        self.stream_handles: dict[str, str] = {}
        self.stream_offsets: dict[str, int] = {}
        self.stream_reads: dict[str, int] = {}
        self.chunk_indices: dict[str, int] = {}

    @classmethod
    async def connect(
        cls,
        _endpoint,
        callback,
        *_: object,
        entry_url: str,
        final_url: str,
        body: bytes,
        headers: dict[str, str],
        redirect: bool,
        chunk_sizes: Sequence[int],
        stream_failure_after: int | None,
        counters: dict[str, dict[str, int]],
    ) -> _Mux:
        return cls(
            callback,
            entry_url=entry_url,
            final_url=final_url,
            body=body,
            headers=headers,
            redirect=redirect,
            chunk_sizes=chunk_sizes,
            stream_failure_after=stream_failure_after,
            counters=counters,
        )

    async def send(
        self,
        session: str | None,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, object]:
        params = params or {}
        if method == "Target.setAutoAttach" and session is None:
            self.callback(
                "session-1",
                "Target.attachedToTarget",
                {"targetInfo": {"targetId": "target-1", "type": "page", "url": "about:blank"}},
            )
        elif method == "Target.getTargets":
            return {
                "targetInfos": [
                    {"targetId": "target-1", "type": "page", "url": "about:blank"}
                ]
            }
        elif method == "Page.getFrameTree":
            return {"frameTree": {"frame": {"id": "frame-1", "url": self.entry_url}}}
        elif method == "Page.navigate":
            self.callback(
                session,
                "Page.frameNavigated",
                {"frame": {"id": "frame-1", "url": self.entry_url}},
            )
            self._network_request(session, "network-1", self.entry_url)
            self._request(session, "request-1", self.entry_url)
            return {"frameId": "frame-1"}
        elif method in {"Fetch.continueRequest", "Fetch.continueResponse"}:
            self._continue(session, str(params["requestId"]))
        elif method == "Fetch.takeResponseBodyAsStream":
            request_id = str(params["requestId"])
            count = self._increment("stream", request_id)
            if count > 1:
                raise AssertionError(f"response stream consumed twice: {request_id}")
            handle = f"stream-{request_id}"
            self.stream_handles[handle] = request_id
            self.stream_offsets[handle] = 0
            self.stream_reads[handle] = 0
            self.chunk_indices[handle] = 0
            return {"stream": handle}
        elif method == "IO.read":
            return self._read(str(params["handle"]), int(params.get("size", 1)))
        elif method == "IO.close":
            return {}
        elif method == "Fetch.fulfillRequest":
            request_id = str(params["requestId"])
            count = self._increment("fulfill", request_id)
            if count > 1:
                raise AssertionError(f"response fulfilled twice: {request_id}")
        return {}

    def _continue(self, session: str | None, request_id: str) -> None:
        if request_id in self.response_seen:
            count = self._increment("response_continue", request_id)
            if count > 1:
                raise AssertionError(f"response continued twice: {request_id}")
            if self.redirect and request_id == "request-1":
                self._network_request(session, "network-2", self.final_url, redirected=True)
                self._request(session, "request-2", self.final_url, redirected="request-1")
            return

        count = self._increment("request_continue", request_id)
        if count > 1:
            raise AssertionError(f"request continued twice: {request_id}")
        self._response(
            session,
            request_id,
            self.entry_url if request_id == "request-1" else self.final_url,
            302 if self.redirect and request_id == "request-1" else 200,
            {"Location": "/page"} if self.redirect and request_id == "request-1" else self.headers,
        )

    def _read(self, handle: str, requested: int) -> dict[str, object]:
        reads = self.stream_reads[handle]
        if self.stream_failure_after is not None and reads >= self.stream_failure_after:
            raise CDPCommandError("IO.read", "synthetic_midstream_failure")
        self.stream_reads[handle] = reads + 1
        offset = self.stream_offsets[handle]
        if offset >= len(self.body):
            return {"data": "", "base64Encoded": True, "eof": True}
        index = self.chunk_indices[handle]
        configured = self.chunk_sizes[min(index, len(self.chunk_sizes) - 1)]
        take = min(configured, requested, len(self.body) - offset)
        if take <= 0:
            raise AssertionError("synthetic CDP returned an empty non-EOF chunk")
        raw = self.body[offset : offset + take]
        self.stream_offsets[handle] = offset + take
        self.chunk_indices[handle] = index + 1
        return {
            "data": base64.b64encode(raw).decode("ascii"),
            "base64Encoded": True,
            "eof": offset + take == len(self.body),
        }

    def _increment(self, category: str, request_id: str) -> int:
        values = self.counters[category]
        values[request_id] = values.get(request_id, 0) + 1
        return values[request_id]

    def _network_request(
        self,
        session: str | None,
        network_id: str,
        url: str,
        *,
        redirected: bool = False,
    ) -> None:
        value: dict[str, object] = {
            "requestId": network_id,
            "request": {"url": url, "method": "GET"},
            "documentURL": self.entry_url,
            "frameId": "frame-1",
            "loaderId": "loader-1",
            "type": "Document",
            "initiator": {"type": "other"},
        }
        if redirected:
            value["redirectResponse"] = {
                "url": self.entry_url,
                "status": 302,
                "headers": {"Location": "/page"},
            }
        self.callback(session, "Network.requestWillBeSent", value)

    def _request(
        self,
        session: str | None,
        request_id: str,
        url: str,
        redirected: str | None = None,
    ) -> None:
        value: dict[str, object] = {
            "requestId": request_id,
            "networkId": f"network-{request_id[-1]}",
            "request": {"url": url, "method": "GET"},
            "resourceType": "Document",
            "frameId": "frame-1",
        }
        if redirected is not None:
            value["redirectedRequestId"] = redirected
        self.callback(session, "Fetch.requestPaused", value)

    def _response(
        self,
        session: str | None,
        request_id: str,
        url: str,
        status: int,
        headers: dict[str, str],
    ) -> None:
        self.response_seen.add(request_id)
        self.callback(
            session,
            "Fetch.requestPaused",
            {
                "requestId": request_id,
                "networkId": f"network-{request_id[-1]}",
                "request": {"url": url, "method": "GET"},
                "resourceType": "Document",
                "frameId": "frame-1",
                "responseStatusCode": status,
                "responseHeaders": [
                    {"name": key, "value": value} for key, value in headers.items()
                ],
            },
        )

    async def close(self) -> None:
        pass


class _Lease:
    def __init__(self, profile: Path) -> None:
        self.profile = profile

    def verify_before_launch(self) -> BrowserLaunchProof:
        return BrowserLaunchProof(
            Path("chrome"),
            self.profile,
            "",
            cdp_endpoint="ws://127.0.0.1:9222/devtools/browser",
            permit_request=lambda _url, _method: None,
        )


def run_browser_capture(
    tmp_path: Path,
    monkeypatch,
    *,
    body: bytes = b"<html>synthetic</html>",
    rendered_html: str | None = None,
    headers: dict[str, str] | None = None,
    purpose: str = "package",
    redirect: bool = True,
    chunk_sizes: Sequence[int] = (4,),
    stream_failure_after: int | None = None,
    include_content_length: bool = True,
    limits: Limits | None = None,
    journal: Any | None = None,
    observation_context: dict[str, str] | None = None,
) -> tuple[Any, list[tuple[str, dict[str, object]]], dict[str, dict[str, int]], Path]:
    entry_url = "https://capture.synthetic.test/old" if redirect else "https://capture.synthetic.test/page"
    final_url = "https://capture.synthetic.test/page"
    response_headers = dict(headers or {"Content-Type": "text/html"})
    if include_content_length:
        response_headers.setdefault("Content-Length", str(len(body)))
    html = rendered_html or "<html><body>synthetic</body></html>"
    recording_journal = journal or RecordingJournal(tmp_path / "task-observations.jsonl")
    context = observation_context or {
        "collector_id": "browser",
        "attempt_id": "browser-attempt-1",
    }
    counters: dict[str, dict[str, int]] = {
        "request_continue": {},
        "response_continue": {},
        "stream": {},
        "fulfill": {},
        "snapshot_session": {},
        "snapshot_target_info": {},
        "snapshot_detach": {},
    }
    page = _Page(final_url, html)
    browser = _Browser(_Context(page, counters))

    async def connect(
        endpoint,
        callback,
        *_: object,
    ) -> _Mux:
        return _Mux(
            callback,
            entry_url=entry_url,
            final_url=final_url,
            body=body,
            headers=response_headers,
            redirect=redirect,
            chunk_sizes=chunk_sizes,
            stream_failure_after=stream_failure_after,
            counters=counters,
        )

    monkeypatch.setattr(browser_capture, "async_playwright", lambda: _PlaywrightManager(browser))
    monkeypatch.setattr(
        browser_capture,
        "resolve_endpoint",
        lambda *_: "ws://127.0.0.1:9222/devtools/browser",
    )
    monkeypatch.setattr(browser_capture.CDPMux, "connect", connect)
    monkeypatch.setattr(browser_capture, "MAX_NO_PROGRESS_SECONDS", 0.05)
    output_dir = tmp_path / "browser"
    result = asyncio.run(
        browser_capture.capture_browser(
            final_url if not redirect else entry_url,
            output_dir,
            threading.Event(),
            lease=_Lease(tmp_path / "profile"),
            limits=limits or Limits(chain_timeout=4, read_timeout=1),
            purpose=purpose,
            journal=recording_journal,
            observation_context=context,
        )
    )
    return result, list(getattr(recording_journal, "rows", [])), counters, output_dir
