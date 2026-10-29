"""Conservative response roles and bounded, non-sensitive capture diagnostics."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from .cdp_transport import CDPCommandError


def package_response_candidate(url: str, headers: dict[str, str]) -> bool:
    return (
        urlsplit(url).path.lower().endswith((".apk", ".ipa"))
        or "attachment" in headers.get("content-disposition", "").lower()
        or any(
            value in headers.get("content-type", "").lower()
            for value in ("android.package", "application/octet-stream", "application/zip", "iphone")
        )
    )


def disclosed_html_response(url: str, headers: dict[str, str], resource_type: str, selected: bool) -> bool:
    """A selected content page can be served as an attachment by object storage."""
    return (
        selected and resource_type == "Document"
        and not urlsplit(url).path.lower().endswith((".apk", ".ipa"))
        and headers.get("content-type", "").partition(";")[0].strip().lower()
        in {"text/html", "application/xhtml+xml"}
    )


def optional_resource_failure(
    url: str, resource_type: str, headers: dict[str, str], *, network_error: str | None = None,
) -> bool:
    """Never demote an original-package candidate or an executable/API failure.

    Unknown network errors can conceal certificate/policy rejection. Only known
    transport failures of decorative resources are recoverable here; upstream
    gateway policy errors and every global budget remain independently fatal.
    """
    if package_response_candidate(url, headers):
        return False
    favicon = resource_type in {"Image", "Other"} and urlsplit(url).path.lower() == "/favicon.ico"
    if resource_type not in {"Image", "Font", "Stylesheet", "Media"} and not favicon:
        return False
    if network_error is None:
        return True
    if network_error == "Aborted":
        return favicon  # Playwright cancels implicit favicon requests.
    return network_error in {
        "TimedOut", "ConnectionClosed", "ConnectionReset", "ConnectionRefused",
        "ConnectionAborted", "ConnectionFailed", "NameNotResolved", "InternetDisconnected",
        "AddressUnreachable",
    }


def expired_resource_fulfillment(error: CDPCommandError, resource_type: str, url: str,
                                 headers: dict[str, str]) -> bool:
    """Chrome may discard an old decorative request during page navigation."""
    return (
        error.method == "Fetch.fulfillRequest" and error.category == "interception_gone"
        and resource_type in {"Image", "Font", "Stylesheet", "Media"}
        and not package_response_candidate(url, headers)
    )


def expired_resource_dispatch(error: CDPCommandError, resource_type: str, url: str,
                              headers: dict[str, str]) -> bool:
    """Do not fail a new page because Chrome cancelled an old decorative request."""
    return (
        error.category == "interception_gone"
        and error.method in {"Fetch.continueRequest", "Fetch.failRequest", "Fetch.takeResponseBodyAsStream"}
        and optional_resource_failure(url, resource_type, headers)
    )


def write_capture_diagnostic(directory: Path, error: BaseException, phase: str) -> None:
    """Keep one small private receipt, never raw error text, URLs or tokens.

    Traceback source filenames/locals are excluded. Diagnostics must not mask
    the original result, including when the output directory cannot be written.
    """
    # Actionability causes often occur deep in Playwright's multiline call log.
    # Inspect a bounded prefix but persist only fixed classifications.
    text = str(error)[:8192].lower()
    first = text.partition("\n")[0]
    actionability = []
    for markers, code in (
        (("intercepts pointer events",), "pointer_intercepted"),
        (("not stable",), "element_unstable"),
        (("outside viewport", "outside of the viewport"), "element_outside_viewport"),
        (("not visible",), "element_not_visible"),
        (("detached", "not attached to the dom"), "element_detached"),
        (("waiting for scheduled navigations",), "navigation_wait"),
        (("click action done",), "click_dispatched"),
        (("performing click action",), "click_dispatch_started"),
        (("done scrolling",), "scroll_completed"),
        (("element is visible, enabled and stable",), "element_actionable"),
    ):
        if any(marker in text for marker in markers):
            actionability.append(code)
    summary = "unclassified_error"
    for marker, code in (
        ("not attached", "element_detached"), ("detached", "element_detached"),
        ("destroyed", "execution_context_destroyed"), ("invalid url", "invalid_url"),
        ("invalid ipv6", "invalid_url"), ("timed out", "operation_timed_out"),
        ("timeout", "operation_timed_out"), ("target closed", "target_closed"),
        ("out of memory", "memory_exhausted"), ("not valid base64", "invalid_base64"),
    ):
        if marker in first:
            summary = code
            break
    if actionability:
        summary = actionability[0]
    frames = []
    trace = error.__traceback__
    while trace is not None:
        frames.append({"function": trace.tb_frame.f_code.co_name[:80], "line": trace.tb_lineno})
        frames = frames[-8:]
        trace = trace.tb_next
    document = {"exception_type": type(error).__name__[:80], "phase": phase[:40],
                "summary": summary, "frames": frames, "actionability": actionability}
    if isinstance(error, CDPCommandError):
        document["cdp_method"] = error.method
        document["cdp_category"] = error.category
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / "capture-diagnostic.json").open("x", encoding="utf-8") as stream:
            json.dump(document, stream, separators=(",", ":"))
    except OSError:
        return  # Diagnostic failure cannot replace the acquisition failure.
