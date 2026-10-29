import json

import pytest

from fxfetch.core.browser_response import optional_resource_failure, write_capture_diagnostic


@pytest.mark.parametrize("resource", ["Document", "Script", "XHR", "Fetch", "WebSocket", "Other", ""])
def test_executable_api_or_unknown_resource_cannot_be_demoted(resource):
    assert not optional_resource_failure("https://example.test/missing", resource, {})


@pytest.mark.parametrize("resource", ["Image", "Font", "Stylesheet", "Media"])
def test_decorative_http_failure_can_continue(resource):
    assert optional_resource_failure("https://example.test/missing", resource, {})


@pytest.mark.parametrize("url,headers", [
    ("https://example.test/file.apk", {}), ("https://example.test/file.ipa", {}),
    ("https://example.test/image.png", {"content-disposition": "attachment; filename=file.bin"}),
    ("https://example.test/image.png", {"content-type": "application/vnd.android.package-archive"}),
    ("https://example.test/image.png", {"content-type": "application/octet-stream"}),
])
def test_package_candidate_is_never_optional_even_when_requested_as_image(url, headers):
    assert not optional_resource_failure(url, "Image", headers)


@pytest.mark.parametrize("error", ["Failed", "BlockedByClient", "BlockedByResponse", "AccessDenied", "CertificateError", "Aborted"])
def test_uncertain_or_security_network_errors_are_not_classified_as_optional(error):
    assert not optional_resource_failure("https://example.test/decoration.png", "Image", {}, network_error=error)


def test_implicit_favicon_is_optional_but_navigated_favicon_is_not():
    assert optional_resource_failure("https://example.test/favicon.ico", "Other", {}, network_error="Aborted")
    assert not optional_resource_failure("https://example.test/favicon.ico", "Document", {}, network_error="Aborted")
    assert optional_resource_failure("https://example.test/img.png", "Image", {}, network_error="ConnectionClosed")


def test_private_diagnostic_keeps_frames_and_fixed_reason_without_error_secrets(tmp_path):
    try:
        raise ValueError("invalid URL https://example.test/token-secret?password=secret\nCookie: private")
    except ValueError as error:
        write_capture_diagnostic(tmp_path, error, "capture")
    body = (tmp_path / "capture-diagnostic.json").read_text()
    result = json.loads(body)
    assert result["summary"] == "invalid_url" and result["exception_type"] == "ValueError"
    assert len(body) < 2048 and result["frames"][-1]["function"].startswith("test_private_diagnostic")
    assert all(value not in body for value in ("https", "token-secret", "password=secret", "Cookie", str(tmp_path)))
    write_capture_diagnostic(tmp_path, TimeoutError("raw later text"), "event_handler")
    assert (tmp_path / "capture-diagnostic.json").read_text() == body


def test_diagnostic_write_failure_does_not_replace_acquisition_error(tmp_path):
    blocked = tmp_path / "file"
    blocked.write_text("retained")
    write_capture_diagnostic(blocked, ValueError("private"), "capture")
    assert blocked.read_text() == "retained"


@pytest.mark.parametrize("marker,expected", [
    ("intercepts pointer events", "pointer_intercepted"),
    ("not stable", "element_unstable"),
    ("outside viewport", "element_outside_viewport"),
    ("outside of the viewport", "element_outside_viewport"),
    ("not visible", "element_not_visible"),
    ("detached", "element_detached"),
    ("not attached to the DOM", "element_detached"),
])
def test_diagnostic_classifies_multiline_actionability_without_raw_log(tmp_path, marker, expected):
    error = TimeoutError("Timeout exceeded\n" + "private-padding" * 180 +
                         "\nhttps://synthetic.test/secret-ticket element " + marker)
    write_capture_diagnostic(tmp_path, error, "capture")
    body = (tmp_path / "capture-diagnostic.json").read_text()
    result = json.loads(body)
    assert result["summary"] == expected
    assert result["actionability"] == [expected]
    assert all(secret not in body for secret in ("private-padding", "https", "secret-ticket"))


def test_diagnostic_call_log_inspection_is_bounded(tmp_path):
    write_capture_diagnostic(tmp_path, TimeoutError("Timeout exceeded\n" + "x" * 8192 +
                                                    "intercepts pointer events"), "capture")
    result = json.loads((tmp_path / "capture-diagnostic.json").read_text())
    assert result["summary"] == "operation_timed_out"
    assert result["actionability"] == []


@pytest.mark.parametrize("line,expected", [
    ("waiting for element to be visible, enabled and stable", False),
    ("element is visible, enabled and stable", True),
])
def test_diagnostic_requires_completed_actionability_marker(tmp_path, line, expected):
    write_capture_diagnostic(tmp_path, TimeoutError("Timeout exceeded\n" + line), "capture")
    result = json.loads((tmp_path / "capture-diagnostic.json").read_text())
    assert ("element_actionable" in result["actionability"]) is expected


@pytest.mark.parametrize("method,category,resource,url,mime,expected", [
    ("Fetch.fulfillRequest", "interception_gone", "Image", "/a.png", "image/png", True),
    ("Fetch.fulfillRequest", "interception_gone", "Document", "/", "text/html", False),
    ("Fetch.fulfillRequest", "interception_gone", "Script", "/a.js", "text/javascript", False),
    ("Fetch.fulfillRequest", "interception_gone", "Image", "/a.apk", "image/png", False),
    ("Fetch.fulfillRequest", "interception_gone", "Image", "/a.png", "application/octet-stream", False),
    ("IO.read", "interception_gone", "Image", "/a.png", "image/png", False),
    ("Fetch.fulfillRequest", "session_error", "Image", "/a.png", "image/png", False),
])
def test_only_expired_decorative_fulfillment_can_continue(method, category, resource, url, mime, expected):
    from fxfetch.core.browser_response import expired_resource_fulfillment
    from fxfetch.core.cdp_transport import CDPCommandError

    assert expired_resource_fulfillment(CDPCommandError(method, category), resource,
                                        "https://example.test" + url, {"content-type": mime}) is expected


@pytest.mark.parametrize("selected,resource,url,mime,expected", [
    (True, "Document", "/content.html", "text/html; charset=UTF-8", True),
    (False, "Document", "/content.html", "text/html", False),
    (True, "Document", "/app.apk", "text/html", False),
    (True, "Document", "/content.html", "application/octet-stream", False),
    (True, "XHR", "/content.html", "text/html", False),
])
def test_only_disclosed_html_documents_override_attachment(selected, resource, url, mime, expected):
    from fxfetch.core.browser_response import disclosed_html_response

    assert disclosed_html_response("https://example.test" + url, {"content-type": mime}, resource, selected) is expected
