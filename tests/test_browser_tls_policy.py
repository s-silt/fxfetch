from __future__ import annotations

import asyncio

import pytest

from fxfetch.core.browser_tls_policy import (
    BrowserTLSPolicy,
    certificate_failure_is_critical,
    resolve_tls_policy,
)
from fxfetch.core.errors import FxfetchError

URL = "https://capture.test/download"
EVENT = {"eventId": 1, "errorType": "ERR_CERT_AUTHORITY_INVALID", "requestURL": URL}


def controller(mode="auto", *, fail_method=None, cancelled=False):
    calls, events = [], []

    def check():
        if cancelled:
            raise FxfetchError("cancelled", "Stopped")

    async def send(session, method, params):
        calls.append((session, method, params))
        if method == fail_method:
            raise FxfetchError("browser_cdp_failed", "Unsupported")
        return {}

    policy = BrowserTLSPolicy(policy=mode, check=check, send=send,
                              emit=lambda kind, fields: events.append((kind, fields)))
    return policy, calls, events


def test_auto_continues_only_a_permitted_certificate_event_and_marks_limited_scope():
    async def run():
        policy, calls, events = controller()
        await policy.setup("session")
        policy.approved("session", "fetch1", URL, "network1")
        await policy.certificate_error("session", EVENT)
        assert calls[:3] == [
            ("session", "Security.setIgnoreCertificateErrors", {"ignore": False}),
            ("session", "Security.enable", {}),
            ("session", "Security.setOverrideCertificateErrors", {"override": True}),
        ]
        assert calls[-1] == ("session", "Security.handleCertificateError", {"eventId": 1, "action": "continue"})
        assert [kind for kind, _ in events] == ["tls_certificate_error", "tls_verification_fallback"]
        fallback = events[1][1]
        assert len(fallback["tls_fallback_id"]) == 32 and "request_ref" not in fallback
        assert fallback["association"] == "browser_certificate_event"
        assert fallback["request_association"] == "url_permission_only"
        assert policy.context("session", URL)["tls_verification"] == "unknown"
        assert policy.context("session", "https://good.test/body")["tls_verification"] == "required"
        assert not policy.pending
    asyncio.run(run())


@pytest.mark.parametrize("mode", ["strict", "auto"])
def test_an_observed_error_without_current_url_session_permission_is_never_continued(mode):
    async def run():
        policy, calls, events = controller(mode)
        await policy.setup("session")
        policy.approved("different-session", "fetch1", URL)
        policy.approved("session", "fetch2", "https://other.test/")
        with pytest.raises(FxfetchError, match="no current"):
            await policy.certificate_error("session", EVENT)
        assert calls[-1][2] == {"eventId": 1, "action": "cancel"}
        assert not events and not policy.fallbacks
    asyncio.run(run())


@pytest.mark.parametrize("settle", ["fetch", "network"])
def test_completed_requests_do_not_leave_reusable_tls_permission(settle):
    async def run():
        policy, calls, _ = controller()
        await policy.setup("session")
        policy.approved("session", "fetch1", URL, "network1")
        if settle == "fetch":
            policy.settled("session", "fetch1")
        else:
            policy.network_settled("session", "network1")
        with pytest.raises(FxfetchError):
            await policy.certificate_error("session", EVENT)
        assert calls[-1][2]["action"] == "cancel" and not policy.active and not policy.network
    asyncio.run(run())


def test_strict_observed_certificate_error_records_failure_and_cancels():
    async def run():
        policy, calls, events = controller("strict")
        await policy.setup("session")
        policy.approved("session", "fetch1", URL)
        with pytest.raises(FxfetchError) as caught:
            await policy.certificate_error("session", EVENT)
        assert caught.value.code == "tls_verification_failed"
        assert calls[-1][2]["action"] == "cancel"
        assert [kind for kind, _ in events] == ["tls_certificate_error"]
        assert not policy.fallbacks
    asyncio.run(run())


@pytest.mark.parametrize("error_type", ["ERR_SSL_PROTOCOL_ERROR", "ERR_CONNECTION_TIMED_OUT", "ERR_CERT_INVENTED", "private-error-value"])
def test_unrecognized_or_non_certificate_errors_are_not_allowed(error_type):
    async def run():
        policy, calls, events = controller()
        await policy.setup("session")
        policy.approved("session", "fetch1", URL)
        with pytest.raises(FxfetchError) as caught:
            await policy.certificate_error("session", {**EVENT, "errorType": error_type})
        assert caught.value.code == "browser_tls_error_unsupported"
        assert calls[-1][2]["action"] == "cancel" and not events
    asyncio.run(run())


def test_failed_continuation_retains_error_and_gap_without_claiming_a_fallback():
    async def run():
        policy, _, events = controller(fail_method="Security.handleCertificateError")
        await policy.setup("session")
        policy.approved("session", "fetch1", URL)
        with pytest.raises(FxfetchError):
            await policy.certificate_error("session", EVENT)
        assert [kind for kind, _ in events] == ["tls_certificate_error", "gap"]
        assert events[-1][1]["code"] == "tls_policy_continuation_unconfirmed"
        assert not policy.fallbacks and not policy.affected and policy.pending == {("session", 1)}
    asyncio.run(run())


def test_unsupported_auto_protocol_fails_closed():
    async def run():
        policy, calls, _ = controller(fail_method="Security.setOverrideCertificateErrors")
        with pytest.raises(FxfetchError) as caught:
            await policy.setup("session")
        assert caught.value.code == "browser_tls_policy_unavailable"
        assert not any(method == "Security.setIgnoreCertificateErrors" and params["ignore"] for _, method, params in calls)
    asyncio.run(run())


def test_iframe_keeps_strict_guard_without_top_level_only_security_domain():
    async def run():
        policy, calls, _ = controller()
        await policy.setup("iframe", target_type="iframe")
        assert calls == [("iframe", "Security.setIgnoreCertificateErrors", {"ignore": False})]
    asyncio.run(run())


def test_detached_target_cannot_reuse_old_request_permission():
    async def run():
        policy, calls, _ = controller()
        await policy.setup("session")
        policy.approved("session", "fetch1", URL, "network1")
        policy.detached("session")
        with pytest.raises(FxfetchError):
            await policy.certificate_error("session", EVENT)
        assert not policy.active and not policy.network
        assert not any(params.get("action") == "continue" for _, _, params in calls)
    asyncio.run(run())


@pytest.mark.parametrize("kind", ["Image", "Script", "Stylesheet", "Font", "Other", "Document"])
def test_bystander_certificate_failure_does_not_cancel_a_transferring_package(kind):
    assert not certificate_failure_is_critical("https://other.test/resource", kind, True)
    assert certificate_failure_is_critical("https://capture.test/app.apk", kind, True)


def test_required_entry_tls_failure_still_stops_without_a_package_transfer():
    assert certificate_failure_is_critical(URL, "Document", False)
    assert not certificate_failure_is_critical("https://other.test/resource.js", "Script", False)


def test_cancelled_policy_never_continues():
    async def run():
        policy, calls, _ = controller(cancelled=True)
        policy.sessions.add("session")
        policy.approved("session", "fetch1", URL)
        with pytest.raises(FxfetchError) as caught:
            await policy.certificate_error("session", EVENT)
        assert caught.value.code == "cancelled" and not calls
    asyncio.run(run())


def test_duplicate_events_are_bounded_and_never_continued_twice():
    async def run():
        policy, calls, _ = controller()
        await policy.setup("session")
        policy.approved("session", "fetch1", URL)
        await policy.certificate_error("session", EVENT)
        with pytest.raises(FxfetchError):
            await policy.certificate_error("session", EVENT)
        assert sum(params.get("action") == "continue" for _, _, params in calls) == 1
    asyncio.run(run())


@pytest.mark.parametrize("invalid", [None, 1, "true", [], {}])
def test_legacy_flag_requires_bool_and_never_maps_to_global_ignore(invalid):
    with pytest.raises(ValueError):
        resolve_tls_policy("strict", invalid)
    assert resolve_tls_policy("strict", True) == "auto"
    assert resolve_tls_policy("strict", False) == "strict"
