"""Offline validation of automatic, certificate-error-specific TLS exceptions."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .tls_policy import CERTIFICATE_ERRORS
from .web_evidence_schema import EvidenceError

HTTP_ERRORS = {9: 'certificate_not_yet_valid', 10: 'certificate_expired', 18: 'self_signed_certificate',
               19: 'self_signed_chain', 20: 'issuer_unavailable', 21: 'issuer_unverified',
               23: 'certificate_revoked', 62: 'hostname_mismatch', 64: 'ip_address_mismatch'}
REASONS = frozenset(HTTP_ERRORS.values()) | frozenset(CERTIFICATE_ERRORS.values()) | {'certificate_verification_failed'}


def _context(fields: dict) -> tuple[str, str]:
    values = tuple(fields.get(key) for key in ('collector_id', 'attempt_id'))
    if not all(isinstance(value, str) and 0 < len(value) <= 256 for value in values):
        raise EvidenceError('task_evidence_tls_fallback_context_invalid')
    return values  # type: ignore[return-value]


def _url(fields: dict) -> str:
    value = fields.get('source_url', fields.get('url'))
    if not isinstance(value, str) or not value.startswith('https://') or len(value) > 8192:
        raise EvidenceError('task_evidence_tls_fallback_context_invalid')
    return value


def _reason(fields: dict) -> str:
    reason = fields.get('tls_verify_reason')
    if not isinstance(reason, str) or reason not in REASONS:
        raise EvidenceError('task_evidence_tls_fallback_reason_invalid')
    return reason


def _http_identity(fields: dict) -> tuple:
    ref, address = fields.get('request_ref'), fields.get('connection_ip')
    code = fields.get('tls_verify_code')
    if (not isinstance(ref, str) or not 0 < len(ref) <= 256 or not isinstance(address, str)
        or not 0 < len(address) <= 64 or type(code) is not int or not 0 <= code <= 2**31 - 1):
        raise EvidenceError('task_evidence_tls_fallback_context_invalid')
    try:
        ipaddress.ip_address(address)
    except ValueError as error:
        raise EvidenceError('task_evidence_tls_fallback_context_invalid') from error
    if _reason(fields) != HTTP_ERRORS.get(code, 'certificate_verification_failed'):
        raise EvidenceError('task_evidence_tls_fallback_reason_invalid')
    return _context(fields) + (ref, _url(fields), address, code, _reason(fields))


def _chrome_identity(fields: dict) -> tuple:
    session, event_id = fields.get('session_id'), fields.get('event_id')
    error_type = fields.get('chrome_error_type')
    if (not isinstance(session, str) or not 0 < len(session) <= 256
        or type(event_id) is not int or not 0 <= event_id <= 2**31 - 1
        or not isinstance(error_type, str) or error_type not in CERTIFICATE_ERRORS
        or 'request_ref' in fields):
        raise EvidenceError('task_evidence_tls_fallback_context_invalid')
    if _reason(fields) != CERTIFICATE_ERRORS[error_type]:
        raise EvidenceError('task_evidence_tls_fallback_reason_invalid')
    return _context(fields) + (session, event_id, _url(fields), error_type, _reason(fields))


def validate_auto_tls_policy(rows: list[dict], policy: str) -> dict[str, Any]:
    if policy not in ('strict', 'auto'):
        raise EvidenceError('task_evidence_tls_policy_invalid')
    policies = [row['fields'].get('tls_policy') for row in rows if row['kind'] == 'task_tls_policy']
    if any(value != policy for value in policies):
        raise EvidenceError('task_evidence_tls_policy_mismatch')
    failures: set[tuple] = set()
    chrome_failures: set[tuple] = set()
    chrome_consumed: set[tuple] = set()
    permitted: set[tuple] = set()
    requests: dict[tuple, str] = {}
    http_requests: set[tuple] = set()
    consumed: set[tuple] = set()
    fallbacks: dict[str, tuple[str, tuple]] = {}
    chrome_fallback_contexts: set[tuple] = set()
    reasons: list[str] = []
    uncertain: list[str] = []
    for row in rows:
        fields, kind = row['fields'], row['kind']
        if kind == 'gap' and fields.get('code') in ('tls_policy_continuation_unconfirmed', 'tls_policy_restore_failed'):
            uncertain.append(fields['code'])
        if 'tls_policy' in fields and fields['tls_policy'] != policy:
            raise EvidenceError('task_evidence_tls_policy_mismatch')
        if 'ignore_tls_errors' in fields and (
            type(fields['ignore_tls_errors']) is not bool or fields['ignore_tls_errors'] != (policy == 'auto')
        ):
            raise EvidenceError('task_evidence_tls_policy_mismatch')
        if kind == 'request_attempted' and isinstance(fields.get('request_ref'), str):
            if all(isinstance(fields.get(key), str) for key in ('collector_id', 'attempt_id', 'url')):
                http_requests.add(_context(fields) + (fields['request_ref'], fields['url']))
            if all(isinstance(fields.get(key), str) for key in ('collector_id', 'attempt_id', 'session_id', 'url')):
                requests[_context(fields) + (fields['session_id'], fields['request_ref'])] = fields['url']
        if kind == 'request_permitted' and fields.get('permitted') is True and isinstance(fields.get('session_id'), str):
            context = _context(fields)
            url = fields.get('url')
            if url is None and isinstance(fields.get('request_ref'), str):
                url = requests.get(context + (fields['session_id'], fields['request_ref']))
            if isinstance(url, str):
                permitted.add(context + (fields['session_id'], url))
        if kind == 'tls_verification_failed':
            identity = _http_identity(fields)
            if identity[:4] not in http_requests:
                raise EvidenceError('task_evidence_tls_fallback_unobserved')
            failures.add((identity, fields.get('tls_fallback_id')))
        elif kind == 'tls_certificate_error':
            chrome_failures.add(_chrome_identity(fields))
        elif kind == 'tls_verification_fallback':
            identifier = fields.get('tls_fallback_id')
            if (policy != 'auto' or not policies or not isinstance(identifier, str)
                or not re.fullmatch(r'[0-9a-f]{32}', identifier) or identifier in fallbacks):
                raise EvidenceError('task_evidence_tls_fallback_unapproved')
            if fields.get('association') == 'browser_certificate_event':
                identity = _chrome_identity(fields)
                if (identity not in chrome_failures or identity in chrome_consumed
                    or fields.get('request_association') != 'url_permission_only'
                    or identity[:3] + (identity[4],) not in permitted):
                    raise EvidenceError('task_evidence_tls_fallback_unobserved')
                chrome_consumed.add(identity)
                fallbacks[identifier] = ('chrome', identity)
                chrome_fallback_contexts.add(identity[:2])
            else:
                identity = _http_identity(fields)
                if (identity, identifier) not in failures or identity in consumed:
                    raise EvidenceError('task_evidence_tls_fallback_unobserved')
                consumed.add(identity)
                fallbacks[identifier] = ('http', identity)
            reasons.append(_reason(fields))
        verification = fields.get('tls_verification')
        if verification == 'ignored' and kind != 'tls_verification_fallback':
            identifier = fields.get('tls_fallback_id')
            fallback = fallbacks.get(identifier) if isinstance(identifier, str) else None
            if fallback is None or fallback[0] != 'http':
                raise EvidenceError('task_evidence_tls_fallback_unobserved')
            identity = fallback[1]
            if (_context(fields) != identity[:2] or fields.get('request_ref') != identity[2]
                or _url(fields) != identity[3]
                or ('connection_ip' in fields and fields['connection_ip'] != identity[4])
                or fields.get('tls_verify_code') != identity[5] or fields.get('tls_verify_reason') != identity[6]):
                raise EvidenceError('task_evidence_tls_fallback_context_invalid')
        elif verification == 'unknown':
            if policy != 'auto' or _context(fields) not in chrome_fallback_contexts:
                raise EvidenceError('task_evidence_tls_fallback_unobserved')
        elif verification == 'not_applicable':
            url = fields.get('source_url', fields.get('url'))
            if not isinstance(url, str) or not url.lower().startswith('http://'):
                raise EvidenceError('task_evidence_tls_policy_mismatch')
        elif verification is not None and verification not in ('required', 'verified', 'ignored'):
            raise EvidenceError('task_evidence_tls_policy_mismatch')
    return {'state': 'unavailable' if uncertain else 'recorded', 'count': len(fallbacks), 'observed': bool(fallbacks),
            'reasons': list(dict.fromkeys(reasons + uncertain))[:64]}


def valid_fallback_summary(value: object) -> bool:
    return (isinstance(value, dict) and set(value) == {'state', 'count', 'observed', 'reasons'}
            and value['state'] in ('recorded', 'unavailable', 'pending')
            and type(value['count']) is int and 0 <= value['count'] <= 20000
            and type(value['observed']) is bool and value['observed'] == (value['count'] > 0)
            and isinstance(value['reasons'], list) and len(value['reasons']) <= 64
            and all(isinstance(reason, str) and re.fullmatch(r'[a-z0-9_]{1,128}', reason) for reason in value['reasons']))
