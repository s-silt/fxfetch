"""Explicit TLS policy admission; old API booleans authorize automatic fallback."""

from __future__ import annotations

from typing import Any, Literal

CERTIFICATE_ERRORS = {
    "ERR_CERT_COMMON_NAME_INVALID": "hostname_mismatch",
    "ERR_CERT_DATE_INVALID": "certificate_date_invalid",
    "ERR_CERT_AUTHORITY_INVALID": "issuer_unverified",
    "ERR_CERT_CONTAINS_ERRORS": "certificate_verification_failed",
    "ERR_CERT_NO_REVOCATION_MECHANISM": "certificate_verification_failed",
    "ERR_CERT_UNABLE_TO_CHECK_REVOCATION": "certificate_verification_failed",
    "ERR_CERT_REVOKED": "certificate_revoked",
    "ERR_CERT_INVALID": "certificate_verification_failed",
    "ERR_CERT_WEAK_SIGNATURE_ALGORITHM": "certificate_verification_failed",
    "ERR_CERT_NON_UNIQUE_NAME": "certificate_verification_failed",
    "ERR_CERT_WEAK_KEY": "certificate_verification_failed",
    "ERR_CERT_NAME_CONSTRAINT_VIOLATION": "certificate_verification_failed",
    "ERR_CERT_VALIDITY_TOO_LONG": "certificate_verification_failed",
    "ERR_CERTIFICATE_TRANSPARENCY_REQUIRED": "certificate_verification_failed",
    "ERR_CERT_SYMANTEC_LEGACY": "certificate_verification_failed",
    "ERR_CERT_KNOWN_INTERCEPTION_BLOCKED": "certificate_verification_failed",
}


def web_tls_policy(value: dict[str, Any]) -> Literal['auto', 'strict']:
    canonical = value.get('tls_policy')
    if 'tls_policy' in value and canonical not in ('auto', 'strict'):
        raise ValueError('tls_policy must be auto or strict')
    legacy = value.get('ignore_tls_errors')
    if 'ignore_tls_errors' in value:
        if type(legacy) is not bool:
            raise ValueError('ignore_tls_errors must be boolean')
        mapped = 'auto' if legacy else 'strict'
        if canonical is not None and canonical != mapped:
            raise ValueError('Conflicting TLS policy fields')
        return mapped
    return 'strict' if canonical == 'strict' else 'auto'
