"""Offline contracts for connection certificates versus Chrome origin snapshots."""

from __future__ import annotations

import math
import re
import time
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from .errors import FxfetchError
from .guard import validate_url
from .web_evidence_schema import EvidenceError

CHROME_CERTIFICATE_SOURCE = 'chrome_cdp_network_get_certificate'
CHROME_CERTIFICATE_FIELDS = frozenset({
    'session_id', 'target_id', 'collector_id', 'attempt_id', 'origin', 'observed_at', 'captured_at',
    'chain_index', 'chain_length', 'chain_complete',
})
NETLOG_CERTIFICATE_SOURCE = 'chrome_netlog_ssl_certificates_received'
NETLOG_CERTIFICATE_FIELDS = frozenset({
    'collector_id', 'attempt_id', 'trace_id', 'trace_started_at', 'captured_at',
    'netlog_source_id', 'netlog_source_type', 'netlog_pid', 'netlog_event_name', 'netlog_timestamp',
    'chain_index', 'chain_length', 'chain_complete',
})
CHROME_CERTIFICATE_SOURCES = {CHROME_CERTIFICATE_SOURCE, NETLOG_CERTIFICATE_SOURCE}


def validate_task_tls_policy(rows: list[dict], ignore_tls_errors: bool) -> None:
    if type(ignore_tls_errors) is not bool:
        raise EvidenceError('task_evidence_tls_policy_invalid')
    policies = [row['fields'].get('ignore_tls_errors') for row in rows if row['kind'] == 'task_tls_policy']
    if any(type(policy) is not bool or policy is not ignore_tls_errors for policy in policies):
        raise EvidenceError('task_evidence_tls_policy_mismatch')
    for row in rows:
        fields = row['fields']
        if 'ignore_tls_errors' in fields and (
            type(fields['ignore_tls_errors']) is not bool or fields['ignore_tls_errors'] is not ignore_tls_errors
        ):
            raise EvidenceError('task_evidence_tls_policy_mismatch')
        if 'tls_verification' in fields:
            verification = fields['tls_verification']
            if verification == 'not_applicable':
                url = fields.get('source_url', fields.get('url'))
                if not isinstance(url, str) or not url.lower().startswith('http://'):
                    raise EvidenceError('task_evidence_tls_policy_mismatch')
            elif (not isinstance(verification, str) or verification not in {'ignored', 'required', 'verified'}
                  or (verification == 'ignored') is not ignore_tls_errors):
                raise EvidenceError('task_evidence_tls_policy_mismatch')
    ignored = any(row['fields'].get('tls_verification') == 'ignored'
                  or row['fields'].get('ignore_tls_errors') is True
                  or row['fields'].get('capture_source') == 'unverified_tls_socket' for row in rows)
    if ignored and (not ignore_tls_errors or not policies):
        raise EvidenceError('task_evidence_tls_policy_unrecorded')


def validate_netlog_context(value: dict[str, Any]) -> None:
    if (value.get('capture_source') != NETLOG_CERTIFICATE_SOURCE
        or value.get('association') != 'browser_network_event'
        or value.get('request_association') != 'unknown' or value.get('source_url') != ''
        or any(key in value for key in ('request_ref', 'url', 'origin', 'session_id', 'target_id'))
        or value.get('netlog_source_type') != 'SOCKET'
        or value.get('netlog_event_name') != 'SSL_CERTIFICATES_RECEIVED'):
        raise EvidenceError('task_evidence_certificate_netlog_invalid')
    if not isinstance(value.get('trace_id'), str) or not re.fullmatch(r'[0-9a-f]{32}', value['trace_id']):
        raise EvidenceError('task_evidence_certificate_netlog_invalid')
    for key in ('collector_id', 'attempt_id', 'netlog_source_id'):
        item = value.get(key)
        if not isinstance(item, str) or not 1 <= len(item) <= 256 or any(ord(character) < 32 for character in item):
            raise EvidenceError('task_evidence_certificate_netlog_invalid')
    if (type(value.get('netlog_pid')) is not int or not 0 < value['netlog_pid'] < 2**32
        or type(value.get('netlog_timestamp')) not in {int, float}
        or not 0 <= value['netlog_timestamp'] <= 1e20 or not math.isfinite(value['netlog_timestamp'])
        or type(value.get('chain_length')) is not int or not 1 <= value['chain_length'] <= 4096
        or _timestamp(value.get('captured_at')) < _timestamp(value.get('trace_started_at'))):
        raise EvidenceError('task_evidence_certificate_netlog_invalid')


def validate_netlog_certificate(value: dict[str, Any]) -> None:
    validate_netlog_context(value)
    index = value.get('chain_index')
    if (type(index) is not int or not 0 <= index < min(value['chain_length'], 8)
        or type(value.get('chain_complete')) is not bool
        or value.get('cert_role') != ('leaf' if index == 0 else 'chain_member')):
        raise EvidenceError('task_evidence_certificate_chain_invalid')


def netlog_chain_key(record: dict[str, Any]) -> tuple:
    return tuple(record[key] for key in ('trace_id', 'netlog_pid', 'netlog_source_id', 'netlog_timestamp',
                                        'collector_id', 'attempt_id'))


def certificate_origin(url: str) -> str:
    try:
        value = urlsplit(validate_url(url))
        if value.scheme != 'https' or not value.hostname:
            raise ValueError('HTTPS origin required')
        host = value.hostname.lower()
        host = '[' + host + ']' if ':' in host else host
        return 'https://' + host + (f':{value.port}' if value.port not in {None, 443} else '')
    except (FxfetchError, ValueError, TypeError) as error:
        raise EvidenceError('task_evidence_certificate_origin_invalid') from error


def _timestamp(value: object) -> datetime:
    try:
        if not isinstance(value, str) or len(value) > 64:
            raise ValueError
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise ValueError
        return parsed
    except ValueError as error:
        raise EvidenceError('task_evidence_certificate_time_invalid') from error


def validate_chrome_certificate(value: dict[str, Any]) -> None:
    if (
        value.get('capture_source') != CHROME_CERTIFICATE_SOURCE
        or value.get('association') != 'origin_snapshot'
        or value.get('request_association') != 'observation_trigger_only'
        or value.get('origin') != certificate_origin(value.get('source_url', value.get('url', '')))
    ):
        raise EvidenceError('task_evidence_certificate_origin_invalid')
    for key in ('session_id', 'target_id', 'collector_id', 'attempt_id', 'request_ref'):
        item = value.get(key)
        if not isinstance(item, str) or not 1 <= len(item) <= 256 or any(ord(character) < 32 for character in item):
            raise EvidenceError('task_evidence_certificate_context_invalid')
    if _timestamp(value.get('captured_at')) < _timestamp(value.get('observed_at')):
        raise EvidenceError('task_evidence_certificate_time_invalid')
    index, length = value.get('chain_index'), value.get('chain_length')
    if (type(index) is not int or type(length) is not int or not 1 <= length <= 4096
        or not 0 <= index < min(length, 8) or type(value.get('chain_complete')) is not bool
        or value.get('cert_role') != ('leaf' if index == 0 else 'chain_member')):
        raise EvidenceError('task_evidence_certificate_chain_invalid')


def chrome_chain_key(record: dict[str, Any]) -> tuple:
    return tuple(record[key] for key in ('session_id', 'target_id', 'origin', 'collector_id', 'attempt_id',
                                        'request_ref', 'observed_at'))


def validate_chrome_chains(records: list[dict[str, Any]]) -> bool:
    """Reject conflicting groups; incomplete, explicitly partial chains are valid."""
    groups: dict[tuple, tuple[int, bool, str, set[int]]] = {}
    partial = False
    for record in records:
        if record.get('capture_source') not in CHROME_CERTIFICATE_SOURCES:
            continue
        if record['capture_source'] == NETLOG_CERTIFICATE_SOURCE:
            validate_netlog_certificate(record)
            key = (NETLOG_CERTIFICATE_SOURCE,) + netlog_chain_key(record)
        else:
            validate_chrome_certificate(record)
            key = (CHROME_CERTIFICATE_SOURCE,) + chrome_chain_key(record)
        length, complete, captured = record['chain_length'], record['chain_complete'], record['captured_at']
        previous = groups.setdefault(key, (length, complete, captured, set()))
        if previous[:3] != (length, complete, captured) or record['chain_index'] in previous[3]:
            raise EvidenceError('task_evidence_certificate_chain_conflict')
        previous[3].add(record['chain_index'])
    for length, complete, _, indices in groups.values():
        if complete and (length > 8 or len(indices) != length or indices != set(range(length))):
            raise EvidenceError('task_evidence_certificate_chain_incomplete')
        partial |= not complete
    return partial


def validate_chrome_provenance(rows: list[dict], attachments: list[dict], deadline: float | None) -> None:
    """Origin snapshots require a matching request, response, and saved event."""
    requests: set[tuple] = set()
    responses: set[tuple] = set()
    saved: set[tuple] = set()
    context_fields = ('request_ref', 'session_id', 'target_id', 'collector_id', 'attempt_id')
    proof_fields = tuple(sorted(CHROME_CERTIFICATE_FIELDS)) + (
        'request_ref', 'cert_role', 'request_association', 'capture_source', 'association')

    def bounded() -> None:
        if deadline is not None and time.monotonic() >= deadline:
            raise EvidenceError('task_evidence_seal_timeout')

    for row in rows:
        bounded()
        fields = row['fields']
        url = fields.get('source_url', fields.get('url'))
        context = tuple(fields.get(key) for key in context_fields) + (url,)
        if not all(isinstance(value, str) and value for value in context):
            continue
        if row['kind'] in {'request_attempted', 'network_request_observed'}:
            requests.add(context)
        elif row['kind'] == 'response_observed' and type(fields.get('status')) is int and 100 <= fields['status'] <= 599:
            observed = fields.get('observed_at')
            if isinstance(observed, str):
                responses.add(context + (observed,))
        elif row['kind'] == 'tls_certificate_saved' and fields.get('capture_source') == CHROME_CERTIFICATE_SOURCE:
            validate_chrome_certificate(fields)
            if (fields.get('complete') is not True or fields.get('representation') != 'tls_certificate_der'
                or fields.get('sha256') != fields.get('tls_der_sha256')
                or not isinstance(fields.get('path'), str) or type(fields.get('size')) is not int
                or not isinstance(fields.get('sha256'), str)):
                continue
            saved.add(tuple(fields[key] for key in proof_fields)
                      + (fields['path'], fields['size'], fields['sha256'], url, fields.get('tls_verification')))
    for item in attachments:
        bounded()
        if item.get('capture_source') != CHROME_CERTIFICATE_SOURCE:
            continue
        context = tuple(item[key] for key in context_fields) + (item['source_url'],)
        proof = tuple(item[key] for key in proof_fields) + (
            item['source_path'], item['size'], item['sha256'], item['source_url'], item.get('tls_verification'))
        if (context not in requests or context + (item['observed_at'],) not in responses or proof not in saved):
            raise EvidenceError('task_evidence_certificate_binding_invalid')


def validate_netlog_provenance(rows: list[dict], attachments: list[dict], deadline: float | None) -> None:
    observations: dict[tuple, tuple[tuple, frozenset[tuple]]] = {}
    saved: set[tuple] = set()
    context_keys = tuple(sorted(NETLOG_CERTIFICATE_FIELDS - {'chain_index', 'chain_complete'}))
    proof_keys = tuple(sorted(NETLOG_CERTIFICATE_FIELDS)) + ('cert_role', 'size', 'sha256')
    for row in rows:
        if deadline is not None and time.monotonic() >= deadline:
            raise EvidenceError('task_evidence_seal_timeout')
        fields = row['fields']
        if fields.get('capture_source') != NETLOG_CERTIFICATE_SOURCE:
            continue
        if row['kind'] == 'tls_certificate_observed':
            validate_netlog_context(fields)
            members = fields.get('certificate_members')
            if not isinstance(members, list) or len(members) > 8:
                raise EvidenceError('task_evidence_certificate_netlog_invalid')
            proof = set()
            indices = set()
            for member in members:
                if (not isinstance(member, dict) or set(member) != {'chain_index', 'size', 'sha256'}
                    or type(member['chain_index']) is not int or not 0 <= member['chain_index'] < min(fields['chain_length'], 8)
                    or type(member['size']) is not int or not 0 < member['size'] <= 1024 * 1024
                    or not isinstance(member['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', member['sha256'])
                    or member['chain_index'] in indices):
                    raise EvidenceError('task_evidence_certificate_netlog_invalid')
                indices.add(member['chain_index'])
                proof.add((member['chain_index'], member['size'], member['sha256']))
            key = netlog_chain_key(fields)
            value = (tuple(fields[key] for key in context_keys), frozenset(proof))
            if key in observations:
                raise EvidenceError('task_evidence_certificate_chain_conflict')
            observations[key] = value
        elif row['kind'] == 'tls_certificate_saved':
            validate_netlog_certificate(fields)
            if (fields.get('complete') is True and fields.get('representation') == 'tls_certificate_der'
                and fields.get('sha256') == fields.get('tls_der_sha256')
                and isinstance(fields.get('path'), str) and type(fields.get('size')) is int
                and isinstance(fields.get('sha256'), str)):
                saved.add(tuple(fields[key] for key in proof_keys) + (fields['path'], fields.get('tls_verification')))
    for item in attachments:
        if deadline is not None and time.monotonic() >= deadline:
            raise EvidenceError('task_evidence_seal_timeout')
        if item.get('capture_source') != NETLOG_CERTIFICATE_SOURCE:
            continue
        observation = observations.get(netlog_chain_key(item))
        if (observation is None or observation[0] != tuple(item[key] for key in context_keys)
            or (item['chain_index'], item['size'], item['sha256']) not in observation[1]
            or tuple(item[key] for key in proof_keys) + (item['source_path'], item.get('tls_verification')) not in saved):
            raise EvidenceError('task_evidence_certificate_binding_invalid')


def tls_capture_summary(rows: list[dict], attachments: list[dict], gaps: list[str]) -> dict[str, Any]:
    certificates = [item for item in attachments if item.get('kind') == 'certificate']
    http_count = sum(item.get('capture_source') in {'verified_tls_socket', 'unverified_tls_socket'} for item in certificates)
    chrome_count = sum(item.get('capture_source') in CHROME_CERTIFICATE_SOURCES for item in certificates)
    reasons = [code for code in gaps if code.startswith('tls_certificate_')
               and code != 'tls_certificate_association_limited']
    response_keys = set()
    known_http = {item.get('request_ref') for item in certificates
                  if item.get('capture_source') in {'verified_tls_socket', 'unverified_tls_socket'}}
    known_chrome = {(item['session_id'], item['target_id'], item['origin'], item['collector_id'], item['attempt_id'])
                    for item in certificates if item.get('capture_source') == CHROME_CERTIFICATE_SOURCE}
    known_netlog = {(item['collector_id'], item['attempt_id']) for item in certificates
                    if item.get('capture_source') == NETLOG_CERTIFICATE_SOURCE}
    for row in rows:
        fields = row['fields']
        if row['kind'] == 'gap' and str(fields.get('code', '')).startswith('tls_certificate_'):
            for value in (fields.get('code'), fields.get('reason_code')):
                if isinstance(value, str) and re.fullmatch(r'[a-z0-9_]{1,128}', value):
                    reasons.append(value)
        if row['kind'] not in {'response_observed', 'request_attempted', 'network_request_observed'}:
            continue
        url = fields.get('source_url', fields.get('url'))
        if not isinstance(url, str) or not url.lower().startswith('https://'):
            continue
        ref = fields.get('request_ref')
        response_keys.add(ref if isinstance(ref, str) else 'unknown')
        try:
            origin = certificate_origin(url)
        except EvidenceError:
            continue
        chrome_key = tuple(fields.get(key) for key in ('session_id', 'target_id')) + (origin,) + tuple(
            fields.get(key) for key in ('collector_id', 'attempt_id'))
        if (not isinstance(ref, str) or ref not in known_http) and (
            all(isinstance(value, (str, type(None))) for value in chrome_key)
            and chrome_key not in known_chrome and chrome_key[-2:] not in known_netlog):
            reasons.append('tls_certificate_original_missing')
    if any(item.get('capture_source') in CHROME_CERTIFICATE_SOURCES and not item['chain_complete'] for item in certificates):
        reasons.append('tls_certificate_chain_partial')
    reasons = list(dict.fromkeys(reasons))[:64]
    present = http_count + chrome_count
    state = ('partial' if reasons else 'saved') if present else (
        'not_captured' if reasons or response_keys else 'not_applicable')
    return {'state': state, 'http_certificates': http_count, 'chrome_certificates': chrome_count,
            'association_limited': bool(chrome_count), 'reasons': reasons}


def validate_tls_summary(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {'state', 'http_certificates', 'chrome_certificates', 'association_limited', 'reasons'}
        and isinstance(value['state'], str)
        and value['state'] in {'not_applicable', 'saved', 'partial', 'not_captured'}
        and all(type(value[key]) is int and 0 <= value[key] <= 2000 for key in ('http_certificates', 'chrome_certificates'))
        and type(value['association_limited']) is bool
        and value['association_limited'] == (value['chrome_certificates'] > 0)
        and isinstance(value['reasons'], list) and len(value['reasons']) <= 64
        and all(isinstance(reason, str) and re.fullmatch(r'[a-z0-9_]{1,128}', reason) for reason in value['reasons'])
        and (value['state'] in {'saved', 'partial'}) == bool(value['http_certificates'] + value['chrome_certificates'])
        and (value['state'] != 'not_applicable' or not value['reasons'])
        and (value['state'] != 'saved' or not value['reasons'])
        and (value['state'] != 'partial' or bool(value['reasons']))
    )
