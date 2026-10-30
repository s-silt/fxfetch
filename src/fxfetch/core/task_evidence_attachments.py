"""Original package and same-connection TLS certificate attachments, offline only."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from cryptography import x509

from ..rejected_files import rejected_files
from .task_evidence_provenance import validate_saved_bytes
from .task_evidence_schema import MAX_TASK_FILES
from .task_evidence_tls import (
    CHROME_CERTIFICATE_FIELDS,
    CHROME_CERTIFICATE_SOURCE,
    NETLOG_CERTIFICATE_FIELDS,
    NETLOG_CERTIFICATE_SOURCE,
    validate_chrome_certificate,
    validate_chrome_chains,
    validate_netlog_certificate,
)
from .web_evidence_io import source_path
from .web_evidence_schema import EvidenceError


def collect_attachments(
    root: Path, job_id: str, result: dict[str, Any], rows: list[dict], external: list[dict],
    maximum: int, deadline: float,
    *, tls_policy: str | None = None,
) -> tuple[list[dict[str, Any]], list[tuple[str, Path]], list[str]]:
    records: list[dict[str, Any]] = []
    sources: list[tuple[str, Path]] = []
    gaps: list[str] = []
    used: set[str] = set()
    total_bytes = 0
    request_keys = {(fields['request_ref'], fields['url']) for row in rows
                    if row['kind'] in {'request_attempted', 'network_request_observed'}
                    and isinstance((fields := row['fields']).get('request_ref'), str)
                    and isinstance(fields.get('url'), str)}

    def check_deadline() -> None:
        if time.monotonic() >= deadline:
            raise EvidenceError('task_evidence_seal_timeout')

    def known_request(ref: object, url: str) -> bool:
        return isinstance(ref, str) and (ref, url) in request_keys

    def package(path: Path, metadata: dict, validation: dict, url: str, ref: object) -> None:
        nonlocal total_bytes
        check_deadline()
        member = f"attachments/packages/{metadata['sha256']}.{metadata['kind']}"
        if member not in used and total_bytes + metadata['size'] > maximum:
            raise EvidenceError('task_evidence_attachment_byte_limit')
        relative = path.absolute().relative_to(root).as_posix()
        path = source_path(root, relative)
        validate_saved_bytes(path, metadata['size'], metadata['sha256'], maximum, deadline)
        # Duplicate observed files retain their linkage in observations/external
        # references while their identical bytes need only one ZIP member.
        record = {'kind': 'package', 'package_kind': metadata['kind'], 'path': member,
                  'source_path': relative, 'source_url': url, 'size': metadata['size'],
                  'sha256': metadata['sha256'], 'complete': True,
                  'request_association': 'known' if known_request(ref, url) else 'unknown',
                  'validation': validation}
        if record['request_association'] == 'known':
            record['request_ref'] = ref
        else:
            gaps.append('package_request_association_incomplete')
        reference = {'kind': metadata['kind'], 'size': metadata['size'], 'sha256': metadata['sha256'],
                     'source_url': url, 'complete': True, 'validated': validation['status'] == 'passed',
                     'embedded_path': member}
        if 'request_ref' in record:
            reference['request_ref'] = record['request_ref']
        previous = next((item for item in external if all(item.get(key) == reference[key]
                        for key in ('kind', 'size', 'sha256', 'source_url', 'validated'))), None)
        if previous is None:
            external.append(reference)
        else:
            previous['embedded_path'] = member
        if member not in used:
            used.add(member)
            total_bytes += metadata['size']
            records.append(record)
            sources.append((member, path))

    for artifact in result.get('artifacts', [])[:16]:
        check_deadline()
        if not isinstance(artifact, dict) or artifact.get('kind') not in {'apk', 'ipa'}:
            continue
        if not any(all(item.get(key) == artifact.get(key) for key in ('kind', 'size', 'sha256')) for item in external):
            gaps.append('package_original_unavailable')
            continue
        package(Path(artifact['path']), artifact, {'status': 'passed', 'reason_code': None},
                str(artifact.get('url') or ''), artifact.get('request_ref'))

    job = {'id': job_id, 'state': 'completed', 'outcome': result.get('outcome'),
           'reason_code': result.get('reason_code'), 'result': result}
    for rejected in rejected_files(job, root, maximum):
        body = next(item for item in result.get('bodies', []) if item.get('path') == str(rejected.path))
        package(rejected.path, rejected.metadata,
                {'status': 'failed', 'reason_code': rejected.metadata['reason_code']},
                body.get('url', ''), body.get('request_ref'))

    certificate_refs: set[tuple[object, object]] = set()
    for row in rows:
        check_deadline()
        if row['kind'] != 'tls_certificate_saved':
            continue
        fields = row['fields']
        url = fields.get('source_url', fields.get('url'))
        ref, digest = fields.get('request_ref'), fields.get('sha256')
        size = fields.get('size')
        chrome = fields.get('capture_source') == CHROME_CERTIFICATE_SOURCE
        netlog = fields.get('capture_source') == NETLOG_CERTIFICATE_SOURCE
        if (
            not isinstance(url, str) or (not netlog and not known_request(ref, url))
            or fields.get('complete') is not True or fields.get('representation') != 'tls_certificate_der'
            or fields.get('tls_der_sha256') != digest
            or type(size) is not int or not 0 < size <= 1024 * 1024
            or not isinstance(digest, str) or len(digest) != 64
            or (not chrome and not netlog and (fields.get('cert_role') != 'leaf'
                or fields.get('capture_source') not in {'verified_tls_socket', 'unverified_tls_socket'}
                or fields.get('association') != 'same_connection'))
        ):
            gaps.append('tls_certificate_binding_incomplete')
            continue
        if chrome or netlog:
            try:
                (validate_netlog_certificate if netlog else validate_chrome_certificate)(fields)
            except EvidenceError:
                gaps.append('tls_certificate_binding_incomplete')
                continue
        relative = fields.get('path')
        if not isinstance(relative, str):
            gaps.append('tls_certificate_original_missing')
            continue
        path = source_path(root, relative)
        if total_bytes + size > maximum:
            raise EvidenceError('task_evidence_attachment_byte_limit')
        validate_saved_bytes(path, size, digest, maximum, deadline)
        with path.open('rb') as stream:
            validate_certificate_der(stream.read(1024 * 1024 + 1))
        # One member per observed request, even when the leaf DER is shared.
        # This keeps each connection binding explicit without conflating hosts.
        member = f"attachments/certificates/{row['seq']:06d}-{digest}.der"
        record = {'kind': 'certificate', 'path': member, 'source_path': relative, 'source_url': url,
                  'size': size, 'sha256': digest, 'complete': True, 'request_association': 'known',
                  'request_ref': ref, 'cert_role': 'leaf', 'capture_source': 'verified_tls_socket',
                  'association': 'same_connection',
                  'validation': {'status': 'not_performed', 'reason_code': 'certificate_identity_not_verified'}}
        if chrome:
            record.update({key: fields[key] for key in CHROME_CERTIFICATE_FIELDS})
            record.update(request_association='observation_trigger_only', cert_role=fields['cert_role'],
                          capture_source=CHROME_CERTIFICATE_SOURCE, association='origin_snapshot')
        elif netlog:
            record.pop('request_ref')
            record.update({key: fields[key] for key in NETLOG_CERTIFICATE_FIELDS})
            record.update(request_association='unknown', cert_role=fields['cert_role'],
                          capture_source=NETLOG_CERTIFICATE_SOURCE, association='browser_network_event')
        else:
            record['capture_source'] = fields['capture_source']
        if 'tls_verification' in fields:
            record['tls_verification'] = fields['tls_verification']
        if tls_policy is not None and not chrome and not netlog:
            for key in ('tls_fallback_id', 'tls_verify_code', 'tls_verify_reason', 'connection_ip'):
                if key in fields:
                    record[key] = fields[key]
        records.append(record)
        total_bytes += size
        sources.append((member, path))
        certificate_refs.add((ref, digest))
        if len(records) >= MAX_TASK_FILES:
            raise EvidenceError('task_evidence_attachment_count_limit')
    fingerprints = {(row['fields'].get('request_ref'), row['fields']['tls_der_sha256'])
                    for row in rows if isinstance(row['fields'].get('tls_der_sha256'), str)
                    and isinstance(row['fields'].get('request_ref'), (str, type(None)))}
    certificate_hashes = {digest for _, digest in certificate_refs}
    if (fingerprints - certificate_refs
        or any(row['kind'] == 'tls_certificate_not_captured'
               or (row['kind'] == 'gap' and row['fields'].get('code') == 'tls_certificate_not_captured')
               for row in rows)
        or any(
        isinstance(hop, dict) and isinstance(hop.get('tls_der_sha256'), str)
        and hop['tls_der_sha256'] not in certificate_hashes
        for hop in result.get('hops', [])
    )):
        gaps.append('tls_certificate_original_missing')
    if any(row['kind'] == 'gap' and row['fields'].get('code') == 'tls_certificate_not_captured' for row in rows):
        gaps.append('tls_certificate_not_captured')
    if validate_chrome_chains(records):
        gaps.append('tls_certificate_chain_partial')
    return records, sources, gaps


def validate_certificate_der(data: bytes) -> None:
    if not 0 < len(data) <= 1024 * 1024:
        raise EvidenceError('task_evidence_certificate_invalid')
    try:
        x509.load_der_x509_certificate(data)
    except ValueError as error:
        raise EvidenceError('task_evidence_certificate_invalid') from error
