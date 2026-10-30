"""Strict schema validation for unified task evidence packages."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any

from .task_evidence_tls import (
    CHROME_CERTIFICATE_FIELDS,
    CHROME_CERTIFICATE_SOURCE,
    NETLOG_CERTIFICATE_FIELDS,
    NETLOG_CERTIFICATE_SOURCE,
    validate_chrome_certificate,
    validate_chrome_chains,
    validate_netlog_certificate,
    validate_tls_summary,
)
from .task_evidence_tls_policy import valid_fallback_summary
from .web_evidence_schema import EvidenceError, portable_path
from .web_evidence_schema import strict_json as strict_json

TASK_EVIDENCE_SCHEMA = "fxfetch.task-evidence.v2"
TASK_EVIDENCE_SCHEMA_V1 = "fxfetch.task-evidence.v1"
MAX_TASK_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_TASK_FILES = 2000
MAX_TASK_OBSERVATIONS_BYTES = 8 * 1024 * 1024
MAX_TASK_OBSERVATIONS = 20_000
_HASH = re.compile(r"^[0-9a-f]{64}$")


def validate_task_manifest(value: object) -> dict[str, Any]:
    fields = {
        "schema_version", "producer_version", "job_id", "entry_url", "package_result",
        "web_materials", "observations", "attempts", "files", "external_packages", "gaps",
    }
    if isinstance(value, dict) and value.get('schema_version') == TASK_EVIDENCE_SCHEMA:
        fields.add('attachments')
        if 'tls_certificates' in value:
            fields.add('tls_certificates')
            if not validate_tls_summary(value['tls_certificates']):
                raise EvidenceError('task_evidence_tls_summary_invalid')
        if 'ignore_tls_errors' in value:
            fields.add('ignore_tls_errors')
            if type(value['ignore_tls_errors']) is not bool:
                raise EvidenceError('task_evidence_tls_policy_invalid')
        if 'tls_policy' in value:
            fields.update({'tls_policy', 'tls_fallback'})
            if (value['tls_policy'] not in ('strict', 'auto') or 'ignore_tls_errors' in value
                or not valid_fallback_summary(value.get('tls_fallback'))):
                raise EvidenceError('task_evidence_tls_policy_invalid')
    if not isinstance(value, dict) or set(value) != fields:
        raise EvidenceError("task_evidence_schema_fields_invalid")
    if value["schema_version"] not in {TASK_EVIDENCE_SCHEMA, TASK_EVIDENCE_SCHEMA_V1}:
        raise EvidenceError("task_evidence_schema_unsupported")
    if not isinstance(value["producer_version"], str) or not value["producer_version"]:
        raise EvidenceError("task_evidence_producer_invalid")
    if not isinstance(value["job_id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value["job_id"]):
        raise EvidenceError("task_evidence_job_id_invalid")
    if not isinstance(value["entry_url"], str) or len(value["entry_url"]) > 8192:
        raise EvidenceError("task_evidence_entry_url_invalid")
    result = value["package_result"]
    if not isinstance(result, dict) or set(result) != {"outcome", "reason_code", "coverage"}:
        raise EvidenceError("task_evidence_package_result_invalid")
    if result["outcome"] not in {"downloaded", "not_found", "blocked", "failed"}:
        raise EvidenceError("task_evidence_package_outcome_invalid")
    if result["reason_code"] is not None and (
        not isinstance(result["reason_code"], str) or len(result["reason_code"]) > 128
    ):
        raise EvidenceError("task_evidence_reason_invalid")
    if not isinstance(result["coverage"], str) or len(result["coverage"]) > 64:
        raise EvidenceError("task_evidence_coverage_invalid")
    materials = value["web_materials"]
    if not isinstance(materials, dict) or set(materials) != {"state", "count", "coverage", "gaps"}:
        raise EvidenceError("task_evidence_materials_invalid")
    if materials["state"] not in {"saved", "empty"} or materials["coverage"] != "partial":
        raise EvidenceError("task_evidence_materials_invalid")
    if isinstance(materials["count"], bool) or not isinstance(materials["count"], int) or materials["count"] < 0:
        raise EvidenceError("task_evidence_material_count_invalid")
    _validate_gaps(materials["gaps"])
    observations = value["observations"]
    if not isinstance(observations, dict) or set(observations) != {
        "state", "records", "path", "size", "sha256", "started_at", "finished_at", "gaps"
    }:
        raise EvidenceError("task_evidence_observations_invalid")
    if observations["state"] not in {
        "healthy", "truncated", "failed", "unavailable", "interrupted"
    }:
        raise EvidenceError("task_evidence_observations_invalid")
    _validate_size(observations["records"])
    _validate_size(observations["size"])
    if observations["records"] > MAX_TASK_OBSERVATIONS or observations["size"] > MAX_TASK_OBSERVATIONS_BYTES:
        raise EvidenceError("task_evidence_observations_invalid")
    for field in ("started_at", "finished_at"):
        timestamp = observations[field]
        if timestamp is not None:
            if not isinstance(timestamp, str) or len(timestamp) > 64:
                raise EvidenceError("task_evidence_observations_invalid")
            try:
                parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    raise ValueError
            except ValueError as error:
                raise EvidenceError("task_evidence_observations_invalid") from error
    if observations["state"] == "healthy" and (
        observations["started_at"] is None or observations["finished_at"] is None
    ):
        raise EvidenceError("task_evidence_observations_invalid")
    if observations["path"] is not None:
        if portable_path(observations["path"]) != "observations.jsonl":
            raise EvidenceError("task_evidence_observations_path_invalid")
        _validate_hash(observations["sha256"])
    elif observations["sha256"] is not None:
        raise EvidenceError("task_evidence_observations_invalid")
    if observations["path"] is None and (
        observations["records"] != 0
        or observations["size"] != 0
        or observations["started_at"] is not None
        or observations["finished_at"] is not None
    ):
        raise EvidenceError("task_evidence_observations_invalid")
    if observations["state"] == "healthy" and observations["path"] is None:
        raise EvidenceError("task_evidence_observations_invalid")
    _validate_gaps(observations["gaps"])
    for name in ("attempts", "files", "external_packages"):
        if not isinstance(value[name], list) or len(value[name]) > MAX_TASK_FILES:
            raise EvidenceError("task_evidence_list_invalid")
    used_paths: set[str] = {"manifest.json"}
    component_spellings: dict[str, str] = {}
    for record in value["files"]:
        if not isinstance(record, dict):
            raise EvidenceError("task_evidence_file_invalid")
        allowed = {
            "path", "size", "sha256", "representation", "complete", "source_url",
            "request_association",
        }
        if set(record) - (allowed | {"request_ref"}) or not allowed.issubset(record):
            raise EvidenceError("task_evidence_file_invalid")
        path = portable_path(record["path"])
        key = path.casefold()
        if key in used_paths:
            raise EvidenceError("task_evidence_path_collision")
        used_paths.add(key)
        for index in range(1, len(PurePosixPath(path).parts) + 1):
            spelling = "/".join(PurePosixPath(path).parts[:index])
            folded = spelling.casefold()
            old = component_spellings.get(folded)
            if old is not None and old != spelling:
                raise EvidenceError("task_evidence_path_collision")
            component_spellings[folded] = spelling
        _validate_size(record["size"])
        _validate_hash(record["sha256"])
        if not isinstance(record["representation"], str) or not record["representation"]:
            raise EvidenceError("task_evidence_representation_invalid")
        if type(record["complete"]) is not bool:
            raise EvidenceError("task_evidence_completeness_invalid")
        if record["source_url"] is not None and (
            not isinstance(record["source_url"], str) or len(record["source_url"]) > 8192
        ):
            raise EvidenceError("task_evidence_source_invalid")
        if "request_ref" in record and (
            not isinstance(record["request_ref"], str) or not record["request_ref"] or len(record["request_ref"]) > 256
        ):
            raise EvidenceError("task_evidence_request_ref_invalid")
        if record["request_association"] not in {"known", "unknown"} or (
            (record["request_association"] == "known") != ("request_ref" in record)
        ):
            raise EvidenceError("task_evidence_request_association_invalid")
    for item in value["external_packages"]:
        if not isinstance(item, dict):
            raise EvidenceError("task_evidence_external_package_invalid")
        allowed = {"kind", "size", "sha256", "source_url", "complete", "validated"}
        optional = {'request_ref'} | ({'embedded_path'} if value['schema_version'] == TASK_EVIDENCE_SCHEMA else set())
        if set(item) - (allowed | optional) or not allowed.issubset(item):
            raise EvidenceError("task_evidence_external_package_invalid")
        if item["kind"] not in {"apk", "ipa"}:
            raise EvidenceError("task_evidence_external_package_invalid")
        _validate_size(item["size"])
        _validate_hash(item["sha256"])
        if not isinstance(item["source_url"], str) or len(item["source_url"]) > 8192:
            raise EvidenceError("task_evidence_external_package_invalid")
        if type(item["complete"]) is not bool or type(item["validated"]) is not bool:
            raise EvidenceError("task_evidence_external_package_invalid")
        if "request_ref" in item and (
            not isinstance(item["request_ref"], str) or not item["request_ref"] or len(item["request_ref"]) > 256
        ):
            raise EvidenceError("task_evidence_request_ref_invalid")
        if 'embedded_path' in item:
            portable_path(item['embedded_path'])
    if value['schema_version'] == TASK_EVIDENCE_SCHEMA:
        _validate_attachments(value, used_paths, component_spellings)
    _validate_gaps(value["gaps"])
    if materials["count"] != len(value["files"]) or (
        materials["state"] == "saved"
    ) != bool(value["files"]):
        raise EvidenceError("task_evidence_material_count_invalid")
    return value


def _validate_attachments(value: dict[str, Any], used_paths: set[str], spellings: dict[str, str]) -> None:
    attachments = value['attachments']
    if not isinstance(attachments, list) or len(attachments) + len(value['files']) > MAX_TASK_FILES:
        raise EvidenceError('task_evidence_attachments_invalid')
    for item in attachments:
        common = {'kind', 'path', 'source_path', 'source_url', 'size', 'sha256', 'complete',
                  'request_association', 'validation'}
        if not isinstance(item, dict) or item.get('kind') not in {'package', 'certificate'}:
            raise EvidenceError('task_evidence_attachment_invalid')
        extra = {'package_kind'} if item['kind'] == 'package' else {
            'cert_role', 'capture_source', 'association'}
        chrome = item['kind'] == 'certificate' and item.get('capture_source') == CHROME_CERTIFICATE_SOURCE
        netlog = item['kind'] == 'certificate' and item.get('capture_source') == NETLOG_CERTIFICATE_SOURCE
        if chrome:
            extra |= CHROME_CERTIFICATE_FIELDS
        if netlog:
            extra |= NETLOG_CERTIFICATE_FIELDS
        optional = {'request_ref'} | ({'tls_verification'} if item['kind'] == 'certificate' else set())
        if item['kind'] == 'certificate' and not chrome and not netlog and 'tls_policy' in value:
            optional |= {'tls_fallback_id', 'tls_verify_code', 'tls_verify_reason', 'connection_ip'}
        if not (common | extra).issubset(item) or set(item) - (common | extra | optional):
            raise EvidenceError('task_evidence_attachment_invalid')
        path = portable_path(item['path'])
        portable_path(item['source_path'])
        if not path.startswith('attachments/') or path.casefold() in used_paths:
            raise EvidenceError('task_evidence_path_collision')
        used_paths.add(path.casefold())
        for index in range(1, len(PurePosixPath(path).parts) + 1):
            spelling = '/'.join(PurePosixPath(path).parts[:index])
            folded = spelling.casefold()
            if folded in spellings and spellings[folded] != spelling:
                raise EvidenceError('task_evidence_path_collision')
            spellings[folded] = spelling
        _validate_size(item['size'])
        _validate_hash(item['sha256'])
        if item['size'] <= 0 or item['complete'] is not True:
            raise EvidenceError('task_evidence_attachment_incomplete')
        if not isinstance(item['source_url'], str) or len(item['source_url']) > 8192:
            raise EvidenceError('task_evidence_source_invalid')
        associations = {'observation_trigger_only'} if chrome else {'known', 'unknown'}
        if item['request_association'] not in associations or (
            (item['request_association'] != 'unknown') != ('request_ref' in item)
        ):
            raise EvidenceError('task_evidence_request_association_invalid')
        if 'request_ref' in item and (not isinstance(item['request_ref'], str) or not 1 <= len(item['request_ref']) <= 256):
            raise EvidenceError('task_evidence_request_ref_invalid')
        validation = item['validation']
        if item['kind'] == 'certificate' and 'tls_verification' in item:
            allowed_tls = ({'required', 'unknown'} if 'tls_policy' in value else {'required', 'ignored'}) if chrome or netlog else (
                {'ignored'} if item.get('capture_source') == 'unverified_tls_socket' else {'verified'})
            if not isinstance(item['tls_verification'], str) or item['tls_verification'] not in allowed_tls or (
                item['tls_verification'] in ('ignored', 'unknown') and not (
                    value.get('tls_policy') == 'auto' or ('tls_policy' not in value and value.get('ignore_tls_errors') is True))
            ):
                raise EvidenceError('task_evidence_tls_policy_invalid')
        if item['kind'] == 'certificate' and 'tls_policy' in value and not chrome and not netlog:
            if 'connection_ip' in item and (not isinstance(item['connection_ip'], str) or not 1 <= len(item['connection_ip']) <= 64):
                raise EvidenceError('task_evidence_tls_policy_invalid')
            if item.get('capture_source') == 'unverified_tls_socket':
                if (not isinstance(item.get('tls_fallback_id'), str) or not re.fullmatch(r'[0-9a-f]{32}', item['tls_fallback_id'])
                    or type(item.get('tls_verify_code')) is not int or not 0 <= item['tls_verify_code'] <= 2**31 - 1
                    or not isinstance(item.get('tls_verify_reason'), str)
                    or not re.fullmatch(r'[a-z0-9_]{1,128}', item['tls_verify_reason']) or 'connection_ip' not in item):
                    raise EvidenceError('task_evidence_tls_policy_invalid')
            elif any(name in item for name in ('tls_fallback_id', 'tls_verify_code', 'tls_verify_reason')):
                raise EvidenceError('task_evidence_tls_policy_invalid')
        if not isinstance(validation, dict) or set(validation) != {'status', 'reason_code'}:
            raise EvidenceError('task_evidence_attachment_validation_invalid')
        if item['kind'] == 'package':
            if item['package_kind'] not in {'apk', 'ipa'}:
                raise EvidenceError('task_evidence_attachment_invalid')
            if validation['status'] == 'passed':
                if validation['reason_code'] is not None:
                    raise EvidenceError('task_evidence_attachment_validation_invalid')
            elif validation['status'] == 'failed':
                if (validation['reason_code'] not in {'archive_invalid', 'archive_unsupported', 'archive_limit', 'archive_ambiguous'}
                    or value['package_result']['outcome'] != 'failed'
                    or value['package_result']['reason_code'] != validation['reason_code']):
                    raise EvidenceError('task_evidence_attachment_validation_invalid')
            else:
                raise EvidenceError('task_evidence_attachment_validation_invalid')
        elif chrome:
            validate_chrome_certificate(item)
            if item['size'] > 1024 * 1024 or validation != {
                'status': 'not_performed', 'reason_code': 'certificate_identity_not_verified'
            }:
                raise EvidenceError('task_evidence_certificate_invalid')
        elif netlog:
            validate_netlog_certificate(item)
            if item['size'] > 1024 * 1024 or validation != {
                'status': 'not_performed', 'reason_code': 'certificate_identity_not_verified'
            }:
                raise EvidenceError('task_evidence_certificate_invalid')
        elif (
            item['request_association'] != 'known' or item['size'] > 1024 * 1024
            or item['cert_role'] != 'leaf' or item['capture_source'] not in {'verified_tls_socket', 'unverified_tls_socket'}
            or (item['capture_source'] == 'unverified_tls_socket' and item.get('tls_verification') != 'ignored')
            or item['association'] != 'same_connection'
            or validation != {'status': 'not_performed', 'reason_code': 'certificate_identity_not_verified'}
        ):
            raise EvidenceError('task_evidence_certificate_invalid')
    validate_chrome_chains(attachments)
    for package in value['external_packages']:
        path = package.get('embedded_path')
        if path is not None and not any(
            item['kind'] == 'package' and item['path'] == path
            and item['package_kind'] == package['kind'] and item['size'] == package['size']
            and item['sha256'] == package['sha256']
            and (item['validation']['status'] == 'passed') is package['validated']
            for item in attachments
        ):
            raise EvidenceError('task_evidence_embedded_package_mismatch')


def _validate_size(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EvidenceError("task_evidence_size_invalid")


def _validate_hash(value: object) -> None:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise EvidenceError("task_evidence_hash_invalid")


def _validate_gaps(value: object) -> None:
    if not isinstance(value, list) or len(value) > 256 or any(
        not isinstance(item, str) or not item or len(item) > 256 for item in value
    ):
        raise EvidenceError("task_evidence_gaps_invalid")
