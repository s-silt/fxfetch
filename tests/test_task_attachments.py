from __future__ import annotations

import copy
import hashlib
import json
import zipfile
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from test_rejected_files import private_job
from test_workflow import apk_bytes

from fxfetch.core.analysis_package import prepare_analysis
from fxfetch.core.task_evidence import finalize_package, package_metadata
from fxfetch.core.task_evidence_io import build_task_archive
from fxfetch.core.task_evidence_recorder import TaskEvidenceRecorder
from fxfetch.core.task_evidence_schema import validate_task_manifest
from fxfetch.core.task_evidence_verify import verify_task_archive
from fxfetch.core.web_evidence_schema import EvidenceError

URL = 'https://download.synthetic.test/app.apk'
MAX_BYTES = 64 * 1024 * 1024


def certificate():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'download.synthetic.test')])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(datetime.now(UTC) - timedelta(days=1))
            .not_valid_after(datetime.now(UTC) + timedelta(days=1)).sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER))


def source(tmp_path, *, tls=True, fingerprint_only=False, large=False):
    root = tmp_path / 'job'
    root.mkdir()
    package = root / 'original.apk'
    if large:
        with package.open('wb') as stream:
            stream.write(b'PK\x03\x04')
            for _ in range(192):
                stream.write(b'synthetic-data--' * 4096)
    else:
        package.write_bytes(apk_bytes())
    size = package.stat().st_size
    with package.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    recorder = TaskEvidenceRecorder(root)
    recorder.set_context('http', 'http-1')
    recorder.observe_transport({'event': 'request_attempted', 'request_ref': 'http-req-1', 'url': URL, 'method': 'GET'})
    der = certificate()
    der_hash = hashlib.sha256(der).hexdigest()
    recorder.observe_transport({'event': 'response_observed', 'request_ref': 'http-req-1', 'url': URL,
                                **({'tls_der_sha256': der_hash} if tls or fingerprint_only else {})})
    if tls:
        path = root / 'tls' / (der_hash + '.der')
        path.parent.mkdir()
        path.write_bytes(der)
        recorder.observe_transport({'event': 'tls_certificate_saved', 'path': path, 'size': len(der),
                                    'sha256': der_hash, 'tls_der_sha256': der_hash, 'complete': True,
                                    'source_url': URL, 'url': URL, 'request_ref': 'http-req-1',
                                    'representation': 'tls_certificate_der', 'cert_role': 'leaf',
                                    'capture_source': 'verified_tls_socket', 'association': 'same_connection'})
    recorder.observe_transport({'event': 'response_body_saved', 'request_ref': 'http-req-1',
                                'source_url': URL, 'path': package, 'size': size, 'sha256': digest,
                                'representation': 'http_response_body', 'complete': True, 'package_stream': True})
    recorder.close()
    result = {'outcome': 'downloaded', 'reason_code': 'package_verified', 'coverage': 'complete',
              'artifacts': [{'kind': 'apk', 'path': str(package), 'size': size, 'sha256': digest,
                             'url': URL, 'request_ref': 'http-req-1'}]}
    return root, result, der


def build(root, result):
    path = root / 'data-package' / 'bundle.zip'
    manifest, _ = build_task_archive(root, path, job_id='synthetic', entry_url=URL,
                                     package_result=result, result=result,
                                     observation_path=root / 'task-observations.jsonl', max_bytes=MAX_BYTES)
    return path, manifest


def rewrite(path, mutate):
    with zipfile.ZipFile(path) as source_zip:
        members = {item.filename: (source_zip.read(item), item.compress_type) for item in source_zip.infolist()}
    manifest = json.loads(members['manifest.json'][0])
    mutate(manifest, members)
    members['manifest.json'] = (json.dumps(manifest).encode(), zipfile.ZIP_DEFLATED)
    destination = path.with_name('mutated.zip')
    with zipfile.ZipFile(destination, 'w') as output:
        for name, (raw, compression) in members.items():
            output.writestr(name, raw, compress_type=compression)
    return destination


def test_v2_package_and_tls_der_originals_separate_from_web_analysis(tmp_path):
    root, result, der = source(tmp_path)
    original = copy.deepcopy(result)
    path, manifest = build(root, result)
    checked, _ = verify_task_archive(path, max_bytes=MAX_BYTES)
    assert checked == manifest and result == original
    assert manifest['schema_version'] == 'fxfetch.task-evidence.v2'
    assert not manifest['files'] and manifest['web_materials']['count'] == 0
    assert [record['kind'] for record in manifest['attachments']] == ['package', 'certificate']
    package, tls = manifest['attachments']
    with zipfile.ZipFile(path) as bundle:
        assert bundle.read(package['path']) == (root / 'original.apk').read_bytes()
        assert bundle.getinfo(package['path']).compress_type == zipfile.ZIP_STORED
        assert bundle.read(tls['path']) == der
    assert tls['request_ref'] == 'http-req-1'
    assert tls['validation']['status'] == 'not_performed'
    receipt = prepare_analysis(path, tmp_path / 'analysis', max_bytes=MAX_BYTES)
    assert receipt['materials'] == [] and receipt['attachments']['count'] == 2
    assert receipt['attachments']['included_in_web_analysis'] is False
    assert not list((tmp_path / 'analysis/input').glob('*.apk'))
    assert not list((tmp_path / 'analysis/input').glob('*.der'))


@pytest.mark.parametrize('legacy', [False, True])
def test_complete_bad_apk_embedded_without_changing_validation(tmp_path, legacy, monkeypatch):
    job, root, _, payload = private_job(tmp_path, legacy=legacy)
    monkeypatch.setattr('fxfetch.core.download.classify_package', lambda *args: pytest.fail('Do not revalidate APK'))
    path, manifest = build(root, job['result'])
    assert manifest['package_result']['outcome'] == 'failed'
    assert manifest['attachments'][0]['validation'] == {'status': 'failed', 'reason_code': 'archive_invalid'}
    assert manifest['external_packages'][0]['validated'] is False
    checked, _ = verify_task_archive(path, max_bytes=MAX_BYTES)
    with zipfile.ZipFile(path) as bundle:
        assert bundle.read(checked['attachments'][0]['path']) == payload


def test_fingerprint_without_der_is_gap_and_no_network(tmp_path, monkeypatch):
    root, result, _ = source(tmp_path, tls=False, fingerprint_only=True)
    monkeypatch.setattr('socket.create_connection', lambda *args, **kwargs: pytest.fail('No network reseal'))
    _, manifest = build(root, result)
    assert [item['kind'] for item in manifest['attachments']] == ['package']
    assert 'tls_certificate_original_missing' in manifest['gaps']


@pytest.mark.parametrize('mutation', ['hash', 'request', 'source', 'path', 'partial', 'wrong_validation', 'certificate_context'])
def test_attachment_tampering_rejected(tmp_path, mutation):
    root, result, _ = source(tmp_path)
    path, _ = build(root, result)

    def mutate(manifest, members):
        tls = manifest['attachments'][1]
        if mutation == 'hash':
            tls['sha256'] = '0' * 64
        elif mutation == 'request':
            tls['request_ref'] = 'unobserved'
        elif mutation == 'source':
            tls['source_url'] = 'https://other.synthetic.test/'
        elif mutation == 'path':
            tls['source_path'] = '../escape.der'
        elif mutation == 'partial':
            tls['complete'] = False
        elif mutation == 'wrong_validation':
            tls['validation']['status'] = 'passed'
        else:
            rows = [json.loads(line) for line in members['observations.jsonl'][0].splitlines()]
            next(row for row in rows if row['kind'] == 'tls_certificate_saved')['fields']['attempt_id'] = 'other'
            raw = b''.join(json.dumps(row).encode() + b'\n' for row in rows)
            members['observations.jsonl'] = (raw, zipfile.ZIP_DEFLATED)
            manifest['observations'].update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())

    with pytest.raises(EvidenceError):
        verify_task_archive(rewrite(path, mutate), max_bytes=MAX_BYTES)


def test_v1_archive_without_attachments_remains_accepted(tmp_path):
    root, result, _ = source(tmp_path)
    path, _ = build(root, result)

    def downgrade(manifest, members):
        manifest['schema_version'] = 'fxfetch.task-evidence.v1'
        manifest.pop('tls_certificates', None)
        manifest.pop('ignore_tls_errors', None)
        for item in manifest.pop('attachments'):
            del members[item['path']]
        for item in manifest['external_packages']:
            item.pop('embedded_path', None)

    old = rewrite(path, downgrade)
    checked, _ = verify_task_archive(old, max_bytes=MAX_BYTES)
    assert 'attachments' not in checked
    assert checked['schema_version'] == 'fxfetch.task-evidence.v1'
    assert prepare_analysis(old, tmp_path / 'legacy-analysis', max_bytes=MAX_BYTES)['attachments']['count'] == 0


def test_large_package_verification_streams_without_reading_whole_member(tmp_path, monkeypatch):
    root, result, _ = source(tmp_path, tls=False, large=True)
    original_read = zipfile.ZipFile.read

    def bounded_read(self, name, *args, **kwargs):
        filename = name.filename if isinstance(name, zipfile.ZipInfo) else name
        assert not filename.startswith('attachments/packages/'), 'APK must use streaming reads'
        return original_read(self, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, 'read', bounded_read)
    path, manifest = build(root, result)
    checked, _ = verify_task_archive(path, max_bytes=MAX_BYTES)
    assert checked == manifest and manifest['attachments'][0]['size'] > 10 * 1024 * 1024


def test_public_attachment_summary_and_byte_budget(tmp_path):
    root, result, _ = source(tmp_path)
    metadata = finalize_package(root, job_id='synthetic', entry_url=URL, terminal_result=result,
                                observation_path=root / 'task-observations.jsonl', max_bytes=MAX_BYTES)
    assert metadata['state'] == 'ready'
    assert metadata['attachments']['packages'] == metadata['attachments']['certificates'] == 1
    assert package_metadata(root, 'completed')['attachments'] == metadata['attachments']
    with pytest.raises(EvidenceError):
        build_task_archive(root, root / 'limited.zip', job_id='synthetic', entry_url=URL,
                           package_result=result, result=result, observation_path=None, max_bytes=1)


def test_attachment_and_web_path_collision_is_rejected(tmp_path):
    root, result, _ = source(tmp_path)
    _, manifest = build(root, result)
    duplicate = copy.deepcopy(manifest['attachments'][0])
    manifest['attachments'].append(duplicate)
    with pytest.raises(EvidenceError):
        validate_task_manifest(manifest)


def test_duplicate_package_bytes_keep_all_external_sources_embedded(tmp_path):
    root, result, _ = source(tmp_path, tls=False)
    duplicate = dict(result['artifacts'][0], url='https://mirror.synthetic.test/same.apk')
    duplicate.pop('request_ref')
    result['artifacts'].append(duplicate)
    _, manifest = build(root, result)
    assert len(manifest['attachments']) == 1
    assert len(manifest['external_packages']) == 2
    assert {item['embedded_path'] for item in manifest['external_packages']} == {manifest['attachments'][0]['path']}


def test_embedded_package_unknown_ref_is_not_reported_as_omitted(tmp_path):
    root, result, _ = source(tmp_path, tls=False)
    result['artifacts'][0].pop('request_ref')
    _, manifest = build(root, result)
    assert len(manifest['attachments']) == 1 and not manifest['files']
    assert 'package_request_association_incomplete' in manifest['gaps']
    assert 'package_body_not_included' not in manifest['gaps']


def test_capture_gap_without_fingerprint_remains_explicit(tmp_path):
    root, result, _ = source(tmp_path, tls=False)
    # A fresh recorder is used only for this wholly synthetic fixture.
    recorder = TaskEvidenceRecorder(root, root / 'gap-observations.jsonl')
    recorder.observe_transport({'event': 'gap', 'code': 'tls_certificate_not_captured',
                                'reason_code': 'request_binding_unavailable'})
    recorder.close()
    path = root / 'data-package/gap.zip'
    manifest, _ = build_task_archive(root, path, job_id='synthetic', entry_url=URL,
                                     package_result=result, result=result,
                                     observation_path=recorder.path, max_bytes=MAX_BYTES)
    assert {'tls_certificate_not_captured', 'tls_certificate_original_missing'} <= set(manifest['gaps'])


def test_attachment_binding_deadline_is_enforced(tmp_path):
    from fxfetch.core.task_evidence_provenance import validate_attachment_provenance

    with pytest.raises(EvidenceError, match='task_evidence_seal_timeout'):
        validate_attachment_provenance([{'kind': 'gap', 'fields': {}}] * 1000, [], deadline=0)
