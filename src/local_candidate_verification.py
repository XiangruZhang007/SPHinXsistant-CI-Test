"""L2-B2a evidence-only remote composition; never an Owner subject or authority.

The caller must pin request bytes and obtain the expected repository domain from
independently pinned configuration. Runtime environment identity remains an
additional private-transport restriction, never approval. Successful receipts
retain verified attachments in a new owned OS temporary directory.
"""
from pathlib import Path
import re
import shutil
import tempfile

from . import trusted_snapshot as trusted, local_candidate_transport as transport
from .corpus_snapshot import canonical, digest, file_digest
from .published_candidate_verification import _json, LIMIT

LOCAL_FIELDS = {'evidence_origin', 'hosted_validation', 'candidate_id', 'baseline_id',
                'corpus_sha256', 'descriptor_sha256', 'archive_sha256',
                'transport', 'transport_sha256'}
TRANSPORT_FIELDS = {'schema_version', 'kind', 'evidence_origin', 'hosted_validation',
    'candidate_id', 'baseline_id', 'parent_id', 'corpus_sha256', 'reference_sha256',
    'descriptor_sha256', 'manifest_sha256', 'archive_sha256', 'archive_size',
    'publication_commit', 'storage'}
STORAGE_FIELDS = {'kind', 'repository', 'repository_id', 'release_id', 'asset_id',
                  'tag', 'asset_name', 'asset_size', 'immutable_required'}


class VerificationError(ValueError):
    """Sanitized diagnostic only; never remote bodies or credentials."""


def need(ok, reason):
    if not ok:
        raise VerificationError(reason)


def validate_transport(local, reference, reference_sha, *, expected_repository,
                       expected_repository_id):
    """Closed metadata validation, not downloading or authorization."""
    try:
        need(isinstance(local, dict) and set(local) == LOCAL_FIELDS,
             'INVALID_LOCAL_EVIDENCE_FIELDS')
        t = local['transport']
        need(isinstance(t, dict) and set(t) == TRANSPORT_FIELDS, 'INVALID_LOCAL_TRANSPORT_FIELDS')
        need(transport.l1._sha(local['transport_sha256'])
             and digest(t) == local['transport_sha256'], 'TRANSPORT_REFERENCE_PIN_MISMATCH')
        need(type(t['schema_version']) is int and t['schema_version'] == 1
             and t['kind'] == 'LOCAL_RESEARCH_EVIDENCE_TRANSPORT', 'INVALID_LOCAL_TRANSPORT_VERSION')
        need(t['evidence_origin'] == local['evidence_origin'] == 'LOCAL_RESEARCH_EXECUTION'
             and t['hosted_validation'] == local['hosted_validation'] == 'HOSTED_NOT_RUN',
             'LOCAL_ORIGIN_REQUIRED')
        for k in ('candidate_id', 'baseline_id', 'parent_id'):
            need(isinstance(t[k], str) and re.fullmatch(r'sha256-[0-9a-f]{64}', t[k]),
                 'INVALID_TRANSPORT_IDENTITY')
        for k in ('corpus_sha256', 'reference_sha256', 'descriptor_sha256',
                  'manifest_sha256', 'archive_sha256'):
            need(transport.l1._sha(t[k]), 'INVALID_TRANSPORT_PIN')
        need(all(t[k] == local[k] for k in ('candidate_id', 'baseline_id',
                 'corpus_sha256', 'descriptor_sha256', 'archive_sha256')),
             'LOCAL_TRANSPORT_BINDING_MISMATCH')
        need(t['reference_sha256'] == reference_sha == digest(reference)
             and reference['schema_version'] == 3
             and reference['package_format'] == 'schema2-research-baseline'
             and reference['node_id'] == t['baseline_id']
             and reference['corpus_sha256'] == t['corpus_sha256']
             and ('candidate_id' not in reference or reference['candidate_id'] == t['candidate_id']),
             'LOCAL_REFERENCE_BINDING_MISMATCH')
        need(isinstance(expected_repository, str)
             and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}', expected_repository)
             and type(expected_repository_id) is int and expected_repository_id > 0,
             'INDEPENDENT_REPOSITORY_REQUIRED')
        stores = [t['storage'], reference['storage'], reference['parent_rows_storage'],
                  reference['notices']['storage']]
        for s in stores:
            need(isinstance(s, dict) and set(s) == STORAGE_FIELDS
                 and s['kind'] == trusted.PRIVATE_RELEASE_KIND
                 and s['repository'] == expected_repository
                 and type(s['repository_id']) is int and s['repository_id'] == expected_repository_id
                 and all(type(s[k]) is int and s[k] > 0 for k in ('release_id', 'asset_id', 'asset_size'))
                 and s['asset_size'] <= transport.LIMIT and s['immutable_required'] is True,
                 'REPOSITORY_OR_ASSET_MISMATCH')
            trusted.release_locator(s)  # Preserve the existing runtime transport gate.
        need(type(t['archive_size']) is int and 0 < t['archive_size'] <= transport.LIMIT
             and t['archive_size'] == t['storage']['asset_size'], 'INVALID_ARCHIVE_SIZE')
        need(isinstance(t['publication_commit'], str)
             and re.fullmatch('[0-9a-f]{40}', t['publication_commit']), 'INVALID_PUBLICATION_COMMIT')
        need(t['storage']['release_id'] != reference['storage']['release_id'],
             'EVIDENCE_RELEASE_MUST_BE_SEPARATE')
        trusted.validate_reference(reference, reference_sha, remote=True)
        return t
    except VerificationError:
        raise
    except Exception:
        raise VerificationError('INVALID_LOCAL_TRANSPORT') from None


def _metadata(url, token):
    with trusted._request(url, token=token) as stream:
        raw = stream.read(LIMIT + 1)
    need(len(raw) <= LIMIT, 'OVERSIZED_REMOTE_METADATA')
    return _json(raw)


def _release(storage, assets, token, publication_commit=None):
    base = trusted.release_locator(storage)
    r = _metadata(base + '/releases/' + str(storage['release_id']), token)
    need(type(r.get('id')) is int and r['id'] == storage['release_id']
         and r.get('tag_name') == storage['tag'] and r.get('immutable') is True
         and r.get('draft') is False, 'REMOTE_RELEASE_MISMATCH')
    expected = {(s['asset_id'], s['asset_name'], s['asset_size']) for s in assets}
    rows = r.get('assets')
    need(isinstance(rows, list) and len(rows) == len(expected)
         and all(isinstance(a, dict) and a.get('state') == 'uploaded'
                 and type(a.get('id')) is int and type(a.get('size')) is int for a in rows)
         and {(a['id'], a.get('name'), a['size']) for a in rows} == expected,
         'REMOTE_ASSET_SET_MISMATCH')
    if publication_commit is not None:
        obj = _metadata(base + '/git/ref/tags/' + storage['tag'], token)
        need(obj.get('ref') == 'refs/tags/' + storage['tag'], 'PUBLICATION_TAG_MISMATCH')
        obj = obj['object']
        for _ in range(5):
            need(isinstance(obj, dict) and isinstance(obj.get('sha'), str)
                 and re.fullmatch('[0-9a-f]{40}', obj['sha']), 'INVALID_TAG_OBJECT')
            if obj.get('type') == 'commit':
                need(obj['sha'] == publication_commit, 'PUBLICATION_COMMIT_MISMATCH')
                break
            need(obj.get('type') == 'tag', 'INVALID_TAG_OBJECT')
            tag = _metadata(base + '/git/tags/' + obj['sha'], token)
            need(tag.get('sha') == obj['sha'], 'INVALID_TAG_OBJECT')
            obj = tag['object']
        else:
            raise VerificationError('TAG_DEPTH_EXCEEDED')
    return {'release_id': storage['release_id'], 'immutable': True,
            'assets': sorted(s['asset_id'] for s in assets)}


def restore_delivery(project, reference, reference_sha, work, *, token, stem):
    """Registration restoration, retaining mandatory v3 delivery beside output.

    Caller supplies a new owned workspace and a fixed implementation stem, not
    an archive-controlled filename. Legacy v2 keeps its original two-argument
    restore behavior and does not gain a notices guarantee.
    """
    need(isinstance(stem,str) and re.fullmatch('[a-z0-9-]+',stem),'INVALID_RESTORE_STEM')
    work = Path(work); package = work/(stem+'.tar.gz'); destination=work/stem
    trusted.validate_reference(reference,reference_sha,remote=True)
    if reference['schema_version'] == 3:
        stores=[reference['storage'],reference['parent_rows_storage'],reference['notices']['storage']]
        _release(stores[0],stores,token)
        for path,storage,pin in [(package,stores[0],reference['transport_sha256']),
                (work/(stem+'-r2.json'),stores[1],reference['parent_rows_sha256']),
                (work/(stem+'-notices.zip'),stores[2],reference['notices']['sha256'])]:
            trusted.download(storage,path,pin,token=token)
            need(file_digest(path)==pin and path.stat().st_size==storage['asset_size'],'PARENT_DOWNLOAD_MISMATCH')
        notices=work/(stem+'-notices.zip')
        receipt=trusted.verify_notices(reference,reference_sha,notices)
        (work/(stem+'-notices-verification.json')).write_bytes(canonical(receipt))
        trusted.restore(project,package,destination,reference,reference_sha,notices_path=notices)
    else:
        trusted.download(reference['storage'],package,reference['transport_sha256'],token=token)
        trusted.restore(project,package,destination,reference,reference_sha)
    return destination


def verify(project, local, reference, reference_sha, *, expected_repository,
           expected_repository_id, token=None):
    """Verify pinned remote content, retaining attachments; no registration calls.

    New local files are allowed only in the owned OS temporary workspace. The
    request CLI supplies raw-byte-pinned inputs and the separately pinned policy
    domain. The library does not infer trust from these arguments or approve them.
    """
    work = None
    phase = 'LOCAL_TRANSPORT_VERIFICATION_FAILED'
    try:
        local, reference = _json(canonical(local)), _json(canonical(reference))
        t = validate_transport(local, reference, reference_sha,
            expected_repository=expected_repository, expected_repository_id=expected_repository_id)
        need(isinstance(token, str) and token and not any(c.isspace() for c in token),
             'PRIVATE_RELEASE_TOKEN_REQUIRED')
        # Frozen Linux runtime: ignore caller-controlled TMPDIR and expose no
        # output-path flag that could place new files in a frozen evidence tree.
        temp_root = transport.l1._safe('/tmp', directory=True)
        need(Path(tempfile.gettempdir()).resolve() == temp_root.resolve()
             and not temp_root.resolve().is_relative_to(Path(project).resolve()), 'UNSAFE_WORKSPACE')
        work = Path(tempfile.mkdtemp(prefix='local-evidence-verification-', dir=temp_root))
        archive_release = _release(t['storage'], [t['storage']], token, t['publication_commit'])
        trusted.download(t['storage'], work / 'local-evidence.tar.gz', t['archive_sha256'], token=token)
        pins = dict(expected_archive_sha256=t['archive_sha256'], expected_archive_size=t['archive_size'],
            expected_manifest_sha256=t['manifest_sha256'], expected_descriptor_sha256=t['descriptor_sha256'])
        transport.extract(work / 'local-evidence.tar.gz', work / 'evidence', **pins)
        d = transport.l1.load_descriptor(work / 'evidence/descriptor.json', t['descriptor_sha256'])
        need(all(d[k] == t[k] for k in ('candidate_id', 'baseline_id', 'parent_id',
                 'corpus_sha256', 'reference_sha256')), 'DESCRIPTOR_TRANSPORT_MISMATCH')
        phase = 'REFERENCE_V3_DELIVERY_FAILED'
        stores = [reference['storage'], reference['parent_rows_storage'], reference['notices']['storage']]
        parent_release = _release(stores[0], stores, token)
        receipts = {}
        for name, storage, pin in [('baseline.tar.gz', stores[0], reference['transport_sha256']),
                ('parent-r2.json', stores[1], reference['parent_rows_sha256']),
                ('notices.zip', stores[2], reference['notices']['sha256'])]:
            receipts[name] = trusted.download(storage, work / name, pin, token=token)
            need(file_digest(work / name) == pin and (work / name).stat().st_size == storage['asset_size'],
                 'PARENT_DOWNLOAD_MISMATCH')
        notice_receipt = trusted.verify_notices(reference, reference_sha, work / 'notices.zip')
        (work / 'notices-verification.json').write_bytes(canonical(notice_receipt))
        # Only the existing public gate may create/restore the Baseline.
        trusted.restore(project, work / 'baseline.tar.gz', work / 'baseline', reference,
                        reference_sha, notices_path=work / 'notices.zip')
        (work / 'reference.json').write_bytes(canonical(reference))
        need(reference['parent_rows_sha256'] == d['candidate_rows_sha256']
             == file_digest(work / 'evidence/run/quality/incremental-raw-results.json'),
             'IMMEDIATE_PARENT_R2_MISMATCH')
        phase = 'L1_VERIFICATION_FAILED'
        receipt = transport.verify_extracted(project, work / 'evidence', work / 'baseline',
            work / 'reference.json', expected_manifest_sha256=t['manifest_sha256'],
            expected_descriptor_sha256=t['descriptor_sha256'])
        transport._check_l1(receipt)
        need(all(receipt[k] == t[k] for k in ('candidate_id', 'baseline_id', 'parent_id',
                 'corpus_sha256', 'descriptor_sha256')), 'L1_TRANSPORT_MISMATCH')
        result = {**receipt, 'status': 'LOCAL_REMOTE_EVIDENCE_VERIFIED',
            'transport_reference_sha256': local['transport_sha256'],
            'reference_sha256': reference_sha, 'archive_sha256': t['archive_sha256'],
            'archive_release': archive_release, 'parent_release': parent_release,
            'downloads': receipts, 'notices_verification': notice_receipt,
            'retained_directory': str(work), 'owner_subject_v2': 'NOT_IMPLEMENTED',
            'registration': 'NOT_PERFORMED', 'owner_authorization': 'NOT_GRANTED',
            'quality_acceptance': 'NOT_GRANTED'}
        (work / 'verification.json').write_bytes(canonical(result))
        return result
    except VerificationError:
        if work is not None:
            shutil.rmtree(work)
        raise
    except Exception:
        if work is not None:
            shutil.rmtree(work)
        raise VerificationError(phase) from None
