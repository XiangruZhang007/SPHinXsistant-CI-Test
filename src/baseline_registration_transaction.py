"""Isolated Registry transactions with a deny-by-default local entry point.

Only tests replace _trusted_dispatch_context. There is deliberately no runtime
switch for that missing trust integration. GitHub actor evidence is necessary
but does not authenticate an arbitrary local process as the approved workflow.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import uuid

from . import published_candidate_verification as evidence
from . import owner_manual_baseline_approval as owner
from . import trusted_snapshot as transport
from .corpus_snapshot import canonical, digest, file_digest

def __getattr__(name):
    # Preserve existing helper aliases without loading scientific dependencies
    # in the stdlib-only Parent Writer's filesystem/strict-JSON path.
    if name not in ('local_subject', 'local_remote'):
        raise AttributeError(name)
    from importlib import import_module
    module = import_module('.' + {'local_subject': 'local_registration_subject',
        'local_remote': 'local_candidate_verification'}[name], __package__)
    globals()[name] = module
    return module


REGISTRY = 'registry.json'
LOCK = '.registration.lock'
PROJECT = Path(__file__).resolve().parents[1]


class TransactionError(ValueError):
    pass


def _need(ok, reason):
    if not ok:
        raise TransactionError(reason)


def _trusted_dispatch_context():
    """Fail closed until a reviewed trusted-workflow integration exists.

    Neither environment variables, event files, API run identity, nor a caller's
    saved approval result establishes this execution trust. Tests monkeypatch
    this private function; no ordinary library/CLI argument enables it.
    """
    raise TransactionError('TRUSTED_WORKFLOW_EXECUTION_NOT_ESTABLISHED')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _registry(raw):
    obj = evidence._json(raw)
    _need(isinstance(obj, dict) and type(obj.get('schema_version')) is int
          and obj['schema_version'] == 2 and isinstance(obj.get('baselines'), dict),
          'INVALID_REGISTRY')
    return obj


def _serialize(obj):
    return (json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + '\n').encode()


def _open_directory(path):
    path = Path(os.path.abspath(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        return fd
    except BaseException:
        os.close(fd)
        raise


def _inode(info):
    return info.st_dev, info.st_ino


def _regular(fd, name):
    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
    _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'UNSAFE_OR_LINKED_FILE')
    return info


def _read(fd, name):
    initial = _regular(fd, name)
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
    with os.fdopen(descriptor, 'rb') as stream:
        _need(_inode(os.fstat(stream.fileno())) == _inode(initial), 'FILE_IDENTITY_CHANGED')
        return stream.read()


def _unchanged_directory(path, fd):
    current = _open_directory(path)
    try:
        _need(_inode(os.fstat(current)) == _inode(os.fstat(fd)), 'ISOLATION_DIRECTORY_CHANGED')
    finally:
        os.close(current)


@contextmanager
def _locked(project, isolation, authoritative):
    project, isolation = Path(project).resolve(), Path(os.path.abspath(isolation))
    _need(not isolation.is_relative_to(project) and not isolation.is_relative_to(PROJECT),
          'ISOLATION_MUST_BE_OUTSIDE_PROJECT')
    fd = _open_directory(isolation)
    lockfd = None
    try:
        allowed = re.compile(r'(?:registry\.json|\.registration\.lock|'
                             r'[0-9a-f]{64}\.(?:prepared|completed|evidence)\.json|'
                             r'[0-9a-f]{64}\.notices\.zip|'
                             r'\.(?:registry|audit)-[0-9a-f]{32}\.tmp)')
        _need(all(allowed.fullmatch(name) for name in os.listdir(fd)),
              'DEDICATED_ISOLATION_DIRECTORY_REQUIRED')
        info = _regular(fd, REGISTRY)
        for path in (authoritative, project / 'configs/ci_v2_schema2_trusted_baselines.json',
                     PROJECT / 'configs/ci_v2_schema2_trusted_baselines.json'):
            if Path(path).exists():
                _need(_inode(info) != _inode(Path(path).stat()), 'PROTECTED_REGISTRY_ALIAS')
        lockfd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        lockinfo = _regular(fd, LOCK)
        _need(_inode(lockinfo) == _inode(os.fstat(lockfd)), 'LOCK_IDENTITY_CHANGED')
        try:
            fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise TransactionError('TRANSACTION_BUSY') from None
        yield fd, lockinfo
    finally:
        if lockfd is not None:
            os.close(lockfd)  # Stable lock file is never unlinked.
        os.close(fd)


def _stage(fd, raw, prefix):
    name = f'.{prefix}-{uuid.uuid4().hex}.tmp'
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=fd)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        _need(_read(fd, name) == raw, 'STAGED_BYTES_MISMATCH')
        return name
    except BaseException:
        os.unlink(name, dir_fd=fd)
        raise


def _write_once(fd, name, raw):
    tmp = _stage(fd, raw, 'audit')
    try:
        os.link(tmp, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
    finally:
        os.unlink(tmp, dir_fd=fd)
    os.fsync(fd)


def _duplicate_check(project, registry, subject, work, token):
    """Restore historical references; never infer missing Candidate IDs."""
    from . import local_candidate_verification as local_remote
    candidate = subject['candidate']
    proposed = subject['registry_entry']['reference']
    seen_nodes, seen_candidates = set(), set()
    notices_deliveries = []
    for number, (key, entry) in enumerate(registry['baselines'].items()):
        _need(key != subject['registry_key'], 'DUPLICATE_REGISTRY_KEY')
        # Each historical entry keeps its own explicitly supported contract.
        try:
            evidence.registration.entry_kind(entry)
        except evidence.registration.RegistrationError:
            raise TransactionError('INVALID_HISTORICAL_REGISTRY_ENTRY') from None
        ref = entry['reference']
        transport.validate_reference(ref, entry['expected_reference_sha256'], remote=True)
        node = ref['node_id']
        _need(node not in seen_nodes and node != proposed['node_id'], 'DUPLICATE_BASELINE_ID')
        seen_nodes.add(node)
        package, restored = work / f'old-{number}.tar.gz', work / f'old-{number}'
        if ref.get('schema_version') == 3:
            local_remote.restore_delivery(project, ref, entry['expected_reference_sha256'],
                                          work, token=token, stem=f'old-{number}')
            notices_deliveries.append({'reference':ref,'reference_sha256':entry['expected_reference_sha256'],
                'path':work/f'old-{number}-notices.zip'})
        else:
            transport.download(ref['storage'], package, ref['transport_sha256'], token=token)
            transport.restore(project, package, restored, ref, entry['expected_reference_sha256'])
        if ref['package_format'] == 'p2-snapshot-v1':
            continue  # Verified bootstrap identity, no invented Candidate ID.
        _need(ref['package_format'] == 'schema2-research-baseline', 'UNKNOWN_LEGACY_FORMAT')
        identity = evidence._read(restored / 'upstream-candidate.json')['candidate_id']
        _need(isinstance(identity, str) and re.fullmatch(r'sha256-[0-9a-f]{64}', identity),
              'HISTORICAL_CANDIDATE_IDENTITY_UNAVAILABLE')
        _need(ref.get('candidate_id', identity) == identity, 'HISTORICAL_IDENTITY_CONFLICT')
        _need(identity not in seen_candidates and identity != candidate['candidate_id'],
              'DUPLICATE_CANDIDATE_ID')
        seen_candidates.add(identity)
        _need(owner._candidate_binding(ref) != owner._candidate_binding(proposed),
              'CONFLICTING_CANDIDATE_BINDING')
    return notices_deliveries


def _approval(project, authoritative, policy_path, policy_sha, baseline, subject, context, client):
    entry = subject['registry_entry']
    result = owner.verify(project, baseline, authoritative, subject['registry_key'], entry,
        policy_path=policy_path, policy_sha256=policy_sha,
        expected_reference_sha256=entry['expected_reference_sha256'],
        expected_build_policy_sha256=entry.get('build_policy_sha256'),
        q1_status=subject['baseline']['q1_status'], context=context, client=client,
        registration_subject=subject)
    _need(result.get('status') == 'OWNER_APPROVAL_VERIFIED'
          and result.get('registration_subject_sha256') == digest(subject)
          and result.get('production_promotion') == 'NOT_AUTHORIZED',
          'OWNER_APPROVAL_NOT_VERIFIED')
    return result


def _completion(prepared, transaction_id):
    return {'schema_version': prepared['schema_version'], 'transaction_id': transaction_id, 'state': 'COMPLETED',
            'registry_sha256': prepared['new_registry_sha256'],
            'completion': 'COMMITTED_BYTES_VERIFIED', 'registration_scope': 'ISOLATED_COPY_ONLY',
            'production_promotion': 'NOT_AUTHORIZED'}


def _complete(fd, prepared, transaction_id):
    name = transaction_id + '.completed.json'
    raw = _serialize(_completion(prepared, transaction_id))
    if name in os.listdir(fd):
        _need(_read(fd, name) == raw, 'COMPLETION_RECORD_CONFLICT')
        os.fsync(fd)
    else:
        _write_once(fd, name, raw)


def register(project, isolation_directory, *, registry_key, proposed_entry,
             candidate_release, expected_candidate_release_sha256,
             expected_reference_sha256, expected_build_policy_sha256=None,
             expected_registry_sha256, approval_policy_path, approval_policy_sha256,
             token=None):
    """Ordinary local entry point; execution authorization remains unavailable.

    No caller-supplied approval result, context, or simulation flag is accepted.
    The existing policy locates the authoritative Registry, which is read only.
    """
    return _register(project, isolation_directory, registry_key=registry_key,
        proposed_entry=proposed_entry, candidate_release=candidate_release,
        expected_candidate_release_sha256=expected_candidate_release_sha256,
        expected_reference_sha256=expected_reference_sha256,
        expected_build_policy_sha256=expected_build_policy_sha256,
        expected_registry_sha256=expected_registry_sha256,
        approval_policy_path=approval_policy_path, approval_policy_sha256=approval_policy_sha256,
        token=token, _execution_context=_trusted_dispatch_context)


def _local_arguments(project, request_path, expected_request_sha256):
    from scripts import register_trusted_baseline as cli
    _need(Path(project).resolve() == cli.PROJECT.resolve(), 'REQUEST_PROJECT_MISMATCH')
    request, policy = cli.load_request(request_path, expected_request_sha256)
    _need(request['schema_version'] == 3, 'LOCAL_REQUEST_REQUIRED')
    return dict(registry_key=request['registry_key'], proposed_entry=request['proposed_entry'],
        expected_reference_sha256=request['expected_reference_sha256'],
        expected_registry_sha256=request['expected_registry_sha256'],
        approval_policy_path=policy, approval_policy_sha256=request['approval_policy_sha256'],
        _local_request=(Path(request_path), expected_request_sha256))


def register_local(project, isolation_directory, *, request_path, expected_request_sha256, token=None):
    """Public local-origin route; the default trusted context still always denies."""
    try:
        values = _local_arguments(project, request_path, expected_request_sha256)
        return _register(project, isolation_directory, token=token,
                         _execution_context=_trusted_dispatch_context, **values)
    except Exception:
        return {'status': 'BLOCKED', 'registry_committed': False, 'registration': 'NOT_PERFORMED',
                'reason': 'INVALID_LOCAL_REQUEST', 'production_promotion': 'NOT_AUTHORIZED'}


def _retain_historical_notices(fd, deliveries):
    retained=[]
    for item in deliveries:
        ref,pin,path=item['reference'],item['reference_sha256'],item['path']
        receipt=transport.verify_notices(ref,pin,path)
        raw=Path(path).read_bytes();sha=_sha(raw)
        _need(sha==ref['notices']['sha256'],'HISTORICAL_NOTICES_CHANGED')
        name=sha+'.notices.zip'
        if name in os.listdir(fd):
            _need(_read(fd,name)==raw,'AUDIT_NOTICES_CONFLICT')
        else:
            _write_once(fd,name,raw)
        retained.append({'reference':ref,'reference_sha256':pin,'notices_sha256':sha,
                         'notices_verification':receipt})
    return retained


def _retain_local(fd, verified, historical_notices):
    work = Path(verified['retained_directory']); subject = verified['registration_subject']
    bundle = dict(schema_version=1, subject_sha256=digest(subject),
        request_text=verified['request_text'], policy_text=verified['policy_text'],
        descriptor_text=(work/'evidence/descriptor.json').read_bytes().decode('utf-8'),
        transport_manifest_text=(work/'evidence/transport-manifest.json').read_bytes().decode('utf-8'),
        historical_notices=historical_notices)
    raw = canonical(bundle); pin = _sha(raw)
    notices = (work/'notices.zip').read_bytes(); notice_pin = _sha(notices)
    _need(len(raw) <= 8*1024**2 and notice_pin == subject['registry_entry']['reference']['notices']['sha256'],
          'INVALID_LOCAL_AUDIT_EVIDENCE')
    for name, data in ((pin+'.evidence.json',raw),(notice_pin+'.notices.zip',notices)):
        if name in os.listdir(fd):
            _need(_read(fd,name) == data,'AUDIT_EVIDENCE_CONFLICT')
        else:
            _write_once(fd,name,data)
    return {'bundle_sha256': pin, 'notices_sha256': notice_pin}


def _register(project, isolation_directory, *, registry_key, proposed_entry,
              candidate_release=None, expected_candidate_release_sha256=None,
              expected_reference_sha256, expected_build_policy_sha256=None,
              expected_registry_sha256, approval_policy_path, approval_policy_sha256,
              token, _execution_context, _local_request=None):
    """One internal transaction core, also used by the reviewed Hosted adapter.

    This is not a public context-selection API. Python private functions are not
    a sandbox against arbitrary same-privilege code. Hosted authority relies on
    the reviewed deployment/code trust root and repeated Owner verification.
    """
    from . import local_registration_subject as local_subject, local_candidate_verification as local_remote
    result = {'status': 'BLOCKED', 'registry_committed': False, 'registration': 'NOT_PERFORMED',
              'scope': 'ISOLATED_COPY_ONLY', 'production_promotion': 'NOT_AUTHORIZED'}
    local_workspaces = []
    try:
        project = Path(project).resolve()
        policy = owner._policy(project, approval_policy_path, approval_policy_sha256)
        authoritative = project / policy['registry_path']
        _need(authoritative.is_file() and not authoritative.is_symlink(), 'UNSAFE_AUTHORITATIVE_REGISTRY')
        with _locked(project, isolation_directory, authoritative) as (fd, lockinfo):
            stage, prepared, transaction_id = None, None, None
            try:
                old = _read(fd, REGISTRY)
                old_inode = _inode(_regular(fd, REGISTRY))
                _need(evidence._sha(expected_registry_sha256) and _sha(old) == expected_registry_sha256
                      and authoritative.read_bytes() == old, 'STALE_OR_UNBOUND_REGISTRY')
                for name in os.listdir(fd):
                    if name.endswith('.prepared.json'):
                        _need(name.replace('.prepared.json', '.completed.json') in os.listdir(fd),
                              'UNRESOLVED_PREPARED_TRANSACTION')
                        _validated_audit(fd, name[:64])
                registry = _registry(old)
                _need(registry_key not in registry['baselines'], 'DUPLICATE_REGISTRY_KEY')
                context = _execution_context()
                if _local_request is not None:
                    _need(candidate_release is None and expected_candidate_release_sha256 is None
                          and expected_build_policy_sha256 is None, 'MIXED_ORIGIN_TRANSACTION')
                    verified = local_subject.prepare(project, authoritative, *_local_request, token=token)
                    local_workspaces.append(Path(verified['retained_directory']))
                    _need(verified['registration_subject']['approval_policy_sha256'] == approval_policy_sha256,
                          'LOCAL_POLICY_PIN_MISMATCH')
                else:
                    verified = evidence.verify(project, authoritative, registry_key, proposed_entry,
                        candidate_release=candidate_release,
                        expected_candidate_release_sha256=expected_candidate_release_sha256,
                        expected_reference_sha256=expected_reference_sha256,
                        expected_build_policy_sha256=expected_build_policy_sha256,
                        expected_registry_sha256=expected_registry_sha256,
                        approval_policy_sha256=approval_policy_sha256, token=token)
                _need(verified.get('status') == 'EVIDENCE_VERIFIED'
                      and verified.get('execution') == 'NO_FRESH_REPLAY', 'EVIDENCE_NOT_VERIFIED')
                subject = evidence._json(canonical(verified['registration_subject']))
                if _local_request is not None:
                    local_subject.validate(subject)
                    _need(subject['request_sha256'] == _local_request[1], 'LOCAL_REQUEST_SUBJECT_MISMATCH')
                _need(verified['registration_subject_sha256'] == digest(subject)
                      and subject['registry_entry'] == proposed_entry
                      and subject['registry_key'] == registry_key
                      and subject['expected_old_registry_sha256'] == expected_registry_sha256,
                      'REGISTRATION_SUBJECT_MISMATCH')
                # A's session is gone. Restore the exact pinned Baseline again;
                # restore() and Owner preflight reverify it, not a saved receipt.
                with tempfile.TemporaryDirectory(prefix='registration-qualification-') as tmp:
                    work = Path(tmp)
                    ref = subject['registry_entry']['reference']
                    if _local_request is not None:
                        baseline = Path(verified['retained_directory'])/'baseline'
                    elif ref.get('schema_version') == 3:
                        baseline = local_remote.restore_delivery(project, ref, expected_reference_sha256,
                                                                 work, token=token, stem='baseline')
                    else:
                        transport.download(ref['storage'], work / 'baseline.tar.gz',
                                           ref['transport_sha256'], token=token)
                        transport.restore(project, work / 'baseline.tar.gz', work / 'baseline',
                                          ref, expected_reference_sha256)
                        baseline = work/'baseline'
                    histories = _duplicate_check(project, registry, subject, work, token)
                    historical_notices = _retain_historical_notices(fd, histories)
                    client = owner.GitHubCLI()
                    approval = _approval(project, authoritative, approval_policy_path,
                        approval_policy_sha256, baseline, subject, context, client)
                    updated = evidence._json(canonical(registry))
                    updated['baselines'][registry_key] = subject['registry_entry']
                    new = _serialize(updated)
                    _registry(new)
                    prepared = {'schema_version': 1, 'state': 'PREPARED',
                        'old_registry_text': old.decode('utf-8'), 'old_registry_sha256': _sha(old),
                        'new_registry_sha256': _sha(new), 'registration_subject': subject,
                        'registration_subject_sha256': digest(subject), 'owner_approval': approval,
                        'execution': 'NO_FRESH_REPLAY', 'registration_scope': 'ISOLATED_COPY_ONLY',
                        'production_promotion': 'NOT_AUTHORIZED'}
                    if _local_request is not None:
                        prepared.update(schema_version=2, evidence_origin='LOCAL_RESEARCH_EXECUTION',
                            request_sha256=_local_request[1], local_audit=_retain_local(fd,verified,historical_notices))
                    # The transaction ID is the externally returned digest of
                    # the full PREPARED payload (no circular self-hash).
                    transaction_id = digest(prepared)
                    result['transaction_id'] = transaction_id
                    _write_once(fd, transaction_id + '.prepared.json',
                                _serialize({'transaction_id': transaction_id, **prepared}))
                    stage = _stage(fd, new, 'registry')
                    # Recheck API/policy/P4.1 state immediately before commit.
                    _need(_execution_context() == context, 'EXECUTION_CONTEXT_CHANGED_BEFORE_COMMIT')
                    if _local_request is not None:
                        repeated = local_subject.prepare(project, authoritative, *_local_request, token=token)
                        local_workspaces.append(Path(repeated['retained_directory']))
                        _need(repeated['registration_subject'] == subject
                              and repeated['registration_subject_sha256'] == digest(subject),
                              'LOCAL_EVIDENCE_CHANGED_BEFORE_COMMIT')
                        baseline = Path(repeated['retained_directory'])/'baseline'
                    latest = _approval(project, authoritative, approval_policy_path,
                        approval_policy_sha256, baseline, subject, context, client)
                    _need(latest == approval, 'APPROVAL_CHANGED_BEFORE_COMMIT')
                    if _local_request is not None:
                        _validated_audit(fd, transaction_id)
                        _need(_execution_context() == context, 'FINAL_EXECUTION_CONTEXT_CHANGED')
                    _unchanged_directory(isolation_directory, fd)
                    _need(_inode(_regular(fd, LOCK)) == _inode(lockinfo), 'LOCK_IDENTITY_CHANGED')
                    _need(_read(fd, REGISTRY) == old and _inode(_regular(fd, REGISTRY)) == old_inode
                          and authoritative.read_bytes() == old, 'REGISTRY_CHANGED_BEFORE_COMMIT')
                    os.replace(stage, REGISTRY, src_dir_fd=fd, dst_dir_fd=fd)  # Commit point.
                    stage = None
                    result.update(registry_committed=True, registry_sha256=_sha(new))
                    os.fsync(fd)
                    _need(_read(fd, REGISTRY) == new, 'COMMITTED_REGISTRY_CHANGED')
                    _complete(fd, prepared, transaction_id)
                    result.update(status='COMPLETED', registration='ISOLATED_COPY_UPDATED',
                                  execution='NO_FRESH_REPLAY')
            except Exception as error:
                # os.replace may have committed even if a wrapper/later operation
                # raised. Report observed bytes, never assume error means rollback.
                try:
                    actual = _sha(_read(fd, REGISTRY))
                    result['registry_sha256'] = actual
                    matches_new = bool(prepared and actual == prepared['new_registry_sha256'])
                    result['registry_matches_new'] = matches_new
                    result['registry_committed'] = result['registry_committed'] or matches_new
                except Exception:
                    result['registry_state'] = 'UNREADABLE'
                if result['registry_committed']:
                    result.update(status='COMMITTED_WITH_ERROR', registration='ISOLATED_COPY_UPDATED')
                result['reason'] = str(error) if isinstance(error, TransactionError) else 'VERIFICATION_OR_TRANSACTION_FAILED'
            finally:
                if stage is not None:
                    try:
                        os.unlink(stage, dir_fd=fd)
                    except FileNotFoundError:
                        pass
    except Exception as error:
        result['reason'] = str(error) if isinstance(error, TransactionError) else 'INVALID_INPUT_OR_ISOLATION'
    finally:
        for path in local_workspaces:
            shutil.rmtree(path, ignore_errors=True)
    return result


def _validated_local_audit(fd, record):
    """Retained bytes only. No network, Owner decision or scientific replay."""
    from . import local_registration_subject as local_subject, local_candidate_verification as local_remote
    subject = local_subject.validate(record['registration_subject'])
    _need(record['evidence_origin'] == 'LOCAL_RESEARCH_EXECUTION'
          and record['request_sha256'] == subject['request_sha256']
          and record['owner_approval']['schema_version'] == 2
          and record['owner_approval']['approval_policy_sha256'] == subject['approval_policy_sha256'],
          'INVALID_LOCAL_AUDIT_BINDING')
    approved=record['owner_approval'];domain=subject['trust_domain']
    _need(all(approved['workflow_run'][k]==domain[k] for k in ('repository','repository_id','workflow_path'))
          and approved['workflow_run']['branch']==domain['default_branch']
          and approved['review_subject']['registry_entry_sha256']==subject['registry_entry_sha256'],
          'INVALID_LOCAL_AUDIT_APPROVAL')
    pins = record['local_audit']
    _need(isinstance(pins,dict) and set(pins) == {'bundle_sha256','notices_sha256'}
          and all(evidence._sha(v) for v in pins.values()), 'INVALID_LOCAL_AUDIT_PINS')
    raw = _read(fd,pins['bundle_sha256']+'.evidence.json')
    _need(len(raw)<=8*1024**2 and _sha(raw)==pins['bundle_sha256'],'CORRUPT_LOCAL_AUDIT_BUNDLE')
    bundle = evidence._json(raw)
    _need(set(bundle) == {'schema_version','subject_sha256','request_text','policy_text',
          'descriptor_text','transport_manifest_text','historical_notices'} and type(bundle['schema_version']) is int
          and bundle['schema_version']==1 and bundle['subject_sha256']==digest(subject), 'INVALID_LOCAL_AUDIT_BUNDLE')
    d=subject['scientific']['descriptor']; local=subject['local_evidence']; ref=subject['registry_entry']['reference']
    for text,pin in [('request_text',subject['request_sha256']),('policy_text',subject['approval_policy_sha256']),
                     ('descriptor_text',local['descriptor_sha256']),
                     ('transport_manifest_text',local['transport']['manifest_sha256'])]:
        _need(isinstance(bundle[text],str) and _sha(bundle[text].encode())==pin,'CORRUPT_RETAINED_EVIDENCE')
    _need(evidence._json(bundle['descriptor_text'])==d,'AUDIT_DESCRIPTOR_MISMATCH')
    request=evidence._json(bundle['request_text']); policy=evidence._json(bundle['policy_text'])
    _need(type(request['schema_version']) is int and request['schema_version']==3
          and request['local_evidence']==local and request['proposed_entry']==subject['registry_entry']
          and request['registry_key']==subject['registry_key']
          and request['expected_registry_sha256']==subject['expected_old_registry_sha256']
          and request['approval_policy_sha256']==subject['approval_policy_sha256']
          and {k:policy[k] for k in local_subject.DOMAIN}==subject['trust_domain'], 'AUDIT_REQUEST_MISMATCH')
    manifest=evidence._json(bundle['transport_manifest_text'])
    _need(set(manifest)==local_remote.transport.MANIFEST_FIELDS
          and manifest['descriptor_sha256']==local['descriptor_sha256']
          and all(manifest[k]==d[k] for k in local_remote.transport.BINDINGS), 'AUDIT_MANIFEST_MISMATCH')
    for name,key in [('run/full/manifest.json','full_snapshot_manifest_sha256'),('run/parity.json','full_parity_sha256')]:
        _need(manifest['files'][name]['sha256']==subject['scientific'][key],'AUDIT_SCIENCE_MISMATCH')
    notice_name=pins['notices_sha256']+'.notices.zip'
    _need(_sha(_read(fd,notice_name))==pins['notices_sha256']==ref['notices']['sha256'], 'CORRUPT_RETAINED_NOTICES')
    # The stable directory fd anchors Linux procfs reads even if its pathname is
    # replaced. Public ZIP validation is offline and never restores a Parent.
    receipt=transport.verify_notices(ref,subject['baseline']['reference_sha256'],
                                    Path('/proc/self/fd')/str(fd)/notice_name)
    _need(receipt==subject['scientific']['notices_verification'],'RETAINED_NOTICES_MISMATCH')
    expected={e['expected_reference_sha256']:e['reference'] for e in
        _registry(record['old_registry_text'].encode())['baselines'].values()
        if e['reference'].get('schema_version')==3}
    histories=bundle['historical_notices']
    _need(isinstance(histories,list) and len(histories)==len(expected),'INCOMPLETE_HISTORICAL_NOTICES')
    seen=set()
    for item in histories:
        _need(isinstance(item,dict) and set(item)=={'reference','reference_sha256','notices_sha256','notices_verification'},
              'INVALID_HISTORICAL_NOTICES')
        pin=item['reference_sha256'];oldref=item['reference']
        _need(pin in expected and pin not in seen and expected[pin]==oldref
              and digest(oldref)==pin and item['notices_sha256']==oldref['notices']['sha256'],
              'HISTORICAL_NOTICES_BINDING_MISMATCH')
        seen.add(pin);name=item['notices_sha256']+'.notices.zip'
        _need(_sha(_read(fd,name))==item['notices_sha256'],'CORRUPT_HISTORICAL_NOTICES')
        observed=transport.verify_notices(oldref,pin,Path('/proc/self/fd')/str(fd)/name)
        _need(observed==item['notices_verification'],'INVALID_HISTORICAL_NOTICES_RECEIPT')


def _prepared_identity(fd, transaction_id):
    """Validate pinned PREPARED identities independently of completion damage."""
    from . import local_registration_subject as local_subject
    _need(evidence._sha(transaction_id), 'INVALID_TRANSACTION_ID')
    record = evidence._json(_read(fd, transaction_id + '.prepared.json'))
    _need(record.pop('transaction_id') == transaction_id and digest(record) == transaction_id,
          'CORRUPT_PREPARED_RECORD')
    subject = record['registration_subject']
    version = record.get('schema_version')
    common = {'schema_version','state','old_registry_text','old_registry_sha256','new_registry_sha256',
        'registration_subject','registration_subject_sha256','owner_approval','execution',
        'registration_scope','production_promotion'}
    _need(type(version) is int and version in (1,2)
          and set(record)==(common if version==1 else common|{'evidence_origin','request_sha256','local_audit'})
          and type(subject.get('schema_version')) is int and subject['schema_version']==version,
          'UNSUPPORTED_AUDIT_VERSION')
    if version==2:
        local_subject.validate(subject)
    _need(record['state'] == 'PREPARED'
          and record['execution'] == subject['execution'] == 'NO_FRESH_REPLAY'
          and record['production_promotion'] == subject['production_promotion'] == 'NOT_AUTHORIZED'
          and record['registration_scope'] == 'ISOLATED_COPY_ONLY'
          and record['registration_subject_sha256'] == digest(subject)
          and record['owner_approval']['registration_subject_sha256'] == digest(subject)
          and record['owner_approval']['status'] == 'OWNER_APPROVAL_VERIFIED', 'INVALID_AUDIT_BINDINGS')
    old = record['old_registry_text'].encode('utf-8')
    _need(_sha(old) == record['old_registry_sha256'] == subject['expected_old_registry_sha256'],
          'INVALID_AUDIT_OLD_REGISTRY')
    updated = _registry(old)
    key, entry = subject['registry_key'], subject['registry_entry']
    _need(key not in updated['baselines'] and digest(entry) == subject['registry_entry_sha256'],
          'INVALID_AUDIT_ENTRY')
    _need(subject['baseline']['baseline_id'] == entry['reference']['node_id']
          and subject['candidate']['corpus_sha256'] == entry['reference']['corpus_sha256']
          and subject['parent_r2_anchor']['candidate_id'] == subject['candidate']['candidate_id'],
          'INVALID_AUDIT_IDENTITY')
    updated['baselines'][key] = entry
    new = _serialize(updated)
    _need(_sha(new) == record['new_registry_sha256'], 'INVALID_AUDIT_NEW_REGISTRY')
    return record, old, new


def _completion_identity(fd, record, transaction_id):
    completed = transaction_id + '.completed.json'
    if completed in os.listdir(fd):
        _need(_read(fd, completed) == _serialize(_completion(record, transaction_id)),
              'CORRUPT_COMPLETION_RECORD')


def _audit_identity(fd, transaction_id):
    record, old, new = _prepared_identity(fd, transaction_id)
    _completion_identity(fd, record, transaction_id)
    return record, old, new


def _validated_audit(fd, transaction_id):
    record, old, new = _audit_identity(fd,transaction_id)
    if record['schema_version']==2:
        _validated_local_audit(fd,record)
    return record, old, new


def recover(project, isolation_directory, *, transaction_id):
    """Verify a journal by its independently retained transaction ID.

    Recovery observes bytes and only completes audit evidence. It cannot write a
    Registry or issue authorization. Journals are trusted local records, not
    cryptographic signatures against a malicious equal-privilege user.
    """
    result = {'status': 'BLOCKED', 'registry_modified': False, 'registry_committed': False,
              'authorization': 'NOT_GRANTED_BY_RECOVERY', 'production_promotion': 'NOT_AUTHORIZED'}
    try:
        authoritative = Path(project) / 'configs/ci_v2_schema2_trusted_baselines.json'
        with _locked(project, isolation_directory, authoritative) as (fd, _):
            record, old, new = _prepared_identity(fd, transaction_id)
            actual = _read(fd, REGISTRY)
            result['registry_sha256'] = _sha(actual)
            if actual == old:
                _need(transaction_id + '.completed.json' not in os.listdir(fd),
                      'COMPLETED_RECORD_WITH_OLD_REGISTRY')
                if record['schema_version']==2:
                    _validated_local_audit(fd,record)
                result['status'] = 'NOT_COMMITTED'
            elif actual == new:
                result.update(status='COMMITTED_WITH_ERROR', registry_committed=True)
                # A valid PREPARED record and exact new bytes already establish
                # the commit. Completion damage must not erase that fact.
                _completion_identity(fd, record, transaction_id)
                if record['schema_version']==2:
                    _validated_local_audit(fd,record)
                _unchanged_directory(isolation_directory, fd)
                os.fsync(fd)
                _complete(fd, record, transaction_id)
                result['status'] = 'COMPLETED'
            else:
                result['status'] = 'CONFLICT'
    except Exception as error:
        result['reason'] = str(error) if isinstance(error, TransactionError) else 'MISSING_OR_INVALID_RECOVERY_EVIDENCE'
    return result
