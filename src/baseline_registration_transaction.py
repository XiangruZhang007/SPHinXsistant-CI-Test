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
import stat
import tempfile
import uuid

from . import published_candidate_verification as evidence
from . import owner_manual_baseline_approval as owner
from . import trusted_snapshot as transport
from .corpus_snapshot import canonical, digest, file_digest

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
                             r'[0-9a-f]{64}\.(?:prepared|completed)\.json|'
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
    candidate = subject['candidate']
    proposed = subject['registry_entry']['reference']
    seen_nodes, seen_candidates = set(), set()
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
    return {'schema_version': 1, 'transaction_id': transaction_id, 'state': 'COMPLETED',
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


def _register(project, isolation_directory, *, registry_key, proposed_entry,
              candidate_release, expected_candidate_release_sha256,
              expected_reference_sha256, expected_build_policy_sha256=None,
              expected_registry_sha256, approval_policy_path, approval_policy_sha256,
              token, _execution_context):
    """One internal transaction core, also used by the reviewed Hosted adapter.

    This is not a public context-selection API. Python private functions are not
    a sandbox against arbitrary same-privilege code. Hosted authority relies on
    the reviewed deployment/code trust root and repeated Owner verification.
    """
    result = {'status': 'BLOCKED', 'registry_committed': False, 'registration': 'NOT_PERFORMED',
              'scope': 'ISOLATED_COPY_ONLY', 'production_promotion': 'NOT_AUTHORIZED'}
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
                    transport.download(ref['storage'], work / 'baseline.tar.gz',
                                       ref['transport_sha256'], token=token)
                    transport.restore(project, work / 'baseline.tar.gz', work / 'baseline',
                                      ref, expected_reference_sha256)
                    _duplicate_check(project, registry, subject, work, token)
                    client = owner.GitHubCLI()
                    approval = _approval(project, authoritative, approval_policy_path,
                        approval_policy_sha256, work / 'baseline', subject, context, client)
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
                    # The transaction ID is the externally returned digest of
                    # the full PREPARED payload (no circular self-hash).
                    transaction_id = digest(prepared)
                    result['transaction_id'] = transaction_id
                    _write_once(fd, transaction_id + '.prepared.json',
                                _serialize({'transaction_id': transaction_id, **prepared}))
                    stage = _stage(fd, new, 'registry')
                    # Recheck API/policy/P4.1 state immediately before commit.
                    _need(_execution_context() == context, 'EXECUTION_CONTEXT_CHANGED_BEFORE_COMMIT')
                    latest = _approval(project, authoritative, approval_policy_path,
                        approval_policy_sha256, work / 'baseline', subject, context, client)
                    _need(latest == approval, 'APPROVAL_CHANGED_BEFORE_COMMIT')
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
    return result


def _validated_audit(fd, transaction_id):
    _need(evidence._sha(transaction_id), 'INVALID_TRANSACTION_ID')
    record = evidence._json(_read(fd, transaction_id + '.prepared.json'))
    _need(record.pop('transaction_id') == transaction_id and digest(record) == transaction_id,
          'CORRUPT_PREPARED_RECORD')
    subject = record['registration_subject']
    _need(record['schema_version'] == 1 and record['state'] == 'PREPARED'
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
    completed = transaction_id + '.completed.json'
    if completed in os.listdir(fd):
        _need(_read(fd, completed) == _serialize(_completion(record, transaction_id)),
              'CORRUPT_COMPLETION_RECORD')
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
            record, old, new = _validated_audit(fd, transaction_id)
            actual = _read(fd, REGISTRY)
            result['registry_sha256'] = _sha(actual)
            if actual == old:
                _need(transaction_id + '.completed.json' not in os.listdir(fd),
                      'COMPLETED_RECORD_WITH_OLD_REGISTRY')
                result['status'] = 'NOT_COMMITTED'
            elif actual == new:
                result.update(status='COMMITTED_WITH_ERROR', registry_committed=True)
                _unchanged_directory(isolation_directory, fd)
                os.fsync(fd)
                _complete(fd, record, transaction_id)
                result['status'] = 'COMPLETED'
            else:
                result['status'] = 'CONFLICT'
    except Exception as error:
        result['reason'] = str(error) if isinstance(error, TransactionError) else 'MISSING_OR_INVALID_RECOVERY_EVIDENCE'
    return result
