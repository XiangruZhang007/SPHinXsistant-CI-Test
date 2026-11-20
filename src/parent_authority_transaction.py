"""Private isolated transaction core, NOT a cross-Hosted-run replay backend.

Reuse D2's no-follow dirfd locking, write-once audit and fsync staging. A single
persistent directory has durable local single-use semantics. Independent runner
directories do not share that protection. The public Hosted adapter therefore
never calls this core until an independently reviewed global backend exists.
Private test callbacks are not a public authorization-provider API.
"""
import base64
import hashlib
import json
import os

from . import baseline_registration_transaction as tx
from . import parent_authority_transition as transition
from .corpus_snapshot import digest


def _need(ok, reason):
    if not ok:
        raise transition.TransitionError(reason)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _id(proposal):
    return digest({'operation': transition.OPERATION,
                   'transaction_id': proposal['request']['transaction_id']})


def _local_apply(project, isolation, proposal, *, expected_proposal_sha256, _revalidate):
    """Internal core; requires a trusted adapter AND external global reservation.

    No production caller is wired in B4. Tests provide a synthetic observation
    callback explicitly at this private boundary. This is not process attestation.
    """
    result = {'status': 'BLOCKED', 'registry_committed': False,
              'scope': 'ISOLATED_COPY_ONLY', 'authorization': 'NOT_GRANTED',
              'global_replay_protection': 'NOT_ESTABLISHED',
              'production_promotion': 'NOT_AUTHORIZED'}
    _need(digest(proposal) == expected_proposal_sha256, 'LOCAL_PROPOSAL_PIN_MISMATCH')
    r = proposal['request']; transition._shape(r)
    _need(proposal['operation'] == transition.OPERATION and proposal['operative'] is False
          and proposal['authorization'] == 'NOT_GRANTED', 'NONOPERATIVE_PREPARE_REQUIRED')
    authoritative = project / r['registry_path']
    tid = _id(proposal)
    with tx._locked(project, isolation, authoritative) as (fd, lockinfo):
        try:
            _need(not any(tid + suffix in os.listdir(fd) for suffix in (
                '.prepared.json', '.completed.json', '.evidence.json')), 'DUPLICATE_TRANSACTION')
            old = tx._read(fd, tx.REGISTRY)
            _need(_sha(old) == r['old_registry_sha256'] and authoritative.read_bytes() == old,
                  'STALE_OR_UNBOUND_REGISTRY')
            registry = tx._registry(old)
            key = r['registry_key']; previous = registry['baselines'][key]
            _need(digest(previous) == proposal['old_entry_sha256']
                  and previous['entry_kind'] == 'REGISTRATION_ONLY'
                  and previous['reference'] == proposal['proposed_entry']['reference']
                  and previous['expected_reference_sha256'] == r['reference_sha256']
                  and previous['reference']['node_id'] == r['baseline_id'], 'OLD_ENTRY_MISMATCH')
            new = transition._result_bytes(registry, key, proposal['proposed_entry'])
            _need(_sha(new) == proposal['result_registry_sha256'] == r['result_registry_sha256'],
                  'RESULT_REGISTRY_PIN_MISMATCH')
            observation = _revalidate()
            _need(observation.get('status') == 'API_OWNER_TRANSITION_SUBJECT_VERIFIED'
                  and observation.get('proposal_sha256') == expected_proposal_sha256
                  and observation.get('proposal') == proposal
                  and observation.get('transaction_id') == r['transaction_id'],
                  'TRUSTED_OBSERVATION_BINDING_MISMATCH')
            evidence = {'schema_version': 1, 'operation': transition.OPERATION,
                'proposal': proposal, 'observation': observation,
                'old_registry_base64': base64.b64encode(old).decode('ascii')}
            evidence_raw = tx._serialize(evidence)
            tx._write_once(fd, tid + '.evidence.json', evidence_raw)
            prepared = {'schema_version': 1, 'operation': transition.OPERATION,
                'transaction_id': r['transaction_id'], 'journal_id': tid,
                'proposal_sha256': expected_proposal_sha256,
                'request_sha256': proposal['request_sha256'],
                'old_registry_sha256': _sha(old), 'result_registry_sha256': _sha(new),
                'evidence_sha256': _sha(evidence_raw), 'scope': 'ISOLATED_COPY_ONLY',
                'global_replay_protection': 'NOT_ESTABLISHED'}
            tx._write_once(fd, tid + '.prepared.json', tx._serialize(prepared))
            stage = tx._stage(fd, new, 'registry')
            _need(_revalidate() == observation, 'TRANSITION_AUTHORITY_CHANGED')
            tx._unchanged_directory(isolation, fd)
            _need(tx._inode(tx._regular(fd, tx.LOCK)) == tx._inode(lockinfo)
                  and tx._read(fd, tx.REGISTRY) == old and authoritative.read_bytes() == old,
                  'TRANSITION_REGISTRY_OR_LOCK_CHANGED')
            os.replace(stage, tx.REGISTRY, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
            _need(tx._read(fd, tx.REGISTRY) == new, 'ISOLATED_RESULT_BYTES_MISMATCH')
            completed = {**prepared, 'status': 'COMPLETED', 'registry_sha256': _sha(new),
                         'prepared_sha256': _sha(tx._read(fd, tid + '.prepared.json'))}
            tx._write_once(fd, tid + '.completed.json', tx._serialize(completed))
            result.update(status='COMPLETED', registry_committed=True, journal_id=tid,
                          transaction_id=r['transaction_id'], result_registry_sha256=_sha(new),
                          receipt=completed)
        except Exception as error:
            # A failed/ambiguous call never triggers a second replace or replay.
            try:
                actual = _sha(tx._read(fd, tx.REGISTRY))
                if actual == r['result_registry_sha256']:
                    result.update(status='COMMITTED_WITH_ERROR', registry_committed=True)
                elif actual != r['old_registry_sha256']:
                    result.update(status='STATE_UNCERTAIN', registry_committed=None)
            except Exception:
                result.update(status='STATE_UNCERTAIN', registry_committed=None)
            result['reason'] = str(error) if isinstance(error, (transition.TransitionError,
                tx.TransactionError)) else 'LOCAL_TRANSITION_FAILED'
    return result


def _inspect_local_state(project, isolation, proposal, *, expected_proposal_sha256):
    """Read-only crash classification. Never reconstruct Owner authority or retry.

    Supplied pins identify an offline review subject, not authenticated audit
    provenance. A fresh Owner/backend review is required for any later action.
    """
    _need(digest(proposal) == expected_proposal_sha256, 'LOCAL_PROPOSAL_PIN_MISMATCH')
    r = proposal['request']; tid = _id(proposal)
    with tx._locked(project, isolation, project / r['registry_path']) as (fd, _):
        evidence_raw = tx._read(fd, tid + '.evidence.json')
        prepared = tx.evidence._json(tx._read(fd, tid + '.prepared.json'))
        _need(prepared['operation'] == transition.OPERATION and prepared['journal_id'] == tid
              and prepared['transaction_id'] == r['transaction_id']
              and prepared['proposal_sha256'] == expected_proposal_sha256
              and prepared['evidence_sha256'] == _sha(evidence_raw), 'INVALID_TRANSITION_AUDIT')
        evidence = tx.evidence._json(evidence_raw)
        _need(evidence['proposal'] == proposal, 'AUDIT_PROPOSAL_MISMATCH')
        old = base64.b64decode(evidence['old_registry_base64'], validate=True)
        _need(_sha(old) == prepared['old_registry_sha256'] == r['old_registry_sha256'],
              'AUDIT_OLD_REGISTRY_MISMATCH')
        new = transition._result_bytes(tx._registry(old), r['registry_key'], proposal['proposed_entry'])
        _need(_sha(new) == prepared['result_registry_sha256'] == r['result_registry_sha256'],
              'AUDIT_RESULT_REGISTRY_MISMATCH')
        actual = tx._read(fd, tx.REGISTRY)
        if actual == old:
            state = 'PREPARED_NOT_APPLIED_REVIEW_REQUIRED'
        elif actual == new:
            state = 'NEW_BYTES_PRESENT_REVIEW_REQUIRED'
        else:
            state = 'STATE_UNCERTAIN'
        return {'status': state, 'global_replay_protection': 'NOT_ESTABLISHED',
                'authorization': 'NOT_GRANTED', 'automatic_recovery': 'NOT_PERFORMED',
                'transaction_id': r['transaction_id'], 'journal_id': tid}
