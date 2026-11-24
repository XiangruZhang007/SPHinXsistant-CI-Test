"""Non-authorizing Git REST protocol; NOT a live authorization backend.

The network transport is separate. The Hosted observer may inspect its chain,
but never reserve or consume before independent Writer/governance verification.
Synthetic successes never authenticate an Owner or grant build authority.
"""
from copy import deepcopy
import hashlib
import json
import re
import secrets

from . import parent_authority_transition as transition
from .corpus_snapshot import canonical, digest
from .trusted_snapshot import repository_identity

PROTOCOL = 'PARENT_AUTHORITY_GIT_AUDIT_V1'
LIMIT = 128 * 1024
CONFIG_FIELDS = {'schema_version', 'repository', 'repository_id', 'ref',
                 'genesis_sha', 'tree_sha', 'governance_sha256'}
BINDING_FIELDS = {'request_sha256', 'proposal_sha256', 'subject_sha256',
                  'owner_decision_sha256', 'decision', 'baseline_id',
                  'reference_sha256', 'notices_sha256'}
POLICY_BINDING_FIELDS = (BINDING_FIELDS - {'owner_decision_sha256'}) | {'policy_decision_sha256'}
POLICY_DECISION_FIELDS = {'schema_version','operation','decision','transaction_id','repository','repository_id',
    'implementation_revision','old_registry_sha256','result_registry_sha256','policy_sha256',
    'run_id','run_attempt','actor_id','workflow_id','workflow_path','event','request_sha256','proposal_sha256'}
EVENT_FIELDS = {'schema_version', 'protocol', 'state', 'previous_sha',
                'previous_event_sha256', 'binding', 'claim_nonce',
                'result_registry_sha256', 'receipt_sha256'}


class AuditError(ValueError):
    pass


def _need(condition, reason):
    if not condition:
        raise AuditError(reason)


def _hash(value, size=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{%d}' % size, value) is not None


def backend_status():
    """Public surface has no opt-in, transport or decision parameters."""
    return {'status': 'BLOCKED', 'authorization': 'NOT_GRANTED',
            'reason': 'INDEPENDENT_AUDIT_GOVERNANCE_AND_LIVE_ADAPTER_NOT_CONFIGURED'}


def _binding(proposal, decision, *, expected_proposal_sha256, expected_subject_sha256,
             expected_actor_id, expected_run_id, governance_policy_sha256=None,
             bootstrap_sha256=None):
    """Reuse B3 consistency validation, explicitly NOT Owner authentication."""
    r = proposal['request']
    transition.inspect_owner_decision(proposal, decision,
        expected_proposal_sha256=expected_proposal_sha256,
        expected_transaction_id=r['transaction_id'],
        expected_actor_id=expected_actor_id, expected_run_id=expected_run_id)
    # Reuse the actual B4 Subject contract, without running its API observer.
    from .hosted_parent_authority_transition import subject
    _need(digest(subject(r, expected_proposal_sha256, decision['workflow_id'],
          governance_policy_sha256=governance_policy_sha256, bootstrap_sha256=bootstrap_sha256))
          == expected_subject_sha256, 'AUDIT_SUBJECT_MISMATCH')
    return {'request_sha256': proposal['request_sha256'],
            'proposal_sha256': expected_proposal_sha256,
            'subject_sha256': expected_subject_sha256,
            'owner_decision_sha256': digest(decision), 'decision': deepcopy(decision),
            **{k: r[k] for k in ('baseline_id', 'reference_sha256', 'notices_sha256')}}


def _scope(config, binding):
    d = binding['decision']
    # The independently pinned genesis is dedicated to ONE exact transaction,
    # not a new branch chosen by a dispatch input or by each competing runner.
    return {'transaction_id': d['transaction_id'],
            'request_sha256': binding['request_sha256'],
            'proposal_sha256': binding['proposal_sha256'],
            'old_registry_sha256': d['old_registry_sha256'],
            'result_registry_sha256': d['result_registry_sha256']}


def _genesis(config, binding):
    if config['schema_version'] == 3:
        from scripts.parent_authority_writer_bootstrap import genesis
        return genesis(config, binding)
    return {'schema_version': 1, 'protocol': PROTOCOL,
            'domain': {k: config[k] for k in CONFIG_FIELDS - {'genesis_sha'}},
            'transaction': _scope(config, binding)}


def _message(value):
    raw = canonical(value)
    _need(len(raw) <= LIMIT, 'OVERSIZED_AUDIT_EVENT')
    return raw.decode('utf-8')


def _parse(message):
    _need(isinstance(message, str) and len(message.encode()) <= LIMIT,
          'INVALID_AUDIT_MESSAGE')
    try:
        def unique(pairs):
            result = {}
            for k, v in pairs:
                _need(k not in result, 'DUPLICATE_AUDIT_KEY')
                result[k] = v
            return result
        value = json.loads(message, object_pairs_hook=unique)
        _need(_message(value) == message, 'NONCANONICAL_AUDIT_MESSAGE')
        return value
    except (ValueError, TypeError, OverflowError, RecursionError) as error:
        raise AuditError('INVALID_AUDIT_MESSAGE') from error


class _IsolatedGitProtocol:
    """Private non-authorizing protocol, reused behind separately verified gates.

    Config v1 retains manual Owner bindings; config v2 binds an explicit automatic
    policy decision. Neither authenticates its caller. Historical primitive
    statuses retain NOT_GRANTED/OFFLINE_PROTOCOL_TEST; real operation success
    requires the outer trusted gate and independent storage/readback verification.
    """
    def __init__(self, transport, config, binding):
        self._api = transport
        self._config = deepcopy(config)
        self._binding = deepcopy(binding)
        c, b = self._config, self._binding
        _need(isinstance(c, dict) and set(c) == CONFIG_FIELDS
              and type(c['schema_version']) is int and c['schema_version'] in (1, 2, 3),
              'INVALID_AUDIT_CONFIG')
        fields = POLICY_BINDING_FIELDS if c['schema_version'] == 2 else BINDING_FIELDS
        _need(isinstance(b, dict) and set(b) == fields, 'INVALID_AUDIT_BINDING')
        d = b['decision']
        _need(isinstance(d, dict) and set(d) == (POLICY_DECISION_FIELDS if c['schema_version'] == 2 else transition.DECISION_FIELDS),
              'INVALID_AUDIT_OWNER_BINDING')
        _need(c['repository'] == d['repository']
              and c['repository_id'] == d['repository_id']
              and type(c['repository_id']) is int and c['repository_id'] > 0
              and isinstance(c['repository'], str)
              and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', c['repository']),
              'AUDIT_REPOSITORY_BINDING_MISMATCH')
        _need(isinstance(d['transaction_id'], str)
              and re.fullmatch('[0-9a-f]{32}', d['transaction_id'])
              and c['ref'] == 'refs/heads/ci-v2-authority-audit/' + d['transaction_id'],
              'AUDIT_REF_BINDING_MISMATCH')
        _need(_hash(c['genesis_sha'], 40) and _hash(c['tree_sha'], 40)
              and _hash(c['governance_sha256'])
              and all(_hash(b[k]) for k in fields if k.endswith('_sha256'))
              and transition._hash(b['baseline_id'], 'sha256-'), 'INVALID_AUDIT_PINS')
        _need(digest(d) == b['policy_decision_sha256' if c['schema_version'] == 2 else 'owner_decision_sha256']
              and d['proposal_sha256'] == b['proposal_sha256']
              and d['request_sha256'] == b['request_sha256'], 'AUDIT_OWNER_BINDING_MISMATCH')
        if c['schema_version'] == 2:
            _need(d['operation'] == 'AUTOMATIC_PARENT_ADVANCEMENT_V1'
                  and d['decision'] == 'POLICY_AUTHORIZED_AUTOMATIC_ADVANCEMENT'
                  and type(d['schema_version']) is int and d['schema_version'] == 1 and d['event'] == 'schedule'
                  and type(d['run_attempt']) is int and d['run_attempt'] == 1 and _hash(d['implementation_revision'],40) and all(type(d[k]) is int and d[k] > 0
                    for k in ('run_id','actor_id','workflow_id'))
                  and _hash(d['policy_sha256']) and _hash(d['old_registry_sha256'])
                  and _hash(d['result_registry_sha256']), 'INVALID_AUTOMATIC_POLICY_BINDING')
        self._prefix = 'repos/' + c['repository']
        self._nonce = None
        self._phase = 'NEW'
        self._observed_head = None

    def _call(self, method, suffix='', body=None):
        try:
            status, value = self._api.request(method, self._prefix + suffix, deepcopy(body))
        except Exception as error:
            # Never retain tokens, signed URLs or an arbitrary transport message.
            raise AuditError('AUDIT_API_OUTCOME_UNCERTAIN') from error
        _need(status == (201 if method == 'POST' else 200),
              'AUDIT_API_CONFLICT' if status in (409, 422) else 'AUDIT_API_UNAVAILABLE')
        _need(isinstance(value, dict), 'INVALID_AUDIT_API_RESPONSE')
        return value

    def _commit(self, sha):
        _need(_hash(sha, 40), 'INVALID_AUDIT_COMMIT_SHA')
        obj = self._call('GET', '/git/commits/' + sha)
        _need(obj.get('sha') == sha and isinstance(obj.get('tree'), dict)
              and obj['tree'].get('sha') == self._config['tree_sha']
              and isinstance(obj.get('parents'), list), 'AUDIT_COMMIT_IDENTITY_MISMATCH')
        parents = obj['parents']
        _need(all(isinstance(p, dict) and _hash(p.get('sha'), 40) for p in parents),
              'INVALID_AUDIT_PARENTS')
        return obj, _parse(obj.get('message'))

    def _scan(self):
        c = self._config
        repo = self._call('GET')
        _need(repository_identity(repo, c['repository'], c['repository_id']),
              'AUDIT_REPOSITORY_IDENTITY_MISMATCH')
        ref = self._call('GET', '/git/ref/' + c['ref'][5:])
        _need(ref.get('ref') == c['ref'] and isinstance(ref.get('object'), dict)
              and ref['object'].get('type') == 'commit',
              'AUDIT_REF_IDENTITY_MISMATCH')
        head = ref['object'].get('sha'); current = head; reverse = []; seen = set()
        # Exactly one transaction has at most RESERVED, CONSUMED, COMPLETED.
        for _ in range(4):
            _need(current not in seen, 'AUDIT_HISTORY_CYCLE'); seen.add(current)
            obj, event = self._commit(current)
            if current == c['genesis_sha']:
                _need(obj['parents'] == [] and event == _genesis(c, self._binding),
                      'AUDIT_GENESIS_MISMATCH')
                break
            _need(len(obj['parents']) == 1 and isinstance(event, dict)
                  and set(event) == EVENT_FIELDS and type(event['schema_version']) is int
                  and event['schema_version'] == 1
                  and event['protocol'] == PROTOCOL
                  and event['previous_sha'] == obj['parents'][0]['sha'],
                  'AUDIT_LINEAR_HISTORY_REQUIRED')
            reverse.append((current, event)); current = obj['parents'][0]['sha']
        else:
            raise AuditError('AUDIT_HISTORY_BOUND_EXCEEDED')
        events = list(reversed(reverse)); previous = _genesis(c, self._binding)
        nonce = None
        for i, (_, event) in enumerate(events):
            _need(event['state'] == ('RESERVED', 'CONSUMED', 'COMPLETED')[i]
                  and event['binding'] == self._binding
                  and event['previous_event_sha256'] == digest(previous),
                  'AUDIT_STATE_OR_BINDING_MISMATCH')
            _need(_hash(event['claim_nonce']) and (nonce is None or nonce == event['claim_nonce']),
                  'AUDIT_CLAIM_MISMATCH')
            nonce = event['claim_nonce']
            expected = self._binding['decision']['result_registry_sha256']
            if i == 2:
                _need(event['result_registry_sha256'] == expected
                      and _hash(event['receipt_sha256']), 'AUDIT_COMPLETION_PIN_MISMATCH')
            else:
                _need(event['result_registry_sha256'] is None and event['receipt_sha256'] is None,
                      'PREMATURE_AUDIT_COMPLETION')
            previous = event
        # Detect rollback/replacement within this process. A fresh runner cannot
        # infer a deleted prior history from genesis + current metadata alone.
        _need(self._observed_head is None or self._observed_head in seen,
              'AUDIT_OBSERVED_HISTORY_ROLLED_BACK')
        self._observed_head = head
        return head, events

    @staticmethod
    def _result(status, **extra):
        return {'status': status, 'authorization': 'NOT_GRANTED',
                'scope': 'OFFLINE_PROTOCOL_TEST', 'live_apply': False, **extra}

    def inspect(self):
        """Read-only restart/reconciliation; never grants or resumes an approval."""
        try:
            head, events = self._scan()
            state = events[-1][1]['state'] if events else 'NOT_RESERVED'
            return self._result(state + '_REVIEW_REQUIRED', head=head,
                                recovered_authorization=False, automatic_retry=False)
        except (AuditError, KeyError, TypeError, ValueError):
            return self._result('STATE_UNCERTAIN', recovered_authorization=False)

    def _append(self, head, events, state, *, result=None, receipt=None):
        event = {'schema_version': 1, 'protocol': PROTOCOL, 'state': state,
                 'previous_sha': head, 'previous_event_sha256': digest(
                     events[-1][1] if events else _genesis(self._config, self._binding)),
                 'binding': self._binding, 'claim_nonce': self._nonce,
                 'result_registry_sha256': result, 'receipt_sha256': receipt}
        message = _message(event)
        # Immediate-child + unique nonce is the essential restriction. This is
        # NOT a generic REST compare-and-swap or a force=false-only guarantee.
        obj = self._call('POST', '/git/commits', {
            'message': message, 'tree': self._config['tree_sha'], 'parents': [head]})
        sha = obj.get('sha'); check, read_event = self._commit(sha)
        _need([p['sha'] for p in check['parents']] == [head] and read_event == event,
              'AUDIT_CREATED_COMMIT_MISMATCH')
        # GitHub parent metadata may include URLs; comparing only SHA above is
        # sufficient for the independently re-read single-parent object.
        self._call('PATCH', '/git/refs/' + self._config['ref'][5:], {'sha': sha, 'force': False})
        actual, records = self._scan()
        _need(actual == sha and records[-1] == (sha, event), 'AUDIT_WRITE_READBACK_MISMATCH')
        return sha

    def reserve(self):
        if self._phase != 'NEW':
            return self._result('DUPLICATE_OR_UNCERTAIN_RESERVATION')
        # Never reset this flag, including failed calls or uncertain writes.
        self._phase = 'CLOSED'
        try:
            head, events = self._scan()
            _need(not events, 'DUPLICATE_TRANSACTION')
            self._nonce = secrets.token_hex(32)
            self._append(head, events, 'RESERVED')
            self._phase = 'RESERVED'
            return self._result('RESERVED')
        except (AuditError, KeyError, TypeError, ValueError):
            return self._result('RESERVATION_NOT_GRANTED', reconciliation=self.inspect())

    def consume(self):
        """Burn approval durably BEFORE any future isolated application.

        A restart can inspect but cannot reacquire the in-memory claim. Crashes
        sacrifice liveness instead of issuing another successful consumption.
        """
        if self._phase != 'RESERVED':
            return self._result('CONSUMPTION_DENIED')
        self._phase = 'CLOSED'
        try:
            head, events = self._scan()
            _need(len(events) == 1 and events[0][1]['claim_nonce'] == self._nonce,
                  'AUDIT_CLAIM_NOT_OWNED')
            self._append(head, events, 'CONSUMED')
            self._phase = 'CONSUMED'
            return self._result('CONSUMED_OFFLINE')
        except (AuditError, KeyError, TypeError, ValueError):
            return self._result('CONSUMPTION_NOT_GRANTED', reconciliation=self.inspect())

    def complete(self, result_bytes, local_result):
        if self._phase != 'CONSUMED':
            return self._result('COMPLETION_DENIED')
        self._phase = 'CLOSED'
        try:
            expected = self._binding['decision']['result_registry_sha256']
            if self._config['schema_version'] == 2:
                receipt = local_result.get('receipt', {})
                _need(isinstance(result_bytes, bytes) and hashlib.sha256(result_bytes).hexdigest() == expected
                      and local_result.get('status') == 'COMPLETED'
                      and local_result.get('scope') == 'DERIVED_DATA_REF_ONLY'
                      and receipt == {'operation':'AUTOMATIC_PARENT_ADVANCEMENT_V1',
                          'transaction_id':self._binding['decision']['transaction_id'],
                          'state_sha':receipt.get('state_sha'),'registry_sha256':expected}
                      and _hash(receipt['state_sha'],40),'DERIVED_COMPLETION_MISMATCH')
            else:
                _need(isinstance(result_bytes, bytes) and hashlib.sha256(result_bytes).hexdigest() == expected
                      and local_result.get('status') == 'COMPLETED'
                      and local_result.get('result_registry_sha256') == expected
                      and local_result.get('scope') == 'ISOLATED_COPY_ONLY'
                      and isinstance(local_result.get('receipt'), dict), 'ISOLATED_COMPLETION_MISMATCH')
                receipt = local_result['receipt']; decision = self._binding['decision']
                _need(receipt.get('status') == 'COMPLETED'
                      and receipt.get('operation') == transition.OPERATION
                      and receipt.get('transaction_id') == decision['transaction_id']
                      and receipt.get('proposal_sha256') == self._binding['proposal_sha256']
                      and receipt.get('request_sha256') == self._binding['request_sha256']
                      and receipt.get('old_registry_sha256') == decision['old_registry_sha256']
                      and receipt.get('result_registry_sha256') == receipt.get('registry_sha256') == expected
                      and receipt.get('scope') == 'ISOLATED_COPY_ONLY'
                      and all(_hash(receipt.get(k)) for k in ('prepared_sha256', 'evidence_sha256', 'journal_id')),
                      'ISOLATED_RECEIPT_BINDING_MISMATCH')
            head, events = self._scan()
            _need(len(events) == 2 and events[-1][1]['claim_nonce'] == self._nonce,
                  'AUDIT_CLAIM_NOT_CONSUMED')
            self._append(head, events, 'COMPLETED', result=expected,
                         receipt=digest(local_result['receipt']))
            return self._result('COMPLETED_OFFLINE')
        except (AuditError, KeyError, TypeError, ValueError):
            return self._result('COMPLETION_UNCERTAIN', reconciliation=self.inspect())
