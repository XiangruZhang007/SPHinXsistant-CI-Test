"""Owner transition V1 preparation only; no operative Registry writer or approval.

The existing registration Request/Subject and approval semantics are untouched.
An offline proposal/decision consistency check never authenticates an Owner.
Live AUTHORIZE/APPLY deliberately remain unavailable until a reviewed trusted
invocation and durable transaction-consumption boundary have been integrated.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from . import ci_v2_research as research, continuous_build_policy as continuous
from . import owner_manual_baseline_approval as owner
from . import schema2_workflow as workflow, trusted_snapshot as trust
from . import trusted_baseline_registration as registration
from . import trusted_parent_selection as selection
from .corpus_snapshot import checked_file, digest

OPERATION = 'PARENT_BUILD_AUTHORITY_TRANSITION_V1'
REQUEST_FIELDS = {
    'schema_version', 'operation', 'repository', 'repository_id', 'default_branch',
    'workflow_path', 'implementation_revision', 'registry_path', 'registry_key',
    'old_registry_sha256', 'baseline_id', 'reference_sha256', 'notices_sha256',
    'build_policy_path', 'build_policy_sha256', 'continuous_policy_path',
    'continuous_policy_sha256', 'owner_policy_path', 'owner_policy_sha256',
    'target_upstreams', 'target_source_state', 'result_registry_sha256',
    'transaction_id', 'resulting_authority',
}
PROPOSAL_FIELDS = {
    'schema_version', 'operation', 'status', 'authorization', 'operative',
    'request', 'request_sha256', 'old_entry_sha256', 'proposed_entry',
    'proposed_entry_sha256', 'result_registry_sha256', 'notices_verification',
    'scientific_verification', 'production_promotion',
}
DECISION_FIELDS = {
    'schema_version', 'operation', 'decision', 'proposal_sha256',
    'request_sha256', 'transaction_id', 'repository', 'repository_id',
    'implementation_revision', 'old_registry_sha256', 'result_registry_sha256',
    'continuous_policy_sha256', 'actor_id', 'triggering_actor_id', 'run_id',
    'run_attempt', 'workflow_id', 'workflow_path', 'event',
}
SCOPE_FIELDS = {'parent', 'base_source_state', 'target_source_state',
                'base_upstreams', 'target_upstreams', 'build_fingerprint',
                'orchestration_fingerprint'}
LIMIT = 8 * 1024**2


class TransitionError(ValueError):
    pass


def _need(ok, reason):
    if not ok:
        raise TransitionError(reason)


def _hash(value, prefix=''):
    return isinstance(value, str) and re.fullmatch(prefix + '[0-9a-f]{64}', value) is not None


def _read(project, name, expected):
    _need(isinstance(name, str) and re.fullmatch(r'configs/[A-Za-z0-9_.-]+\.json', name),
          'UNSAFE_CONFIG_PATH')
    _need(_hash(expected), 'INDEPENDENT_FILE_PIN_REQUIRED')
    path = checked_file(project, name)
    _need(path.stat().st_size <= LIMIT, 'OVERSIZED_CONFIG')
    raw = path.read_bytes()
    _need(len(raw) <= LIMIT and hashlib.sha256(raw).hexdigest() == expected,
          'FILE_PIN_MISMATCH')
    value = owner._strict_json(raw.decode('utf-8'))
    digest(value)
    return raw, value


def _shape(request):
    _need(isinstance(request, dict) and set(request) == REQUEST_FIELDS,
          'INVALID_TRANSITION_REQUEST')
    _need(type(request['schema_version']) is int and request['schema_version'] == 1
          and request['operation'] == OPERATION, 'WRONG_TRANSITION_OPERATION')
    _need(isinstance(request['repository'], str)
          and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', request['repository'])
          and type(request['repository_id']) is int and request['repository_id'] > 0,
          'INVALID_REPOSITORY_BINDING')
    _need(isinstance(request['registry_key'], str)
          and re.fullmatch('[a-z0-9][a-z0-9_-]{0,63}', request['registry_key']),
          'INVALID_PARENT_KEY')
    _need(isinstance(request['transaction_id'], str)
          and re.fullmatch('[0-9a-f]{32}', request['transaction_id']), 'INVALID_TRANSACTION_ID')
    _need(isinstance(request['implementation_revision'], str)
          and re.fullmatch('[0-9a-f]{40}', request['implementation_revision']),
          'INVALID_IMPLEMENTATION_REVISION')
    _need(all(_hash(request[k]) for k in REQUEST_FIELDS if k.endswith('_sha256')),
          'INVALID_TRANSITION_PIN')
    _need(_hash(request['baseline_id'], 'sha256-')
          and _hash(request['target_source_state'], 'sha256-'), 'INVALID_SOURCE_OR_BASELINE_ID')
    _need(request['resulting_authority'] == 'RESTRICTED_BUILD_CANDIDATE_ONLY',
          'UNSUPPORTED_RESULTING_AUTHORITY')
    research.validate_request('formal', request['registry_key'], request['target_upstreams'])


def _result_bytes(registry, key, entry):
    """Private deterministic calculation, never returned/written as a Registry."""
    result = deepcopy(registry)
    result['baselines'][key] = deepcopy(entry)
    return (json.dumps(result, ensure_ascii=False, sort_keys=True,
                       indent=2, allow_nan=False) + '\n').encode('utf-8')


def prepare(project, request, *, expected_request_sha256,
            expected_implementation_revision, notices_path):
    """Read pinned inputs; return a nonoperative proposal, never a Registry.

    Request/proposal pins are canonical JSON digests. Policy/Registry/notices
    pins are raw-byte digests. Neither a pin nor PREPARE supplies authorization.
    Metadata checks do not replace future source/package/P4.1/R2 verification.
    """
    _shape(request)
    _need(_hash(expected_request_sha256) and digest(request) == expected_request_sha256,
          'TRANSITION_REQUEST_PIN_MISMATCH')
    _need(request['implementation_revision'] == expected_implementation_revision,
          'IMPLEMENTATION_REVISION_MISMATCH')
    request = deepcopy(request)
    project = Path(project).resolve()
    raw, registry = _read(project, request['registry_path'], request['old_registry_sha256'])
    _need(isinstance(registry, dict) and type(registry.get('schema_version')) is int
          and registry['schema_version'] == 2 and isinstance(registry.get('baselines'), dict),
          'INVALID_REGISTRY')
    key = request['registry_key']
    _need(key in registry['baselines'], 'EXISTING_PARENT_KEY_REQUIRED')
    nodes, bindings = set(), set()
    for name, row in registry['baselines'].items():
        registration.entry_kind(row)
        trust.registry_reference(registry, name)
        node = row['reference']['node_id']
        binding = digest(owner._candidate_binding(row['reference']))
        _need(node not in nodes and binding not in bindings, 'DUPLICATE_PARENT_BINDING')
        nodes.add(node); bindings.add(binding)
    old = registry['baselines'][key]
    _need(registration.entry_kind(old) == registration.REGISTRATION_ONLY,
          'REGISTRATION_ONLY_SOURCE_REQUIRED')
    ref = old['reference']
    _need(ref['node_id'] == request['baseline_id'], 'PARENT_IDENTITY_MISMATCH')
    _need(type(ref['schema_version']) is int and ref['schema_version'] == 3
          and old['expected_reference_sha256'] == request['reference_sha256'] == digest(ref),
          'REFERENCE_V3_IDENTITY_MISMATCH')
    trust.validate_reference(ref, request['reference_sha256'])
    _need(notices_path is not None, 'MANDATORY_NOTICES_REQUIRED')
    _need(request['notices_sha256'] == ref['notices']['sha256'], 'NOTICES_PIN_MISMATCH')
    notices = trust.verify_notices(ref, request['reference_sha256'], notices_path)
    proposed = {'reference': deepcopy(ref), 'expected_reference_sha256': request['reference_sha256'],
                'build_policy_path': request['build_policy_path'],
                'build_policy_sha256': request['build_policy_sha256']}
    build_raw, build = _read(project, request['build_policy_path'], request['build_policy_sha256'])
    selection._policy(project, proposed)
    workflow._research_parent_scope(ref, build)
    s = build['scope']
    _need(set(s) == SCOPE_FIELDS and s['target_upstreams'] == request['target_upstreams']
          and s['target_source_state'] == request['target_source_state'], 'SOURCE_SCOPE_MISMATCH')
    policy_raw, _ = _read(project, request['continuous_policy_path'], request['continuous_policy_sha256'])
    policy = continuous.load_policy(project, request['continuous_policy_path'],
                                    request['continuous_policy_sha256'])
    expected_parent = {'key': key, 'node_id': ref['node_id'],
                       'package_checksum': ref['package_checksum'],
                       'expected_reference_sha256': request['reference_sha256']}
    _need(policy['eligible_parents'] == [expected_parent]
          and policy['build_fingerprint'] == ref['build_fingerprint']
          and policy['orchestration_fingerprint'] == s['orchestration_fingerprint'],
          'CONTINUOUS_SCOPE_MISMATCH')
    # Identity/policy-domain checks only; this is NOT Owner identity or approval.
    owner_raw, _ = _read(project, request['owner_policy_path'], request['owner_policy_sha256'])
    authority = owner._policy(project, project / request['owner_policy_path'],
                              request['owner_policy_sha256'])
    _need(all(authority[k] == request[k] for k in (
        'repository', 'repository_id', 'default_branch', 'workflow_path', 'registry_path')),
        'OWNER_POLICY_DOMAIN_MISMATCH')
    for name in ('storage', 'parent_rows_storage'):
        _need(ref[name]['repository'] == request['repository']
              and ref[name]['repository_id'] == request['repository_id'], 'ASSET_REPOSITORY_MISMATCH')
    result = _result_bytes(registry, key, proposed)
    result_sha = hashlib.sha256(result).hexdigest()
    _need(result_sha == request['result_registry_sha256'], 'RESULT_REGISTRY_PIN_MISMATCH')
    # Exercise existing closed metadata consumers against an in-memory result.
    # It is never written, returned as a Registry or used to execute a Plan.
    candidate = deepcopy(registry); candidate['baselines'][key] = proposed
    selected, _, _ = continuous._parent(project, candidate, policy)
    _need(selected == key, 'UNEXPECTED_PARENT_SELECTION')
    for name, pin, original in (
        (request['registry_path'], request['old_registry_sha256'], raw),
        (request['build_policy_path'], request['build_policy_sha256'], build_raw),
        (request['continuous_policy_path'], request['continuous_policy_sha256'], policy_raw),
        (request['owner_policy_path'], request['owner_policy_sha256'], owner_raw)):
        _need(_read(project, name, pin)[0] == original, 'INPUT_CHANGED_DURING_PREPARATION')
    _need(trust.verify_notices(ref, request['reference_sha256'], notices_path) == notices,
          'NOTICES_CHANGED_DURING_PREPARATION')
    return {'schema_version': 1, 'operation': OPERATION, 'status': 'PREPARED_NONOPERATIVE',
            'authorization': 'NOT_GRANTED', 'operative': False, 'request': request,
            'request_sha256': expected_request_sha256, 'old_entry_sha256': digest(old),
            'proposed_entry': proposed, 'proposed_entry_sha256': digest(proposed),
            'result_registry_sha256': result_sha, 'notices_verification': notices,
            'scientific_verification': 'NOT_PERFORMED', 'production_promotion': 'NOT_AUTHORIZED'}


def inspect_owner_decision(proposal, decision, *, expected_proposal_sha256,
                           expected_transaction_id, expected_actor_id, expected_run_id):
    """Offline consistency only. Caller JSON never authenticates a live Owner.

    A future trusted invocation must re-PREPARE from original independently
    pinned files, verify real API/runtime/checkout/dispatch evidence, and consume
    the transaction once in a durable ledger. None of that is inferred here.
    """
    _need(isinstance(proposal, dict) and set(proposal) == PROPOSAL_FIELDS
          and type(proposal['schema_version']) is int and proposal['schema_version'] == 1
          and proposal['operation'] == OPERATION
          and proposal['status'] == 'PREPARED_NONOPERATIVE'
          and proposal['operative'] is False and proposal['authorization'] == 'NOT_GRANTED'
          and proposal['scientific_verification'] == 'NOT_PERFORMED'
          and proposal['production_promotion'] == 'NOT_AUTHORIZED'
          and _hash(expected_proposal_sha256) and digest(proposal) == expected_proposal_sha256,
          'PROPOSAL_IDENTITY_MISMATCH')
    r = proposal['request']; _shape(r)
    _need(digest(r) == proposal['request_sha256'], 'TRANSITION_REQUEST_PIN_MISMATCH')
    new = proposal['proposed_entry']
    _need(registration.entry_kind(new) == registration.LEGACY_BUILD_BOUND
          and digest(new) == proposal['proposed_entry_sha256']
          and _hash(proposal['old_entry_sha256'])
          and proposal['result_registry_sha256'] == r['result_registry_sha256']
          and new['expected_reference_sha256'] == r['reference_sha256'] == digest(new['reference'])
          and new['reference']['node_id'] == r['baseline_id']
          and all(new[k] == r[k] for k in ('build_policy_path', 'build_policy_sha256')),
          'PROPOSED_ENTRY_BINDING_MISMATCH')
    notice = proposal['notices_verification']
    _need(isinstance(notice, dict) and notice.get('status') == 'NOTICES_VERIFIED'
          and notice.get('baseline_id') == r['baseline_id']
          and notice.get('reference_sha256') == r['reference_sha256']
          and notice.get('notices_sha256') == r['notices_sha256'],
          'NOTICES_RECEIPT_BINDING_MISMATCH')
    _need(decision is not None, 'OWNER_DECISION_REQUIRED')
    _need(isinstance(decision, dict) and set(decision) == DECISION_FIELDS,
          'OPERATION_SPECIFIC_OWNER_DECISION_REQUIRED')
    _need(type(decision['schema_version']) is int and decision['schema_version'] == 1
          and decision['operation'] == OPERATION
          and decision['decision'] == 'APPROVE_RESTRICTED_BUILD_AUTHORITY_TRANSITION',
          'WRONG_TRANSITION_OPERATION')
    _need(all(type(v) is int and v > 0 for v in (
        expected_actor_id, expected_run_id, decision['actor_id'], decision['triggering_actor_id'],
        decision['run_id'], decision['workflow_id'], decision['repository_id'])),
        'INVALID_OWNER_RUN_BINDING')
    _need(decision['actor_id'] == decision['triggering_actor_id'] == expected_actor_id
          and decision['run_id'] == expected_run_id
          and type(decision['run_attempt']) is int and decision['run_attempt'] == 1,
          'OWNER_RUN_OR_REPLAY_MISMATCH')
    _need(decision['transaction_id'] == r['transaction_id'] == expected_transaction_id,
          'TRANSACTION_ID_MISMATCH')
    _need(decision['proposal_sha256'] == expected_proposal_sha256
          and decision['request_sha256'] == proposal['request_sha256']
          and decision['event'] == 'workflow_dispatch'
          and all(decision[k] == r[k] for k in (
              'repository', 'repository_id', 'implementation_revision', 'workflow_path',
              'old_registry_sha256', 'result_registry_sha256', 'continuous_policy_sha256')),
          'OWNER_DECISION_SUBJECT_MISMATCH')
    return {'status': 'CONSISTENT_UNAUTHENTICATED_OWNER_DECISION',
            'operation': OPERATION, 'authorization': 'NOT_GRANTED',
            'operative': False, 'live_owner_verified': False, 'replay_consumed': False}


def authorize(proposal, decision=None, **expected):
    """No flags, injectable approval provider or saved receipt enable this gate."""
    inspect_owner_decision(proposal, decision, **expected)
    raise TransitionError('TRUSTED_OWNER_TRANSITION_INVOCATION_NOT_IMPLEMENTED')


def apply(proposal, decision=None, **expected):
    """No Registry output/write parameter exists before live authorization integration."""
    return authorize(proposal, decision, **expected)
