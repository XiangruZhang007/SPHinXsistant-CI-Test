"""Stdlib-only run-bound R4 genesis encoding; no API, credentials or writes.

This is an explicit deployment mode, not an authorization provider. The caller
must authenticate the Owner run and enforce the existing manual Writer gate.
"""
from copy import deepcopy
import hashlib
import json
import re

KIND = 'GITHUB_GIT_AUDIT_OWNER_RUN_BOOTSTRAP_V1'
REF = 'refs/heads/ci-v2-authority-audit/ed20b392594046db84a6f2306053440e'
REPOSITORY = 'XiangruZhang007/SPHinXsistant-CI-Test'
REPOSITORY_ID = 1455203884
OWNER_ID = 239840087
TREE = hashlib.sha1(b'tree 0\0').hexdigest()
PERSON = {'name': 'CI V2 R4 Writer',
          'email': 'ci-v2-r4-writer@users.noreply.github.com', 'date': '2000-01-01T00:00:00Z'}
AUDIT_FIELDS = {'schema_version', 'repository', 'repository_id', 'ref',
                'tree_sha', 'governance_sha256', 'genesis_sha'}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def selected(config):
    backend = config.get('transaction_backend')
    return isinstance(backend, dict) and backend.get('kind') == KIND


def validate(config):
    backend = config['transaction_backend']; c = backend['audit']; r = config['request']
    need(config['schema_version'] == 3 and set(backend) == {'kind', 'audit',
        'history_ruleset_id', 'writer_ruleset_id', 'writer_integration_id'} and selected(config)
        and set(c) == AUDIT_FIELDS - {'genesis_sha'} and type(c['schema_version']) is int
        and c['schema_version'] == 3, 'INVALID_RUN_BOUND_BOOTSTRAP_DEPLOYMENT')
    need(c['repository'] == r['repository'] == REPOSITORY
        and type(c['repository_id']) is int and c['repository_id'] == r['repository_id'] == REPOSITORY_ID
        and c['ref'] == REF == 'refs/heads/ci-v2-authority-audit/' + r['transaction_id']
        and c['tree_sha'] == TREE and isinstance(c['governance_sha256'], str)
        and re.fullmatch('[0-9a-f]{64}', c['governance_sha256'])
        and backend['writer_integration_id'] == 5855475
        and all(type(backend[k]) is int and backend[k] > 0 for k in (
            'history_ruleset_id', 'writer_ruleset_id', 'writer_integration_id')),
        'RUN_BOUND_BOOTSTRAP_SCOPE_MISMATCH')


def subject_payload(request, proposal_sha256, workflow_id, governance_policy_sha256=None,
                    bootstrap_sha256=None):
    value = {'schema_version': 1, 'operation': request['operation'],
        'request': deepcopy(request), 'request_sha256': digest(request),
        'proposal_sha256': proposal_sha256, 'workflow_id': workflow_id}
    if governance_policy_sha256 is not None:
        value.update(schema_version=2, governance_policy_sha256=governance_policy_sha256)
    if bootstrap_sha256 is not None:
        need(governance_policy_sha256 is not None, 'BOOTSTRAP_GOVERNANCE_PIN_REQUIRED')
        value.update(schema_version=3, bootstrap_sha256=bootstrap_sha256)
    return value


def decision(config, actor):
    r = config['request']
    return {'schema_version': 1, 'operation': r['operation'],
        'decision': 'APPROVE_RESTRICTED_BUILD_AUTHORITY_TRANSITION',
        'proposal_sha256': config['proposal_sha256'], 'request_sha256': digest(r),
        **{k: r[k] for k in ('transaction_id', 'repository', 'repository_id',
            'implementation_revision', 'old_registry_sha256', 'result_registry_sha256',
            'continuous_policy_sha256', 'workflow_path')},
        'actor_id': actor['actor_id'], 'triggering_actor_id': actor['actor_id'],
        'run_id': actor['run_id'], 'run_attempt': actor['run_attempt'],
        'workflow_id': actor['workflow_id'], 'event': actor['event']}


def genesis(config, binding):
    d = binding['decision']
    value = {'schema_version': 1, 'protocol': 'PARENT_AUTHORITY_GIT_AUDIT_V1',
        'domain': {k: config[k] for k in AUDIT_FIELDS - {'genesis_sha'}},
        'transaction': {k: d[k] for k in ('transaction_id', 'old_registry_sha256', 'result_registry_sha256')}}
    value['transaction'].update({k: binding[k] for k in ('request_sha256', 'proposal_sha256')})
    if config['schema_version'] == 3:
        value['owner_run_binding_sha256'] = digest(binding)
    return value


def resolve(config, actor):
    validate(config)
    r = config['request']
    need(all(type(actor.get(k)) is int and actor[k] > 0 for k in (
        'actor_id', 'run_id', 'run_attempt', 'workflow_id'))
        and actor['actor_id'] == OWNER_ID and actor['run_attempt'] == 1
        and actor['workflow_id'] == config['workflow_id'] and actor.get('event') == 'workflow_dispatch'
        and all(actor.get(k) == v for k, v in {
            'repository': REPOSITORY, 'repository_id': REPOSITORY_ID,
            'commit_sha': r['implementation_revision'], 'workflow_path': r['workflow_path']}.items()),
        'BOOTSTRAP_AUTHENTICATED_OWNER_RUN_REQUIRED')
    pin = digest(config['transaction_backend'])
    need(config['subject_sha256'] == digest(subject_payload(r, config['proposal_sha256'],
        config['workflow_id'], config['governance']['policy_sha256'], pin)), 'BOOTSTRAP_SUBJECT_MISMATCH')
    d = decision(config, actor)
    binding = {'request_sha256': digest(r), 'proposal_sha256': config['proposal_sha256'],
        'subject_sha256': config['subject_sha256'], 'owner_decision_sha256': digest(d), 'decision': d,
        **{k: r[k] for k in ('baseline_id', 'reference_sha256', 'notices_sha256')}}
    resolved = deepcopy(config); c = resolved['transaction_backend']['audit']
    message = json.dumps(genesis(c, binding), sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False)
    identity = PERSON['name'] + ' <' + PERSON['email'] + '> 946684800 +0000'
    raw = ('tree ' + TREE + '\nauthor ' + identity + '\ncommitter ' + identity + '\n\n' + message).encode()
    c['genesis_sha'] = hashlib.sha1(b'commit ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    receipt = {'mode': KIND, 'ref': REF, 'genesis_sha': c['genesis_sha'],
        'backend_sha256': pin, 'binding_sha256': digest(binding),
        'run_id': actor['run_id'], 'run_attempt': 1, 'authorization': 'NOT_GRANTED'}
    return resolved, binding, receipt
