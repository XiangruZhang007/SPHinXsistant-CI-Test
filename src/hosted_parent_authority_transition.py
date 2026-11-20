"""Dedicated transition observation; live APPLY blocked without durable backend.

No caller-supplied client/context/decision enables this entry point. Tests mock
the existing GitHubCLI transport. Registration approvals are never consumed.
Maintainer-controlled deployment pins and a clean reviewed checkout are the
trust root, as in hosted_registration; environment strings alone are not proof.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from . import parent_authority_transition as transition
from . import owner_manual_baseline_approval as owner
from .corpus_snapshot import checked_file, digest, file_digest
from .ci_v2_research import frozen_runtime
from .trusted_snapshot import repository_identity

PROJECT = Path(__file__).resolve().parents[1]
WORKFLOW = '.github/workflows/ci_v2_parent_authority_transition.yml'
DEPLOYMENT_FIELDS = {'schema_version', 'operation', 'request', 'proposal_sha256',
                     'subject_sha256', 'implementation_contract_sha256',
                     'workflow_id', 'transaction_backend'}
DISPATCH_FIELDS = {'operation', 'decision', 'request_sha256', 'proposal_sha256',
                   'transition_subject_sha256', 'transaction_id'}
CODE = ('src/hosted_parent_authority_transition.py',
        'src/parent_authority_git_audit.py', 'src/parent_authority_github_transport.py',
        'src/parent_authority_transaction.py', 'scripts/parent_authority_transition_hosted.py',
        WORKFLOW, 'src/parent_authority_transition.py',
        'src/owner_manual_baseline_approval.py', 'src/baseline_registration_transaction.py',
        'src/corpus_snapshot.py', 'src/trusted_snapshot.py', 'src/continuous_build_policy.py',
        'src/schema2_workflow.py', 'src/trusted_baseline_registration.py',
        'src/trusted_parent_selection.py', 'src/ci_v2_research.py')


def need(ok, reason):
    if not ok:
        raise transition.TransitionError(reason)


def contract(project):
    # The exact reviewed commit/clean checkout covers all tracked dependencies;
    # the existing frozen runtime additionally verifies scientific contracts.
    return {'schema_version': 1, 'operation': transition.OPERATION,
            'files': {name: file_digest(checked_file(project, name)) for name in CODE}}


def subject(request, proposal_sha256, workflow_id):
    """One nested Request is the source of all operation-specific identities."""
    transition._shape(request)
    need(transition._hash(proposal_sha256) and type(workflow_id) is int and workflow_id > 0,
         'INVALID_TRANSITION_SUBJECT')
    return {'schema_version': 1, 'operation': transition.OPERATION,
            'request': deepcopy(request), 'request_sha256': digest(request),
            'proposal_sha256': proposal_sha256, 'workflow_id': workflow_id}


def _deployment():
    raw = os.environ.get('PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_JSON', '')
    pin = os.environ.get('PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_SHA256', '')
    need(0 < len(raw.encode()) <= transition.LIMIT and transition._hash(pin),
         'TRANSITION_DEPLOYMENT_NOT_CONFIGURED')
    need(hashlib.sha256(raw.encode()).hexdigest() == pin, 'TRANSITION_DEPLOYMENT_PIN_MISMATCH')
    config = owner._strict_json(raw)
    need(isinstance(config, dict) and set(config) == DEPLOYMENT_FIELDS
         and type(config['schema_version']) is int and config['schema_version'] in (1, 2)
         and config['operation'] == transition.OPERATION, 'INVALID_TRANSITION_DEPLOYMENT')
    transition._shape(config['request'])
    need(config['request']['workflow_path'] == WORKFLOW, 'TRANSITION_WORKFLOW_REQUIRED')
    need(all(transition._hash(config[k]) for k in (
        'proposal_sha256', 'subject_sha256', 'implementation_contract_sha256')),
        'INVALID_TRANSITION_DEPLOYMENT_PINS')
    need(type(config['workflow_id']) is int and config['workflow_id'] > 0,
         'INVALID_TRANSITION_WORKFLOW_ID')
    # No local path, one-run artifact, boolean or unreviewed remote backend may
    # opt into live mutation. A backend needs a separately reviewed extension.
    backend = config['transaction_backend']
    if config['schema_version'] == 1 or backend == 'UNCONFIGURED':
        need(backend == 'UNCONFIGURED', 'UNREVIEWED_TRANSACTION_BACKEND')
    else:
        from . import parent_authority_git_audit as audit
        need(isinstance(backend, dict) and set(backend) == {'kind', 'audit',
            'history_ruleset_id', 'writer_ruleset_id', 'writer_integration_id'}
            and backend['kind'] == 'GITHUB_GIT_AUDIT_V1'
            and isinstance(backend['audit'], dict)
            and set(backend['audit']) == audit.CONFIG_FIELDS
            and all(type(backend[k]) is int and backend[k] > 0 for k in (
                'history_ruleset_id', 'writer_ruleset_id', 'writer_integration_id')),
            'INVALID_GITHUB_AUDIT_DEPLOYMENT')
    need(digest(subject(config['request'], config['proposal_sha256'], config['workflow_id']))
         == config['subject_sha256'], 'TRANSITION_SUBJECT_PIN_MISMATCH')
    return config


def _git(project, *args):
    env = {**os.environ, 'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
           'GIT_NO_LAZY_FETCH': '1', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
    return subprocess.check_output(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
        '-C', str(project), *args], env=env, stderr=subprocess.PIPE)


def _checkout(project, config):
    project = Path(project).resolve(); r = config['request']
    need(_git(project, 'rev-parse', '--show-toplevel').decode().strip() == str(project)
         and _git(project, 'rev-parse', 'HEAD').decode().strip() == r['implementation_revision'],
         'TRANSITION_CHECKOUT_REVISION_MISMATCH')
    _git(project, 'diff', '--quiet', '--no-ext-diff', 'HEAD', '--')
    need(not _git(project, 'ls-files', '--others', '--exclude-standard', '--',
                  'src', 'scripts', 'configs', '.github').strip(), 'UNTRACKED_TRANSITION_IMPLEMENTATION')
    for name in (*CODE, r['registry_path'], r['owner_policy_path'], r['build_policy_path'],
                 r['continuous_policy_path']):
        _git(project, 'ls-files', '--error-unmatch', '--', name)
        checked_file(project, name)
    need(digest(contract(project)) == config['implementation_contract_sha256']
         and contract(project) == contract(PROJECT), 'TRANSITION_CODE_CONTRACT_MISMATCH')


def _observe(project, config):
    """Same API/runtime/subject logic for tests and future Hosted observation."""
    project = Path(project).resolve(); r = config['request']
    _checkout(project, config)
    frozen_runtime(project)
    env = os.environ
    need(env.get('GITHUB_ACTIONS') == 'true' and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
         and env.get('RUNNER_ARCH') == 'ARM64' and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
         and env.get('GITHUB_WORKSPACE') == str(project)
         and env.get('GITHUB_REPOSITORY') == r['repository']
         and env.get('GITHUB_REPOSITORY_ID') == str(r['repository_id'])
         and env.get('GITHUB_SHA') == env.get('GITHUB_WORKFLOW_SHA') == r['implementation_revision']
         and env.get('GITHUB_WORKFLOW_REF') == r['repository'] + '/' + WORKFLOW
             + '@refs/heads/' + r['default_branch'], 'TRANSITION_RUNTIME_BINDING_MISMATCH')
    context = owner.context_from_environment()
    inputs = context['dispatch_inputs']
    expected = {'operation': transition.OPERATION,
        'decision': 'APPROVE_RESTRICTED_BUILD_AUTHORITY_TRANSITION',
        'request_sha256': digest(r), 'proposal_sha256': config['proposal_sha256'],
        'transition_subject_sha256': config['subject_sha256'], 'transaction_id': r['transaction_id']}
    need(isinstance(inputs, dict) and inputs == expected, 'TRANSITION_DISPATCH_SUBJECT_MISMATCH')
    policy = owner._policy(project, project / r['owner_policy_path'], r['owner_policy_sha256'])
    need(all(policy[k] == r[k] for k in (
        'repository', 'repository_id', 'default_branch', 'workflow_path', 'registry_path')),
        'TRANSITION_OWNER_POLICY_DOMAIN_MISMATCH')
    # This operation is Owner-only even if a generic registration policy lists
    # additional approvers. Never infer Owner identity from a local username.
    need(policy['allow_repository_owner'] is True and policy['authorized_approver_ids'] == [],
         'TRANSITION_OWNER_ONLY_POLICY_REQUIRED')
    client = owner.GitHubCLI()
    repo = owner._api(client, 'repos/' + r['repository'])
    need(repository_identity(repo, r['repository'], r['repository_id'])
         and repo.get('owner', {}).get('type') == 'User', 'TRANSITION_PRIVATE_OWNER_REPOSITORY_REQUIRED')
    actor = owner._github_identity(client, policy, context)
    need(actor['actor_id'] == repo['owner']['id'] and actor['workflow_id'] == config['workflow_id']
         and actor['commit_sha'] == r['implementation_revision'], 'TRANSITION_OWNER_RUN_MISMATCH')
    raw, _ = transition._read(project, r['registry_path'], r['old_registry_sha256'])
    need(owner._remote_registry_bytes(client, policy, actor['commit_sha']) == raw,
         'TRANSITION_REMOTE_REGISTRY_MISMATCH')
    # Fetch only the separately pinned notices; existing transport rechecks
    # immutable repo/Release/asset identity. No Parent restoration or R2 here.
    # Caller owns an already downloaded attachment; path is deployment-owned
    # RUNNER_TEMP, never a dispatch input. _notice_path verifies its exact bytes.
    notice = _notice_path(project, r)
    proposal = transition.prepare(project, r, expected_request_sha256=digest(r),
        expected_implementation_revision=r['implementation_revision'], notices_path=notice)
    need(digest(proposal) == config['proposal_sha256'], 'TRANSITION_PROPOSAL_PIN_MISMATCH')
    decision = {'schema_version': 1, 'operation': transition.OPERATION,
        'decision': expected['decision'], 'proposal_sha256': digest(proposal),
        'request_sha256': digest(r), **{k: r[k] for k in (
            'transaction_id', 'repository', 'repository_id', 'implementation_revision',
            'old_registry_sha256', 'result_registry_sha256', 'continuous_policy_sha256', 'workflow_path')},
        'actor_id': actor['actor_id'], 'triggering_actor_id': actor['actor_id'],
        'run_id': actor['run_id'], 'run_attempt': actor['run_attempt'],
        'workflow_id': actor['workflow_id'], 'event': actor['event']}
    transition.inspect_owner_decision(proposal, decision,
        expected_proposal_sha256=config['proposal_sha256'], expected_transaction_id=r['transaction_id'],
        expected_actor_id=repo['owner']['id'], expected_run_id=actor['run_id'])
    need(owner._github_identity(client, policy, context) == actor
         and owner._remote_registry_bytes(client, policy, actor['commit_sha']) == raw,
         'TRANSITION_AUTHORITY_CHANGED_DURING_VERIFICATION')
    _checkout(project, config)
    return {'status': 'API_OWNER_TRANSITION_SUBJECT_VERIFIED', 'operation': transition.OPERATION,
        'authorization': 'NOT_GRANTED', 'proposal': proposal, 'proposal_sha256': digest(proposal),
        'subject_sha256': config['subject_sha256'], 'workflow_run': actor,
        'transaction_id': r['transaction_id'], 'durable_transaction_reserved': False,
        'production_promotion': 'NOT_AUTHORIZED'}


def _notice_path(project, request):
    temp = Path(os.environ.get('RUNNER_TEMP', ''))
    need(temp.is_absolute() and temp.resolve() == temp.absolute()
         and not temp.resolve().is_relative_to(Path(project).resolve()), 'UNSAFE_TRANSITION_RUNNER_TEMP')
    # Existing safe directory traversal and exact immutable download utilities.
    from . import baseline_registration_transaction as tx
    from . import trusted_snapshot as trust
    fd = tx._open_directory(temp)
    try:
        name = 'transition-notices-' + request['transaction_id']
        os.mkdir(name, mode=0o700, dir_fd=fd)
    finally:
        os.close(fd)
    _, registry = transition._read(project, request['registry_path'], request['old_registry_sha256'])
    ref = registry['baselines'][request['registry_key']]['reference']
    return trust.fetch_notices(ref, request['reference_sha256'], temp / name / 'notices.zip')


def _run(project):
    result = {'status': 'BLOCKED', 'operation': transition.OPERATION,
              'authorization': 'NOT_GRANTED', 'registry_committed': False,
              'production_promotion': 'NOT_AUTHORIZED'}
    try:
        config = _deployment()
        observed = _observe(project, config)
        need(_deployment() == config, 'TRANSITION_DEPLOYMENT_CHANGED')
        result.update(owner_subject_observation_sha256=digest(observed),
                      subject_sha256=observed['subject_sha256'],
                      observed_workflow_run=observed['workflow_run'],
                      durable_transaction_reserved=False)
        if isinstance(config['transaction_backend'], dict):
            result['audit_backend'] = _inspect_github_backend(config, observed)
            # Matching current rules cannot prove credential installation scope
            # or independent control of rule changes. Never convert observations
            # into a single-use grant or call the isolated writer here.
            raise transition.TransitionError('AUDIT_WRITER_AND_INDEPENDENT_GOVERNANCE_NOT_VERIFIED')
        # Run-local directories/artifacts and workflow concurrency do not provide
        # global single-use semantics. Never invoke the local transaction core.
        raise transition.TransitionError('DURABLE_CROSS_RUN_TRANSACTION_BACKEND_NOT_CONFIGURED')
    except Exception as error:
        from .parent_authority_git_audit import AuditError
        result['reason'] = str(error) if isinstance(error, (transition.TransitionError,
            owner.OwnerApprovalError, AuditError)) and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(error)) else 'TRANSITION_VERIFICATION_FAILED'
    return result


def _inspect_github_backend(config, observed):
    """Connected real REST readback after the genuine existing Owner observer.

    No client/credential override is exposed through the public run() interface.
    Saved decisions and configured ruleset IDs never stand in for Owner checks.
    """
    from . import parent_authority_git_audit as audit
    from .parent_authority_github_transport import GitHubAuditTransport
    r = config['request']; backend = config['transaction_backend']; actor = observed['workflow_run']
    decision = {'schema_version': 1, 'operation': transition.OPERATION,
        'decision': 'APPROVE_RESTRICTED_BUILD_AUTHORITY_TRANSITION',
        'proposal_sha256': config['proposal_sha256'], 'request_sha256': digest(r),
        **{k: r[k] for k in ('transaction_id', 'repository', 'repository_id',
            'implementation_revision', 'old_registry_sha256', 'result_registry_sha256',
            'continuous_policy_sha256', 'workflow_path')},
        'actor_id': actor['actor_id'], 'triggering_actor_id': actor['actor_id'],
        'run_id': actor['run_id'], 'run_attempt': actor['run_attempt'],
        'workflow_id': actor['workflow_id'], 'event': actor['event']}
    binding = audit._binding(observed['proposal'], decision,
        expected_proposal_sha256=config['proposal_sha256'],
        expected_subject_sha256=config['subject_sha256'],
        expected_actor_id=actor['actor_id'], expected_run_id=actor['run_id'])
    transport = GitHubAuditTransport(backend['audit'], binding, os.environ.get('GH_TOKEN', ''))
    transport.verify_tree()
    state = audit._IsolatedGitProtocol(transport, backend['audit'], binding).inspect()
    need(state['status'] != 'STATE_UNCERTAIN', 'AUDIT_HISTORY_NOT_VERIFIED')
    governance = transport.observe_governance(backend['history_ruleset_id'],
        backend['writer_ruleset_id'], backend['writer_integration_id'])
    need(_deployment() == config, 'TRANSITION_DEPLOYMENT_CHANGED')
    readback = {**state, 'scope': 'AUTHENTICATED_GITHUB_READBACK_ONLY'}
    return {'status': 'GITHUB_AUDIT_READBACK_VERIFIED', 'state': readback,
        'governance': governance, 'authorization': 'NOT_GRANTED',
        'durable_transaction_reserved': False, 'live_apply': False}


def run():
    """No client, actor, decision, filesystem or backend override parameters."""
    return _run(PROJECT)
