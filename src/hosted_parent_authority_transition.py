"""Exact Owner observation and gated durable isolated Writer composition.

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
import secrets
import platform
import sys
import subprocess

from . import parent_authority_transition as transition
from . import owner_manual_baseline_approval as owner
from .corpus_snapshot import checked_file, digest, file_digest
from .ci_v2_research import frozen_runtime
from .trusted_snapshot import repository_identity
from scripts import parent_authority_writer_bootstrap as bootstrap

PROJECT = Path(__file__).resolve().parents[1]
WORKFLOW = '.github/workflows/ci_v2_parent_authority_transition.yml'
DEPLOYMENT_FIELDS = {'schema_version', 'operation', 'request', 'proposal_sha256',
                     'subject_sha256', 'implementation_contract_sha256',
                     'workflow_id', 'transaction_backend'}
DISPATCH_FIELDS = {'operation', 'decision', 'request_sha256', 'proposal_sha256',
                   'transition_subject_sha256', 'transaction_id'}
CODE = ('src/hosted_parent_authority_transition.py',
        '.github/CODEOWNERS',
        'src/parent_authority_git_audit.py', 'src/parent_authority_github_transport.py',
        'src/owner_managed_governance.py',
        'scripts/runtime_ruleset_observation.py',
        'scripts/parent_authority_writer_bootstrap.py',
        'scripts/parent_authority_writer_prepare.py', 'scripts/parent_authority_writer_gate.py',
        'scripts/parent_authority_writer_execute.py',
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


def subject(request, proposal_sha256, workflow_id, *, governance_policy_sha256=None,
            bootstrap_sha256=None):
    """One nested Request is the source of all operation-specific identities."""
    transition._shape(request)
    need(transition._hash(proposal_sha256) and type(workflow_id) is int and workflow_id > 0,
         'INVALID_TRANSITION_SUBJECT')
    if governance_policy_sha256 is not None:
        need(transition._hash(governance_policy_sha256), 'INVALID_GOVERNANCE_SUBJECT_PIN')
    if bootstrap_sha256 is not None:
        need(transition._hash(bootstrap_sha256), 'INVALID_BOOTSTRAP_SUBJECT_PIN')
    return bootstrap.subject_payload(request, proposal_sha256, workflow_id,
        governance_policy_sha256, bootstrap_sha256)


def _deployment():
    raw = os.environ.get('PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_JSON', '')
    pin = os.environ.get('PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_SHA256', '')
    need(0 < len(raw.encode()) <= transition.LIMIT and transition._hash(pin),
         'TRANSITION_DEPLOYMENT_NOT_CONFIGURED')
    need(hashlib.sha256(raw.encode()).hexdigest() == pin, 'TRANSITION_DEPLOYMENT_PIN_MISMATCH')
    config = owner._strict_json(raw)
    need(isinstance(config, dict) and set(config) == (DEPLOYMENT_FIELDS | ({'governance'} if config.get('schema_version') == 3 else set()))
         and type(config['schema_version']) is int and config['schema_version'] in (1, 2, 3)
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
        initializing = bootstrap.selected(config)
        if initializing:
            bootstrap.validate(config)
        need(isinstance(backend, dict) and set(backend) == {'kind', 'audit',
            'history_ruleset_id', 'writer_ruleset_id', 'writer_integration_id'}
            and backend['kind'] in ('GITHUB_GIT_AUDIT_V1', bootstrap.KIND)
            and isinstance(backend['audit'], dict)
            and set(backend['audit']) == audit.CONFIG_FIELDS - ({'genesis_sha'} if initializing else set())
            and (initializing or backend['audit']['schema_version'] in (1, 2))
            and all(type(backend[k]) is int and backend[k] > 0 for k in (
                'history_ruleset_id', 'writer_ruleset_id', 'writer_integration_id')),
            'INVALID_GITHUB_AUDIT_DEPLOYMENT')
    if config['schema_version'] == 3:
        from . import owner_managed_governance as governance
        need(isinstance(backend, dict), 'OWNER_MANAGED_BACKEND_REQUIRED')
        policy = governance.load(PROJECT, config)
        if bootstrap.selected(config):
            need(policy['schema_version'] == 2, 'BOOTSTRAP_RUNTIME_OBSERVATION_REQUIRED')
    need(digest(subject(config['request'], config['proposal_sha256'], config['workflow_id'],
         governance_policy_sha256=(config['governance']['policy_sha256'] if config['schema_version'] == 3 else None),
         bootstrap_sha256=(digest(backend) if bootstrap.selected(config) else None)))
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
                 r['continuous_policy_path'], *([config['governance']['policy_path']] if config['schema_version'] == 3 else [])):
        _git(project, 'ls-files', '--error-unmatch', '--', name)
        checked_file(project, name)
    need(digest(contract(project)) == config['implementation_contract_sha256']
         and contract(project) == contract(PROJECT), 'TRANSITION_CODE_CONTRACT_MISMATCH')


def _observe(project, config):
    """Same API/runtime/subject logic for tests and future Hosted observation."""
    project = Path(project).resolve(); r = config['request']
    _checkout(project, config)
    frozen_runtime(project)
    return _observe_subject(project, config)


def _observe_subject(project, config):
    # Shared exact Owner/subject checks. Only the reader _observe() runs the
    # scientific runtime check; the Writer first authenticates that successful
    # pinned reader job through its existing standard-library gate.
    project = Path(project).resolve(); r = config['request']
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
        name = 'transition-notices-' + request['transaction_id'] + '-' + secrets.token_hex(16)
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
    if bootstrap.selected(config):
        resolved, binding, receipt = bootstrap.resolve(config, observed['workflow_run'])
        transport = GitHubAuditTransport(resolved['transaction_backend']['audit'], binding,
            os.environ.get('GH_TOKEN', ''))
        transport.verify_absent_ref()
        return {'status': 'BOOTSTRAP_REF_ABSENCE_OBSERVED', 'bootstrap': receipt,
            'authorization': 'NOT_GRANTED', 'live_apply': False}
    backend = config['transaction_backend']
    binding = _audit_binding(config, observed)
    # A dedicated App token is separate from the Owner-observation reader token.
    # Default scope remains read-only, regardless of the token's API capabilities.
    transport = GitHubAuditTransport(backend['audit'], binding,
        os.environ.get('PARENT_AUTHORITY_AUDIT_TOKEN', os.environ.get('GH_TOKEN', '')))
    transport.verify_tree()
    state = audit._IsolatedGitProtocol(transport, backend['audit'], binding).inspect()
    need(state['status'] != 'STATE_UNCERTAIN', 'AUDIT_HISTORY_NOT_VERIFIED')
    kwargs = {}
    if config['schema_version'] == 3:
        from . import owner_managed_governance as owner_governance
        policy = owner_governance.load(PROJECT, config)
        if policy['schema_version'] == 2:
            kwargs = {'project': PROJECT, 'policy': policy, 'operation': 'MANUAL_R4'}
    governance = transport.observe_governance(backend['history_ruleset_id'],
        backend['writer_ruleset_id'], backend['writer_integration_id'], **kwargs)
    need(_deployment() == config, 'TRANSITION_DEPLOYMENT_CHANGED')
    readback = {**state, 'scope': 'AUTHENTICATED_GITHUB_READBACK_ONLY'}
    return {'status': 'GITHUB_AUDIT_READBACK_VERIFIED', 'state': readback,
        'governance': governance, 'authorization': 'NOT_GRANTED',
        'durable_transaction_reserved': False, 'live_apply': False}


def run():
    """No client, actor, decision, filesystem or backend override parameters."""
    return _run(PROJECT)


def _audit_binding(config, observed):
    from . import parent_authority_git_audit as audit
    actor = observed['workflow_run']
    decision = bootstrap.decision(config, actor)
    backend = deepcopy(config['transaction_backend'])
    if bootstrap.selected(config):
        backend['audit'].pop('genesis_sha', None)  # Resolved config retains the reviewed Subject.
    return audit._binding(observed['proposal'], decision,
        expected_proposal_sha256=config['proposal_sha256'],
        expected_subject_sha256=config['subject_sha256'],
        expected_actor_id=actor['actor_id'], expected_run_id=actor['run_id'],
        governance_policy_sha256=(config['governance']['policy_sha256'] if config['schema_version'] == 3 else None),
        bootstrap_sha256=(digest(backend) if bootstrap.selected(config) else None))


def _writer_context(project):
    """No caller-supplied observation: authenticate the successful reader job.

    Scientific dependencies/frozen checks remain in that exact pinned reader.
    The fresh Writer rechecks all mutable Owner/subject/Registry/policy evidence
    using stdlib only; it never executes dependency installation or extraction.
    """
    from scripts import parent_authority_writer_gate as gate
    gate.verify(os.environ, Path(project), gate.GitHubRead())
    gate.verify_token(os.environ, gate.GitHubRead())
    need(sys.flags.isolated == 1 and sys.flags.no_site == 1
         and platform.python_version() == '3.12.3' and platform.machine() == 'aarch64',
         'WRITER_STDLIB_RUNTIME_MISMATCH')
    config = _deployment()
    need(isinstance(config['transaction_backend'], dict), 'DURABLE_CROSS_RUN_TRANSACTION_BACKEND_NOT_CONFIGURED')
    _checkout(project, config)
    observed = _observe_subject(project, config)
    need(_deployment() == config, 'TRANSITION_DEPLOYMENT_CHANGED')
    return config, observed


def _writer_governance(transport, backend, *, config=None, project=None):
    """Actual transport observation, never an environment/dispatch approval flag.

    Legacy deployments still require independently verified governance. Only
    deployment schema 3 explicitly selects the separately policy-pinned Owner-
    managed contract; it does not certify the historical independence guarantee.
    """
    if config is not None and config['schema_version'] == 3:
        from . import owner_managed_governance as owner_governance
        return owner_governance.observe(project, config, transport)
    governance = transport.observe_governance(backend['history_ruleset_id'],
        backend['writer_ruleset_id'], backend['writer_integration_id'])
    need(governance.get('status') == 'PINNED_RULESETS_OBSERVED'
         and governance.get('writer_credential_isolation') == 'VERIFIED'
         and governance.get('independent_governance') == 'VERIFIED',
         'AUDIT_WRITER_AND_INDEPENDENT_GOVERNANCE_NOT_VERIFIED')
    return governance


def _readback(protocol, count, state, *, receipt=None):
    """Fresh client + real GET chain; do not trust a phase return code alone."""
    from . import parent_authority_git_audit as audit
    reader = audit._IsolatedGitProtocol(protocol._api, protocol._config, protocol._binding)
    head, events = reader._scan()
    need(head == protocol._observed_head and len(events) == count
         and events[-1][1]['state'] == state
         and events[-1][1]['claim_nonce'] == protocol._nonce,
         'TRANSACTION_INDEPENDENT_READBACK_MISMATCH')
    if receipt is not None:
        need(events[-1][1]['receipt_sha256'] == digest(receipt), 'COMPLETION_RECEIPT_READBACK_MISMATCH')
    return head


def _execute_transaction(project, isolation, config, observed, protocol, *, _revalidate):
    """Private composition of existing adapters; fixtures are explicitly offline.

    Only run_writer() supplies live context after Writer/governance checks.
    This function accepts no CLI flags and is not an authorization provider.
    Protocol OFFLINE statuses retain their historical meaning; completion here
    records isolated evidence, never authoritative BUILD_CANDIDATE eligibility.
    """
    from . import parent_authority_transaction as core
    from . import baseline_registration_transaction as tx
    project, isolation = Path(project), Path(isolation)
    result = {'status': 'BLOCKED', 'authorization': 'NOT_GRANTED',
        'scope': 'ISOLATED_COPY_ONLY', 'durable_transaction_reserved': False,
        'transaction_consumed': False, 'registry_committed': False,
        'authoritative_registry_applied': False, 'build_candidate_authority': 'NOT_GRANTED',
        'production_promotion': 'NOT_AUTHORIZED', 'phase': 'VERIFY'}
    def current():
        need(_revalidate() == observed, 'TRANSITION_AUTHORITY_CHANGED_DURING_EXECUTION')
        return observed
    try:
        r = config['request']; proposal = observed['proposal']
        need(protocol._config == config['transaction_backend']['audit']
             and protocol._binding == _audit_binding(config, observed)
             and observed['status'] == 'API_OWNER_TRANSITION_SUBJECT_VERIFIED'
             and observed['proposal_sha256'] == digest(proposal) == config['proposal_sha256']
             and proposal['request'] == r and observed['subject_sha256'] == config['subject_sha256'],
             'WRITER_TRANSACTION_BINDING_MISMATCH')
        current()
        need(file_digest(project / r['registry_path']) == r['old_registry_sha256'], 'STALE_OR_UNBOUND_REGISTRY')
        result['phase'] = 'RESERVE'
        result['durable_transaction_reserved'] = None  # Write may persist before a timeout.
        reservation = protocol.reserve(); need(reservation['status'] == 'RESERVED', 'TRANSACTION_RESERVATION_NOT_GRANTED')
        result['durable_transaction_reserved'] = True
        result['reservation_head'] = _readback(protocol, 1, 'RESERVED')
        current()
        result['phase'] = 'CONSUME'
        result['transaction_consumed'] = None
        consumption = protocol.consume(); need(consumption['status'] == 'CONSUMED_OFFLINE', 'TRANSACTION_CONSUMPTION_NOT_GRANTED')
        result['transaction_consumed'] = True
        result['consumption_head'] = _readback(protocol, 2, 'CONSUMED')
        current()
        result['phase'] = 'ISOLATED_APPLY'
        result['registry_committed'] = None
        local = core._local_apply(project, isolation, proposal,
            expected_proposal_sha256=config['proposal_sha256'], _revalidate=current)
        result['local_result'] = local; result['registry_committed'] = local['registry_committed']
        need(local['status'] == 'COMPLETED', 'ISOLATED_APPLY_NOT_COMPLETED')
        current()
        # Reuse the original no-follow lock/read helpers, including exact audit
        # receipt bytes. No unbounded or symlink-following result-file read.
        with tx._locked(project, isolation, project / r['registry_path']) as (fd, _):
            raw = tx._read(fd, tx.REGISTRY)
            receipt_raw = tx._read(fd, core._id(proposal) + '.completed.json')
            need(receipt_raw == tx._serialize(local['receipt'])
                 and hashlib.sha256(raw).hexdigest() == r['result_registry_sha256'],
                 'ISOLATED_COMPLETION_BYTES_MISMATCH')
        result['phase'] = 'COMPLETE'
        completed = protocol.complete(raw, local)
        need(completed['status'] == 'COMPLETED_OFFLINE', 'DURABLE_COMPLETION_NOT_VERIFIED')
        result['completion_head'] = _readback(protocol, 3, 'COMPLETED', receipt=local['receipt'])
        current()
        need(file_digest(project / r['registry_path']) == r['old_registry_sha256'], 'AUTHORITATIVE_REGISTRY_CHANGED')
        result.update(status='COMPLETED', phase='VERIFIED',
            result_registry_sha256=hashlib.sha256(raw).hexdigest(),
            completion_receipt_sha256=digest(local['receipt']),
            transaction_id=r['transaction_id'], proposal_sha256=config['proposal_sha256'],
            subject_sha256=config['subject_sha256'])
    except Exception as error:
        # A timeout may have persisted a claim even when no phase receipt was
        # returned. Never infer NOT_CONSUMED from the Boolean progress fields.
        result['reason'] = str(error) if isinstance(error, (transition.TransitionError, tx.TransactionError)) and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(error)) else 'WRITER_TRANSACTION_FAILED_OR_UNCERTAIN'
        try:
            result['reconciliation'] = protocol.inspect()
        except Exception:
            result['reconciliation'] = {'status': 'STATE_UNCERTAIN', 'authorization': 'NOT_GRANTED'}
        result['automatic_retry'] = False
        if result.get('local_result', {}).get('status') in ('COMMITTED_WITH_ERROR', 'STATE_UNCERTAIN'):
            result['status'] = result['local_result']['status']
        elif (result['phase'] in ('ISOLATED_APPLY', 'COMPLETE')
              or result['durable_transaction_reserved'] is None
              or result['transaction_consumed'] is None
              or result['registry_committed']):
            result['status'] = 'STATE_UNCERTAIN'
    return result


def run_writer():
    """Trusted Writer entry only; no project, API, decision or approval overrides."""
    from . import parent_authority_git_audit as audit
    from .parent_authority_github_transport import GitHubAuditTransport
    from . import baseline_registration_transaction as tx
    result = {'status': 'BLOCKED', 'authorization': 'NOT_GRANTED', 'registry_committed': False,
        'authoritative_registry_applied': False, 'production_promotion': 'NOT_AUTHORIZED'}
    transports = []
    def connected(*args, **kwargs):
        transport = GitHubAuditTransport(*args, **kwargs)
        transports.append(transport)
        return transport
    def diagnostics():
        rows = [row for transport in transports for row in transport.http_diagnostics()]
        # Preserve failures even when a different transport has recent reads.
        rows.sort(key=lambda row: row['outcome'] != 'HTTP_RESPONSE')
        return rows[-8:]
    try:
        reviewed, observed = _writer_context(PROJECT)
        initializing = bootstrap.selected(reviewed)
        if initializing:
            config, predicted_binding, identity = bootstrap.resolve(reviewed, observed['workflow_run'])
            result['bootstrap'] = {**identity, 'phase': 'PRECHECK', 'mutation_attempted': False,
                'automatic_retry': False}
        else:
            config = reviewed
        backend = config['transaction_backend']; binding = _audit_binding(config, observed)
        if initializing:
            need(binding == predicted_binding, 'BOOTSTRAP_BINDING_MISMATCH')
        token = os.environ.get('PARENT_AUTHORITY_AUDIT_TOKEN', '')
        read_transport = connected(backend['audit'], binding, token)
        if not initializing:
            read_transport.verify_tree()
        controls = _writer_governance(read_transport, backend, config=config, project=PROJECT)  # Before APPEND exists.
        if config['schema_version'] == 3 and controls.get('complete_current_ruleset_verification') is False:
            result['ruleset_observation'] = controls['rules']
        temp = Path(os.environ.get('RUNNER_TEMP', ''))
        need(temp.is_absolute() and temp.resolve() == temp.absolute()
             and not temp.resolve().is_relative_to(PROJECT)
             and all(os.environ.get(k, '').isdecimal() for k in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')),
             'UNSAFE_WRITER_RESULT_PATH')
        root = temp / ('parent-authority-writer-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT'])
        fd = tx._open_directory(temp)
        try: os.mkdir(root.name, 0o700, dir_fd=fd)
        finally: os.close(fd)
        isolation = root / 'isolation'
        fd = tx._open_directory(root)
        try: os.mkdir('isolation', 0o700, dir_fd=fd)
        finally: os.close(fd)
        old, _ = transition._read(PROJECT, config['request']['registry_path'], config['request']['old_registry_sha256'])
        fd = tx._open_directory(isolation)
        try: tx._write_once(fd, tx.REGISTRY, old)
        finally: os.close(fd)
        def revalidate():
            actual, observation = _writer_context(PROJECT)
            need(actual == reviewed, 'TRANSITION_DEPLOYMENT_CHANGED')
            need(observation == observed, 'TRANSITION_AUTHORITY_CHANGED_DURING_EXECUTION')
            if initializing:
                resolved, actual_binding, actual_identity = bootstrap.resolve(actual, observation['workflow_run'])
                need(resolved == config and actual_binding == binding and actual_identity == identity,
                    'BOOTSTRAP_RUN_BINDING_CHANGED')
            _writer_governance(read_transport, backend, config=config, project=PROJECT)
            return observation
        if initializing:
            # Real App-token governance (including GraphQL where needed) above
            # and again here must succeed before any INITIALIZE transport exists.
            revalidate()
            read_transport.verify_absent_ref()
            result['bootstrap'].update(phase='CREATE_GENESIS', mutation_attempted=True)
            creator = connected(backend['audit'], binding, token, write_scope='INITIALIZE')
            creator.create_genesis(deepcopy(bootstrap.PERSON))
            revalidate()
            read_transport.verify_absent_ref()
            result['bootstrap']['phase'] = 'INITIALIZE_REF'
            # Each primitive is one-shot; never reuse creator or reset its state.
            initializer = connected(backend['audit'], binding, token, write_scope='INITIALIZE')
            initializer.initialize_ref()
            read_transport.verify_tree()
            need(audit._IsolatedGitProtocol(read_transport, backend['audit'], binding).inspect()['status']
                 == 'NOT_RESERVED_REVIEW_REQUIRED', 'BOOTSTRAP_INITIAL_STATE_UNVERIFIED')
            result['bootstrap']['phase'] = 'VERIFIED'
        transport = connected(backend['audit'], binding, token, write_scope='APPEND')
        transport.verify_tree()
        protocol = audit._IsolatedGitProtocol(transport, backend['audit'], binding)
        executed = _execute_transaction(PROJECT, isolation, config, observed, protocol, _revalidate=revalidate)
        if initializing:
            executed['bootstrap'] = result['bootstrap']
        if 'ruleset_observation' in result:
            executed['ruleset_observation'] = result['ruleset_observation']
        if executed.get('status') != 'COMPLETED' and diagnostics():
            executed['api_diagnostics'] = diagnostics()
        return executed
    except Exception as error:
        if result.get('bootstrap', {}).get('mutation_attempted'):
            result.update(status='STATE_UNCERTAIN', automatic_retry=False,
                reconciliation='OWNER_READ_ONLY_RECONCILIATION_REQUIRED')
        result['reason'] = str(error) if isinstance(error, (transition.TransitionError, audit.AuditError, owner.OwnerApprovalError, ValueError)) and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(error)) else 'WRITER_VERIFICATION_FAILED'
        if diagnostics():
            result['api_diagnostics'] = diagnostics()
    return result
