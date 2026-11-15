"""Read-only, run-bound owner approval for a schema-2 research Baseline.

This is a separate trust mode from the protected-PR verifier. It verifies the
GitHub Actions workflow-dispatch actor from the authenticated run API, checks
the exact P4.1 Baseline and proposed Registry entry, and never writes the
Trusted Baseline Registry.
"""
from __future__ import annotations

import base64
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
from urllib.parse import quote

from .corpus_snapshot import digest, file_digest

POLICY_FIELDS = {
    'schema_version', 'enabled', 'repository', 'repository_id',
    'default_branch', 'workflow_path', 'registry_path',
    'allow_repository_owner', 'authorized_approver_ids',
}


class OwnerApprovalError(ValueError):
    """Sanitized owner-approval verification error."""


def _need(condition, reason):
    if not condition:
        raise OwnerApprovalError(reason)


def _sha(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def _positive(value):
    return type(value) is int and value > 0


def _strict_json(value):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise OwnerApprovalError('AMBIGUOUS_JSON_OBJECT')
            result[key] = item
        return result
    return json.loads(value, object_pairs_hook=unique)


def _policy(project, policy_path, expected_sha256):
    policy_path = Path(policy_path).expanduser().absolute()
    config_dir = (Path(project) / 'configs').resolve()
    _need(policy_path.is_file() and not policy_path.is_symlink()
          and policy_path.parent.resolve() == config_dir,
          'UNSAFE_OWNER_APPROVAL_POLICY_PATH')
    _need(_sha(expected_sha256) and file_digest(policy_path) == expected_sha256,
          'OWNER_APPROVAL_POLICY_SHA256_MISMATCH')
    try:
        policy = _strict_json(policy_path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, ValueError) as error:
        raise OwnerApprovalError('INVALID_OWNER_APPROVAL_POLICY') from error
    _need(isinstance(policy, dict) and set(policy) == POLICY_FIELDS
          and type(policy.get('schema_version')) is int
          and policy['schema_version'] == 1 and policy.get('enabled') is True,
          'INVALID_OR_DISABLED_OWNER_APPROVAL_POLICY')
    _need(isinstance(policy.get('repository'), str)
          and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', policy['repository'])
          and _positive(policy.get('repository_id')),
          'INVALID_OWNER_APPROVAL_REPOSITORY_POLICY')
    branch = policy.get('default_branch')
    _need(isinstance(branch, str) and re.fullmatch(r'[A-Za-z0-9._/-]{1,200}', branch)
          and not branch.startswith('-') and '..' not in branch
          and not any(char in branch for char in ('~', '^', ':', '?', '*', '[', '\\')),
          'INVALID_OWNER_APPROVAL_BRANCH_POLICY')
    workflow = policy.get('workflow_path')
    _need(isinstance(workflow, str)
          and re.fullmatch(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml', workflow),
          'INVALID_OWNER_APPROVAL_WORKFLOW_PATH')
    registry = policy.get('registry_path')
    registry_path = PurePosixPath(registry) if isinstance(registry, str) else PurePosixPath('.')
    _need(isinstance(registry, str)
          and registry_path.as_posix() == registry and not registry_path.is_absolute()
          and all(part not in ('.', '..') and re.fullmatch(r'[A-Za-z0-9._-]+', part)
                  for part in registry_path.parts),
          'INVALID_OWNER_APPROVAL_REGISTRY_PATH')
    _need(type(policy.get('allow_repository_owner')) is bool,
          'INVALID_OWNER_APPROVAL_AUTHORITY_POLICY')
    ids = policy.get('authorized_approver_ids')
    _need(isinstance(ids, list) and all(_positive(item) for item in ids)
          and len(ids) == len(set(ids)), 'INVALID_OWNER_APPROVER_IDS')
    _need(ids or policy['allow_repository_owner'], 'NO_OWNER_APPROVAL_AUTHORITY_CONFIGURED')
    return policy


def _api(client, endpoint, reason='GITHUB_API_UNAVAILABLE'):
    try:
        response = client.json(endpoint)
    except Exception as error:
        raise OwnerApprovalError(reason) from error
    _need(isinstance(response, dict), 'INVALID_GITHUB_API_RESPONSE')
    return response


def _candidate_binding(reference):
    """Return the strongest Candidate identity tuple present in schema-2 refs."""
    return (
        reference.get('package_format'), reference.get('corpus_sha256'),
        reference.get('source_state'), reference.get('build_fingerprint'),
        reference.get('upstreams'),
    )


def _remote_registry_bytes(client, policy, commit_sha):
    endpoint = (
        f"repos/{policy['repository']}/contents/"
        f"{quote(policy['registry_path'], safe='/')}?ref={commit_sha}"
    )
    remote = _api(client, endpoint, 'REMOTE_REGISTRY_CONTENT_UNAVAILABLE')
    _need(remote.get('path') == policy['registry_path']
          and remote.get('type') == 'file' and remote.get('encoding') == 'base64'
          and isinstance(remote.get('content'), str), 'INVALID_REMOTE_REGISTRY_CONTENT')
    try:
        return base64.b64decode(''.join(remote['content'].split()), validate=True)
    except (ValueError, TypeError) as error:
        raise OwnerApprovalError('INVALID_REMOTE_REGISTRY_CONTENT') from error


def _github_identity(client, policy, context):
    """Verify runtime context against GitHub's run/repository/workflow APIs."""
    repo_name = policy['repository']
    run_id = context.get('run_id')
    attempt = context.get('run_attempt')
    context_actor_id = context.get('actor_id')
    context_sha = context.get('head_sha')
    context_ref = context.get('ref')
    _need(_positive(run_id) and type(attempt) is int and attempt == 1,
          'INVALID_OR_REPLAYED_WORKFLOW_ATTEMPT')
    _need(_positive(context_actor_id), 'WORKFLOW_ACTOR_ID_UNAVAILABLE')
    _need(isinstance(context_sha, str) and re.fullmatch(r'[0-9a-f]{40}', context_sha),
          'WORKFLOW_COMMIT_UNAVAILABLE')
    _need(context_ref == f"refs/heads/{policy['default_branch']}",
          'WORKFLOW_REF_NOT_DEFAULT_BRANCH')

    repository = _api(client, f'repos/{repo_name}', 'GITHUB_REPOSITORY_UNAVAILABLE')
    _need(repository.get('full_name', '').casefold() == repo_name.casefold()
          and repository.get('id') == policy['repository_id']
          and repository.get('default_branch') == policy['default_branch']
          and isinstance(repository.get('owner'), dict),
          'GITHUB_REPOSITORY_IDENTITY_MISMATCH')
    owner = repository['owner']
    _need(_positive(owner.get('id')) and owner.get('type') in ('User', 'Organization'),
          'GITHUB_REPOSITORY_OWNER_UNAVAILABLE')

    run = _api(client, f'repos/{repo_name}/actions/runs/{run_id}',
               'GITHUB_WORKFLOW_RUN_UNAVAILABLE')
    run_repository = run.get('repository')
    actor = run.get('actor')
    trigger = run.get('triggering_actor')
    _need(run.get('id') == run_id and run.get('event') == 'workflow_dispatch'
          and run.get('status') == 'in_progress'
          and run.get('run_attempt') == attempt
          and run.get('head_branch') == policy['default_branch']
          and run.get('head_sha') == context_sha
          and isinstance(run_repository, dict)
          and run_repository.get('id') == policy['repository_id']
          and run_repository.get('full_name', '').casefold() == repo_name.casefold(),
          'GITHUB_WORKFLOW_RUN_BINDING_MISMATCH')
    _need(isinstance(actor, dict) and _positive(actor.get('id'))
          and actor.get('type') == 'User' and actor.get('id') == context_actor_id,
          'GITHUB_WORKFLOW_ACTOR_MISMATCH')
    _need(isinstance(trigger, dict) and trigger.get('type') == 'User'
          and trigger.get('id') == actor['id'],
          'WORKFLOW_RERUN_ACTOR_MISMATCH')
    _need(isinstance(run.get('workflow_id'), int) and run['workflow_id'] > 0,
          'GITHUB_WORKFLOW_ID_UNAVAILABLE')
    workflow = _api(client, f"repos/{repo_name}/actions/workflows/{run['workflow_id']}",
                    'GITHUB_WORKFLOW_METADATA_UNAVAILABLE')
    _need(workflow.get('id') == run['workflow_id']
          and workflow.get('path') == policy['workflow_path'],
          'GITHUB_WORKFLOW_PATH_MISMATCH')
    branch_ref = _api(client, f"repos/{repo_name}/git/ref/heads/"
                      f"{quote(policy['default_branch'], safe='/')}",
                      'CURRENT_DEFAULT_BRANCH_HEAD_UNAVAILABLE')
    _need(branch_ref.get('ref') == f"refs/heads/{policy['default_branch']}"
          and branch_ref.get('object', {}).get('sha') == context_sha,
          'STALE_WORKFLOW_COMMIT')

    authorized = set(policy['authorized_approver_ids'])
    if policy['allow_repository_owner'] and owner.get('type') == 'User':
        authorized.add(owner['id'])
    _need(actor['id'] in authorized, 'UNAUTHORIZED_WORKFLOW_ACTOR')
    created_at = run.get('created_at')
    _need(isinstance(created_at, str), 'GITHUB_APPROVAL_TIMESTAMP_UNAVAILABLE')
    try:
        timestamp = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
    except ValueError as error:
        raise OwnerApprovalError('INVALID_GITHUB_APPROVAL_TIMESTAMP') from error
    _need(timestamp.tzinfo is not None, 'INVALID_GITHUB_APPROVAL_TIMESTAMP')
    return {
        'repository': repo_name, 'repository_id': policy['repository_id'],
        'workflow_id': run['workflow_id'], 'workflow_path': workflow['path'],
        'run_id': run_id, 'run_attempt': attempt, 'event': run['event'],
        'branch': run['head_branch'], 'commit_sha': run['head_sha'],
        'actor_id': actor['id'], 'actor_login': actor.get('login'),
        'approved_at': timestamp.isoformat(),
    }


def verify(project, baseline_path, registry_path, registry_key, proposed_entry, *,
           policy_path, policy_sha256, expected_reference_sha256,
           expected_build_policy_sha256=None, q1_status, context, client,
           registration_subject=None):
    """Verify one explicit owner-triggered decision; never mutate Registry."""
    result = {
        'schema_version': 1, 'status': 'BLOCKED',
        'decision': 'NOT_VERIFIED', 'registration': 'NOT_PERFORMED',
        'registry_modified': False, 'production_promotion': 'NOT_AUTHORIZED',
        'reasons': [],
    }
    try:
        policy = _policy(project, policy_path, policy_sha256)
        _need(isinstance(context, dict), 'INVALID_WORKFLOW_CONTEXT')
        runtime_repository = context.get('repository')
        runtime_repository_id = context.get('repository_id')
        _need(runtime_repository == policy['repository']
              and str(runtime_repository_id) == str(policy['repository_id']),
              'WORKFLOW_REPOSITORY_CONTEXT_MISMATCH')

        registry_path = Path(registry_path)
        _need(registry_path.is_file() and not registry_path.is_symlink(),
              'LOCAL_REGISTRY_UNSAFE')
        _need(registry_path.resolve() == (Path(project) / policy['registry_path']).resolve(),
              'LOCAL_REGISTRY_PATH_POLICY_MISMATCH')
        registry_raw = registry_path.read_bytes()
        registry = _strict_json(registry_raw.decode('utf-8'))
        _need(isinstance(registry, dict) and type(registry.get('schema_version')) is int
              and registry['schema_version'] == 2
              and isinstance(registry.get('baselines'), dict), 'INVALID_SCHEMA2_REGISTRY')
        _need(registry_key not in registry['baselines'], 'REGISTRY_KEY_ALREADY_EXISTS')
        _need(isinstance(proposed_entry, dict), 'INVALID_PROPOSED_REGISTRY_ENTRY')
        reference = proposed_entry.get('reference')
        _need(isinstance(reference, dict), 'INVALID_PROPOSED_BASELINE_REFERENCE')
        candidate_id = None
        baseline_id = reference.get('node_id')
        _need(isinstance(baseline_id, str) and re.fullmatch(r'sha256-[0-9a-f]{64}', baseline_id),
              'INVALID_BASELINE_ID')
        for existing_key, existing in registry['baselines'].items():
            _need(isinstance(existing_key, str) and isinstance(existing, dict)
                  and isinstance(existing.get('reference'), dict),
                  'INVALID_EXISTING_REGISTRY_ENTRY')
            existing_ref = existing['reference']
            if existing_ref.get('node_id') == baseline_id:
                raise OwnerApprovalError('BASELINE_ALREADY_REGISTERED')

        from . import trusted_baseline_registration as registration
        try:
            if registration.entry_kind(proposed_entry) == registration.REGISTRATION_ONLY:
                _need(registration_subject is not None, 'REGISTRATION_SUBJECT_REQUIRED')
            preflight = registration.prepare(
                project, registry_path, registry_key, baseline_path, proposed_entry,
                expected_reference_sha256=expected_reference_sha256,
                expected_build_policy_sha256=expected_build_policy_sha256,
                expected_workflow_repository=policy['repository'],
                expected_workflow_repository_id=policy['repository_id'],
            )
        except registration.RegistrationError as error:
            code = str(error)
            if re.fullmatch(r'[A-Z0-9_]{1,100}', code):
                raise OwnerApprovalError(code) from error
            raise OwnerApprovalError('EXISTING_REGISTRATION_PREFLIGHT_FAILED') from error
        _need(preflight.get('blocking_reasons') ==
              ['INDEPENDENT_REGISTRATION_AUTHORITY_NOT_CONFIGURED'],
              'EXISTING_REGISTRATION_PREFLIGHT_FAILED')
        _need(preflight.get('P4_1_verification') == 'P4_1_VERIFIED',
              'P4_1_BASELINE_QUALIFICATION_REQUIRED')
        _need(preflight.get('quality_status') in
              ('QUALITY_ACCEPTED', 'QUALITY_REVIEW_REQUIRED'), 'INVALID_QUALITY_STATUS')
        _need(q1_status in ('QUALIFIED', 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR',
                           'NOT_RECORDED_IN_EXISTING_BASELINE_QUALITY_SCHEMA')
              and preflight.get('q1_status') == q1_status,
              'Q1_STATUS_MISMATCH')
        candidate_id = preflight.get('candidate_id')
        _need(isinstance(candidate_id, str) and candidate_id,
              'CANDIDATE_IDENTITY_UNAVAILABLE')
        for existing_key, existing in registry['baselines'].items():
            _need(isinstance(existing_key, str) and isinstance(existing, dict)
                  and isinstance(existing.get('reference'), dict),
                  'INVALID_EXISTING_REGISTRY_ENTRY')
            existing_ref = existing['reference']
            existing_candidate = existing_ref.get('candidate_id')
            if existing_candidate == candidate_id:
                raise OwnerApprovalError('CANDIDATE_ALREADY_REGISTERED')
            existing_binding = _candidate_binding(existing_ref)
            proposed_binding = _candidate_binding(reference)
            if (all(value is not None for value in existing_binding)
                    and existing_binding == proposed_binding):
                raise OwnerApprovalError('CANDIDATE_BINDING_ALREADY_REGISTERED')

        actor = _github_identity(client, policy, context)
        remote_registry_raw = _remote_registry_bytes(client, policy, actor['commit_sha'])
        _need(remote_registry_raw == registry_raw, 'REMOTE_REGISTRY_CHECKOUT_MISMATCH')
        current_registry_sha = hashlib.sha256(registry_raw).hexdigest()
        entry_sha = digest(proposed_entry)
        dispatch_inputs = context.get('dispatch_inputs')
        _need(isinstance(dispatch_inputs, dict), 'WORKFLOW_DISPATCH_INPUTS_UNAVAILABLE')
        expected_dispatch = {
            'registry_key': registry_key,
            'baseline_id': baseline_id,
            'candidate_id': candidate_id,
            'corpus_sha256': reference.get('corpus_sha256'),
            'registry_entry_sha256': entry_sha,
        }
        if registration_subject is not None:
            # The transaction reconstructs this from fresh verified evidence.
            # This read-only interface checks the binding, not the provenance
            # of the caller's execution environment or a saved result JSON.
            from .published_candidate_verification import _json
            from .corpus_snapshot import canonical
            registration_subject = _json(canonical(registration_subject))
            subject = registration_subject
            from .published_candidate_verification import ASSETS, ANCHOR_FIELDS
            _need(set(subject) == {'schema_version', 'purpose', 'registry_key', 'registry_entry',
                  'registry_entry_sha256', 'expected_old_registry_sha256', 'approval_policy_sha256',
                  'candidate_release', 'candidate_release_reference_sha256', 'candidate', 'baseline',
                  'parent_r2_anchor', 'execution', 'production_promotion'}
                  and set(subject['candidate_release']) == {'schema_version', 'assets'}
                  and subject['candidate_release']['schema_version'] == 1
                  and set(subject['candidate_release']['assets']) == ASSETS
                  and all(set(item) == {'storage', 'sha256'} and _sha(item['sha256'])
                          and isinstance(item['storage'], dict)
                          for item in subject['candidate_release']['assets'].values())
                  and set(subject['parent_r2_anchor']) == ANCHOR_FIELDS,
                  'INCOMPLETE_REGISTRATION_SUBJECT')
            _need(subject.get('schema_version') == 1
                  and subject.get('purpose') == 'TRUSTED_RESEARCH_PARENT_REGISTRATION'
                  and subject.get('registry_key') == registry_key
                  and subject.get('registry_entry') == proposed_entry
                  and subject.get('registry_entry_sha256') == entry_sha
                  and subject.get('expected_old_registry_sha256') == current_registry_sha
                  and subject.get('approval_policy_sha256') == policy_sha256
                  and subject.get('execution') == 'NO_FRESH_REPLAY'
                  and subject.get('production_promotion') == 'NOT_AUTHORIZED',
                  'REGISTRATION_SUBJECT_BINDING_MISMATCH')
            candidate = subject.get('candidate', {})
            baseline = subject.get('baseline', {})
            _need(set(candidate) == {'candidate_id', 'corpus_sha256', 'source_state', 'generation',
                  'upstreams', 'parent_id', 'build_fingerprint', 'benchmark_sha256',
                  'quality_status', 'q1_status'}
                  and set(baseline) == {'baseline_id', 'reference_sha256', 'p4_1_verification', 'q1_status'},
                  'INCOMPLETE_REGISTRATION_SUBJECT')
            _need(candidate.get('candidate_id') == candidate_id
                  and candidate.get('corpus_sha256') == reference['corpus_sha256']
                  and candidate.get('upstreams') == reference['upstreams']
                  and candidate.get('source_state') == reference['source_state']
                  and candidate.get('build_fingerprint') == reference['build_fingerprint']
                  and candidate.get('generation') == preflight['generation']
                  and candidate.get('quality_status') == preflight['quality_status']
                  and baseline.get('baseline_id') == baseline_id
                  and baseline.get('reference_sha256') == expected_reference_sha256
                  and baseline.get('p4_1_verification') == 'P4_1_VERIFIED'
                  and baseline.get('q1_status') == q1_status,
                  'REGISTRATION_SUBJECT_IDENTITY_MISMATCH')
            _need(digest(subject['candidate_release']) == subject.get('candidate_release_reference_sha256')
                  and subject['parent_r2_anchor']['candidate_id'] == candidate_id
                  and subject['parent_r2_anchor']['baseline_id'] == baseline_id
                  and (q1_status == 'NOT_RECORDED_IN_EXISTING_BASELINE_QUALITY_SCHEMA'
                       or candidate.get('q1_status') == q1_status),
                  'REGISTRATION_SUBJECT_EVIDENCE_MISMATCH')
            expected_dispatch['registration_subject_sha256'] = digest(subject)
        _need(set(dispatch_inputs) == set(expected_dispatch)
              and all(dispatch_inputs.get(key) == value
                      for key, value in expected_dispatch.items()),
              'WORKFLOW_DISPATCH_SUBJECT_MISMATCH')
        payload = {
            'schema_version': 1,
            'decision_type': 'OWNER_MANUAL_RESEARCH_BASELINE_APPROVAL',
            'decision': 'APPROVED_FOR_TRUSTED_RESEARCH_PARENT_REGISTRATION_ONLY',
            'workflow_run': actor,
            'review_subject': {
                'registry_key': registry_key,
                'registry_sha256_before_registration': current_registry_sha,
                'registry_entry_sha256': entry_sha,
                'baseline_id': baseline_id,
                'candidate_id': candidate_id,
                'corpus_sha256': reference.get('corpus_sha256'),
                'release_identity': reference.get('storage'),
                'parent_r2_release_identity': reference.get('parent_rows_storage'),
                'source_revisions': reference.get('upstreams'),
                'source_state': reference.get('source_state'),
                'build_fingerprint': reference.get('build_fingerprint'),
                'generation': preflight.get('generation'),
                'quality_status': preflight.get('quality_status'),
                'q1_status': q1_status,
                'p4_1_verification': preflight.get('P4_1_verification'),
            },
            'approval_policy_sha256': policy_sha256,
            'registry_modified': False,
            'registration': 'NOT_PERFORMED',
            'production_promotion': 'NOT_AUTHORIZED',
        }
        if registration_subject is not None:
            payload['registration_subject_sha256'] = digest(registration_subject)
        _need(payload['review_subject']['corpus_sha256'] == preflight['bindings']['corpus_sha256']
              and payload['review_subject']['source_revisions'] == preflight['bindings']['upstreams'],
              'APPROVAL_SUBJECT_BINDING_MISMATCH')
        latest_actor = _github_identity(client, policy, context)
        _need(latest_actor == actor, 'WORKFLOW_APPROVAL_CONTEXT_CHANGED')
        _need(_remote_registry_bytes(client, policy, actor['commit_sha']) == registry_raw,
              'REMOTE_REGISTRY_CHANGED_DURING_VERIFICATION')
        result.update(payload)
        result.update({
            'status': 'OWNER_APPROVAL_VERIFIED',
            'decision': 'OWNER_APPROVAL_VERIFIED',
            'research_approval': 'VERIFIED_FOR_REGISTRATION_ONLY',
            'trust_scope': 'REPOSITORY_OWNER_OR_CONFIGURED_APPROVER_SELF_ATTESTATION',
            'independent_expert_review': 'NOT_ESTABLISHED',
            'quality_acceptance': 'NOT_GRANTED_BY_THIS_APPROVAL',
        })
        return result
    except OwnerApprovalError as error:
        result['reasons'].append(str(error))
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError,
            RuntimeError, subprocess.SubprocessError) as error:
        result['reasons'].append('INVALID_OR_UNAVAILABLE_OWNER_APPROVAL_EVIDENCE')
    return result


class GitHubCLI:
    """Read-only GitHub API client using the runner's GH_TOKEN/gh auth."""
    def __init__(self):
        self.executable = shutil.which('gh')
        _need(self.executable is not None, 'GITHUB_CLI_UNAVAILABLE')

    def json(self, endpoint):
        _need(isinstance(endpoint, str) and endpoint.startswith('repos/'),
              'UNSUPPORTED_GITHUB_ENDPOINT')
        try:
            response = subprocess.run(
                [self.executable, 'api', '--hostname', 'github.com', '--method', 'GET',
                 '-H', 'Accept: application/vnd.github+json', endpoint],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=45,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise OwnerApprovalError('GITHUB_API_UNAVAILABLE') from error
        _need(response.returncode == 0, 'GITHUB_API_UNAVAILABLE')
        try:
            value = json.loads(response.stdout)
        except (ValueError, TypeError) as error:
            raise OwnerApprovalError('INVALID_GITHUB_API_RESPONSE') from error
        _need(isinstance(value, dict), 'INVALID_GITHUB_API_RESPONSE')
        return value


def context_from_environment(environment=None):
    """Read GitHub-provided runtime identifiers; never accept actor as CLI input."""
    env = os.environ if environment is None else environment
    try:
        run_id = int(env.get('GITHUB_RUN_ID', ''))
        attempt = int(env.get('GITHUB_RUN_ATTEMPT', ''))
        actor_id = int(env.get('GITHUB_ACTOR_ID', ''))
        repository_id = int(env.get('GITHUB_REPOSITORY_ID', ''))
    except (TypeError, ValueError) as error:
        raise OwnerApprovalError('GITHUB_RUNTIME_CONTEXT_UNAVAILABLE') from error
    event_name = env.get('GITHUB_EVENT_NAME')
    event_path = env.get('GITHUB_EVENT_PATH')
    _need(event_name == 'workflow_dispatch' and isinstance(event_path, str),
          'GITHUB_DISPATCH_EVENT_UNAVAILABLE')
    try:
        event = _strict_json(Path(event_path).read_text(encoding='utf-8'))
        dispatch_inputs = event.get('inputs') if isinstance(event, dict) else None
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        raise OwnerApprovalError('GITHUB_DISPATCH_EVENT_UNAVAILABLE') from error
    _need(isinstance(dispatch_inputs, dict), 'GITHUB_DISPATCH_INPUTS_UNAVAILABLE')
    return {
        'run_id': run_id, 'run_attempt': attempt, 'actor_id': actor_id,
        'repository': env.get('GITHUB_REPOSITORY'), 'repository_id': repository_id,
        'head_sha': env.get('GITHUB_SHA'), 'ref': env.get('GITHUB_REF'),
        'dispatch_inputs': dispatch_inputs,
    }
