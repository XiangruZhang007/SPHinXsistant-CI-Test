#!/usr/bin/env python3
"""Stdlib-only, fresh-runner gate; never loads project/scientific modules or keys.

The same checks execute before mint and before installation-token read-only use.
Environment approval is not a Workflow allowlist. Real branch protection remains
mandatory, and no gate or token validation invokes the audit writer or APPLY.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPOSITORY = 'XiangruZhang007/SPHinXsistant-CI-Test'
REPOSITORY_ID = 1455203884
OWNER_ID = 239840087
APP_ID = 5855475
INSTALLATION_ID = 184185108
ENVIRONMENT_ID = 28077782729
WORKFLOW = '.github/workflows/ci_v2_parent_authority_transition.yml'
ENVIRONMENT = 'ci-v2-audit-writer'
PROJECT = Path(__file__).resolve().parents[1]
OPERATION = 'PARENT_BUILD_AUTHORITY_TRANSITION_V1'


def need(ok, reason):
    if not ok: raise ValueError(reason)


def strict(raw):
    need(isinstance(raw, str) and 0 < len(raw.encode()) <= 256 * 1024, 'INVALID_WRITER_JSON')
    def unique(pairs):
        value = {}
        for k, v in pairs:
            need(k not in value, 'INVALID_WRITER_JSON'); value[k] = v
        return value
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('INVALID_WRITER_JSON')))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()).hexdigest()


class GitHubRead:
    def __call__(self, endpoint, token=None):
        need(endpoint.startswith('repos/' + REPOSITORY + '/') or endpoint in (
            'repos/' + REPOSITORY, 'installation/repositories?per_page=100'), 'WRITER_API_ENDPOINT_DENIED')
        env = {k: v for k, v in os.environ.items() if k != 'GH_DEBUG'}
        if token is not None: env['GH_TOKEN'] = token
        result = subprocess.run(['gh', 'api', '--method', 'GET', endpoint,
            '-H', 'X-GitHub-Api-Version: 2022-11-28'], env=env, capture_output=True,
            text=True, timeout=30)
        need(result.returncode == 0, 'WRITER_API_READ_FAILED')
        return strict(result.stdout)


def checkout(project, revision, files):
    critical = {WORKFLOW, '.github/CODEOWNERS', 'src/hosted_parent_authority_transition.py',
                'scripts/parent_authority_writer_prepare.py', 'scripts/parent_authority_writer_gate.py'}
    need(isinstance(files, dict) and critical <= files.keys(), 'WRITER_CODE_MANIFEST_INCOMPLETE')
    for name, pin in files.items():
        need(isinstance(name, str) and not Path(name).is_absolute()
             and '..' not in Path(name).parts and isinstance(pin, str)
             and re.fullmatch('[0-9a-f]{64}', pin), 'WRITER_CODE_MANIFEST_INVALID')
        path = project
        for part in Path(name).parts:
            path = path / part; need(not path.is_symlink(), 'WRITER_CODE_SYMLINK_DENIED')
        need(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == pin,
             'WRITER_CODE_BYTES_MISMATCH')
    env = {**os.environ, 'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1'}
    def git(*args):
        return subprocess.check_output(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
            '-C', str(project), *args], env=env, stderr=subprocess.PIPE)
    need(git('rev-parse', 'HEAD').decode().strip() == revision, 'WRITER_CHECKOUT_REVISION_MISMATCH')
    git('diff', '--quiet', '--no-ext-diff', 'HEAD', '--')
    need(not git('ls-files', '--others', '--exclude-standard', '--', 'src', 'scripts', 'configs', '.github').strip(),
         'WRITER_CHECKOUT_UNTRACKED_CODE')
    for name in files: git('ls-files', '--error-unmatch', '--', name)


def verify(env, project, api):
    need(env.get('GITHUB_ACTIONS') == 'true' and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
         and env.get('RUNNER_ARCH') == 'ARM64' and env.get('GITHUB_JOB') == 'trusted-audit-writer'
         and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
         and env.get('GITHUB_REPOSITORY') == REPOSITORY and env.get('GITHUB_REPOSITORY_ID') == str(REPOSITORY_ID)
         and env.get('GITHUB_ACTOR_ID') == str(OWNER_ID) and env.get('GITHUB_RUN_ATTEMPT') == '1'
         and env.get('GITHUB_REF') == 'refs/heads/ci-upstream-refresh'
         and env.get('GITHUB_WORKFLOW_REF') == REPOSITORY + '/' + WORKFLOW + '@refs/heads/ci-upstream-refresh',
         'WRITER_RUNTIME_IDENTITY_MISMATCH')
    need(env.get('PARENT_AUTHORITY_WRITER_PREPARATION_ENABLED') == 'true', 'WRITER_PREPARATION_DISABLED')
    raw = env.get('PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_JSON', '')
    need(hashlib.sha256(raw.encode()).hexdigest() == env.get('PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_SHA256'),
         'WRITER_DEPLOYMENT_PIN_MISMATCH')
    config = strict(raw); r = config['request']; sha = r['implementation_revision']
    need(env.get('GITHUB_SHA') == env.get('GITHUB_WORKFLOW_SHA') == sha
         and r['repository'] == REPOSITORY and r['repository_id'] == REPOSITORY_ID
         and r['workflow_path'] == WORKFLOW and r['default_branch'] == 'ci-upstream-refresh',
         'WRITER_DEPLOYMENT_IDENTITY_MISMATCH')
    receipt = strict(env.get('OWNER_PREPARATION_RECEIPT', ''))
    files = strict(env.get('OWNER_IMPLEMENTATION_FILES', ''))
    need(digest({'schema_version': 1, 'operation': OPERATION, 'files': files})
         == config['implementation_contract_sha256'], 'WRITER_IMPLEMENTATION_CONTRACT_MISMATCH')
    checkout(project, sha, files)
    base = 'repos/' + REPOSITORY
    repo = api(base)
    need(repo.get('full_name') == REPOSITORY and repo.get('id') == REPOSITORY_ID
         and repo.get('owner', {}).get('id') == OWNER_ID and repo['owner'].get('type') == 'User'
         and repo.get('default_branch') == 'ci-upstream-refresh' and repo.get('private') is False,
         'WRITER_REPOSITORY_OWNER_MISMATCH')
    run_id = int(env.get('GITHUB_RUN_ID', '0')); need(run_id > 0, 'WRITER_RUN_ID_REQUIRED')
    run = api(base + '/actions/runs/' + str(run_id) + '/attempts/1')
    need(run.get('id') == run_id and run.get('run_attempt') == 1 and run.get('event') == 'workflow_dispatch'
         and run.get('status') == 'in_progress' and run.get('head_sha') == sha
         and run.get('head_branch') == 'ci-upstream-refresh'
         and run.get('repository', {}).get('id') == REPOSITORY_ID
         and run['repository'].get('full_name') == REPOSITORY
         and run.get('actor', {}).get('id') == run.get('triggering_actor', {}).get('id') == OWNER_ID
         and run['actor'].get('type') == run['triggering_actor'].get('type') == 'User',
         'WRITER_OWNER_RUN_MISMATCH')
    workflow = api(base + '/actions/workflows/' + str(config['workflow_id']))
    need(workflow.get('id') == run.get('workflow_id') == config['workflow_id']
         and workflow.get('path') == WORKFLOW and workflow.get('state') == 'active', 'WRITER_WORKFLOW_MISMATCH')
    ref = api(base + '/git/ref/heads/ci-upstream-refresh')
    need(ref.get('ref') == 'refs/heads/ci-upstream-refresh' and ref.get('object', {}).get('sha') == sha,
         'WRITER_STALE_DEFAULT_HEAD')
    expected = {'operation': OPERATION, 'decision': 'APPROVE_RESTRICTED_BUILD_AUTHORITY_TRANSITION',
        'request_sha256': digest(r), 'proposal_sha256': config['proposal_sha256'],
        'transition_subject_sha256': config['subject_sha256'], 'transaction_id': r['transaction_id']}
    event = strict(Path(env['GITHUB_EVENT_PATH']).read_text())
    need(event.get('inputs') == expected, 'WRITER_DISPATCH_BINDING_MISMATCH')
    need(receipt.get('status') == 'OWNER_VERIFIED_WRITER_PREPARATION_ONLY'
         and receipt.get('authorization') == 'NOT_GRANTED' and receipt.get('registry_committed') is False
         and all(receipt.get(k) == v for k, v in {
             'request_sha256': digest(r), 'proposal_sha256': config['proposal_sha256'],
             'subject_sha256': config['subject_sha256'],
             'implementation_contract_sha256': config['implementation_contract_sha256']}.items()),
         'WRITER_OWNER_PREPARATION_BINDING_MISMATCH')
    actor = receipt['workflow_run']
    need(all(actor.get(k) == v for k,v in {'repository':REPOSITORY, 'repository_id':REPOSITORY_ID,
        'actor_id':OWNER_ID,'run_id':run_id,'run_attempt':1,'workflow_id':config['workflow_id'],
        'workflow_path':WORKFLOW,'commit_sha':sha,'event':'workflow_dispatch'}.items()),
        'WRITER_OWNER_PREPARATION_RUN_MISMATCH')
    jobs = api(base + '/actions/runs/' + str(run_id) + '/attempts/1/jobs?per_page=100')
    need(jobs.get('total_count', 101) <= 100, 'WRITER_JOB_INVENTORY_INCOMPLETE')
    prepare_jobs = [j for j in jobs.get('jobs', []) if j.get('name') == 'inspect-transition']
    need(len(prepare_jobs) == 1 and prepare_jobs[0].get('head_sha') == sha
         and prepare_jobs[0].get('status') == 'completed' and prepare_jobs[0].get('conclusion') == 'success',
         'WRITER_OWNER_JOB_NOT_SUCCESSFUL')
    steps = [x for x in prepare_jobs[0].get('steps', []) if x.get('name') == 'Prepare verified Owner context for isolated Writer']
    need(len(steps) == 1 and steps[0].get('conclusion') == 'success', 'WRITER_OWNER_STEP_NOT_SUCCESSFUL')
    environment = api(base + '/environments/' + ENVIRONMENT)
    reviewers = [x for x in environment.get('protection_rules', []) if x.get('type') == 'required_reviewers']
    need(environment.get('id') == ENVIRONMENT_ID and environment.get('name') == ENVIRONMENT
         and environment.get('can_admins_bypass') is False and len(reviewers) == 1
         and reviewers[0].get('prevent_self_review') is False
         and len(reviewers[0].get('reviewers', [])) == 1
         and reviewers[0]['reviewers'][0].get('type') == 'User'
         and reviewers[0]['reviewers'][0].get('reviewer', {}).get('id') == OWNER_ID
         and environment.get('deployment_branch_policy') == {'protected_branches': False, 'custom_branch_policies': True},
         'WRITER_ENVIRONMENT_PROTECTION_MISMATCH')
    policies = api(base + '/environments/' + ENVIRONMENT + '/deployment-branch-policies?per_page=100')
    need(policies.get('total_count') == 1 and len(policies.get('branch_policies', [])) == 1
         and policies['branch_policies'][0].get('name') == 'ci-upstream-refresh'
         and policies['branch_policies'][0].get('type') == 'branch', 'WRITER_ENVIRONMENT_BRANCH_MISMATCH')
    rules = api(base + '/rules/branches/ci-upstream-refresh')
    need(isinstance(rules, list), 'WRITER_BRANCH_RULES_UNVERIFIED')
    types = {x.get('type') for x in rules}
    prs = [x.get('parameters', {}) for x in rules if x.get('type') == 'pull_request']
    need({'deletion', 'non_fast_forward', 'pull_request'} <= types and any(
        x.get('required_approving_review_count', 0) >= 1 and x.get('require_code_owner_review') is True
        and x.get('dismiss_stale_reviews_on_push') is True for x in prs), 'TRUSTED_WORKFLOW_BRANCH_PROTECTION_REQUIRED')
    # Effective-rule presence alone must not hide a broad admin/writer bypass.
    for kind in ('deletion', 'non_fast_forward', 'pull_request'):
        protected = False
        for rule in (x for x in rules if x.get('type') == kind):
            number = rule.get('ruleset_id')
            need(type(number) is int and number > 0, 'WRITER_BRANCH_RULE_ORIGIN_UNVERIFIED')
            origin = api(base + '/rulesets/' + str(number))
            if (origin.get('id') == number and origin.get('target') == 'branch'
                    and origin.get('enforcement') == 'active' and origin.get('bypass_actors') == []
                    and origin.get('conditions') == {'ref_name': {
                        'include': ['refs/heads/ci-upstream-refresh'], 'exclude': []}}
                    and rule['type'] in {x.get('type') for x in origin.get('rules', [])}):
                if kind != 'pull_request' or any(x.get('type') == kind
                    and x.get('parameters', {}).get('required_approving_review_count', 0) >= 1
                    and x['parameters'].get('require_code_owner_review') is True
                    and x['parameters'].get('dismiss_stale_reviews_on_push') is True
                    for x in origin['rules']): protected = True
        need(protected, 'WRITER_BRANCH_PROTECTION_BYPASS_OR_SCOPE_UNSAFE')
    return {'status': 'TRUSTED_WRITER_PRETOKEN_CONTEXT_VERIFIED', 'authorization': 'NOT_GRANTED',
        'run_id': run_id, 'run_attempt': 1, 'implementation_revision': sha,
        'environment_id': ENVIRONMENT_ID, 'live_apply': False}


def verify_token(env, api):
    need(env.get('ACTUAL_WRITER_INSTALLATION_ID') == str(INSTALLATION_ID), 'WRITER_INSTALLATION_MISMATCH')
    token = env.get('PARENT_AUTHORITY_AUDIT_TOKEN', '')
    need(bool(token) and not any(c.isspace() for c in token), 'WRITER_INSTALLATION_TOKEN_REQUIRED')
    repos = api('installation/repositories?per_page=100', token=token)
    values = repos.get('repositories', [])
    need(repos.get('total_count') == len(values) == 1 and values[0].get('id') == REPOSITORY_ID
         and values[0].get('full_name') == REPOSITORY, 'WRITER_INSTALLATION_REPOSITORY_SCOPE_MISMATCH')
    return {'status': 'WRITER_INSTALLATION_TOKEN_SCOPE_VERIFIED', 'app_id': APP_ID,
        'installation_id': INSTALLATION_ID, 'repository_id': REPOSITORY_ID,
        'authorization': 'NOT_GRANTED', 'live_apply': False, 'audit_mutation': 'NOT_PERFORMED'}


def main():
    try:
        need(sys.argv[1:] in ([], ['--verify-token']), 'WRITER_GATE_ARGUMENTS_DENIED')
        api = GitHubRead(); result = verify(os.environ, PROJECT, api)
        if sys.argv[1:]: result = verify_token(os.environ, api)
        print(json.dumps(result, sort_keys=True)); return 0
    except Exception as error:
        reason = str(error) if re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(error)) else 'WRITER_GATE_FAILED'
        print(json.dumps({'status': 'BLOCKED', 'reason': reason, 'authorization': 'NOT_GRANTED'})); return 1


if __name__ == '__main__':
    raise SystemExit(main())
