#!/usr/bin/env python3
"""Owner-dispatched credential verification; no repository-data mutation."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import re
import time
import urllib.error
import urllib.request

REPOSITORY = 'XiangruZhang007/SPHinXsistant-CI-Test'
REPOSITORY_ID = 1455203884
OWNER_ID = 239840087
APP_ID = 5855475
INSTALLATION_ID = 184185108
WORKFLOW = '.github/workflows/ci_v2_writer_credentials.yml'
ENVIRONMENTS = {'ci-v2-audit-writer': 28077782729, 'ci-v2-automatic-writer': 28321116175}
PERMISSIONS = {'contents': 'write', 'metadata': 'read'}


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def api(method, path, token, body=None):
    # Fixed host, bounded responses, no redirect/retry or response-body logging.
    allowed = (method, path) in {
        ('GET', '/app'), ('GET', '/app/installations/' + str(INSTALLATION_ID)),
        ('POST', '/app/installations/' + str(INSTALLATION_ID) + '/access_tokens'),
        ('GET', '/installation/repositories?per_page=100'), ('DELETE', '/installation/token'),
        ('GET', '/repos/' + REPOSITORY),
        ('GET', '/repos/' + REPOSITORY + '/git/ref/heads/ci-upstream-refresh'),
        ('GET', '/repos/' + REPOSITORY + '/rulesets/27770139'),
        ('GET', '/repos/' + REPOSITORY + '/rulesets/27793434'),
    } or method == 'GET' and path in {
        '/repos/' + REPOSITORY + '/environments/' + name + suffix
        for name in ENVIRONMENTS for suffix in ('', '/deployment-branch-policies?per_page=100')
    } or method == 'GET' and path == '/repos/' + REPOSITORY + '/actions/runs/' + os.environ.get('GITHUB_RUN_ID', '') + '/attempts/1'
    need(allowed, 'API_OPERATION_DENIED')
    request = urllib.request.Request('https://api.github.com' + path, method=method,
        data=None if body is None else json.dumps(body).encode(), headers={
            'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json', 'User-Agent': 'ci-v2-credential-verifier'})
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=15) as response:
            raw = response.read(1024 * 1024 + 1)
            need(len(raw) <= 1024 * 1024, 'OVERSIZED_API_RESPONSE')
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        raise ValueError('GITHUB_API_HTTP_' + str(error.code)) from None
    except Exception:
        raise ValueError('GITHUB_API_FAILED_NO_RETRY') from None


def preflight(env, call=api):
    name = env.get('WRITER_ENVIRONMENT')
    need(name in ENVIRONMENTS and env.get('GITHUB_ACTIONS') == 'true'
         and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
         and env.get('GITHUB_REPOSITORY') == REPOSITORY
         and env.get('GITHUB_REPOSITORY_ID') == str(REPOSITORY_ID)
         and env.get('GITHUB_ACTOR_ID') == str(OWNER_ID)
         and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
         and env.get('GITHUB_RUN_ATTEMPT') == '1'
         and env.get('GITHUB_REF') == 'refs/heads/ci-upstream-refresh'
         and env.get('GITHUB_WORKFLOW_REF') == REPOSITORY + '/' + WORKFLOW + '@refs/heads/ci-upstream-refresh'
         and env.get('GITHUB_SHA') == env.get('GITHUB_WORKFLOW_SHA'), 'UNTRUSTED_VERIFICATION_CONTEXT')
    token = env.get('GH_TOKEN', '')
    need(bool(token), 'READER_TOKEN_REQUIRED')
    root = '/repos/' + REPOSITORY
    repo = call('GET', root, token)
    need(repo.get('id') == REPOSITORY_ID and repo.get('owner', {}).get('id') == OWNER_ID
         and repo.get('default_branch') == 'ci-upstream-refresh', 'REPOSITORY_MISMATCH')
    run = call('GET', root + '/actions/runs/' + env['GITHUB_RUN_ID'] + '/attempts/1', token)
    need(run.get('event') == 'workflow_dispatch' and run.get('run_attempt') == 1
         and run.get('head_sha') == env['GITHUB_SHA'] and run.get('path') == WORKFLOW
         and run.get('actor', {}).get('id') == run.get('triggering_actor', {}).get('id') == OWNER_ID,
         'OWNER_RUN_MISMATCH')
    ref = call('GET', root + '/git/ref/heads/ci-upstream-refresh', token)
    need(ref.get('object', {}).get('sha') == env['GITHUB_SHA'], 'STALE_PROTECTED_REVISION')
    environment = call('GET', root + '/environments/' + name, token)
    need(environment.get('id') == ENVIRONMENTS[name] and environment.get('name') == name
         and environment.get('can_admins_bypass') is False
         and environment.get('deployment_branch_policy') == {'protected_branches': False, 'custom_branch_policies': True},
         'ENVIRONMENT_MISMATCH')
    rules = environment.get('protection_rules', [])
    if name == 'ci-v2-automatic-writer':
        need([r.get('type') for r in rules] == ['branch_policy'], 'AUTOMATIC_PROTECTION_MISMATCH')
    else:
        reviewers = [r for r in rules if r.get('type') == 'required_reviewers']
        need(len(reviewers) == 1 and reviewers[0].get('reviewers')
             and [(r.get('type'), r.get('reviewer', {}).get('id')) for r in reviewers[0]['reviewers']] == [('User', OWNER_ID)],
             'MANUAL_REVIEWER_MISMATCH')
    branches = call('GET', root + '/environments/' + name + '/deployment-branch-policies?per_page=100', token)
    need(branches.get('total_count') == 1 and len(branches.get('branch_policies', [])) == 1
         and {k: branches['branch_policies'][0].get(k) for k in ('name', 'type')} == {'name': 'ci-upstream-refresh', 'type': 'branch'},
         'ENVIRONMENT_BRANCH_MISMATCH')
    for number, target, required in [(27770139, 'ci-v2-authority-audit/*', {'deletion', 'non_fast_forward', 'required_linear_history'}),
                                     (27793434, 'ci-upstream-refresh', {'deletion', 'non_fast_forward', 'pull_request'})]:
        rule = call('GET', root + '/rulesets/' + str(number), token)
        need(rule.get('enforcement') == 'active' and rule.get('target') == 'branch'
             and rule.get('conditions') == {'ref_name': {'include': ['refs/heads/' + target], 'exclude': []}}
             and rule.get('bypass_actors') == [] and required <= {r.get('type') for r in rule.get('rules', [])}, 'PROTECTION_MISMATCH')
        if number == 27793434:
            pr = next(r['parameters'] for r in rule['rules'] if r['type'] == 'pull_request')
            need(pr.get('required_approving_review_count', 0) >= 1 and pr.get('require_code_owner_review') is True
                 and pr.get('dismiss_stale_reviews_on_push') is True, 'CODEOWNERS_PROTECTION_REQUIRED')
    return {'environment': name, 'environment_id': ENVIRONMENTS[name], 'implementation_revision': env['GITHUB_SHA']}


def jwt(private_key):
    encode = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b'=')
    now = int(time.time())
    message = b'.'.join(encode(json.dumps(v, separators=(',', ':')).encode()) for v in (
        {'alg': 'RS256', 'typ': 'JWT'}, {'iat': now - 60, 'exp': now + 540, 'iss': str(APP_ID)}))
    # Anonymous RAM-backed descriptor: no private-key filesystem file is created.
    key_bytes = private_key.encode()
    need(0 < len(key_bytes) <= 65536, 'INVALID_APP_KEY_SIZE')
    fd = os.memfd_create('ci-v2-app-key', flags=os.MFD_CLOEXEC)
    try:
        offset = 0
        while offset < len(key_bytes):
            offset += os.write(fd, key_bytes[offset:])
        os.lseek(fd, 0, os.SEEK_SET)
        result = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', '/proc/self/fd/' + str(fd)],
            input=message, pass_fds=(fd,), env={'PATH': '/usr/bin:/bin'},
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False)
        need(result.returncode == 0, 'APP_KEY_SIGNING_FAILED')
    finally:
        os.close(fd)
    return (message + b'.' + encode(result.stdout)).decode()


def verify_credentials(app_jwt, call=api):
    app = call('GET', '/app', app_jwt)
    need(app.get('id') == APP_ID and app.get('slug') == 'sphinxsistant-audit-writer'
         and app.get('permissions') == PERMISSIONS, 'APP_IDENTITY_OR_PERMISSION_MISMATCH')
    installation = call('GET', '/app/installations/' + str(INSTALLATION_ID), app_jwt)
    need(installation.get('id') == INSTALLATION_ID and installation.get('app_id') == APP_ID
         and installation.get('account', {}).get('id') == OWNER_ID
         and installation.get('repository_selection') == 'selected'
         and installation.get('suspended_at') is None and installation.get('permissions') == PERMISSIONS,
         'INSTALLATION_IDENTITY_OR_PERMISSION_MISMATCH')
    endpoint = '/app/installations/' + str(INSTALLATION_ID) + '/access_tokens'
    # First observe the entire installation, using a read-only token without repo narrowing.
    for label, body, expected in (
        ('installation-read', {'permissions': {'contents': 'read'}}, {'contents': 'read', 'metadata': 'read'}),
        ('repository-writer', {'repository_ids': [REPOSITORY_ID], 'permissions': {'contents': 'write'}}, PERMISSIONS)):
        token = None
        try:
            issued = call('POST', endpoint, app_jwt, body)
            token = issued.get('token')
            need(isinstance(token, str) and bool(token), 'INSTALLATION_TOKEN_NOT_ISSUED')
            need(issued.get('permissions') == expected, 'TOKEN_PERMISSION_MISMATCH')
            repos = call('GET', '/installation/repositories?per_page=100', token)
            need(repos.get('total_count') == 1 and len(repos.get('repositories', [])) == 1
                 and repos['repositories'][0].get('id') == REPOSITORY_ID
                 and repos['repositories'][0].get('full_name') == REPOSITORY, 'ACTUAL_INSTALLATION_SCOPE_MISMATCH')
            result = call('GET', '/repos/' + REPOSITORY, token)
            need(result.get('id') == REPOSITORY_ID and result.get('full_name') == REPOSITORY, 'TOKEN_UNUSABLE')
        finally:
            if token:
                call('DELETE', '/installation/token', token)
    return {'status': 'WRITER_CREDENTIALS_VERIFIED', 'app_id': APP_ID, 'installation_id': INSTALLATION_ID,
        'repository': REPOSITORY, 'repository_id': REPOSITORY_ID, 'installation_permissions': PERMISSIONS,
        'full_installation_repository_count': 1, 'temporary_tokens_revoked': True,
        'write_permission': 'ISSUANCE_VERIFIED_NO_DATA_WRITE_TEST', 'repository_data_mutations': False}


def main():
    try:
        need(len(sys.argv) == 2 and sys.argv[1] in ('preflight', 'verify'), 'INVALID_OPERATION')
        env = dict(os.environ)
        context = preflight(env)
        if sys.argv[1] == 'preflight':
            print(json.dumps({'status': 'CREDENTIAL_PREFLIGHT_PASSED', **context})); return 0
        key = os.environ.pop('CI_V2_AUDIT_APP_PRIVATE_KEY', '')
        need(bool(key), 'APP_KEY_SECRET_MISSING')
        result = {**verify_credentials(jwt(key)), **context}
        # Reobserve protected context after verification; no lifecycle handoff.
        need(preflight(env) == context, 'VERIFICATION_CONTEXT_CHANGED')
        print(json.dumps(result, sort_keys=True)); return 0
    except Exception as error:
        reason = str(error) if isinstance(error, ValueError) and re.fullmatch('[A-Z][A-Z0-9_]{0,79}', str(error)) else 'CREDENTIAL_VERIFICATION_FAILED'
        print(json.dumps({'status': 'BLOCKED', 'reason': reason, 'retry': False})); return 1


if __name__ == '__main__':
    raise SystemExit(main())
