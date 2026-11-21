"""Owner-dispatched Bot PR for an already uploaded, reviewed source branch.

Never checks out or executes proposal code. No retry, approval, merge or ref write.
"""
import json
import os
import re
import subprocess

REPO = 'XiangruZhang007/SPHinXsistant-CI-Test'
BASE = 'ci-upstream-refresh'
OWNER = 239840087
WORKFLOW = '.github/workflows/ci_v2_bot_proposal.yml'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def gh(method, path, data=None):
    command = ['gh', 'api', '--hostname', 'github.com', '--method', method, path]
    if data is not None:
        command += ['--input', '-']
    result = subprocess.run(command, input=json.dumps(data) if data is not None else None,
                            text=True, capture_output=True, timeout=45, check=False)
    require(result.returncode == 0, 'GITHUB_API_FAILED_OR_UNCERTAIN_NO_RETRY')
    require(len(result.stdout) <= 2_000_000, 'API_RESPONSE_TOO_LARGE')
    return json.loads(result.stdout)


def propose(env, api):
    require(env.get('GITHUB_REPOSITORY') == REPO and
            env.get('GITHUB_REPOSITORY_ID') == '1455203884' and
            env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and
            env.get('GITHUB_REF') == 'refs/heads/' + BASE and
            env.get('GITHUB_RUN_ATTEMPT') == '1' and
            env.get('GITHUB_ACTOR_ID') == str(OWNER), 'UNTRUSTED_DISPATCH')
    source, target = env.get('PROPOSAL_SHA', ''), env.get('EXPECTED_BASE_SHA', '')
    branch = env.get('PROPOSAL_BRANCH', '')
    require(all(re.fullmatch('[0-9a-f]{40}', s) for s in (source, target)), 'INVALID_SHA')
    require(re.fullmatch(r'ci-v2-proposals/[a-z0-9][a-z0-9-]{0,63}', branch), 'INVALID_BRANCH')
    root = 'repos/' + REPO
    repo = api('GET', root)
    require(repo['id'] == 1455203884 and repo['full_name'] == REPO and
            repo['default_branch'] == BASE and repo['owner']['id'] == OWNER, 'REPOSITORY_MISMATCH')
    run = api('GET', root + '/actions/runs/' + env['GITHUB_RUN_ID'])
    require(run['repository']['id'] == 1455203884 and
            run['actor']['id'] == OWNER and run['triggering_actor']['id'] == OWNER and
            run['event'] == 'workflow_dispatch' and run['run_attempt'] == 1 and
            run['head_sha'] == target == env.get('GITHUB_SHA') == env.get('GITHUB_WORKFLOW_SHA') and
            run['head_branch'] == BASE and run['path'] == WORKFLOW, 'RUN_IDENTITY_MISMATCH')
    # The Actions PR-creation setting is an Owner/admin deployment preflight.
    # GITHUB_TOKEN deliberately has no Administration permission to inspect it.
    # If disabled later, GitHub rejects the single POST; never escalate or retry.
    identity = api('GET', 'users/github-actions%5Bbot%5D')
    require(identity['type'] == 'Bot' and identity['login'] == 'github-actions[bot]' and
            identity['id'] != OWNER, 'BOT_IDENTITY_UNVERIFIED')
    comparison = api('GET', root + '/compare/' + target + '...' + source)
    require(comparison['status'] == 'ahead' and comparison['behind_by'] == 0 and
            comparison['ahead_by'] > 0 and comparison['total_commits'] > 0 and
            comparison['merge_base_commit']['sha'] == target, 'PROPOSAL_NOT_FAST_FORWARD')
    # Immediate immutable-input readback. A later race is detected in the PR response;
    # it is never repaired automatically. Human review still targets the actual PR diff.
    require(api('GET', root + '/git/ref/heads/' + BASE)['object']['sha'] == target and
            api('GET', root + '/git/ref/heads/' + branch)['object']['sha'] == source,
            'BRANCH_MOVED')
    # One mutation only. No repair/retry on ambiguous or rejected responses.
    pr = api('POST', root + '/pulls', {
        'title': 'Reviewed proposal ' + source[:12], 'base': BASE, 'head': branch,
        'body': 'Exact proposed commit: ' + source + '\nReviewed base: ' + target +
                '\nOwner review and applicable CODEOWNERS approval are required. '
                'No automatic approval or merge. No Writer authority granted.',
        'maintainer_can_modify': False})
    require(pr['user']['id'] == identity['id'] and pr['user']['type'] == 'Bot' and
            pr['user']['login'] == identity['login'] and pr['base']['ref'] == BASE and
            pr['base']['sha'] == target and pr['head']['sha'] == source and
            pr['head']['ref'] == branch and pr['head']['repo']['id'] == 1455203884 and
            pr['base']['repo']['id'] == 1455203884 and pr['state'] == 'open',
            'CREATED_PR_UNEXPECTED_STOP_WITHOUT_REPAIR')
    return {'status': 'BOT_PR_CREATED_OWNER_REVIEW_REQUIRED', 'number': pr['number'],
            'author': identity['login'], 'head_sha': source, 'base_sha': target}


if __name__ == '__main__':
    try:
        print(json.dumps(propose(os.environ, gh), sort_keys=True))
    except Exception:
        # API stderr may contain sensitive data; preserve uncertainty, never retry.
        raise SystemExit('BOT_PR_FAILED_OR_UNCERTAIN: inspect Run and PRs read-only; do not retry')
