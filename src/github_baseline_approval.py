"""Read-only GitHub PR approval verification for schema-2 Baseline registration.

This adapter verifies an independently pinned policy, exact PR review, exact
registry proposal and current protection state. It does not write a Registry,
create approval, alter P8, or authorize production deployment.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import shutil
import subprocess
from unittest.mock import patch
from urllib.parse import quote

from .corpus_snapshot import canonical, digest, file_digest, read_json

POLICY_FIELDS = {'schema_version', 'enabled', 'repository', 'repository_id',
                 'default_branch', 'registry_path', 'allow_personal_owner',
                 'trusted_approver_ids', 'minimum_approving_reviews'}
REQUEST_KIND = 'sphinxsistant-trusted-baseline-registration'
REQUEST_MARKER = '<!-- sphinxsistant-baseline-registration-v1'


class ApprovalError(ValueError):
    """Sanitized fail-closed approval verification error."""


def _strict_json(value):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ApprovalError('AMBIGUOUS_JSON_OBJECT')
            result[key] = item
        return result
    return json.loads(value, object_pairs_hook=unique)


def _need(test, reason):
    if not test:
        raise ApprovalError(reason)


def _positive(value):
    return type(value) is int and value > 0


def _sha(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def _time(value):
    _need(isinstance(value, str) and value.endswith('Z'), 'INVALID_REVIEW_TIMESTAMP')
    try:
        parsed = datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError as error:
        raise ApprovalError('INVALID_REVIEW_TIMESTAMP') from error
    _need(parsed.tzinfo is not None, 'INVALID_REVIEW_TIMESTAMP')
    return parsed


def _policy(project, path, expected_sha):
    path = Path(path).expanduser().absolute()
    config_dir = (Path(project) / 'configs').resolve()
    _need(path.is_file() and not path.is_symlink() and path.parent.resolve() == config_dir,
          'UNSAFE_APPROVAL_POLICY_PATH')
    _need(_sha(expected_sha) and file_digest(path) == expected_sha,
          'APPROVAL_POLICY_SHA256_MISMATCH')
    config = _strict_json(path.read_text(encoding='utf-8'))
    _need(isinstance(config, dict) and set(config) == POLICY_FIELDS
          and type(config['schema_version']) is int and config['schema_version'] == 1
          and config['enabled'] is True, 'INVALID_OR_DISABLED_APPROVAL_POLICY')
    _need(isinstance(config['repository'], str)
          and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', config['repository'])
          and _positive(config['repository_id']), 'INVALID_APPROVAL_REPOSITORY_POLICY')
    _need(isinstance(config['default_branch'], str)
          and re.fullmatch(r'[A-Za-z0-9._/-]{1,200}', config['default_branch'])
          and not config['default_branch'].startswith('-')
          and '..' not in config['default_branch']
          and not any(x in config['default_branch'] for x in ('~', '^', ':', '?', '*', '[', '\\')),
          'INVALID_APPROVAL_BRANCH_POLICY')
    registry_path = config['registry_path'] if isinstance(config['registry_path'], str) else ''
    registry_parts = PurePosixPath(registry_path).parts if registry_path else ()
    _need(registry_parts and PurePosixPath(registry_path).as_posix() == registry_path
          and not PurePosixPath(registry_path).is_absolute()
          and all(re.fullmatch(r'[A-Za-z0-9._-]+', part) and part != '..' for part in registry_parts),
          'INVALID_REGISTRY_PATH_POLICY')
    _need(type(config['allow_personal_owner']) is bool, 'INVALID_OWNER_APPROVAL_POLICY')
    approvers = config['trusted_approver_ids']
    _need(isinstance(approvers, list) and all(_positive(value) for value in approvers)
          and len(approvers) == len(set(approvers)), 'INVALID_APPROVER_ID_POLICY')
    _need(approvers or config['allow_personal_owner'], 'NO_APPROVER_AUTHORITY_CONFIGURED')
    _need(type(config['minimum_approving_reviews']) is int
          and 1 <= config['minimum_approving_reviews'] <= 6,
          'INVALID_APPROVAL_COUNT_POLICY')
    return config


def _api(client, path, reason='GITHUB_API_UNAVAILABLE'):
    try:
        return client.json(path)
    except Exception as error:
        raise ApprovalError(reason) from error


def _all_pages(client, path, *, maximum_pages=100):
    values = []
    for page in range(1, maximum_pages + 1):
        separator = '&' if '?' in path else '?'
        rows = _api(client, f'{path}{separator}per_page=100&page={page}')
        _need(isinstance(rows, list) and len(rows) <= 100, 'INVALID_GITHUB_PAGINATION_RESPONSE')
        values.extend(rows)
        if len(rows) < 100:
            return values
    raise ApprovalError('GITHUB_PAGINATION_LIMIT_EXCEEDED')


def _content(client, repository, path, ref):
    endpoint = f'repos/{repository}/contents/{quote(path, safe="/")}?ref={quote(ref, safe="/")}'
    value = _api(client, endpoint, 'REGISTRY_CONTENT_UNAVAILABLE')
    _need(isinstance(value, dict) and value.get('path') == path
          and value.get('type') == 'file' and value.get('encoding') == 'base64',
          'INVALID_REGISTRY_CONTENT_RESPONSE')
    try:
        # GitHub's Contents API wraps base64 in whitespace/newlines.
        raw = base64.b64decode(''.join(value['content'].split()), validate=True)
        parsed = _strict_json(raw.decode('utf-8'))
    except (KeyError, ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise ApprovalError('INVALID_REGISTRY_CONTENT_RESPONSE') from error
    _need(isinstance(parsed, dict), 'INVALID_REGISTRY_CONTENT_RESPONSE')
    return raw, parsed


def _request_body(body):
    _need(isinstance(body, str) and body.count(REQUEST_MARKER) == 1,
          'MISSING_OR_AMBIGUOUS_REGISTRATION_REQUEST')
    suffix = body.split(REQUEST_MARKER, 1)[1]
    _need(suffix.count('-->') == 1, 'INVALID_REGISTRATION_REQUEST_BLOCK')
    payload = suffix.split('-->', 1)[0].strip()
    try:
        value = _strict_json(payload)
    except (ValueError, TypeError) as error:
        raise ApprovalError('INVALID_REGISTRATION_REQUEST_BLOCK') from error
    _need(isinstance(value, dict), 'INVALID_REGISTRATION_REQUEST_BLOCK')
    return value


def _verify_rulesets(client, repository, branch):
    # Ask GitHub which active rules actually apply to this branch instead of
    # reimplementing its ref-pattern matching semantics locally.
    branch_path = quote(branch, safe='')
    effective = _all_pages(client, f'repos/{repository}/rules/branches/{branch_path}')
    ids = set()
    for rule in effective:
        _need(isinstance(rule, dict) and _positive(rule.get('ruleset_id')),
              'UNVERIFIABLE_EFFECTIVE_RULESET_ID')
        ids.add(rule['ruleset_id'])
    for ruleset_id in sorted(ids):
        detail = _api(client, f'repos/{repository}/rulesets/{ruleset_id}?includes_parents=true',
                      'EFFECTIVE_RULESET_DETAILS_UNAVAILABLE')
        _need(isinstance(detail, dict) and detail.get('id') == ruleset_id
              and detail.get('enforcement') == 'active', 'INVALID_EFFECTIVE_RULESET_DETAILS')
        bypass = detail.get('bypass_actors')
        _need(isinstance(bypass, list), 'UNVERIFIABLE_RULESET_BYPASS_POLICY')
        _need(not bypass, 'EFFECTIVE_RULESET_HAS_BYPASS_ACTORS')


def _verify_protection(client, repository, branch, minimum):
    branch_path = quote(branch, safe='')
    branch_info = _api(client, f'repos/{repository}/branches/{branch_path}',
                       'EFFECTIVE_BRANCH_PROTECTION_UNAVAILABLE')
    _need(isinstance(branch_info, dict) and branch_info.get('protected') is True,
          'DEFAULT_BRANCH_NOT_PROTECTED')
    protection = _api(client, f'repos/{repository}/branches/{branch_path}/protection',
                      'EFFECTIVE_BRANCH_PROTECTION_UNAVAILABLE')
    required = protection.get('required_pull_request_reviews') if isinstance(protection, dict) else None
    _need(isinstance(required, dict), 'PULL_REQUEST_REVIEW_PROTECTION_MISSING')
    _need(type(required.get('required_approving_review_count')) is int
          and required['required_approving_review_count'] >= minimum,
          'INSUFFICIENT_BRANCH_PROTECTION_APPROVAL_COUNT')
    _need(required.get('dismiss_stale_reviews') is True
          and required.get('require_last_push_approval') is True,
          'STALE_OR_LAST_PUSH_REVIEW_PROTECTION_MISSING')
    bypass = required.get('bypass_pull_request_allowances', {})
    _need(isinstance(bypass, dict)
          and all(key in bypass and isinstance(bypass[key], list) and bypass[key] == []
                  for key in ('users', 'teams', 'apps')),
          'BRANCH_PROTECTION_HAS_REVIEW_BYPASS')
    admins = protection.get('enforce_admins')
    if not isinstance(admins, dict) or 'enabled' not in admins:
        admins = _api(client, f'repos/{repository}/branches/{branch_path}/protection/enforce_admins',
                      'ADMIN_PROTECTION_UNAVAILABLE')
    _need(isinstance(admins, dict) and admins.get('enabled') is True,
          'ADMIN_BRANCH_PROTECTION_NOT_ENFORCED')
    _verify_rulesets(client, repository, branch)


def _reviewers(client, repository, pull_number, head_sha, author_id, policy, owner):
    reviews = _all_pages(client, f'repos/{repository}/pulls/{pull_number}/reviews')
    by_user = {}
    for review in reviews:
        _need(isinstance(review, dict) and _positive(review.get('id'))
              and isinstance(review.get('user'), dict) and _positive(review['user'].get('id'))
              and review['user'].get('type') == 'User',
              'INVALID_PULL_REVIEW_RESPONSE')
        state = review.get('state')
        _need(state in ('APPROVED', 'CHANGES_REQUESTED', 'COMMENTED', 'DISMISSED', 'PENDING'),
              'INVALID_PULL_REVIEW_STATE')
        if state == 'PENDING':
            continue
        submitted = _time(review.get('submitted_at'))
        user_id = review['user']['id']
        item = (submitted, review)
        previous = by_user.get(user_id)
        if previous is None or item[0] >= previous[0]:
            by_user[user_id] = item

    allowed = set(policy['trusted_approver_ids'])
    if policy['allow_personal_owner'] and owner.get('type') == 'User':
        owner_id = owner.get('id')
        _need(_positive(owner_id), 'REPOSITORY_OWNER_ID_UNAVAILABLE')
        allowed.add(owner_id)
    approvals = []
    for user_id, (_, review) in by_user.items():
        if review.get('state') == 'CHANGES_REQUESTED':
            raise ApprovalError('CURRENT_CHANGES_REQUESTED_REVIEW')
        if user_id not in allowed or user_id == author_id:
            continue
        if review.get('state') == 'APPROVED':
            _need(review.get('commit_id') == head_sha, 'STALE_APPROVAL_FOR_OLDER_COMMIT')
            approvals.append({'review_id': review['id'], 'reviewer_id': user_id,
                              'commit_sha': head_sha, 'submitted_at': review['submitted_at']})
    _need(len(approvals) >= policy['minimum_approving_reviews'],
          'MISSING_AUTHORIZED_APPROVAL')
    return approvals


def _proposal_manifest(key, entry, report, quality, q1_status, base_sha, proposed_sha):
    ref = entry['reference']
    _need(isinstance(q1_status, str) and q1_status in
          ('QUALIFIED', 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR'), 'INVALID_Q1_STATUS')
    return {
        'schema_version': 1, 'kind': REQUEST_KIND, 'registry_key': key,
        'candidate_id': report['candidate_id'], 'baseline_id': report['baseline_id'],
        'corpus_sha256': ref['corpus_sha256'], 'entry_sha256': digest(entry),
        'base_registry_sha256': base_sha, 'proposed_registry_sha256': proposed_sha,
        'source_revisions': ref['upstreams'], 'source_state': ref['source_state'],
        'generation': report['generation'], 'build_fingerprint': ref['build_fingerprint'],
        'benchmark_sha256': quality['policy']['benchmark_sha256'],
        'quality_status': quality['status'], 'q1_status': q1_status,
        'release_assets': {'baseline': ref['storage'], 'parent_r2_results': ref['parent_rows_storage']},
        'production_promotion': 'NOT_AUTHORIZED',
    }


def verify(project, baseline_path, registry_path, registry_key, proposed_entry, *,
           policy_path, policy_sha256, pull_number, expected_base_registry_sha256,
           expected_proposed_registry_sha256, q1_status, client, now=None):
    """Return a point-in-time PR approval verification; never mutates files."""
    now = now or datetime.now(timezone.utc)
    result = {'schema_version': 1, 'status': 'BLOCKED', 'registry_modified': False,
              'registration': 'NOT_PERFORMED', 'production_promotion': 'NOT_AUTHORIZED',
              'reasons': []}
    try:
        policy = _policy(project, policy_path, policy_sha256)
        _need(type(pull_number) is int and pull_number > 0, 'INVALID_PULL_NUMBER')
        _need(_sha(expected_base_registry_sha256) and _sha(expected_proposed_registry_sha256),
              'INVALID_REGISTRY_CONTENT_PIN')
        registry_path = Path(registry_path)
        _need(registry_path.is_file() and not registry_path.is_symlink(), 'LOCAL_REGISTRY_UNSAFE')
        _need(registry_path.resolve() == (Path(project) / policy['registry_path']).resolve(),
              'LOCAL_REGISTRY_PATH_POLICY_MISMATCH')
        local_base_raw = registry_path.read_bytes()
        _need(hashlib.sha256(local_base_raw).hexdigest() == expected_base_registry_sha256,
              'LOCAL_BASE_REGISTRY_PIN_MISMATCH')
        base_registry = _strict_json(local_base_raw.decode('utf-8'))
        _need(isinstance(base_registry, dict) and base_registry.get('schema_version') == 2
              and isinstance(base_registry.get('baselines'), dict), 'INVALID_SCHEMA2_REGISTRY')
        _need(registry_key not in base_registry['baselines'], 'REGISTRY_KEY_ALREADY_EXISTS')
        _need(isinstance(proposed_entry, dict), 'INVALID_PROPOSED_REGISTRY_ENTRY')

        report = _validators(project, baseline_path, proposed_entry, policy)
        from .corpus_snapshot import checked_file
        quality_path = checked_file(baseline_path, 'quality.json')
        quality = read_json(quality_path)
        checksums = read_json(checked_file(baseline_path, 'checksums.json'))
        _need(report.get('P4_1_verification') == 'P4_1_VERIFIED'
              and report.get('baseline_id') == proposed_entry['reference']['node_id'],
              'P4_1_BASELINE_QUALIFICATION_REQUIRED')
        _need(isinstance(checksums, dict)
              and checksums.get('quality.json') == file_digest(quality_path),
              'P4_1_QUALITY_EVIDENCE_NOT_SEALED')
        _need(quality.get('status') in ('QUALITY_ACCEPTED', 'QUALITY_REVIEW_REQUIRED'),
              'INVALID_RECORDED_QUALITY_STATUS')
        _need(quality.get('assessment') == report.get('retrieval_evaluation'),
              'QUALITY_ASSESSMENT_BINDING_MISMATCH')
        proposed_registry = _strict_json(local_base_raw.decode('utf-8'))
        proposed_registry['baselines'][registry_key] = proposed_entry
        proposed_bytes = (json.dumps(proposed_registry, ensure_ascii=False, sort_keys=True,
                          indent=2, allow_nan=False) + '\n').encode('utf-8')
        proposed_raw_sha = hashlib.sha256(proposed_bytes).hexdigest()
        _need(proposed_raw_sha == expected_proposed_registry_sha256,
              'PROPOSED_REGISTRY_PIN_MISMATCH')
        manifest = _proposal_manifest(registry_key, proposed_entry, report, quality,
                                      q1_status, expected_base_registry_sha256,
                                      expected_proposed_registry_sha256)

        repository = policy['repository']
        repo = _api(client, f'repos/{repository}')
        _need(repo.get('full_name', '').casefold() == repository.casefold()
              and repo.get('id') == policy['repository_id']
              and repo.get('default_branch') == policy['default_branch'],
              'REPOSITORY_IDENTITY_MISMATCH')
        _need(isinstance(repo.get('owner'), dict), 'REPOSITORY_OWNER_ID_UNAVAILABLE')
        _verify_protection(client, repository, policy['default_branch'],
                           policy['minimum_approving_reviews'])
        pull = _api(client, f'repos/{repository}/pulls/{pull_number}')
        _need(pull.get('number') == pull_number and pull.get('state') == 'open'
              and pull.get('merged') is False and pull.get('draft') is False,
              'PULL_REQUEST_NOT_OPEN_FOR_REVIEW')
        _need(isinstance(pull.get('base'), dict) and pull['base'].get('ref') == policy['default_branch']
              and pull['base'].get('repo', {}).get('id') == policy['repository_id'],
              'PULL_REQUEST_BASE_MISMATCH')
        _need(isinstance(pull.get('head'), dict) and pull['head'].get('repo', {}).get('id') == policy['repository_id'],
              'CROSS_REPOSITORY_PULL_REQUEST_NOT_ALLOWED')
        head_sha = pull['head'].get('sha')
        _need(isinstance(head_sha, str) and re.fullmatch(r'[0-9a-f]{40}', head_sha),
              'INVALID_PULL_HEAD_SHA')
        author_id = pull.get('user', {}).get('id')
        _need(_positive(author_id), 'PULL_AUTHOR_ID_UNAVAILABLE')
        body_manifest = _request_body(pull.get('body'))
        _need(canonical(body_manifest) == canonical(manifest), 'PULL_REQUEST_CANDIDATE_BINDING_MISMATCH')

        files = _all_pages(client, f'repos/{repository}/pulls/{pull_number}/files')
        _need(len(files) == 1 and files[0].get('filename') == policy['registry_path'],
              'PULL_REQUEST_CHANGES_OUTSIDE_REGISTRY')
        base_sha = pull.get('base', {}).get('sha')
        _need(isinstance(base_sha, str) and re.fullmatch(r'[0-9a-f]{40}', base_sha),
              'INVALID_PULL_BASE_SHA')
        base_raw, api_base_registry = _content(client, repository, policy['registry_path'], base_sha)
        current_raw, current_registry = _content(client, repository, policy['registry_path'], policy['default_branch'])
        head_raw, api_proposed_registry = _content(client, repository, policy['registry_path'], head_sha)
        _need(hashlib.sha256(base_raw).hexdigest() == expected_base_registry_sha256
              and base_raw == local_base_raw, 'PULL_BASE_REGISTRY_CHANGED')
        _need(hashlib.sha256(current_raw).hexdigest() == expected_base_registry_sha256
              and current_raw == base_raw, 'REGISTRY_CHANGED_SINCE_REVIEW_BASE')
        _need(hashlib.sha256(head_raw).hexdigest() == expected_proposed_registry_sha256
              and canonical(api_proposed_registry) == canonical(proposed_registry),
              'PULL_PROPOSED_REGISTRY_MISMATCH')
        _need(canonical(api_base_registry) == canonical(base_registry), 'PULL_BASE_REGISTRY_MISMATCH')

        approvals = _reviewers(client, repository, pull_number, head_sha,
                               author_id, policy, repo['owner'])
        _need(all(_time(item['submitted_at']) <= now for item in approvals),
              'FUTURE_APPROVAL_TIMESTAMP')
        # Re-read the mutable review/protection state and content after pagination.
        latest_approvals = _reviewers(client, repository, pull_number, head_sha,
                                      author_id, policy, repo['owner'])
        _need(canonical(latest_approvals) == canonical(approvals),
              'APPROVALS_CHANGED_DURING_VERIFICATION')
        _verify_protection(client, repository, policy['default_branch'],
                           policy['minimum_approving_reviews'])
        latest_pull = _api(client, f'repos/{repository}/pulls/{pull_number}')
        latest_current_raw, _ = _content(client, repository, policy['registry_path'], policy['default_branch'])
        _need(latest_pull.get('head', {}).get('sha') == head_sha
              and latest_pull.get('body') == pull.get('body')
              and latest_pull.get('state') == 'open'
              and latest_current_raw == current_raw,
              'APPROVAL_OR_REGISTRY_CHANGED_DURING_VERIFICATION')
        result.update({
            'status': 'GITHUB_APPROVAL_VERIFIED', 'repository': policy['repository'],
            'repository_id': policy['repository_id'], 'pull_number': pull_number,
            'pull_head_sha': head_sha, 'pull_author_id': author_id,
            'registry_key': registry_key, 'registry_entry_sha256': digest(proposed_entry),
            'base_registry_sha256': expected_base_registry_sha256,
            'proposed_registry_sha256': expected_proposed_registry_sha256,
            'candidate_id': report['candidate_id'], 'baseline_id': report['baseline_id'],
            'corpus_sha256': proposed_entry['reference']['corpus_sha256'],
            'source_revisions': proposed_entry['reference']['upstreams'],
            'source_state': proposed_entry['reference']['source_state'],
            'generation': report['generation'],
            'build_fingerprint': proposed_entry['reference']['build_fingerprint'],
            'benchmark_sha256': quality['policy']['benchmark_sha256'],
            'quality_status': quality['status'], 'q1_status': q1_status,
            'q1_status_source': 'EXPLICIT_REVIEW_BINDING_NOT_REQUALIFIED_HERE',
            'reviewers': approvals, 'release_assets': manifest['release_assets'],
            'p4_1_verification': report['P4_1_verification'],
            'decision': 'APPROVED',
            'research_approval': 'VERIFIED_FOR_REGISTRATION_ONLY',
            'quality_acceptance': 'NOT_GRANTED_BY_THIS_APPROVAL',
            'production_promotion': 'NOT_AUTHORIZED',
            'registry_modified': False, 'registration': 'NOT_PERFORMED',
            'policy_sha256': policy_sha256,
            'verified_at': now.astimezone(timezone.utc).isoformat(),
        })
        return result
    except ApprovalError as error:
        result['reasons'].append(str(error))
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError,
            RuntimeError, subprocess.SubprocessError) as error:
        # Do not include API response bodies, paths, URLs, or credential-adjacent
        # stderr in user-facing diagnostics.
        result['reasons'].append('INVALID_OR_UNAVAILABLE_APPROVAL_EVIDENCE')
    return result


def _validators(project, baseline_path, entry, approval_policy):
    from . import research_baseline, schema2_workflow, trusted_snapshot
    ref = entry['reference']
    _need(set(entry) == {'build_policy_path', 'build_policy_sha256',
                         'expected_reference_sha256', 'reference'},
          'INVALID_SCHEMA2_REGISTRY_ENTRY')
    # Keep the existing remote/private same-repository invariant: the expected
    # identity comes from independently pinned deployment policy, not the entry.
    with patch.dict(os.environ, {
        'GITHUB_REPOSITORY': approval_policy['repository'],
        'GITHUB_REPOSITORY_ID': str(approval_policy['repository_id']),
    }):
        trusted_snapshot.validate_reference(ref, entry['expected_reference_sha256'], remote=True)
    from .corpus_snapshot import checked_file
    policy_path = checked_file(project, entry['build_policy_path'])
    _need(_sha(entry['build_policy_sha256'])
          and file_digest(policy_path) == entry['build_policy_sha256'], 'BUILD_POLICY_CHECKSUM_MISMATCH')
    schema2_workflow._research_parent_scope(ref, read_json(policy_path))
    return research_baseline.verify_baseline(project, baseline_path,
        ref['build_fingerprint'], expected_id=ref['node_id'])


class GitHubCLI:
    """Read-only GitHub API client backed by existing gh authentication."""
    def __init__(self):
        self.executable = shutil.which('gh')
        _need(self.executable is not None, 'GITHUB_CLI_UNAVAILABLE')

    def json(self, endpoint):
        _need(isinstance(endpoint, str) and endpoint.startswith('repos/'), 'UNSUPPORTED_GITHUB_ENDPOINT')
        try:
            response = subprocess.run([self.executable, 'api', '--hostname', 'github.com',
                '--method', 'GET', '-H', 'Accept: application/vnd.github+json', endpoint],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=45)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ApprovalError('GITHUB_API_UNAVAILABLE') from error
        _need(response.returncode == 0, 'GITHUB_API_UNAVAILABLE')
        try:
            return json.loads(response.stdout)
        except (ValueError, TypeError) as error:
            raise ApprovalError('INVALID_GITHUB_API_RESPONSE') from error
