"""Point-in-time GitHub Issue research-review diagnostics, never authorization.

Operator-owned, independently SHA-pinned configuration lives directly in the CI
configs/ directory, never in an artifact. No real reviewer is configured here.
The live API author ID, exact comment bytes/times and sealed CI bindings must
all match. Edits, rejection, revocation, duplicates, expiry and offline caches
are not accepted. Only the designated Issue is read; no GitHub writes occur.
See docs/research_review.md for the deliberately narrow trust contract.
"""
from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from . import update_eligibility_gate as gate
from .corpus_snapshot import canonical, digest

CONFIG_ROOT = Path(__file__).resolve().parents[1] / 'configs'
REPOSITORY = 'XiangruZhang007/SPHinX_AI_Assistant'
KIND = 'sphinxsistant-research-review'
CONFIG_KEYS = {'schema_version', 'repository', 'repository_id', 'issue_number', 'issue_id',
               'comment_id', 'reviewer_ids', 'comment_sha256', 'created_at', 'updated_at', 'valid_until'}
RECORD_KEYS = {'schema_version', 'kind', 'scope', 'bindings', 'decision', 'reviewer_id', 'reviewed_at'}


class ReviewError(ValueError):
    pass


def _need(condition, code):
    if not condition:
        raise ReviewError(code)


def _positive(value):
    return type(value) is int and value > 0


def _json(raw):
    return json.loads(raw, object_pairs_hook=gate._unique, parse_constant=gate._reject_constant)


def _time(value):
    _need(isinstance(value, str) and value.endswith('Z'), 'INVALID_REVIEW_TIME')
    parsed = datetime.fromisoformat(value[:-1] + '+00:00')
    return parsed


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _configuration(path, expected_sha, now):
    _need(path is not None and expected_sha is not None, 'TRUST_CONFIGURATION_MISSING')
    path = Path(path).expanduser().absolute()
    _need(path.is_file() and not path.is_symlink() and not CONFIG_ROOT.is_symlink()
          and '..' not in path.parts and path.parent == CONFIG_ROOT
          and path.resolve().parent == CONFIG_ROOT.resolve(), 'UNSAFE_TRUST_CONFIGURATION')
    raw = path.read_bytes()
    _need(len(raw) <= 16384 and isinstance(expected_sha, str) and _sha(raw) == expected_sha,
          'TRUST_CONFIGURATION_SHA256_MISMATCH')
    config = _json(raw)
    _need(set(config) == CONFIG_KEYS and type(config['schema_version']) is int
          and config['schema_version'] == 1 and config['repository'] == REPOSITORY,
          'INVALID_TRUST_CONFIGURATION')
    _need(all(_positive(config[k]) for k in ('repository_id', 'issue_number', 'issue_id', 'comment_id')),
          'INVALID_TRUST_CONFIGURATION')
    reviewers = config['reviewer_ids']
    _need(isinstance(reviewers, list) and reviewers and all(_positive(x) for x in reviewers)
          and len(set(reviewers)) == len(reviewers), 'REVIEWER_AUTHORITY_MISSING')
    sha = config['comment_sha256']
    _need(isinstance(sha, str) and len(sha) == 64 and all(c in '0123456789abcdef' for c in sha),
          'INVALID_COMMENT_PIN')
    # V1 accepts only original, unedited comments. Replacement requires a newly
    # reviewed independent configuration, not a silent update of this pin.
    _need(config['created_at'] == config['updated_at'], 'MODIFIED_REVIEW')
    _need(_time(config['created_at']) <= now <= _time(config['valid_until']), 'STALE_REVIEW')
    return config


def _bindings(artifact, result, transport):
    _need(result['artifact_integrity'] == 'PASS'
          and result['gate']['evidence_consistency'] == 'VERIFIED_ARCHIVED_BINDINGS',
          'INTERNAL_EVIDENCE_UNVERIFIED')
    _need(transport['repository'] == REPOSITORY
          and all(_positive(transport[k]) for k in ('repository_id', 'run_id', 'attempt', 'artifact_id'))
          and transport['artifact_name'] == f"ci-v2-research-{transport['run_id']}-{transport['attempt']}",
          'TRANSPORT_BINDING_UNVERIFIED')
    artifact = Path(artifact)
    _need(artifact.is_file() and not artifact.is_symlink(), 'ORIGINAL_ZIP_REQUIRED')
    with artifact.open('rb') as source:
        sha = hashlib.file_digest(source, 'sha256').hexdigest()
    _need(sha == transport['expected_sha256'], 'TRANSPORT_SHA256_MISMATCH')
    with ExitStack() as stack:
        evidence = gate._Evidence(artifact, stack)
        candidate = evidence.json('candidate/candidate.json')
        identity = candidate['identity']
        quality = evidence.json('quality/quality-report.json')
        original = evidence.json('result.json')['bindings']
        quality_sha = evidence.sha('quality/quality-report.json')
        _need(quality_sha == evidence.json('checksums.json')['quality/quality-report.json']
              == evidence.json('quality/checksums.json')['quality-report.json'], 'QUALITY_REPORT_UNVERIFIED')
        expected = {
            'candidate_id': candidate['candidate_id'],
            'corpus_sha256': quality['corpus_sha256'],
            'build_fingerprint': quality['build_fingerprint'],
            'benchmark_sha256': original['benchmark_sha256'],
            'upstreams': identity['upstreams'],
        }
        _need(canonical(expected) == canonical(result['bindings'])
              and expected['candidate_id'] == 'sha256-' + digest(identity)
              == quality['candidate_id'] == original['candidate_id'], 'CANDIDATE_BINDING_MISMATCH')
        _need(quality['raw_results_sha256'] == original['target_rows_sha256']
              == evidence.sha('quality/incremental-raw-results.json')
              and quality['policy_sha256'] == digest(quality['policy']), 'QUALITY_BINDING_MISMATCH')
        expected['quality'] = {'quality_report_sha256': quality_sha,
                               'raw_results_sha256': quality['raw_results_sha256'],
                               'policy_sha256': quality['policy_sha256']}
        expected['transport'] = {key: transport[key] for key in
                                 ('repository', 'repository_id', 'run_id', 'attempt', 'artifact_id')}
        expected['transport']['artifact_sha256'] = sha
        return expected


def _get(client, endpoint):
    try:
        return client.json(endpoint)
    except Exception as error:
        # API stderr, URLs and comment contents must not leak into diagnostics.
        raise ReviewError('GITHUB_UNAVAILABLE') from error


def _comment(comment, config, api):
    _need(type(comment['id']) is int and comment['id'] == config['comment_id']
          and comment['url'] == f"{api}/issues/comments/{config['comment_id']}"
          and comment['issue_url'] == f"{api}/issues/{config['issue_number']}", 'COMMENT_IDENTITY_MISMATCH')
    author = comment['user']
    _need(_positive(author['id']) and author['id'] in config['reviewer_ids'] and author['type'] == 'User',
          'UNAUTHORIZED_REVIEWER')
    _need(comment['created_at'] == config['created_at']
          and comment['updated_at'] == config['updated_at'], 'MODIFIED_REVIEW')
    body = comment['body']
    _need(isinstance(body, str) and len(body.encode('utf-8')) <= 16384
          and _sha(body.encode('utf-8')) == config['comment_sha256'], 'MODIFIED_REVIEW')
    record = _json(body)
    _need(set(record) == RECORD_KEYS and type(record['schema_version']) is int and record['schema_version'] == 1
          and record['kind'] == KIND and record['scope'] == 'RESEARCH_DIAGNOSTIC_ONLY', 'INVALID_REVIEW_RECORD')
    _need(_positive(record['reviewer_id']) and record['reviewer_id'] == author['id'], 'FORGED_REVIEWER')
    _need(_time(record['reviewed_at']) <= _time(comment['created_at']), 'INVALID_REVIEW_TIME')
    _need(record['decision'] in ('APPROVE_RESEARCH_REVIEW', 'REJECT', 'REVOKE'), 'INVALID_REVIEW_DECISION')
    return record


def _issue(issue, config, api):
    _need(issue['id'] == config['issue_id'] and issue['number'] == config['issue_number']
          and issue['url'] == f"{api}/issues/{config['issue_number']}"
          and issue['repository_url'] == api and 'pull_request' not in issue, 'ISSUE_IDENTITY_MISMATCH')
    _need(type(issue['comments']) is int and 0 < issue['comments'] <= 10000, 'MISSING_OR_EXCESSIVE_REVIEWS')


def _live_review(client, config, expected):
    prefix = f'repos/{REPOSITORY}'
    api = 'https://api.github.com/' + prefix
    repository = _get(client, prefix)
    _need(repository['full_name'] == REPOSITORY and repository['id'] == config['repository_id']
          == expected['transport']['repository_id'], 'REPOSITORY_IDENTITY_MISMATCH')
    issue_path = f"{prefix}/issues/{config['issue_number']}"
    comment_path = f"{prefix}/issues/comments/{config['comment_id']}"
    issue = _get(client, issue_path)
    _issue(issue, config, api)
    comment = _get(client, comment_path)
    record = _comment(comment, config, api)
    _need(canonical(record['bindings']) == canonical(expected), 'REVIEW_BINDING_MISMATCH')
    _need(record['decision'] == 'APPROVE_RESEARCH_REVIEW', 'REVIEW_' + record['decision'])
    # Inspect only the designated Issue. Never choose a latest matching approval.
    comments = []
    for page in range(1, 102):
        rows = _get(client, f'{issue_path}/comments?per_page=100&page={page}')
        _need(isinstance(rows, list) and len(rows) <= 100, 'INVALID_REVIEW_LIST')
        comments.extend(rows)
        if len(rows) < 100:
            break
    _need(len(comments) == issue['comments'], 'INCOMPLETE_OR_CHANGED_REVIEW_LIST')
    ids = [row['id'] for row in comments]
    _need(all(_positive(x) for x in ids) and len(set(ids)) == len(ids), 'DUPLICATE_REVIEW')
    selected = [row for row in comments if row['id'] == config['comment_id']]
    _need(len(selected) == 1, 'MISSING_REVIEW')
    _need(canonical(selected[0]) == canonical(comment), 'REVIEW_CHANGED_DURING_VERIFICATION')
    for other in comments:
        _need(other['issue_url'] == f"{api}/issues/{config['issue_number']}", 'COMMENT_IDENTITY_MISMATCH')
        if other['id'] == config['comment_id'] or other['user']['id'] not in config['reviewer_ids']:
            continue
        body = other['body']
        _need(isinstance(body, str) and len(body.encode('utf-8')) <= 16384, 'INVALID_REVIEW_RECORD')
        if not body.lstrip().startswith('{'):
            continue
        candidate = _json(body)
        if candidate.get('kind') == KIND:
            _need(candidate['bindings']['candidate_id'] != expected['candidate_id'],
                  'DUPLICATE_CONFLICTING_OR_REVOKED_REVIEW')
    # A second read detects edits/deletions and Issue changes during pagination.
    _need(canonical(_get(client, comment_path)) == canonical(comment), 'REVIEW_CHANGED_DURING_VERIFICATION')
    _need(canonical(_get(client, issue_path)) == canonical(issue), 'REVIEW_CHANGED_DURING_VERIFICATION')
    return {'issue_id': config['issue_id'], 'issue_number': config['issue_number'],
            'comment_id': config['comment_id'], 'reviewer_id': comment['user']['id'],
            'decision': record['decision'], 'reviewed_at': record['reviewed_at'],
            'created_at': comment['created_at'], 'updated_at': comment['updated_at'],
            'comment_sha256': config['comment_sha256']}


def verify(artifact, result, transport, config_path=None, config_sha256=None, *, client):
    """Report diagnostics beside the existing gate. Never mutate its result."""
    now = datetime.now(timezone.utc)
    review = {'status': 'RESEARCH_REVIEW_UNVERIFIED', 'diagnostic_only': True,
              'affects_eligibility': False, 'production_authorization': 'NOT_AUTHORIZED',
              'verified_at': now.isoformat(), 'reason_codes': []}
    try:
        review['bindings'] = _bindings(artifact, result, transport)
        config = _configuration(config_path, config_sha256, now)
        review['configuration_sha256'] = config_sha256
        review['review'] = _live_review(client, config, review['bindings'])
        _need(datetime.now(timezone.utc) <= _time(config['valid_until']), 'STALE_REVIEW')
        review['status'] = 'RESEARCH_REVIEW_VERIFIED'
    except ReviewError as error:
        review['reason_codes'].append(str(error))
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError,
            RuntimeError, EOFError) as error:
        review['reason_codes'].append('INVALID_OR_UNREADABLE_REVIEW_EVIDENCE')
    finally:
        review['verified_at'] = datetime.now(timezone.utc).isoformat()
    return review
