"""Offline, mocked tests for read-only GitHub Baseline approval verification."""
import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src import github_baseline_approval as approval
from src.corpus_snapshot import digest, file_digest


class FakeGitHub:
    def __init__(self, *, repository_id=111, owner_type='User', owner_id=2,
                 branch_protected=True, reviews=None, review_files=None,
                 body_manifest=None, registry_override=None, rulesets=None):
        self.repository_id = repository_id
        self.owner_type = owner_type
        self.owner_id = owner_id
        self.branch_protected = branch_protected
        self.reviews = reviews
        self.review_files = review_files
        self.body_manifest = body_manifest
        self.registry_override = registry_override
        self.rulesets = [] if rulesets is None else rulesets
        self.fixture = None

    def bind(self, fixture):
        self.fixture = fixture
        return self

    def json(self, endpoint):
        path, _, query = endpoint.partition('?')
        if path == 'repos/acct/research-ci':
            return {'id': self.repository_id, 'full_name': 'acct/research-ci',
                    'default_branch': 'main',
                    'owner': {'id': self.owner_id, 'type': self.owner_type}}
        if path == 'repos/acct/research-ci/branches/main':
            return {'protected': self.branch_protected}
        if path == 'repos/acct/research-ci/branches/main/protection':
            return {
                'required_pull_request_reviews': {
                    'required_approving_review_count': 1,
                    'dismiss_stale_reviews': True,
                    'require_last_push_approval': True,
                    'bypass_pull_request_allowances': {'users': [], 'teams': [], 'apps': []},
                },
                'enforce_admins': {'enabled': True},
            }
        if path == 'repos/acct/research-ci/rulesets':
            return self.rulesets
        if path == 'repos/acct/research-ci/rules/branches/main':
            return [{'ruleset_id': item['id']} for item in self.rulesets]
        if path.startswith('repos/acct/research-ci/rulesets/'):
            wanted = int(path.rsplit('/', 1)[1])
            return next(item for item in self.rulesets if item['id'] == wanted)
        if path == 'repos/acct/research-ci/pulls/7':
            body = self.fixture['body']
            if self.body_manifest is not None:
                body = approval.REQUEST_MARKER + '\n' + json.dumps(self.body_manifest) + '\n-->'
            return {
                'number': 7, 'state': 'open', 'merged': False, 'draft': False, 'body': body,
                'user': {'id': 10},
                'head': {'sha': self.fixture['head_sha'],
                         'repo': {'id': self.repository_id}},
                'base': {'ref': 'main', 'sha': self.fixture['base_sha'],
                         'repo': {'id': self.repository_id}},
            }
        if path == 'repos/acct/research-ci/pulls/7/files':
            return self.review_files if self.review_files is not None else [
                {'filename': 'configs/trusted.json'}]
        if path == 'repos/acct/research-ci/pulls/7/reviews':
            return self.reviews if self.reviews is not None else [self.fixture['review']]
        if path == 'repos/acct/research-ci/contents/configs/trusted.json':
            from urllib.parse import parse_qs
            ref = parse_qs(query).get('ref', [''])[0]
            data = self.fixture['base_raw'] if ref in ('main', self.fixture['base_sha']) else self.fixture['proposed_raw']
            if self.registry_override is not None and ref not in ('main', self.fixture['base_sha']):
                data = self.registry_override
            return {'path': 'configs/trusted.json', 'type': 'file', 'encoding': 'base64',
                    # GitHub commonly wraps this field; exercise whitespace-tolerant decoding.
                    'content': base64.encodebytes(data).decode('ascii')}
        raise AssertionError('Unexpected GitHub API request: ' + endpoint)


class GitHubBaselineApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name) / 'project'
        self.configs = self.project / 'configs'
        self.configs.mkdir(parents=True)
        self.registry_path = self.configs / 'trusted.json'
        self.base_registry = {'schema_version': 2, 'baselines': {'existing': {'kept': True}}}
        self.registry_path.write_text(json.dumps(self.base_registry) + '\n', encoding='utf-8')
        self.base_raw = self.registry_path.read_bytes()
        self.base_sha256 = file_digest(self.registry_path)
        self.baseline = Path(self.temp.name) / 'baseline'
        self.baseline.mkdir()
        self.quality = {'status': 'QUALITY_REVIEW_REQUIRED',
                        'assessment': 'FROZEN_128_EVALUATED',
                        'policy': {'benchmark_sha256': 'b' * 64}}
        self._write_json(self.baseline / 'quality.json', self.quality)
        self._write_json(self.baseline / 'checksums.json', {
            'quality.json': file_digest(self.baseline / 'quality.json')})
        self.policy_path = self.configs / 'approval-policy.json'
        self.policy = {
            'schema_version': 1, 'enabled': True,
            'repository': 'acct/research-ci', 'repository_id': 111,
            'default_branch': 'main', 'registry_path': 'configs/trusted.json',
            'allow_personal_owner': True, 'trusted_approver_ids': [],
            'minimum_approving_reviews': 1,
        }
        self._write_json(self.policy_path, self.policy)
        self.policy_sha = file_digest(self.policy_path)
        self.head_sha = 'c' * 40
        self.base_commit = 'd' * 40
        self.ref = {
            'node_id': 'sha256-' + '1' * 64,
            'corpus_sha256': '2' * 64,
            'upstreams': {'SPHinXsys': '3' * 40, 'SPHinXsim': '4' * 40},
            'source_state': 'sha256-' + '5' * 64,
            'build_fingerprint': '6' * 64,
            'storage': {'kind': 'GITHUB_PRIVATE_RELEASE_ASSET', 'asset_id': 77},
            'parent_rows_storage': {'kind': 'GITHUB_PRIVATE_RELEASE_ASSET', 'asset_id': 78},
        }
        self.entry = {
            'build_policy_path': 'configs/build-policy.json',
            'build_policy_sha256': '7' * 64,
            'expected_reference_sha256': digest(self.ref),
            'reference': self.ref,
        }
        self.report = {
            'P4_1_verification': 'P4_1_VERIFIED', 'baseline_id': self.ref['node_id'],
            'candidate_id': 'candidate-c2', 'generation': 2,
            'retrieval_evaluation': 'FROZEN_128_EVALUATED',
        }
        proposed = json.loads(self.base_raw.decode('utf-8'))
        proposed['baselines']['candidate-c2'] = self.entry
        self.proposed_raw = (json.dumps(proposed, ensure_ascii=False, sort_keys=True,
                               indent=2, allow_nan=False) + '\n').encode('utf-8')
        self.proposed_sha256 = __import__('hashlib').sha256(self.proposed_raw).hexdigest()
        self.manifest = approval._proposal_manifest(
            'candidate-c2', self.entry, self.report, self.quality,
            'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR', self.base_sha256, self.proposed_sha256)
        body = approval.REQUEST_MARKER + '\n' + json.dumps(self.manifest, sort_keys=True) + '\n-->'
        self.review = {
            'id': 201, 'state': 'APPROVED', 'commit_id': self.head_sha,
            'submitted_at': '2026-11-13T10:00:00Z',
            'user': {'id': 2, 'type': 'User'},
        }
        self.client = FakeGitHub().bind({
            'body': body, 'head_sha': self.head_sha, 'base_sha': self.base_commit,
            'base_raw': self.base_raw, 'proposed_raw': self.proposed_raw,
            'review': self.review,
        })

    @staticmethod
    def _write_json(path, value):
        Path(path).write_text(json.dumps(value, sort_keys=True) + '\n', encoding='utf-8')

    def _verify(self, client=None, **kwargs):
        client = client or self.client
        values = {
            'policy_path': self.policy_path, 'policy_sha256': self.policy_sha,
            'pull_number': 7, 'expected_base_registry_sha256': self.base_sha256,
            'expected_proposed_registry_sha256': self.proposed_sha256,
            'q1_status': 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR', 'client': client,
            'now': __import__('datetime').datetime.fromisoformat('2026-11-13T11:00:00+00:00'),
        }
        values.update(kwargs)
        with patch.object(approval, '_validators', return_value=self.report):
            return approval.verify(
                self.project, self.baseline, self.registry_path, 'candidate-c2', self.entry,
                **values)

    def test_personal_repository_owner_approval_is_verified_without_mutation(self):
        result = self._verify()
        self.assertEqual(result['status'], 'GITHUB_APPROVAL_VERIFIED', result['reasons'])
        self.assertEqual(result['reviewers'][0]['reviewer_id'], 2)
        self.assertEqual(result['quality_status'], 'QUALITY_REVIEW_REQUIRED')
        self.assertEqual(result['q1_status'], 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
        self.assertEqual(result['q1_status_source'], 'EXPLICIT_REVIEW_BINDING_NOT_REQUALIFIED_HERE')
        self.assertEqual(result['quality_acceptance'], 'NOT_GRANTED_BY_THIS_APPROVAL')
        self.assertEqual(result['production_promotion'], 'NOT_AUTHORIZED')
        self.assertEqual(result['registration'], 'NOT_PERFORMED')
        self.assertEqual(self.registry_path.read_bytes(), self.base_raw)

    def test_designated_organization_approver_is_supported(self):
        self.policy.update(allow_personal_owner=False, trusted_approver_ids=[20])
        self._write_json(self.policy_path, self.policy)
        self.policy_sha = file_digest(self.policy_path)
        self.review.update(user={'id': 20, 'type': 'User'})
        self.client.owner_type = 'Organization'
        result = self._verify()
        self.assertEqual(result['status'], 'GITHUB_APPROVAL_VERIFIED', result['reasons'])
        self.assertEqual(result['reviewers'][0]['reviewer_id'], 20)

    def test_unauthorized_reviewer_blocks(self):
        self.review['user'] = {'id': 99, 'type': 'User'}
        result = self._verify()
        self.assertIn('MISSING_AUTHORIZED_APPROVAL', result['reasons'])

    def test_missing_approval_blocks(self):
        self.client.reviews = []
        result = self._verify()
        self.assertIn('MISSING_AUTHORIZED_APPROVAL', result['reasons'])

    def test_stale_review_for_older_commit_blocks(self):
        self.review['commit_id'] = 'e' * 40
        result = self._verify()
        self.assertIn('STALE_APPROVAL_FOR_OLDER_COMMIT', result['reasons'])

    def test_dismissed_review_does_not_count(self):
        self.review['state'] = 'DISMISSED'
        result = self._verify()
        self.assertIn('MISSING_AUTHORIZED_APPROVAL', result['reasons'])

    def test_self_approval_blocks(self):
        self.policy.update(allow_personal_owner=False, trusted_approver_ids=[10])
        self._write_json(self.policy_path, self.policy)
        self.policy_sha = file_digest(self.policy_path)
        self.review['user'] = {'id': 10, 'type': 'User'}
        result = self._verify()
        self.assertIn('MISSING_AUTHORIZED_APPROVAL', result['reasons'])

    def test_candidate_or_manifest_mismatch_blocks(self):
        bad = dict(self.manifest)
        bad['candidate_id'] = 'candidate-other'
        self.client.body_manifest = bad
        result = self._verify()
        self.assertIn('PULL_REQUEST_CANDIDATE_BINDING_MISMATCH', result['reasons'])

    def test_registry_content_mismatch_blocks(self):
        self.client.registry_override = b'{"schema_version":2,"baselines":{}}\n'
        result = self._verify()
        self.assertIn('PULL_PROPOSED_REGISTRY_MISMATCH', result['reasons'])

    def test_missing_effective_branch_protection_blocks(self):
        self.client.branch_protected = False
        result = self._verify()
        self.assertIn('DEFAULT_BRANCH_NOT_PROTECTED', result['reasons'])

    def test_repository_identity_mismatch_blocks(self):
        self.client.repository_id = 999
        result = self._verify()
        self.assertIn('REPOSITORY_IDENTITY_MISMATCH', result['reasons'])

    def test_ruleset_bypass_actor_blocks(self):
        self.client.rulesets = [{
            'id': 88,
            'enforcement': 'active', 'conditions': {'ref_name': {'include': ['~DEFAULT_BRANCH'], 'exclude': []}},
            'bypass_actors': [{'actor_id': 1, 'actor_type': 'RepositoryRole'}],
        }]
        result = self._verify()
        self.assertIn('EFFECTIVE_RULESET_HAS_BYPASS_ACTORS', result['reasons'])

    def test_unreadable_ruleset_bypass_policy_blocks(self):
        self.client.rulesets = [{
            'id': 88,
            'enforcement': 'active', 'conditions': {'ref_name': {'include': ['~DEFAULT_BRANCH'], 'exclude': []}},
        }]
        result = self._verify()
        self.assertIn('UNVERIFIABLE_RULESET_BYPASS_POLICY', result['reasons'])

    def test_pull_request_must_change_only_trusted_registry(self):
        self.client.review_files = [{'filename': 'configs/trusted.json'}, {'filename': 'README.md'}]
        result = self._verify()
        self.assertIn('PULL_REQUEST_CHANGES_OUTSIDE_REGISTRY', result['reasons'])

    def test_missing_or_unpinned_policy_blocks(self):
        result = self._verify(policy_sha256='0' * 64)
        self.assertIn('APPROVAL_POLICY_SHA256_MISMATCH', result['reasons'])

    def test_unsealed_quality_status_blocks(self):
        altered = dict(self.quality, status='QUALITY_ACCEPTED')
        self._write_json(self.baseline / 'quality.json', altered)
        result = self._verify()
        self.assertIn('P4_1_QUALITY_EVIDENCE_NOT_SEALED', result['reasons'])

    def test_pull_request_must_remain_open_and_unmerged(self):
        original = self.client.json

        def closed(endpoint):
            value = original(endpoint)
            if endpoint.split('?', 1)[0] == 'repos/acct/research-ci/pulls/7':
                value['state'] = 'closed'
            return value
        self.client.json = closed
        result = self._verify()
        self.assertIn('PULL_REQUEST_NOT_OPEN_FOR_REVIEW', result['reasons'])

    def test_approval_dismissed_during_verification_blocks(self):
        original = self.client.json
        review_reads = 0

        def changing_reviews(endpoint):
            nonlocal review_reads
            if endpoint.split('?', 1)[0] == 'repos/acct/research-ci/pulls/7/reviews':
                review_reads += 1
                if review_reads > 1:
                    dismissed = dict(self.review, state='DISMISSED')
                    return [dismissed]
            return original(endpoint)

        self.client.json = changing_reviews
        result = self._verify()
        self.assertIn('MISSING_AUTHORIZED_APPROVAL', result['reasons'])
        self.assertEqual(review_reads, 2)

    def test_duplicate_json_binding_fields_are_rejected(self):
        with self.assertRaisesRegex(approval.ApprovalError, 'INVALID_REGISTRATION_REQUEST_BLOCK'):
            approval._request_body(
                approval.REQUEST_MARKER + '\n{"candidate_id":"one","candidate_id":"two"}\n-->')


if __name__ == '__main__':
    unittest.main()
