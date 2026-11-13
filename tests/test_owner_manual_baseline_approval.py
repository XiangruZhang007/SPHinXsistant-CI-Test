"""Offline tests for the read-only Owner Manual Approval adapter."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import base64

from src import owner_manual_baseline_approval as owner_approval
from src.corpus_snapshot import digest, file_digest


class FakeGitHub:
    def __init__(self):
        self.repository = {
            'id': 111, 'full_name': 'acct/research-ci', 'default_branch': 'main',
            'owner': {'id': 2, 'type': 'User', 'login': 'acct'},
        }
        self.run = {
            'id': 9001, 'event': 'workflow_dispatch', 'status': 'in_progress',
            'run_attempt': 1, 'head_branch': 'main', 'head_sha': 'c' * 40,
            'repository': {'id': 111, 'full_name': 'acct/research-ci'},
            'actor': {'id': 2, 'login': 'acct', 'type': 'User'},
            'triggering_actor': {'id': 2, 'login': 'acct', 'type': 'User'},
            'workflow_id': 88, 'created_at': '2026-11-13T10:00:00Z',
        }
        self.workflow = {'id': 88, 'path': '.github/workflows/approve_baseline.yml'}

    def json(self, endpoint):
        if endpoint == 'repos/acct/research-ci':
            return self.repository
        if endpoint == 'repos/acct/research-ci/actions/runs/9001':
            return self.run
        if endpoint == 'repos/acct/research-ci/actions/workflows/88':
            return self.workflow
        if endpoint == 'repos/acct/research-ci/git/ref/heads/main':
            return {'ref': 'refs/heads/main', 'object': {'sha': 'c' * 40}}
        if endpoint == 'repos/acct/research-ci/contents/configs/trusted.json?ref=' + 'c' * 40:
            raw = self.registry_raw
            return {'path': 'configs/trusted.json', 'type': 'file',
                    'encoding': 'base64', 'content': base64.encodebytes(raw).decode('ascii')}
        raise AssertionError(f'unexpected API endpoint: {endpoint}')


class OwnerManualBaselineApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / 'project'
        self.configs = self.project / 'configs'
        self.configs.mkdir(parents=True)
        self.policy_path = self.configs / 'owner-policy.json'
        self.policy = {
            'schema_version': 1, 'enabled': True,
            'repository': 'acct/research-ci', 'repository_id': 111,
            'default_branch': 'main',
            'workflow_path': '.github/workflows/approve_baseline.yml',
            'registry_path': 'configs/trusted.json',
            'allow_repository_owner': True, 'authorized_approver_ids': [],
        }
        self._write_json(self.policy_path, self.policy)
        self.policy_sha = file_digest(self.policy_path)
        self.registry = self.configs / 'trusted.json'
        self._write_json(self.registry, {'schema_version': 2, 'baselines': {}})
        self.registry_before = self.registry.read_bytes()
        self.client = FakeGitHub()
        self.client.registry_raw = self.registry_before
        self.baseline = self.root / 'baseline'
        self.baseline.mkdir()
        self.ref = {
            'package_format': 'schema2-research-baseline',
            'node_id': 'sha256-' + '1' * 64,
            'corpus_sha256': '2' * 64,
            'upstreams': {'SPHinXsys': '3' * 40, 'SPHinXsim': '4' * 40},
            'source_state': 'sha256-' + '5' * 64,
            'build_fingerprint': '6' * 64,
            'storage': {'kind': 'GITHUB_PRIVATE_RELEASE_ASSET', 'release_id': 70,
                        'asset_id': 71, 'asset_sha256': '7' * 64},
            'parent_rows_storage': {'kind': 'GITHUB_PRIVATE_RELEASE_ASSET',
                                    'release_id': 70, 'asset_id': 72,
                                    'asset_sha256': '8' * 64},
        }
        self.entry = {
            'build_policy_path': 'configs/build-policy.json',
            'build_policy_sha256': '9' * 64,
            'expected_reference_sha256': digest(self.ref),
            'reference': self.ref,
        }
        self.report = {
            'P4_1_verification': 'P4_1_VERIFIED',
            'baseline_id': self.ref['node_id'],
            'candidate_id': 'sha256-' + 'a' * 64,
            'generation': 2,
            'bindings': {
                'corpus_sha256': self.ref['corpus_sha256'],
                'upstreams': self.ref['upstreams'],
            },
            'quality_status': 'QUALITY_REVIEW_REQUIRED',
            'q1_status': 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR',
            'blocking_reasons': ['INDEPENDENT_REGISTRATION_AUTHORITY_NOT_CONFIGURED'],
        }
        self.context = {
            'run_id': 9001, 'run_attempt': 1, 'actor_id': 2,
            'repository': 'acct/research-ci', 'repository_id': 111,
            'head_sha': 'c' * 40, 'ref': 'refs/heads/main',
            'dispatch_inputs': self._dispatch_inputs(),
        }

    def _dispatch_inputs(self):
        return {
            'registry_key': 'candidate-c2',
            'baseline_id': self.ref['node_id'],
            'candidate_id': 'sha256-' + 'a' * 64,
            'corpus_sha256': self.ref['corpus_sha256'],
            'registry_entry_sha256': digest(self.entry),
        }

    @staticmethod
    def _write_json(path, value):
        Path(path).write_text(json.dumps(value, sort_keys=True) + '\n', encoding='utf-8')

    def _verify(self, **overrides):
        values = {
            'policy_path': self.policy_path, 'policy_sha256': self.policy_sha,
            'expected_reference_sha256': digest(self.ref),
            'expected_build_policy_sha256': self.entry['build_policy_sha256'],
            'q1_status': 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR',
            'context': self.context, 'client': self.client,
        }
        values.update(overrides)
        with patch('src.trusted_baseline_registration.prepare', return_value=self.report):
            return owner_approval.verify(
                self.project, self.baseline, self.registry, 'candidate-c2', self.entry,
                **values)

    def test_owner_manual_approval_is_candidate_bound_and_read_only(self):
        result = self._verify()
        self.assertEqual(result['status'], 'OWNER_APPROVAL_VERIFIED', result['reasons'])
        self.assertEqual(result['decision'], 'OWNER_APPROVAL_VERIFIED')
        self.assertEqual(result['workflow_run']['actor_id'], 2)
        self.assertEqual(result['review_subject']['baseline_id'], self.ref['node_id'])
        self.assertEqual(result['review_subject']['candidate_id'], 'sha256-' + 'a' * 64)
        self.assertEqual(result['review_subject']['corpus_sha256'], self.ref['corpus_sha256'])
        self.assertEqual(result['review_subject']['release_identity'], self.ref['storage'])
        self.assertEqual(result['review_subject']['source_revisions'], self.ref['upstreams'])
        self.assertEqual(result['review_subject']['quality_status'], 'QUALITY_REVIEW_REQUIRED')
        self.assertEqual(result['review_subject']['q1_status'], 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
        self.assertEqual(result['registration'], 'NOT_PERFORMED')
        self.assertFalse(result['registry_modified'])
        self.assertEqual(result['production_promotion'], 'NOT_AUTHORIZED')
        self.assertEqual(self.registry.read_bytes(), self.registry_before)

    def test_designated_approver_is_supported_for_organization_repository(self):
        self.policy.update(allow_repository_owner=False, authorized_approver_ids=[20])
        self._write_json(self.policy_path, self.policy)
        self.policy_sha = file_digest(self.policy_path)
        self.client.repository['owner'] = {'id': 50, 'type': 'Organization', 'login': 'acct'}
        self.client.run['actor'] = {'id': 20, 'login': 'reviewer', 'type': 'User'}
        self.client.run['triggering_actor'] = self.client.run['actor']
        self.context['actor_id'] = 20
        result = self._verify()
        self.assertEqual(result['status'], 'OWNER_APPROVAL_VERIFIED', result['reasons'])
        self.assertEqual(result['workflow_run']['actor_id'], 20)

    def test_unauthorized_actor_blocks(self):
        self.client.run['actor'] = {'id': 99, 'login': 'other', 'type': 'User'}
        self.client.run['triggering_actor'] = self.client.run['actor']
        self.context['actor_id'] = 99
        result = self._verify()
        self.assertIn('UNAUTHORIZED_WORKFLOW_ACTOR', result['reasons'])

    def test_actor_context_mismatch_blocks(self):
        self.context['actor_id'] = 77
        result = self._verify()
        self.assertIn('GITHUB_WORKFLOW_ACTOR_MISMATCH', result['reasons'])

    def test_repository_identity_mismatch_blocks(self):
        self.client.repository['id'] = 999
        result = self._verify()
        self.assertIn('GITHUB_REPOSITORY_IDENTITY_MISMATCH', result['reasons'])

    def test_wrong_run_event_commit_branch_or_attempt_blocks(self):
        cases = [
            ('event', 'push', 'GITHUB_WORKFLOW_RUN_BINDING_MISMATCH'),
            ('head_sha', 'd' * 40, 'GITHUB_WORKFLOW_RUN_BINDING_MISMATCH'),
            ('head_branch', 'feature', 'GITHUB_WORKFLOW_RUN_BINDING_MISMATCH'),
            ('run_attempt', 2, 'GITHUB_WORKFLOW_RUN_BINDING_MISMATCH'),
        ]
        for field, value, reason in cases:
            with self.subTest(field=field):
                original = self.client.run[field]
                self.client.run[field] = value
                result = self._verify()
                self.assertIn(reason, result['reasons'])
                self.client.run[field] = original

    def test_wrong_workflow_path_blocks(self):
        self.client.workflow['path'] = '.github/workflows/other.yml'
        result = self._verify()
        self.assertIn('GITHUB_WORKFLOW_PATH_MISMATCH', result['reasons'])

    def test_branch_moving_after_dispatch_blocks_as_stale(self):
        original = self.client.json
        def changed_branch(endpoint):
            if endpoint == 'repos/acct/research-ci/git/ref/heads/main':
                return {'ref': 'refs/heads/main', 'object': {'sha': 'd' * 40}}
            return original(endpoint)
        self.client.json = changed_branch
        result = self._verify()
        self.assertIn('STALE_WORKFLOW_COMMIT', result['reasons'])

    def test_remote_registry_mismatch_blocks(self):
        self.client.registry_raw = b'{"schema_version":2,"baselines":{}}\n'
        result = self._verify()
        self.assertIn('REMOTE_REGISTRY_CHECKOUT_MISMATCH', result['reasons'])

    def test_dispatch_inputs_must_match_exact_candidate_subject(self):
        self.context['dispatch_inputs']['candidate_id'] = 'sha256-' + 'b' * 64
        result = self._verify()
        self.assertIn('WORKFLOW_DISPATCH_SUBJECT_MISMATCH', result['reasons'])

    def test_missing_or_invalid_p4_1_qualification_blocks(self):
        from src.trusted_baseline_registration import RegistrationError
        with patch('src.trusted_baseline_registration.prepare',
                   side_effect=RegistrationError('P4_1_BASELINE_QUALIFICATION_REQUIRED')):
            result = owner_approval.verify(
                self.project, self.baseline, self.registry, 'candidate-c2', self.entry,
                policy_path=self.policy_path, policy_sha256=self.policy_sha,
                expected_reference_sha256=digest(self.ref),
                expected_build_policy_sha256=self.entry['build_policy_sha256'],
                q1_status='Q1_NOT_QUALIFIED_FOR_VERSION_PAIR',
                context=self.context, client=self.client)
        self.assertIn('P4_1_BASELINE_QUALIFICATION_REQUIRED', result['reasons'])

    def test_quality_and_q1_status_are_not_upgraded_or_changed(self):
        self.report['quality_status'] = 'QUALITY_REVIEW_REQUIRED'
        result = self._verify()
        self.assertEqual(result['status'], 'OWNER_APPROVAL_VERIFIED', result['reasons'])
        self.assertEqual(result['review_subject']['quality_status'], 'QUALITY_REVIEW_REQUIRED')
        self.assertEqual(result['review_subject']['q1_status'], 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
        result = self._verify(q1_status='QUALIFIED')
        self.assertIn('Q1_STATUS_MISMATCH', result['reasons'])

    def test_duplicate_baseline_and_conflicting_registry_key_block(self):
        self._write_json(self.registry, {'schema_version': 2, 'baselines': {
            'old': {'reference': {'node_id': self.ref['node_id']}}}})
        result = self._verify()
        self.assertIn('BASELINE_ALREADY_REGISTERED', result['reasons'])
        self._write_json(self.registry, {'schema_version': 2,
                                         'baselines': {'candidate-c2': {}}})
        result = self._verify()
        self.assertIn('REGISTRY_KEY_ALREADY_EXISTS', result['reasons'])

    def test_candidate_with_same_sealed_source_and_corpus_binding_blocks(self):
        existing_ref = dict(self.ref)
        existing_ref['node_id'] = 'sha256-' + 'f' * 64
        self._write_json(self.registry, {'schema_version': 2, 'baselines': {
            'previous-key': {'reference': existing_ref}}})
        result = self._verify()
        self.assertIn('CANDIDATE_BINDING_ALREADY_REGISTERED', result['reasons'])

    def test_invalid_policy_pin_and_absent_owner_authority_fail_closed(self):
        result = self._verify(policy_sha256='0' * 64)
        self.assertIn('OWNER_APPROVAL_POLICY_SHA256_MISMATCH', result['reasons'])
        self.policy.update(allow_repository_owner=False, authorized_approver_ids=[])
        self._write_json(self.policy_path, self.policy)
        self.policy_sha = file_digest(self.policy_path)
        result = self._verify()
        self.assertIn('NO_OWNER_APPROVAL_AUTHORITY_CONFIGURED', result['reasons'])

    def test_context_is_loaded_from_github_event_not_a_cli_actor_argument(self):
        event_path = self.root / 'event.json'
        event_path.write_text(json.dumps({'inputs': self.context['dispatch_inputs']}),
                              encoding='utf-8')
        env = {
            'GITHUB_RUN_ID': '9001', 'GITHUB_RUN_ATTEMPT': '1',
            'GITHUB_ACTOR_ID': '2', 'GITHUB_REPOSITORY_ID': '111',
            'GITHUB_REPOSITORY': 'acct/research-ci', 'GITHUB_SHA': 'c' * 40,
            'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
            'GITHUB_EVENT_PATH': str(event_path),
        }
        context = owner_approval.context_from_environment(env)
        self.assertEqual(context['actor_id'], 2)
        self.assertEqual(context['dispatch_inputs'], self.context['dispatch_inputs'])
        env['GITHUB_EVENT_NAME'] = 'push'
        with self.assertRaisesRegex(owner_approval.OwnerApprovalError,
                                    'GITHUB_DISPATCH_EVENT_UNAVAILABLE'):
            owner_approval.context_from_environment(env)


if __name__ == '__main__':
    unittest.main()
