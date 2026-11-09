"""Mocked live Issue research reviews never authorize a real update."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
from contextlib import redirect_stdout
import unittest
from unittest.mock import patch

from src import github_artifact_delivery as delivery
from src import corpus_update_integration as integration
from src import research_review as review
import test_github_artifact_delivery as delivery_fixtures


class ResearchReviewTests(unittest.TestCase):
    def setUp(self):
        # Reuse the sealed miniature run and strict no-real-network fixture.
        self.base = delivery_fixtures.DeliveryTests()
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.root = self.base.root
        self.config_root = self.root / 'configs'
        self.config_root.mkdir()
        context = patch.object(review, 'CONFIG_ROOT', self.config_root)
        context.start()
        self.addCleanup(context.stop)
        self.archive = self.root / 'original.zip'
        self.archive.write_bytes(self.base.raw)
        self.result = integration.run(self.archive)
        self.client = delivery.GitHub()
        self.transport = delivery._resolve(self.client, 123, 2, 'ci-v2-research-123-2', None)
        self.expected = review._bindings(self.archive, self.result, self.transport)
        self.api = f'https://api.github.com/repos/{delivery.REPOSITORY}'
        self.issue = {'id': 77, 'number': 7, 'url': self.api + '/issues/7',
                      'repository_url': self.api, 'comments': 1, 'updated_at': '2026-11-01T12:30:00Z'}
        now = datetime.now(timezone.utc).replace(microsecond=0)
        self.created = (now - timedelta(hours=1)).isoformat().replace('+00:00', 'Z')
        self.record = {'schema_version': 1, 'kind': review.KIND, 'scope': 'RESEARCH_DIAGNOSTIC_ONLY',
                       'bindings': deepcopy(self.expected), 'decision': 'APPROVE_RESEARCH_REVIEW',
                       'reviewer_id': 42, 'reviewed_at': self.created}
        self.comment = {'id': 88, 'url': self.api + '/issues/comments/88',
                        'issue_url': self.issue['url'], 'user': {'id': 42, 'type': 'User', 'login': 'fixture'},
                        'created_at': self.created, 'updated_at': self.created, 'body': ''}
        self.comments = [self.comment]
        self.config = {'schema_version': 1, 'repository': delivery.REPOSITORY, 'repository_id': 10,
                       'issue_number': 7, 'issue_id': 77, 'comment_id': 88, 'reviewer_ids': [42],
                       'comment_sha256': '', 'created_at': self.created, 'updated_at': self.created,
                       'valid_until': (now + timedelta(hours=1)).isoformat().replace('+00:00', 'Z')}
        self.path = self.config_root / 'review.json'
        self.repin()
        context = patch.object(delivery.GitHub, 'json', side_effect=self.response)
        self.mock_api = context.start()
        self.addCleanup(context.stop)

    def repin(self):
        self.comment['body'] = json.dumps(self.record, sort_keys=True)
        self.config['comment_sha256'] = hashlib.sha256(self.comment['body'].encode()).hexdigest()
        self.save_config()

    def save_config(self):
        self.path.write_text(json.dumps(self.config))
        self.config_sha = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def response(self, endpoint):
        prefix = f'repos/{delivery.REPOSITORY}'
        if endpoint == prefix:
            return {'id': 10, 'full_name': delivery.REPOSITORY}
        if endpoint == prefix + '/issues/7':
            return deepcopy(self.issue)
        if endpoint == prefix + '/issues/comments/88':
            return deepcopy(self.comment)
        if endpoint.startswith(prefix + '/issues/7/comments?per_page=100&page='):
            page = int(endpoint.rsplit('=', 1)[1])
            return deepcopy(self.comments[(page-1)*100:page*100])
        return self.base.response(endpoint)

    def verify(self, **overrides):
        args = {'artifact': self.archive, 'result': self.result, 'transport': self.transport,
                'config_path': self.path, 'config_sha256': self.config_sha, 'client': self.client}
        args.update(overrides)
        before = deepcopy(self.result)
        result = review.verify(**args)
        self.assertEqual(self.result, before)
        self.assertTrue(result['diagnostic_only'])
        self.assertFalse(result['affects_eligibility'])
        self.assertEqual(result['production_authorization'], 'NOT_AUTHORIZED')
        self.assertNotIn('fixture', json.dumps(result))  # No comment bodies/logins.
        return result

    def unverified(self, code=None, **overrides):
        result = self.verify(**overrides)
        self.assertEqual(result['status'], 'RESEARCH_REVIEW_UNVERIFIED')
        if code:
            self.assertIn(code, result['reason_codes'])
        return result

    def test_exact_review_verified_with_p8_still_blocked(self):
        result = self.verify()
        self.assertEqual(result['status'], 'RESEARCH_REVIEW_VERIFIED')
        self.assertEqual(result['review']['reviewer_id'], 42)
        self.assertEqual(result['bindings'], self.expected)
        self.assertEqual(self.result['decision'], 'BLOCKED')
        self.assertEqual(self.result['gate']['gate_mode'], 'BLOCKING_ONLY')
        self.assertEqual(self.result['activation'], 'DENIED')
        self.assertEqual(self.result['gradio_reinitialization'], 'NOT_ATTEMPTED')

    def test_each_internal_binding_mismatch_rejected(self):
        cases = [('candidate_id',), ('corpus_sha256',), ('build_fingerprint',), ('benchmark_sha256',),
                 ('upstreams', 'SPHinXsys'), ('upstreams', 'SPHinXsim'),
                 ('quality', 'quality_report_sha256'), ('quality', 'raw_results_sha256'),
                 ('quality', 'policy_sha256')]
        for keys in cases:
            with self.subTest(keys=keys):
                self.record['bindings'] = deepcopy(self.expected)
                node = self.record['bindings']
                for key in keys[:-1]:
                    node = node[key]
                node[keys[-1]] = 'wrong'
                self.repin()
                self.unverified('REVIEW_BINDING_MISMATCH')

    def test_each_transport_binding_mismatch_rejected(self):
        for key in self.expected['transport']:
            with self.subTest(key=key):
                self.record['bindings'] = deepcopy(self.expected)
                self.record['bindings']['transport'][key] = 'wrong'
                self.repin()
                self.unverified('REVIEW_BINDING_MISMATCH')

    def test_authority_missing_or_plain_local_approved_json_rejected(self):
        result = self.unverified('TRUST_CONFIGURATION_MISSING', config_path=None, config_sha256=None)
        self.assertEqual(result['bindings'], self.expected)
        self.mock_api.assert_not_called()
        self.config['reviewer_ids'] = []
        self.save_config()
        self.unverified('REVIEWER_AUTHORITY_MISSING')
        self.path.write_text('{"APPROVED":true}')
        self.config_sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.unverified('INVALID_TRUST_CONFIGURATION')

    def test_configuration_pin_required_and_config_outside_candidate(self):
        self.unverified('TRUST_CONFIGURATION_MISSING', config_sha256=None)
        self.unverified('TRUST_CONFIGURATION_SHA256_MISMATCH', config_sha256='0'*64)
        outside = self.root / 'run' / 'review.json'
        outside.write_bytes(self.path.read_bytes())
        self.unverified('UNSAFE_TRUST_CONFIGURATION', config_path=outside)
        link = self.config_root / 'link.json'
        link.symlink_to(self.path)
        self.unverified('UNSAFE_TRUST_CONFIGURATION', config_path=link)
        self.mock_api.assert_not_called()

    def test_nonallowlisted_repository_rejected_before_api(self):
        self.config['repository'] = 'another-owner/another-repository'
        self.save_config()
        self.unverified('INVALID_TRUST_CONFIGURATION')
        self.mock_api.assert_not_called()

    def test_forged_reviewer_in_body_cannot_replace_api_author(self):
        self.comment['user']['id'] = 43
        self.unverified('UNAUTHORIZED_REVIEWER')
        self.comment['user']['id'] = 42
        self.record['reviewer_id'] = 43
        self.repin()
        self.unverified('FORGED_REVIEWER')
        self.record['reviewer_id'] = True
        self.repin()
        self.unverified('FORGED_REVIEWER')

    def test_missing_deleted_or_unavailable_review_no_cache_fallback(self):
        with patch.object(delivery.GitHub, 'json', side_effect=OSError('SECRET')):
            result = self.unverified('GITHUB_UNAVAILABLE')
        self.assertNotIn('SECRET', json.dumps(result))
        self.comments = []
        self.issue['comments'] = 0
        self.unverified('MISSING_OR_EXCESSIVE_REVIEWS')
        self.issue['comments'] = 1
        self.unverified('INCOMPLETE_OR_CHANGED_REVIEW_LIST')

    def test_modified_body_or_time_rejected(self):
        self.comment['body'] += ' '
        self.unverified('MODIFIED_REVIEW')
        self.repin()
        self.comment['updated_at'] = '2099-01-01T00:00:00Z'
        self.unverified('MODIFIED_REVIEW')
        self.config['updated_at'] = self.comment['updated_at']
        self.save_config()
        self.unverified('MODIFIED_REVIEW')

    def test_revoked_and_rejected_review_rejected(self):
        for decision in ('REVOKE', 'REJECT'):
            self.record['decision'] = decision
            self.repin()
            self.unverified('REVIEW_' + decision)

    def test_stale_or_future_dated_review_rejected(self):
        self.config['valid_until'] = '2000-01-01T00:00:00Z'
        self.save_config()
        self.unverified('STALE_REVIEW')
        self.config['valid_until'] = '2099-01-01T00:00:00Z'
        self.save_config()
        self.record['reviewed_at'] = '2098-01-01T00:00:00Z'
        self.repin()
        self.unverified('INVALID_REVIEW_TIME')

    def test_review_expiring_during_api_verification_rejected(self):
        now = datetime.now(timezone.utc)
        with patch.object(review, 'datetime', wraps=datetime) as clock:
            clock.now.side_effect = [now, now + timedelta(hours=2), now + timedelta(hours=2)]
            self.unverified('STALE_REVIEW')

    def test_duplicate_conflicting_and_revocation_comments_rejected(self):
        other = deepcopy(self.comment)
        other['id'] = 89
        other['url'] = self.api + '/issues/comments/89'
        self.comments.append(other)
        self.issue['comments'] = 2
        for decision in ('APPROVE_RESEARCH_REVIEW', 'REJECT', 'REVOKE'):
            with self.subTest(decision=decision):
                other_record = deepcopy(self.record)
                other_record['decision'] = decision
                other['body'] = json.dumps(other_record)
                self.unverified('DUPLICATE_CONFLICTING_OR_REVOKED_REVIEW')
        other['id'] = 88
        self.unverified('DUPLICATE_REVIEW')

    def test_wrong_issue_or_comment_identity_rejected(self):
        self.issue['id'] = 78
        self.unverified('ISSUE_IDENTITY_MISMATCH')
        self.issue['id'] = 77
        self.comment['issue_url'] = self.api + '/issues/8'
        self.unverified('COMMENT_IDENTITY_MISMATCH')

    def test_json_duplicate_keys_or_unsupported_scope_rejected(self):
        self.comment['body'] = self.comment['body'][:-1] + ',"schema_version":1}'
        self.config['comment_sha256'] = hashlib.sha256(self.comment['body'].encode()).hexdigest()
        self.save_config()
        self.unverified('INVALID_OR_UNREADABLE_REVIEW_EVIDENCE')
        self.record['scope'] = 'PRODUCTION_APPROVED'
        self.repin()
        self.unverified('INVALID_REVIEW_RECORD')

    def test_internal_or_transport_evidence_unverified_rejected(self):
        self.result['artifact_integrity'] = 'FAIL'
        self.unverified('INTERNAL_EVIDENCE_UNVERIFIED')
        self.result['artifact_integrity'] = 'PASS'
        self.transport['expected_sha256'] = '0'*64
        self.unverified('TRANSPORT_SHA256_MISMATCH')

    def test_review_mutation_during_verification_rejected(self):
        calls = 0

        def mutate(endpoint):
            nonlocal calls
            if endpoint.endswith('/issues/comments/88'):
                calls += 1
                if calls == 2:
                    self.comment['body'] += ' '
            return self.response(endpoint)

        with patch.object(delivery.GitHub, 'json', side_effect=mutate):
            self.unverified('REVIEW_CHANGED_DURING_VERIFICATION')

    def test_full_delivery_adds_diagnostic_without_changing_gate(self):
        result = self.base.execute(research_review_config=self.path, research_review_config_sha256=self.config_sha)
        self.assertEqual(result['research_review']['status'], 'RESEARCH_REVIEW_VERIFIED')
        self.assertEqual(result['p8_decision'], 'BLOCKED')
        self.assertTrue(result['selection_unchanged'])
        saved = json.loads((Path(result['evidence_directory']) / 'integration-result.json').read_text())
        self.assertEqual(saved['gate'], self.result['gate'])
        self.assertEqual(saved['activation'], 'DENIED')
        self.assertEqual(saved['gradio_reinitialization'], 'NOT_ATTEMPTED')
        self.assertNotIn(self.comment['body'], (Path(result['evidence_directory']) / 'research-review.json').read_text())

    def test_no_config_default_preserves_delivery_and_reports_unverified(self):
        result = self.base.execute()
        self.assertEqual(result['delivery'], 'VERIFIED')
        self.assertEqual(result['research_review']['status'], 'RESEARCH_REVIEW_UNVERIFIED')
        self.assertEqual(result['research_review']['reason_codes'], ['TRUST_CONFIGURATION_MISSING'])
        self.assertFalse(any('/issues/' in call.args[0] for call in self.mock_api.call_args_list))

    def test_cli_requires_paired_configuration(self):
        for extra in (['--research-review-config', str(self.path)],
                      ['--research-review-config-sha256', self.config_sha]):
            output = io.StringIO()
            with redirect_stdout(output):
                code = delivery.main(['--repository', delivery.REPOSITORY, '--run-id', '123',
                                      '--attempt', '2', '--artifact-name', 'ci-v2-research-123-2'] + extra)
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output.getvalue())['decision'], 'BLOCKED')
            self.assertIn('supplied together', json.loads(output.getvalue())['error'])
        self.mock_api.assert_not_called()

    def test_issue_pagination_checks_later_conflicts(self):
        others = [dict(deepcopy(self.comment), id=i+1000, user={'id': 999, 'type': 'User'}) for i in range(99)]
        other = dict(deepcopy(self.comment), id=9999)
        self.comments = [self.comment] + others + [other]
        self.issue['comments'] = len(self.comments)
        self.unverified('DUPLICATE_CONFLICTING_OR_REVOKED_REVIEW')
        self.assertTrue(any('page=2' in call.args[0] for call in self.mock_api.call_args_list))


class ReviewEndpointTests(unittest.TestCase):
    def test_adapter_allows_only_read_only_personal_issue_routes(self):
        with patch.object(delivery.shutil, 'which', return_value='/mock/gh'):
            client = delivery.GitHub()
        with patch.object(delivery.subprocess, 'run') as run:
            run.return_value.returncode = 0
            run.return_value.stdout = b'{}'
            base = f'repos/{delivery.REPOSITORY}'
            for endpoint in (base, base + '/issues/7', base + '/issues/comments/88',
                             base + '/issues/7/comments?per_page=100&page=2'):
                client.json(endpoint)
                self.assertIn('GET', run.call_args.args[0])
            run.reset_mock()
            for endpoint in ('repos/another-owner/another-repository/issues/7', base + '/issues',
                             base + '/issues/7/comments', base + '/issues/../secrets', base + '/pulls/7'):
                with self.assertRaises(delivery.DeliveryError):
                    client.json(endpoint)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
