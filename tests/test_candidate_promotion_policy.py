"""Synthetic authority providers are test-only; no Candidate is authorized here."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

from src import candidate_promotion_policy as promotion
from src import corpus_update_integration as integration
from src import update_eligibility_gate as gate
from src.corpus_snapshot import digest
from src.corpus_switching_test_session import TestWorkspace
import test_update_eligibility_gate as fixtures


class PurePolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = deepcopy(promotion.POLICY)
        self.policy.update(name='SYNTHETIC_TEST_POLICY', quality_authority='TEST_ONLY', release_authority='TEST_ONLY',
                           adjudicable_quality_statuses=['QUALITY_REVIEW_REQUIRED'],
                           adjudicable_finding_kinds=['FROZEN_STRICT_FAILURE', 'REGRESSION'])
        self.facts = {
            'bindings': {'candidate_id': 'sha256-' + digest({'synthetic': 'A'}),
                         'corpus_sha256': digest('synthetic-corpus'), 'build_fingerprint': digest('synthetic-build'),
                         'benchmark_sha256': digest('synthetic-benchmark'), 'parent_id': 'sha256-' + digest('parent'),
                         'quality_report_sha256': digest('report'), 'raw_results_sha256': digest('results'),
                         'quality_policy_sha256': digest('frozen-policy'),
                         'upstreams': {'SPHinXsys': 'a'*40, 'SPHinXsim': 'b'*40}},
            'integrity_status': 'VERIFIED', 'recorded_quality_status': 'QUALITY_REVIEW_REQUIRED',
            'quality_accepted_flag': False, 'explicit_prohibitions': [],
            'checked_at': '2026-11-09T00:00:00Z',
            'findings': [
                {'key': 'candidate/combined/DOC-Q27/hit_at_5', 'kind': 'FROZEN_STRICT_FAILURE'},
                {'key': 'immediate_parent/combined/DOC-Q27/hit_at_10', 'kind': 'REGRESSION'},
            ],
        }

    def authority(self, purpose, **changes):
        """An explicitly assumed synthetic trusted source, never shipped to runtime."""
        def verify(expected):
            record = {
                'status': 'VERIFIED', 'scope': purpose,
                'decision': 'ACCEPT_QUALITY_FINDINGS' if purpose == 'QUALITY_ADJUDICATION' else 'AUTHORIZE_CORPUS_RELEASE',
                'authority_id': 'SYNTHETIC_TEST_AUTHORITY',
                'source_id': 'tests/test_candidate_promotion_policy.py::' + purpose,
                'bindings': deepcopy(expected), 'checked_at': '2026-11-08T23:00:00Z',
                'expires_at': '2026-11-10T00:00:00Z',
            }
            if purpose == 'QUALITY_ADJUDICATION':
                record['accepted_findings'] = [f['key'] for f in self.facts['findings']]
            record.update(deepcopy(changes))
            record['source_sha256'] = digest(record)
            return record
        return verify

    def decide(self, adjudication=None, release=None, policy=None):
        before = deepcopy(self.facts)
        result = promotion._decide(self.facts, policy or self.policy,
                                   adjudication or promotion._missing, release or promotion._missing)
        self.assertEqual(self.facts, before)
        self.assertTrue(result['policy_only'])
        self.assertFalse(result['activation_authority'])
        return result

    def direct_quality(self):
        self.facts.update(recorded_quality_status='QUALITY_ACCEPTED', quality_accepted_flag=True, findings=[])

    def test_complete_synthetic_scenario_is_eligible_only_as_policy_math(self):
        result = self.decide(self.authority('QUALITY_ADJUDICATION'), self.authority('CORPUS_RELEASE'))
        self.assertEqual(result['final_eligibility'], 'ELIGIBLE')
        self.assertEqual(result['quality_status'], 'QUALITY_ACCEPTED')
        self.assertEqual(result['quality_adjudication_status'], 'VERIFIED')
        self.assertEqual(result['release_authorization_status'], 'VERIFIED')
        self.assertEqual(result['blocking_reasons'], [])
        self.assertEqual(self.facts['recorded_quality_status'], 'QUALITY_REVIEW_REQUIRED')

    def test_direct_acceptance_still_requires_release(self):
        self.direct_quality()
        result = self.decide()
        self.assertEqual(result['quality_status'], 'QUALITY_ACCEPTED')
        self.assertEqual(result['final_eligibility'], 'BLOCKED')
        self.assertEqual(result['release_authorization_status'], 'MISSING')
        self.assertEqual(self.decide(release=self.authority('CORPUS_RELEASE'))['final_eligibility'], 'ELIGIBLE')

    def test_integrity_or_provenance_failure_cannot_be_adjudicated(self):
        self.facts['integrity_status'] = 'REJECTED'
        provider = Mock(side_effect=AssertionError('Must not consult authority'))
        result = self.decide(provider, provider)
        self.assertEqual(result['blocking_reasons'], [{'code': 'INTEGRITY_REJECTED'}])
        provider.assert_not_called()

    def test_quality_failure_and_unknown_review_basis_block(self):
        result = self.decide(release=self.authority('CORPUS_RELEASE'))
        self.assertEqual(result['quality_status'], 'QUALITY_REVIEW_REQUIRED')
        self.assertEqual(len(result['quality_decision']['remaining_findings']), 2)
        self.facts['findings'] = []
        self.assertEqual(self.decide(self.authority('QUALITY_ADJUDICATION'),
                                    self.authority('CORPUS_RELEASE'))['final_eligibility'], 'BLOCKED')
        self.facts['recorded_quality_status'] = 'QUALITY_REJECTED'
        self.assertEqual(self.decide()['quality_status'], 'QUALITY_REJECTED')

    def test_partial_adjudication_does_not_hide_unrelated_findings(self):
        first = self.facts['findings'][0]['key']
        result = self.decide(self.authority('QUALITY_ADJUDICATION', accepted_findings=[first]),
                             self.authority('CORPUS_RELEASE'))
        self.assertEqual(result['final_eligibility'], 'BLOCKED')
        self.assertEqual(result['quality_decision']['accepted_findings'], [first])
        self.assertEqual(result['quality_decision']['remaining_findings'], self.facts['findings'][1:])

    def test_wrong_candidate_report_result_policy_or_upstream_binding_rejected(self):
        for key in self.facts['bindings']:
            with self.subTest(key=key):
                def wrong(expected):
                    result = self.authority('QUALITY_ADJUDICATION')(expected)
                    result['bindings'][key] = 'different'
                    return result
                result = self.decide(wrong, self.authority('CORPUS_RELEASE'))
                self.assertEqual(result['quality_adjudication_status'], 'INVALID')
                self.assertEqual(result['final_eligibility'], 'BLOCKED')

    def test_wrong_release_candidate_or_quality_decision_rejected(self):
        self.direct_quality()
        for key in ('candidate_id', 'quality_decision_sha256', 'promotion_policy_sha256'):
            with self.subTest(key=key):
                def wrong(expected):
                    record = self.authority('CORPUS_RELEASE')(expected)
                    record['bindings'][key] = 'another-decision'
                    return record
                self.assertEqual(self.decide(release=wrong)['release_authorization_status'], 'INVALID')

    def test_untrusted_malformed_stale_or_rejected_release_is_invalid(self):
        self.direct_quality()
        providers = [lambda _: {'approved': True}, lambda _: {'status': 'INVALID'},
                     self.authority('CORPUS_RELEASE', expires_at='2000-01-01T00:00:00Z'),
                     self.authority('CORPUS_RELEASE', decision='REJECT'),
                     self.authority('CORPUS_RELEASE', authority_id=''),
                     self.authority('CORPUS_RELEASE', checked_at='2099-01-01T00:00:00Z')]
        for provider in providers:
            with self.subTest(provider=provider):
                result = self.decide(release=provider)
                self.assertEqual(result['release_authorization_status'], 'INVALID')
                self.assertEqual(result['final_eligibility'], 'BLOCKED')
        result = self.decide(release=Mock(side_effect=OSError('SECRET')))
        self.assertEqual(result['release_authorization_status'], 'INVALID')
        self.assertNotIn('SECRET', json.dumps(result))

    def test_research_review_is_not_release_or_quality_authority(self):
        research = lambda _: {'status': 'RESEARCH_REVIEW_VERIFIED', 'diagnostic_only': True}
        self.assertEqual(self.decide(research)['quality_adjudication_status'], 'INVALID')
        self.direct_quality()
        self.assertEqual(self.decide(release=research)['release_authorization_status'], 'INVALID')
        wrong_scope = self.authority('CORPUS_RELEASE', scope='RESEARCH_DIAGNOSTIC_ONLY')
        self.assertEqual(self.decide(release=wrong_scope)['release_authorization_status'], 'INVALID')

    def test_explicit_not_authorized_is_never_overridden(self):
        self.facts['explicit_prohibitions'] = ['candidate/candidate.json', 'build-policy.json']
        result = self.decide(self.authority('QUALITY_ADJUDICATION'), self.authority('CORPUS_RELEASE'))
        self.assertEqual(result['quality_status'], 'QUALITY_ACCEPTED')
        self.assertEqual(result['release_authorization_status'], 'VERIFIED')
        self.assertEqual(result['final_eligibility'], 'BLOCKED')
        self.assertIn('PRODUCTION_NOT_AUTHORIZED', str(result['blocking_reasons']))

    def test_default_policy_has_no_real_adjudication_permission(self):
        result = self.decide(self.authority('QUALITY_ADJUDICATION'), self.authority('CORPUS_RELEASE'),
                             policy=promotion.POLICY)
        self.assertEqual(result['quality_adjudication_status'], 'INVALID')
        self.assertEqual(result['final_eligibility'], 'BLOCKED')

    def test_unknown_duplicate_or_nonpermitted_findings_rejected(self):
        for keys in (['unknown'], [self.facts['findings'][0]['key']]*2, [True]):
            with self.subTest(keys=keys):
                result = self.decide(self.authority('QUALITY_ADJUDICATION', accepted_findings=keys))
                self.assertEqual(result['quality_adjudication_status'], 'INVALID')

    def test_binding_mutation_cannot_redefine_expected_candidate(self):
        self.direct_quality()
        def mutate(expected):
            expected['candidate_id'] = 'another-candidate'
            return self.authority('CORPUS_RELEASE')(expected)
        self.assertEqual(self.decide(release=mutate)['release_authorization_status'], 'INVALID')

    def test_quality_decision_digest_is_deterministic_and_policy_bound(self):
        provider = self.authority('QUALITY_ADJUDICATION')
        a = self.decide(provider)
        self.assertEqual(a['quality_decision_sha256'], self.decide(provider)['quality_decision_sha256'])
        self.policy['name'] = 'ANOTHER_SYNTHETIC_POLICY'
        self.assertNotEqual(a['quality_decision_sha256'], self.decide(provider)['quality_decision_sha256'])


class ArchivePolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'run'
        self.root.mkdir()
        original = fixtures.put
        def put(root, name, value):
            value = deepcopy(value)
            if name.endswith('/corpus.jsonl'):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value) + '\n')
                return
            if name in ('quality/incremental-raw-results.json', 'quality/full-raw-results.json'):
                value = [{**row, 'strict': {'hit_at_5': row['id'] != 'DOC-Q27',
                                            'hit_at_10': row['id'] != 'DOC-Q27'}} for row in value]
            if name == 'quality/transitions.json':
                for rows in value.values():
                    for row in rows:
                        if row['id'] == 'DOC-Q27':
                            row.update(hit5='PASS\u2192FAIL', hit10='PASS\u2192FAIL')
            if name == 'quality/quality-report.json':
                value['new_losses'] = {source: [{'id': 'DOC-Q27', 'mode': mode, 'hit5': 'PASS\u2192FAIL',
                                                 'hit10': 'PASS\u2192FAIL'}
                                                for mode in ('combined', 'documentation_only')]
                                       for source in ('historical', 'immediate_parent')}
            original(root, name, value)
        with patch.object(fixtures, 'put', side_effect=put):
            fixtures.fixture(self.root)

    def test_runtime_uses_original_p8_and_preserves_every_blocker(self):
        original = gate.evaluate(self.root)
        result = promotion.evaluate(self.root)
        self.assertEqual(result['p8'], original)
        self.assertEqual(result['integrity_status'], 'VERIFIED')
        self.assertEqual(result['quality_status'], 'QUALITY_REVIEW_REQUIRED')
        self.assertEqual(result['release_authorization_status'], 'MISSING')
        self.assertEqual(result['final_eligibility'], 'BLOCKED')
        self.assertFalse(result['activation_authority'])
        for reason in original['reasons']:
            self.assertIn({'source': 'P8', **reason}, result['blocking_reasons'])

    def test_finding_coordinates_separate_modes_metrics_and_comparisons(self):
        result = promotion.evaluate(self.root)
        findings = result['quality_decision']['findings']
        self.assertEqual(len(findings), 12)
        self.assertEqual(len({row['key'] for row in findings}), 12)
        self.assertEqual({row['comparison'] for row in findings}, {'candidate', 'historical', 'immediate_parent'})
        self.assertEqual({row['mode'] for row in findings}, {'combined', 'documentation_only'})

    def test_corruption_missing_or_unsupported_evidence_fail_closed(self):
        corpus = self.root / 'candidate/corpus.jsonl'
        corpus.write_bytes(b'corrupted')
        result = promotion.evaluate(self.root)
        self.assertEqual(result['integrity_status'], 'REJECTED')
        self.assertEqual(result['final_eligibility'], 'BLOCKED')
        self.assertIn('INVALID_EVIDENCE', str(result['p8']['reasons']))
        self.assertEqual(promotion.evaluate(self.root / 'missing')['final_eligibility'], 'BLOCKED')

    def test_integration_denies_selection_and_gradio_initialization(self):
        with TestWorkspace() as workspace:
            raw = b'{"chunk_id":"previous"}\n'
            integration._register(workspace, 'previous', raw, hashlib.sha256(raw).hexdigest())
            workspace.switch('previous')
            before = workspace.current()
            with patch.object(integration, '_load_gradio', side_effect=AssertionError('No activation')) as initialize:
                result = integration._integrate(self.root, workspace)
            self.assertEqual(result['decision'], 'BLOCKED')
            self.assertEqual(result['promotion_policy']['final_eligibility'], 'BLOCKED')
            self.assertEqual(result['activation'], 'DENIED')
            self.assertEqual(result['gradio_reinitialization'], 'NOT_ATTEMPTED')
            self.assertEqual(workspace.current(), before)
            initialize.assert_not_called()

    def test_cli_has_no_trust_injection_or_override_options(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(promotion.main(['--artifact', str(self.root)]), 1)
        self.assertEqual(json.loads(output.getvalue())['final_eligibility'], 'BLOCKED')
        for flag in ('--force', '--approve', '--skip-quality', '--ignore-p8', '--synthetic', '--release-json'):
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(promotion.main(['--artifact', str(self.root), flag]), 1)
            self.assertEqual(json.loads(output.getvalue())['blocking_reasons'], [{'code': 'INVALID_INPUT'}])

    def test_additional_policy_gate_is_required_even_if_p8_were_accepting(self):
        hypothetical = gate.evaluate(self.root)
        hypothetical.update(decision='ELIGIBLE', gate_mode='HYPOTHETICAL_TEST_GATE', reasons=[])
        with TestWorkspace() as workspace, patch.object(gate, 'evaluate', return_value=hypothetical), \
                patch.object(integration, '_load_gradio', side_effect=AssertionError('No authorization')) as initialize:
            result = integration._integrate(self.root, workspace)
        self.assertEqual(result['decision'], 'BLOCKED')
        self.assertEqual(result['promotion_policy']['final_eligibility'], 'BLOCKED')
        self.assertEqual(result['activation'], 'DENIED')
        self.assertTrue(result['selection_unchanged'])
        initialize.assert_not_called()


if __name__ == '__main__':
    unittest.main()
