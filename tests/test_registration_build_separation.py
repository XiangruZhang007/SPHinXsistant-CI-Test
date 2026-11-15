"""Registration-only contracts; every successful approval below is simulated."""
from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_published_candidate_verification as published_fixtures
import test_register_trusted_baseline_cli as cli_fixtures
import test_baseline_registration_transaction as transaction_fixtures
import test_hosted_registration as hosted_fixtures
import test_schema2_research_parent as planning_fixtures
from src import trusted_baseline_registration as registration
from src import schema2_workflow as workflow, ci_v2_research as research
from src import github_baseline_approval as pr_approval
from src import continuous_corpus as local_chain
from src.corpus_snapshot import digest, file_digest


def registration_entry(entry):
    return {'entry_kind': 'REGISTRATION_ONLY', 'reference': entry['reference'],
            'expected_reference_sha256': entry['expected_reference_sha256']}


def fixture(test, cls):
    value = cls()
    value.setUp()
    test.addCleanup(value.doCleanups)
    test.addCleanup(value.tearDown)
    return value


def use_registration_entry(value):
    entry = registration_entry(value.entry)
    value.entry.clear()
    value.entry.update(entry)


class EntryContractsTests(unittest.TestCase):
    def test_closed_contracts_and_no_placeholder_policy_pin(self):
        legacy = {'reference': {}, 'expected_reference_sha256': '1' * 64,
                  'build_policy_path': 'configs/policy.json', 'build_policy_sha256': '2' * 64}
        self.assertEqual(registration.entry_kind(legacy), registration.LEGACY_BUILD_BOUND)
        new = registration_entry(legacy)
        new['reference'] = {'package_format': 'schema2-research-baseline'}
        self.assertEqual(registration.validate_build_policy_pin(new, None), 'REGISTRATION_ONLY')
        invalid = [dict(new, build_policy_path='configs/fake.json'),
                   dict(new, build_policy_sha256='0' * 64),
                   dict(new, entry_kind='APPROVED'),
                   {k: v for k, v in new.items() if k != 'entry_kind'},
                   dict(new, reference={'package_format': 'p2-snapshot-v1'})]
        for entry in invalid:
            with self.subTest(entry=entry), self.assertRaises(registration.RegistrationError):
                registration.entry_kind(entry)
        for pin in ('', '0' * 64, '2' * 64, False):
            with self.subTest(pin=pin), self.assertRaisesRegex(
                    registration.RegistrationError, 'UNEXPECTED_BUILD_POLICY_PIN'):
                registration.validate_build_policy_pin(new, pin)
        with self.assertRaises(registration.RegistrationError):
            registration.validate_build_policy_pin(legacy, None)

    def test_protected_pr_mode_explicitly_refuses_new_contract(self):
        entry = {'entry_kind': 'REGISTRATION_ONLY', 'expected_reference_sha256': '1' * 64,
                 'reference': {'package_format': 'schema2-research-baseline'}}
        with self.assertRaisesRegex(pr_approval.ApprovalError,
                                    'REGISTRATION_ONLY_UNSUPPORTED_BY_PR_APPROVAL'):
            pr_approval._validators(Path('.'), Path('.'), entry, {})


class RegistrationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, published_fixtures.PublishedCandidateVerificationTests)
        use_registration_entry(self.f)
        self.f.arguments.pop('expected_build_policy_sha256')
        self.f.build.unlink()

    def test_evidence_verified_without_future_policy_and_subject_is_complete(self):
        one = self.f.run_verification()
        self.assertEqual(one, self.f.run_verification())
        self.assertEqual(one['status'], 'EVIDENCE_VERIFIED')
        self.assertEqual(one['execution'], 'NO_FRESH_REPLAY')
        self.assertEqual(one['authorization'], 'NOT_VERIFIED')
        subject = one['registration_subject']
        self.assertEqual(subject['registry_entry'], self.f.entry)
        self.assertEqual(subject['registry_entry_sha256'], digest(self.f.entry))
        self.assertEqual(subject['candidate']['quality_status'], 'QUALITY_REVIEW_REQUIRED')
        self.assertEqual(subject['candidate']['q1_status'], 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
        self.assertEqual(subject['production_promotion'], 'NOT_AUTHORIZED')
        self.f.validators[1]._research_parent_scope.assert_not_called()
        self.f.anchor.assert_called()
        self.assertIs(self.f.anchor.call_args.kwargs['fresh_replay'], False)

    def test_p41_and_original_r2_bindings_remain_required(self):
        self.f.upstream_report['P4_1_verification'] = 'NOT_APPROVED'
        with self.assertRaises(published_fixtures.v.VerificationError):
            self.f.run_verification()
        self.f.upstream_report['P4_1_verification'] = 'P4_1_VERIFIED'
        self.f.qualified['bindings']['parent_rows_sha256'] = '0' * 64
        with self.assertRaises(published_fixtures.v.VerificationError):
            self.f.run_verification()

    def test_stale_registry_or_ambiguous_build_pin_is_rejected(self):
        for kwargs in ({'expected_registry_sha256': '0' * 64},
                       {'expected_build_policy_sha256': '0' * 64}):
            with self.subTest(kwargs=kwargs), self.assertRaises(published_fixtures.v.VerificationError):
                self.f.run_verification(**kwargs)

    def test_registration_only_cannot_fall_back_to_legacy_baseline_verification(self):
        baseline = self.f.root / 'baseline-original'
        (baseline / 'upstream-baseline.json').unlink()
        with self.assertRaisesRegex(registration.RegistrationError, 'SCHEMA2_BASELINE_REQUIRED'):
            registration.prepare(self.f.project, self.f.registry, 'proposed-baseline',
                baseline, self.f.entry, expected_reference_sha256=digest(self.f.ref),
                expected_workflow_repository=self.f.repo['full_name'],
                expected_workflow_repository_id=self.f.repo['id'])
        self.f.validators[0].verify_baseline.assert_not_called()


class RegistrationRequestTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, cli_fixtures.RegistrationCLITests)
        use_registration_entry(self.f.f)
        self.f.request['schema_version'] = 2
        self.f.request.pop('expected_build_policy_sha256')
        self.f.f.build.unlink()
        self.f.write_request()

    def test_version_two_request_has_no_build_pin_and_is_deterministic(self):
        code, one = self.f.call()
        self.assertEqual(code, 0, one)
        self.assertEqual(one, self.f.call()[1])
        self.assertEqual(one['registration_subject']['registry_entry'], self.f.f.entry)

    def test_cross_version_requests_and_dummy_policy_fields_are_rejected(self):
        original = deepcopy(self.f.request)
        cases = [dict(original, schema_version=1),
                 dict(original, expected_build_policy_sha256='0' * 64),
                 dict(original, expected_build_policy_sha256=None),
                 dict(original, expected_build_policy_sha256='')]
        legacy = deepcopy(original)
        legacy['proposed_entry'] = {
            'reference': self.f.f.ref, 'expected_reference_sha256': digest(self.f.f.ref),
            'build_policy_path': 'configs/fake.json', 'build_policy_sha256': '0' * 64}
        cases.append(legacy)
        for request in cases:
            with self.subTest(request=request):
                self.f.request = request
                self.f.write_request()
                self.assertEqual(self.f.call()[0], 1)

    def test_ordinary_cli_remains_blocked_even_with_spoofed_github_environment(self):
        code, result = self.f.call('register')
        self.assertEqual(code, 1)
        self.assertEqual(result['reason'], 'TRUSTED_WORKFLOW_EXECUTION_NOT_ESTABLISHED')
        self.assertEqual((self.f.isolation / 'registry.json').read_bytes(), self.f.f.registry_bytes)


class BuildBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, planning_fixtures.ResearchPlanningTests)
        self.registry = self.f.registry()
        self.registry['baselines']['research'] = registration_entry(
            self.registry['baselines']['research'])

    def test_planning_blocks_even_when_a_historical_policy_file_exists(self):
        with patch.object(workflow.trust, 'download') as download, self.assertRaises(research.GateError) as caught:
            workflow.plan(self.f.root, self.registry, 'research', self.f.revisions)
        self.assertEqual(caught.exception.status, 'AUTHORIZATION_FAILED')
        download.assert_not_called()

    def test_execution_rechecks_registry_and_rejects_a_forged_plan(self):
        registry_path = self.f.root / 'registry.json'
        registry_path.write_text(json.dumps(self.registry))
        plan_path = self.f.root / 'plan.json'
        plan_path.write_text(json.dumps({'key': 'research', 'upstreams': self.f.revisions,
            'status': 'SCHEMA2_MANUAL_PLAN', 'registry_entry_sha256': digest(
                self.registry['baselines']['research'])}))
        work = self.f.root / 'work'
        with patch.object(workflow.trust, 'REGISTRY', registry_path), \
                patch.object(research, 'frozen_runtime') as runtime, \
                patch.object(workflow.trust, 'download') as download, \
                patch.object(workflow, 'run_local') as local, \
                self.assertRaises(research.GateError):
            workflow.execute_plan(self.f.root, plan_path, work, self.f.root / 'output')
        runtime.assert_not_called()
        download.assert_not_called()
        local.assert_not_called()
        self.assertFalse(work.exists())

    def test_adding_build_fields_cannot_turn_registration_into_build_authorization(self):
        self.registry['baselines']['research'].update(build_policy_path='policy.json',
            build_policy_sha256=file_digest(self.f.root / 'policy.json'))
        with self.assertRaises(research.GateError) as caught:
            workflow.plan(self.f.root, self.registry, 'research', self.f.revisions)
        self.assertEqual(caught.exception.status, 'INVALID_REFERENCE')

    def test_local_build_next_also_rejects_registration_only_before_verification(self):
        registry_path = self.f.root / 'registry.json'
        registry_path.write_text(json.dumps(self.registry))
        parent = self.f.root / 'parent'
        parent.mkdir()
        output = self.f.root / 'output'
        with patch.object(local_chain.trust, 'verify_package') as verify, \
                patch.object(local_chain.u, 'build') as build, \
                self.assertRaises(research.GateError) as caught:
            local_chain.build_next(planning_fixtures.P, registry_path, 'research',
                digest(self.f.ref), parent, self.f.root / 'base', self.f.root / 'target',
                output, self.f.root / 'policy.json', file_digest(self.f.root / 'policy.json'))
        self.assertEqual(caught.exception.status, 'AUTHORIZATION_FAILED')
        verify.assert_not_called()
        build.assert_not_called()
        self.assertFalse(output.exists())


class RegistrationTransactionTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, transaction_fixtures.RegistrationTransactionTests)
        self.legacy = self.f.historical('0', '9')
        use_registration_entry(self.f.fixture)
        self.f.arguments.pop('expected_build_policy_sha256')
        self.f.subject['registry_entry_sha256'] = digest(self.f.fixture.entry)
        self.f.fixture.context['dispatch_inputs'] = self.f.fixture._dispatch_inputs()
        self.f.sync_subject()

    def test_mixed_entries_register_without_modifying_legacy_records(self):
        old_new = self.f.historical('e', 'f')
        history = {'legacy': self.legacy, 'registered': old_new}
        self.f.add_history(history, note='unchanged')
        result = self.f.run_registration()
        self.assertEqual(result['status'], 'COMPLETED', result)
        current = json.loads(self.f.copy.read_bytes())
        self.assertEqual(current['baselines']['legacy'], self.legacy)
        self.assertEqual(current['baselines']['registered'], old_new)
        self.assertEqual(current['baselines']['candidate-c2'], self.f.fixture.entry)
        self.assertEqual(current['note'], 'unchanged')

    def test_mixed_entry_duplicate_candidate_is_rejected(self):
        self.legacy['reference']['node_id'] = 'sha256-' + 'e' * 64
        self.legacy['expected_reference_sha256'] = digest(self.legacy['reference'])
        self.f.candidates[self.legacy['reference']['node_id']] = self.f.fixture.report['candidate_id']
        self.f.add_history({'legacy': self.legacy})
        result = self.f.run_registration()
        self.assertEqual(result['reason'], 'DUPLICATE_CANDIDATE_ID', result)
        self.assertEqual(self.f.copy.read_bytes(), self.f.fixture.client.registry_raw)

    def test_stale_registry_and_mutated_subject_remain_blocked(self):
        self.f.test_stale_registry_and_incorrect_evidence_subject()

    def test_wrong_owner_dispatch_remains_blocked(self):
        self.f.fixture.context['dispatch_inputs']['registry_entry_sha256'] = '0' * 64
        result = self.f.run_registration()
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(self.f.copy.read_bytes(), self.f.fixture.client.registry_raw)

    def test_registration_only_owner_approval_requires_complete_subject(self):
        f = self.f.fixture
        result = transaction_fixtures.tx.owner.verify(f.project, f.baseline, f.registry,
            'candidate-c2', f.entry, policy_path=f.policy_path, policy_sha256=f.policy_sha,
            expected_reference_sha256=digest(f.ref), q1_status=f.report['q1_status'],
            context=f.context, client=f.client)
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertIn('REGISTRATION_SUBJECT_REQUIRED', result['reasons'])

    def test_concurrent_transactions_remain_serialized(self):
        self.f.test_concurrent_registration_is_rejected_and_lock_is_stable()

    def test_precommit_interruption_does_not_register_on_recovery(self):
        self.f.test_interruption_after_prepared_blocks_retry_and_recovery_does_not_write()

    def test_postcommit_interruption_has_idempotent_audit_only_recovery(self):
        self.f.test_interruption_immediately_after_commit_and_repeated_recovery()

    def test_postcommit_error_reports_commit_and_can_recover(self):
        self.f.test_replace_exception_after_commit_reports_actual_state()


class HostedCompositionTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, hosted_fixtures.HostedRegistrationTests)
        cli = self.f.fixture
        use_registration_entry(cli.f)
        cli.request['schema_version'] = 2
        cli.request.pop('expected_build_policy_sha256')
        cli.f.build.unlink()
        cli.write_request()
        self.f.request_path.write_bytes(cli.path.read_bytes())
        self.f.deployment['request_sha256'] = cli.sha
        code, verified = cli.call()
        self.assertEqual(code, 0, verified)
        self.f.inputs['registry_entry_sha256'] = digest(cli.f.entry)
        self.f.inputs['registration_subject_sha256'] = verified['registration_subject_sha256']
        self.f.event.write_text(json.dumps({'inputs': self.f.inputs}))

    def test_mocked_hosted_composition_preserves_exact_subject_and_isolation(self):
        result = self.f.invoke()
        self.assertEqual(result['status'], 'COMPLETED', result)
        self.assertTrue(result['authoritative_registry_unchanged'])
        self.assertEqual(result['execution'], 'NO_FRESH_REPLAY')
        self.assertEqual(result['production_promotion'], 'NOT_AUTHORIZED')

    def test_mocked_hosted_dispatch_subject_mutation_is_rejected(self):
        self.f.inputs['registration_subject_sha256'] = '0' * 64
        self.f.event.write_text(json.dumps({'inputs': self.f.inputs}))
        self.assertEqual(self.f.invoke()['status'], 'BLOCKED')


if __name__ == '__main__':
    unittest.main()
