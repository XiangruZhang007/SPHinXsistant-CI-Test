"""Controlled lifecycle with real frozen evidence/replay, never Owner authority."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import test_continuous_execution as fixtures
from src import approval_evidence as ev, ci_v2_research as c
from src import continuous_execution as execution, continuous_lifecycle as life
from src import parent_r2_anchor
from src import trusted_snapshot, upstream_provenance as legacy
from src.corpus_snapshot import digest, file_digest, read_json

P = Path(__file__).resolve().parents[1]


def write_json(path, value):
    # Deliberate adversarial overwrites apply only to disposable test fixtures.
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


class ContinuousLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse the existing factory without inheriting/duplicating its tests.
        factory = cls.factory = fixtures.ContinuousExecutionTests
        factory.setUpClass(); cls.addClassCleanup(factory.doClassCleanups)
        temp = tempfile.TemporaryDirectory(prefix='continuous-lifecycle-tests-')
        cls.addClassCleanup(temp.cleanup); cls.shared = Path(temp.name)
        cls.project = factory.project
        shutil.copyfile(P / 'src/continuous_lifecycle.py', cls.project / 'src/continuous_lifecycle.py')
        cls.package = factory.original
        cls.candidate_pins = {**factory.pins, 'expected_candidate_id': factory.result['candidate_id'],
                              'expected_manifest_sha256': factory.result['manifest_sha256']}
        cls.lifecycle_pin = digest(life.contract(cls.project))
        cls.policy = cls.shared / 'policy.json'
        metadata = read_json(cls.package / 'candidate/continuous-candidate.json')
        identity = metadata['identity']; quality = read_json(cls.package / 'quality/quality-report.json')
        policy = {'schema_version': 1, 'mode': 'RETRIEVAL_EVALUATED',
            'scope': {'experiment_id': 'synthetic-continuous-lifecycle-fixture',
                      'parent_baseline_id': identity['parent']['node_id'],
                      'target_source_state': identity['target_source_state'],
                      'build_fingerprint': identity['build_fingerprint'],
                      'quality_policy_sha256': digest(quality['policy'])},
            'reference_rows_sha256': {
                ev.RAW_FILES[2]: file_digest(cls.package / 'evidence/historical-rows.json'),
                ev.RAW_FILES[3]: file_digest(cls.package / 'evidence/parent-rows.json')},
            'quality_status': 'QUALITY_REVIEW_REQUIRED', 'automatic_reuse': False,
            'production_promotion': 'NOT_AUTHORIZED'}
        write_json(cls.policy, policy); cls.policy_pin = file_digest(cls.policy)
        subject = cls.subject = life.approval_subject(cls.project, cls.package,
            candidate_pins=cls.candidate_pins, expected_lifecycle_contract_sha256=cls.lifecycle_pin,
            expected_approval_policy_sha256=cls.policy_pin)
        cls.decision = cls.shared / 'decision.json'
        write_json(cls.decision, {'schema_version': 1, 'kind': life.DECISION,
            'provenance_type': execution.SYNTHETIC, 'subject_sha256': digest(subject),
            'authorization': {'schema_version': 1, 'research_only': True, 'approved': True,
                'candidate_id': metadata['candidate_id'], 'parent_baseline_id': identity['parent']['node_id'],
                'experiment_id': policy['scope']['experiment_id'],
                'quality_status': 'QUALITY_REVIEW_REQUIRED', 'allow_quality_review': True}})
        cls.decision_pin = file_digest(cls.decision)
        cls.baseline = cls.shared / 'baseline'
        cls.result = life._approve_controlled_fixture(cls.project, cls.package, cls.baseline,
            candidate_pins=cls.candidate_pins, expected_lifecycle_contract_sha256=cls.lifecycle_pin,
            approval_policy=cls.policy, expected_approval_policy_sha256=cls.policy_pin,
            decision_path=cls.decision, expected_decision_sha256=cls.decision_pin)
        cls.baseline_pins = {'candidate_pins': cls.candidate_pins,
            'expected_lifecycle_contract_sha256': cls.lifecycle_pin,
            'expected_approval_policy_sha256': cls.policy_pin,
            'expected_decision_sha256': cls.decision_pin,
            'expected_baseline_id': cls.result['baseline_id'],
            'expected_manifest_sha256': cls.result['manifest_sha256']}

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='continuous-lifecycle-case-')
        self.addCleanup(temp.cleanup); self.root = Path(temp.name)
        self.baseline_copy = self.root / 'baseline'; shutil.copytree(self.baseline, self.baseline_copy)
        self.pins = deepcopy(self.baseline_pins)

    def verify(self, **overrides):
        return life.verify_baseline(self.project, self.baseline_copy, **{**self.pins, **overrides})

    def qualify(self, **overrides):
        reference = life.parent_reference(self.result)
        arguments = {'reference': reference, 'expected_reference_sha256': digest(reference),
            'rows_path': self.package / 'quality/incremental-raw-results.json',
            'expected_rows_sha256': file_digest(self.package / 'quality/incremental-raw-results.json'),
            'baseline_pins': self.pins}
        return life.qualify_controlled_parent(self.project, self.baseline_copy, **{**arguments, **overrides})

    def reseal(self, recompute_identity=False):
        if recompute_identity:
            identity = life._identity(self.baseline_copy, self.subject, self.decision_pin)
            baseline_id = 'sha256-' + digest(identity)
            write_json(self.baseline_copy / 'baseline.json',
                       {'format': life.FORMAT, 'baseline_id': baseline_id, 'identity': identity})
            self.pins['expected_baseline_id'] = baseline_id
        (self.baseline_copy / 'checksums.json').unlink(); execution._seal(self.baseline_copy)
        self.pins['expected_manifest_sha256'] = file_digest(self.baseline_copy / 'checksums.json')

    def change(self, relative, mutate):
        path = self.baseline_copy / relative; value = read_json(path); mutate(value); write_json(path, value)

    def reseal_evidence(self):
        (self.baseline_copy / 'approval-evidence/checksums.json').unlink()
        ev.seal(self.baseline_copy / 'approval-evidence')

    def test_end_to_end_actual_replay_parent_and_blocked_registration(self):
        report = self.verify(fresh_replay=True)
        self.assertEqual(report['status'], 'CONTROLLED_BASELINE_VERIFIED')
        self.assertEqual(report['replay'], 'FRESH_SYNTHETIC_R2_REPLAY')
        self.assertNotEqual(report['candidate_id'], report['baseline_id'])
        self.assertEqual(report['generation'], 2)
        parent = self.qualify()
        self.assertEqual(parent['status'], 'CONTROLLED_PARENT_QUALIFIED')
        self.assertEqual(parent['execution'], 'FRESH_SYNTHETIC_R2_REPLAY')
        self.assertEqual(parent['bindings']['candidate_id'], report['candidate_id'])
        self.assertNotEqual(parent['bindings']['original_parent_rows_sha256'],
                            parent['previous_parent_rows_sha256'])
        before = file_digest(P / 'configs/ci_v2_schema2_trusted_baselines.json')
        result = life.registration_preflight(self.project, self.baseline_copy, baseline_pins=self.pins)
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(result['controlled_preflight'], 'CONTROLLED_PREFLIGHT_VERIFIED')
        self.assertIn('NEW_FORMAT_REGISTRY_NOT_SUPPORTED', result['blockers'])
        self.assertIn('INDEPENDENT_REGISTRATION_AUTHORITY_NOT_ESTABLISHED', result['blockers'])
        self.assertEqual(before, file_digest(P / 'configs/ci_v2_schema2_trusted_baselines.json'))
        print('CONTROLLED_LIFECYCLE_EVIDENCE', {
            'candidate_id': report['candidate_id'], 'baseline_id': report['baseline_id'],
            'generation': report['generation'], 'candidate_full_replay_rows_each': 128,
            'parent_qualification': parent['status'], 'registry': result['status'],
            'owner_authorization': report['owner_authorization']})

    def test_sealed_inspection_does_not_call_fresh_replay(self):
        with patch.object(ev, 'replay', side_effect=AssertionError('Unexpected replay')):
            self.assertEqual(self.verify()['replay'], 'SEALED_REPLAY_INSPECTED')
            result = self.qualify(fresh_replay=False)
        self.assertEqual(result['execution'], 'NO_FRESH_REPLAY')
        self.assertEqual(result['status'], 'CONTROLLED_PARENT_INSPECTED')

    def test_missing_or_wrong_independent_pins(self):
        for key in ('expected_manifest_sha256', 'expected_approval_policy_sha256',
                    'expected_decision_sha256', 'expected_lifecycle_contract_sha256'):
            for value in (None, '0' * 64):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.verify(**{key: value})
        pins = deepcopy(self.candidate_pins); pins.pop('expected_candidate_id')
        with self.assertRaises(ValueError): self.verify(candidate_pins=pins)

    def test_candidate_identity_and_projection_tampering(self):
        for name, mutate in (
            ('continuous-candidate.json', lambda v: v['identity'].update(generation=900)),
            ('candidate.json', lambda v: v.update(candidate_id='sha256-' + '0' * 64))):
            path = self.baseline_copy / 'original/candidate' / name; original = path.read_bytes()
            try:
                value = read_json(path); mutate(value); write_json(path, value)
                self.reseal()
                with self.assertRaises(ValueError): self.verify()
            finally: path.write_bytes(original)

    def test_forged_receipt_rejected_even_after_new_baseline_identity(self):
        self.change('approval-evidence/verification.json', lambda v: v.update(candidate_id='forged'))
        self.reseal_evidence(); self.reseal(recompute_identity=True)
        with self.assertRaises(ValueError): self.verify()

    def test_structural_only_receipt_rejected(self):
        self.change('approval-evidence/verification.json',
                    lambda v: v.update(mode='STRUCTURAL_ONLY', execution='NOT_EVALUATED'))
        self.reseal_evidence(); self.reseal(recompute_identity=True)
        with self.assertRaises(ValueError): self.verify()

    def test_wrong_parent_id_or_generation_in_reference(self):
        for key, value in (('baseline_id', 'sha256-' + '0' * 64), ('generation', 99), ('generation', True)):
            reference = life.parent_reference(self.result); reference[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.qualify(reference=reference, expected_reference_sha256=digest(reference))

    def test_wrong_parent_binding_in_decision(self):
        self.change('controlled-decision.json', lambda v: v['authorization'].update(parent_baseline_id='wrong'))
        self.reseal(recompute_identity=True)
        with self.assertRaises(ValueError): self.verify()

    def test_original_parent_rows_cannot_be_substituted_with_previous_parent(self):
        path = self.package / 'evidence/parent-rows.json'
        with self.assertRaisesRegex(ValueError, 'ORIGINAL_PARENT_R2_ANCHOR'):
            self.qualify(rows_path=path, expected_rows_sha256=file_digest(path))

    def test_missing_and_modified_replay_rejected(self):
        path = self.baseline_copy / 'approval-evidence/candidate-replay.json'
        original = path.read_bytes(); path.unlink()
        self.reseal(recompute_identity=True)
        with self.assertRaises(ValueError): self.verify()
        path.write_bytes(original)
        self.change('approval-evidence/candidate-replay.json', lambda v: v.pop())
        self.reseal_evidence(); self.reseal(recompute_identity=True)
        with self.assertRaises(ValueError): self.verify()

    def test_actual_fresh_candidate_replay_failure_rejected(self):
        actual = ev.replay
        def fail(spec, corpus, documentation):
            rows = actual(spec, corpus, documentation); rows.pop(); return rows
        with patch.object(ev, 'replay', side_effect=fail), self.assertRaisesRegex(ValueError, 'replay mismatch'):
            self.verify(fresh_replay=True)

    def test_actual_fresh_parent_replay_failure_rejected(self):
        actual = ev.replay
        def fail(spec, corpus, documentation):
            rows = actual(spec, corpus, documentation); rows.pop(); return rows
        with patch.object(ev, 'replay', side_effect=fail), self.assertRaisesRegex(ValueError, 'PARENT_REPLAY'):
            self.qualify()

    def test_modified_source_evidence_rejected(self):
        self.change('original/evidence/assessment.json', lambda v: v['subject'].update(target_source_state='forged'))
        self.reseal()
        with self.assertRaises(ValueError): self.verify()

    def test_changed_approval_policy_rejected(self):
        self.change('approval-policy.json', lambda v: v.update(quality_status='QUALITY_ACCEPTED'))
        self.reseal(recompute_identity=True)
        with self.assertRaises(ValueError): self.verify()

    def test_unapproved_candidate_not_a_parent(self):
        reference = life.parent_reference(self.result)
        with self.assertRaises(ValueError):
            life.qualify_controlled_parent(self.project, self.package, reference, digest(reference),
                self.package / 'quality/incremental-raw-results.json',
                file_digest(self.package / 'quality/incremental-raw-results.json'), baseline_pins=self.pins)

    def test_controlled_baseline_cannot_claim_genuine(self):
        self.change('baseline.json', lambda v: v['identity'].update(provenance_type='GENUINE_UPSTREAM'))
        self.reseal()
        with self.assertRaises(ValueError): self.verify()

    def test_stale_decision_subject_or_rejected_decision(self):
        for update in ({'subject_sha256': '0' * 64}, {'authorization': {'approved': False}}):
            decision = read_json(self.decision); decision.update(update)
            path = self.root / 'rejected.json'; write_json(path, decision)
            with self.subTest(update=update), self.assertRaises(ValueError):
                life._approve_controlled_fixture(self.project, self.package, self.root / 'not-created',
                    candidate_pins=self.candidate_pins, expected_lifecycle_contract_sha256=self.lifecycle_pin,
                    approval_policy=self.policy, expected_approval_policy_sha256=self.policy_pin,
                    decision_path=path, expected_decision_sha256=file_digest(path))
            self.assertFalse((self.root / 'not-created').exists())

    def test_quality_review_requires_explicit_fixture_acknowledgement(self):
        decision = read_json(self.decision); decision['authorization']['allow_quality_review'] = False
        path = self.root / 'decision.json'; write_json(path, decision)
        with self.assertRaisesRegex(ValueError, 'quality review'):
            life._approve_controlled_fixture(self.project, self.package, self.root / 'not-created',
                candidate_pins=self.candidate_pins, expected_lifecycle_contract_sha256=self.lifecycle_pin,
                approval_policy=self.policy, expected_approval_policy_sha256=self.policy_pin,
                decision_path=path, expected_decision_sha256=file_digest(path))

    def test_public_approval_stays_blocked_even_with_fixture_decision(self):
        with self.assertRaisesRegex(ValueError, 'TRUSTED_CONTINUOUS_LIFECYCLE_NOT_ESTABLISHED'):
            life.approve(decision_path=self.decision, approved=True)

    def test_historical_verifiers_still_reject_new_format(self):
        with self.assertRaises(ValueError):
            legacy.verify(self.project, self.baseline_copy, self.factory.ref['build_fingerprint'])
        with self.assertRaises(ValueError):
            parent_r2_anchor.qualify_parent_anchor(self.project, self.baseline_copy,
                life.parent_reference(self.result), digest(life.parent_reference(self.result)),
                self.package / 'quality/incremental-raw-results.json', controlled=True)
        reference = {**self.factory.ref, 'package_format': life.FORMAT}
        with self.assertRaises(ValueError): trusted_snapshot.validate_reference(reference, digest(reference), controlled=True)

    def test_no_automatic_authority_production_or_old_registry_entry(self):
        result = self.verify()
        for key, value in life.RESTRICTIONS.items(): self.assertEqual(result[key], value)
        self.assertFalse(result['registered_trusted_parent'])
        self.assertFalse(result['old_format_parent_compatible'])
        self.assertEqual(result['research_approval'], 'CONTROLLED_FIXTURE_ONLY')
        self.assertEqual(digest(legacy.contract(P)), 'b0b43411aef4d716a15a2f0a794071523fbb3c260dc4cb3fc9b2736eed9e1ac1')

    def test_relocation_preserves_offline_baseline_identity(self):
        moved = self.root / 'moved'; self.baseline_copy.rename(moved)
        report = life.verify_baseline(self.project, moved, **self.pins)
        self.assertEqual(report['baseline_id'], self.result['baseline_id'])

    def test_symlink_and_unexpected_entry_rejected(self):
        (self.baseline_copy / 'unexpected').write_text('unexpected')
        with self.assertRaises(ValueError): self.verify()
        (self.baseline_copy / 'unexpected').unlink()
        (self.baseline_copy / 'alias').symlink_to(self.baseline_copy / 'baseline.json')
        with self.assertRaises(ValueError): self.verify()


if __name__ == '__main__': unittest.main()
