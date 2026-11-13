"""Offline checks for the fail-closed registration preparation entry."""
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from src import trusted_baseline_registration as registration
from src.corpus_snapshot import digest, file_digest


class TrustedBaselineRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / 'project'
        self.project.mkdir()
        (self.project / 'configs').mkdir()
        self.policy_path = self.project / 'configs/build-policy.json'
        self.policy_path.write_text('{"policy":"fixture"}\n', encoding='utf-8')
        self.baseline = self.root / 'baseline'
        self.baseline.mkdir()
        self._json(self.baseline / 'checksums.json', {'sealed': 'fixture'})
        (self.baseline / 'corpus.jsonl').write_bytes(b'{"synthetic":true}\n')
        self._json(self.baseline / 'upstream-candidate.json', {'candidate_id': 'candidate-test'})
        self.quality = {'status': 'QUALITY_REVIEW_REQUIRED', 'candidate_id': 'candidate-test',
                        'corpus_sha256': file_digest(self.baseline / 'corpus.jsonl')}
        self._json(self.baseline / 'quality.json', self.quality)
        self._json(self.baseline / 'research-decision.json', {
            'quality_status': self.quality['status'], 'production_promotion': 'NOT_AUTHORIZED',
            'automatic_reuse': False})
        self._json(self.baseline / 'authorization.json', {
            'quality_status': self.quality['status'], 'production_promotion': 'NOT_AUTHORIZED'})
        self.registry = self.root / 'registry.json'
        self._json(self.registry, {'schema_version': 2, 'baselines': {'existing': {'unchanged': True}}})
        self.registry_before = self.registry.read_bytes()
        self.ref = {
            'schema_version': 2, 'package_format': 'schema2-research-baseline',
            'accepted_package_schema': 2, 'node_id': 'sha256-' + '1' * 64,
            'package_checksum': '2' * 64, 'manifest_sha256': file_digest(self.baseline / 'checksums.json'),
            'transport_sha256': '3' * 64, 'source_state': 'sha256-' + '4' * 64,
            'upstreams': {'SPHinXsys': 'a' * 40, 'SPHinXsim': 'b' * 40},
            'build_fingerprint': '5' * 64, 'corpus_sha256': self.quality['corpus_sha256'],
            'authorization': {'research_only': True, 'production_promotion': 'NOT_AUTHORIZED'},
            'storage': {'kind': 'GITHUB_PRIVATE_RELEASE_ASSET'},
            'parent_rows_sha256': '6' * 64,
            'parent_rows_storage': {'kind': 'GITHUB_PRIVATE_RELEASE_ASSET'},
        }
        self.policy_sha = file_digest(self.policy_path)
        self.entry = {
            'build_policy_path': 'configs/build-policy.json',
            'build_policy_sha256': self.policy_sha,
            'expected_reference_sha256': digest(self.ref),
            'reference': self.ref,
        }
        self.report = {
            'P4_1_verification': 'P4_1_VERIFIED', 'baseline_id': self.ref['node_id'],
            'candidate_id': 'candidate-test', 'package_checksum': self.ref['package_checksum'],
            'manifest_sha256': self.ref['manifest_sha256'], 'target_source_state': self.ref['source_state'],
            'upstreams': self.ref['upstreams'], 'generation': 2,
        }

    @staticmethod
    def _json(path, value):
        Path(path).write_text(json.dumps(value, sort_keys=True) + '\n', encoding='utf-8')

    def _prepare(self, **overrides):
        arguments = {
            'expected_reference_sha256': digest(self.ref),
            'expected_build_policy_sha256': self.policy_sha,
            'expected_workflow_repository': 'owner/research-ci',
            'expected_workflow_repository_id': 1234,
        }
        arguments.update(overrides)
        validate_reference = Mock()
        validators = (SimpleNamespace(verify_baseline=Mock(return_value=self.report)),
                      SimpleNamespace(_research_parent_scope=Mock()),
                      SimpleNamespace(validate_reference=validate_reference,
                                      release_locator=Mock()))
        with patch.object(registration, '_validators', return_value=validators):
            result = registration.prepare(self.project, self.registry, 'candidate-key',
                                          self.baseline, self.entry, **arguments)
        validate_reference.assert_called_once_with(self.ref, digest(self.ref), remote=True)
        return result

    def test_valid_p41_inputs_remain_blocked_without_independent_authority(self):
        result = self._prepare()
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(result['registration'], 'NOT_PERFORMED')
        self.assertFalse(result['registry_modified'])
        self.assertEqual(result['P4_1_verification'], 'P4_1_VERIFIED')
        self.assertEqual(result['quality_status'], 'QUALITY_REVIEW_REQUIRED')
        self.assertEqual(result['generation'], 2)
        self.assertEqual(result['release_assets']['baseline'], self.ref['storage'])
        self.assertEqual(result['research_review_status'], 'NOT_AN_AUTHORIZATION_SOURCE')
        self.assertEqual(result['reviewer_identity'], 'NOT_INDEPENDENTLY_VERIFIED')
        self.assertEqual(result['blocking_reasons'], ['INDEPENDENT_REGISTRATION_AUTHORITY_NOT_CONFIGURED'])
        self.assertEqual(self.registry.read_bytes(), self.registry_before)

    def test_reference_pin_must_be_independent_and_exact(self):
        with self.assertRaisesRegex(registration.RegistrationError, 'INDEPENDENT_REFERENCE_PIN_MISMATCH'):
            self._prepare(expected_reference_sha256='0' * 64)
        self.assertEqual(self.registry.read_bytes(), self.registry_before)

    def test_build_policy_pin_must_be_independent_and_exact(self):
        with self.assertRaisesRegex(registration.RegistrationError, 'INDEPENDENT_BUILD_POLICY_PIN_MISMATCH'):
            self._prepare(expected_build_policy_sha256='0' * 64)

    def test_existing_registry_key_cannot_be_replaced(self):
        with self.assertRaisesRegex(registration.RegistrationError, 'REGISTRY_KEY_ALREADY_EXISTS'):
            registration.prepare(self.project, self.registry, 'existing', self.baseline, self.entry,
                expected_reference_sha256=digest(self.ref),
                expected_build_policy_sha256=self.policy_sha,
                expected_workflow_repository='owner/research-ci',
                expected_workflow_repository_id=1234)
        self.assertEqual(self.registry.read_bytes(), self.registry_before)

    def test_p41_failure_blocks_registration(self):
        validators = (SimpleNamespace(verify_baseline=Mock(return_value={'P4_1_verification': 'P4_1_NOT_VERIFIED'})),
                      SimpleNamespace(_research_parent_scope=Mock()),
                      SimpleNamespace(validate_reference=Mock(), release_locator=Mock()))
        with patch.object(registration, '_validators', return_value=validators):
            with self.assertRaisesRegex(registration.RegistrationError, 'P4_1_BASELINE_QUALIFICATION_REQUIRED'):
                registration.prepare(self.project, self.registry, 'candidate-key', self.baseline,
                    self.entry, expected_reference_sha256=digest(self.ref),
                    expected_build_policy_sha256=self.policy_sha,
                    expected_workflow_repository='owner/research-ci',
                    expected_workflow_repository_id=1234)

    def test_candidate_identity_mismatch_blocks(self):
        self.report['candidate_id'] = 'candidate-other'
        validators = (SimpleNamespace(verify_baseline=Mock(return_value=self.report)),
                      SimpleNamespace(_research_parent_scope=Mock()),
                      SimpleNamespace(validate_reference=Mock(), release_locator=Mock()))
        with patch.object(registration, '_validators', return_value=validators):
            with self.assertRaisesRegex(registration.RegistrationError, 'CANDIDATE_IDENTITY_MISMATCH'):
                registration.prepare(self.project, self.registry, 'candidate-key', self.baseline,
                    self.entry, expected_reference_sha256=digest(self.ref),
                    expected_build_policy_sha256=self.policy_sha,
                    expected_workflow_repository='owner/research-ci',
                    expected_workflow_repository_id=1234)

    def test_corpus_checksum_and_source_revision_mismatches_block(self):
        for field, changed in [
            ('corpus_sha256', '7' * 64),
            ('upstreams', {'SPHinXsys': 'c' * 40, 'SPHinXsim': 'b' * 40}),
            ('source_state', 'sha256-' + '8' * 64),
            ('package_checksum', '9' * 64),
        ]:
            with self.subTest(field=field):
                ref = dict(self.ref)
                ref[field] = changed
                entry = {**self.entry, 'reference': ref,
                         'expected_reference_sha256': digest(ref)}
                validators = (SimpleNamespace(verify_baseline=Mock(return_value=self.report)),
                              SimpleNamespace(_research_parent_scope=Mock()),
                              SimpleNamespace(validate_reference=Mock(), release_locator=Mock()))
                with patch.object(registration, '_validators', return_value=validators):
                    with self.assertRaisesRegex(registration.RegistrationError,
                                                'BASELINE_REFERENCE_BINDING_MISMATCH'):
                        registration.prepare(self.project, self.registry, 'candidate-key',
                            self.baseline, entry,
                            expected_reference_sha256=digest(ref),
                            expected_build_policy_sha256=self.policy_sha,
                            expected_workflow_repository='owner/research-ci',
                            expected_workflow_repository_id=1234)

    def test_quality_upgrades_and_production_authorization_are_rejected(self):
        self.quality['status'] = 'QUALITY_ACCEPTED'
        self._json(self.baseline / 'quality.json', self.quality)
        validators = (SimpleNamespace(verify_baseline=Mock(return_value=self.report)),
                      SimpleNamespace(_research_parent_scope=Mock()),
                      SimpleNamespace(validate_reference=Mock(), release_locator=Mock()))
        with patch.object(registration, '_validators', return_value=validators):
            with self.assertRaisesRegex(registration.RegistrationError, 'QUALITY_STATUS_BINDING_MISMATCH'):
                registration.prepare(self.project, self.registry, 'candidate-key', self.baseline,
                    self.entry, expected_reference_sha256=digest(self.ref),
                    expected_build_policy_sha256=self.policy_sha,
                    expected_workflow_repository='owner/research-ci',
                    expected_workflow_repository_id=1234)

    def test_production_authorization_or_automatic_reuse_cannot_be_added(self):
        decision = {'quality_status': self.quality['status'],
                    'production_promotion': 'AUTHORIZED', 'automatic_reuse': False}
        self._json(self.baseline / 'research-decision.json', decision)
        validators = (SimpleNamespace(verify_baseline=Mock(return_value=self.report)),
                      SimpleNamespace(_research_parent_scope=Mock()),
                      SimpleNamespace(validate_reference=Mock(), release_locator=Mock()))
        with patch.object(registration, '_validators', return_value=validators):
            with self.assertRaisesRegex(registration.RegistrationError,
                                        'PRODUCTION_OR_AUTOMATIC_REUSE_RESTRICTION_MISMATCH'):
                registration.prepare(self.project, self.registry, 'candidate-key', self.baseline,
                    self.entry, expected_reference_sha256=digest(self.ref),
                    expected_build_policy_sha256=self.policy_sha,
                    expected_workflow_repository='owner/research-ci',
                    expected_workflow_repository_id=1234)


if __name__ == '__main__':
    unittest.main()
