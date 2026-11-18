"""L2-A parser/routing fixtures only; no publication, authority or Registry writes."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

import test_register_trusted_baseline_cli as fixtures
from scripts import register_trusted_baseline as cli
from src import local_candidate_evidence as local, hosted_registration as hosted
from src.corpus_snapshot import digest


class LocalRegistrationRequestTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.RegistrationCLITests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.addCleanup(self.f.tearDown)
        self.hosted_request = deepcopy(self.f.request)
        r = self.f.request
        r['schema_version'] = 3
        r.pop('candidate_release')
        r.pop('expected_candidate_release_sha256')
        r.pop('expected_build_policy_sha256')
        r['proposed_entry'] = {'entry_kind': 'REGISTRATION_ONLY',
            'reference': r['proposed_entry']['reference'],
            'expected_reference_sha256': r['expected_reference_sha256']}
        ref = r['proposed_entry']['reference']
        r['local_evidence'] = dict(evidence_origin='LOCAL_RESEARCH_EXECUTION',
            hosted_validation='HOSTED_NOT_RUN', candidate_id=self.f.f.upstream_report['candidate_id'],
            baseline_id=ref['node_id'], corpus_sha256=ref['corpus_sha256'],
            descriptor_sha256='a' * 64, archive_sha256='b' * 64)
        self.f.write_request()

    def pin_reference(self):
        ref = self.f.request['proposed_entry']['reference']
        sha = digest(ref)
        self.f.request['expected_reference_sha256'] = sha
        self.f.request['proposed_entry']['expected_reference_sha256'] = sha
        self.f.write_request()

    def use_v3(self):
        ref = self.f.request['proposed_entry']['reference']
        ref['schema_version'] = 3
        store = dict(ref['storage'], asset_id=ref['storage']['asset_id'] + 1000,
                     asset_name='notices.zip', asset_size=100)
        ref['notices'] = dict(schema_version=1, baseline_id=ref['node_id'],
            parent_transport_sha256=ref['transport_sha256'], sha256='c' * 64, storage=store)
        self.pin_reference()

    def load(self):
        return cli.load_request(self.f.path, self.f.sha)[0]

    def test_closed_local_request_parses_without_verification_or_authority(self):
        with patch.object(local, 'verify') as l1, patch.object(cli.evidence, 'verify') as original:
            self.assertEqual(self.load(), self.f.request)
        l1.assert_not_called()
        original.assert_not_called()

    def test_local_operations_are_blocked_before_any_backend(self):
        before = (self.f.isolation / 'registry.json').read_bytes()
        with patch.object(local, 'verify') as l1, patch.object(cli.evidence, 'verify') as original, \
                patch.object(cli.transaction, 'register') as transaction:
            for command in ('verify-subject', 'register'):
                code, result = self.f.call(command)
                self.assertEqual(code, 1)
                self.assertEqual(result['reason'], 'LOCAL_EVIDENCE_TRANSPORT_CONTRACT_NOT_FINALIZED')
                self.assertEqual(result['registration'], 'NOT_PERFORMED')
        l1.assert_not_called()
        original.assert_not_called()
        transaction.assert_not_called()
        self.assertEqual((self.f.isolation / 'registry.json').read_bytes(), before)

    def test_each_required_local_field_and_pin(self):
        original = deepcopy(self.f.request)
        for field in cli.LOCAL_REQUEST_FIELDS:
            self.f.request = deepcopy(original)
            del self.f.request[field]
            self.f.write_request()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load()
        for field in cli.LOCAL_EVIDENCE_FIELDS:
            self.f.request = deepcopy(original)
            del self.f.request['local_evidence'][field]
            self.f.write_request()
            with self.subTest(local_field=field), self.assertRaises(ValueError):
                self.load()
        for field in ('archive_sha256', 'descriptor_sha256'):
            for value in (None, '', 'not-a-pin', True):
                self.f.request = deepcopy(original)
                self.f.request['local_evidence'][field] = value
                self.f.write_request()
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.load()

    def test_mixed_unknown_and_self_approved_fields(self):
        original = deepcopy(self.f.request)
        for key in ('candidate_release', 'expected_candidate_release_sha256',
                    'expected_build_policy_sha256', 'approved', 'run_id', 'job_id', 'artifact_id'):
            for nested in (False, True):
                self.f.request = deepcopy(original)
                target = self.f.request['local_evidence'] if nested else self.f.request
                target[key] = True
                self.f.write_request()
                with self.subTest(key=key, nested=nested), self.assertRaises(ValueError):
                    self.load()

    def test_local_origin_and_exact_reference_bindings(self):
        original = deepcopy(self.f.request)
        for key, value in [('evidence_origin', 'GITHUB_ACTIONS'),
                ('hosted_validation', 'SUCCESS'), ('candidate_id', 'invalid'),
                ('baseline_id', 'sha256-' + '0' * 64), ('corpus_sha256', '0' * 64)]:
            self.f.request = deepcopy(original)
            self.f.request['local_evidence'][key] = value
            self.f.write_request()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.load()
        self.f.request = deepcopy(original)
        self.f.request['proposed_entry']['reference']['candidate_id'] = 'sha256-' + '0' * 64
        self.pin_reference()
        with self.assertRaises(ValueError):
            self.load()

    def test_local_request_requires_independent_raw_request_pin(self):
        self.f.path.write_bytes(self.f.path.read_bytes() + b' ')
        with self.assertRaisesRegex(cli.InputError, 'REQUEST_SHA256_MISMATCH'):
            self.load()

    def test_hosted_schemas_reject_local_fields(self):
        for version in (1, 2):
            self.f.request = deepcopy(self.hosted_request)
            if version == 2:
                self.f.request.pop('expected_build_policy_sha256')
                self.f.request['proposed_entry'] = {
                    'entry_kind': 'REGISTRATION_ONLY',
                    'reference': self.f.request['proposed_entry']['reference'],
                    'expected_reference_sha256': self.f.request['expected_reference_sha256']}
            self.f.request['schema_version'] = version
            self.f.write_request()
            self.assertEqual(self.load(), self.f.request)
            for field in ('local_evidence', 'descriptor_sha256', 'archive_sha256'):
                changed = deepcopy(self.f.request)
                changed[field] = {}
                self.f.write_request(json.dumps(changed).encode())
                with self.subTest(version=version, field=field), self.assertRaises(ValueError):
                    self.load()

    def test_hosted_failure_never_falls_back_to_local(self):
        self.f.request = deepcopy(self.hosted_request)
        self.f.write_request()
        with patch.object(cli.evidence, 'verify', side_effect=cli.evidence.VerificationError(
                'HOSTED_EVIDENCE_INVALID')) as original, patch.object(local, 'verify') as l1:
            code, result = self.f.call()
        self.assertEqual(code, 1)
        self.assertEqual(result['reason'], 'HOSTED_EVIDENCE_INVALID')
        original.assert_called_once()
        l1.assert_not_called()

    def test_v3_notices_parse_only_and_execution_remains_blocked(self):
        self.use_v3()
        self.assertEqual(self.load(), self.f.request)
        for version in (1, 2):
            self.f.request = deepcopy(self.hosted_request)
            if version == 2:
                self.f.request.pop('expected_build_policy_sha256')
                self.f.request['proposed_entry'] = {'entry_kind': 'REGISTRATION_ONLY',
                    'reference': self.f.request['proposed_entry']['reference'],
                    'expected_reference_sha256': self.f.request['expected_reference_sha256']}
            self.f.request['schema_version'] = version
            self.use_v3()
            self.assertEqual(self.load(), self.f.request)
            with patch.object(cli.evidence, 'verify') as backend:
                for command in ('verify-subject', 'register'):
                    code, result = self.f.call(command)
                    self.assertEqual(code, 1)
                    self.assertEqual(result['reason'], 'REFERENCE_V3_REGISTRATION_INTEGRATION_PENDING')
            backend.assert_not_called()

    def test_bad_v3_notices_and_v2_downgrade_rejected(self):
        self.use_v3()
        original = deepcopy(self.f.request)
        mutations = [lambda r: r.pop('notices'),
            lambda r: r['notices'].update(unexpected=True),
            lambda r: r['notices'].update(baseline_id='sha256-' + '0' * 64),
            lambda r: r['notices'].update(parent_transport_sha256='0' * 64),
            lambda r: r['notices']['storage'].update(repository_id=999),
            lambda r: r['notices']['storage'].update(release_id=999),
            lambda r: r['notices']['storage'].update(asset_id=r['storage']['asset_id']),
            lambda r: r['notices']['storage'].update(asset_name='not-notices.tar.gz'),
            lambda r: r['notices']['storage'].update(token='forbidden'),
            lambda r: r.update(schema_version=2)]
        for mutate in mutations:
            self.f.request = deepcopy(original)
            mutate(self.f.request['proposed_entry']['reference'])
            self.pin_reference()
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.load()

    def test_hosted_composition_rejects_preparation_requests_before_authorization(self):
        path = self.f.project / 'configs/local-request.json'
        path.write_bytes(self.f.path.read_bytes())
        deployment = dict(request_path='configs/local-request.json', request_sha256=self.f.sha,
                          approval_policy_path='configs/owner-policy.json')
        with patch.object(hosted, 'PROJECT', self.f.project), self.assertRaisesRegex(
                hosted.tx.TransactionError, 'LOCAL_EVIDENCE_TRANSPORT_CONTRACT_NOT_FINALIZED'):
            hosted._inputs(deployment)

    def test_hosted_composition_v3_stops_before_context_or_registry_copy(self):
        self.f.request = deepcopy(self.hosted_request)
        self.use_v3()
        path = self.f.project / 'configs/v3-request.json'
        path.write_bytes(self.f.path.read_bytes())
        deployment = dict(request_path='configs/v3-request.json', request_sha256=self.f.sha,
                          approval_policy_path='configs/owner-policy.json')
        with patch.object(hosted, 'PROJECT', self.f.project), self.assertRaisesRegex(
                hosted.tx.TransactionError, 'REFERENCE_V3_REGISTRATION_INTEGRATION_PENDING'):
            hosted._inputs(deployment)


if __name__ == '__main__':
    unittest.main()
