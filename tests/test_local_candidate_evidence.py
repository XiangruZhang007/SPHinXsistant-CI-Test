"""L1 contract tests: temporary records, mocked scientific validators, no builds.

The optional authentic closure test consumes a caller-prepared fixture index:
LOCAL_EVIDENCE_TEST_INDEX points to JSON with project/run/execution_records/
baseline/descriptor_path/reference_path and expected_descriptor_sha256. This
test-only index is not part of the verifier or an authorization mechanism.
"""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src import local_candidate_evidence as l
from src.corpus_snapshot import canonical, digest, file_digest


class LocalEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.run, self.records, self.baseline = (self.root / n for n in ('run', 'records', 'baseline'))
        for p in (self.run, self.records, self.baseline):
            p.mkdir()
        self.path = self.root / 'descriptor.json'
        self.refpath = self.root / 'reference.json'
        self.d = {k: 'a' * 64 for k in l.HASH_FIELDS}
        self.d.update({k: 'sha256-' + str(i) * 64
                       for i, k in enumerate(sorted(l.ID_FIELDS), 1)})
        self.d.update(schema_version=1, evidence_origin='LOCAL_RESEARCH_EXECUTION',
            hosted_validation='HOSTED_NOT_RUN', generation=1,
            upstreams={k: 'b' * 40 for k in l.provenance.REPOSITORIES})
        self.identity = dict(parent={'node_id': self.d['parent_id']},
            orchestration_fingerprint=self.d['orchestration_fingerprint'],
            policy_sha256=self.d['build_policy_sha256'])
        self.candidate = dict(provenance_type='GENUINE_UPSTREAM', generation=1,
            upstreams=self.d['upstreams'], target_source_state=self.d['source_state'])
        self.parity = dict(status='PARITY_PASS', candidate_id=self.d['candidate_id'])
        self.quality = dict(status='QUALITY_REVIEW_REQUIRED',
            policy={'benchmark_sha256': self.d['benchmark_sha256'], 'R2_fingerprint': {'fixture': True}})
        self.d['r2_contract_sha256'] = digest(self.quality['policy']['R2_fingerprint'])
        self.result = dict(hosted_validation='HOSTED_NOT_RUN', candidate_id=self.d['candidate_id'],
            baseline_id=self.d['parent_id'], automatic_research_approval=False,
            automatic_reuse=False, production_promotion='NOT_AUTHORIZED',
            bindings={'four_artifact_parity': self.parity})
        self.write(self.run, 'candidate/upstream-candidate.json', {'identity': self.identity})
        self.write(self.baseline, 'upstream-candidate.json', {'identity': self.identity})
        self.write(self.run, 'candidate/corpus.jsonl', {'fixture': 'no extraction performed'})
        self.d['corpus_sha256'] = file_digest(self.run / 'candidate/corpus.jsonl')
        for original, approved, value in [
                ('benchmark.json', 'benchmark.json', {'benchmark': 'test double'}),
                ('quality/quality-report.json', 'quality.json', self.quality),
                ('quality/incremental-raw-results.json', 'incremental-raw-results.json', []),
                ('quality/full-raw-results.json', 'full-raw-results.json', []),
                ('parent-raw-results.json', 'parent-raw-results.json', [])]:
            self.write(self.run, original, value)
            self.write(self.baseline, 'approval-evidence/' + approved, value)
        self.d['benchmark_sha256'] = file_digest(self.run / 'benchmark.json')
        self.quality['policy']['benchmark_sha256'] = self.d['benchmark_sha256']
        for root, name in [(self.run, 'quality/quality-report.json'),
                           (self.baseline, 'approval-evidence/quality.json')]:
            self.write(root, name, self.quality)
        self.write(self.run, 'build-policy.json', {'policy': 'test double'})
        self.d['build_policy_sha256'] = file_digest(self.run / 'build-policy.json')
        self.identity['policy_sha256'] = self.d['build_policy_sha256']
        self.write(self.run, 'candidate/upstream-candidate.json', {'identity': self.identity})
        self.write(self.baseline, 'upstream-candidate.json', {'identity': self.identity})
        for name in ('incremental', 'full'):
            self.write(self.run, 'execution-verification/' + name + '-replay.json', [])
        self.write(self.run, 'execution-verification/verification.json', dict(status='VERIFIED',
            candidate_corpus_sha256=self.d['corpus_sha256'], full_corpus_sha256=self.d['corpus_sha256']))
        self.write(self.run, 'q1-status.json', {'status': 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR'})
        self.write(self.run, 'parity.json', self.parity)
        self.write(self.run, 'full/manifest.json', {'fixture': True})
        self.write(self.run, 'result.json', self.result)
        ref = {'node_id': self.d['baseline_id']}
        self.write(self.root, 'reference.json', ref)
        self.d['reference_sha256'] = digest(ref)
        pref = {'node_id': self.d['parent_id'], 'package_format': 'schema2-research-baseline'}
        self.write(self.run, 'trusted-reference.json', pref)
        self.d['parent_reference_sha256'] = digest(pref)
        self.write(self.records, 'execution-start.json', {'command_count': 1})
        self.write(self.records, 'execution-exit.json',
                   dict(command_count=1, exit_code=0, automatic_retry=False))
        self.write(self.records, 'authorization.json', dict(
            approved_policy_sha256=self.d['build_policy_sha256'],
            target_upstreams=self.d['upstreams'], production_promotion='NOT_AUTHORIZED'))
        for name in ('executed-command.txt', 'execution.stdout.log', 'execution.stderr.log', 'report.md'):
            (self.records / name).write_bytes(b'test record; never executed')
        self.d['execution_records'] = {n: file_digest(self.records / n) for n in l.RECORD_FILES}
        self.write(self.baseline, 'approval-evidence/external-policy.json', {'p41': 'test double'})
        self.write(self.baseline, 'approval-evidence/checksums.json', {})
        self.d['approval_manifest_sha256'] = file_digest(self.baseline / 'approval-evidence/checksums.json')
        self.d['approval_policy_sha256'] = file_digest(self.baseline / 'approval-evidence/external-policy.json')
        self.d['quality_sha256'] = file_digest(self.run / 'quality/quality-report.json')
        self.d['candidate_rows_sha256'] = file_digest(self.run / 'quality/incremental-raw-results.json')
        self.reseal()
        self.approved = dict(status='P4_1_VERIFIED', mode='RETRIEVAL_EVALUATED',
            candidate_id=self.d['candidate_id'], parent_baseline_id=self.d['parent_id'],
            candidate_corpus_sha256=self.d['corpus_sha256'])
        self.anchor_receipt = dict(status='QUALIFIED', execution='NO_FRESH_REPLAY',
            reference_trust='CALLER_PINNED_REFERENCE', controlled_fixture=False,
            quality_acceptance='NOT_GRANTED', production_promotion='NOT_AUTHORIZED',
            bindings=dict(baseline_id=self.d['baseline_id'], candidate_id=self.d['candidate_id'],
                          parent_rows_sha256=self.d['candidate_rows_sha256']))
        self.mocks = {}
        for module, name, value in [(l.provenance, 'verify', self.candidate),
                (l.provenance, 'compare_full', self.parity),
                (l.trusted, 'validate_reference', None), (l.trusted, 'verify_package', {}),
                (l.approval, 'verify_bundle', self.approved),
                (l.anchor, 'qualify_parent_anchor', self.anchor_receipt)]:
            p = patch.object(module, name, return_value=value)
            self.mocks[name] = p.start()
            self.addCleanup(p.stop)
        p = patch.object(l.approval, 'replay', side_effect=AssertionError('No fresh replay'))
        p.start()
        self.addCleanup(p.stop)

    @staticmethod
    def write(root, name, value):
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(canonical(value))

    def reseal(self):
        for root, key in [(self.run, 'run_manifest_sha256'),
                          (self.baseline, 'baseline_manifest_sha256')]:
            checks = {p.relative_to(root).as_posix(): file_digest(p)
                      for p in root.rglob('*') if p.is_file() and p != root / 'checksums.json'}
            self.write(root, 'checksums.json', checks)
            self.d[key] = file_digest(root / 'checksums.json')

    def invoke(self, d=None):
        self.path.write_bytes(canonical(self.d if d is None else d))
        return l.verify(self.root, self.run, self.records, self.baseline, self.path,
            expected_descriptor_sha256=file_digest(self.path), reference_path=self.refpath)

    def test_success_preserves_restrictions_and_no_replay(self):
        before = {p: file_digest(p) for p in self.root.rglob('*') if p.is_file()}
        result = self.invoke()
        self.assertEqual(result['hosted_validation'], 'HOSTED_NOT_RUN')
        self.assertEqual(result['replay'], 'NO_FRESH_REPLAY')
        self.assertEqual(result['registration_authorization'], 'NOT_GRANTED')
        self.assertEqual(result['production_promotion'], 'NOT_AUTHORIZED')
        self.assertEqual(result['Q1'], 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
        self.assertEqual(result['P8'], 'BLOCKED')
        self.assertEqual(result, self.invoke())
        self.assertTrue(all(file_digest(p) == sha for p, sha in before.items()))
        self.assertIs(self.mocks['verify_bundle'].call_args.kwargs['fresh_replay'], False)
        self.assertIs(self.mocks['qualify_parent_anchor'].call_args.kwargs['fresh_replay'], False)

    def test_unknown_missing_and_hosted_fields(self):
        for name in ('approved', 'run_id', 'job_id', 'artifact_id', 'workflow_commit', 'approval'):
            d = copy.deepcopy(self.d)
            d[name] = True
            with self.subTest(name=name), self.assertRaises(l.EvidenceError):
                self.invoke(d)
        for name in self.d:
            d = copy.deepcopy(self.d)
            del d[name]
            with self.subTest(missing=name), self.assertRaises(l.EvidenceError):
                self.invoke(d)

    def test_version_origin_and_types(self):
        for name, value in [('schema_version', 2), ('schema_version', True),
                ('evidence_origin', 'GITHUB_ACTIONS'), ('hosted_validation', 'SUCCESS'),
                ('generation', True), ('generation', 0), ('upstreams', {}),
                ('candidate_id', 'bad'), ('execution_records', {})]:
            d = copy.deepcopy(self.d)
            d[name] = value
            with self.subTest(name=name, value=value), self.assertRaises(l.EvidenceError):
                self.invoke(d)

    def test_each_independent_pin_is_enforced(self):
        for name in l.HASH_FIELDS:
            d = copy.deepcopy(self.d)
            d[name] = '0' * 64
            # These are delegated to existing verifiers; simulate their rejection.
            delegated = {'reference_sha256': 'validate_reference',
                'parent_reference_sha256': 'qualify_parent_anchor', 'build_fingerprint': 'verify'}
            m = self.mocks.get(delegated.get(name))
            if m:
                m.side_effect = ValueError('secret must not escape')
            with self.subTest(name=name), self.assertRaises(l.EvidenceError) as error:
                self.invoke(d)
            self.assertNotIn('secret', str(error.exception))
            if m:
                m.side_effect = None

    def test_identity_mismatches(self):
        for name in (*l.ID_FIELDS, 'generation', 'upstreams'):
            d = copy.deepcopy(self.d)
            d[name] = {'SPHinXsys': '0' * 40, 'SPHinXsim': '0' * 40} if name == 'upstreams' else (
                2 if name == 'generation' else 'sha256-' + '0' * 64)
            with self.subTest(name=name), self.assertRaises(l.EvidenceError):
                self.invoke(d)

    def test_missing_or_corrupt_sealed_members(self):
        for name in ('full/manifest.json', 'parity.json', 'quality/incremental-raw-results.json'):
            p = self.run / name
            raw = p.read_bytes()
            p.unlink()
            with self.subTest(missing=name), self.assertRaises(l.EvidenceError):
                self.invoke()
            p.write_bytes(b'corrupt')
            with self.subTest(corrupt=name), self.assertRaises(l.EvidenceError):
                self.invoke()
            p.write_bytes(raw)

    def test_unsafe_member_and_root_alias(self):
        (self.run / 'link').symlink_to(self.run / 'result.json')
        with self.assertRaises(l.EvidenceError):
            self.invoke()
        (self.run / 'link').unlink()
        alias = self.root / 'alias'
        alias.symlink_to(self.run, target_is_directory=True)
        with self.assertRaises(l.EvidenceError):
            l._tree(alias)
        with self.assertRaises(l.EvidenceError):
            l._tree(alias / 'candidate')
        with self.assertRaises(l.EvidenceError):
            l._safe(self.run / '../run/result.json')

    def test_hard_link_rejected(self):
        os.link(self.run / 'result.json', self.run / 'hardlink')
        with self.assertRaises(l.EvidenceError):
            self.invoke()

    def test_oversized_and_duplicate_json(self):
        self.path.write_bytes(b' ' * (l.DESCRIPTOR_LIMIT + 1))
        with self.assertRaises(l.EvidenceError):
            l.load_descriptor(self.path, file_digest(self.path))
        self.path.write_bytes(b'{"schema_version":1,"schema_version":1}')
        with self.assertRaises(l.EvidenceError):
            l.load_descriptor(self.path, file_digest(self.path))
        self.path.write_bytes(canonical(self.d))
        with self.assertRaises(l.EvidenceError):
            l.load_descriptor(self.path, '0' * 64)
        with patch.object(l, 'FILE_LIMIT', 1), self.assertRaises(l.EvidenceError):
            self.invoke()

    def test_failed_scientific_verifiers_fail_closed(self):
        for name in ('verify', 'compare_full', 'verify_package', 'verify_bundle', 'qualify_parent_anchor'):
            m = self.mocks[name]
            m.side_effect = ValueError('Authorization: secret')
            with self.subTest(name=name), self.assertRaises(l.EvidenceError) as error:
                self.invoke()
            self.assertNotIn('secret', str(error.exception))
            m.side_effect = None

    def test_resealed_false_replay_and_parity_rejected(self):
        for name, value in [('parity.json', {'status': 'FAIL'}),
                ('execution-verification/full-replay.json', [{'altered': True}])]:
            p = self.run / name
            raw = p.read_bytes()
            self.write(self.run, name, value)
            self.reseal()
            with self.subTest(name=name), self.assertRaises(l.EvidenceError):
                self.invoke()
            p.write_bytes(raw)
        self.reseal()

    def test_changed_evidence_during_verification_rejected(self):
        def change(*args, **kwargs):
            (self.run / 'result.json').write_bytes(b'changed')
            return self.anchor_receipt
        self.mocks['qualify_parent_anchor'].side_effect = change
        with self.assertRaises(l.EvidenceError):
            self.invoke()

    def test_missing_p41_evidence(self):
        (self.baseline / 'approval-evidence/checksums.json').unlink()
        self.reseal()
        with self.assertRaises(l.EvidenceError):
            self.invoke()

    def test_mismatched_p41_receipt(self):
        for name, value in [('candidate_id', 'sha256-' + '0' * 64),
                ('parent_baseline_id', 'sha256-' + '0' * 64),
                ('candidate_corpus_sha256', '0' * 64), ('status', 'NOT_APPROVED'),
                ('mode', 'STRUCTURAL_ONLY')]:
            bad = {**self.approved, name: value}
            self.mocks['verify_bundle'].return_value = bad
            with self.subTest(name=name), self.assertRaises(l.EvidenceError):
                self.invoke()

    def test_record_pin_and_unsuccessful_execution(self):
        for name in l.RECORD_FILES:
            d = copy.deepcopy(self.d)
            d['execution_records'][name] = '0' * 64
            with self.subTest(name=name), self.assertRaises(l.EvidenceError):
                self.invoke(d)
        self.write(self.records, 'execution-exit.json',
                   dict(command_count=1, exit_code=1, automatic_retry=False))
        self.d['execution_records']['execution-exit.json'] = file_digest(self.records / 'execution-exit.json')
        with self.assertRaises(l.EvidenceError):
            self.invoke()


    def test_matching_failed_parity_objects_rejected(self):
        failed = {**self.parity, 'status': 'PARITY_FAIL'}
        self.mocks['compare_full'].return_value = failed
        self.write(self.run, 'parity.json', failed)
        self.write(self.run, 'result.json', {**self.result,
            'bindings': {'four_artifact_parity': failed}})
        self.reseal()
        with self.assertRaisesRegex(l.EvidenceError, '^FULL_PARITY_NOT_PASSED$'):
            self.invoke()

    def test_no_replay_does_not_establish_qualification(self):
        for status in ('PINNED_ANCHOR_INSPECTED', 'ARCHIVE_INTEGRITY_VERIFIED', 'BLOCKED', None):
            bad = {**self.anchor_receipt, 'status': status}
            for failed_call in (0, 1):
                receipts = [self.anchor_receipt, self.anchor_receipt]
                receipts[failed_call] = bad
                self.mocks['qualify_parent_anchor'].side_effect = receipts
                with self.subTest(status=status, failed_call=failed_call), self.assertRaisesRegex(
                        l.EvidenceError, '^PARENT_ANCHOR_NOT_QUALIFIED$'):
                    self.invoke()

    def test_anchor_restrictions_and_binding_required(self):
        for key, value in [('execution', 'FRESH_R2_REPLAY_VERIFIED'),
                ('reference_trust', 'ARCHIVE_INTEGRITY_ONLY'), ('controlled_fixture', True),
                ('quality_acceptance', 'ACCEPTED'), ('production_promotion', 'AUTHORIZED')]:
            for failed_call in (0, 1):
                receipts = [self.anchor_receipt, self.anchor_receipt]
                receipts[failed_call] = {**self.anchor_receipt, key: value}
                self.mocks['qualify_parent_anchor'].side_effect = receipts
                with self.subTest(key=key, failed_call=failed_call), self.assertRaises(l.EvidenceError):
                    self.invoke()
        for key in self.anchor_receipt['bindings']:
            bad = {**self.anchor_receipt,
                   'bindings': {**self.anchor_receipt['bindings'], key: 'wrong'}}
            self.mocks['qualify_parent_anchor'].side_effect = [self.anchor_receipt, bad]
            with self.subTest(binding=key), self.assertRaisesRegex(
                    l.EvidenceError, '^BASELINE_R2_ANCHOR_MISMATCH$'):
                self.invoke()

    def test_original_p2_inspection_is_not_qualified(self):
        pref = {'node_id': self.d['parent_id'], 'package_format': 'p2-snapshot-v1'}
        self.write(self.run, 'trusted-reference.json', pref)
        self.d['parent_reference_sha256'] = digest(pref)
        self.reseal()
        self.mocks['qualify_parent_anchor'].side_effect = [
            {**self.anchor_receipt, 'status': 'PINNED_ANCHOR_INSPECTED'}, self.anchor_receipt]
        receipt = self.invoke()
        self.assertEqual(receipt['original_parent_anchor_status'], 'PINNED_ANCHOR_INSPECTED')
        self.assertEqual(receipt['baseline_anchor_status'], 'QUALIFIED')


class AuthenticLocalEvidenceTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('LOCAL_EVIDENCE_TEST_INDEX'), 'Retained authentic closure not supplied')
    def test_authentic_closure_without_replay(self):
        index = json.loads(Path(os.environ['LOCAL_EVIDENCE_TEST_INDEX']).read_bytes())
        with patch.object(l.approval, 'replay', side_effect=AssertionError('Fresh replay prohibited')):
            receipt = l.verify(**index)
        self.assertEqual(receipt['status'], 'LOCAL_EVIDENCE_VERIFIED')
        self.assertEqual(receipt['hosted_validation'], 'HOSTED_NOT_RUN')
        self.assertEqual(receipt['replay'], 'NO_FRESH_REPLAY')
        self.assertEqual(receipt['baseline_anchor_status'], 'QUALIFIED')


if __name__ == '__main__':
    unittest.main()
