"""Isolated transaction tests. All successful authority is explicitly simulated."""
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import test_owner_manual_baseline_approval as fixtures
from src import baseline_registration_transaction as tx
from src import trusted_baseline_registration as preflight
from src.corpus_snapshot import digest, file_digest


class Crash(BaseException):
    """Simulate process termination without ordinary exception recovery."""


class RegistrationTransactionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = f = fixtures.OwnerManualBaselineApprovalTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.isolation = f.root / 'isolated'
        self.isolation.mkdir()
        self.copy = self.isolation / 'registry.json'
        self.copy.write_bytes(f.registry_before)
        f.ref['transport_sha256'] = '7' * 64
        f.entry['expected_reference_sha256'] = digest(f.ref)
        f.context['dispatch_inputs'] = f._dispatch_inputs()
        self.subject = {
            'schema_version': 1, 'purpose': 'TRUSTED_RESEARCH_PARENT_REGISTRATION',
            'registry_key': 'candidate-c2', 'registry_entry': f.entry,
            'registry_entry_sha256': digest(f.entry),
            'expected_old_registry_sha256': file_digest(f.registry),
            'approval_policy_sha256': f.policy_sha,
            'candidate_release': {'schema_version': 1, 'assets': {
                name: {'storage': {'synthetic': True}, 'sha256': '7' * 64}
                for name in tx.evidence.ASSETS}},
            'candidate': {'candidate_id': f.report['candidate_id'],
                'corpus_sha256': f.ref['corpus_sha256'], 'source_state': f.ref['source_state'],
                'generation': 2, 'upstreams': f.ref['upstreams'], 'parent_id': 'sha256-' + 'b' * 64,
                'build_fingerprint': f.ref['build_fingerprint'], 'benchmark_sha256': 'd' * 64,
                'quality_status': f.report['quality_status'], 'q1_status': f.report['q1_status']},
            'baseline': {'baseline_id': f.ref['node_id'], 'reference_sha256': digest(f.ref),
                'p4_1_verification': 'P4_1_VERIFIED', 'q1_status': f.report['q1_status']},
            'parent_r2_anchor': {**{k: '8' * 64 for k in tx.evidence.ANCHOR_FIELDS},
                'candidate_id': f.report['candidate_id'], 'baseline_id': f.ref['node_id']},
            'execution': 'NO_FRESH_REPLAY', 'production_promotion': 'NOT_AUTHORIZED',
        }
        self.subject['candidate_release_reference_sha256'] = digest(self.subject['candidate_release'])
        self.arguments = dict(registry_key='candidate-c2', proposed_entry=f.entry,
            candidate_release=self.subject['candidate_release'],
            expected_candidate_release_sha256=self.subject['candidate_release_reference_sha256'],
            expected_reference_sha256=digest(f.ref), expected_build_policy_sha256=f.entry['build_policy_sha256'],
            expected_registry_sha256=file_digest(f.registry), approval_policy_path=f.policy_path,
            approval_policy_sha256=f.policy_sha, token='synthetic-secret')
        self.sync_subject()
        self.baseline_paths = []
        self.candidates = {f.ref['node_id']: f.report['candidate_id']}
        self.calls = []
        for p in (
            patch.object(tx, '_trusted_dispatch_context', return_value=f.context),
            patch.object(tx.evidence, 'verify', side_effect=self.verify_evidence),
            patch.object(tx.owner, 'GitHubCLI', return_value=f.client),
            patch.object(tx.transport, 'download', side_effect=self.download),
            patch.object(tx.transport, 'restore', side_effect=self.restore),
            patch.object(tx.transport, 'validate_reference', side_effect=self.validate_reference),
            patch.object(preflight, 'prepare', side_effect=self.prepare),
        ):
            p.start()
            self.addCleanup(p.stop)
        self.protected_hash = file_digest(tx.PROJECT / 'configs/ci_v2_schema2_trusted_baselines.json')

    def sync_subject(self):
        self.fixture.context['dispatch_inputs']['registration_subject_sha256'] = digest(self.subject)

    def tearDown(self):
        self.assertEqual(self.fixture.registry.read_bytes(), self.fixture.client.registry_raw)
        self.assertEqual(file_digest(tx.PROJECT / 'configs/ci_v2_schema2_trusted_baselines.json'),
                         self.protected_hash)
        for p in self.baseline_paths:
            self.assertFalse(p.exists())

    def verify_evidence(self, *a, **kw):
        self.calls.append('candidate-verification')
        return {'status': 'EVIDENCE_VERIFIED', 'execution': 'NO_FRESH_REPLAY',
                'registration_subject': deepcopy(self.subject),
                'registration_subject_sha256': digest(self.subject)}

    def validate_reference(self, ref, pin, **kw):
        if digest(ref) != pin:
            raise ValueError('bad test pin')

    def download(self, locator, path, expected, **kw):
        Path(path).write_bytes(b'synthetic archive')

    def restore(self, project, archive, destination, ref, pin):
        self.assertEqual(digest(ref), pin)
        destination.mkdir()
        self.baseline_paths.append(destination)
        if ref['package_format'] != 'p2-snapshot-v1':
            fixtures.OwnerManualBaselineApprovalTests._write_json(
                destination / 'upstream-candidate.json', {'candidate_id': self.candidates.get(ref['node_id'])})

    def prepare(self, project, registry, key, baseline, entry, **kw):
        self.assertTrue((baseline / 'upstream-candidate.json').is_file())
        self.assertNotEqual(baseline, self.fixture.baseline)
        self.calls.append('owner-preflight-with-restored-files')
        return self.fixture.report

    def run_registration(self, isolation=None):
        return tx.register(self.fixture.project, isolation or self.isolation, **self.arguments)

    def recover(self, transaction_id):
        return tx.recover(self.fixture.project, self.isolation, transaction_id=transaction_id)

    def add_history(self, entries, **metadata):
        f = self.fixture
        raw = tx._serialize({'schema_version': 2, 'baselines': entries, **metadata})
        f.registry.write_bytes(raw)
        f.client.registry_raw = raw
        self.copy.write_bytes(raw)
        self.arguments['expected_registry_sha256'] = tx._sha(raw)
        self.subject['expected_old_registry_sha256'] = tx._sha(raw)
        self.sync_subject()

    def historical(self, node='e', candidate='f', kind='schema2-research-baseline'):
        entry = deepcopy(self.fixture.entry)
        ref = entry['reference']
        ref.update(node_id='sha256-' + node * 64, package_format=kind, corpus_sha256=node * 64)
        self.candidates[ref['node_id']] = 'sha256-' + candidate * 64
        entry['expected_reference_sha256'] = digest(ref)
        return entry

    def test_simulated_success_preserves_metadata_and_subject(self):
        history = {'p2': self.historical(kind='p2-snapshot-v1'),
                   'previous': self.historical('0', '9')}
        self.add_history(history, note='preserved', status='unchanged')
        before = self.copy.read_bytes()
        result = self.run_registration()
        self.assertEqual(result['status'], 'COMPLETED', result)
        self.assertTrue(result['registry_committed'])
        current = json.loads(self.copy.read_bytes())
        self.assertEqual(current, {**json.loads(before), 'baselines': {**history, 'candidate-c2': self.fixture.entry}})
        self.assertEqual(self.calls.count('candidate-verification'), 1)
        self.assertEqual(self.calls.count('owner-preflight-with-restored-files'), 2)
        tid = result['transaction_id']
        audit = json.loads((self.isolation / (tid + '.prepared.json')).read_bytes())
        self.assertEqual(audit['registration_subject'], self.subject)
        self.assertEqual(audit['owner_approval']['workflow_run']['actor_id'], 2)
        self.assertEqual(audit['execution'], 'NO_FRESH_REPLAY')
        self.assertEqual(audit['production_promotion'], 'NOT_AUTHORIZED')
        self.assertFalse(any(self.isolation.glob('*.tmp')))

    def test_unconfigured_real_execution_blocks_even_with_github_environment(self):
        # Restore the actual deny-by-default boundary despite otherwise valid API fixtures.
        def unavailable():
            raise tx.TransactionError('TRUSTED_WORKFLOW_EXECUTION_NOT_ESTABLISHED')
        before = self.copy.read_bytes()
        with patch.object(tx, '_trusted_dispatch_context', side_effect=unavailable), \
                patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch'}):
            result = self.run_registration()
        self.assertEqual(result['reason'], 'TRUSTED_WORKFLOW_EXECUTION_NOT_ESTABLISHED')
        self.assertEqual(self.copy.read_bytes(), before)
        self.assertEqual(self.calls, [])

    def test_missing_wrong_stale_or_unauthorized_approval(self):
        for mutation in ('missing', 'wrong', 'actor', 'stale'):
            f = self.fixture
            context, run = deepcopy(f.context), deepcopy(f.client.run)
            if mutation == 'missing':
                f.context['dispatch_inputs'].pop('registration_subject_sha256')
            elif mutation == 'wrong':
                f.context['dispatch_inputs']['registration_subject_sha256'] = '0' * 64
            elif mutation == 'actor':
                f.client.run['actor']['id'] = 99
            else:
                f.client.run['head_sha'] = 'd' * 40
            with self.subTest(case=mutation):
                before = self.copy.read_bytes()
                result = self.run_registration()
                self.assertEqual(result['status'], 'BLOCKED', result)
                self.assertEqual(self.copy.read_bytes(), before)
            f.context.clear(); f.context.update(context)
            f.client.run = run

    def test_stale_registry_and_incorrect_evidence_subject(self):
        self.arguments['expected_registry_sha256'] = '0' * 64
        self.assertEqual(self.run_registration()['status'], 'BLOCKED')
        self.arguments['expected_registry_sha256'] = file_digest(self.copy)
        self.subject['candidate']['corpus_sha256'] = '0' * 64
        self.sync_subject()
        self.assertEqual(self.run_registration()['status'], 'BLOCKED')
        self.assertEqual(self.copy.read_bytes(), self.fixture.client.registry_raw)

    def test_duplicate_key_baseline_candidate_and_conflicting_bindings(self):
        cases = [({'candidate-c2': self.historical()}, 'DUPLICATE_REGISTRY_KEY'),
                 ({'other': self.fixture.entry}, 'DUPLICATE_BASELINE_ID'),
                 ({'other': self.historical(node='d', candidate='a')}, 'DUPLICATE_CANDIDATE_ID')]
        conflict = deepcopy(self.fixture.entry)
        conflict['reference']['node_id'] = 'sha256-' + 'e' * 64
        conflict['expected_reference_sha256'] = digest(conflict['reference'])
        self.candidates[conflict['reference']['node_id']] = 'sha256-' + 'f' * 64
        cases.append(({'other': conflict}, 'CONFLICTING_CANDIDATE_BINDING'))
        for entries, reason in cases:
            self.add_history(entries)
            with self.subTest(reason=reason):
                result = self.run_registration()
                self.assertEqual(result['reason'], reason, result)
                self.assertEqual(self.copy.read_bytes(), self.fixture.client.registry_raw)

    def test_missing_historical_candidate_evidence_blocks(self):
        old = self.historical()
        self.add_history({'legacy': old})
        self.candidates.pop(old['reference']['node_id'])
        result = self.run_registration()
        self.assertEqual(result['reason'], 'HISTORICAL_CANDIDATE_IDENTITY_UNAVAILABLE')

    def test_failed_restoration_leaves_no_registry_changes(self):
        with patch.object(tx.transport, 'restore', side_effect=ValueError('bad evidence')):
            self.assertEqual(self.run_registration()['status'], 'BLOCKED')
        self.assertEqual(self.copy.read_bytes(), self.fixture.client.registry_raw)

    def test_protected_directory_symlinks_hardlinks_and_nondedicated_root(self):
        self.assertEqual(self.run_registration(self.fixture.configs)['status'], 'BLOCKED')
        self.copy.unlink()
        for mode in ('symlink', 'hardlink'):
            if mode == 'symlink':
                self.copy.symlink_to(self.fixture.registry)
            else:
                os.link(self.fixture.registry, self.copy)
            with self.subTest(mode=mode):
                self.assertEqual(self.run_registration()['status'], 'BLOCKED')
            self.copy.unlink()
        self.copy.write_bytes(self.fixture.client.registry_raw)
        link = self.fixture.root / 'alias'
        link.symlink_to(self.isolation, target_is_directory=True)
        self.assertEqual(self.run_registration(link)['status'], 'BLOCKED')
        (self.isolation / 'unrelated').write_text('unrelated')
        self.assertEqual(self.run_registration()['status'], 'BLOCKED')

    def test_concurrent_registration_is_rejected_and_lock_is_stable(self):
        entered, release = threading.Event(), threading.Event()
        original = self.verify_evidence
        def wait(*a, **kw):
            entered.set()
            if not release.wait(5):
                raise RuntimeError('test timeout')
            return original(*a, **kw)
        outcomes = []
        with patch.object(tx.evidence, 'verify', side_effect=wait):
            thread = threading.Thread(target=lambda: outcomes.append(self.run_registration()))
            thread.start()
            try:
                self.assertTrue(entered.wait(5))
                inode = (self.isolation / tx.LOCK).stat().st_ino
                second = self.run_registration()
                self.assertEqual(second['reason'], 'TRANSACTION_BUSY')
            finally:
                release.set()
                thread.join(5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(outcomes[0]['status'], 'COMPLETED', outcomes)
        self.assertEqual((self.isolation / tx.LOCK).stat().st_ino, inode)

    def test_interruption_before_prepared_does_not_commit(self):
        with patch.object(tx.evidence, 'verify', side_effect=Crash), self.assertRaises(Crash):
            self.run_registration()
        self.assertEqual(self.copy.read_bytes(), self.fixture.client.registry_raw)
        self.assertEqual(list(self.isolation.glob('*.prepared.json')), [])

    def test_interruption_after_prepared_blocks_retry_and_recovery_does_not_write(self):
        original = tx._stage
        def fail(fd, raw, prefix):
            if prefix == 'registry':
                raise Crash()
            return original(fd, raw, prefix)
        with patch.object(tx, '_stage', side_effect=fail), self.assertRaises(Crash):
            self.run_registration()
        tid = next(self.isolation.glob('*.prepared.json')).name[:64]
        self.assertEqual(self.run_registration()['reason'], 'UNRESOLVED_PREPARED_TRANSACTION')
        self.assertEqual(self.recover(tid)['status'], 'NOT_COMMITTED')
        self.assertEqual(self.recover(tid)['status'], 'NOT_COMMITTED')
        self.assertEqual(self.copy.read_bytes(), self.fixture.client.registry_raw)

    def test_replace_error_before_commit_preserves_registry(self):
        with patch.object(tx.os, 'replace', side_effect=OSError('failed')):
            result = self.run_registration()
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertFalse(result['registry_committed'])
        self.assertEqual(self.copy.read_bytes(), self.fixture.client.registry_raw)
        self.assertFalse(any(self.isolation.glob('.registry-*.tmp')))

    def test_replace_exception_after_commit_reports_actual_state(self):
        original = os.replace
        def committed(*a, **kw):
            original(*a, **kw)
            raise OSError('after commit')
        with patch.object(tx.os, 'replace', side_effect=committed):
            result = self.run_registration()
        self.assertEqual(result['status'], 'COMMITTED_WITH_ERROR', result)
        self.assertEqual(self.recover(result['transaction_id'])['status'], 'COMPLETED')

    def test_interruption_immediately_after_commit_and_repeated_recovery(self):
        original = os.replace
        def committed(*a, **kw):
            original(*a, **kw)
            raise Crash()
        with patch.object(tx.os, 'replace', side_effect=committed), self.assertRaises(Crash):
            self.run_registration()
        tid = next(self.isolation.glob('*.prepared.json')).name[:64]
        before = self.copy.read_bytes()
        first = self.recover(tid)
        completed = self.isolation / (tid + '.completed.json')
        stamp = completed.stat().st_mtime_ns
        second = self.recover(tid)
        self.assertEqual(first, second)
        self.assertEqual(first['status'], 'COMPLETED')
        self.assertEqual(completed.stat().st_mtime_ns, stamp)
        self.assertEqual(self.copy.read_bytes(), before)

    def test_audit_completion_failure_and_recovery_conflict_corruption(self):
        with patch.object(tx, '_complete', side_effect=OSError('audit disk error')):
            result = self.run_registration()
        self.assertEqual(result['status'], 'COMMITTED_WITH_ERROR')
        tid = result['transaction_id']
        new = self.copy.read_bytes()
        self.copy.write_bytes(new + b' ')
        self.assertEqual(self.recover(tid)['status'], 'CONFLICT')
        self.assertEqual(self.copy.read_bytes(), new + b' ')
        self.copy.write_bytes(new)
        record = self.isolation / (tid + '.prepared.json')
        record.write_bytes(record.read_bytes() + b'broken')
        self.assertEqual(self.recover(tid)['status'], 'BLOCKED')
        self.assertEqual(self.copy.read_bytes(), new)

    def test_missing_audit_cannot_be_recovered(self):
        self.assertEqual(self.recover('0' * 64)['status'], 'BLOCKED')
        self.assertEqual(self.copy.read_bytes(), self.fixture.client.registry_raw)

    def test_incomplete_subject_is_not_accepted_by_owner(self):
        self.subject['parent_r2_anchor'].pop('metrics_sha256')
        self.sync_subject()
        self.assertEqual(self.run_registration()['status'], 'BLOCKED')
        self.assertEqual(self.copy.read_bytes(), self.fixture.client.registry_raw)

    def test_commit_time_registry_inode_change_is_rejected(self):
        original = tx._approval
        count = 0
        def changed(*a, **kw):
            nonlocal count
            result = original(*a, **kw)
            count += 1
            if count == 2:
                tmp = self.isolation / '.registry-00000000000000000000000000000000.tmp'
                tmp.write_bytes(self.copy.read_bytes())
                os.replace(tmp, self.copy)
            return result
        with patch.object(tx, '_approval', side_effect=changed):
            result = self.run_registration()
        self.assertEqual(result['reason'], 'REGISTRY_CHANGED_BEFORE_COMMIT', result)
        self.assertEqual(self.copy.read_bytes(), self.fixture.client.registry_raw)

    def test_final_owner_recheck_failure_preserves_registry(self):
        original = tx._approval
        count = 0
        def fail(*a, **kw):
            nonlocal count
            count += 1
            if count == 2:
                raise tx.TransactionError('OWNER_APPROVAL_NOT_VERIFIED')
            return original(*a, **kw)
        with patch.object(tx, '_approval', side_effect=fail):
            result = self.run_registration()
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(self.copy.read_bytes(), self.fixture.client.registry_raw)
        self.assertEqual(self.recover(result['transaction_id'])['status'], 'NOT_COMMITTED')

    def test_directory_sync_failure_after_commit_and_recovery_error_are_reported(self):
        original = tx.os.fsync
        def fail(fd):
            if tx.stat.S_ISDIR(os.fstat(fd).st_mode) and self.copy.read_bytes() != self.fixture.client.registry_raw:
                raise OSError('directory sync failure')
            return original(fd)
        with patch.object(tx.os, 'fsync', side_effect=fail):
            result = self.run_registration()
            self.assertEqual(result['status'], 'COMMITTED_WITH_ERROR')
            recovery = self.recover(result['transaction_id'])
            self.assertEqual(recovery['status'], 'COMMITTED_WITH_ERROR')
            self.assertTrue(recovery['registry_committed'])
        self.assertEqual(self.recover(result['transaction_id'])['status'], 'COMPLETED')

    def test_audit_tampering_and_false_completion_are_rejected(self):
        result = self.run_registration()
        tid = result['transaction_id']
        prepared = self.isolation / (tid + '.prepared.json')
        original = prepared.read_bytes()
        record = json.loads(original)
        record['registration_subject']['candidate']['candidate_id'] = 'sha256-' + '0' * 64
        prepared.write_bytes(tx._serialize(record))
        self.assertEqual(self.recover(tid)['status'], 'BLOCKED')
        prepared.write_bytes(original)
        completed = self.isolation / (tid + '.completed.json')
        completed.write_bytes(b'{}\n')
        self.assertEqual(self.recover(tid)['status'], 'BLOCKED')

    def test_audit_publication_failure_before_commit_preserves_registry(self):
        with patch.object(tx, '_write_once', side_effect=OSError('cannot write prepared')):
            result = self.run_registration()
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(self.copy.read_bytes(), self.fixture.client.registry_raw)


class UnconfiguredExecutionTests(unittest.TestCase):
    def test_real_boundary_cannot_be_enabled_with_environment_or_saved_approval(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                                     'OWNER_APPROVED': 'true'}):
            with self.assertRaisesRegex(tx.TransactionError, 'TRUSTED_WORKFLOW_EXECUTION_NOT_ESTABLISHED'):
                tx._trusted_dispatch_context()


class EvidenceSessionIntegrationTests(unittest.TestCase):
    def test_real_evidence_pipeline_then_fresh_restore_and_owner_verification(self):
        # Reuse A's HTTP fixtures and actual transport/extraction/preflight.
        # Only qualification internals and execution trust are simulated.
        import test_published_candidate_verification as evidence_fixtures
        f = evidence_fixtures.PublishedCandidateVerificationTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.addCleanup(f.tearDown)
        f.registry = f.project / 'configs/trusted.json'
        f.registry.write_bytes(f.registry_bytes)
        policy = {
            'schema_version': 1, 'enabled': True, 'repository': f.repo['full_name'],
            'repository_id': f.repo['id'], 'default_branch': 'main',
            'workflow_path': '.github/workflows/approve_baseline.yml',
            'registry_path': 'configs/trusted.json', 'allow_repository_owner': True,
            'authorized_approver_ids': []}
        policy_path = f.project / 'configs/owner-policy.json'
        policy_path.write_bytes(tx._serialize(policy))
        policy_sha = file_digest(policy_path)
        verified = f.run_verification(approval_policy_sha256=policy_sha)
        client = fixtures.FakeGitHub()
        client.registry_raw = f.registry_bytes
        client.repository.update(id=f.repo['id'], full_name=f.repo['full_name'])
        client.run['repository'] = {'id': f.repo['id'], 'full_name': f.repo['full_name']}
        original_api = client.json
        client.json = lambda endpoint: original_api(endpoint.replace(f.repo['full_name'], 'acct/research-ci'))
        context = {'run_id': 9001, 'run_attempt': 1, 'actor_id': 2,
            'repository': f.repo['full_name'], 'repository_id': f.repo['id'],
            'head_sha': 'c' * 40, 'ref': 'refs/heads/main', 'dispatch_inputs': {
                'registry_key': 'proposed-baseline', 'baseline_id': f.ref['node_id'],
                'candidate_id': f.fixture.cid, 'corpus_sha256': f.ref['corpus_sha256'],
                'registry_entry_sha256': digest(f.entry),
                'registration_subject_sha256': verified['registration_subject_sha256']}}
        isolated = f.root / 'transaction'
        isolated.mkdir()
        (isolated / 'registry.json').write_bytes(f.registry_bytes)
        args = {k: value for k, value in f.arguments.items() if k != 'approval_policy_sha256'}
        with patch.object(tx, '_trusted_dispatch_context', return_value=context), \
                patch.object(tx.owner, 'GitHubCLI', return_value=client):
            result = tx.register(f.project, isolated, registry_key='proposed-baseline',
                proposed_entry=f.entry, approval_policy_path=policy_path,
                approval_policy_sha256=policy_sha, **args)
        self.assertEqual(result['status'], 'COMPLETED', result)
        self.assertEqual(result['execution'], 'NO_FRESH_REPLAY')
        self.assertEqual(f.registry.read_bytes(), f.registry_bytes)


if __name__ == '__main__':
    unittest.main()
