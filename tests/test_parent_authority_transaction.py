"""Synthetic private-core transactions; no cross-run backend or real permission."""
from copy import deepcopy
import hashlib
import json
import os
import unittest
from unittest.mock import patch

import test_hosted_parent_authority_transition as invocation
from src import parent_authority_transaction as core
from src import baseline_registration_transaction as tx
from src.corpus_snapshot import digest


class Interrupted(BaseException):
    pass


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.f = invocation.InvocationTests(); self.f.setUp(); self.addCleanup(self.f.doCleanups)
        self.project = self.f.root
        # Existing fixture root is the synthetic project; isolation is a sibling.
        import tempfile
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        from pathlib import Path
        self.work = Path(self.temp.name)
        self.authoritative = self.project / self.f.f.registry_path
        self.old = self.authoritative.read_bytes()
        (self.work / 'registry.json').write_bytes(self.old)
        self.proposal = self.f.proposal; self.observed = self.f.observe()
        self.kwargs = {'expected_proposal_sha256': digest(self.proposal),
                       '_revalidate': lambda: deepcopy(self.observed)}

    def apply(self, **extra):
        return core._local_apply(self.project, self.work, self.proposal, **{**self.kwargs, **extra})

    def inspect(self):
        return core._inspect_local_state(self.project, self.work, self.proposal,
                                         expected_proposal_sha256=digest(self.proposal))

    def test_private_synthetic_apply_exact_result_and_audits_only_in_isolation(self):
        result = self.apply(); self.assertEqual(result['status'], 'COMPLETED')
        self.assertEqual(hashlib.sha256((self.work / 'registry.json').read_bytes()).hexdigest(),
                         self.proposal['result_registry_sha256'])
        self.assertEqual(self.authoritative.read_bytes(), self.old)
        self.assertEqual(result['global_replay_protection'], 'NOT_ESTABLISHED')
        self.assertEqual(result['authorization'], 'NOT_GRANTED')
        tid = result['journal_id']
        self.assertTrue((self.work / (tid + '.prepared.json')).exists())
        self.assertTrue((self.work / (tid + '.completed.json')).exists())

    def test_completed_transaction_cannot_replay_in_same_persistent_directory(self):
        self.apply(); repeated = self.apply()
        self.assertEqual(repeated['reason'], 'DUPLICATE_TRANSACTION')
        # Existing new bytes are reported honestly; never a second write.
        self.assertEqual(repeated['status'], 'COMMITTED_WITH_ERROR')

    def test_local_single_use_journal_survives_process_restart(self):
        import subprocess
        import sys
        self.apply()
        proposal_path = self.project / 'review.json'
        proposal_path.write_text(json.dumps(self.proposal))
        script = '''import json,sys
from pathlib import Path
from src import parent_authority_transaction as core
from src.corpus_snapshot import digest
p=json.loads(Path(sys.argv[3]).read_text())
def forbidden(): raise AssertionError("must reject duplicate before reauthorization")
r=core._local_apply(Path(sys.argv[1]),Path(sys.argv[2]),p,expected_proposal_sha256=digest(p),_revalidate=forbidden)
print(json.dumps(r))
'''
        env = {**os.environ, 'PYTHONPATH': str(core.tx.PROJECT)}
        result = subprocess.run([sys.executable, '-B', '-c', script, str(self.project),
            str(self.work), str(proposal_path)], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['reason'], 'DUPLICATE_TRANSACTION')

    def test_interruption_after_prepared_does_not_retry_or_infer_completion(self):
        calls = 0
        def context():
            nonlocal calls
            calls += 1
            if calls == 2: raise Interrupted()
            return deepcopy(self.observed)
        with self.assertRaises(Interrupted): self.apply(_revalidate=context)
        self.assertEqual((self.work / 'registry.json').read_bytes(), self.old)
        self.assertEqual(self.inspect()['status'], 'PREPARED_NOT_APPLIED_REVIEW_REQUIRED')
        self.assertEqual(self.apply()['reason'], 'DUPLICATE_TRANSACTION')

    def test_partial_apply_failure_preserves_old_bytes_and_reservation(self):
        with patch.object(core.os, 'replace', side_effect=OSError): result = self.apply()
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual((self.work / 'registry.json').read_bytes(), self.old)
        self.assertEqual(self.apply()['reason'], 'DUPLICATE_TRANSACTION')

    def test_completion_persistence_failure_reports_commit_without_retry(self):
        original = tx._write_once
        def write(fd, name, raw):
            if name.endswith('.completed.json'): raise OSError()
            return original(fd, name, raw)
        with patch.object(tx, '_write_once', side_effect=write): result = self.apply()
        self.assertEqual(result['status'], 'COMMITTED_WITH_ERROR')
        self.assertTrue(result['registry_committed'])
        self.assertEqual(self.inspect()['status'], 'NEW_BYTES_PRESENT_REVIEW_REQUIRED')
        self.assertEqual(self.authoritative.read_bytes(), self.old)

    def test_raise_after_replace_readback_does_not_claim_no_commit(self):
        original = os.replace
        def uncertain(*args, **kwargs): original(*args, **kwargs); raise OSError()
        with patch.object(core.os, 'replace', side_effect=uncertain): result = self.apply()
        self.assertEqual(result['status'], 'COMMITTED_WITH_ERROR')
        self.assertTrue(result['registry_committed'])

    def test_concurrent_transaction_rejected_by_reused_dirfd_lock(self):
        with tx._locked(self.project, self.work, self.authoritative):
            with self.assertRaisesRegex(tx.TransactionError, 'TRANSACTION_BUSY'): self.apply()
        self.assertEqual(self.authoritative.read_bytes(), self.old)

    def test_registry_alias_symlink_and_project_output_are_rejected(self):
        with self.assertRaises(tx.TransactionError):
            core._local_apply(self.project, self.project, self.proposal, **self.kwargs)
        (self.work / 'registry.json').unlink(); os.link(self.authoritative, self.work / 'registry.json')
        with self.assertRaises(tx.TransactionError): self.apply()
        (self.work / 'registry.json').unlink(); (self.work / 'registry.json').symlink_to(self.authoritative)
        with self.assertRaises(tx.TransactionError): self.apply()
        self.assertEqual(self.authoritative.read_bytes(), self.old)

    def test_wrong_old_registry_or_result_or_owner_binding_is_rejected(self):
        (self.work / 'registry.json').write_bytes(b'{}')
        self.assertEqual(self.apply()['status'], 'STATE_UNCERTAIN')
        (self.work / 'registry.json').write_bytes(self.old)
        observed = {**self.observed, 'proposal_sha256': '0' * 64}
        result = self.apply(_revalidate=lambda: observed)
        self.assertEqual(result['reason'], 'TRUSTED_OBSERVATION_BINDING_MISMATCH')
        self.assertFalse(result['registry_committed'])

    def test_corrupt_prepared_audit_cannot_authenticate_new_registry_bytes(self):
        self.apply(); tid = core._id(self.proposal)
        path = self.work / (tid + '.prepared.json'); record = json.loads(path.read_text())
        record['evidence_sha256'] = '0' * 64; path.write_text(json.dumps(record))
        with self.assertRaises(ValueError): self.inspect()


if __name__ == '__main__':
    unittest.main()
