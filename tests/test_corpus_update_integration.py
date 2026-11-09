"""Complete evidence import plus synthetic post-gate mechanics; no fake approvals.

The real P8 is used for import/blocked tests. Reinitialization tests exercise
the private operation directly; they do not claim an authorized update.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

from src import corpus_update_integration as integration
from src.corpus_snapshot import read_json
from src.corpus_switching_test_session import TestWorkspace
from src.synthetic_retriever_reload import _records as synthetic_records
from test_update_eligibility_gate import fixture, put, seal


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'run'
        self.root.mkdir()
        def put_jsonl(root, name, value):
            if name.endswith('/corpus.jsonl'):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value) + '\n')
            else:
                put(root, name, value)

        # P8's metadata fixture deliberately uses pretty JSON even for .jsonl.
        # Use valid JSONL before it computes and seals all dependent bindings.
        with patch('test_update_eligibility_gate.put', side_effect=put_jsonl):
            fixture(self.root)
        self.workspace = TestWorkspace()
        self.addCleanup(self.workspace.close)
        self.no_load = patch.object(integration, '_load_gradio', side_effect=AssertionError('Must not load Gradio'))
        self.loader = self.no_load.start()
        self.addCleanup(self.no_load.stop)

    def check_blocked(self, artifact=None):
        before = self.workspace.current()
        result = integration._integrate(artifact or self.root, self.workspace)
        self.assertEqual(result['decision'], 'BLOCKED')
        self.assertEqual(result['activation'], 'DENIED')
        self.assertEqual(result['gradio_reinitialization'], 'NOT_ATTEMPTED')
        self.assertEqual(self.workspace.current(), before)
        self.assertTrue(result['selection_unchanged'])
        self.assertEqual(result['production_promotion'], 'NOT_AUTHORIZED')
        self.loader.assert_not_called()
        return result

    def test_valid_directory_uses_real_p8_and_p9_registration(self):
        result = self.check_blocked()
        self.assertEqual(result['artifact_integrity'], 'PASS')
        self.assertEqual(result['registration']['status'], 'STORED')
        version = result['bindings']['candidate_id']
        stored = self.workspace.root / version / 'corpus.jsonl'
        self.assertEqual(stored.read_bytes(), (self.root / 'candidate/corpus.jsonl').read_bytes())
        self.assertEqual(result['bindings']['corpus_sha256'], hashlib.sha256(stored.read_bytes()).hexdigest())
        self.assertIn('RELEASE_AUTHORIZATION_UNAVAILABLE', str(result['gate']['reasons']))

    def test_valid_zip_supported_without_extraction(self):
        archive = Path(self.tmp.name) / 'run.zip'
        with zipfile.ZipFile(archive, 'w') as z:
            for p in self.root.rglob('*'):
                if p.is_file():
                    z.write(p, 'run/' + p.relative_to(self.root).as_posix())
        self.assertEqual(self.check_blocked(archive)['artifact_integrity'], 'PASS')

    def test_blocked_preserves_existing_selection(self):
        integration._register(self.workspace, 'previous', b'{"chunk_id":"old"}\n',
                              hashlib.sha256(b'{"chunk_id":"old"}\n').hexdigest())
        self.workspace.switch('previous')
        before = os.readlink(self.workspace.root / 'current')
        self.check_blocked()
        self.assertEqual(os.readlink(self.workspace.root / 'current'), before)

    def test_corrupted_corpus_never_registered(self):
        (self.root / 'candidate/corpus.jsonl').write_bytes(b'corrupted')
        result = self.check_blocked()
        self.assertEqual(result['artifact_integrity'], 'FAIL')
        self.assertEqual(result['registration']['status'], 'NOT_ATTEMPTED')

    def test_resealed_identity_mismatch_rejected(self):
        candidate = read_json(self.root / 'candidate/candidate.json')
        candidate['candidate_id'] = 'sha256-' + '0' * 64
        put(self.root, 'candidate/candidate.json', candidate)
        seal(self.root / 'candidate')
        seal(self.root)
        self.assertEqual(self.check_blocked()['artifact_integrity'], 'FAIL')

    def test_missing_evidence_and_inspection_subset_blocked(self):
        (self.root / 'quality/quality-report.json').unlink()
        self.assertEqual(self.check_blocked()['artifact_integrity'], 'FAIL')
        subset = Path(self.tmp.name) / 'inspection'
        subset.mkdir()
        put(subset, 'result.json', {})
        self.assertEqual(self.check_blocked(subset)['artifact_integrity'], 'FAIL')

    def test_authorized_true_field_does_not_authorize(self):
        result = read_json(self.root / 'result.json')
        result['authorized'] = True
        put(self.root, 'result.json', result)
        seal(self.root)
        self.assertEqual(self.check_blocked()['artifact_integrity'], 'PASS')

    def test_missing_authorization_is_invalid_not_eligible(self):
        reference = read_json(self.root / 'trusted-reference.json')
        del reference['authorization']
        put(self.root, 'trusted-reference.json', reference)
        seal(self.root)
        self.assertEqual(self.check_blocked()['artifact_integrity'], 'FAIL')

    def test_blocking_only_gate_cannot_be_overridden_by_decision_alone(self):
        decision = integration.gate.evaluate(self.root)
        decision.update(decision='ELIGIBLE', reasons=[])
        with patch.object(integration.gate, 'evaluate', return_value=decision):
            self.check_blocked()

    def test_registration_failure_is_distinct_from_artifact_corruption(self):
        with patch.object(self.workspace, 'register', side_effect=OSError('Synthetic storage failure')):
            result = self.check_blocked()
        self.assertEqual(result['artifact_integrity'], 'PASS')
        self.assertEqual(result['registration']['status'], 'FAILED')

    def test_artifact_mutation_after_p8_is_rejected(self):
        original = integration.gate.evaluate

        def mutate(path):
            result = original(path)
            (self.root / 'candidate/corpus.jsonl').write_bytes(b'{"chunk_id":"replaced"}')
            return result

        with patch.object(integration.gate, 'evaluate', side_effect=mutate):
            result = self.check_blocked()
        self.assertEqual(result['artifact_integrity'], 'FAIL')
        self.assertIn('checksum mismatch', result['error'])

    def test_unsafe_zip_and_symlink_evidence_rejected(self):
        archive = Path(self.tmp.name) / 'unsafe.zip'
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr('../escape', 'bad')
        self.assertEqual(self.check_blocked(archive)['artifact_integrity'], 'FAIL')
        link = Path(self.tmp.name) / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        self.assertEqual(self.check_blocked(link)['artifact_integrity'], 'FAIL')
        self.assertFalse((Path(self.tmp.name) / 'escape').exists())

    def test_run_cleans_owned_store(self):
        workspace = TestWorkspace()
        root = workspace.root
        with patch.object(integration, 'TestWorkspace', return_value=workspace):
            result = integration.run(self.root)
        self.assertTrue(result['temporary_store_removed'])
        self.assertFalse(root.exists())

    def test_cli_json_exit_status_and_no_approval_options(self):
        command = [sys.executable, '-B', '-m', 'src.corpus_update_integration', '--artifact', str(self.root)]
        child = subprocess.run(command, cwd=integration.PROJECT, capture_output=True, text=True)
        self.assertEqual(child.returncode, 1)
        self.assertEqual(json.loads(child.stdout)['decision'], 'BLOCKED')
        for option in ('--authorize', '--force', '--root'):
            invalid = subprocess.run(command + [option, 'x'], cwd=integration.PROJECT,
                                     capture_output=True, text=True)
            self.assertNotEqual(invalid.returncode, 0)


class ReinitializationTests(unittest.TestCase):
    def setUp(self):
        self.workspace = TestWorkspace()
        self.addCleanup(self.workspace.close)
        for version in ('v1', 'v2'):
            raw = b''.join(json.dumps(r, sort_keys=True).encode() + b'\n' for r in synthetic_records(version))
            integration._register(self.workspace, version, raw, hashlib.sha256(raw).hexdigest())
        self.workspace.switch('v1')

    def summary(self, path, expected):
        return {'corpus_path': str(path), 'sha256': expected, 'records': 2,
                'complete_records_equal': True, 'callbacks_share_assistant': True,
                'retriever_class': 'src.retrieval_v1.RetrievalV1', 'application_closed': True}

    def test_real_gradio_callback_a_b_a_without_authorization_or_llm(self):
        first = integration._verify_loaded(self.workspace, 'v1', integration._load_gradio)
        second = integration._reinitialize(self.workspace, 'v2')
        third = integration._reinitialize(self.workspace, 'v1')
        self.assertEqual((second['status'], third['status']), ('TEST_REINITIALIZED', 'TEST_REINITIALIZED'))
        self.assertEqual(second['verified_loaded_version'], 'v2')
        self.assertEqual(third['verified_loaded_version'], 'v1')
        self.assertEqual(len({first['pid'], second['initialization']['pid'], third['initialization']['pid']}), 3)
        self.assertFalse(third['application_running'])

    def test_failed_initialization_reinitializes_previous_real_application(self):
        def initialize(path, expected):
            if path.parent.name == 'v2':
                raise RuntimeError('Synthetic initialization failure')
            return integration._load_gradio(path, expected)

        result = integration._reinitialize(self.workspace, 'v2', initialize)
        self.assertEqual(result['status'], 'REINITIALIZATION_FAILED')
        self.assertEqual(result['rollback']['status'], 'RESTORED')
        self.assertEqual(result['verified_loaded_version'], 'v1')
        self.assertEqual(result['selection']['version'], 'v1')
        self.assertTrue(result['rollback']['initialization']['complete_records_equal'])

    def test_failed_verification_restores_previous_real_application(self):
        def initialize(path, expected):
            if path.parent.name == 'v2':
                return {**self.summary(path, expected), 'sha256': '0' * 64}
            return integration._load_gradio(path, expected)

        result = integration._reinitialize(self.workspace, 'v2', initialize)
        self.assertIn('verification mismatch', result['error'])
        self.assertEqual(result['rollback']['status'], 'RESTORED')
        self.assertEqual(result['verified_loaded_version'], 'v1')

    def test_rollback_switch_failure_does_not_claim_health(self):
        original = self.workspace.switch

        def switch(version):
            if version == 'v1':
                raise OSError('Synthetic rollback failure')
            return original(version)

        with patch.object(self.workspace, 'switch', side_effect=switch):
            result = integration._reinitialize(self.workspace, 'v2',
                                               lambda *args: (_ for _ in ()).throw(ValueError('Fail target')))
        self.assertEqual(result['rollback']['status'], 'FAILED')
        self.assertEqual(result['selection']['version'], 'v2')
        self.assertIsNone(result['verified_loaded_version'])
        self.assertFalse(result['application_running'])

    def test_rollback_initialization_failure_does_not_claim_recovery(self):
        result = integration._reinitialize(self.workspace, 'v2',
                                           lambda *args: (_ for _ in ()).throw(ValueError('Fail initialization')))
        self.assertEqual(result['rollback']['status'], 'FAILED')
        self.assertEqual(result['selection']['version'], 'v1')
        self.assertIsNone(result['verified_loaded_version'])

    def test_committed_with_error_is_explicit_and_restored(self):
        original = self.workspace.switch

        def switch(version):
            result = original(version)
            return {**result, 'status': 'COMMITTED_WITH_ERROR', 'error': 'Synthetic post-commit failure'} if version == 'v2' else result

        with patch.object(self.workspace, 'switch', side_effect=switch):
            result = integration._reinitialize(self.workspace, 'v2', self.summary)
        self.assertIn('COMMITTED_WITH_ERROR', result['error'])
        self.assertEqual(result['rollback']['status'], 'RESTORED')
        self.assertEqual(result['selection']['version'], 'v1')

    def test_rollback_committed_with_error_is_not_clean_recovery(self):
        original = self.workspace.switch

        def switch(version):
            result = original(version)
            return {**result, 'status': 'COMMITTED_WITH_ERROR'} if version == 'v1' else result

        with patch.object(self.workspace, 'switch', side_effect=switch):
            result = integration._reinitialize(self.workspace, 'v2',
                                               lambda *args: (_ for _ in ()).throw(ValueError('Fail target')))
        self.assertEqual(result['rollback']['status'], 'FAILED')
        self.assertEqual(result['selection']['version'], 'v1')
        self.assertIsNone(result['verified_loaded_version'])

    def test_no_previous_selection_means_no_switch(self):
        with TestWorkspace() as empty, patch.object(empty, 'switch') as switch:
            with self.assertRaisesRegex(ValueError, 'previous selection'):
                integration._reinitialize(empty, 'v2', self.summary)
            switch.assert_not_called()

    def test_reinitialization_preserves_stored_corpus_and_metadata(self):
        files = [p for version in ('v1', 'v2') for p in (self.workspace.root / version).iterdir()]
        before = {str(p): (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino) for p in files}
        self.assertEqual(integration._reinitialize(self.workspace, 'v2', self.summary)['status'], 'TEST_REINITIALIZED')
        self.assertEqual(before, {str(p): (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ino) for p in files})

    def test_transaction_serializes_selection_and_initialization(self):
        entered = threading.Event()
        release = threading.Event()
        started = threading.Event()

        def initialize(path, expected):
            entered.set()
            self.assertTrue(release.wait(5))
            return self.summary(path, expected)

        def competing_switch():
            started.set()
            return self.workspace.switch('v1')

        with ThreadPoolExecutor(2) as pool:
            operation = pool.submit(integration._reinitialize, self.workspace, 'v2', initialize)
            try:
                self.assertTrue(entered.wait(5))
                other = pool.submit(competing_switch)
                self.assertTrue(started.wait(5))
                self.assertFalse(other.done())
            finally:
                release.set()
            self.assertEqual(operation.result()['status'], 'TEST_REINITIALIZED')
            self.assertEqual(other.result()['status'], 'SWITCHED')


if __name__ == '__main__':
    unittest.main()
