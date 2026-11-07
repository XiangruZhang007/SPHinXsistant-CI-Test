"""Real GroundedAnswerV1 on synthetic data; only negative cases inject faults."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
import builtins
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from src import synthetic_retriever_reload as reload_demo


def inventory(root):
    return {p.relative_to(root).as_posix(): (hashlib.sha256(p.read_bytes()).hexdigest(),
            p.stat().st_ino, p.stat().st_mtime_ns, p.stat().st_ctime_ns)
            for p in root.rglob('*') if p.is_file() and not p.is_symlink()}


class ReloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from src import grounded_answer_v1
        except ModuleNotFoundError as error:
            raise unittest.SkipTest('Real GroundedAnswerV1 dependency unavailable: ' + str(error))
        cls.grounded = grounded_answer_v1

    def setUp(self):
        self.demo = reload_demo.SyntheticReloadDemo()
        self.addCleanup(self.demo.close)
        self.root = self.demo.root
        self.before = inventory(self.root)

    def prime(self):
        self.assertEqual(self.demo.reload('v1')['status'], 'RELOADED')
        return self.demo.active_assistant

    def assert_working(self, assistant, version):
        self.assertIs(self.demo.active_assistant, assistant)
        self.assertEqual(self.demo.state()['loaded_version'], version)
        results = assistant.retriever.search(reload_demo.TOKENS[version])
        self.assertEqual([r.record['chunk_id'] for r in results], ['p93-' + version + '-primary'])
        self.assertEqual(inventory(self.root), self.before)

    def test_initial_v1_is_a_real_validated_assistant(self):
        result = self.demo.reload('v1')
        self.assertEqual(result['status'], 'RELOADED')
        self.assertEqual((result['selected_version'], result['loaded_version']), ('v1', 'v1'))
        self.assertIsInstance(self.demo.active_assistant, self.grounded.GroundedAnswerV1)
        self.assertEqual(result['validation']['records'], 2)
        self.assertEqual(result['validation']['evidence_chunk_id'], 'p93-v1-primary')
        self.assertIs(result['validation']['deterministic'], True)

    def test_selection_does_not_replace_existing_retriever(self):
        old = self.prime()
        result = self.demo.select('v2')
        self.assertEqual((result['selected_version'], result['loaded_version']), ('v2', 'v1'))
        self.assertIs(result['state_consistent'], False)
        self.assert_working(old, 'v1')
        self.assertEqual(old.retriever.search(reload_demo.TOKENS['v2']), [])

    def test_v2_replaces_instance_only_after_successful_validation(self):
        old = self.prime()
        validate = self.demo._validate
        candidates = []

        def observe(candidate, version):
            self.assertIs(self.demo.active_assistant, old)
            self.assertIsNot(candidate, old)
            self.assertIsInstance(candidate, self.grounded.GroundedAnswerV1)
            candidates.append(candidate)
            return validate(candidate, version)

        with patch.object(self.demo, '_validate', side_effect=observe):
            result = self.demo.reload('v2')
        self.assertEqual((result['selected_version'], result['loaded_version']), ('v2', 'v2'))
        self.assertIs(self.demo.active_assistant, candidates[0])
        self.assert_working(candidates[0], 'v2')
        self.assertEqual(old.retriever.records, reload_demo._records('v1'))

    def test_deterministic_version_specific_retrieval(self):
        for version in ('v1', 'v2'):
            result = self.demo.reload(version)
            self.assertEqual(result['status'], 'RELOADED')
            retriever = self.demo.active_assistant.retriever
            first = [(r.record['chunk_id'], r.score) for r in retriever.search(reload_demo.TOKENS[version])]
            second = [(r.record['chunk_id'], r.score) for r in retriever.search(reload_demo.TOKENS[version])]
            self.assertEqual(first, second)
            self.assertEqual(first[0][0], 'p93-' + version + '-primary')

    def test_initialization_failure_rolls_back_to_loaded_not_selected_version(self):
        old = self.prime()
        self.demo.select('v2')
        with patch.object(self.demo, '_initialize', side_effect=RuntimeError('Initialization failed')):
            result = self.demo.reload('v2')
        self.assertEqual(result['status'], 'RELOAD_FAILED')
        self.assertEqual(result['failure_stage'], 'INITIALIZE')
        self.assertEqual(result['rollback_result']['status'], 'RESTORED')
        self.assertEqual((result['selected_version'], result['loaded_version']), ('v1', 'v1'))
        self.assert_working(old, 'v1')

    def test_validation_failure_preserves_old_instance(self):
        old = self.prime()
        with patch.object(self.demo, '_validate', side_effect=ValueError('Validation failed')):
            result = self.demo.reload('v2')
        self.assertEqual(result['failure_stage'], 'VALIDATE')
        self.assertEqual(result['rollback_result']['status'], 'RESTORED')
        self.assert_working(old, 'v1')

    def test_constructor_success_with_wrong_records_is_rejected(self):
        old = self.prime()
        initialize = self.demo._initialize

        def wrong_records(version):
            candidate = initialize(version)
            candidate.retriever.records = list(reversed(candidate.retriever.records))
            return candidate

        with patch.object(self.demo, '_initialize', side_effect=wrong_records):
            result = self.demo.reload('v2')
        self.assertEqual(result['failure_stage'], 'VALIDATE')
        self.assertIn('records/content mismatch', result['error'])
        self.assert_working(old, 'v1')

    def test_constructor_success_with_wrong_retrieval_is_rejected(self):
        old = self.prime()
        initialize = self.demo._initialize

        def wrong_retrieval(version):
            candidate = initialize(version)
            candidate.retriever.search = lambda *args, **kwargs: []
            return candidate

        with patch.object(self.demo, '_initialize', side_effect=wrong_retrieval):
            result = self.demo.reload('v2')
        self.assertEqual(result['failure_stage'], 'VALIDATE')
        self.assertIn('evidence mismatch', result['error'])
        self.assert_working(old, 'v1')

    def test_rollback_target_tracks_last_successful_v2(self):
        self.demo.reload('v2')
        old = self.demo.active_assistant
        self.demo.select('v1')
        with patch.object(self.demo, '_initialize', side_effect=RuntimeError('Initialization failed')):
            result = self.demo.reload('v1')
        self.assertEqual((result['selected_version'], result['loaded_version']), ('v2', 'v2'))
        self.assertEqual(result['rollback_result']['status'], 'RESTORED')
        self.assert_working(old, 'v2')

    def test_rollback_failure_reports_divergence_and_preserves_working_instance(self):
        old = self.prime()
        switch = self.demo._workspace.switch

        def fail_rollback(version):
            if version == 'v1':
                raise OSError('Rollback failed')
            return switch(version)

        with patch.object(self.demo, '_initialize', side_effect=RuntimeError('Initialization failed')), \
                patch.object(self.demo._workspace, 'switch', side_effect=fail_rollback):
            result = self.demo.reload('v2')
        self.assertEqual(result['rollback_result']['status'], 'FAILED')
        self.assertIs(result['rollback_result']['selection_restored'], False)
        self.assertEqual((result['selected_version'], result['loaded_version']), ('v2', 'v1'))
        self.assertIs(result['state_consistent'], False)
        self.assert_working(old, 'v1')

    def test_exception_after_rollback_commit_reports_verified_actual_selection(self):
        old = self.prime()
        switch = self.demo._workspace.switch

        def rollback_commits_then_errors(version):
            result = switch(version)
            if version == 'v1':
                raise OSError('Rollback committed before error')
            return result

        with patch.object(self.demo, '_initialize', side_effect=RuntimeError('Initialization failed')), \
                patch.object(self.demo._workspace, 'switch', side_effect=rollback_commits_then_errors):
            result = self.demo.reload('v2')
        self.assertEqual(result['rollback_result']['status'], 'RESTORED_WITH_ERROR')
        self.assertIs(result['rollback_result']['selection_restored'], True)
        self.assertEqual(result['selected_version'], 'v1')
        self.assert_working(old, 'v1')

    def test_committed_with_error_prevents_initialization_and_recovers_selection(self):
        old = self.prime()
        with patch('os.fsync', side_effect=[OSError('Post-commit sync error'), None]), \
                patch.object(self.demo, '_initialize', side_effect=AssertionError('Must not initialize')) as initialize:
            result = self.demo.reload('v2')
        initialize.assert_not_called()
        self.assertEqual(result['switch_result']['status'], 'COMMITTED_WITH_ERROR')
        self.assertEqual(result['failure_stage'], 'SELECT')
        self.assertEqual(result['rollback_result']['status'], 'RESTORED')
        self.assert_working(old, 'v1')

    def test_rollback_committed_with_error_is_not_reported_as_clean_success(self):
        old = self.prime()
        with patch('os.fsync', side_effect=OSError('Post-commit sync error')):
            result = self.demo.reload('v2')
        self.assertEqual(result['rollback_result']['status'], 'RESTORED_WITH_ERROR')
        self.assertEqual(result['rollback_result']['switch_result']['durability'], 'NOT_CONFIRMED')
        self.assertIs(result['rollback_result']['selection_restored'], True)
        self.assert_working(old, 'v1')

    def test_precommit_switch_failure_preserves_selection_without_reinitialization(self):
        old = self.prime()
        with patch('os.replace', side_effect=OSError('Before commit')):
            result = self.demo.reload('v2')
        self.assertEqual(result['failure_stage'], 'SELECT')
        self.assertEqual(result['rollback_result']['status'], 'PRESERVED')
        self.assertEqual(result['selected_version'], 'v1')
        self.assert_working(old, 'v1')

    def test_initial_failure_does_not_claim_a_working_instance_or_rollback(self):
        with patch.object(self.demo, '_initialize', side_effect=RuntimeError('First initialization failed')):
            result = self.demo.reload('v1')
        self.assertIsNone(self.demo.active_assistant)
        self.assertIsNone(result['loaded_version'])
        self.assertEqual(result['selected_version'], 'v1')
        self.assertEqual(result['rollback_result']['status'], 'UNAVAILABLE')
        self.assertIs(result['state_consistent'], False)

    def test_entire_reload_transaction_is_serialized(self):
        self.prime()
        initialize = self.demo._initialize
        entered = threading.Event()
        release = threading.Event()
        later_entered = threading.Event()
        second_started = threading.Event()

        def held_initialize(version):
            if version == 'v2':
                entered.set()
                if not release.wait(timeout=5):
                    raise RuntimeError('Transaction test timed out')
            else:
                later_entered.set()
            return initialize(version)

        def later():
            second_started.set()
            return self.demo.reload('v1')

        with patch.object(self.demo, '_initialize', side_effect=held_initialize), ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.demo.reload, 'v2')
            try:
                self.assertTrue(entered.wait(timeout=5))
                second = pool.submit(later)
                self.assertTrue(second_started.wait(timeout=5))
                self.assertFalse(later_entered.wait(timeout=0.05))
                self.assertEqual(os.readlink(self.root / 'current'), 'v2/corpus.jsonl')
            finally:
                release.set()
            self.assertEqual(first.result(timeout=5)['status'], 'RELOADED')
            self.assertEqual(second.result(timeout=5)['status'], 'RELOADED')
        self.assertEqual((self.demo.state()['selected_version'], self.demo.state()['loaded_version']), ('v1', 'v1'))

    def test_direct_p92_switch_is_also_excluded_during_reload(self):
        self.prime()
        initialize = self.demo._initialize
        entered = threading.Event()
        release = threading.Event()
        switched = threading.Event()

        def held_initialize(version):
            entered.set()
            if not release.wait(timeout=5):
                raise RuntimeError('Transaction test timed out')
            return initialize(version)

        def direct_switch():
            result = self.demo._workspace.switch('v1')
            switched.set()
            return result

        with patch.object(self.demo, '_initialize', side_effect=held_initialize), ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.demo.reload, 'v2')
            try:
                self.assertTrue(entered.wait(timeout=5))
                second = pool.submit(direct_switch)
                self.assertFalse(switched.wait(timeout=0.05))
            finally:
                release.set()
            self.assertEqual(first.result(timeout=5)['status'], 'RELOADED')
            self.assertEqual(second.result(timeout=5)['status'], 'SWITCHED')
        self.assertEqual((self.demo.state()['selected_version'], self.demo.state()['loaded_version']), ('v1', 'v2'))

    def test_no_external_corpus_or_root_inputs(self):
        with self.assertRaises(TypeError):
            reload_demo.SyntheticReloadDemo(root=self.root)
        for version in ('../escape', '/tmp/corpus.jsonl', 'candidate', None):
            with self.subTest(version=version), self.assertRaises(ValueError):
                self.demo.reload(version)
        self.assertEqual(self.demo.state()['selection_status'], 'UNSELECTED')

    def test_workspace_cleanup(self):
        self.prime()
        self.demo.close()
        self.assertFalse(self.root.exists())

    def test_full_demo_uses_real_assistants_without_llm_client_or_environment_access(self):
        environment = dict(os.environ)
        with patch.object(self.grounded, 'OpenAI', side_effect=AssertionError('No LLM clients')) as client, \
                patch.object(self.grounded.GroundedAnswerV1, 'answer', side_effect=AssertionError('No synthesis')) as answer, \
                patch.object(self.grounded.LLMConfiguration, 'from_environment',
                             side_effect=AssertionError('No LLM configuration')) as configuration, \
                patch('socket.socket.connect', side_effect=AssertionError('No network')):
            result = reload_demo.run_demo()
        client.assert_not_called()
        answer.assert_not_called()
        configuration.assert_not_called()
        self.assertEqual(result['status'], 'DEMO_PASS')
        self.assertIs(result['workspace_cleaned'], True)
        self.assertIs(result['llm_api_called'], False)
        self.assertEqual(dict(os.environ), environment)
        cases = {r['case']: r for r in result['cases']}
        self.assertEqual(cases['initialization_failure']['result']['rollback_result']['status'], 'RESTORED')
        self.assertEqual(cases['validation_failure']['result']['rollback_result']['status'], 'RESTORED')
        self.assertEqual(cases['rollback_failure']['result']['rollback_result']['status'], 'FAILED')
        self.assertEqual(cases['committed_with_error']['result']['rollback_result']['status'], 'RESTORED_WITH_ERROR')

    def test_cli_runs_only_fixed_demonstration(self):
        project = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run([sys.executable, '-B', '-m', 'src.synthetic_retriever_reload'],
                cwd=temporary, env={**os.environ, 'PYTHONPATH': str(project)},
                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        report = json.loads(result.stdout)
        self.assertEqual(report['status'], 'DEMO_PASS')
        self.assertIs(report['workspace_cleaned'], True)


class EntryBoundaryTests(unittest.TestCase):
    def test_unavailable_dependency_is_reported_without_mock_fallback_or_workspace(self):
        original = builtins.__import__

        def missing(name, *args, **kwargs):
            if name.endswith('grounded_answer_v1'):
                raise ModuleNotFoundError("No module named 'openai'", name='openai')
            return original(name, *args, **kwargs)

        output = io.StringIO()
        with patch('builtins.__import__', side_effect=missing), \
                patch.object(reload_demo, 'TestWorkspace', side_effect=AssertionError('No workspace without dependencies')), \
                redirect_stdout(output):
            code = reload_demo.main([])
        self.assertEqual(code, 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result['status'], 'DEPENDENCY_UNAVAILABLE')
        self.assertEqual(result['dependency'], 'openai')

    def test_cli_rejects_production_and_external_options(self):
        for arguments in (['--root', '/tmp/anywhere'], ['--corpus', '/tmp/anywhere'], ['--production']):
            with self.subTest(arguments=arguments), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(reload_demo.main(arguments), 2)
                self.assertEqual(json.loads(output.getvalue())['status'], 'ERROR')


if __name__ == '__main__':
    unittest.main()
