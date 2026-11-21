"""Research handoff boundary tests; synthetic identity, no scientific replay."""
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from src import corpus_update_integration as integration
from src import research_corpus_selection as selection
import test_research_corpus_selection as fixtures


class ResearchGradioLoadingTests(unittest.TestCase):
    setUp = fixtures.SelectionTests.setUp

    def runtime(self, path, sha, *, queries):
        self.selected_path = Path(path)
        self.assertEqual(self.selected_path.read_bytes(), self.corpus.read_bytes())
        return {'corpus_path': str(path), 'sha256': sha, 'records': self.review.records,
                'retriever_class': 'src.retrieval_v1.RetrievalV1',
                'complete_records_equal': True, 'callbacks_share_assistant': True,
                'application_closed': True,
                'retrieval': [{'query': q, 'results': [{'chunk_id': 'fixture'}]} for q in queries]}

    def run_loading(self, **kwargs):
        return selection.verify_gradio_loading(self.review, self.corpus, self.root,
                                               queries=['test evidence'], **kwargs)

    def test_verified_selection_reaches_runtime_and_is_cleaned(self):
        original = self.corpus.read_bytes()
        with patch.object(integration, '_load_gradio', side_effect=self.runtime):
            result = self.run_loading()
        self.assertEqual(result['status'], 'RESEARCH_GRADIO_LOADING_VERIFIED')
        self.assertFalse(result['application_running'])
        self.assertFalse(result['hot_reload'])
        self.assertEqual(result['identity']['scope'], 'RESEARCH_LOADING_ONLY')
        self.assertIn('P8_BLOCKED', result['identity']['restrictions'])
        self.assertFalse(self.selected_path.exists())
        self.assertEqual(self.corpus.read_bytes(), original)

    def test_corrupt_artifact_never_reaches_application(self):
        self.corpus.write_bytes(b'corrupted')
        with patch.object(integration, '_load_gradio') as runtime:
            with self.assertRaises(selection.SelectionError):
                self.run_loading()
            runtime.assert_not_called()

    def test_missing_notices_is_not_bypassed(self):
        with patch.object(selection, 'verify', side_effect=selection.SelectionError('MANDATORY_NOTICES_REQUIRED')):
            with patch.object(integration, '_load_gradio') as runtime:
                with self.assertRaisesRegex(selection.SelectionError, 'MANDATORY_NOTICES_REQUIRED'):
                    self.run_loading()
                runtime.assert_not_called()

    def test_production_and_build_requests_never_load_app(self):
        for purpose in ['PRODUCTION_ACTIVATION', 'BUILD_CANDIDATE', 'PUBLISH']:
            with self.subTest(purpose=purpose), patch.object(integration, '_load_gradio') as runtime:
                with self.assertRaises(selection.SelectionError):
                    self.run_loading(purpose=purpose)
                runtime.assert_not_called()

    def test_failed_runtime_removes_owned_selection(self):
        def fail(path, sha, **kwargs):
            self.selected_path = Path(path)
            raise RuntimeError('Synthetic application failure')
        with patch.object(integration, '_load_gradio', side_effect=fail):
            with self.assertRaisesRegex(RuntimeError, 'Synthetic application failure'):
                self.run_loading()
        self.assertFalse(self.selected_path.exists())

    def test_wrong_loaded_identity_rejected_and_cleaned(self):
        def wrong(path, sha, **kwargs):
            return {**self.runtime(path, sha, **kwargs), 'records': 999}
        with patch.object(integration, '_load_gradio', side_effect=wrong):
            with self.assertRaisesRegex(selection.SelectionError, 'RESEARCH_RUNTIME_BINDING_MISMATCH'):
                self.run_loading()
        self.assertFalse(self.selected_path.exists())

    def test_unbounded_or_empty_queries_rejected_before_runtime(self):
        for queries in [[], ['x'] * 4, [' '], ['x' * 2049], 'not a query list']:
            with self.subTest(queries=repr(queries)[:50]), patch.object(integration, '_load_gradio') as runtime:
                with self.assertRaisesRegex(selection.SelectionError, 'BOUNDED_RESEARCH_QUERIES_REQUIRED'):
                    selection.verify_gradio_loading(self.review, self.corpus, self.root, queries=queries)
                runtime.assert_not_called()

    def test_child_does_not_receive_provider_writer_or_proxy_credentials(self):
        captured = {}
        def child(args, **kwargs):
            captured.update(kwargs)
            self.assertIn('socket.sendto', args[3])
            self.assertIn('subprocess.Popen', args[3])
            self.assertEqual(json.loads(args[-1]), ['test evidence'])
            class Result:
                returncode, stdout = 0, '{}'
            return Result()
        with patch.dict(os.environ, {'GH_TOKEN': 'synthetic', 'PARENT_AUTHORITY_AUDIT_TOKEN': 'synthetic',
                                    'LLM_API_KEY': 'synthetic', 'HTTPS_PROXY': 'synthetic'}):
            with patch.object(integration.subprocess, 'run', side_effect=child):
                integration._load_gradio(self.corpus, self.review.corpus_sha256, queries=['test evidence'])
        env = captured['env']
        for name in ('GH_TOKEN', 'PARENT_AUTHORITY_AUDIT_TOKEN', 'LLM_API_KEY', 'HTTPS_PROXY'):
            self.assertNotIn(name, env)
        self.assertEqual(env['SPHINX_CORPUS_PATH'], str(self.corpus))
        self.assertEqual(env['GRADIO_ANALYTICS_ENABLED'], 'False')
        self.assertEqual(captured['timeout'], 60)
        self.assertFalse(Path(env['GRADIO_TEMP_DIR']).exists())


if __name__ == '__main__':
    unittest.main()
