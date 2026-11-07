"""P9.3 built-in synthetic reload demonstration, not a production reload API.

Run with an existing Python environment that provides openai; the real
GroundedAnswerV1 constructor imports that SDK but does not construct a client.
Only constructor and local retrieval are used, never answer() or LLM settings.
There are no external corpus, workspace, server or authorization arguments.
P9.2's guard is held across the entire select/load/validate/publish/rollback
transaction. Selection and loaded state are distinct; only validated instances
replace the last working instance. All fixture files are temporary.
"""
from __future__ import annotations

import hashlib
import json
import sys
from unittest.mock import patch

from .corpus_snapshot import canonical
from .corpus_switching_test_session import TestWorkspace
from . import versioned_corpus_storage as storage

TOKENS = {'v1': 'amberanchor', 'v2': 'cobaltanchor'}


def _records(version):
    storage._need(isinstance(version, str) and version in TOKENS, 'Only built-in v1 and v2 fixtures are supported')
    records = []
    for name, content in [('primary', 'Synthetic evidence ' + TOKENS[version]),
                          ('reference', 'Unrelated synthetic reference material')]:
        records.append({'chunk_id': 'p93-' + version + '-' + name, 'repository': 'SPHinXsim',
            'source_role': 'documentation', 'source_path': 'repos/SPHinXsim/docs/p93_' + name + '.md',
            'chunk_type': 'documentation_section', 'node_type': 'section', 'symbol': None,
            'section_title': 'Synthetic ' + name, 'start_line': 1, 'end_line': 1,
            'byte_start': 0, 'byte_end': len(content.encode()), 'parent_context': {}, 'content': content})
    return records


class SyntheticReloadDemo:
    """A process-local demonstration owning exactly two internally defined fixtures."""

    def __init__(self):
        from .grounded_answer_v1 import GroundedAnswerV1
        self._assistant_type = GroundedAnswerV1
        self._workspace = TestWorkspace()
        self._assistant = None
        self._loaded_version = None
        self._expected = {}
        try:
            for version in TOKENS:
                raw = b''.join(canonical(r) + b'\n' for r in _records(version))
                # Pin the internally defined template bytes before writing a source.
                self._expected[version] = hashlib.sha256(raw).hexdigest()
                source = self._workspace.root / ('.synthetic-' + version + '.jsonl')
                source.write_bytes(raw)
                try:
                    self._workspace.register(version, source, self._expected[version])
                finally:
                    source.unlink()
        except BaseException:
            self._workspace.close()
            raise

    @property
    def root(self):
        return self._workspace.root

    @property
    def active_assistant(self):
        with self._workspace._guard():
            return self._assistant

    def _state(self):
        selection = self._workspace._actual_after_error()
        selected = selection.get('version')
        if selection['status'] == 'UNVERIFIED':
            selected = next((v for v in TOKENS if selection.get('target') == v + '/corpus.jsonl'), None)
        return {'selected_version': selected, 'loaded_version': self._loaded_version,
                'selection_status': selection['status'],
                'state_consistent': selection['status'] in {'CURRENT', 'UNSELECTED'}
                                    and selected == self._loaded_version,
                'selection': selection, 'test_only': True}

    def state(self):
        with self._workspace._guard():
            return self._state()

    def select(self, version):
        _records(version)
        with self._workspace._guard():
            result = self._workspace.switch(version)
            return {'status': 'SELECTED' if result['status'] == 'SWITCHED' else 'SELECTION_ERROR',
                    'switch_result': result, **self._state()}

    def _initialize(self, version):
        # A concrete version path cannot silently follow a later current switch.
        return self._assistant_type(self.root / version / 'corpus.jsonl')

    def _validate(self, assistant, version):
        retriever = assistant.retriever
        storage._need(retriever.corpus_path == self.root / version / 'corpus.jsonl', 'Loaded path mismatch')
        storage._need(retriever.records == _records(version), 'Loaded records/content mismatch')
        first = retriever.search(TOKENS[version], top_k=2)
        second = retriever.search(TOKENS[version], top_k=2)
        expected_id = 'p93-' + version + '-primary'
        storage._need(len(first) == 1 and first[0].record['chunk_id'] == expected_id and first[0].score > 0,
                      'Version-specific retrieval evidence mismatch')
        storage._need([(r.record, r.score) for r in first] == [(r.record, r.score) for r in second],
                      'Retrieval is not reproducible')
        other = next(v for v in TOKENS if v != version)
        storage._need(not retriever.search(TOKENS[other]), 'Unexpected evidence from another version')
        return {'records': len(retriever.records), 'query': TOKENS[version],
                'evidence_chunk_id': expected_id, 'deterministic': True}

    def _verified_selection(self, version):
        selection = self._workspace.current()
        storage._need(selection.get('version') == version and selection['metadata']['sha256'] == self._expected[version],
                      'Selected version/template checksum mismatch')

    def _rollback(self, previous):
        if previous is None:
            return {'status': 'UNAVAILABLE', 'selection_restored': False,
                    'reason': 'No previously loaded and validated instance exists'}
        switch = None
        try:
            state = self._state()
            if state['selection_status'] == 'CURRENT' and state['selected_version'] == previous:
                self._verified_selection(previous)
                return {'status': 'PRESERVED', 'selection_restored': True}
            switch = self._workspace.switch(previous)
            self._verified_selection(previous)
            return {'status': 'RESTORED' if switch['status'] == 'SWITCHED' else 'RESTORED_WITH_ERROR',
                    'selection_restored': True, 'switch_result': switch}
        except Exception as error:
            try:
                self._verified_selection(previous)
                restored = True
            except Exception:
                restored = False
            return {'status': 'RESTORED_WITH_ERROR' if restored else 'FAILED',
                    'selection_restored': restored, 'switch_result': switch, 'error': str(error)}

    def reload(self, version):
        _records(version)
        # Deliberately hold the workspace guard for the WHOLE transaction, also
        # excluding direct P9.2 API switching until commit or rollback finishes.
        with self._workspace._guard():
            previous, working = self._loaded_version, self._assistant
            stage = 'SELECT'
            switched = None
            try:
                switched = self._workspace.switch(version)
                storage._need(switched['status'] == 'SWITCHED', 'Selection returned COMMITTED_WITH_ERROR')
                self._verified_selection(version)
                stage = 'INITIALIZE'
                replacement = self._initialize(version)
                stage = 'VALIDATE'
                validation = self._validate(replacement, version)
                self._verified_selection(version)
                self._assistant, self._loaded_version = replacement, version
                return {'status': 'RELOADED', 'validation': validation,
                        'rollback_result': {'status': 'NOT_NEEDED'}, 'switch_result': switched, **self._state()}
            except Exception as error:
                self._assistant, self._loaded_version = working, previous
                rollback = self._rollback(previous)
                return {'status': 'RELOAD_FAILED', 'failure_stage': stage, 'error': str(error),
                        'rollback_result': rollback, 'switch_result': switched, **self._state()}

    def close(self):
        self._workspace.close()

    def __enter__(self):
        return self

    def __exit__(self, *error):
        self.close()


def run_demo():
    """Run fixed synthetic scenarios; fault injection never edits stored corpus bytes."""
    cases = []
    with SyntheticReloadDemo() as demo:
        root = demo.root
        cases.append({'case': 'initialize_v1', 'result': demo.reload('v1')})
        old = demo.active_assistant
        cases.append({'case': 'select_v2_without_reload', 'result': demo.select('v2'),
                      'old_instance_preserved': demo.active_assistant is old})
        cases.append({'case': 'reload_v2', 'result': demo.reload('v2')})
        demo.reload('v1')
        old = demo.active_assistant
        demo.select('v2')
        with patch.object(demo, '_initialize', side_effect=RuntimeError('Injected initialization failure')):
            result = demo.reload('v2')
        cases.append({'case': 'initialization_failure', 'result': result,
                      'old_instance_preserved': demo.active_assistant is old})
        demo.select('v2')
        with patch.object(demo, '_validate', side_effect=ValueError('Injected validation failure')):
            result = demo.reload('v2')
        cases.append({'case': 'validation_failure', 'result': result,
                      'old_instance_preserved': demo.active_assistant is old})
        switch = demo._workspace.switch

        def fail_rollback(version):
            if version == 'v1':
                raise OSError('Injected rollback failure')
            return switch(version)

        with patch.object(demo, '_initialize', side_effect=RuntimeError('Injected initialization failure')), \
                patch.object(demo._workspace, 'switch', side_effect=fail_rollback):
            result = demo.reload('v2')
        cases.append({'case': 'rollback_failure', 'result': result,
                      'old_instance_preserved': demo.active_assistant is old})
        demo.select('v1')
        with patch('os.fsync', side_effect=OSError('Injected post-commit sync failure')):
            result = demo.reload('v2')
        cases.append({'case': 'committed_with_error', 'result': result,
                      'old_instance_preserved': demo.active_assistant is old})
    expected = [('RELOADED', 'v1', 'v1'), ('SELECTED', 'v2', 'v1'), ('RELOADED', 'v2', 'v2'),
                ('RELOAD_FAILED', 'v1', 'v1'), ('RELOAD_FAILED', 'v1', 'v1'),
                ('RELOAD_FAILED', 'v2', 'v1'), ('RELOAD_FAILED', 'v1', 'v1')]
    passed = all((case['result']['status'], case['result']['selected_version'],
                  case['result']['loaded_version']) == outcome for case, outcome in zip(cases, expected))
    passed = passed and all(c.get('old_instance_preserved', True) for c in cases) and not root.exists()
    return {'status': 'DEMO_PASS' if passed else 'DEMO_FAILED', 'cases': cases,
            'workspace_cleaned': not root.exists(), 'llm_api_called': False, 'test_only': True}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        print(json.dumps({'status': 'ERROR', 'error': 'Only the built-in demonstration is supported; no arguments',
                          'test_only': True}))
        return 2
    try:
        result = run_demo()
    except ModuleNotFoundError as error:
        result = {'status': 'DEPENDENCY_UNAVAILABLE', 'dependency': error.name,
                  'error': 'Use an existing environment providing real GroundedAnswerV1 dependencies; no mock fallback.',
                  'test_only': True}
    except (OSError, ValueError, RuntimeError) as error:
        result = {'status': 'DEMO_FAILED', 'error': str(error), 'test_only': True}
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if result['status'] == 'DEMO_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
