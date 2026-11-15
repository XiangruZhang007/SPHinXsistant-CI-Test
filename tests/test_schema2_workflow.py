"""Manual workflow gates and inspection of a genuine archived integration run."""
import copy
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scripts import ci_v2_schema2_research as cli
from src import ci_v2_research as c, schema2_workflow as w, trusted_snapshot as t
from src.corpus_snapshot import digest, file_digest, read_json, write_json

P = Path(__file__).resolve().parents[1]


class WorkflowContractTests(unittest.TestCase):
    def test_workflow_dispatch_only_readonly_and_pinned_actions(self):
        import yaml
        doc = yaml.safe_load((P / '.github/workflows/ci_v2_manual_research.yml').read_text())
        self.assertEqual(set(doc.get('on', doc.get(True))), {'workflow_dispatch'})
        self.assertEqual(doc['permissions'], {'contents': 'read'})
        steps = doc['jobs']['candidate']['steps']
        run = '\n'.join(s.get('run', '') for s in steps)
        self.assertIn('ci_v2_schema2_research.py plan', run)
        self.assertIn('ci_v2_schema2_research.py execute-plan', run)
        self.assertNotIn('ci_v2_manual_research.py', run)
        upload = next(s for s in steps if s.get('id') == 'evidence')
        self.assertEqual(upload['if'], 'always()')
        self.assertEqual(upload['with']['if-no-files-found'], 'error')
        for step in steps:
            if 'uses' in step: self.assertRegex(step['uses'], r'@[0-9a-f]{40}$')

    def test_empty_registry_and_missing_entry_remain_rejected(self):
        cases = [({'schema_version': 2, 'baselines': {}}, 'p2-initial-bootstrap'),
                 (read_json(t.REGISTRY), 'unconfigured')]
        for registry, key in cases:
            with self.subTest(key=key), self.assertRaises(c.GateError) as caught:
                w.plan(P, registry, key, c.read(c.LOCK)['upstreams'])
            self.assertEqual(caught.exception.status, 'BOOTSTRAP_REQUIRED')

    def test_stdlib_only_plan_reports_bootstrap_blocker(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = subprocess.run(['python3', '-B', str(P / 'scripts/ci_v2_schema2_research.py'), 'plan',
                '--key', 'unconfigured', '--sys-revision', c.read(c.LOCK)['upstreams']['SPHinXsys'],
                '--sim-revision', c.read(c.LOCK)['upstreams']['SPHinXsim'], '--output', tmp + '/plan'],
                cwd=tmp, capture_output=True, text=True)
            self.assertEqual(run.returncode, 2, run.stderr)
            self.assertEqual(json.loads(run.stdout)['status'], 'BOOTSTRAP_REQUIRED')

    def test_no_approval_or_publication_command(self):
        run = subprocess.run([sys.executable, '-B', str(P / 'scripts/ci_v2_schema2_research.py'), '--help'], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0)
        self.assertNotIn('approve', run.stdout.split('positional arguments:')[-1])
        self.assertNotIn('publish', run.stdout)

    def test_unqualified_q1_still_emits_uncertain_nonblocking_attribution(self):
        from src.regression_attribution import summarize
        spec = {'questions': [{'id': 'unit', 'evidence_mode': 'ALL_OF', 'requirements': []}]}
        row = {'id': 'unit', 'mode': 'combined', 'strict': {'hit_at_5': False, 'hit_at_10': False}, 'top_10': []}
        report = summarize(spec, [row], [row], None, bindings={})
        self.assertEqual(report['Q1_status'], 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
        self.assertFalse(report['blocking'])

    def test_research_parent_without_bound_transition_policy_is_rejected(self):
        ref = {'package_format': 'schema2-research-baseline'}
        entry = {'reference': ref, 'expected_reference_sha256': 'fixture-pin',
                 'build_policy_path': 'policy.json', 'build_policy_sha256': 'pinned'}
        revisions = c.read(c.LOCK)['upstreams']
        policy = {'scope': {'target_upstreams': revisions}, 'provenance_type': 'GENUINE_UPSTREAM'}
        with patch.object(t, 'registry_reference', return_value=entry), patch.object(w, 'checked_file', return_value=Path('dummy')), \
             patch.object(w, 'read_json', return_value=policy), patch.object(w, 'file_digest', return_value='pinned'):
            with self.assertRaises(c.GateError) as caught: w.plan(P, {}, 'valid', revisions)
        self.assertEqual(caught.exception.status, 'AUTHORIZATION_FAILED')

    def test_unsafe_manual_revision_input(self):
        with self.assertRaises(c.GateError):
            w.plan(P, {}, 'bad', {'SPHinXsys': 'main', 'SPHinXsim': '$(id)'})

    def test_qualified_plan_revalidates_scope(self):
        ref = {'package_format': 'p2-snapshot-v1'}
        entry = {'reference': ref, 'expected_reference_sha256': 'fixture-pin',
                 'build_policy_path': 'policy.json', 'build_policy_sha256': 'pinned'}
        revisions = c.read(c.LOCK)['upstreams']
        policy = {'scope': {'target_upstreams': revisions}, 'provenance_type': 'GENUINE_UPSTREAM'}
        with patch.object(t, 'registry_reference', return_value=entry), patch.object(w, 'checked_file', return_value=Path('dummy')), \
             patch.object(w, 'read_json', return_value=policy), patch.object(w, 'file_digest', return_value='pinned'):
            planned = w.plan(P, {}, 'valid', revisions)
        self.assertEqual(planned['status'], 'SCHEMA2_MANUAL_PLAN')
        self.assertFalse(planned['automatic_research_approval'])

    def test_optional_q1_error_does_not_claim_success_or_approve(self):
        from src import version_aware_evidence as q
        spec = {'questions': [{'id': 'unit', 'evidence_mode': 'ALL_OF', 'requirements': []}]}
        row = {'id': 'unit', 'mode': 'combined', 'strict': {'hit_at_5': False, 'hit_at_10': False}, 'top_10': []}
        with tempfile.TemporaryDirectory() as tmp, patch.object(q, 'generate', side_effect=ValueError('Unqualified pair')):
            status, report = w.diagnostics(P, Path(tmp), spec, [row], [row], {}, q1_inputs=Path(tmp) / 'inputs.json', q1_sha='0' * 64)
            self.assertEqual(status['status'], 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
            self.assertFalse(report['automatic_research_approval'])
            self.assertFalse(report['blocking'])


class ExecutePlanQ1Tests(unittest.TestCase):
    """Parameter wiring only; transport, Git and corpus work never execute."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.work = self.root / 'work'
        self.output = self.root / 'output'
        self.plan_path = self.root / 'plan.json'
        self.registry_path = self.root / 'registry.json'
        self.inputs = self.root / 'q1-inputs.json'
        self.sha = 'a' * 64
        self.planned = {'key': 'fixture', 'upstreams': {'SPHinXsys': 'a' * 40, 'SPHinXsim': 'b' * 40}}
        self.entry = {'reference': {'storage': {}, 'transport_sha256': 'b' * 64,
            'parent_rows_storage': {}, 'parent_rows_sha256': 'c' * 64,
            'upstreams': self.planned['upstreams']}, 'expected_reference_sha256': 'd' * 64,
            'build_policy_path': 'policy.json', 'build_policy_sha256': 'e' * 64}
        write_json(self.plan_path, self.planned)
        write_json(self.registry_path, {'baselines': {'fixture': self.entry}})
        write_json(self.root / 'policy.json', {})
        self.argv = ['execute-plan', '--plan', str(self.plan_path), '--work', str(self.work),
                     '--output', str(self.output)]

    def test_cli_parses_and_forwards_optional_pair_and_default(self):
        for extra, expected in [([], {'q1_inputs': None, 'q1_sha': None}),
                (['--q1-inputs', str(self.inputs), '--q1-inputs-sha256', self.sha],
                 {'q1_inputs': self.inputs, 'q1_sha': self.sha})]:
            with self.subTest(extra=extra), patch.object(w, 'execute_plan', return_value=c.RESTRICTIONS) as execute, \
                    redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(cli.main(self.argv + extra), 0)
                execute.assert_called_once_with(P, self.plan_path, self.work, self.output, **expected)
                self.assertEqual(json.loads(stdout.getvalue())['production_promotion'], 'NOT_AUTHORIZED')

    def test_cli_rejects_unpaired_options_before_execution(self):
        for extra in (['--q1-inputs', str(self.inputs)], ['--q1-inputs-sha256', self.sha]):
            with self.subTest(extra=extra), patch.object(w, 'execute_plan') as execute, \
                    redirect_stderr(io.StringIO()) as stderr, self.assertRaises(SystemExit) as caught:
                cli.main(self.argv + extra)
            self.assertEqual(caught.exception.code, 2)
            self.assertIn('must be provided together', stderr.getvalue())
            execute.assert_not_called()
            self.assertFalse(self.work.exists())
            self.assertFalse(self.output.exists())

    def execute_fixture(self, **kwargs):
        stack = self.enterContext(ExitStack())
        stack.enter_context(patch.object(t, 'REGISTRY', self.registry_path))
        self.plan_check = stack.enter_context(patch.object(w, 'plan', return_value=self.planned))
        stack.enter_context(patch.object(c, 'frozen_runtime'))
        stack.enter_context(patch.object(w.shutil, 'disk_usage', return_value=SimpleNamespace(free=9 * 1024**3)))
        self.download = stack.enter_context(patch.object(t, 'download'))
        stack.enter_context(patch.object(c, 'SOURCES', {r: 'https://example.invalid/' + r
                                                      for r in self.planned['upstreams']}))
        self.git = stack.enter_context(patch.object(w.subprocess, 'run'))
        self.local = stack.enter_context(patch.object(w, 'run_local', return_value=c.RESTRICTIONS))
        self.package = stack.enter_context(patch.object(c, 'package_candidate'))
        return w.execute_plan(self.root, self.plan_path, self.work, self.output, **kwargs)

    def test_execute_plan_forwards_q1_pair_to_existing_local_path(self):
        self.assertEqual(self.execute_fixture(q1_inputs=self.inputs, q1_sha=self.sha), c.RESTRICTIONS)
        self.assertEqual(self.local.call_args.kwargs, {'q1_inputs': self.inputs, 'q1_sha': self.sha})
        self.assertEqual(self.local.call_args.args[-1], self.work / 'parent-rows.json')
        self.assertEqual(self.download.call_count, 2)
        self.package.assert_called_once_with(self.output, self.output.parent / 'candidate.tar.gz')

    def test_execute_plan_without_q1_preserves_defaults(self):
        self.assertEqual(self.execute_fixture(), c.RESTRICTIONS)
        self.assertEqual(self.local.call_args.kwargs, {'q1_inputs': None, 'q1_sha': None})

    def test_direct_execute_plan_rejects_unpaired_options_before_side_effects(self):
        for kwargs in ({'q1_inputs': self.inputs}, {'q1_sha': self.sha}):
            with self.subTest(kwargs=kwargs), patch.object(w, 'plan') as plan, \
                    patch.object(t, 'download') as download, self.assertRaises(c.GateError) as caught:
                w.execute_plan(P, self.plan_path, self.work, self.output, **kwargs)
            self.assertEqual(caught.exception.status, 'UNSAFE_INPUT')
            plan.assert_not_called()
            download.assert_not_called()
            self.assertFalse(self.work.exists())

    def test_mandatory_plan_failure_is_not_suppressed_by_q1(self):
        with patch.object(t, 'REGISTRY', self.registry_path), \
                patch.object(w, 'plan', side_effect=c.GateError('INVALID_REFERENCE', 'Scope changed')), \
                patch.object(t, 'download') as download, self.assertRaises(c.GateError) as caught:
            w.execute_plan(P, self.plan_path, self.work, self.output, q1_inputs=self.inputs, q1_sha=self.sha)
        self.assertEqual(caught.exception.status, 'INVALID_REFERENCE')
        download.assert_not_called()
        self.assertFalse(self.work.exists())

    def test_mandatory_local_failures_retain_cli_status_and_cannot_package(self):
        for status in ('AUTHORIZATION_FAILED', 'RETRIEVAL_EXECUTION_FAILED'):
            with self.subTest(status=status), patch.object(w, 'run_local',
                    side_effect=c.GateError(status, 'Mandatory failure')), \
                    patch.object(c, 'package_candidate') as package, \
                    patch.object(cli, 'P', self.root), \
                    patch.object(t, 'REGISTRY', self.registry_path), \
                    patch.object(w, 'plan', return_value=self.planned), patch.object(c, 'frozen_runtime'), \
                    patch.object(w.shutil, 'disk_usage', return_value=SimpleNamespace(free=9 * 1024**3)), \
                    patch.object(t, 'download'), patch.object(w.subprocess, 'run'), \
                    redirect_stdout(io.StringIO()) as stdout:
                # New paths avoid reusing the previous subcase's temporary output.
                args = ['execute-plan', '--plan', str(self.plan_path), '--work', str(self.root / status),
                        '--output', str(self.root / (status + '-output')), '--q1-inputs', str(self.inputs),
                        '--q1-inputs-sha256', self.sha]
                self.assertEqual(cli.main(args), 2)
                result = json.loads(stdout.getvalue())
                self.assertEqual(result['status'], status)
                self.assertEqual(result['production_promotion'], 'NOT_AUTHORIZED')
                self.assertFalse(result['automatic_research_approval'])
                package.assert_not_called()

    def diagnostic_fixture(self):
        criterion = {'kind': 'line_range', 'path': 'repos/SPHinXsim/docs/unit.md',
                     'role': 'documentation', 'range': [1, 1]}
        spec = {'questions': [{'id': 'unit', 'evidence_mode': 'ALL_OF', 'requirements': [criterion]}]}
        row = {'id': 'unit', 'mode': 'combined', 'strict': {'hit_at_5': False, 'hit_at_10': False},
               'evidence_available': False, 'top_10': []}
        return spec, row

    def test_real_q1_loader_rejects_invalid_inputs_as_nonblocking_diagnostics(self):
        spec, row = self.diagnostic_fixture()
        for name, raw, sha in [('checksum', b'{}', '0' * 64), ('malformed', b'{', None)]:
            with self.subTest(name=name):
                source = self.root / (name + '.json')
                source.write_bytes(raw)
                output = self.root / (name + '-diagnostic')
                output.mkdir()
                status, report = w.diagnostics(P, output, spec, [row], [row], {},
                    q1_inputs=source, q1_sha=sha or file_digest(source))
                self.assertEqual(status['status'], 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
                self.assertTrue(status['reason'])
                self.assertIn('ATTRIBUTION_UNCERTAIN', report['failures'][0]['supported_attribution'])
                self.assertFalse(report['blocking'])
                self.assertEqual(report['production_promotion'], 'NOT_AUTHORIZED')

    def test_existing_qualification_rejects_run_and_archived_row_mismatches(self):
        from src import version_aware_evidence as q
        spec, row = self.diagnostic_fixture()
        base = {'source_state_id': 'base-source', 'package_id': 'parent', 'corpus_sha256': 'base-corpus'}
        target = {'source_state_id': 'target-source', 'package_id': 'candidate', 'corpus_sha256': 'target-corpus'}
        possible = {'base': base, 'target': target,
                    'archived_rows_digests': {'base': digest([row]), 'target': digest([row])}}
        bindings = {'base_source_state': base['source_state_id'], 'target_source_state': target['source_state_id'],
                    'parent_id': base['package_id'], 'candidate_id': target['package_id'],
                    'base_corpus_sha256': base['corpus_sha256'], 'target_corpus_sha256': target['corpus_sha256']}
        for field in (*bindings, 'archived_rows'):
            with self.subTest(field=field):
                report_input = copy.deepcopy(possible)
                run_bindings = dict(bindings)
                if field == 'archived_rows': report_input['archived_rows_digests']['target'] = 'wrong'
                else: run_bindings[field] = 'wrong'
                output = self.root / field
                output.mkdir()
                with patch.object(q, 'generate', return_value=report_input) as generate, \
                        patch.object(q, 'write_report') as write_report:
                    status, report = w.diagnostics(P, output, spec, [row], [row], run_bindings,
                                                  q1_inputs=self.inputs, q1_sha=self.sha)
                self.assertEqual(status['status'], 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
                self.assertIn('differ' if field == 'archived_rows' else 'does not bind', status['reason'])
                self.assertIn('ATTRIBUTION_UNCERTAIN', report['failures'][0]['supported_attribution'])
                self.assertFalse(report['blocking'])
                generate.assert_called_once_with(P, self.inputs, self.sha)
                write_report.assert_not_called()


class GenuineIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.environ.get('SPHINX_P5A2_RUN')
        if not path: raise unittest.SkipTest('Pinned genuine P5A.2 integration output not configured')
        cls.root = Path(path); cls.result = read_json(cls.root / 'result.json')

    def test_actual_schema2_parent_and_upstream_transition(self):
        m = read_json(self.root / 'candidate/upstream-candidate.json')
        self.assertEqual(m['schema_version'], 2)
        self.assertEqual(m['identity']['parent']['node_id'], self.result['baseline_id'])
        self.assertNotEqual(m['identity']['base_upstreams'], m['identity']['upstreams'])
        self.assertEqual(m['identity']['provenance_type'], 'GENUINE_UPSTREAM')

    def test_trusted_parent_restored_exactly(self):
        ref = read_json(self.root / 'trusted-reference.json')
        self.assertEqual(file_digest(self.root / 'parent/checksums.json'), ref['manifest_sha256'])
        self.assertEqual(file_digest(self.root / 'parent/corpus.jsonl'), ref['corpus_sha256'])

    def test_independent_full_four_artifact_exact_parity(self):
        parity = read_json(self.root / 'parity.json')
        self.assertEqual(parity['status'], 'PARITY_PASS')
        self.assertEqual(len(parity['comparisons']), 4)
        for name, value in parity['comparisons'].items():
            self.assertTrue(value['exact_bytes_equal'])
            self.assertEqual((self.root / 'candidate' / name).read_bytes(), (self.root / 'full' / name).read_bytes())

    def test_frozen_results_and_actual_replays(self):
        raw = read_json(self.root / 'quality/incremental-raw-results.json')
        self.assertEqual(len(raw), 128)
        self.assertEqual(raw, read_json(self.root / 'quality/full-raw-results.json'))
        self.assertEqual(raw, read_json(self.root / 'execution-verification/incremental-replay.json'))
        self.assertEqual(raw, read_json(self.root / 'execution-verification/full-replay.json'))

    def test_Q1_and_attribution_present_but_nonblocking(self):
        self.assertEqual(read_json(self.root / 'q1-status.json')['status'], 'QUALIFIED')
        report = read_json(self.root / 'regression-attribution.json')
        self.assertFalse(report['blocking'])
        self.assertEqual(report['inventory']['question_mode_combinations'], 128)

    def test_no_baseline_created_or_pointer_update(self):
        self.assertFalse(self.result['RESEARCH_BASELINE_APPROVED'])
        self.assertFalse(self.result['RETRIEVAL_QUALITY_ACCEPTED'])
        self.assertFalse(self.result['automatic_research_approval'])
        self.assertEqual(self.result['production_promotion'], 'NOT_AUTHORIZED')
        self.assertFalse((self.root / 'candidate/upstream-baseline.json').exists())
        self.assertEqual(read_json(self.root / 'trusted-reference.json')['storage']['kind'],
                         'LOCAL_QUALIFICATION_ONLY')

    def test_no_change_genuine_transition_reuses_every_file(self):
        unchanged = os.environ.get('SPHINX_P5A2_NOCHANGE_RUN')
        self.assertIsNotNone(unchanged, 'Final qualification must configure no-change output')
        root = Path(unchanged); result = read_json(root / 'result.json')
        metadata = read_json(root / 'candidate/upstream-candidate.json')['identity']
        self.assertEqual(metadata['base_upstreams'], metadata['upstreams'])
        self.assertEqual(result['reuse']['actual_extraction_invocations'], 0)
        self.assertEqual(result['reuse']['reused_files'], result['reuse']['selected_files'])
        self.assertEqual(result['STRUCTURAL_PARITY'], 'PASS')
        self.assertEqual(read_json(root / 'q1-status.json')['status'], 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')


if __name__ == '__main__': unittest.main()
