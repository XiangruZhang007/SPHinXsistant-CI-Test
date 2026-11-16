"""Synthetic offline adapter checks; no real authorization, network or builds."""
from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import check_upstream_updates as detector, prepare_ci_v2_update as cli
from src import ci_v2_research as c, schema2_workflow as workflow, trusted_snapshot as trust
from src.corpus_snapshot import digest, file_digest, read_json
import test_trusted_parent_selection as fixtures


class UpdatePreflightTests(unittest.TestCase):
    def setUp(self):
        # Reuse the existing isolated metadata fixture, not a real Candidate.
        self.fx = fixtures.SelectionTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.input = self.root / 'upstream_status.json'
        self.output = self.root / 'new-preflight'
        base = self.fx.registry['baselines']['research']['reference']['upstreams']
        self.report = {repo: {'branch': branch, 'baseline_commit': base[repo],
                             'latest_commit': self.fx.targets[repo], 'update_available': True}
                       for repo, branch in [('SPHinXsys', 'master'), ('SPHinXsim', 'main')]}
        self.write_report()
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.guards = [stack.enter_context(patch.object(module, name,
                       side_effect=AssertionError('Forbidden side effect: ' + name)))
                       for module, name in [(workflow, 'execute_plan'), (workflow, 'run_local'),
                                            (workflow, 'qualify_parent_anchor'), (trust, 'download')]]

    def tearDown(self):
        for guard in self.guards:
            guard.assert_not_called()

    def write_report(self):
        self.input.write_text(json.dumps(self.report))

    def run_cli(self):
        out = io.StringIO()
        with patch.object(cli, 'P', self.fx.root), patch.object(trust, 'REGISTRY', self.fx.registry_path), redirect_stdout(out):
            code = cli.main(['--detection', str(self.input), '--output', str(self.output)])
        return code, json.loads(out.getvalue())

    def assert_blocked(self, reason):
        code, result = self.run_cli()
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(result['reason'], reason)
        self.assertFalse((self.output / 'plan.json').exists())
        return result

    def test_detector_output_is_consumed_without_network_or_schema_changes(self):
        config = {repo: {'branch': row['branch'], 'baseline_commit': row['baseline_commit'],
                         'remote': 'https://example.invalid/' + repo}
                  for repo, row in self.report.items()}
        path = self.root / 'detector-config.json'
        path.write_text(json.dumps(config))
        def runner(argv, **kwargs):
            repo = argv[2].rsplit('/', 1)[1]
            return type('Result', (), {'returncode': 0, 'stderr': '',
                'stdout': self.fx.targets[repo] + '\t' + argv[3] + '\n'})()
        self.report = detector.check_updates(path, runner=runner)
        self.write_report()
        code, result = self.run_cli()
        self.assertEqual((code, result['status']), (0, 'PLAN_READY'))

    def test_exact_planner_result_is_saved_unwrapped_and_deterministically(self):
        expected = workflow.plan_auto(self.fx.root, self.fx.registry_path, self.fx.targets)
        before = {p: p.read_bytes() for p in self.fx.root.rglob('*') if p.is_file()}
        with patch.object(workflow, 'plan_auto', wraps=workflow.plan_auto) as planner:
            code, result = self.run_cli()
        planner.assert_called_once_with(self.fx.root, self.fx.registry_path, self.fx.targets)
        self.assertEqual((code, result['status']), (0, 'PLAN_READY'))
        self.assertEqual(result['selected_parent'], 'research')
        self.assertEqual(result['upstreams'], self.fx.targets)
        self.assertEqual(read_json(self.output / 'plan.json'), expected)
        self.assertEqual(result['plan_canonical_sha256'], digest(expected))
        self.assertEqual(result['detection_sha256'], file_digest(self.input))
        self.assertEqual(read_json(self.output / 'result.json'), result)
        self.assertEqual(before, {p: p.read_bytes() for p in self.fx.root.rglob('*') if p.is_file()})
        second = self.root / 'second'
        self.output = second
        _, other = self.run_cli()
        self.assertEqual(result, other)
        self.assertEqual((second / 'plan.json').read_bytes(), (self.root / 'new-preflight/plan.json').read_bytes())

    def test_no_update_validates_both_repositories_without_planner_or_registry(self):
        for row in self.report.values():
            row['latest_commit'] = row['baseline_commit']
            row['update_available'] = False
        self.write_report()
        # NO_UPDATE is explicitly not a Registry-health or newest-Parent claim.
        self.fx.registry_path.write_text('not JSON')
        with patch.object(workflow, 'plan_auto') as planner:
            code, result = self.run_cli()
        self.assertEqual((code, result['status']), (0, 'NO_UPDATE'))
        self.assertFalse(result['update_reported'])
        self.assertEqual(result['upstreams'], result['baseline_upstreams'])
        self.assertNotIn('selected_parent', result)
        self.assertFalse((self.output / 'plan.json').exists())
        planner.assert_not_called()

    def test_one_repository_change_passes_both_exact_target_commits(self):
        self.report['SPHinXsys'].update(baseline_commit=self.fx.targets['SPHinXsys'], update_available=False)
        self.write_report()
        code, result = self.run_cli()
        self.assertEqual((code, result['upstreams']), (0, self.fx.targets))

    def test_no_authorized_parent_is_distinct_from_invalid_input(self):
        self.report['SPHinXsim']['latest_commit'] = 'e' * 40
        self.write_report()
        result = self.assert_blocked('NO_ELIGIBLE_PARENT')
        self.assertTrue(result['update_reported'])
        self.assertEqual(result['upstreams']['SPHinXsim'], 'e' * 40)

    def test_ambiguous_parents_never_fall_back(self):
        self.fx.add_parent('second', 'two')
        self.assert_blocked('AMBIGUOUS_PARENT')

    def test_registration_only_is_not_upgraded(self):
        entry = self.fx.registry['baselines']['research']
        self.fx.registry['baselines']['research'] = {'entry_kind': 'REGISTRATION_ONLY',
            'reference': entry['reference'], 'expected_reference_sha256': entry['expected_reference_sha256']}
        self.fx.write_registry()
        self.assert_blocked('NO_ELIGIBLE_PARENT')

    def test_malformed_json_and_duplicate_fields_are_rejected(self):
        original = self.input.read_text()
        cases = ['{', '[]', 'null', original[:-1] + ',"SPHinXsim":{}}',
                 original.replace('"update_available": true', '"update_available":true,"update_available":true', 1)]
        for i, raw in enumerate(cases):
            with self.subTest(raw=raw[:30]), patch.object(workflow, 'plan_auto') as planner:
                self.output = self.root / ('bad-json-' + str(i))
                self.input.write_text(raw)
                self.assert_blocked('INVALID_DETECTION')
                planner.assert_not_called()

    def test_missing_unknown_and_wrong_type_fields_are_rejected(self):
        cases = []
        for field in cli.DETECTION_FIELDS:
            value = deepcopy(self.report); value['SPHinXsys'].pop(field); cases.append(value)
        for value in [None, [], {}, 'false', 0, 1]:
            row = deepcopy(self.report); row['SPHinXsys']['update_available'] = value; cases.append(row)
        for value in ['', ' ', 'bad\nbranch', None, 1]:
            row = deepcopy(self.report); row['SPHinXsys']['branch'] = value; cases.append(row)
        row = deepcopy(self.report); row['SPHinXsys']['unknown'] = 1; cases.append(row)
        row = deepcopy(self.report); row['Other'] = row.pop('SPHinXsys'); cases.append(row)
        row = deepcopy(self.report); row['Other'] = {}; cases.append(row)
        cases.extend([{'SPHinXsys': self.report['SPHinXsys']}, {'SPHinXsys': [], 'SPHinXsim': {}}])
        for i, row in enumerate(cases):
            with self.subTest(case=i), patch.object(workflow, 'plan_auto') as planner:
                self.report = row; self.write_report(); self.output = self.root / ('fields-' + str(i))
                self.assert_blocked('INVALID_DETECTION'); planner.assert_not_called()

    def test_invalid_commit_formats_never_reach_planner(self):
        original = deepcopy(self.report)
        for field in ('baseline_commit', 'latest_commit'):
            for i, value in enumerate([None, 1, True, '', 'main', 'A' * 40, 'a' * 39, 'g' * 40, float('nan')]):
                with self.subTest(field=field, value=value), patch.object(workflow, 'plan_auto') as planner:
                    self.report = deepcopy(original); self.report['SPHinXsim'][field] = value
                    self.write_report(); self.output = self.root / (field + str(i))
                    self.assert_blocked('INVALID_DETECTION'); planner.assert_not_called()

    def test_contradictory_flags_and_invalid_second_row_do_not_return_no_update(self):
        for i, same in enumerate((False, True)):
            self.report['SPHinXsys']['update_available'] = same
            self.report['SPHinXsys']['latest_commit'] = (self.report['SPHinXsys']['baseline_commit']
                                                       if same else self.fx.targets['SPHinXsys'])
            self.write_report(); self.output = self.root / ('contradictory-' + str(i))
            self.assert_blocked('INVALID_DETECTION')
        self.report['SPHinXsys']['latest_commit'] = self.report['SPHinXsys']['baseline_commit']
        self.report['SPHinXsys']['update_available'] = False
        self.report['SPHinXsim'] = {'update_available': False}
        self.write_report(); self.output = self.root / 'invalid-second'
        self.assert_blocked('INVALID_DETECTION')

    def test_corrupt_registry_and_policy_fail_closed(self):
        self.fx.registry_path.write_text('not JSON')
        self.assert_blocked('INVALID_PLANNING_EVIDENCE')
        self.fx.write_registry()
        (self.fx.root / 'research-policy.json').write_text('{}')
        self.output = self.root / 'corrupt-policy'
        self.assert_blocked('AUTHORIZATION_FAILED')

    def test_private_context_is_preserved_and_never_manufactured(self):
        entry = self.fx.registry['baselines']['research']; ref = entry['reference']
        for name in ('storage', 'parent_rows_storage'):
            ref[name].update(kind=trust.PRIVATE_RELEASE_KIND, repository='fixture-owner/private-test',
                             repository_id=1234, asset_size=100)
        entry['expected_reference_sha256'] = digest(ref); self.fx.write_registry()
        with patch.dict(os.environ, {}, clear=True):
            self.assert_blocked('UNSAFE_INPUT')
            self.assertNotIn('GITHUB_REPOSITORY', os.environ)
        self.output = self.root / 'synthetic-context'
        with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'fixture-owner/private-test',
                                   'GITHUB_REPOSITORY_ID': '1234'}):
            self.assertEqual(self.run_cli()[0], 0)  # Metadata-only fixture, not Hosted authority.

    def test_missing_and_symlink_input_are_rejected_without_leaking_paths(self):
        self.input.unlink(); self.assert_blocked('INVALID_DETECTION')
        self.output = self.root / 'symlink-input'
        target = self.root / 'target'; target.write_text(json.dumps(self.report)); self.input.symlink_to(target)
        result = self.assert_blocked('INVALID_DETECTION')
        self.assertNotIn(str(self.input), json.dumps(result))

    def test_existing_internal_and_symlink_output_do_not_overwrite(self):
        self.output.mkdir(); old = self.output / 'plan.json'; old.write_bytes(b'existing evidence')
        self.assertEqual(self.run_cli()[1]['reason'], 'INVALID_OUTPUT')
        self.assertEqual(old.read_bytes(), b'existing evidence')
        self.output = self.fx.root / 'forbidden'; self.assert_blocked('INVALID_OUTPUT')
        self.output = self.root / 'link'; self.output.symlink_to(self.fx.root, target_is_directory=True)
        self.assert_blocked('INVALID_OUTPUT')

    def test_failed_receipt_write_removes_new_plan(self):
        original = cli.write_json
        def fail_result(path, value):
            if path.name == 'result.json':
                raise OSError('token=DO_NOT_PRINT https://secret.invalid')
            return original(path, value)
        with patch.object(cli, 'write_json', side_effect=fail_result):
            result = self.assert_blocked('OUTPUT_WRITE_FAILED')
        self.assertNotIn('DO_NOT_PRINT', json.dumps(result))
        self.assertEqual(list(self.output.iterdir()), [])

    def test_partial_plan_write_failure_removes_partial_file(self):
        def partial(path, value):
            path.write_text('{"incomplete":')
            raise OSError('Simulated interrupted write')
        with patch.object(cli, 'write_json', side_effect=partial):
            self.assert_blocked('OUTPUT_WRITE_FAILED')
        self.assertEqual(list(self.output.iterdir()), [])

    def test_receipt_collision_preserves_other_file_and_removes_our_plan(self):
        original = cli.write_json
        def collision(path, value):
            if path.name == 'result.json':
                path.write_text('other writer')
            return original(path, value)
        with patch.object(cli, 'write_json', side_effect=collision):
            self.assert_blocked('OUTPUT_WRITE_FAILED')
        self.assertEqual((self.output / 'result.json').read_text(), 'other writer')

    def test_real_cli_entry_point_needs_no_third_party_packages(self):
        for row in self.report.values():
            row.update(latest_commit=row['baseline_commit'], update_available=False)
        self.write_report()
        result = subprocess.run([sys.executable, '-B', '-S', str(Path(cli.__file__).resolve()),
            '--detection', str(self.input), '--output', str(self.output)],
            cwd=self.root, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'NO_UPDATE')
        self.assertFalse((self.output / 'plan.json').exists())

    def test_output_restrictions_do_not_grant_any_approval(self):
        _, result = self.run_cli()
        for key, value in c.RESTRICTIONS.items():
            self.assertEqual(result[key], value)
        self.assertFalse(result['automatic_research_approval'])
        self.assertFalse(result['research_baseline_created'])
        self.assertEqual(result['production_promotion'], 'NOT_AUTHORIZED')


if __name__ == '__main__':
    unittest.main()
