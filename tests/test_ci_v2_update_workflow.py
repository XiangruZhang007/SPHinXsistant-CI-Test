"""Execute actual Workflow shells with isolated metadata and explicit build stubs."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml
import test_trusted_parent_selection as fixtures
from src import ci_v2_research as c
from src.corpus_snapshot import digest, read_json

P = Path(__file__).resolve().parents[1]


class UpdateWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.SelectionTests(); self.fx.setUp(); self.addCleanup(self.fx.doCleanups)
        temp = tempfile.TemporaryDirectory(prefix='step4b-workflow-')
        self.addCleanup(temp.cleanup); self.root = Path(temp.name)
        self.doc = yaml.safe_load((P / '.github/workflows/upstream_refresh.yml').read_text())
        self.source = self.doc['jobs']['candidate-refresh']; self.build = self.doc['jobs']['candidate']
        self.export_shell = next(s['run'] for s in self.source['steps'] if s.get('id') == 'ci_v2_route')
        self.restore_shell = next(s['run'] for s in self.build['steps'] if 'route_ci_v2_update.py restore' in s.get('run', ''))
        self.execute_shell = next(s['run'] for s in self.build['steps'] if ' execute-plan ' in s.get('run', ''))
        base = self.fx.registry['baselines']['research']['reference']['upstreams']
        self.report = {repo: {'branch': branch, 'baseline_commit': base[repo],
                             'latest_commit': self.fx.targets[repo], 'update_available': True}
                       for repo, branch in [('SPHinXsys', 'master'), ('SPHinXsim', 'main')]}
        binary = self.root / 'bin'; binary.mkdir()
        self.driver = self.root / 'driver.py'
        self.driver.write_text('''import json, os, sys
from pathlib import Path
sys.path.insert(0, os.environ['TEST_REPO'])
from scripts import prepare_ci_v2_update as adapter, route_ci_v2_update as route
from src import trusted_snapshot as trust
from src.corpus_snapshot import digest
adapter.P = route.P = Path(os.environ['TEST_PROJECT'])
trust.REGISTRY = Path(os.environ['TEST_REGISTRY'])
args = sys.argv[1:]
assert args[0] == '-B'
if args[1] == 'scripts/prepare_ci_v2_update.py':
    code = adapter.main(args[2:])
    output = Path(args[args.index('--output') + 1])
    mutation = os.environ.get('TEST_MUTATION')
    plan, result = output/'plan.json', output/'result.json'
    if mutation == 'missing_plan': plan.unlink()
    if mutation == 'missing_result': result.unlink()
    if mutation in ('wrong_revisions', 'canonical_rebound'):
        p = json.loads(plan.read_text()); p['upstreams']['SPHinXsys'] = 'e'*40
        plan.write_text(json.dumps(p))
        if mutation == 'canonical_rebound':
            r = json.loads(result.read_text()); r['plan_canonical_sha256'] = digest(p)
            result.write_text(json.dumps(r))
    if mutation == 'reformatted':
        plan.write_text(json.dumps(json.loads(plan.read_text()), indent=4))
    if mutation == 'bad_status':
        r = json.loads(result.read_text()); r['status'] = 'SUCCESS'; result.write_text(json.dumps(r))
    if mutation == 'extra_receipt_field':
        r = json.loads(result.read_text()); r['approved'] = True; result.write_text(json.dumps(r))
    if mutation == 'exit_failure': code = 2
    raise SystemExit(code)
assert args[1] == 'scripts/route_ci_v2_update.py'
raise SystemExit(route.main(args[2:]))
''')
        shim = binary / 'python'
        shim.write_text('#!/bin/sh\nexec "$TEST_PYTHON" -B "$TEST_DRIVER" "$@"\n'); shim.chmod(0o755)
        self.env = {**os.environ, 'PATH': str(binary) + os.pathsep + os.defpath,
                    'TEST_PYTHON': sys.executable, 'TEST_DRIVER': str(self.driver),
                    'TEST_REPO': str(P), 'TEST_PROJECT': str(self.fx.root),
                    'TEST_REGISTRY': str(self.fx.registry_path), 'PYTHONDONTWRITEBYTECODE': '1',
                    'PYTHONHASHSEED': '0', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                    'CI_V2_BUILD_REQUESTED': 'true', 'GITHUB_RUN_ATTEMPT': '1'}
        self.counter = 0

    def shell(self, script, env, cwd=None):
        return subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', script],
                              env=env, cwd=cwd or self.root, capture_output=True, text=True)

    def export(self, **env_values):
        self.counter += 1
        runner = self.root / ('runner space ' + str(self.counter)); runner.mkdir()
        candidate = runner / 'sphinxsistant_candidate'; candidate.mkdir()
        (candidate/'upstream_status.json').write_text(json.dumps(self.report))
        outputs = runner/'job-output'; outputs.touch()
        env = {**self.env, 'RUNNER_TEMP': str(runner), 'GITHUB_OUTPUT': str(outputs), **env_values}
        executed = self.shell(self.export_shell, env)
        values = dict(line.split('=', 1) for line in outputs.read_text().splitlines())
        return executed, values, env

    def restore(self, values, env, **overrides):
        runner = self.root / ('other runner ' + str(self.counter)); runner.mkdir()
        updated = {**env, 'RUNNER_TEMP': str(runner), 'CI_V2_TRANSFER': values.get('transfer', ''), **overrides}
        return self.shell(self.restore_shell, updated), updated

    def assert_no_build(self, result, outputs):
        self.assertNotEqual(outputs.get('execute_candidate'), 'true')
        self.assertNotIn('transfer', outputs)

    def test_success_transfers_original_plan_to_real_execute_plan_cli(self):
        export, values, env = self.export()
        self.assertEqual(export.returncode, 0, export.stderr)
        self.assertEqual(values['execute_candidate'], 'true')
        original = Path(env['RUNNER_TEMP'])/'ci-v2-update/preflight/plan.json'
        restored, env = self.restore(values, env)
        self.assertEqual(restored.returncode, 0, restored.stderr)
        target = Path(env['RUNNER_TEMP'])/'p5a/plan.json'
        self.assertEqual(original.read_bytes(), target.read_bytes())
        # The actual execute-plan CLI is invoked, with only its expensive method mocked.
        driver = self.root/'execute-driver.py'
        driver.write_text('''import json, os, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, os.environ['TEST_REPO'])
from scripts import ci_v2_schema2_research as cli
from src import schema2_workflow as w
def record(project, plan, work, output, **kwargs):
    Path(os.environ['TEST_EXEC_RECEIPT']).write_text(json.dumps({
        'plan': str(plan), 'upstreams': json.loads(Path(plan).read_text())['upstreams'],
        'work': str(work), 'output': str(output), 'kwargs': kwargs}))
    return {'status': 'OFFLINE_EXECUTION_STUB_ONLY'}
with patch.object(w, 'execute_plan', side_effect=record):
    raise SystemExit(cli.main(sys.argv[3:]))
''')
        binary = self.root/'build-checkout/tools/treesitter-chunker/.venv/bin/python'
        binary.parent.mkdir(parents=True)
        binary.write_text('#!/bin/sh\nexec "$TEST_PYTHON" -B "$TEST_EXEC_DRIVER" "$@"\n'); binary.chmod(0o755)
        receipt = self.root/'execution.json'
        env.update(TEST_EXEC_DRIVER=str(driver), TEST_EXEC_RECEIPT=str(receipt))
        executed = self.shell(self.execute_shell, env, cwd=self.root/'build-checkout')
        self.assertEqual(executed.returncode, 0, executed.stderr)
        actual = read_json(receipt)
        self.assertEqual(actual['upstreams'], self.fx.targets)
        self.assertEqual(actual['plan'], str(target))
        self.assertEqual(actual['kwargs'], {'q1_inputs': None, 'q1_sha': None})

    def test_no_update_does_not_export_a_plan_or_build(self):
        for row in self.report.values(): row.update(latest_commit=row['baseline_commit'], update_available=False)
        result, outputs, env = self.export()
        self.assertEqual(result.returncode, 0, result.stderr); self.assert_no_build(result, outputs)
        self.assertEqual(read_json(Path(env['RUNNER_TEMP'])/'ci-v2-update/routing.json')['status'], 'NO_UPDATE')

    def test_missing_authorization_is_reported_without_build(self):
        self.report['SPHinXsim']['latest_commit'] = 'e'*40
        result, outputs, env = self.export()
        self.assertEqual(result.returncode, 0); self.assert_no_build(result, outputs)
        self.assertEqual(read_json(Path(env['RUNNER_TEMP'])/'ci-v2-update/routing.json')['reason'], 'NO_ELIGIBLE_PARENT')

    def test_ambiguous_parent_and_corrupt_policy_never_build(self):
        self.fx.add_parent('other', 'two')
        result, outputs, env = self.export(); self.assert_no_build(result, outputs)
        self.assertEqual(read_json(Path(env['RUNNER_TEMP'])/'ci-v2-update/routing.json')['reason'], 'AMBIGUOUS_PARENT')
        (self.fx.root/'other-policy.json').write_text('{}')
        result, outputs, env = self.export(); self.assert_no_build(result, outputs)
        self.assertEqual(read_json(Path(env['RUNNER_TEMP'])/'ci-v2-update/routing.json')['reason'], 'AUTHORIZATION_FAILED')

    def test_invalid_detection_never_routes_to_build(self):
        self.report['SPHinXsys']['latest_commit'] = 'main'
        result, outputs, env = self.export()
        self.assertNotEqual(result.returncode, 0); self.assert_no_build(result, outputs)
        self.assertEqual(read_json(Path(env['RUNNER_TEMP'])/'ci-v2-update/routing.json')['status'], 'BLOCKED')

    def test_failed_or_malformed_preflight_and_missing_plan_are_rejected(self):
        for mutation in ('exit_failure', 'bad_status', 'missing_result', 'missing_plan', 'extra_receipt_field'):
            with self.subTest(mutation=mutation):
                result, outputs, _ = self.export(TEST_MUTATION=mutation)
                self.assertNotEqual(result.returncode, 0); self.assert_no_build(result, outputs)

    def test_plan_revision_mismatch_is_rejected_even_with_recomputed_hash(self):
        for mutation in ('wrong_revisions', 'canonical_rebound'):
            with self.subTest(mutation=mutation):
                result, outputs, _ = self.export(TEST_MUTATION=mutation)
                self.assertNotEqual(result.returncode, 0); self.assert_no_build(result, outputs)

    def test_canonical_hash_accepts_reformatting_but_preserves_exact_plan_bytes(self):
        result, outputs, env = self.export(TEST_MUTATION='reformatted')
        self.assertEqual(result.returncode, 0)
        original = Path(env['RUNNER_TEMP'])/'ci-v2-update/preflight/plan.json'
        result, env = self.restore(outputs, env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(original.read_bytes(), (Path(env['RUNNER_TEMP'])/'p5a/plan.json').read_bytes())

    def test_schedule_and_other_automatic_events_remain_blocked_repeatedly(self):
        keys = []
        for event in ('schedule', 'schedule', 'workflow_run', 'push'):
            result, outputs, env = self.export(GITHUB_EVENT_NAME=event)
            self.assertEqual(result.returncode, 0); self.assert_no_build(result, outputs)
            route = read_json(Path(env['RUNNER_TEMP'])/'ci-v2-update/routing.json')
            self.assertEqual(route['status'], 'BLOCKED')
            self.assertIn('DEDUPLICATION_NOT_ESTABLISHED', route['blocking_reasons'])
            self.assertFalse(route['scheduled_execution']); keys.append(outputs['execution_key'])
        self.assertEqual(len(set(keys)), 1)

    def test_manual_default_and_repeat_attempt_do_not_execute(self):
        for overrides in ({'CI_V2_BUILD_REQUESTED': 'false'}, {'CI_V2_BUILD_REQUESTED': ''},
                          {'GITHUB_RUN_ATTEMPT': '2'}):
            result, outputs, _ = self.export(**overrides)
            self.assertEqual(result.returncode, 0); self.assert_no_build(result, outputs)

    def test_transferred_payload_tampering_and_changed_registry_are_rejected(self):
        _, values, env = self.export()
        transfer = json.loads(values['transfer']); transfer['exit_code'] = 2
        result, updated = self.restore(values, env, CI_V2_TRANSFER=json.dumps(transfer))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((Path(updated['RUNNER_TEMP'])/'p5a/plan.json').exists())
        self.counter += 1
        self.fx.registry['note'] += ' changed'; self.fx.write_registry()
        result, updated = self.restore(values, env)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((Path(updated['RUNNER_TEMP'])/'p5a/plan.json').exists())

    def test_forced_transfer_on_schedule_cannot_reach_execution(self):
        _, values, env = self.export()
        result, updated = self.restore(values, env, GITHUB_EVENT_NAME='schedule')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((Path(updated['RUNNER_TEMP'])/'p5a/plan.json').exists())

    def test_missing_malformed_and_unexpected_transfer_fields_fail_closed(self):
        _, values, env = self.export()
        original = json.loads(values['transfer'])
        missing = dict(original); missing.pop('plan')
        extra = dict(original, approved=True)
        bad_base64 = dict(original, plan='not valid base64!')
        for raw in ('', '{', json.dumps(missing), json.dumps(extra), json.dumps(bad_base64)):
            with self.subTest(raw=raw[:25]):
                self.counter += 1
                result, updated = self.restore(values, env, CI_V2_TRANSFER=raw)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((Path(updated['RUNNER_TEMP'])/'p5a/plan.json').exists())

    def test_routing_receipt_preserves_all_research_restrictions(self):
        result, values, env = self.export()
        self.assertEqual(result.returncode, 0)
        route = read_json(Path(env['RUNNER_TEMP'])/'ci-v2-update/routing.json')
        for key, value in c.RESTRICTIONS.items():
            self.assertEqual(route[key], value)
        self.assertEqual(route['deduplication'], 'NOT_ESTABLISHED')

    def test_environment_values_are_not_shell_interpolated(self):
        marker = self.root/'injected'
        result, outputs, _ = self.export(CI_V2_BUILD_REQUESTED='$(touch '+str(marker)+')')
        self.assertEqual(result.returncode, 0); self.assert_no_build(result, outputs)
        self.assertFalse(marker.exists())

    def test_oversized_transfer_never_exports_execution_permission(self):
        self.report['SPHinXsys']['branch'] = 'x' * 65536
        result, outputs, env = self.export()
        self.assertNotEqual(result.returncode, 0); self.assert_no_build(result, outputs)
        self.assertEqual(read_json(Path(env['RUNNER_TEMP'])/'ci-v2-update/routing.json')['reason'], 'INVALID_TRANSFER')

    def test_v1_steps_schedule_and_manual_v2_workflow_are_preserved(self):
        added = {'ci_v2_route'}
        steps = [s for s in self.source['steps'] if s.get('id') not in added
                 and s.get('name') != 'Preserve detection and CI V2 routing evidence']
        # Recorded from the original V1 steps; portable to shallow/migrated repos.
        self.assertEqual(digest(steps), '8e55a79c35626863832e9fdf91b61adff9edbc732ba9cd7d2099650437ffdef2')
        self.assertEqual(self.source['runs-on'], 'ubuntu-latest')
        self.assertEqual(self.doc['permissions'], {'contents': 'read'})
        events = self.doc.get('on',self.doc.get(True))
        self.assertEqual(events['schedule'], [{'cron': '0 6 * * 1'}])
        self.assertIs(events['workflow_dispatch']['inputs']['build_ci_v2']['default'], False)
        manual = yaml.safe_load((P/'.github/workflows/ci_v2_manual_research.yml').read_text())
        self.assertEqual(set(manual.get('on',manual.get(True))), {'workflow_dispatch'})
        self.assertNotIn('build_ci_v2', manual.get('on',manual.get(True))['workflow_dispatch']['inputs'])

    def test_runner_permissions_tokens_and_job_gates_are_fail_closed(self):
        self.assertEqual(self.build['runs-on'], 'ubuntu-24.04-arm')
        runtime = next(s for s in self.build['steps'] if s.get('uses','').startswith('actions/setup-python@'))
        self.assertEqual(runtime['with'], {'python-version':'3.12.3','architecture':'arm64'})
        self.assertEqual(self.doc['permissions'], {'contents':'read'})
        condition = self.build['if']
        for gate in ("github.event_name == 'workflow_dispatch'", 'inputs.build_ci_v2',
                     "needs.candidate-refresh.outputs.execute_candidate == 'true'"):
            self.assertIn(gate,condition)
        self.assertIn("steps.ci_v2_route.outcome == 'success'",self.source['outputs']['execute_candidate'])
        # Only non-building preflight can continue on error; execution cannot.
        for step in self.build['steps']:
            self.assertNotIn('continue-on-error',step)
            if 'uses' in step:self.assertRegex(step['uses'],r'@[0-9a-f]{40}$')
        self.assertEqual(self.build['concurrency']['cancel-in-progress'],False)
        execution = next(s for s in self.build['steps'] if ' execute-plan ' in s.get('run',''))
        self.assertEqual(execution['env'],{'TRUSTED_RELEASE_TOKEN':'${{ secrets.GITHUB_TOKEN }}'})
        all_runs='\n'.join(s.get('run','') for s in self.build['steps'])
        self.assertNotIn(' plan ',all_runs); self.assertNotIn('--publish',all_runs)
        self.assertNotIn('approve',all_runs); self.assertNotIn('register',all_runs)
        self.assertNotIn('${{',all_runs)

    def test_all_shell_blocks_parse_and_runtime_provisioning_matches_existing_v2(self):
        for job in self.doc['jobs'].values():
            for step in job['steps']:
                if 'run' in step:
                    parsed=subprocess.run(['bash','-n'],input=step['run'],text=True,capture_output=True)
                    self.assertEqual(parsed.returncode,0,parsed.stderr)
        manual=yaml.safe_load((P/'.github/workflows/ci_v2_manual_research.yml').read_text())
        select=lambda steps:next(s['run'] for s in steps if s['name']=='Prepare pinned extraction runtime')
        self.assertEqual(select(self.build['steps']),select(manual['jobs']['candidate']['steps']))


if __name__ == '__main__':
    unittest.main()
