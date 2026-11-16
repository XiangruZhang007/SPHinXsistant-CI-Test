"""Offline metadata, CLI and execution wiring; no extraction, network or R2."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import ci_v2_schema2_research as cli
from src import ci_v2_research as c, schema2_workflow as w, trusted_snapshot as trust
from src import trusted_parent_selection as selection
from src.corpus_snapshot import digest, file_digest, read_json

P = Path(__file__).resolve().parents[1]


class SelectionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.registry_path = self.root / 'registry.json'
        self.registry = {'schema_version': 2, 'baselines': {}, 'note': 'synthetic isolated fixture'}
        self.targets = {'SPHinXsys': 'c' * 40, 'SPHinXsim': 'd' * 40}
        self.add_parent('research', 'one')

    def add_parent(self, key, seed, targets=None, p2=False):
        ref = deepcopy(read_json(trust.REGISTRY)['baselines']['p2-initial-bootstrap']['reference'])
        def hashed(label): return hashlib.sha256((seed + label).encode()).hexdigest()
        ref.update(node_id='sha256-' + hashed('node'), package_checksum=hashed('package'),
                   source_state='sha256-' + hashed('source'), corpus_sha256=hashed('corpus'),
                   upstreams={'SPHinXsys': hashed('sys')[:40], 'SPHinXsim': hashed('sim')[:40]})
        if not p2:
            ref.update(package_format='schema2-research-baseline', accepted_package_schema=2)
            ref['authorization']['type'] = 'EXPLICIT_RESEARCH_BASELINE_REUSE'
        for name, asset in [('storage', 101), ('parent_rows_storage', 102)]:
            ref[name].update(release_id=100, asset_id=asset, tag='synthetic-parent-fixture',
                             asset_name=name + '.fixture')
        entry = {'reference': ref, 'expected_reference_sha256': digest(ref),
                 'build_policy_path': key + '-policy.json', 'build_policy_sha256': '0' * 64}
        self.registry['baselines'][key] = entry
        policy = {'schema_version': 2, 'operation': 'BUILD_CANDIDATE', 'research_only': True,
                  'experiment_id': 'SYNTHETIC_OFFLINE_SELECTION', 'provenance_type': 'GENUINE_UPSTREAM',
                  'automatic_reuse': False, 'automatic_research_approval': False,
                  'production_promotion': 'NOT_AUTHORIZED', 'p2_anchor_authorized': p2,
                  'scope': {'parent': {'kind': 'P2_ANCHOR' if p2 else 'RESEARCH_BASELINE',
                                      'node_id': ref['node_id'], 'package_checksum': ref['package_checksum']},
                            'base_upstreams': ref['upstreams'], 'base_source_state': ref['source_state'],
                            'build_fingerprint': ref['build_fingerprint'], 'orchestration_fingerprint': hashed('orchestration'),
                            'target_upstreams': targets or self.targets, 'target_source_state': 'sha256-' + hashed('target')}}
        self.write_policy(key, policy)
        self.write_registry()
        return policy

    def write_policy(self, key, policy):
        entry = self.registry['baselines'][key]
        path = self.root / entry['build_policy_path']
        path.write_text(json.dumps(policy))
        entry['build_policy_sha256'] = file_digest(path)

    def policy(self, key='research'):
        return read_json(self.root / self.registry['baselines'][key]['build_policy_path'])

    def write_registry(self):
        self.registry_path.write_text(json.dumps(self.registry))

    def plan(self):
        self.write_registry()
        return w.plan_auto(self.root, self.registry_path, self.targets)

    def blocked(self, expected=None):
        with self.assertRaises((c.GateError, ValueError, KeyError, TypeError)) as caught:
            self.plan()
        if expected: self.assertEqual(caught.exception.status, expected)

    def test_unique_match_pins_raw_registry_canonical_entry_and_policy_bytes(self):
        with patch.object(trust, 'download') as download, patch.object(w, 'qualify_parent_anchor') as anchor:
            planned = self.plan()
        entry = self.registry['baselines']['research']
        self.assertEqual(planned['status'], 'SCHEMA2_AUTO_PLAN')
        self.assertEqual(planned['key'], 'research')
        self.assertEqual(planned['registry_entry_sha256'], digest(entry))
        pin = planned['selection']
        self.assertEqual(pin['registry_sha256'], file_digest(self.registry_path))
        self.assertNotEqual(pin['registry_sha256'], digest(self.registry))
        self.assertEqual(pin['build_policy_sha256'], file_digest(self.root / entry['build_policy_path']))
        self.assertEqual(pin['expected_target_source_state'], self.policy()['scope']['target_source_state'])
        self.assertNotIn('parent_r2_anchor', planned)
        self.assertNotIn('qualification', pin)
        self.assertFalse(planned['automatic_reuse'])
        self.assertFalse(planned['automatic_research_approval'])
        self.assertEqual(planned['production_promotion'], 'NOT_AUTHORIZED')
        download.assert_not_called(); anchor.assert_not_called()

    def test_deterministic_same_bytes_and_pure_unique_rule(self):
        self.assertEqual(self.plan(), self.plan())
        rows = [{'key': 'z', 'reason': 'TARGET_NOT_AUTHORIZED'},
                {'key': 'a', 'reason': 'AUTHORIZED_TARGET_MATCH'}]
        self.assertEqual(selection.unique_match(rows), selection.unique_match(list(reversed(rows))))

    def test_valid_other_target_is_nonmatch_not_an_error(self):
        self.add_parent('other', 'two', {'SPHinXsys': 'e' * 40, 'SPHinXsim': 'f' * 40})
        planned = self.plan()
        self.assertEqual(planned['key'], 'research')
        self.assertIn({'key': 'other', 'reason': 'TARGET_NOT_AUTHORIZED'}, planned['selection']['assessments'])

    def test_zero_matches_and_empty_registry_do_not_bootstrap(self):
        self.targets = {'SPHinXsys': 'e' * 40, 'SPHinXsim': 'f' * 40}
        self.blocked('NO_ELIGIBLE_PARENT')
        self.registry['baselines'].clear()
        self.blocked('NO_ELIGIBLE_PARENT')

    def test_multiple_authorized_parents_are_ambiguous_in_either_order(self):
        self.add_parent('other', 'two')
        self.blocked('AMBIGUOUS_PARENT')
        self.registry['baselines'] = dict(reversed(list(self.registry['baselines'].items())))
        self.blocked('AMBIGUOUS_PARENT')

    def test_explicit_p2_authorization_is_preserved(self):
        self.registry['baselines'].clear()
        self.add_parent('bootstrap', 'bootstrap', p2=True)
        self.assertEqual(self.plan()['key'], 'bootstrap')
        policy = self.policy('bootstrap'); policy['p2_anchor_authorized'] = False
        self.write_policy('bootstrap', policy)
        self.blocked('AUTHORIZATION_FAILED')

    def test_registration_only_never_acquires_build_authority(self):
        e = self.registry['baselines']['research']
        self.registry['baselines']['research'] = {'entry_kind': 'REGISTRATION_ONLY',
            'reference': e['reference'], 'expected_reference_sha256': e['expected_reference_sha256']}
        self.blocked('NO_ELIGIBLE_PARENT')
        self.add_parent('authorized', 'two')
        self.assertIn({'key': 'research', 'reason': 'NO_BUILD_AUTHORIZATION'}, self.plan()['selection']['assessments'])

    def test_missing_authorization_and_unsupported_entries_are_not_skipped(self):
        self.add_parent('other', 'two', {'SPHinXsys': 'e' * 40, 'SPHinXsim': 'f' * 40})
        self.registry['baselines']['other'].pop('build_policy_path')
        self.blocked('INVALID_REFERENCE')

    def test_duplicate_nodes_and_conflicting_content_bindings_rejected(self):
        original = deepcopy(self.registry['baselines']['research'])
        self.registry['baselines']['duplicate'] = deepcopy(original)
        self.blocked('INVALID_REFERENCE')
        ref = self.registry['baselines']['duplicate']['reference']
        ref['node_id'] = 'sha256-' + 'e' * 64
        self.registry['baselines']['duplicate']['expected_reference_sha256'] = digest(ref)
        self.blocked('INVALID_REFERENCE')

    def test_bad_reference_pin_even_on_nonmatching_entry_is_fatal(self):
        self.add_parent('other', 'two', {'SPHinXsys': 'e' * 40, 'SPHinXsim': 'f' * 40})
        self.registry['baselines']['other']['reference']['corpus_sha256'] = '0' * 64
        self.blocked('INVALID_REFERENCE')

    def test_malformed_nested_reference_metadata_is_a_clear_gate_failure(self):
        original = deepcopy(self.registry['baselines']['research']['reference'])
        for field in ('upstreams', 'authorization', 'storage', 'parent_rows_storage'):
            with self.subTest(field=field):
                entry = self.registry['baselines']['research']
                entry['reference'] = deepcopy(original); entry['reference'][field] = []
                entry['expected_reference_sha256'] = digest(entry['reference'])
                self.blocked('INVALID_REFERENCE')

    def test_bad_policy_hash_even_on_nonmatching_entry_is_fatal(self):
        self.add_parent('other', 'two', {'SPHinXsys': 'e' * 40, 'SPHinXsim': 'f' * 40})
        (self.root / 'other-policy.json').write_text('{}')
        self.blocked('AUTHORIZATION_FAILED')

    def test_malformed_or_unsafe_policy_is_not_a_nonmatch(self):
        original = self.policy()
        for field, value in [('operation', 'APPROVE'), ('research_only', False), ('automatic_reuse', True),
                             ('automatic_research_approval', True), ('production_promotion', 'AUTHORIZED'),
                             ('provenance_type', 'CONTROLLED_GIT_FIXTURE'), ('scope', {})]:
            with self.subTest(field=field):
                policy = deepcopy(original); policy[field] = value
                self.write_policy('research', policy)
                self.blocked('AUTHORIZATION_FAILED')

    def test_missing_malformed_source_and_wrong_chain_bindings_rejected(self):
        original = self.policy()
        for field, value in [('parent', {'kind': 'CANDIDATE'}), ('base_upstreams', self.targets),
                             ('base_source_state', 'sha256-' + '0' * 64), ('build_fingerprint', '0' * 64),
                             ('target_source_state', 'unknown'), ('orchestration_fingerprint', 'bad')]:
            with self.subTest(field=field):
                policy = deepcopy(original); policy['scope'][field] = value
                self.write_policy('research', policy)
                self.blocked('AUTHORIZATION_FAILED')

    def test_valid_incompatible_build_cannot_be_selected(self):
        entry = self.registry['baselines']['research']
        entry['reference']['build_fingerprint'] = '0' * 64
        entry['expected_reference_sha256'] = digest(entry['reference'])
        policy = self.policy(); policy['scope']['build_fingerprint'] = '0' * 64
        self.write_policy('research', policy)
        self.blocked('NO_ELIGIBLE_PARENT')

    def test_corpus_archive_or_unregistered_candidate_is_not_a_registry_parent(self):
        # Merely existing on disk cannot affect authoritative Registry selection.
        (self.root / 'published-c2-release.json').write_text(json.dumps({'immutable': True, 'approved': True}))
        self.registry['baselines'].clear()
        self.blocked('NO_ELIGIBLE_PARENT')
        self.add_parent('ordinary-candidate', 'candidate')
        ref = self.registry['baselines']['ordinary-candidate']['reference']
        ref['package_format'] = 'schema2-candidate'
        self.registry['baselines']['ordinary-candidate']['expected_reference_sha256'] = digest(ref)
        self.blocked('INVALID_REFERENCE')

    def test_duplicate_json_fields_and_invalid_registry_are_rejected(self):
        for raw in ('{"schema_version":2,"baselines":{},"baselines":{}}',
                    '{"schema_version":true,"baselines":{}}', '[]', '{broken'):
            with self.subTest(raw=raw):
                self.registry_path.write_text(raw)
                with self.assertRaises((c.GateError, ValueError)):
                    w.plan_auto(self.root, self.registry_path, self.targets)

    def test_symlink_policy_and_registry_are_rejected(self):
        path = self.root / 'research-policy.json'
        raw = path.read_bytes(); path.unlink()
        (self.root / 'other.json').write_bytes(raw); path.symlink_to('other.json')
        self.blocked()
        path.unlink(); path.write_bytes(raw)
        self.write_registry()
        alias = self.root / 'registry-alias.json'; alias.symlink_to(self.registry_path.name)
        with self.assertRaises(ValueError): w.plan_auto(self.root, alias, self.targets)

    def test_real_registry_metadata_selects_c1_only_for_its_existing_target(self):
        before = trust.REGISTRY.read_bytes()
        with patch.dict('os.environ', {'GITHUB_REPOSITORY': 'XiangruZhang007/SPHinXsistant-CI-Test',
                                     'GITHUB_REPOSITORY_ID': '1455203884'}), \
                patch.object(trust, 'download') as download:
            targets = read_json(P / 'configs/ci_v2_c1_c2_build_policy.json')['scope']['target_upstreams']
            planned = w.plan_auto(P, trust.REGISTRY, targets)
        self.assertEqual(planned['key'], 'c1-research-parent-09b91a36')
        self.assertEqual(trust.REGISTRY.read_bytes(), before)
        self.assertNotIn('c2', planned['key'])
        download.assert_not_called()

    def test_stdlib_only_planning_uses_real_selection_and_no_packages(self):
        self.write_registry()
        code = ('import json,sys; from src.schema2_workflow import plan_auto; '
                'r=plan_auto(sys.argv[1],sys.argv[2],json.loads(sys.argv[3])); print(r["status"])')
        run = subprocess.run([sys.executable, '-B', '-S', '-c', code, str(self.root),
                              str(self.registry_path), json.dumps(self.targets)], cwd=P, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), 'SCHEMA2_AUTO_PLAN')

    def execute(self, planned, failure=None, download_failure=None, mutate=None):
        plan_path = self.root / 'plan.json'; plan_path.write_text(json.dumps(planned))
        stack = self.enterContext(ExitStack())
        stack.enter_context(patch.object(trust, 'REGISTRY', self.registry_path))
        stack.enter_context(patch.object(c, 'frozen_runtime'))
        stack.enter_context(patch.object(w.shutil, 'disk_usage', return_value=SimpleNamespace(free=9*1024**3)))
        self.download = stack.enter_context(patch.object(trust, 'download', side_effect=download_failure))
        stack.enter_context(patch.object(w.subprocess, 'run'))
        def local(*args, **kwargs):
            if failure: raise failure
            if mutate: mutate()
            return c.RESTRICTIONS
        self.local = stack.enter_context(patch.object(w, 'run_local', side_effect=local))
        self.package = stack.enter_context(patch.object(c, 'package_candidate'))
        return w.execute_plan(self.root, plan_path, self.root/'work', self.root/'output')

    def test_execution_rechecks_and_delivers_exact_parent_to_unchanged_local_path(self):
        planned = self.plan()
        self.assertEqual(self.execute(planned), c.RESTRICTIONS)
        self.assertEqual(self.local.call_args.args[5], self.registry['baselines']['research']['reference'])
        self.assertEqual(self.local.call_args.args[6], planned['selection']['reference_sha256'])
        self.assertEqual(self.download.call_count, 2)
        self.package.assert_called_once()

    def test_registry_byte_change_including_formatting_blocks_before_download(self):
        planned = self.plan()
        self.registry_path.write_bytes(self.registry_path.read_bytes() + b'\n')
        with self.assertRaises(c.GateError): self.execute(planned)
        self.download.assert_not_called(); self.local.assert_not_called(); self.package.assert_not_called()

    def test_policy_change_blocks_before_download(self):
        planned = self.plan()
        (self.root/'research-policy.json').write_text('{}')
        with self.assertRaises(c.GateError): self.execute(planned)
        self.download.assert_not_called(); self.local.assert_not_called()

    def test_registry_change_while_planning_is_rejected(self):
        original = w.plan
        changed = False
        def mutate(*args):
            nonlocal changed
            result = original(*args)
            if not changed:
                self.registry_path.write_bytes(self.registry_path.read_bytes() + b'\n')
                changed = True
            return result
        with patch.object(w, 'plan', side_effect=mutate):
            self.blocked('INVALID_REFERENCE')

    def test_selected_entry_change_blocks_before_download(self):
        planned = self.plan()
        entry = self.registry['baselines']['research']
        entry['reference']['storage']['asset_id'] += 1
        entry['expected_reference_sha256'] = digest(entry['reference'])
        self.write_registry()
        with self.assertRaises(c.GateError): self.execute(planned)
        self.download.assert_not_called()

    def test_tampered_selection_or_added_plan_fields_are_rejected(self):
        planned = self.plan(); planned['selection']['mode'] = 'LATEST'
        with self.assertRaises(c.GateError): self.execute(planned)
        self.download.assert_not_called()

    def test_restore_checksum_or_qualification_failure_cannot_package(self):
        planned = self.plan()
        with self.assertRaises(c.GateError):
            self.execute(planned, failure=c.GateError('INVALID_BASELINE', 'Synthetic restore/checksum refusal'))
        self.package.assert_not_called()

    def test_download_failure_cannot_call_local_or_package(self):
        planned = self.plan()
        with self.assertRaises(c.GateError):
            self.execute(planned, download_failure=c.GateError('CORRUPT_DOWNLOAD', 'Synthetic checksum refusal'))
        self.local.assert_not_called(); self.package.assert_not_called()

    def test_existing_build_authorization_refusal_still_blocks_after_selection(self):
        planned = self.plan()
        with self.assertRaises(c.GateError) as caught:
            self.execute(planned, failure=c.GateError('AUTHORIZATION_FAILED', 'Existing build path refusal'))
        self.assertEqual(caught.exception.status, 'AUTHORIZATION_FAILED')
        self.local.assert_called_once(); self.package.assert_not_called()

    def test_registry_change_during_local_path_prevents_packaging(self):
        planned = self.plan()
        def mutate(): self.registry_path.write_bytes(self.registry_path.read_bytes()+b'\n')
        with self.assertRaises(c.GateError): self.execute(planned, mutate=mutate)
        self.local.assert_called_once(); self.package.assert_not_called()

    def test_manual_plan_remains_identical_and_explicit(self):
        self.write_registry()
        manual = w.plan(self.root, self.registry, 'research', self.targets)
        self.assertEqual(manual['status'], 'SCHEMA2_MANUAL_PLAN')
        self.assertNotIn('selection', manual)
        self.assertEqual(self.execute(manual), c.RESTRICTIONS)

    def test_cli_auto_propagates_and_manual_missing_or_contradictory_mode_rejected(self):
        common = ['plan','--sys-revision',self.targets['SPHinXsys'],
                  '--sim-revision',self.targets['SPHinXsim'],'--output',str(self.root/'cli-plan')]
        self.write_registry()
        with patch.object(cli, 'P', self.root), patch.object(trust, 'REGISTRY', self.registry_path), \
                redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(common+['--auto-parent']), 0)
        result = json.loads(out.getvalue())
        self.assertEqual(result['status'], 'SCHEMA2_AUTO_PLAN')
        self.assertEqual(read_json(self.root/'cli-plan/plan.json'), result)
        for extra in ([], ['--auto-parent','--key','research']):
            with self.subTest(extra=extra), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                cli.main(common+extra)
            self.assertEqual(caught.exception.code, 2)

    def test_cli_explicit_manual_mode_produces_unchanged_plan(self):
        self.write_registry()
        args = ['plan', '--key', 'research', '--sys-revision', self.targets['SPHinXsys'],
                '--sim-revision', self.targets['SPHinXsim'], '--output', str(self.root/'manual-cli')]
        with patch.object(cli, 'P', self.root), patch.object(trust, 'REGISTRY', self.registry_path), \
                redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(args), 0)
        self.assertEqual(json.loads(out.getvalue()), w.plan(self.root, self.registry, 'research', self.targets))


if __name__ == '__main__': unittest.main()
