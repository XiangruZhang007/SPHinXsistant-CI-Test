"""Non-P2 metadata/lineage gates; all asset IDs and paths are isolated fixtures."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from src import schema2_workflow as w, trusted_snapshot as trust, ci_v2_research as c
from src.corpus_snapshot import digest, file_digest, read_json

P = Path(__file__).resolve().parents[1]


class ResearchPlanningTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.ref = copy.deepcopy(read_json(trust.REGISTRY)['baselines']['p2-initial-bootstrap']['reference'])
        self.ref.update(package_format='schema2-research-baseline', accepted_package_schema=2,
                        node_id='sha256-' + 'a' * 64, package_checksum='b' * 64)
        self.ref['authorization']['type'] = 'EXPLICIT_RESEARCH_BASELINE_REUSE'
        for name, asset in [('storage', 101), ('parent_rows_storage', 102)]:
            self.ref[name].update(release_id=100, asset_id=asset, tag='synthetic-research-fixture',
                                 asset_name=name + '.fixture')
        self.revisions = {'SPHinXsys': 'c' * 40, 'SPHinXsim': 'd' * 40}
        self.policy = {'schema_version': 2, 'operation': 'BUILD_CANDIDATE', 'research_only': True,
            'experiment_id': 'SYNTHETIC_HOSTED_PLANNING_FIXTURE', 'provenance_type': 'GENUINE_UPSTREAM',
            'automatic_reuse': False, 'automatic_research_approval': False,
            'production_promotion': 'NOT_AUTHORIZED', 'scope': {
                'parent': {'kind': 'RESEARCH_BASELINE', 'node_id': self.ref['node_id'],
                           'package_checksum': self.ref['package_checksum']},
                'base_upstreams': self.ref['upstreams'], 'base_source_state': self.ref['source_state'],
                'build_fingerprint': self.ref['build_fingerprint'], 'target_upstreams': self.revisions}}

    def registry(self):
        path = self.root / 'policy.json'
        path.write_text(json.dumps(self.policy))
        return {'schema_version': 2, 'baselines': {'research': {
            'reference': self.ref, 'expected_reference_sha256': digest(self.ref),
            'build_policy_path': 'policy.json', 'build_policy_sha256': file_digest(path)}}}

    def plan(self):
        return w.plan(self.root, self.registry(), 'research', self.revisions)

    def test_verified_remote_baseline_selection_supports_public_and_private_release(self):
        for kind in (trust.PUBLIC_RELEASE_KIND, trust.PRIVATE_RELEASE_KIND):
            with self.subTest(kind=kind):
                ref = copy.deepcopy(self.ref)
                ref['storage']['kind'] = kind
                self.assertEqual(w._remote_baseline_selection(ref), 'PINNED_REFERENCE_VERIFIED')

    def test_local_baseline_selection_still_requires_remote_configuration(self):
        ref = copy.deepcopy(self.ref)
        ref['storage'] = {'kind': 'LOCAL_QUALIFICATION_ONLY'}
        self.assertEqual(w._remote_baseline_selection(ref), 'CONFIGURATION_REQUIRED')

    def test_research_plan_is_metadata_only_and_does_not_claim_qualification(self):
        with patch.object(trust, 'download') as download, patch.object(w, 'qualify_parent_anchor') as qualify:
            planned = self.plan()
        self.assertEqual(planned['status'], 'SCHEMA2_MANUAL_PLAN')
        self.assertNotIn('parent_r2_anchor', planned)
        self.assertFalse(planned['research_baseline_created'])
        self.assertFalse(planned['automatic_research_approval'])
        self.assertEqual(planned['production_promotion'], 'NOT_AUTHORIZED')
        download.assert_not_called()
        qualify.assert_not_called()

    def test_research_planning_remains_stdlib_only(self):
        registry = self.root / 'registry.json'
        registry.write_text(json.dumps(self.registry()))
        # No site-packages means parser packages cannot accidentally be required.
        code = ('import json,sys; from pathlib import Path; from src.schema2_workflow import plan; '
                'r=json.load(open(sys.argv[1])); '
                'v=r["baselines"]["research"]; '
                'p=json.load(open(Path(sys.argv[1]).parent / v["build_policy_path"])); '
                'print(plan(Path(sys.argv[1]).parent,r,"research",p["scope"]["target_upstreams"])["status"])')
        run = subprocess.run([sys.executable, '-B', '-S', '-c', code, str(registry)],
                             cwd=P, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), 'SCHEMA2_MANUAL_PLAN')

    def test_local_only_and_incomplete_release_references_fail_before_transport(self):
        for kind in ('local', 'incomplete'):
            with self.subTest(kind=kind):
                original = copy.deepcopy(self.ref)
                if kind == 'local': self.ref['storage'] = {'kind': 'LOCAL_QUALIFICATION_ONLY'}
                else: self.ref['parent_rows_storage'].pop('asset_id')
                with patch.object(trust, 'download') as download, self.assertRaises(c.GateError):
                    self.plan()
                download.assert_not_called()
                self.ref = original

    def test_stale_local_reference_pin_cannot_authorize_remote_locator(self):
        registry = self.registry()
        registry['baselines']['research']['reference']['storage']['asset_id'] += 1
        with self.assertRaises(c.GateError) as caught:
            w.plan(self.root, registry, 'research', self.revisions)
        self.assertEqual(caught.exception.status, 'INVALID_REFERENCE')

    def test_wrong_parent_scope_is_rejected(self):
        cases = [('parent', {'kind': 'CANDIDATE'}), ('base_upstreams', self.revisions),
                 ('base_source_state', 'sha256-' + '0' * 64), ('build_fingerprint', '0' * 64)]
        for field, value in cases:
            original = copy.deepcopy(self.policy)
            self.policy['scope'][field] = value
            with self.subTest(field=field), self.assertRaises(c.GateError) as caught:
                self.plan()
            self.assertEqual(caught.exception.status, 'AUTHORIZATION_FAILED')
            self.policy = original

    def test_research_scope_rejects_wrong_parent_receipt_fields(self):
        for field, value in [('node_id', 'sha256-' + '0' * 64), ('package_checksum', '0' * 64),
                             ('kind', 'P2_ANCHOR')]:
            original = copy.deepcopy(self.policy)
            self.policy['scope']['parent'][field] = value
            with self.subTest(field=field), self.assertRaises(c.GateError): self.plan()
            self.policy = original

    def test_automatic_approval_production_or_controlled_bypass_is_rejected(self):
        cases = [('automatic_reuse', True), ('automatic_research_approval', True),
                 ('production_promotion', 'AUTHORIZED'), ('controlled_chain_fixture', {'candidate_id': 'fake'}),
                 ('operation', 'APPROVE'), ('research_only', False)]
        for field, value in cases:
            original = copy.deepcopy(self.policy)
            self.policy[field] = value
            with self.subTest(field=field), self.assertRaises(c.GateError): self.plan()
            self.policy = original

    def test_wrong_exact_target_and_policy_digest_are_rejected(self):
        registry = self.registry()
        with self.assertRaises(c.GateError):
            w.plan(self.root, registry, 'research', {'SPHinXsys': '0' * 40, 'SPHinXsim': '1' * 40})
        (self.root / 'policy.json').write_text('{}')
        with self.assertRaises(c.GateError): w.plan(self.root, registry, 'research', self.revisions)

    def execute(self, *, failure=None):
        registry = self.registry()
        registry_path, plan_path = self.root / 'registry.json', self.root / 'plan.json'
        registry_path.write_text(json.dumps(registry))
        plan_path.write_text(json.dumps(w.plan(self.root, registry, 'research', self.revisions)))
        work, output = self.root / 'work', self.root / 'run'
        with patch.object(trust, 'REGISTRY', registry_path), patch.object(c, 'frozen_runtime'), \
                patch.object(w.shutil, 'disk_usage', return_value=SimpleNamespace(free=9 * 1024**3)), \
                patch.object(trust, 'download') as download, patch.object(w.subprocess, 'run'), \
                patch.object(w, 'run_local', return_value=c.RESTRICTIONS, side_effect=failure) as local, \
                patch.object(c, 'package_candidate') as package:
            if failure:
                with self.assertRaises(c.GateError):
                    w.execute_plan(self.root, plan_path, work, output)
                package.assert_not_called()
            else:
                self.assertEqual(w.execute_plan(self.root, plan_path, work, output), c.RESTRICTIONS)
                package.assert_called_once_with(output, output.parent / 'candidate.tar.gz')
            self.assertEqual(download.call_count, 2)
            self.assertEqual([call.kwargs for call in download.call_args_list], [{}, {}])
            self.assertEqual(local.call_args.args[5:7], (self.ref, digest(self.ref)))
            self.assertEqual(local.call_args.args[-1], work / 'parent-rows.json')
            self.assertEqual(local.call_args.kwargs, {'q1_inputs': None, 'q1_sha': None})

    def test_execute_plan_delivers_exact_research_reference_and_rows_to_local_checks(self):
        self.execute()

    def test_execute_plan_cannot_package_after_research_qualification_failure(self):
        self.execute(failure=c.GateError('PARENT_RETRIEVAL_ANCHOR_NOT_QUALIFIED', 'Fixture refusal'))

    def test_execute_plan_passes_token_only_for_same_repository_private_assets(self):
        for name, asset_id in [('storage', 101), ('parent_rows_storage', 102)]:
            self.ref[name].update(kind=trust.PRIVATE_RELEASE_KIND, repository='research-owner/research-ci',
                repository_id=99001, asset_size=1234 if name == 'storage' else 567,
                release_id=100, asset_id=asset_id, tag='synthetic-research-fixture',
                asset_name=name + '.fixture')
        registry = self.registry()
        registry_path, plan_path = self.root / 'private-registry.json', self.root / 'private-plan.json'
        registry_path.write_text(json.dumps(registry))
        work, output = self.root / 'private-work', self.root / 'private-run'
        with patch.dict('os.environ', {'GITHUB_REPOSITORY': 'research-owner/research-ci',
                'GITHUB_REPOSITORY_ID': '99001', 'TRUSTED_RELEASE_TOKEN': 'synthetic-workflow-token'}):
            planned = w.plan(self.root, registry, 'research', self.revisions)
            plan_path.write_text(json.dumps(planned))
            with patch.object(trust, 'REGISTRY', registry_path), patch.object(c, 'frozen_runtime'), \
                    patch.object(w.shutil, 'disk_usage', return_value=SimpleNamespace(free=9 * 1024**3)), \
                    patch.object(trust, 'download') as download, patch.object(w.subprocess, 'run'), \
                    patch.object(w, 'run_local', return_value=c.RESTRICTIONS), \
                    patch.object(c, 'package_candidate'):
                w.execute_plan(self.root, plan_path, work, output)
        self.assertEqual(download.call_count, 2)
        self.assertEqual([call.kwargs for call in download.call_args_list], [
            {'token': 'synthetic-workflow-token'}, {'token': 'synthetic-workflow-token'}])

    def edge(self):
        parent, child = self.root / 'parent', self.root / 'candidate'
        parent.mkdir(exist_ok=True); child.mkdir(exist_ok=True)
        (parent / 'upstream-baseline.json').write_text(json.dumps({
            'baseline_id': self.ref['node_id'], 'identity': {'generation': self.parent_generation}}))
        (child / 'upstream-candidate.json').write_text(json.dumps({'identity': self.child}))
        w._research_parent_edge(self.ref, parent, child)

    def set_edge(self):
        self.parent_generation = 1
        self.child = {**self.policy['scope'], 'base_snapshot_id': self.ref['node_id'], 'generation': 2}

    def test_selected_parent_edge_and_next_generation(self):
        self.set_edge()
        self.edge()

    def test_wrong_child_parent_binding_or_generation_is_rejected(self):
        self.set_edge()
        for field, value in [('generation', 1), ('generation', True),
                ('parent', {'kind': 'CANDIDATE'}), ('base_snapshot_id', 'sha256-' + '0' * 64),
                ('base_source_state', 'sha256-' + '0' * 64), ('base_upstreams', self.revisions),
                ('build_fingerprint', '0' * 64)]:
            original = copy.deepcopy(self.child)
            self.child[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(c.GateError): self.edge()
            self.child = original

    def test_invalid_parent_generation_is_rejected(self):
        self.set_edge()
        for value in (0, True, '1'):
            self.parent_generation = value
            with self.subTest(value=value), self.assertRaises(c.GateError): self.edge()


if __name__ == '__main__': unittest.main()
