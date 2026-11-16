"""Actual miniature extraction/full/R2 computations; no genuine Owner authority."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import test_parent_r2_anchor as parents
from test_upstream_provenance import git, commit
from src import approval_evidence as ev, ci_v2_research as c
from src import continuous_execution as run, continuous_build_policy as scope
from src import upstream_provenance as legacy, trusted_snapshot as trust
from src.corpus_snapshot import digest, file_digest, read_json

P = Path(__file__).resolve().parents[1]


def write(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


class ContinuousExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Existing factory executes P4.1/R2 on miniature controlled corpora. It
        # never touches genuine archived C1/C2 or invokes an external LLM.
        parents.AnchorTests.setUpClass()
        cls.addClassCleanup(parents.AnchorTests.doClassCleanups)
        temp = tempfile.TemporaryDirectory(prefix='continuous-execution-tests-')
        cls.addClassCleanup(temp.cleanup); cls.shared = Path(temp.name)
        cls.project = cls.shared / 'implementation'; cls.project.mkdir()
        paths = {'configs/ci_v2_runtime_lock.json', ev.BENCHMARK}
        def collect(value):
            if isinstance(value, dict):
                for key, child in value.items(): collect(key); collect(child)
            elif isinstance(value, (list, tuple)):
                for child in value: collect(child)
            elif isinstance(value, str) and value.startswith(('src/', 'scripts/', 'tests/', 'configs/', 'docs/')):
                if (P / value).is_file(): paths.add(value)
        collect(run.contract(P)); collect(read_json(c.LOCK)['quality_policy'])
        for name in paths:
            target = cls.project / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(P / name, target)
        (cls.project / 'tools').mkdir()
        (cls.project / 'tools/treesitter-chunker').symlink_to(P / 'tools/treesitter-chunker', target_is_directory=True)
        git(cls.project, 'init'); commit(cls.project)
        cls.base = parents.AnchorTests.shared / 'source1'
        cls.target = cls.shared / 'target'; shutil.copytree(cls.base, cls.target)
        cls.revisions = dict(parents.AnchorTests.revs)
        (cls.target / 'repos/SPHinXsys/src/a.cpp').write_text('int a() { return 900; }\n')
        (cls.target / 'repos/SPHinXsys/src/b.cpp').unlink()
        cls.revisions['SPHinXsys'] = commit(cls.target / 'repos/SPHinXsys')
        added = cls.target / 'repos/SPHinXsim/sphinxsim/bindings/new.py'
        added.write_text('def new_binding():\n    return 5\n')
        cls.revisions['SPHinXsim'] = commit(cls.target / 'repos/SPHinXsim')
        cls.ref = deepcopy(parents.AnchorTests.ref)
        cls.parent_archive = parents.AnchorTests.shared / 'approved.tar.gz'
        cls.parent_rows = parents.AnchorTests.shared / 'raw' / ev.RAW_FILES[0]
        selected, _ = legacy.verify_sources(cls.project, cls.target, cls.revisions)
        exact = {'schema_version': 2, 'operation': 'BUILD_CANDIDATE', 'research_only': True,
                 'experiment_id': 'SYNTHETIC_METADATA_ONLY_NOT_REAL_BUILD_APPROVAL',
                 'automatic_reuse': False, 'automatic_research_approval': False,
                 'production_promotion': 'NOT_AUTHORIZED', 'provenance_type': 'GENUINE_UPSTREAM',
                 'scope': {'parent': {'kind': 'RESEARCH_BASELINE', 'node_id': cls.ref['node_id'],
                                      'package_checksum': cls.ref['package_checksum']},
                           'base_upstreams': cls.ref['upstreams'], 'base_source_state': cls.ref['source_state'],
                           'target_upstreams': cls.revisions, 'target_source_state': legacy.state(selected),
                           'build_fingerprint': cls.ref['build_fingerprint'],
                           'orchestration_fingerprint': digest(legacy.contract(cls.project))}}
        write(cls.project / 'fixture-exact-policy.json', exact)
        cls.entry = {'reference': cls.ref, 'expected_reference_sha256': digest(cls.ref),
                     'build_policy_path': 'fixture-exact-policy.json',
                     'build_policy_sha256': file_digest(cls.project / 'fixture-exact-policy.json')}
        cls.registry = cls.project / 'fixture-registry.json'
        write(cls.registry, {'schema_version': 2, 'baselines': {'fixture-parent': cls.entry}})
        clock = datetime.now(timezone.utc)
        cls.policy = {'schema_version': 1, 'mode': scope.MODE, 'operation': 'BUILD_CANDIDATE',
                      'policy_id': 'synthetic-execution-not-owner-approved', 'enabled': True,
                      'research_only': True, 'valid_from': (clock - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                      'expires_at': (clock + timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                      'upstreams': {repo: {'url': url, 'repository_id': i, 'branch': 'fixture-branch'}
                                    for i, (repo, url) in enumerate(c.SOURCES.items(), 1)},
                      'eligible_parents': [{'key': 'fixture-parent', 'node_id': cls.ref['node_id'],
                                            'package_checksum': cls.ref['package_checksum'],
                                            'expected_reference_sha256': digest(cls.ref)}],
                      'build_fingerprint': cls.ref['build_fingerprint'],
                      'orchestration_fingerprint': digest(legacy.contract(cls.project)),
                      'max_advance_commits': 4, 'requirements': scope.REQUIREMENTS,
                      'automatic_registration': False, **c.RESTRICTIONS}
        cls.policy_path = 'fixture-continuous-policy.json'; write(cls.project / cls.policy_path, cls.policy)
        cls.pins = {'expected_execution_contract_sha256': digest(run.contract(cls.project)),
                    'expected_policy_sha256': file_digest(cls.project / cls.policy_path),
                    'expected_registry_sha256': file_digest(cls.registry),
                    'expected_reference_sha256': digest(cls.ref)}
        cls.responses = {}
        for repo, config in cls.policy['upstreams'].items():
            name = config['url'].removeprefix('https://github.com/').removesuffix('.git'); endpoint = 'repos/' + name
            cls.responses[endpoint] = {'id': config['repository_id'], 'full_name': name}
            cls.responses[endpoint + '/git/ref/heads/fixture-branch'] = {
                'ref': 'refs/heads/fixture-branch', 'object': {'type': 'commit', 'sha': cls.revisions[repo]}}
            for oid in {cls.ref['upstreams'][repo], cls.revisions[repo]}:
                tree, ancestors = legacy._commit(legacy._git(cls.target / 'repos' / repo, 'cat-file', 'commit', oid))
                cls.responses[endpoint + '/commits/' + oid] = {'sha': oid,
                    'html_url': 'https://github.com/' + name + '/commit/' + oid,
                    'commit': {'tree': {'sha': tree}}, 'parents': [{'sha': sha} for sha in ancestors]}
        cls.original = cls.shared / 'original'
        with cls.transport_context(), patch.object(scope, 'GitHubCLI', return_value=cls.client()):
            cls.result = cls.build(cls.original)

    @classmethod
    def client(cls):
        client = Mock(); client.json.side_effect = lambda endpoint: deepcopy(cls.responses[endpoint])
        return client

    @classmethod
    def transport_context(cls):
        def local_fixture_registry(registry, key):
            # Only adapt unavailable remote transport metadata. Full reference
            # validation and actual restore/Parent P4.1/R2 checks are NOT mocked.
            entry = registry['baselines'][key]
            trust.validate_reference(entry['reference'], entry['expected_reference_sha256'], controlled=True)
            return entry
        return patch.object(trust, 'registry_reference', side_effect=local_fixture_registry)

    @classmethod
    def build(cls, output, **overrides):
        return run._build_synthetic_fixture(cls.project, cls.parent_archive, cls.base, cls.target, output,
                 registry_path=cls.registry, policy_path=cls.policy_path, ref=cls.ref,
                 parent_rows_path=cls.parent_rows, revisions=cls.revisions, **{**cls.pins, **overrides})

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='continuous-verification-')
        self.addCleanup(temp.cleanup); self.root = Path(temp.name) / 'package'
        shutil.copytree(self.original, self.root)
        self.expected = {**self.pins, 'expected_candidate_id': self.result['candidate_id'],
                         'expected_manifest_sha256': self.result['manifest_sha256']}

    def verify(self, **overrides):
        return run.verify_package(self.project, self.root, **{**self.expected, **overrides})

    def reseal(self):
        (self.root / 'checksums.json').unlink(); run._seal(self.root)
        self.expected['expected_manifest_sha256'] = file_digest(self.root / 'checksums.json')

    def test_actual_build_full_parity_and_replay_receipts(self):
        result = self.verify(fresh_replay=True)
        self.assertEqual(result['status'], 'OFFLINE_PACKAGE_VERIFIED')
        self.assertEqual(result['replay'], 'FRESH_SYNTHETIC_R2_REPLAY')
        self.assertEqual(result['parity'], 'PARITY_PASS')
        self.assertEqual(len(read_json(self.root / 'incremental-replay.json')), 128)
        self.assertEqual(len(read_json(self.root / 'full-replay.json')), 128)
        self.assertEqual(result['live_authorization'], 'NOT_ESTABLISHED')
        self.assertEqual(result['trusted_parent_eligibility'], 'NOT_GRANTED')
        print('SYNTHETIC_EXECUTION_EVIDENCE ' + json.dumps({
            'candidate_id': result['candidate_id'],
            'generation': read_json(self.root / 'candidate/continuous-candidate.json')['identity']['generation'],
            'expected_execution_contract_sha256': self.pins['expected_execution_contract_sha256'],
            'actual_execution_contract_sha256': digest(run.contract(self.project)),
            'pin_origin': 'ISOLATED_TEST_FIXTURE_NOT_MAINTAINER_APPROVAL',
            'reuse': read_json(self.root / 'candidate/reuse-summary.json'),
            'parity': result['parity'], 'R2_rows_each': 128}, sort_keys=True))

    def test_actual_reuse_changed_extraction_and_deletion(self):
        summary = read_json(self.root / 'candidate/reuse-summary.json')
        self.assertGreater(summary['reused_files'], 0); self.assertGreater(summary['reused_chunks'], 0)
        self.assertEqual(summary['re_extracted_files'], 2); self.assertEqual(summary['deleted_files'], 1)
        events = read_json(self.root / 'candidate/extraction-trace.json')
        actual = [(e['repository'], e['path']) for e in events if e['file_processing_entry']]
        self.assertEqual(actual, [('SPHinXsys', 'src/a.cpp'), ('SPHinXsim', 'sphinxsim/bindings/new.py')])
        self.assertFalse((self.root / 'candidate/input/repos/SPHinXsys/src/b.cpp').exists())
        old = {engine_key(row): row for row in read_json(self.root / 'parent/inventory.json')}
        changes = {engine_key(row): row['change'] for row in read_json(self.root / 'candidate/change-manifest.json')}
        graph = {engine_key(row): row for row in read_json(self.root / 'parent/extraction-graph.json')}
        for row, evidence in zip(read_json(self.root / 'candidate/inventory.json'), read_json(self.root / 'candidate/extraction-graph.json')):
            if changes[engine_key(row)] == 'UNCHANGED':
                self.assertEqual(row['record_digest'], old[engine_key(row)]['record_digest'])
                self.assertEqual(evidence, graph[engine_key(row)])

    def test_deterministic_identity_across_independent_builds(self):
        output = self.root.parent / 'another-build'
        with self.transport_context(), patch.object(scope, 'GitHubCLI', return_value=self.client()):
            result = self.build(output)
        self.assertEqual(result['candidate_id'], self.result['candidate_id'])
        self.assertNotEqual(read_json(output / 'observations.json'), read_json(self.root / 'observations.json'))

    def test_offline_verification_makes_no_api_or_replay_call(self):
        with (patch.object(scope, 'GitHubCLI', side_effect=AssertionError('No API allowed')),
              patch.object(ev, 'replay', side_effect=AssertionError('No fresh replay allowed'))):
            self.assertEqual(self.verify()['replay'], 'SEALED_REPLAY_INSPECTED')

    def test_archive_verification_does_not_apply_todays_policy_clock(self):
        class FutureClock(datetime):
            @classmethod
            def now(cls, tz=None): return cls(2099, 1, 1, tzinfo=timezone.utc)
        with patch.object(scope, 'datetime', FutureClock):
            with self.assertRaises(c.GateError):
                scope.load_policy(self.project, self.policy_path, self.pins['expected_policy_sha256'])
            self.assertEqual(self.verify()['policy_validity_at_execution'], 'NOT_INDEPENDENTLY_ESTABLISHED')

    def test_saved_observation_does_not_prove_policy_time_or_owner_approval(self):
        value = read_json(self.root / 'observations.json'); value['started_at'] = '1900-01-01T00:00:00Z'
        write(self.root / 'observations.json', value); self.reseal()
        result = self.verify()
        self.assertEqual(result['historical_owner_authorization'], 'NOT_ESTABLISHED')
        self.assertEqual(result['policy_validity_at_execution'], 'NOT_INDEPENDENTLY_ESTABLISHED')
        self.assertEqual(result['candidate_id'], self.result['candidate_id'])

    def test_independent_pins_required(self):
        for key in self.expected:
            with self.subTest(key=key), self.assertRaises(ValueError): self.verify(**{key: '0' * 64})

    def test_live_entry_is_blocked_even_with_matching_independent_fixture_pins(self):
        with patch.object(scope, 'GitHubCLI') as api, patch.object(trust, 'restore') as restore:
            with self.assertRaises(c.GateError) as caught:
                run.execute(self.project, self.registry, self.policy_path,
                    **{k: v for k, v in self.pins.items() if k != 'expected_reference_sha256'})
        self.assertEqual(caught.exception.status, 'TRUSTED_CONTINUOUS_EXECUTION_NOT_ESTABLISHED')
        api.assert_not_called(); restore.assert_not_called()

    def test_live_bad_execution_pin_fails_before_policy_or_transport(self):
        with self.assertRaises(c.GateError) as caught:
            run.execute(self.project, self.registry, self.policy_path,
                expected_execution_contract_sha256=None, expected_policy_sha256=self.pins['expected_policy_sha256'],
                expected_registry_sha256=self.pins['expected_registry_sha256'])
        self.assertEqual(caught.exception.status, 'INDEPENDENT_EXECUTION_PIN_REQUIRED')

    def test_copy_cannot_impersonate_actual_loaded_execution_code(self):
        path = self.project / 'src/continuous_execution.py'; original = path.read_bytes()
        try:
            path.write_bytes(original + b'\n# different copied implementation\n')
            fake_pin = digest(run.contract(self.project))
            with self.assertRaises(c.GateError) as caught:
                run._implementation(self.project, fake_pin)
            self.assertEqual(caught.exception.status, 'PROJECT_DIFFERS_FROM_EXECUTING_IMPLEMENTATION')
        finally: path.write_bytes(original)

    def test_mutated_projection_rejected_even_with_new_seal(self):
        projection = read_json(self.root / 'candidate/candidate.json'); projection['kind'] = 'upstream-research-candidate'
        write(self.root / 'candidate/candidate.json', projection); self.reseal()
        with self.assertRaises(ValueError): self.verify()

    def test_wrong_candidate_identity_generation_and_unknown_fields(self):
        path = self.root / 'candidate/continuous-candidate.json'; original = read_json(path)
        for change in ({'generation': 999}, {'approved': True}, {'target_source_state': 'sha256-' + '0' * 64}):
            value = deepcopy(original); value['identity'].update(change)
            value['candidate_id'] = 'sha256-' + digest(value['identity']); write(path, value); self.reseal()
            with self.assertRaises(ValueError): self.verify(expected_candidate_id=value['candidate_id'])
        write(path, original)

    def test_source_and_git_proof_tampering_rejected(self):
        path = self.root / 'candidate/input/repos/SPHinXsys/src/a.cpp'
        path.write_text('altered source'); self.reseal()
        with self.assertRaises(ValueError): self.verify()

    def test_altered_archived_branch_evidence_rejected(self):
        path = self.root / 'evidence/assessment.json'; value = read_json(path)
        value['source_evidence']['source_refs']['SPHinXsys']['ref'] = 'refs/heads/unapproved'
        write(path, value); self.reseal()
        with self.assertRaises(ValueError): self.verify()

    def test_saved_assessment_cannot_turn_itself_into_approval(self):
        path = self.root / 'evidence/assessment.json'; value = read_json(path)
        value['execution_authorization'] = 'APPROVED'; value['approved'] = True
        write(path, value); self.reseal()
        with self.assertRaises(ValueError): self.verify()

    def test_controlled_candidate_cannot_be_relabelled_genuine(self):
        path = self.root / 'candidate/continuous-candidate.json'; value = read_json(path)
        value['identity']['provenance_type'] = 'GENUINE_UPSTREAM'
        value['candidate_id'] = 'sha256-' + digest(value['identity'])
        write(path, value); self.reseal()
        with self.assertRaises(ValueError): self.verify(expected_candidate_id=value['candidate_id'])

    def test_extra_missing_symlink_duplicate_json_and_unknown_format_rejected(self):
        extra = self.root / 'extra.json'; write(extra, {}); self.reseal()
        with self.assertRaises(ValueError): self.verify()
        extra.unlink(); self.reseal()
        extra.symlink_to('observations.json')
        with self.assertRaises(ValueError): self.verify()
        extra.unlink()
        (self.root / 'candidate/candidate.json').write_text('{"kind":"x","kind":"y"}')
        self.reseal()
        with self.assertRaises(ValueError): self.verify()

    def test_full_parity_corruption_and_raw_result_tampering_rejected(self):
        path = self.root / 'full/corpus.jsonl'; path.write_bytes(path.read_bytes() + b'{}\n'); self.reseal()
        with self.assertRaises(ValueError): self.verify()

    def test_raw_result_corruption_cannot_hide_behind_new_outer_seal(self):
        write(self.root / 'quality/incremental-raw-results.json', [])
        self.reseal()
        with self.assertRaises(ValueError): self.verify()

    def test_empty_unrecorded_directories_hardlinks_and_missing_files_rejected(self):
        directory = self.root / 'unrecorded-empty'; directory.mkdir()
        with self.assertRaises(ValueError): self.verify()
        directory.rmdir()
        link = self.root / 'hardlink.json'; os.link(self.root / 'observations.json', link)
        with self.assertRaises(ValueError): self.verify()
        link.unlink()
        (self.root / 'candidate/selection.json').unlink()
        with self.assertRaises(ValueError): self.verify()

    def test_owned_output_is_never_overwritten(self):
        before = file_digest(self.root / 'checksums.json')
        with self.assertRaises(ValueError): self.build(self.root)
        self.assertEqual(file_digest(self.root / 'checksums.json'), before)

    def test_replay_mismatch_rejected(self):
        write(self.root / 'full-replay.json', []); self.reseal()
        with self.assertRaises(ValueError): self.verify()

    def test_legacy_candidate_and_new_candidate_are_not_interchangeable(self):
        with self.assertRaises(ValueError):
            legacy.verify(self.project, self.root / 'candidate', self.ref['build_fingerprint'])
        path = self.root / 'candidate/continuous-candidate.json'; write(path, {'schema_version': 2, 'kind': 'upstream-research-candidate'})
        self.reseal()
        with self.assertRaises(ValueError): self.verify()

    def test_parent_corruption_and_fresh_parent_replay_are_mandatory(self):
        output = self.root.parent / 'must-not-exist'
        with (self.transport_context(), patch.object(scope, 'GitHubCLI', return_value=self.client()),
              patch.object(ev, 'replay', return_value=[])):
            with self.assertRaises(ValueError): self.build(output)
        self.assertFalse(output.exists())
        (self.root / 'parent/approval-evidence/verification.json').write_text('{}'); self.reseal()
        with self.assertRaises(ValueError): self.verify()

    def test_changed_target_during_construction_fails_without_publication(self):
        output = self.root.parent / 'must-not-exist'; original = scope.revalidate_scope
        def mutate(*args, **kwargs):
            path = self.target / 'repos/SPHinXsys/src/a.cpp'; before = path.read_bytes()
            path.write_text('dirty during build')
            try: return original(*args, **kwargs)
            finally: path.write_bytes(before)
        with (self.transport_context(), patch.object(scope, 'GitHubCLI', return_value=self.client()),
              patch.object(scope, 'revalidate_scope', side_effect=mutate)):
            with self.assertRaises(ValueError): self.build(output)
        self.assertFalse(output.exists())

    def test_no_approval_registration_or_production_claims_and_old_contract_unchanged(self):
        result = self.verify()
        for key, value in c.RESTRICTIONS.items(): self.assertEqual(result[key], value)
        self.assertEqual(result['provenance_type'], run.SYNTHETIC)
        self.assertEqual(digest(legacy.contract(P)), 'b0b43411aef4d716a15a2f0a794071523fbb3c260dc4cb3fc9b2736eed9e1ac1')
        self.assertFalse((self.root / 'candidate/upstream-baseline.json').exists())


def engine_key(row):
    return row['repository'], row['path']


if __name__ == '__main__': unittest.main()
