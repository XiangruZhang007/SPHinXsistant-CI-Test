"""Synthetic source trees and mocked official API GETs; no build or retrieval."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import Mock, patch

import test_trusted_parent_selection as fixtures
from test_incremental_corpus import make_sources
from src import ci_v2_research as c, continuous_build_policy as scope
from src import upstream_provenance as u, incremental_corpus as inc, research_baseline as baseline
from src import trusted_snapshot as trust, schema2_workflow as workflow
from src.corpus_snapshot import digest, file_digest, read_json

P = Path(__file__).resolve().parents[1]


def git(root, *args):
    return subprocess.check_output(
        ['git', '-c', 'user.name=Synthetic Fixture', '-c', 'user.email=fixture@example.invalid',
         '-c', 'core.autocrlf=false', '-C', str(root), *args], stderr=subprocess.PIPE).decode().strip()


def commit(root):
    git(root, 'add', '--all'); git(root, 'commit', '-qm', 'Synthetic offline source')
    return git(root, 'rev-parse', 'HEAD')


class ContinuousPolicyTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.SelectionTests(); self.fx.setUp(); self.addCleanup(self.fx.doCleanups)
        self.root = self.fx.root
        # Copy only small configuration/contract files; no Corpus or Baseline.
        paths = {*u.FILES, *inc.P3_FILES, *baseline.P4_FILES,
                 'configs/ci_v2_runtime_lock.json', 'configs/indexing_scope.json',
                 'configs/documentation_scope.json'}
        for name in paths:
            target = self.root / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(P / name, target)
        self.base = self.root / 'base-source'; make_sources(self.base)
        self.base_revs = {}
        for repo, url in c.SOURCES.items():
            root = self.base / 'repos' / repo
            git(root, 'init', '-q'); git(root, 'remote', 'add', 'origin', url)
            self.base_revs[repo] = commit(root)
        self.target = self.root / 'target-source'; shutil.copytree(self.base, self.target)
        self.revs = dict(self.base_revs)
        (self.target / 'repos/SPHinXsys/src/a.cpp').write_text('int a() { return 5; }\n')
        self.revs['SPHinXsys'] = commit(self.target / 'repos/SPHinXsys')
        self.bind_parent('research')
        clock = datetime.now(timezone.utc)
        self.policy = {'schema_version': 1, 'mode': scope.MODE, 'operation': 'BUILD_CANDIDATE',
                       'policy_id': 'synthetic-not-owner-approved', 'enabled': True,
                       'research_only': True,
                       'valid_from': (clock - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                       'expires_at': (clock + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                       'upstreams': {repo: {'url': url, 'repository_id': index,
                                            'branch': 'master' if repo == 'SPHinXsys' else 'main'}
                                     for index, (repo, url) in enumerate(c.SOURCES.items(), 1)},
                       'eligible_parents': [self.parent_pin('research')],
                       'build_fingerprint': digest(read_json(c.LOCK)['P2']),
                       'orchestration_fingerprint': digest(u.contract(P)),
                       'max_advance_commits': 4, 'requirements': deepcopy(scope.REQUIREMENTS),
                       'automatic_registration': False, **c.RESTRICTIONS}
        self.policy_path = 'continuous-fixture.json'; self.save_policy()
        self.responses = self.api_responses()
        self.client = Mock()
        self.client.json.side_effect = lambda endpoint: deepcopy(self.responses[endpoint])
        mocked = patch.object(scope, 'GitHubCLI', return_value=self.client)
        mocked.start(); self.addCleanup(mocked.stop)

    def bind_parent(self, key):
        entry = self.fx.registry['baselines'][key]; ref = entry['reference']
        source, _ = u.verify_sources(self.root, self.base, self.base_revs)
        ref.update(upstreams=dict(self.base_revs), source_state=u.state(source))
        entry['expected_reference_sha256'] = digest(ref)
        policy = self.fx.policy(key)
        policy['scope'].update(base_upstreams=ref['upstreams'], base_source_state=ref['source_state'],
                               orchestration_fingerprint=digest(u.contract(P)))
        self.fx.write_policy(key, policy); self.fx.write_registry()

    def parent_pin(self, key):
        entry = self.fx.registry['baselines'][key]
        return {'key': key, 'node_id': entry['reference']['node_id'],
                'package_checksum': entry['reference']['package_checksum'],
                'expected_reference_sha256': entry['expected_reference_sha256']}

    def save_policy(self):
        (self.root / self.policy_path).write_text(json.dumps(self.policy, sort_keys=True))

    def api_responses(self):
        result = {}
        for repo, config in self.policy['upstreams'].items():
            name = config['url'].removeprefix('https://github.com/').removesuffix('.git')
            endpoint = 'repos/' + name
            result[endpoint] = {'id': config['repository_id'], 'full_name': name}
            result[endpoint + '/git/ref/heads/' + config['branch']] = {
                'ref': 'refs/heads/' + config['branch'],
                'object': {'type': 'commit', 'sha': self.revs[repo]}}
            for oid in {self.base_revs[repo], self.revs[repo]}:
                raw = u._git(self.target / 'repos' / repo, 'cat-file', 'commit', oid)
                tree, parents = u._commit(raw)
                result[endpoint + '/commits/' + oid] = {
                    'sha': oid, 'html_url': 'https://github.com/' + name + '/commit/' + oid,
                    'commit': {'tree': {'sha': tree}}, 'parents': [{'sha': p} for p in parents]}
        return result

    def arguments(self):
        return {'expected_policy_sha256': file_digest(self.root / self.policy_path),
                'expected_registry_sha256': file_digest(self.fx.registry_path),
                'revisions': self.revs, 'base_source': self.base, 'target_source': self.target}

    def assess(self, **overrides):
        return scope.assess_scope(self.root, self.fx.registry_path, self.policy_path,
                                  **{**self.arguments(), **overrides})

    def reject(self, **overrides):
        with self.assertRaises((ValueError, TypeError, KeyError, OSError)):
            self.assess(**overrides)

    def test_valid_scope_uses_actual_git_source_and_live_mocked_ref_checks(self):
        with patch.object(u, 'build') as build, patch.object(trust, 'download') as download:
            result = self.assess()
        self.assertEqual(result['status'], scope.PLAN_STATUS)
        subject = result['subject']; evidence = result['source_evidence']
        self.assertEqual(subject['upstreams'], self.revs)
        self.assertEqual(subject['target_source_state'], u.state(evidence['target_selection']))
        self.assertEqual(subject['source_evidence_sha256'], digest(evidence))
        self.assertEqual(evidence['relationships']['SPHinXsys']['type'], 'FAST_FORWARD')
        self.assertEqual(evidence['relationships']['SPHinXsim']['type'], 'SAME_COMMIT')
        self.assertEqual(result['execution_authorization'], 'BLOCKED')
        self.assertEqual(result['parent_package_qualification'], 'NOT_PERFORMED')
        self.assertTrue(self.client.json.called); build.assert_not_called(); download.assert_not_called()

    def test_deterministic_subject_and_no_writes(self):
        before = {p.relative_to(self.root).as_posix(): file_digest(p)
                  for p in self.root.rglob('*') if p.is_file()}
        first = self.assess(); self.assertEqual(first, self.assess())
        after = {p.relative_to(self.root).as_posix(): file_digest(p)
                 for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(first['execution_identity'], digest(first['subject']))

    def test_independent_pin_required_and_raw_bytes_are_pinned(self):
        self.reject(expected_policy_sha256=None)
        self.reject(expected_policy_sha256='0' * 64)
        self.reject(expected_policy_sha256=digest(self.policy))
        old = self.arguments()['expected_policy_sha256']
        with (self.root / self.policy_path).open('a') as f: f.write('\n')
        self.reject(expected_policy_sha256=old)

    def test_disabled_fixture_cannot_be_used(self):
        self.policy['enabled'] = False; self.save_policy(); self.reject()
        self.assertFalse(self.client.json.called)

    def test_policy_symlink_is_not_an_independent_reviewed_file(self):
        path = self.root / self.policy_path
        path.rename(self.root / 'original-fixture.json')
        path.symlink_to('original-fixture.json'); self.reject()

    def test_missing_duplicate_unknown_and_malformed_fields(self):
        original = deepcopy(self.policy)
        for mutate in (lambda p: p.pop('eligible_parents'), lambda p: p.update(approved=True),
                       lambda p: p.update(schema_version=True), lambda p: p.update(upstreams=[]),
                       lambda p: p.update(max_advance_commits=True), lambda p: p.update(valid_from='yesterday')):
            with self.subTest(mutation=mutate):
                self.policy = deepcopy(original); mutate(self.policy); self.save_policy(); self.reject()
        (self.root / self.policy_path).write_text('{"mode":"CONTINUOUS_SCOPE","mode":"EXACT_TARGET"}')
        self.reject()

    def test_stale_or_future_authorization_rejected(self):
        self.policy['expires_at'] = '2000-01-01T00:00:00Z'; self.save_policy(); self.reject()
        self.policy['valid_from'] = '2099-01-01T00:00:00Z'
        self.policy['expires_at'] = '2100-01-01T00:00:00Z'; self.save_policy(); self.reject()

    def test_research_production_and_scheduling_restrictions_cannot_change(self):
        original = deepcopy(self.policy)
        for key, value in [('scheduled_execution', True), ('automatic_registration', True),
                           ('automatic_research_approval', True), ('automatic_reuse', True),
                           ('production_promotion', 'AUTHORIZED'), ('requirements', {})]:
            with self.subTest(key=key):
                self.policy = deepcopy(original); self.policy[key] = value; self.save_policy(); self.reject()

    def test_generated_record_is_not_authority_or_legacy_executable_plan(self):
        planned = self.assess()
        self.reject(expected_policy_sha256=planned['subject']['policy_canonical_sha256'])
        self.policy['generated_approval'] = planned; self.save_policy(); self.reject()
        path = self.root / 'assessment.json'; path.write_text(json.dumps(planned))
        with self.assertRaises(ValueError): u._policy(path, file_digest(path))
        with patch.object(workflow, 'run_local') as run, patch.object(trust, 'download') as download:
            with self.assertRaises((ValueError, KeyError)):
                workflow.execute_plan(self.root, path, self.root / 'work', self.root / 'output')
        run.assert_not_called(); download.assert_not_called()

    def test_wrong_upstream_repository_scope_and_ids(self):
        self.policy['upstreams']['SPHinXsys']['url'] = 'https://github.com/untrusted/fork.git'
        self.save_policy(); self.reject()
        self.policy['upstreams']['SPHinXsys']['url'] = c.SOURCES['SPHinXsys']
        self.save_policy(); self.responses['repos/Xiangyu-Hu/SPHinXsys']['id'] = 999; self.reject()

    def test_branch_must_be_bound_by_official_ref_not_detector_or_ancestry(self):
        endpoint = 'repos/Xiangyu-Hu/SPHinXsys/git/ref/heads/master'
        for change in ({'sha': self.base_revs['SPHinXsys']}, {'type': 'tag'}):
            original = deepcopy(self.responses[endpoint])
            self.responses[endpoint]['object'].update(change); self.reject()
            self.responses[endpoint] = original
        self.responses[endpoint]['ref'] = 'refs/heads/unapproved'; self.reject()

    def test_branch_scope_rejects_wildcard_and_unsafe_names(self):
        for name in ('*', '../main', 'main.lock', '/main', 'main//other', 'main?x=1'):
            self.policy['upstreams']['SPHinXsys']['branch'] = name
            self.save_policy(); self.reject()

    def test_api_unavailable_and_altered_publication_receipt(self):
        endpoint = 'repos/Xiangyu-Hu/SPHinXsys/commits/' + self.revs['SPHinXsys']
        self.responses[endpoint]['commit']['tree']['sha'] = 'a' * 40; self.reject()
        self.client.json.side_effect = RuntimeError('token-bearing message must not escape')
        with self.assertRaises(c.GateError) as caught: self.assess()
        self.assertEqual(str(caught.exception), 'SOURCE_REF_UNAVAILABLE')

    def test_malformed_live_commit_receipts_return_blocked_reason(self):
        endpoint = 'repos/Xiangyu-Hu/SPHinXsys/commits/' + self.revs['SPHinXsys']
        original = deepcopy(self.responses[endpoint])
        for malformed in ({'commit': {'tree': None}}, {'parents': [None]}, {'commit': None}):
            self.responses[endpoint] = {**deepcopy(original), **malformed}
            with self.assertRaises(c.GateError) as caught: self.assess()
            self.assertEqual(caught.exception.status, 'SOURCE_PUBLICATION_MISMATCH')

    def test_missing_unknown_or_dirty_source_is_rejected(self):
        bad = dict(self.revs, SPHinXsys='f' * 40); self.reject(revisions=bad)
        (self.target / 'repos/SPHinXsys/src/a.cpp').write_text('uncommitted')
        self.reject()

    def test_same_commit_pair_has_verified_same_relationships(self):
        git(self.target / 'repos/SPHinXsys', 'checkout', '--detach', self.base_revs['SPHinXsys'])
        self.revs = dict(self.base_revs); self.responses = self.api_responses()
        planned = self.assess()
        self.assertTrue(all(p['type'] == 'SAME_COMMIT'
                            for p in planned['source_evidence']['relationships'].values()))
        self.assertEqual(planned['execution_authorization'], 'BLOCKED')

    def test_actual_parent_source_state_cannot_be_asserted_by_metadata(self):
        entry = self.fx.registry['baselines']['research']
        entry['reference']['source_state'] = 'sha256-' + '0' * 64
        entry['expected_reference_sha256'] = digest(entry['reference'])
        exact = self.fx.policy(); exact['scope']['base_source_state'] = entry['reference']['source_state']
        self.fx.write_policy('research', exact); self.fx.write_registry()
        self.policy['eligible_parents'] = [self.parent_pin('research')]; self.save_policy()
        self.reject()

    def test_divergent_and_rollback_relationships_are_rejected(self):
        root = self.target / 'repos/SPHinXsys'; forward = self.revs['SPHinXsys']
        original = self.base_revs['SPHinXsys']
        # Make the Parent the forward commit, then test its sibling and ancestor.
        git(self.base / 'repos/SPHinXsys', 'fetch', str(root), forward)
        git(self.base / 'repos/SPHinXsys', 'checkout', '--detach', forward)
        self.base_revs['SPHinXsys'] = forward
        self.bind_parent('research'); self.policy['eligible_parents'] = [self.parent_pin('research')]
        self.save_policy()
        git(root, 'checkout', '--detach', original)
        (root / 'src/a.cpp').write_text('int divergent() { return 9; }\n')
        self.revs['SPHinXsys'] = commit(root); self.responses = self.api_responses(); self.reject()
        git(root, 'checkout', '--detach', original)
        self.revs['SPHinXsys'] = original
        self.responses = self.api_responses(); self.reject()

    def test_bounded_advance_rejected(self):
        root = self.target / 'repos/SPHinXsys'
        (root / 'src/a.cpp').write_text('int next() { return 6; }\n')
        self.revs['SPHinXsys'] = commit(root)
        self.policy['max_advance_commits'] = 1; self.save_policy()
        self.responses = self.api_responses(); self.reject()

    def test_parent_source_state_and_policy_fingerprints_bound(self):
        self.policy['build_fingerprint'] = '0' * 64; self.save_policy(); self.reject()
        self.policy['build_fingerprint'] = digest(read_json(c.LOCK)['P2'])
        self.policy['orchestration_fingerprint'] = '0' * 64; self.save_policy(); self.reject()

    def test_registration_only_and_missing_scoped_parent_never_fall_back(self):
        entry = self.fx.registry['baselines']['research']
        entry.pop('build_policy_path'); entry.pop('build_policy_sha256'); entry['entry_kind'] = 'REGISTRATION_ONLY'
        self.fx.write_registry(); self.reject()
        self.fx.registry['baselines'].clear(); self.fx.write_registry(); self.reject()

    def test_ambiguous_parent_and_corrupt_unselected_policy_fail_closed(self):
        self.fx.add_parent('other', 'second'); self.bind_parent('other')
        self.policy['eligible_parents'].append(self.parent_pin('other')); self.save_policy(); self.reject()
        self.policy['eligible_parents'].pop(); self.save_policy()
        (self.root / 'other-policy.json').write_text('{}'); self.reject()

    def test_wrong_scoped_parent_identity_and_duplicate_scope_rejected(self):
        self.policy['eligible_parents'][0]['package_checksum'] = '0' * 64
        self.save_policy(); self.reject()
        self.policy['eligible_parents'] = [self.parent_pin('research')] * 2
        self.save_policy(); self.reject()

    def test_registry_pin_and_parent_binding_changes_rejected(self):
        old = self.arguments()['expected_registry_sha256']
        self.fx.registry['note'] += ' changed'; self.fx.write_registry()
        self.reject(expected_registry_sha256=old)
        self.fx.registry['baselines']['research']['expected_reference_sha256'] = '0' * 64
        self.fx.write_registry(); self.reject()

    def revalidate(self, planned, **overrides):
        return scope.revalidate_scope(planned, self.root, self.fx.registry_path, self.policy_path,
                                      expected_plan_sha256=digest(planned),
                                      **{**self.arguments(), **overrides})

    def test_execution_boundary_rechecks_and_remains_blocked(self):
        planned = self.assess(); before = self.client.json.call_count
        result = self.revalidate(planned)
        self.assertGreater(self.client.json.call_count, before)
        self.assertEqual(result['execution_authorization'], 'BLOCKED')
        self.assertEqual(result['status'], 'SCOPE_REVALIDATED_EXECUTION_BLOCKED')
        self.assertFalse(result['scheduled_execution'])

    def test_revalidation_rejects_policy_registry_source_or_ref_change(self):
        planned = self.assess(); pins = self.arguments()
        self.policy['policy_id'] += '-changed'; self.save_policy()
        with self.assertRaises(ValueError): self.revalidate(planned, **pins)
        with self.assertRaises(ValueError): self.revalidate(planned)
        self.policy['policy_id'] = 'synthetic-not-owner-approved'; self.save_policy()
        self.responses['repos/Xiangyu-Hu/SPHinXsys/git/ref/heads/master']['object']['sha'] = 'e' * 40
        with self.assertRaises(ValueError): self.revalidate(planned)

    def test_revalidation_rejects_registry_and_source_changes(self):
        planned = self.assess(); pins = self.arguments()
        self.fx.registry['note'] += ' changed'; self.fx.write_registry()
        with self.assertRaises(ValueError): self.revalidate(planned, **pins)
        with self.assertRaises(ValueError): self.revalidate(planned)
        self.fx.registry['note'] = 'synthetic isolated fixture'; self.fx.write_registry()
        (self.target / 'repos/SPHinXsys/src/a.cpp').write_text('dirty source')
        with self.assertRaises(ValueError): self.revalidate(planned)

    def test_policy_change_during_live_ref_observation_rejected(self):
        def changing(endpoint):
            self.policy['policy_id'] = 'changed-during-observation'; self.save_policy()
            return deepcopy(self.responses[endpoint])
        self.client.json.side_effect = changing
        self.reject()

    def test_exact_parent_policy_change_during_observation_rejected(self):
        def changing(endpoint):
            (self.root / 'research-policy.json').write_text('{}')
            return deepcopy(self.responses[endpoint])
        self.client.json.side_effect = changing
        self.reject()

    def test_actual_source_change_during_observation_rejected(self):
        def changing(endpoint):
            (self.target / 'repos/SPHinXsys/src/a.cpp').write_text('changed during observation')
            return deepcopy(self.responses[endpoint])
        self.client.json.side_effect = changing
        self.reject()

    def test_result_cannot_mutate_mandatory_check_contract(self):
        result = self.assess(); result['requirements']['p8'] = 'PASS'
        self.assertEqual(scope.REQUIREMENTS['p8'], 'BLOCKED')
        self.assertEqual(self.assess()['requirements']['p8'], 'BLOCKED')

    def test_plan_tampering_and_missing_independent_pin_cannot_self_authorize(self):
        planned = self.assess(); expected = digest(planned)
        planned['execution_authorization'] = 'APPROVED'
        with self.assertRaises(ValueError):
            scope.revalidate_scope(planned, self.root, self.fx.registry_path, self.policy_path,
                                   expected_plan_sha256=expected, **self.arguments())
        with self.assertRaises(ValueError): self.revalidate(planned)
        with self.assertRaises(TypeError):
            scope.assess_scope(self.root, self.fx.registry_path, self.policy_path,
                               revisions=self.revs, base_source=self.base, target_source=self.target)

    def test_historical_c1_orchestration_and_frozen_contracts_unchanged(self):
        historical = read_json(P / 'configs/ci_v2_c1_c2_build_policy.json')
        self.assertEqual(digest(u.contract(P)), historical['scope']['orchestration_fingerprint'])
        self.assertEqual(digest(u.contract(self.root)), digest(u.contract(P)))
        self.assertEqual(digest(inc.orchestration_contract(P)), digest(read_json(c.LOCK)['P3']))
        self.assertEqual(digest(baseline.lifecycle_contract(P)), digest(read_json(c.LOCK)['P4_1']))


if __name__ == '__main__':
    unittest.main()
