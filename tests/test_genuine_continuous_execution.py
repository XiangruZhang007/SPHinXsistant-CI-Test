"""Genuine-format integration with mocked publication/Hosted observations only.

Local Git commits, fixture decisions and mock Releases are NOT official sources
or real Owner authorization. All artifacts live in disposable temporary trees.
"""
from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import base64
import io
import json
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import yaml
import test_continuous_execution as fixtures
from test_continuous_corpus import reference
from test_trusted_snapshot import pack
from test_upstream_provenance import git, commit, policy_for
from src import approval_evidence as ev, ci_v2_research as c, genuine_continuous_execution as run
from src import continuous_execution as v1, continuous_lifecycle as life, continuous_build_policy as scope
from src import owner_manual_baseline_approval as owner, parent_r2_anchor as anchor
from src import trusted_snapshot as trust, upstream_provenance as source
from src.corpus_snapshot import digest, file_digest, read_json
from src.research_quality import evaluate_quality
from scripts import run_continuous_ci_v2 as cli

P = Path(__file__).resolve().parents[1]


def write(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


class GenuineFormatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        factory = cls.factory = fixtures.ContinuousExecutionTests
        factory.setUpClass(); cls.addClassCleanup(factory.doClassCleanups)
        temporary = tempfile.TemporaryDirectory(prefix='genuine-format-offline-')
        cls.addClassCleanup(temporary.cleanup); cls.shared = Path(temporary.name)
        cls.project = factory.project
        for name in run.FILES:
            target = cls.project / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(P / name, target)
        ancestors = fixtures.parents.AnchorTests
        cls.fp = factory.ref['build_fingerprint']
        # Build a NEW schema-2 parent from the P2 fixture with independently
        # supplied MOCK publication responses. Never edit/relabel a sealed
        # controlled Candidate or Baseline to pass the genuine Parent gate.
        publications = {}
        for repo, url in c.SOURCES.items():
            repo_root = factory.target / 'repos' / repo; entries = {}
            old = read_json(ancestors.shared / 'p2/manifest.json')['identity']['upstreams'][repo]
            for oid in {old, ancestors.revs[repo]}:
                tree, parents = source._commit(source._git(repo_root, 'cat-file', 'commit', oid))
                full = url.removeprefix('https://github.com/').removesuffix('.git')
                body = json.dumps({'sha': oid, 'html_url': 'https://github.com/' + full + '/commit/' + oid,
                    'commit': {'tree': {'sha': tree}}, 'parents': [{'sha': x} for x in parents]}).encode()
                import hashlib
                entries[oid] = {'api_url': 'https://api.github.com/repos/' + full + '/commits/' + oid,
                    'response_base64': base64.b64encode(body).decode(), 'response_sha256': hashlib.sha256(body).hexdigest()}
            publications[repo] = entries
        policy = policy_for(ancestors.shared / 'p2', ancestors.shared / 'source0', factory.base,
                            ancestors.revs, cls.fp, genuine=True, publications=publications)
        write(cls.shared / 'mock-publication-build-policy.json', policy)
        source.build(P, ancestors.shared / 'p2', ancestors.shared / 'source0', factory.base,
            cls.shared / 'new-parent-candidate', policy_path=cls.shared / 'mock-publication-build-policy.json',
            expected_policy_sha256=file_digest(cls.shared / 'mock-publication-build-policy.json'), expected_fingerprint=cls.fp)
        quality = evaluate_quality(P, cls.shared / 'new-parent-candidate', ancestors.shared / 'full', cls.shared / 'quality',
            benchmark=P / ev.BENCHMARK, policy=read_json(c.LOCK)['quality_policy'], expected_fingerprint=cls.fp,
            historical_rows=read_json(ancestors.shared / 'p2-rows.json'), parent_rows=read_json(ancestors.shared / 'p2-rows.json'),
            parent_corpus=ancestors.shared / 'p2/corpus.jsonl', parent_sources=ancestors.shared / 'source0')
        raw = cls.shared / 'raw'; raw.mkdir()
        for name in ev.RAW_FILES[:2]: shutil.copyfile(cls.shared / 'quality' / name, raw / name)
        for name in ev.RAW_FILES[2:]: shutil.copyfile(ancestors.shared / 'p2-rows.json', raw / name)
        cls.ap = cls.shared / 'fixture-approval-policy.json'
        shutil.copyfile(ancestors.shared / 'approval-policy.json', cls.ap)
        write(raw / 'inputs.json', ev.input_manifest(cls.shared / 'new-parent-candidate', ancestors.shared / 'full',
              quality, file_digest(cls.ap), raw))
        candidate = read_json(cls.shared / 'new-parent-candidate/upstream-candidate.json')
        auth = {'schema_version': 1, 'approved': True, 'research_only': True, 'candidate_id': candidate['candidate_id'],
            'parent_baseline_id': candidate['identity']['parent']['node_id'],
            'experiment_id': read_json(cls.ap)['scope']['experiment_id'],
            'quality_status': 'QUALITY_REVIEW_REQUIRED', 'allow_quality_review': True}
        source.approve(P, cls.shared / 'new-parent-candidate', ancestors.shared / 'p2', ancestors.shared / 'full',
            cls.shared / 'mock-publication-parent', expected_fingerprint=cls.fp, quality=quality, authorization=auth,
            approval_policy=cls.ap, expected_policy_sha256=file_digest(cls.ap), evidence=raw)
        cls.archive = cls.shared / 'mock-parent.tar.gz'; pack(cls.shared / 'mock-publication-parent', cls.archive)
        cls.rows_path = raw / ev.RAW_FILES[0]
        cls.ref = reference(cls.shared / 'mock-publication-parent', cls.archive, cls.fp)
        cls.repo = 'FixtureOwner/ContinuousTest'; cls.repo_id = 10001; cls.actor_id = 101
        def storage(name, asset_id, path):
            return {'kind': trust.PRIVATE_RELEASE_KIND, 'repository': cls.repo, 'repository_id': cls.repo_id,
                'release_id': 201, 'tag': 'offline-fixture-only', 'asset_id': asset_id, 'asset_name': name,
                'asset_size': path.stat().st_size, 'immutable_required': True}
        cls.ref.update(storage=storage('parent.tar.gz', 301, cls.archive), parent_rows_sha256=file_digest(cls.rows_path),
                       parent_rows_storage=storage('rows.json', 302, cls.rows_path))
        exact = deepcopy(read_json(factory.project / 'fixture-exact-policy.json'))
        exact['scope'].update(parent={'kind': 'RESEARCH_BASELINE', 'node_id': cls.ref['node_id'],
            'package_checksum': cls.ref['package_checksum']}, base_upstreams=cls.ref['upstreams'],
            base_source_state=cls.ref['source_state'])
        write(cls.project / 'configs/mock-existing-exact-policy.json', exact)
        cls.registry = cls.project / 'configs/mock-registry.json'
        write(cls.registry, {'schema_version': 2, 'baselines': {'fixture-parent': {
            'reference': cls.ref, 'expected_reference_sha256': digest(cls.ref),
            'build_policy_path': 'configs/mock-existing-exact-policy.json',
            'build_policy_sha256': file_digest(cls.project / 'configs/mock-existing-exact-policy.json')}}})
        scope_policy = deepcopy(factory.policy)
        scope_policy['eligible_parents'] = [{'key': 'fixture-parent', 'node_id': cls.ref['node_id'],
            'package_checksum': cls.ref['package_checksum'], 'expected_reference_sha256': digest(cls.ref)}]
        cls.policy_path = cls.project / 'configs/mock-continuous-policy.json'; write(cls.policy_path, scope_policy)
        cls.owner_path = cls.project / 'configs/mock-build-authority.json'
        write(cls.owner_path, {'schema_version': 1, 'enabled': True, 'repository': cls.repo,
            'repository_id': cls.repo_id, 'default_branch': 'research', 'workflow_path': '.github/workflows/upstream_refresh.yml',
            'registry_path': 'configs/mock-registry.json', 'allow_repository_owner': True, 'authorized_approver_ids': []})
        cls.head = commit(cls.project)
        cls.config = {'schema_version': 1, 'purpose': run.PURPOSE, 'repository': cls.repo, 'repository_id': cls.repo_id,
            'default_branch': 'research', 'workflow_path': '.github/workflows/upstream_refresh.yml',
            'implementation_revision': cls.head, 'authority_policy_path': 'configs/mock-build-authority.json',
            'authority_policy_sha256': file_digest(cls.owner_path), 'continuous_policy_path': 'configs/mock-continuous-policy.json',
            'continuous_policy_sha256': file_digest(cls.policy_path), 'registry_path': 'configs/mock-registry.json',
            'registry_sha256': file_digest(cls.registry), 'execution_contract_sha256': digest(run.contract(cls.project))}
        cls.responses = deepcopy(factory.responses)
        cls.responses['repos/' + cls.repo] = {'id': cls.repo_id, 'full_name': cls.repo, 'private': True,
            'default_branch': 'research', 'owner': {'id': cls.actor_id, 'type': 'User'}}
        cls.responses['repos/' + cls.repo + '/actions/runs/401'] = {'id': 401, 'event': 'workflow_dispatch',
            'status': 'in_progress', 'run_attempt': 1, 'head_branch': 'research', 'head_sha': cls.head,
            'repository': {'id': cls.repo_id, 'full_name': cls.repo}, 'actor': {'id': cls.actor_id, 'type': 'User'},
            'triggering_actor': {'id': cls.actor_id, 'type': 'User'}, 'workflow_id': 501, 'created_at': '2026-01-01T00:00:00Z'}
        cls.responses['repos/' + cls.repo + '/actions/workflows/501'] = {'id': 501, 'path': cls.config['workflow_path']}
        cls.responses['repos/' + cls.repo + '/git/ref/heads/research'] = {'ref': 'refs/heads/research',
            'object': {'type': 'commit', 'sha': cls.head}}
        cls.responses['repos/' + cls.repo + '/contents/configs/mock-registry.json?ref=' + cls.head] = {
            'path': 'configs/mock-registry.json', 'type': 'file', 'encoding': 'base64',
            'content': base64.b64encode(cls.registry.read_bytes()).decode()}
        cls.report = {repo: {'branch': scope_policy['upstreams'][repo]['branch'],
            'baseline_commit': cls.ref['upstreams'][repo], 'latest_commit': factory.revisions[repo],
            'update_available': cls.ref['upstreams'][repo] != factory.revisions[repo]} for repo in c.SOURCES}
        cls.detection_path = cls.shared / 'detected.json'; write(cls.detection_path, cls.report)
        cls.event_path = cls.shared / 'event.json'
        write(cls.event_path, {'inputs': {'build_continuous_ci_v2': 'true', 'build_ci_v2': 'false'}})
        cls.counter = 0; cls.original = cls.shared / 'successful'
        with cls.boundaries(): cls.result = run.execute(cls.project, cls.detection_path, cls.shared / 'work-original', cls.original)
        cls.pins = read_json(cls.original / 'verification-inputs.json')

    @classmethod
    def environment(cls):
        raw = json.dumps(cls.config, sort_keys=True); import hashlib
        return {'CONTINUOUS_BUILD_DEPLOYMENT_JSON': raw,
            'CONTINUOUS_BUILD_DEPLOYMENT_SHA256': hashlib.sha256(raw.encode()).hexdigest(),
            'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_ARCH': 'ARM64',
            'GITHUB_WORKSPACE': str(cls.project.resolve()), 'GITHUB_REPOSITORY': cls.repo,
            'GITHUB_REPOSITORY_ID': str(cls.repo_id), 'GITHUB_SHA': cls.head, 'GITHUB_REF': 'refs/heads/research',
            'GITHUB_WORKFLOW_SHA': cls.head, 'GITHUB_WORKFLOW_REF': cls.repo + '/' + cls.config['workflow_path'] + '@refs/heads/research',
            'GITHUB_RUN_ID': '401', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_ACTOR_ID': str(cls.actor_id),
            'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_EVENT_PATH': str(cls.event_path),
            'TRUSTED_RELEASE_TOKEN': 'offline-test-token-not-a-secret'}

    @classmethod
    def client(cls):
        client = Mock(); client.json.side_effect = lambda endpoint: deepcopy(cls.responses[endpoint]); return client

    @classmethod
    def boundaries(cls):
        stack = ExitStack(); stack.enter_context(patch.dict(os.environ, cls.environment()))
        stack.enter_context(patch.object(owner, 'GitHubCLI', side_effect=cls.client))
        stack.enter_context(patch.object(scope, 'GitHubCLI', side_effect=cls.client))
        def request(url, *, binary=False, token=None):
            assets = [(cls.ref['storage'], cls.archive), (cls.ref['parent_rows_storage'], cls.rows_path)]
            if binary:
                path = next(path for storage, path in assets if url.endswith('/assets/' + str(storage['asset_id'])))
                return io.BytesIO(path.read_bytes())
            if '/releases/assets/' in url:
                storage, path = next((s, p) for s, p in assets if url.endswith('/assets/' + str(s['asset_id'])))
                value = {'id': storage['asset_id'], 'name': storage['asset_name'], 'size': path.stat().st_size,
                         'state': 'uploaded', 'digest': 'sha256:' + file_digest(path)}
            elif '/releases/' in url:
                value = {'id': 201, 'immutable': True, 'draft': False, 'tag_name': 'offline-fixture-only',
                    'assets': [{'id': s['asset_id'], 'name': s['asset_name'], 'size': p.stat().st_size} for s, p in assets]}
            else: value = {'id': cls.repo_id, 'full_name': cls.repo, 'private': True}
            return io.BytesIO(json.dumps(value).encode())
        stack.enter_context(patch.object(trust, '_request', side_effect=request))
        def clone(work, ref, revisions):
            # Git transport redirected to local repositories; real cloning,
            # checkout, object/source verification and ancestry are unchanged.
            for label, pair in (('base-source', ref['upstreams']), ('target-source', revisions)):
                for repo, url in c.SOURCES.items():
                    dest = work / label / 'repos' / repo; dest.parent.mkdir(parents=True, exist_ok=True)
                    subprocess.run(['git', 'clone', '--no-checkout', str(cls.factory.target / 'repos' / repo), str(dest)],
                                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    git(dest, 'remote', 'set-url', 'origin', url); git(dest, 'checkout', '--detach', pair[repo])
        stack.enter_context(patch.object(run, '_clone_sources', side_effect=clone))
        return stack

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='genuine-format-case-'); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.baseline_bytes = self.registry.read_bytes()
        self.api = deepcopy(type(self).responses); type(self).responses = self.api
        self.addCleanup(setattr, type(self), 'responses', deepcopy(self.api))

    def verify(self, **overrides):
        return run.verify_package(self.project, self.original / 'run', **{**self.pins, **overrides})

    def test_real_format_pipeline_and_fresh_replays_with_explicit_mock_limits(self):
        result = self.verify(fresh_replay=True)
        self.assertEqual(result['verification'], 'PACKAGE_INTEGRITY_VERIFIED')
        self.assertEqual(result['replay'], 'FRESH_R2_REPLAY')
        self.assertEqual(result['live_authorization'], 'NOT_ESTABLISHED_BY_OFFLINE_VERIFIER')
        self.assertEqual(result['official_source_authenticity'], 'ARCHIVED_OBSERVATIONS_NOT_FRESH_AUTHORITY')
        self.assertEqual(result['upstreams'], self.factory.revisions)
        self.assertEqual(result['generation'], 2); self.assertEqual(result['parity'], 'PARITY_PASS')
        reuse = read_json(self.original / 'run/candidate/reuse-summary.json')
        self.assertGreater(reuse['reused_files'], 0); self.assertEqual(reuse['re_extracted_files'], 2)
        self.assertEqual(len(read_json(self.original / 'run/incremental-replay.json')), 128)
        self.assertEqual(len(read_json(self.original / 'run/full-replay.json')), 128)
        self.assertEqual(self.registry.read_bytes(), self.baseline_bytes)
        c.check_archive(self.original / 'candidate.tar.gz', read_json(self.original / 'transport.json')['transport_sha256'])
        print('OFFLINE_GENUINE_FORMAT_ONLY_NOT_HOSTED_AUTHORIZATION', {
            'candidate_id': result['candidate_id'], 'reuse': reuse, 'parity': result['parity'], 'R2_rows_each': 128})

    def test_offline_inspection_never_queries_api_or_replays(self):
        with (patch.object(owner, 'GitHubCLI', side_effect=AssertionError('Unexpected API')),
              patch.object(ev, 'replay', side_effect=AssertionError('Unexpected replay'))):
            self.assertEqual(self.verify()['replay'], 'SEALED_REPLAY_INSPECTED')

    def test_missing_real_deployment_blocks_before_transport(self):
        with (patch.dict(os.environ, {'CONTINUOUS_BUILD_DEPLOYMENT_JSON': '', 'CONTINUOUS_BUILD_DEPLOYMENT_SHA256': ''}),
              patch.object(trust, 'download', side_effect=AssertionError('Unexpected transport'))):
            with self.assertRaisesRegex(ValueError, 'CONTINUOUS_DEPLOYMENT_NOT_CONFIGURED'):
                run.execute(P, self.detection_path, self.root / 'work', self.root / 'out')
        self.assertFalse((self.root / 'work').exists())

    def test_genuine_context_rejects_wrong_actor_repository_commit_and_rerun(self):
        for key, value in (('GITHUB_ACTOR_ID', '999'), ('GITHUB_REPOSITORY_ID', '999'),
                           ('GITHUB_SHA', '0' * 40), ('GITHUB_RUN_ATTEMPT', '2'), ('GITHUB_EVENT_NAME', 'schedule')):
            with (self.subTest(key=key), self.boundaries(), patch.dict(os.environ, {key: value}),
                  patch.object(trust, 'download', side_effect=AssertionError('Unexpected download'))):
                with self.assertRaises(ValueError): run.execute(self.project, self.detection_path, self.root / 'work', self.root / 'out')

    def test_real_api_actor_authorization_is_not_inferred_from_environment(self):
        original = self.api['repos/' + self.repo]['owner']['id']; self.api['repos/' + self.repo]['owner']['id'] = 999
        try:
            with self.boundaries(), self.assertRaisesRegex(ValueError, 'UNAUTHORIZED_WORKFLOW_ACTOR'):
                run.execute(self.project, self.detection_path, self.root / 'work', self.root / 'out')
        finally: self.api['repos/' + self.repo]['owner']['id'] = original

    def test_changed_default_branch_head_rejects_stale_deployment(self):
        self.api['repos/' + self.repo + '/git/ref/heads/research']['object']['sha'] = '0' * 40
        with self.boundaries(), self.assertRaisesRegex(ValueError, 'STALE_WORKFLOW_COMMIT'):
            run.execute(self.project, self.detection_path, self.root / 'work', self.root / 'out')

    def test_changed_registry_bytes_rejects_before_download(self):
        endpoint = 'repos/' + self.repo + '/contents/configs/mock-registry.json?ref=' + self.head
        self.api[endpoint]['content'] = base64.b64encode(b'{}').decode()
        with self.boundaries(), self.assertRaisesRegex(ValueError, 'REMOTE_REGISTRY_MISMATCH'):
            run.execute(self.project, self.detection_path, self.root / 'work', self.root / 'out')

    def test_missing_independent_package_pins(self):
        for name in ('expected_execution_contract_sha256', 'expected_policy_sha256', 'expected_registry_sha256',
                     'expected_reference_sha256', 'expected_deployment_sha256', 'expected_manifest_sha256'):
            with self.subTest(name=name), self.assertRaises(ValueError): self.verify(**{name: '0' * 64})

    def test_advanced_branch_cannot_retarget_detection(self):
        endpoint = next(key for key in self.api if '/git/ref/heads/fixture-branch' in key)
        self.api[endpoint]['object']['sha'] = '0' * 40
        with self.boundaries(), self.assertRaisesRegex(ValueError, 'SOURCE_BRANCH_MISMATCH'):
            run.execute(self.project, self.detection_path, self.root / 'work', self.root / 'out')
        self.assertFalse((self.root / 'out').exists())
        self.assertEqual(read_json(self.detection_path), self.report)

    def test_future_branch_commit_needs_no_exact_target_or_policy_edit(self):
        root = self.factory.target / 'repos/SPHinXsys'; previous = self.factory.revisions['SPHinXsys']
        policy_before = self.policy_path.read_bytes(); exact_before = (self.project / 'configs/mock-existing-exact-policy.json').read_bytes()
        try:
            (root / 'src/a.cpp').write_text('int a() { return 901; }\n')
            oid = commit(root); tree, parents = source._commit(source._git(root, 'cat-file', 'commit', oid))
            full = c.SOURCES['SPHinXsys'].removeprefix('https://github.com/').removesuffix('.git')
            self.api['repos/' + full + '/commits/' + oid] = {'sha': oid,
                'html_url': 'https://github.com/' + full + '/commit/' + oid,
                'commit': {'tree': {'sha': tree}}, 'parents': [{'sha': p} for p in parents]}
            self.api['repos/' + full + '/git/ref/heads/fixture-branch']['object']['sha'] = oid
            report = deepcopy(self.report); report['SPHinXsys']['latest_commit'] = oid
            detected = self.root / 'new-detection.json'; write(detected, report)
            with self.boundaries(): result = run.execute(self.project, detected, self.root / 'work', self.root / 'out')
            self.assertEqual(result['upstreams']['SPHinXsys'], oid)
            self.assertNotEqual(oid, previous); self.assertEqual(result['parity'], 'PARITY_PASS')
            self.assertEqual(self.policy_path.read_bytes(), policy_before)
            self.assertEqual((self.project / 'configs/mock-existing-exact-policy.json').read_bytes(), exact_before)
        finally: git(root, 'checkout', '--detach', previous)

    def test_rollback_and_divergent_history_cannot_construct(self):
        repo = 'SPHinXsim'; root = self.factory.target / 'repos' / repo
        previous = self.factory.revisions[repo]; old = fixtures.parents.AnchorTests.p2ref['upstreams'][repo]
        try:
            report = deepcopy(self.report); report[repo]['latest_commit'] = old
            detected = self.root / 'rollback.json'; write(detected, report)
            with self.boundaries(), self.assertRaisesRegex(ValueError, 'OLDER_HISTORICAL_COMMIT'):
                run.execute(self.project, detected, self.root / 'work-rollback', self.root / 'out-rollback')
            git(root, 'checkout', '--detach', old)
            (root / 'docs/cli-usage.md').write_text('# Divergent miniature documentation\n')
            sibling = commit(root); report[repo]['latest_commit'] = sibling
            detected = self.root / 'divergent.json'; write(detected, report)
            with self.boundaries(), self.assertRaisesRegex(ValueError, 'DIVERGENT_HISTORY'):
                run.execute(self.project, detected, self.root / 'work-divergent', self.root / 'out-divergent')
            self.assertFalse((self.root / 'out-rollback').exists()); self.assertFalse((self.root / 'out-divergent').exists())
        finally: git(root, 'checkout', '--detach', previous)

    def test_original_detection_branches_are_required(self):
        report = deepcopy(self.report); report['SPHinXsys']['branch'] = 'other'
        path = self.root / 'detector.json'; write(path, report)
        with self.boundaries(), self.assertRaisesRegex(ValueError, 'DETECTOR_BRANCH_OUTSIDE_POLICY'):
            run.execute(self.project, path, self.root / 'work', self.root / 'out')

    def test_no_update_never_constructs(self):
        report = deepcopy(self.report)
        for repo, row in report.items():
            row.update(latest_commit=self.ref['upstreams'][repo], update_available=False)
        path = self.root / 'no-update.json'; write(path, report)
        with self.boundaries(), patch.object(trust, 'download', side_effect=AssertionError('Unexpected transport')):
            self.assertEqual(run.execute(self.project, path, self.root / 'work', self.root / 'out')['status'], 'NO_UPDATE')
        self.assertFalse((self.root / 'work').exists())
        self.assertEqual(read_json(self.root / 'out/no-update.json')['status'], 'NO_UPDATE')
        self.assertEqual({p.name for p in (self.root / 'out').iterdir()}, {'no-update.json'})

    def test_static_detector_no_update_does_not_hide_real_parent_update(self):
        report = deepcopy(self.report)
        for row in report.values(): row.update(baseline_commit=row['latest_commit'], update_available=False)
        path = self.root / 'static-no-update.json'; write(path, report)
        original_bytes = path.read_bytes()
        with self.boundaries():
            result = run.execute(self.project, path, self.root / 'work', self.root / 'out')
        self.assertEqual(result['status'], 'GENUINE_CONTINUOUS_CANDIDATE_BUILT')
        self.assertEqual(result['upstreams'], self.factory.revisions)
        observation = read_json(self.root / 'out/run/evidence/authorization-context.json')['parent_comparison']
        self.assertFalse(observation['detector_update_reported']); self.assertTrue(observation['update_available'])
        self.assertEqual(path.read_bytes(), original_bytes)

    def test_static_detector_update_does_not_rebuild_identical_parent(self):
        report = deepcopy(self.report)
        for repo, row in report.items():
            row.update(baseline_commit='0' * 40, latest_commit=self.ref['upstreams'][repo], update_available=True)
        path = self.root / 'static-update.json'; write(path, report)
        with self.boundaries(), patch.object(trust, 'download', side_effect=AssertionError('Unexpected download')):
            result = run.execute(self.project, path, self.root / 'work', self.root / 'out')
        self.assertEqual(result['status'], 'NO_UPDATE')
        self.assertTrue(result['authority_observation']['parent_comparison']['detector_update_reported'])
        self.assertFalse(result['authority_observation']['parent_comparison']['update_available'])

    def test_execution_key_is_stable_across_runs_and_detector_baseline_changes(self):
        altered = deepcopy(self.report)
        for row in altered.values(): row.update(baseline_commit='0' * 40, update_available=True)
        path = self.root / 'baseline-changed.json'; write(path, altered)
        with self.boundaries():
            config, _, pin = run.deployment()
            first = run._authority(self.project, self.detection_path, config, pin)
            other = run._authority(self.project, path, config, pin)
        self.assertNotEqual(first['detection_sha256'], other['detection_sha256'])
        self.assertEqual(first['parent_comparison']['execution_key'], other['parent_comparison']['execution_key'])
        later = deepcopy(self.api['repos/' + self.repo + '/actions/runs/401']); later['id'] = 402
        self.api['repos/' + self.repo + '/actions/runs/402'] = later
        with self.boundaries(), patch.dict(os.environ, {'GITHUB_RUN_ID': '402'}):
            again = run._authority(self.project, self.detection_path, config, pin)
        self.assertNotEqual(digest(first), digest(again))
        self.assertEqual(first['parent_comparison']['execution_key'], again['parent_comparison']['execution_key'])
        observed = run.detection(self.detection_path)
        entry = read_json(self.registry)['baselines']['fixture-parent']
        for field in ('continuous_policy_sha256', 'registry_sha256', 'execution_contract_sha256'):
            different = run._comparison(observed, 'fixture-parent', entry, {**config, field: '0' * 64})
            self.assertNotEqual(first['parent_comparison']['execution_key'], different['execution_key'])

    def schedule_boundaries(self):
        stack = ExitStack()
        config = {**self.config, 'schema_version': 2, 'build_events': ['workflow_dispatch', 'schedule']}
        stack.enter_context(patch.object(type(self), 'config', config))
        stack.enter_context(patch.dict(self.api['repos/' + self.repo + '/actions/runs/401'], {'event': 'schedule'}))
        stack.enter_context(self.boundaries())
        stack.enter_context(patch.dict(os.environ, {'GITHUB_EVENT_NAME': 'schedule'}))
        return stack

    def test_scheduled_preflight_verifies_actual_identity_but_cannot_build(self):
        with (self.schedule_boundaries(),
              patch.object(owner, '_github_identity', side_effect=AssertionError('Registration verifier reused')),
              patch.object(trust, 'download', side_effect=AssertionError('Unexpected transport')),
              patch.object(v1, '_assemble', side_effect=AssertionError('Unexpected build'))):
            result = run.preflight(self.project, self.detection_path)
            self.assertEqual(result['status'], 'BLOCKED'); self.assertFalse(result['execute_candidate'])
            self.assertEqual(result['blockers'], ['SCHEDULED_SCOPE_AUTHORIZATION_NOT_IMPLEMENTED',
                                                 'DURABLE_REPEAT_EXECUTION_PROTECTION_NOT_ESTABLISHED'])
            self.assertEqual(result['authority_observation']['workflow_run']['event'], 'schedule')
            self.assertEqual(result['authority_observation']['authority'], 'PREAUTHORIZED_SCHEDULE_CONTEXT_ONLY')
            self.assertEqual(result['authority_observation']['research_approval'], 'NOT_GRANTED')
            self.assertFalse(result['scheduled_execution'])
            with self.assertRaisesRegex(ValueError, 'SCHEDULED_CONSTRUCTION_NOT_AUTHORIZED'):
                run.execute(self.project, self.detection_path, self.root / 'work', self.root / 'out')
        self.assertFalse((self.root / 'work').exists()); self.assertFalse((self.root / 'out').exists())

    def test_schedule_is_not_inferred_from_owner_policy_or_environment(self):
        with self.boundaries(), patch.dict(os.environ, {'GITHUB_EVENT_NAME': 'schedule'}):
            with self.assertRaisesRegex(ValueError, 'BUILD_EVENT_NOT_PREAUTHORIZED'):
                run.preflight(self.project, self.detection_path)
        with self.schedule_boundaries():
            self.api['repos/' + self.repo + '/actions/runs/401']['event'] = 'workflow_dispatch'
            with self.assertRaisesRegex(ValueError, 'GITHUB_WORKFLOW_RUN_BINDING_MISMATCH'):
                run.preflight(self.project, self.detection_path)

    def test_schedule_rejects_wrong_run_actor_repository_workflow_commit_and_attempt(self):
        endpoint = 'repos/' + self.repo + '/actions/runs/401'
        cases = [('run_attempt', 2), ('status', 'completed'), ('head_sha', '0' * 40), ('head_branch', 'other'),
                 ('repository', {'id': 999, 'full_name': self.repo}),
                 ('actor', {'id': 999, 'type': 'User'}), ('triggering_actor', {'id': 999, 'type': 'User'})]
        for field, value in cases:
            with self.subTest(field=field), self.schedule_boundaries(), patch.dict(self.api[endpoint], {field: value}):
                with self.assertRaises(ValueError): run.preflight(self.project, self.detection_path)
        with self.schedule_boundaries(), patch.dict(self.api['repos/' + self.repo + '/actions/workflows/501'], {'path': 'other.yml'}):
            with self.assertRaisesRegex(ValueError, 'GITHUB_WORKFLOW_PATH_MISMATCH'):
                run.preflight(self.project, self.detection_path)

    def test_scheduler_actor_is_observation_not_human_reviewer(self):
        endpoint = 'repos/' + self.repo + '/actions/runs/401'
        with (self.schedule_boundaries(), patch.dict(os.environ, {'GITHUB_ACTOR_ID': '999'}),
              patch.dict(self.api[endpoint], {'actor': {'id': 999, 'type': 'User'},
                                            'triggering_actor': {'id': 999, 'type': 'User'}})):
            result = run.preflight(self.project, self.detection_path)
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(result['authority_observation']['workflow_run']['actor_id'], 999)
        self.assertEqual(result['authority_observation']['research_approval'], 'NOT_GRANTED')

    def test_schedule_no_update_receipt_and_cli_cannot_construct_or_replay(self):
        report = deepcopy(self.report)
        for repo, row in report.items(): row.update(latest_commit=self.ref['upstreams'][repo], update_available=False)
        path = self.root / 'detected.json'; write(path, report)
        for label, detected, expected in [('no-update', path, 0), ('update', self.detection_path, 1)]:
            stdout = io.StringIO(); output = self.root / label
            with (self.schedule_boundaries(), patch.object(cli, 'P', self.project), redirect_stdout(stdout),
                  patch.object(run, 'execute', side_effect=AssertionError('Unexpected execution')),
                  patch.object(ev, 'replay', side_effect=AssertionError('Unexpected replay')),
                  patch.object(trust, 'download', side_effect=AssertionError('Unexpected download'))):
                code = cli.main(['--preflight-only', '--detection', str(detected), '--work', str(self.root / 'work'),
                                 '--output', str(output)])
            self.assertEqual(code, expected)
            result = json.loads(stdout.getvalue()); self.assertFalse(result['execute_candidate'])
            self.assertEqual(read_json(output / 'preflight.json'), result)
        self.assertFalse((self.root / 'work').exists())

    def test_deployment_events_are_versioned_and_strict(self):
        self.assertEqual(run._shape(self.config), self.config)
        for value in ([], ['schedule'], ['push'], ['workflow_dispatch', 'schedule', 'schedule'], 'schedule'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'INVALID_BUILD_EVENTS'):
                run._shape({**self.config, 'schema_version': 2, 'build_events': value})
        with self.assertRaisesRegex(ValueError, 'INVALID_CONTINUOUS_DEPLOYMENT'):
            run._shape({**self.config, 'build_events': ['schedule']})

    def test_changed_source_during_construction_cannot_emit_candidate(self):
        actual = v1._assemble
        def mutate(project, stage, parent, target, selection):
            result = actual(project, stage, parent, target, selection)
            (target / 'repos/SPHinXsys/src/a.cpp').write_text('uncommitted alteration\n'); return result
        with self.boundaries(), patch.object(v1, '_assemble', side_effect=mutate), self.assertRaises(ValueError):
            run.execute(self.project, self.detection_path, self.root / 'work', self.root / 'out')
        self.assertFalse((self.root / 'out').exists())

    def test_actual_parent_replay_failure_blocks_construction(self):
        replay = ev.replay
        def wrong(*args):
            rows = replay(*args); rows.pop(); return rows
        with (self.boundaries(), patch.object(ev, 'replay', side_effect=wrong),
              patch.object(v1, '_assemble', side_effect=AssertionError('Unexpected construction')),
              self.assertRaisesRegex(ValueError, 'Pinned parent R2 anchor replay differs')):
            run.execute(self.project, self.detection_path, self.root / 'work', self.root / 'out')
        self.assertFalse((self.root / 'out').exists())

    def test_independent_full_corruption_stops_before_packaging(self):
        actual = source.full_reference
        def corrupt(project, target, destination, revisions, fingerprint):
            result = actual(project, target, destination, revisions, fingerprint)
            with (destination / 'corpus.jsonl').open('ab') as stream: stream.write(b'corrupted\n')
            return result
        with (self.boundaries(), patch.object(source, 'full_reference', side_effect=corrupt),
              patch.object(c, 'package_candidate', side_effect=AssertionError('Unexpected packaging')),
              self.assertRaises(ValueError)):
            run.execute(self.project, self.detection_path, self.root / 'work', self.root / 'out')
        self.assertFalse((self.root / 'out').exists())

    def test_provenance_and_projection_tampering_rejected(self):
        root = self.root / 'package'; shutil.copytree(self.original / 'run', root)
        path = root / 'candidate/genuine-candidate.json'; metadata = read_json(path)
        metadata['identity']['provenance_type'] = 'CONTROLLED_GIT_FIXTURE'; write(path, metadata)
        (root / 'checksums.json').unlink(); v1._seal(root)
        with self.assertRaises(ValueError):
            run.verify_package(self.project, root, **{**self.pins, 'expected_manifest_sha256': file_digest(root / 'checksums.json')})
        with self.assertRaises(ValueError):
            run.verify_package(self.project, self.factory.original, **self.pins)

    def test_failed_fresh_candidate_replay_rejected(self):
        actual = ev.replay
        def wrong(*args):
            rows = actual(*args); rows.pop(); return rows
        with patch.object(ev, 'replay', side_effect=wrong), self.assertRaises(ValueError): self.verify(fresh_replay=True)

    def test_quality_and_old_contracts_preserved(self):
        for key, value in run.LIMITS.items(): self.assertEqual(self.result[key], value)
        self.assertEqual(digest(source.contract(P)), 'b0b43411aef4d716a15a2f0a794071523fbb3c260dc4cb3fc9b2736eed9e1ac1')
        self.assertEqual(digest(v1.contract(P)), '2d9c41cc55d5f6c7dd8022280e38b7d1ec8ad5d991d7e452396dfa02e19220e3')
        self.assertEqual(digest(life.contract(P)), 'cf1e270eb655805934dace62e3934041db57202bdfb05d6d5d5a2dd2574ec7a3')

    def test_cli_missing_authority_has_sanitized_blocked_receipt(self):
        with patch.dict(os.environ, {'CONTINUOUS_BUILD_DEPLOYMENT_JSON': '', 'CONTINUOUS_BUILD_DEPLOYMENT_SHA256': ''}):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = cli.main(['--detection', str(self.detection_path), '--work', str(self.root / 'work'), '--output', str(self.root / 'out')])
        self.assertEqual(code, 1)
        result = json.loads(stdout.getvalue()); self.assertEqual(result['reason'], 'CONTINUOUS_DEPLOYMENT_NOT_CONFIGURED')
        self.assertFalse(result['execute_candidate']); self.assertNotIn('token', stdout.getvalue())
        self.assertEqual(read_json(self.root / 'out/failure.json'), result)

    def test_delivery_failure_preserves_only_blocked_receipt_in_upload_directory(self):
        stdout = io.StringIO()
        with (self.boundaries(), patch.object(cli, 'P', self.project),
              patch.object(c, 'package_candidate', side_effect=OSError('sensitive-token-example')),
              redirect_stdout(stdout)):
            code = cli.main(['--detection', str(self.detection_path), '--work', str(self.root / 'work'),
                             '--output', str(self.root / 'out')])
        self.assertEqual(code, 1); self.assertNotIn('sensitive-token-example', stdout.getvalue())
        self.assertEqual(read_json(self.root / 'out/failure.json')['status'], 'BLOCKED')
        self.assertEqual({p.name for p in (self.root / 'out').iterdir()}, {'failure.json'})
        self.assertTrue((self.root / 'work/delivery/run/checksums.json').is_file())

    def test_workflow_entry_routing_shell_and_minimal_permissions(self):
        workflow = yaml.safe_load((P / '.github/workflows/upstream_refresh.yml').read_text())
        events = workflow.get('on', workflow.get(True)); opt_in = events['workflow_dispatch']['inputs']['build_continuous_ci_v2']
        self.assertIs(opt_in['default'], False)
        job = workflow['jobs']['continuous-candidate']
        self.assertIn("github.event_name == 'workflow_dispatch'", job['if'])
        self.assertIn('inputs.build_continuous_ci_v2', job['if']); self.assertIn('!inputs.build_ci_v2', job['if'])
        self.assertEqual(job['permissions'], {'contents': 'read', 'actions': 'read'})
        self.assertEqual(job['runs-on'], 'ubuntu-24.04-arm')
        shell = next(step['run'] for step in job['steps'] if 'scripts/run_continuous_ci_v2.py' in step.get('run', ''))
        self.assertNotIn('${{', shell); self.assertIn('upstream_status.json', shell)
        marker = self.root / 'injected'
        temp = self.root / 'runner space'; temp.mkdir()
        env = {**os.environ, 'RUNNER_TEMP': str(temp), 'CONTINUOUS_BUILD_DEPLOYMENT_JSON': '',
               'CONTINUOUS_BUILD_DEPLOYMENT_SHA256': '', 'CI_V2_UNUSED': '$(touch ' + str(marker) + ')'}
        result = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', shell],
                                 cwd=P, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1); self.assertFalse(marker.exists())
        self.assertEqual(read_json(temp / 'continuous-result/failure.json')['status'], 'BLOCKED')
        for step in job['steps']:
            self.assertNotIn('continue-on-error', step)
            if 'uses' in step: self.assertRegex(step['uses'], '@[0-9a-f]{40}$')
            if 'run' in step:
                self.assertEqual(subprocess.run(['bash', '-n'], input=step['run'], text=True, capture_output=True).returncode, 0)

    def test_scheduled_workflow_only_executes_read_only_preflight_shell(self):
        workflow = yaml.safe_load((P / '.github/workflows/upstream_refresh.yml').read_text())
        job = workflow['jobs']['continuous-schedule-preflight']
        self.assertIn("github.event_name == 'schedule'", job['if'])
        self.assertIn("github.event_name == 'workflow_dispatch'", workflow['jobs']['continuous-candidate']['if'])
        self.assertEqual(job['permissions'], {'contents': 'read', 'actions': 'read'})
        self.assertEqual(job['runs-on'], 'ubuntu-24.04-arm')
        steps = [step for step in job['steps'] if 'run' in step]
        self.assertEqual(len(steps), 2)
        runtime, preflight = steps
        build_runtime = next(step['run'] for step in workflow['jobs']['continuous-candidate']['steps']
                             if step.get('name') == 'Prepare pinned extraction runtime')
        self.assertEqual(runtime['run'], build_runtime)
        shell = preflight['run']; self.assertIn('--preflight-only', shell); self.assertNotIn('${{', shell)
        self.assertTrue(shell.startswith('tools/treesitter-chunker/.venv/bin/python -B '))
        self.assertNotIn('TRUSTED_RELEASE_TOKEN', preflight['env'])
        self.assertNotIn('continue-on-error', preflight)
        for step in job['steps']:
            if 'uses' in step: self.assertRegex(step['uses'], '@[0-9a-f]{40}$')
        bin_dir = self.root / 'bin'; bin_dir.mkdir()
        shim = bin_dir / 'python'; shim.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' "$@"\n'); shim.chmod(0o755)
        runner = self.root / 'runner with spaces'; runner.mkdir()
        marker = self.root / 'unexpected-execution'
        env = {**os.environ, 'PATH': str(bin_dir) + os.pathsep + os.defpath, 'RUNNER_TEMP': str(runner),
               'CONTINUOUS_BUILD_DEPLOYMENT_JSON': '', 'CONTINUOUS_BUILD_DEPLOYMENT_SHA256': '',
               'GITHUB_EVENT_NAME': 'schedule', 'UNUSED': '$(touch ' + str(marker) + ')'}
        completed = subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', '-c', shell],
                                   cwd=P, env=env, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 1); self.assertFalse(marker.exists())
        receipt = read_json(runner / 'continuous-result/failure.json')
        self.assertEqual(receipt['reason'], 'CONTINUOUS_DEPLOYMENT_NOT_CONFIGURED')
        self.assertFalse(receipt['execute_candidate']); self.assertFalse((runner / 'continuous-work').exists())


if __name__ == '__main__': unittest.main()
