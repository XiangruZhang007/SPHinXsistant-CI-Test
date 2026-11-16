from __future__ import annotations

from copy import deepcopy
import gzip
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from src import candidate_release_archive as archive
from src.corpus_snapshot import file_digest
from src.ci_v2_research import REGISTRY as BASELINE_REGISTRY


def put(root, rel, value):
    path = Path(root) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + '\n', encoding='utf-8')
    return path


def seal(root):
    root = Path(root)
    values = {p.relative_to(root).as_posix(): file_digest(p)
              for p in sorted(root.rglob('*')) if p.is_file() and p != root / 'checksums.json'}
    put(root, 'checksums.json', values)


class CandidateArchiveTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        self.artifact = self.root / 'artifact'
        self.artifact.mkdir()
        run = self.artifact / 'run'
        candidate = run / 'candidate'
        candidate.mkdir(parents=True)
        self.cid = 'sha256-' + 'a' * 64
        self.corpus = b'{"chunk_id":"synthetic-candidate"}\n'
        (candidate / 'corpus.jsonl').write_bytes(self.corpus)
        self.upstreams = {'SPHinXsys': '1' * 40, 'SPHinXsim': '2' * 40}
        self.base_upstreams = {'SPHinXsys': '1' * 40, 'SPHinXsim': '3' * 40}
        self.parent_id = 'sha256-' + 'b' * 64
        self.corpus_sha = hashlib.sha256(self.corpus).hexdigest()
        fp = 'c' * 64
        source_state = 'sha256-' + 'd' * 64
        base_source_state = 'sha256-' + '9' * 64
        identity = {'candidate_id': self.cid, 'generation': 2,
            'build_fingerprint': fp,
            'base_source_state': base_source_state, 'base_upstreams': self.base_upstreams,
            'parent': {'kind': 'RESEARCH_BASELINE', 'node_id': self.parent_id,
                       'package_checksum': 'e' * 64},
            'upstreams': self.upstreams, 'target_source_state': source_state}
        put(candidate, 'candidate.json', {'schema_version': 2, 'kind': 'upstream-research-candidate',
             'candidate_id': self.cid, 'identity': identity})
        put(run, 'candidate/upstream-candidate.json', {'candidate_id': self.cid, 'identity': identity})
        seal(candidate)
        self.plan = {'upstreams': self.upstreams}
        put(self.artifact, 'plan.json', self.plan)
        benchmark = b'{"synthetic":"frozen-benchmark"}\n'
        parent_rows = b'{"synthetic":"parent-r2"}\n'
        target_rows = b'{"synthetic":"candidate-r2"}\n'
        put(run, 'benchmark.json', json.loads(benchmark))
        benchmark_sha = file_digest(run / 'benchmark.json')
        (run / 'parent-raw-results.json').write_bytes(parent_rows)
        put(run, 'quality/incremental-raw-results.json', json.loads(target_rows))
        target_rows = (run / 'quality/incremental-raw-results.json').read_bytes()
        put(run, 'parity.json', {'candidate_id': self.cid, 'status': 'PARITY_PASS',
                                 'full_reference_independently_built': True})
        put(run, 'execution-verification/verification.json', {
            'status': 'VERIFIED', 'candidate_corpus_sha256': self.corpus_sha,
            'full_corpus_sha256': self.corpus_sha, 'original_combinations': 4,
            'independent_replay_combinations': 4, 'production_promotion': 'NOT_AUTHORIZED'})
        put(run, 'quality/quality-report.json', {'status': 'QUALITY_REVIEW_REQUIRED',
             'assessment': 'FROZEN_128_EVALUATED', 'candidate_id': self.cid,
             'corpus_sha256': self.corpus_sha, 'build_fingerprint': fp,
             'raw_results_sha256': hashlib.sha256(target_rows).hexdigest(),
             'independent_candidate_full_rows_equal': True})
        put(run, 'q1-status.json', {'status': 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR'})
        self.result = {'candidate_id': self.cid, 'baseline_id': self.parent_id,
            'target_source_state': source_state, 'STRUCTURAL_PARITY': 'PASS',
            'RESEARCH_BASELINE_APPROVED': False, 'RETRIEVAL_QUALITY_ACCEPTED': False,
            'retrieval_quality': 'QUALITY_REVIEW_REQUIRED',
            'Q1': {'status': 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR'},
            'hosted_validation': 'PENDING_HOSTED_REVIEW',
            'research_baseline_created': False, 'automatic_research_approval': False,
            'automatic_reuse': False, 'production_promotion': 'NOT_AUTHORIZED',
            'bindings': {'candidate_id': self.cid, 'target_corpus_sha256': self.corpus_sha,
                         'target_source_state': source_state, 'build_fingerprint': fp,
                         'target_upstreams': self.upstreams, 'base_upstreams': self.base_upstreams,
                         'base_source_state': base_source_state,
                         'benchmark_sha256': benchmark_sha,
                         'target_rows_sha256': hashlib.sha256(target_rows).hexdigest(),
                         'base_rows_sha256': hashlib.sha256(parent_rows).hexdigest()}}
        put(run, 'result.json', self.result)
        seal(run)
        with tarfile.open(self.artifact / 'candidate.tar.gz', 'w:gz') as tar:
            for path in sorted(run.rglob('*')):
                if path.is_file():
                    tar.add(path, arcname=path.relative_to(run).as_posix(), recursive=False)
        self.run_id, self.attempt, self.repo_id, self.artifact_id = 41, 2, 55, 77
        self.head = '9' * 40
        self.artifact_digest = 'sha256:' + '8' * 64
        self.output = self.root / 'assets'
        self.registry_before = file_digest(BASELINE_REGISTRY)

    def metadata(self):
        return dict(run_id=self.run_id, attempt=self.attempt, repository_id=self.repo_id,
                    head_sha=self.head, artifact_id=self.artifact_id,
                    artifact_digest=self.artifact_digest)

    def repack_run(self):
        with tarfile.open(self.artifact / 'candidate.tar.gz', 'w:gz') as tar:
            for path in sorted((self.artifact / 'run').rglob('*')):
                if path.is_file():
                    tar.add(path, arcname=path.relative_to(self.artifact / 'run').as_posix(), recursive=False)

    def prepare(self, output=None):
        output = output or self.output
        output.parent.mkdir(parents=True, exist_ok=True)
        return archive.prepare(self.artifact, output, **self.metadata())

    def test_successful_prepare_is_deterministic_and_candidate_bound(self):
        one = self.prepare()
        self.assertEqual(one['manifest']['technical_verification'], 'PASS')
        self.assertEqual(one['manifest']['candidate_id'], self.cid)
        self.assertEqual(one['manifest']['corpus_sha256'], self.corpus_sha)
        self.assertEqual(one['manifest']['parent_id'], self.parent_id)
        self.assertEqual(one['manifest']['quality_status'], 'QUALITY_REVIEW_REQUIRED')
        self.assertEqual(one['manifest']['q1_status'], 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
        self.assertFalse(one['manifest']['approval']['trusted_parent_registered'])
        self.assertEqual(one['manifest']['approval']['production_promotion'], 'NOT_AUTHORIZED')
        first_tar = (self.output / 'research-evidence.tar.gz').read_bytes()
        second = self.prepare(self.root / 'second' / 'assets')
        self.assertEqual(first_tar, (self.root / 'second/assets/research-evidence.tar.gz').read_bytes())
        self.assertEqual(one['manifest_sha256'], second['manifest_sha256'])
        with tarfile.open(self.output / 'research-evidence.tar.gz', 'r:gz') as tar:
            self.assertTrue({'plan.json', 'run/result.json', 'run/quality/quality-report.json'}
                            <= set(tar.getnames()))
        self.assertEqual(file_digest(BASELINE_REGISTRY), self.registry_before)

    def test_prepare_accepts_upload_action_raw_digest_and_pins_canonical_form(self):
        raw = '8' * 64
        result = archive.prepare(self.artifact, self.root / 'raw-digest-assets',
            run_id=self.run_id, attempt=self.attempt, repository_id=self.repo_id,
            head_sha=self.head, artifact_id=self.artifact_id, artifact_digest=raw)
        self.assertEqual(result['manifest']['actions_artifact_digest'], 'sha256:' + raw)

    def test_missing_corrupted_or_unverified_inputs_fail_closed(self):
        (self.artifact / 'candidate.tar.gz').unlink()
        with self.assertRaises(archive.ArchiveError):
            self.prepare()
        (self.artifact / 'candidate.tar.gz').write_bytes(b'bad')
        with self.assertRaises(archive.ArchiveError):
            self.prepare(self.root / 'other' / 'assets')
        (self.artifact / 'candidate.tar.gz').unlink()
        # A validly readable archive with one altered member must still fail
        # comparison against the independently sealed run tree.
        with tarfile.open(self.artifact / 'candidate.tar.gz', 'w:gz') as tar:
            for path in sorted((self.artifact / 'run').rglob('*')):
                if path.is_file():
                    tar.add(path, arcname=path.relative_to(self.artifact / 'run').as_posix(), recursive=False)
        (self.artifact / 'run/candidate/corpus.jsonl').write_bytes(b'{"chunk_id":"changed"}\n')
        with self.assertRaises(archive.ArchiveError):
            self.prepare(self.root / 'third' / 'assets')

    def test_checksum_and_verification_failure_prevent_archiving(self):
        result = self.artifact / 'run/result.json'
        result.write_text(result.read_text() + ' ', encoding='utf-8')
        with self.assertRaisesRegex(archive.ArchiveError, 'checksum'):
            self.prepare()
        # Re-seal a changed but structurally failing record: checksum validity
        # must not substitute for mandatory technical verification.
        seal(self.artifact / 'run')
        parity = self.artifact / 'run/execution-verification/verification.json'
        data = json.loads(parity.read_text()); data['status'] = 'FAILED'
        put(self.artifact / 'run', 'execution-verification/verification.json', data)
        seal(self.artifact / 'run')
        self.repack_run()
        with self.assertRaisesRegex(archive.ArchiveError, 'technical verification'):
            self.prepare(self.root / 'failed' / 'assets')

    def test_wrong_candidate_or_approval_claim_is_rejected(self):
        p = self.artifact / 'run/result.json'
        data = json.loads(p.read_text()); data['candidate_id'] = 'sha256-' + '0' * 64
        put(self.artifact / 'run', 'result.json', data); seal(self.artifact / 'run')
        self.repack_run()
        with self.assertRaisesRegex(archive.ArchiveError, 'identity'):
            self.prepare()
        data['candidate_id'] = self.cid; data['research_baseline_created'] = True
        put(self.artifact / 'run', 'result.json', data); seal(self.artifact / 'run')
        self.repack_run()
        with self.assertRaisesRegex(archive.ArchiveError, 'approval'):
            self.prepare(self.root / 'unsafe' / 'assets')

    def test_duplicate_release_tag_is_rejected_without_creation(self):
        publisher = archive.GitHubReleasePublisher('test-token')
        calls = []
        def api(method, endpoint, payload=None, **kwargs):
            calls.append((method, endpoint))
            if endpoint == '/repos/' + archive.REPOSITORY:
                return {'id': self.repo_id, 'full_name': archive.REPOSITORY, 'private': True}
            if endpoint.endswith('/releases/tags/ci-v2-research-run-41-attempt-2-aaaaaaaa'):
                return {'id': 1}
            return None
        with patch.object(publisher, '_api', side_effect=api):
            with self.assertRaisesRegex(archive.ArchiveError, 'already exists'):
                publisher.publish({'manifest': {'research_review': 'PENDING', 'quality_status': 'QUALITY_REVIEW_REQUIRED'},
                                   'directory': str(self.output)}, run_id=41, attempt=2,
                                  head_sha=self.head, candidate_id=self.cid)
        self.assertFalse(any(m == 'POST' for m, _ in calls))

    def test_private_repository_permission_failure_is_sanitized(self):
        with self.assertRaisesRegex(archive.ArchiveError, 'authorization'):
            archive.GitHubReleasePublisher('')
        publisher = archive.GitHubReleasePublisher('test-token')
        with patch.object(publisher, '_api', side_effect=archive.ArchiveError('GitHub API request failed')):
            with self.assertRaises(archive.ArchiveError):
                publisher.verify_origin(run_id=41, attempt=2, head_sha=self.head,
                    artifact_id=self.artifact_id, artifact_digest=self.artifact_digest)

    def test_upload_action_raw_digest_matches_rest_api_prefixed_digest(self):
        raw_digest = '8' * 64
        publisher = archive.GitHubReleasePublisher('test-token')
        repo = {'id': self.repo_id, 'full_name': archive.REPOSITORY, 'private': True}
        run = {'id': self.run_id, 'run_attempt': self.attempt,
               'path': archive.WORKFLOW, 'event': 'workflow_dispatch',
               'head_branch': archive.WORKFLOW_BRANCH,
               'status': 'in_progress', 'head_sha': self.head,
               'repository': {'id': self.repo_id, 'full_name': archive.REPOSITORY},
               'head_repository': {'id': self.repo_id, 'full_name': archive.REPOSITORY}}
        jobs = {'total_count': 2, 'jobs': [
            {'id': 901, 'name': 'candidate', 'run_id': self.run_id,
             'head_sha': self.head, 'head_branch': archive.WORKFLOW_BRANCH,
             'status': 'completed', 'conclusion': 'success'},
            {'id': 902, 'name': 'archive-candidate', 'run_id': self.run_id,
             'head_sha': self.head, 'head_branch': archive.WORKFLOW_BRANCH,
             'status': 'in_progress', 'conclusion': None},
        ]}
        artifact = {'id': self.artifact_id,
                    'name': f'ci-v2-research-{self.run_id}-{self.attempt}',
                    'expired': False, 'size_in_bytes': 123,
                    'digest': 'sha256:' + raw_digest,
                    'workflow_run': {'id': self.run_id, 'repository_id': self.repo_id,
                        'head_repository_id': self.repo_id, 'head_sha': self.head}}
        with patch.object(publisher, '_api', side_effect=[repo, run, jobs, artifact]) as api:
            result = publisher.verify_origin(run_id=self.run_id, attempt=self.attempt,
                head_sha=self.head, artifact_id=self.artifact_id, artifact_digest=raw_digest)
        self.assertEqual(result['artifact_digest'], 'sha256:' + raw_digest)
        self.assertEqual(result['candidate_job_id'], 901)
        self.assertEqual(result['candidate_job_conclusion'], 'success')
        self.assertTrue(any(
            call.args[1].endswith(
                f'/actions/runs/{self.run_id}/attempts/{self.attempt}/jobs?per_page=100&page=1')
            for call in api.call_args_list))
        self.assertEqual(archive._canonical_artifact_digest('sha256:' + raw_digest),
                         'sha256:' + raw_digest)
        with self.assertRaises(archive.ArchiveError):
            archive._canonical_artifact_digest('sha256:' + 'G' * 64)

    def test_origin_rejects_failed_or_mismatched_candidate_job(self):
        publisher = archive.GitHubReleasePublisher('test-token')
        repo = {'id': self.repo_id, 'full_name': archive.REPOSITORY, 'private': True}
        run = {'id': self.run_id, 'run_attempt': self.attempt,
               'path': archive.WORKFLOW, 'event': 'workflow_dispatch',
               'head_branch': archive.WORKFLOW_BRANCH,
               'status': 'in_progress', 'head_sha': self.head,
               'repository': {'id': self.repo_id, 'full_name': archive.REPOSITORY},
               'head_repository': {'id': self.repo_id, 'full_name': archive.REPOSITORY}}
        invalid_jobs = [
            {'total_count': 1, 'jobs': [{'id': 901, 'name': 'candidate', 'run_id': self.run_id,
                'head_sha': self.head, 'head_branch': archive.WORKFLOW_BRANCH,
                'status': 'completed', 'conclusion': 'failure'}]},
            {'total_count': 1, 'jobs': [{'id': 901, 'name': 'candidate', 'run_id': self.run_id,
                'head_sha': self.head, 'head_branch': archive.WORKFLOW_BRANCH,
                'status': 'completed', 'conclusion': 'cancelled'}]},
            {'total_count': 1, 'jobs': [{'id': 901, 'name': 'candidate', 'run_id': self.run_id,
                'head_sha': self.head, 'head_branch': archive.WORKFLOW_BRANCH,
                'status': 'completed', 'conclusion': 'skipped'}]},
            {'total_count': 1, 'jobs': [{'id': 901, 'name': 'candidate', 'run_id': self.run_id,
                'head_sha': self.head, 'head_branch': archive.WORKFLOW_BRANCH,
                'status': 'queued', 'conclusion': None}]},
            {'total_count': 1, 'jobs': [{'id': 901, 'name': 'candidate', 'run_id': self.run_id + 1,
                'head_sha': self.head, 'head_branch': archive.WORKFLOW_BRANCH,
                'status': 'completed', 'conclusion': 'success'}]},
            {'total_count': 2, 'jobs': [{'id': 901, 'name': 'candidate', 'run_id': self.run_id,
                'head_sha': self.head, 'head_branch': archive.WORKFLOW_BRANCH,
                'status': 'completed', 'conclusion': 'success'}]},
            {'total_count': 2, 'jobs': [
                {'id': 901, 'name': 'candidate', 'run_id': self.run_id,
                 'head_sha': self.head, 'head_branch': archive.WORKFLOW_BRANCH,
                 'status': 'completed', 'conclusion': 'success'},
                {'id': 903, 'name': 'candidate', 'run_id': self.run_id,
                 'head_sha': self.head, 'head_branch': archive.WORKFLOW_BRANCH,
                 'status': 'completed', 'conclusion': 'success'}]},
            {'total_count': 1, 'jobs': [{'id': 901, 'name': 'candidate', 'run_id': self.run_id,
                'head_sha': self.head, 'head_branch': 'other-branch',
                'status': 'completed', 'conclusion': 'success'}]},
        ]
        for jobs in invalid_jobs:
            with self.subTest(jobs=jobs), patch.object(publisher, '_api', side_effect=[repo, run, jobs]):
                with self.assertRaises(archive.ArchiveError):
                    publisher.verify_origin(run_id=self.run_id, attempt=self.attempt,
                        head_sha=self.head, artifact_id=self.artifact_id,
                        artifact_digest=self.artifact_digest)

    def test_origin_rejects_completed_whole_run_during_archive_job(self):
        publisher = archive.GitHubReleasePublisher('test-token')
        repo = {'id': self.repo_id, 'full_name': archive.REPOSITORY, 'private': True}
        completed_run = {'id': self.run_id, 'run_attempt': self.attempt,
            'path': archive.WORKFLOW, 'event': 'workflow_dispatch',
            'head_branch': archive.WORKFLOW_BRANCH,
            'status': 'completed', 'conclusion': 'success', 'head_sha': self.head,
            'repository': {'id': self.repo_id, 'full_name': archive.REPOSITORY},
            'head_repository': {'id': self.repo_id, 'full_name': archive.REPOSITORY}}
        with patch.object(publisher, '_api', side_effect=[repo, completed_run]):
            with self.assertRaisesRegex(archive.ArchiveError, 'in-progress'):
                publisher.verify_origin(run_id=self.run_id, attempt=self.attempt,
                    head_sha=self.head, artifact_id=self.artifact_id,
                    artifact_digest=self.artifact_digest)

    def test_origin_rejects_run_from_unapproved_branch(self):
        publisher = archive.GitHubReleasePublisher('test-token')
        repo = {'id': self.repo_id, 'full_name': archive.REPOSITORY, 'private': True}
        run = {'id': self.run_id, 'run_attempt': self.attempt,
            'path': archive.WORKFLOW, 'event': 'workflow_dispatch',
            'head_branch': 'other-branch', 'status': 'in_progress', 'head_sha': self.head,
            'repository': {'id': self.repo_id, 'full_name': archive.REPOSITORY},
            'head_repository': {'id': self.repo_id, 'full_name': archive.REPOSITORY}}
        with patch.object(publisher, '_api', side_effect=[repo, run]):
            with self.assertRaisesRegex(archive.ArchiveError, 'exact in-progress'):
                publisher.verify_origin(run_id=self.run_id, attempt=self.attempt,
                    head_sha=self.head, artifact_id=self.artifact_id,
                    artifact_digest=self.artifact_digest)

    def test_successful_draft_upload_publish_and_immutable_verification(self):
        prepared = self.prepare()
        prepared['directory'] = str(self.output)
        publisher = archive.GitHubReleasePublisher('test-token')
        calls = []; uploaded = []; state = {'draft': None}
        def api(method, endpoint, payload=None, **kwargs):
            calls.append((method, endpoint, payload))
            if endpoint == '/repos/' + archive.REPOSITORY:
                return {'id': self.repo_id, 'full_name': archive.REPOSITORY, 'private': True}
            if '/releases/tags/' in endpoint or '/git/ref/tags/' in endpoint:
                return None
            if method == 'POST' and endpoint.endswith('/releases'):
                state['draft'] = {'id': 99, 'tag_name': payload['tag_name'], 'draft': True,
                    'target_commitish': self.head, 'upload_url': f'https://uploads.github.com/repos/{archive.REPOSITORY}/releases/99/assets{{?name,label}}',
                    'assets': []}
                return deepcopy(state['draft'])
            if endpoint.endswith('/releases/99') and method == 'GET':
                return deepcopy(state['draft']) if state['draft']['draft'] else {
                    **state['draft'], 'draft': False, 'immutable': True}
            if endpoint.endswith('/releases/99') and method == 'PATCH':
                state['draft']['draft'] = False
                return {'id': 99}
            raise AssertionError((method, endpoint))
        def upload(url, release_id, path):
            value = {'id': len(uploaded) + 1, 'name': Path(path).name,
                'size': Path(path).stat().st_size, 'state': 'uploaded',
                'digest': 'sha256:' + archive._digest(path)}
            uploaded.append(value); state['draft']['assets'].append(value); return value
        with patch.object(publisher, '_api', side_effect=api), patch.object(publisher, '_upload', side_effect=upload):
            result = publisher.publish(prepared, run_id=41, attempt=2, head_sha=self.head, candidate_id=self.cid)
        self.assertEqual(result['status'], 'PUBLISHED_IMMUTABLE_RESEARCH_ARCHIVE')
        self.assertEqual(len(result['assets']), 3)
        self.assertEqual([m for m, _, _ in calls if m == 'PATCH'], ['PATCH'])
        self.assertFalse(any(entry['name'] == 'trusted_baselines.json' for entry in result['assets']))
        self.assertEqual(file_digest(BASELINE_REGISTRY), self.registry_before)

    def test_partial_upload_failure_leaves_draft_unpublished(self):
        prepared = self.prepare(); prepared['directory'] = str(self.output)
        publisher = archive.GitHubReleasePublisher('test-token')
        calls = []; state = {'draft': None}; uploads = 0
        def api(method, endpoint, payload=None, **kwargs):
            calls.append((method, endpoint))
            if endpoint == '/repos/' + archive.REPOSITORY:
                return {'id': self.repo_id, 'full_name': archive.REPOSITORY, 'private': True}
            if '/releases/tags/' in endpoint or '/git/ref/tags/' in endpoint: return None
            if method == 'POST':
                state['draft'] = {'id': 101, 'tag_name': payload['tag_name'], 'draft': True,
                    'target_commitish': self.head, 'upload_url': f'https://uploads.github.com/repos/{archive.REPOSITORY}/releases/101/assets{{?name,label}}', 'assets': []}
                return state['draft']
            return state['draft']
        def upload(*args):
            nonlocal uploads
            uploads += 1
            if uploads == 2: raise archive.ArchiveError('GitHub Release asset upload failed')
            path = Path(args[2])
            return {'id': 1, 'name': path.name, 'size': path.stat().st_size, 'state': 'uploaded',
                    'digest': 'sha256:' + archive._digest(path)}
        with patch.object(publisher, '_api', side_effect=api), patch.object(publisher, '_upload', side_effect=upload):
            with self.assertRaises(archive.ArchiveError):
                publisher.publish(prepared, run_id=41, attempt=2, head_sha=self.head, candidate_id=self.cid)
        self.assertTrue(state['draft']['draft'])
        self.assertFalse(any(method == 'PATCH' for method, _ in calls))
        self.assertEqual(file_digest(BASELINE_REGISTRY), self.registry_before)

    def test_workflow_opt_in_defaults_false_and_permissions_are_job_scoped(self):
        workflow = Path(__file__).resolve().parents[1] / '.github/workflows/ci_v2_manual_research.yml'
        text = workflow.read_text()
        self.assertIn('archive_candidate:', text)
        self.assertIn('default: false', text)
        self.assertIn("contents: read", text)
        self.assertIn('archive-candidate:', text)
        self.assertIn('contents: write', text)
        self.assertIn("needs.candidate.result == 'success'", text)
        self.assertIn("github.ref == 'refs/heads/ci-upstream-refresh'", text)
        self.assertIn('70fc10c6e5e1ce46ad2ea6f2b72d43f7d47b13c3', text)
        self.assertIn('digest-mismatch: error', text)
        self.assertIn('--publish', text)
        self.assertIn('scripts/archive_candidate_release.py', text)


class ReleaseUploadUrlTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.asset = Path(directory.name) / 'candidate.tar.gz'
        self.asset.write_bytes(b'synthetic-upload-asset\n')
        self.publisher = archive.GitHubReleasePublisher('synthetic-upload-token')
        self.release_id = 99
        self.endpoint = f'/repos/{archive.REPOSITORY}/releases/{self.release_id}/assets'
        self.base_url = 'https://uploads.github.com' + self.endpoint

    def assert_upload(self, url, *, publisher=None, asset=None, target=None):
        publisher = self.publisher if publisher is None else publisher
        asset = self.asset if asset is None else asset
        metadata = {'id': 123, 'name': asset.name, 'size': asset.stat().st_size,
                    'state': 'uploaded', 'digest': 'sha256:' + file_digest(asset)}
        with patch.object(archive.http.client, 'HTTPSConnection', autospec=True) as connect:
            connection = connect.return_value
            response = connection.getresponse.return_value
            response.status = 201
            response.read.return_value = json.dumps(metadata).encode()
            # Exercise the actual uploader, including its URL validation.
            result = publisher._upload(url, self.release_id, asset)
            self.assertEqual(result, metadata)
            connect.assert_called_once_with('uploads.github.com', timeout=300)
            connection.putrequest.assert_called_once_with(
                'POST', target or self.endpoint + '?name=candidate.tar.gz')
            connection.putheader.assert_any_call('Content-Length', str(asset.stat().st_size))
            connection.putheader.assert_any_call('Content-Type', 'application/gzip')
            connection.send.assert_called_once_with(asset.read_bytes())
            connection.close.assert_called_once_with()
        self.assertEqual(publisher._verify_asset(self.release_id, result, asset)['sha256'],
                         file_digest(asset))

    def assert_rejected(self, urls):
        for url in urls:
            with self.subTest(url=url):
                with patch.object(archive.http.client, 'HTTPSConnection', autospec=True) as connect:
                    with self.assertRaisesRegex(archive.ArchiveError, 'unsafe Release upload URL') as error:
                        self.publisher._upload(url, self.release_id, self.asset)
                    connect.assert_not_called()
                    self.assertNotIn(self.publisher.token, str(error.exception))

    def test_real_github_uri_template_is_accepted(self):
        self.assert_upload(self.base_url + '{?name,label}')

    def test_bare_url_and_explicit_https_port_remain_compatible(self):
        for authority in ('uploads.github.com', 'uploads.github.com:443'):
            for suffix in ('', '{?name,label}'):
                with self.subTest(authority=authority, suffix=suffix):
                    self.assert_upload('https://' + authority + self.endpoint + suffix)

    def test_filename_is_percent_encoded_in_constructed_request(self):
        asset = self.asset.with_name('candidate +\u00e9?#.tar.gz')
        asset.write_bytes(self.asset.read_bytes())
        self.assert_upload(self.base_url + '{?name,label}', asset=asset,
                           target=self.endpoint + '?name=candidate%20%2B%C3%A9%3F%23.tar.gz')

    def test_historical_adapter_uses_real_uploader_with_template(self):
        from src.historical_candidate_archive import _Publisher
        self.assertIs(_Publisher._upload, archive.GitHubReleasePublisher._upload)
        publisher = _Publisher('synthetic-upload-token', archive.REPOSITORY)
        self.assert_upload(self.base_url + '{?name,label}', publisher=publisher)

    def test_unexpected_template_forms_are_rejected(self):
        self.assert_rejected([self.base_url + suffix for suffix in (
            '{?name}', '{?label,name}', '{?name,label,extra}', '{name,label}',
            '{?name,label}{?name,label}', '{?name,label}/extra', '{?name,label',
            '%7B?name,label%7D', '{}')])

    def test_queries_and_fragments_are_rejected(self):
        self.assert_rejected([self.base_url + suffix for suffix in (
            '?name=unexpected', '?', '#fragment', '#', '?x=1{?name,label}',
            '{?name,label}?x=1', '{?name,label}#fragment')])

    def test_wrong_hosts_schemes_and_ports_are_rejected(self):
        self.assert_rejected([
            'http://uploads.github.com' + self.endpoint,
            'https://api.github.com' + self.endpoint,
            'https://uploads.github.com.example.com' + self.endpoint,
            'https://uploads.github.com:444' + self.endpoint,
            'https://uploads.github.com:invalid' + self.endpoint,
            '//uploads.github.com' + self.endpoint,
            self.base_url + '\n', '\t' + self.base_url,
        ])

    def test_embedded_credentials_are_rejected(self):
        self.assert_rejected([
            'https://user:password@uploads.github.com' + self.endpoint,
            'https://@uploads.github.com' + self.endpoint,
            'https://uploads.github.com@other.example' + self.endpoint,
        ])

    def test_wrong_repository_release_and_path_suffixes_are_rejected(self):
        self.assert_rejected([
            self.base_url.replace('/releases/99/', '/releases/999/'),
            self.base_url.replace(archive.REPOSITORY, 'other-owner/other-repository'),
            self.base_url + '/extra', self.base_url + '-suffix',
            self.base_url + '/../assets', self.base_url + '%2fextra',
            self.base_url + '/extra{?name,label}',
            self.base_url.replace('/assets', '/assets-extra') + '{?name,label}',
        ])

    def test_non_string_urls_are_rejected_before_connection(self):
        self.assert_rejected([None, 123, self.base_url.encode()])


if __name__ == '__main__':
    unittest.main()
