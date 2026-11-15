"""Offline only: synthetic sealed evidence and mocked GitHub API/transport."""
from copy import deepcopy
from contextlib import ExitStack, redirect_stdout
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import unittest
from unittest.mock import patch
import zipfile

from src import historical_candidate_archive as h
from src import candidate_release_archive as archive
import test_candidate_release_archive as fixtures


class FakeGitHub(h._Publisher):
    def __init__(self, deployment, request, zip_bytes):
        super().__init__('offline-secret', deployment['repository'])
        self.d, self.request, self.zip_bytes = deployment, request, zip_bytes
        d, o = deployment, request['original']
        repo = {'id': d['repository_id'], 'full_name': d['repository'], 'private': True,
                'default_branch': d['default_branch'], 'owner': {'id': 13, 'type': 'User'}}
        origin = {'id': o['run_id'], 'run_attempt': 1, 'status': 'completed', 'conclusion': 'success',
                  'path': o['workflow_path'], 'head_branch': o['branch'], 'head_sha': o['head_sha'],
                  'event': 'workflow_dispatch', 'repository': repo, 'head_repository': repo,
                  'created_at': '2026-01-01T00:00:00Z', 'updated_at': '2026-01-01T00:10:00Z'}
        job = {'id': o['candidate_job_id'], 'run_id': o['run_id'], 'head_sha': o['head_sha'],
               'head_branch': o['branch'], 'status': 'completed', 'conclusion': 'success',
               'name': 'candidate', 'started_at': '2026-01-01T00:00:01Z', 'completed_at': '2026-01-01T00:09:59Z'}
        artifact = {'id': o['artifact_id'], 'name': o['artifact_name'], 'size_in_bytes': o['artifact_size'],
            'digest': 'sha256:' + o['artifact_sha256'], 'expired': False, 'created_at': '2026-01-01T00:09:58Z',
            'workflow_run': {'id': o['run_id'], 'repository_id': d['repository_id'],
                             'head_repository_id': d['repository_id'], 'head_sha': o['head_sha']}}
        current = {'id': 900, 'run_attempt': 1, 'status': 'in_progress', 'event': 'workflow_dispatch',
            'head_branch': d['default_branch'], 'head_sha': d['implementation_revision'], 'repository': repo,
            'actor': {'id': 13, 'type': 'User', 'login': 'owner'}, 'triggering_actor': {'id': 13, 'type': 'User'},
            'workflow_id': 901, 'created_at': '2026-01-02T00:00:00Z'}
        base = '/repos/' + d['repository']
        self.base = base
        self.responses = {base: repo,
            f"{base}/actions/runs/{o['run_id']}": deepcopy(origin),
            f"{base}/actions/runs/{o['run_id']}/attempts/1": origin,
            f"{base}/actions/runs/{o['run_id']}/attempts/1/jobs?per_page=100&page=1": {'total_count': 1, 'jobs': [job]},
            f"{base}/actions/artifacts/{o['artifact_id']}": artifact,
            base + '/actions/runs/900': current,
            base + '/actions/workflows/901': {'id': 901, 'path': d['workflow_path']},
            base + '/git/ref/heads/' + d['default_branch']: {'ref': 'refs/heads/' + d['default_branch'],
                                                               'object': {'sha': d['implementation_revision']}}}
        self.release = None
        self.tag = None
        self.calls = []
        self.fail_upload = None
        self.digest_missing = False
        self.mutable = False
        self.lost_patch = False
        self.lost_post = False
        self.fail_readback = False
        self.fail_post = False
        self.wrong_target = False

    def _api(self, method, endpoint, payload=None, *, allow_404=False):
        self.calls.append((method, endpoint))
        if method == 'GET' and endpoint in self.responses:
            return deepcopy(self.responses[endpoint])
        if method == 'GET' and '/git/ref/tags/' in endpoint:
            return deepcopy(self.tag)
        if method == 'POST':
            if self.fail_post:
                raise archive.ArchiveError('offline-secret https://unsafe.example/?token=offline-secret')
            self.release = {'id': 700, **payload, 'assets': [], 'upload_url': 'https://uploads.github.com' + self.base + '/releases/700/assets', 'immutable': False}
            if self.lost_post:
                raise OSError('lost response')
            return deepcopy(self.release)
        if method == 'PATCH':
            self.release.update(draft=False, immutable=not self.mutable)
            self.tag = {'ref': 'refs/tags/' + self.release['tag_name'], 'object': {'type': 'commit',
                'sha': '0' * 40 if self.wrong_target else self.d['implementation_revision']}}
            if self.lost_patch:
                raise OSError('lost response')
            return deepcopy(self.release)
        if method == 'GET' and '/releases/' in endpoint:
            if self.fail_readback and any(method == 'POST' for method, _ in self.calls):
                raise OSError('readback unavailable')
            return deepcopy(self.release)
        raise AssertionError((method, endpoint))

    def _upload(self, url, release_id, path):
        if path.name == self.fail_upload:
            raise archive.ArchiveError('partial upload')
        value = {'id': 800 + len(self.release['assets']), 'name': path.name, 'size': path.stat().st_size,
                 'state': 'uploaded', 'digest': None if self.digest_missing else 'sha256:' + archive._digest(path)}
        self.release['assets'].append(value)
        return deepcopy(value)


class HistoricalArchiveTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.CandidateArchiveTests('test_successful_prepare_is_deterministic_and_candidate_bound')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.attempt = 1
        self.project = self.f.root / 'project'
        (self.project / 'configs').mkdir(parents=True)
        self.temp = self.f.root / 'runner-temp'
        self.temp.mkdir()
        source_zip = self.f.root / 'original.zip'
        with zipfile.ZipFile(source_zip, 'w') as z:
            for p in sorted(self.f.artifact.rglob('*')):
                if p.is_file():
                    z.write(p, p.relative_to(self.f.artifact).as_posix())
        self.zip_bytes = source_zip.read_bytes()
        self.f.artifact_digest = 'sha256:' + h._hash(self.zip_bytes)
        self.prepared = archive.prepare(self.f.artifact, self.f.output, repository='portable/research', **self.f.metadata())
        self.d = {'schema_version': 1, 'repository': 'portable/research', 'repository_id': 55,
            'default_branch': 'research', 'workflow_path': h.WORKFLOW, 'implementation_revision': '7' * 40,
            'request_path': 'configs/archive-request.json', 'request_sha256': '',
            'policy_path': 'configs/archive-policy.json', 'policy_sha256': ''}
        self.request = {'schema_version': 1, 'purpose': h.PURPOSE,
            'original': {'workflow_path': archive.WORKFLOW, 'branch': 'research', 'run_id': 41, 'run_attempt': 1,
                'head_sha': self.f.head, 'candidate_job_id': 66, 'artifact_id': 77,
                'artifact_name': 'ci-v2-research-41-1', 'artifact_size': len(self.zip_bytes), 'artifact_sha256': h._hash(self.zip_bytes)},
            'candidate': {'candidate_id': self.f.cid, 'corpus_sha256': self.f.corpus_sha, 'upstreams': self.f.upstreams},
            'assets': self.prepared['assets']}
        self.policy = {'schema_version': 1, 'purpose': h.PURPOSE, 'enabled': True,
            'repository': 'portable/research', 'repository_id': 55, 'default_branch': 'research',
            'workflow_path': h.WORKFLOW, 'allow_repository_owner': True, 'authorized_approver_ids': []}
        self.env = {'RUNNER_TEMP': str(self.temp), 'GITHUB_RUN_ID': '900', 'GITHUB_RUN_ATTEMPT': '1',
            'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'GITHUB_REPOSITORY': 'portable/research',
            'GITHUB_REPOSITORY_ID': '55', 'GITHUB_SHA': '7' * 40, 'GITHUB_WORKFLOW_SHA': '7' * 40,
            'GITHUB_WORKFLOW_REF': 'portable/research/' + h.WORKFLOW + '@refs/heads/research',
            'GITHUB_WORKSPACE': str(self.project), 'GITHUB_ACTOR_ID': '13', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
            'GITHUB_REF': 'refs/heads/research', 'GITHUB_EVENT_PATH': str(self.f.root / 'event.json'),
            'GITHUB_TOKEN': 'offline-secret'}
        self.refresh()
        self.client = FakeGitHub(self.d, self.request, self.zip_bytes)

    def refresh(self):
        for name, value, key in ((self.d['request_path'], self.request, 'request_sha256'),
                                 (self.d['policy_path'], self.policy, 'policy_sha256')):
            raw = h._canonical(value)
            (self.project / name).write_bytes(raw)
            self.d[key] = h._hash(raw)
        raw = h._canonical(self.d).decode()
        self.env['HISTORICAL_ARCHIVE_DEPLOYMENT_JSON'] = raw
        self.env['HISTORICAL_ARCHIVE_DEPLOYMENT_SHA256'] = h._hash(raw.encode())
        _, self.subject_sha = h.archival_subject(self.d, self.request, self.request['candidate'])
        Path(self.env['GITHUB_EVENT_PATH']).write_text(json.dumps({'inputs': {'archival_subject_sha256': self.subject_sha}}))

    def execute(self, **overrides):
        def download(client, request, destination):
            destination.write_bytes(self.zip_bytes)
            h._need(len(self.zip_bytes) == request['original']['artifact_size']
                    and h._hash(self.zip_bytes) == request['original']['artifact_sha256'], 'ARTIFACT_DOWNLOAD_HASH_MISMATCH')
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, self.env, clear=True))
            stack.enter_context(patch.object(h, 'PROJECT', self.project))
            stack.enter_context(patch.object(h, '_checkout'))
            stack.enter_context(patch.object(h, '_Publisher', return_value=self.client))
            stack.enter_context(patch.object(h, '_download', side_effect=download))
            stack.enter_context(patch.object(archive.trusted_snapshot, '_request', side_effect=lambda *a, **k: io.BytesIO(self.zip_bytes)))
            for name, value in overrides.items():
                stack.enter_context(patch.object(h, name, value))
            return h.run()

    def assert_blocked(self, reason=None):
        result = self.execute()
        self.assertEqual(result['publication_state'], 'BLOCKED_BEFORE_PUBLICATION', result)
        self.assertFalse(any(method != 'GET' for method, _ in self.client.calls))
        if reason:
            self.assertEqual(result['reason'], reason)
        self.assertEqual(archive._digest(fixtures.BASELINE_REGISTRY), self.f.registry_before)
        return result

    def test_completed_origin_and_separate_authorized_dispatch_publish_exact_assets(self):
        result = self.execute()
        self.assertEqual(result['publication_state'], 'PUBLISHED_IMMUTABLE_VERIFIED', result)
        self.assertTrue(result['audit_saved'])
        self.assertEqual(len(result['assets']), 3)
        self.assertEqual(result['original']['original']['head_sha'], self.f.head)
        self.assertEqual(result['subject']['release_target_commit'], '7' * 40)
        self.assertEqual(self.prepared['manifest']['workflow_commit'], self.f.head)
        self.assertEqual(result['quality_status'], 'QUALITY_REVIEW_REQUIRED')
        self.assertEqual(result['q1_status'], 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
        self.assertEqual(result['P8'], 'BLOCKED')
        self.assertEqual(result['production_promotion'], 'NOT_AUTHORIZED')
        self.assertFalse(result['trusted_parent_registered'])
        audit = Path(result['output_directory'])
        self.assertEqual(set(p.name for p in audit.iterdir()), {'result.json', 'checksums.json'})
        self.assertEqual(json.loads((audit / 'checksums.json').read_text())['result.json'], archive._digest(audit / 'result.json'))
        self.assertEqual(list(self.temp.iterdir()), [audit])
        self.assertEqual(archive._digest(fixtures.BASELINE_REGISTRY), self.f.registry_before)

    def test_failed_cancelled_or_incomplete_original_run(self):
        endpoint = self.client.base + '/actions/runs/41'
        for status, conclusion in [('completed', 'failure'), ('completed', 'cancelled'), ('in_progress', None)]:
            with self.subTest(status=status, conclusion=conclusion):
                self.client.responses[endpoint].update(status=status, conclusion=conclusion)
                self.assert_blocked('ORIGINAL_RUN_MISMATCH_OR_RERUN')

    def test_original_workflow_branch_commit_repository_and_reruns(self):
        endpoint = self.client.base + '/actions/runs/41'
        original = deepcopy(self.client.responses[endpoint])
        for key, value in [('path', 'wrong.yml'), ('head_branch', 'wrong'), ('head_sha', '0' * 40),
                           ('run_attempt', 2), ('repository', {'id': 999})]:
            with self.subTest(key=key):
                self.client.responses[endpoint] = {**deepcopy(original), key: value}
                self.assert_blocked()

    def test_private_repository_identity(self):
        self.client.responses[self.client.base]['private'] = False
        self.assert_blocked('ORIGINAL_REPOSITORY_MISMATCH')

    def test_candidate_job_absent_duplicate_failed_skipped_or_wrong_id(self):
        endpoint = self.client.base + '/actions/runs/41/attempts/1/jobs?per_page=100&page=1'
        job = deepcopy(self.client.responses[endpoint]['jobs'][0])
        for jobs in ([], [job, job], [{**job, 'id': 999}], [{**job, 'conclusion': 'skipped'}],
                     [{**job, 'conclusion': 'failure'}], [{**job, 'head_sha': '0' * 40}]):
            with self.subTest(jobs=jobs):
                self.client.responses[endpoint] = {'total_count': len(jobs), 'jobs': jobs}
                self.assert_blocked()

    def test_expired_foreign_wrong_artifact_digest_name_size_and_timestamps(self):
        endpoint = self.client.base + '/actions/artifacts/77'
        original = deepcopy(self.client.responses[endpoint])
        for key, value in [('expired', True), ('digest', None), ('digest', 'sha256:' + '0' * 64),
                           ('name', 'foreign'), ('id', 999), ('size_in_bytes', 1),
                           ('workflow_run', {'id': 999}), ('created_at', '2026-01-02T00:00:00Z')]:
            with self.subTest(key=key, value=value):
                self.client.responses[endpoint] = {**deepcopy(original), key: value}
                self.assert_blocked()

    def test_missing_artifact(self):
        self.client.responses[self.client.base + '/actions/artifacts/77'] = None
        self.assert_blocked()

    def test_unauthorized_actor(self):
        self.policy.update(allow_repository_owner=False, authorized_approver_ids=[99])
        self.refresh()
        self.assert_blocked('UNAUTHORIZED_WORKFLOW_ACTOR')

    def test_designated_approver(self):
        self.policy.update(allow_repository_owner=False, authorized_approver_ids=[13])
        self.refresh()
        self.assertEqual(self.execute()['publication_state'], 'PUBLISHED_IMMUTABLE_VERIFIED')

    def test_wrong_current_workflow(self):
        self.client.responses[self.client.base + '/actions/workflows/901']['path'] = archive.WORKFLOW
        self.assert_blocked('GITHUB_WORKFLOW_PATH_MISMATCH')

    def test_stale_default_head(self):
        self.client.responses[self.client.base + '/git/ref/heads/research']['object']['sha'] = '0' * 40
        self.assert_blocked('STALE_WORKFLOW_COMMIT')

    def test_replayed_archival_attempt(self):
        self.env['GITHUB_RUN_ATTEMPT'] = '2'
        self.assert_blocked('INVALID_OR_REPLAYED_WORKFLOW_ATTEMPT')

    def test_implementation_revision_mismatch(self):
        self.env['GITHUB_SHA'] = '0' * 40
        self.assert_blocked('UNTRUSTED_RUNTIME_CONTEXT')

    def test_policy_pin_mismatch(self):
        (self.project / self.d['policy_path']).write_text('{}')
        self.assert_blocked('INDEPENDENT_CONFIG_PIN_MISMATCH')

    def test_wrong_dispatch_subject(self):
        Path(self.env['GITHUB_EVENT_PATH']).write_text(json.dumps({'inputs': {'archival_subject_sha256': '0' * 64}}))
        self.assert_blocked('DISPATCH_SUBJECT_MISMATCH')

    def test_candidate_corpus_and_upstream_mismatch(self):
        original = deepcopy(self.request['candidate'])
        for key, value in [('candidate_id', 'sha256-' + '0' * 64), ('corpus_sha256', '0' * 64),
                           ('upstreams', {'SPHinXsys': '0' * 40, 'SPHinXsim': '2' * 40})]:
            with self.subTest(key=key):
                self.request['candidate'] = {**original, key: value}
                self.refresh()
                self.assert_blocked('CANDIDATE_EVIDENCE_MISMATCH')
                # Each failure owns a new audit directory; preserve all earlier outputs.
                self.env['GITHUB_RUN_ID'] = '900'
                prior = self.temp / 'historical-archive-900-1'
                if prior.exists():
                    prior.rename(self.temp / ('failed-' + key))

    def test_wrong_prepared_asset_pin(self):
        self.request['assets']['release-manifest.json']['sha256'] = '0' * 64
        self.refresh()
        self.assert_blocked('PREPARED_ASSET_CHANGED')

    def test_zip_transport_checksum_failure(self):
        self.zip_bytes = b'bad'
        self.assert_blocked('ARTIFACT_DOWNLOAD_HASH_MISMATCH')

    def test_unsafe_zip_members_duplicate_and_symlinks(self):
        for index, (name, mode) in enumerate([('../escape', stat.S_IFREG), ('/absolute', stat.S_IFREG), ('a\\b', stat.S_IFREG), ('link', stat.S_IFLNK)]):
            with self.subTest(name=name):
                source = self.f.root / 'unsafe.zip'
                with zipfile.ZipFile(source, 'w') as z:
                    info = zipfile.ZipInfo(name)
                    info.external_attr = mode << 16
                    z.writestr(info, b'x')
                with self.assertRaises(ValueError):
                    h._extract(source, self.f.root / ('extract-' + str(index)))

    def test_canonical_archive_paths_allow_spaces_and_unicode(self):
        source = self.f.root / 'portable.zip'
        with zipfile.ZipFile(source, 'w') as z:
            z.writestr('run/source/a file.txt', b'content')
            z.writestr('run/source/\u03b1.txt', b'content')
        destination = self.f.root / 'portable-extracted'
        h._extract(source, destination)
        self.assertEqual((destination / 'run/source/\u03b1.txt').read_bytes(), b'content')

    def test_duplicate_zip_member_rejected(self):
        import warnings
        source = self.f.root / 'duplicate.zip'
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(source, 'w') as z:
                z.writestr('run/result.json', b'one')
                z.writestr('run/result.json', b'two')
        with self.assertRaisesRegex(h.HistoricalArchiveError, 'UNSAFE_ZIP_INVENTORY'):
            h._extract(source, self.f.root / 'duplicate-extracted')

    def test_tag_and_release_conflicts(self):
        self.client.tag = {'ref': 'existing'}
        self.assert_blocked('RELEASE_OR_TAG_CONFLICT')

    def test_duplicate_release_is_not_reused(self):
        self.client.release = {'id': 700, 'draft': False}
        self.assert_blocked('RELEASE_OR_TAG_CONFLICT')

    def test_partial_upload_retains_unpublished_draft(self):
        self.client.fail_upload = 'research-evidence.tar.gz'
        result = self.execute()
        self.assertEqual(result['publication_state'], 'DRAFT_CREATED_NOT_PUBLISHED')
        self.assertTrue(self.client.release['draft'])
        self.assertFalse(any(method == 'PATCH' for method, _ in self.client.calls))

    def test_no_digest_uses_credential_safe_independent_download(self):
        self.client.digest_missing = True
        def stream(url, **kwargs):
            if '/actions/artifacts/' in url:
                return io.BytesIO(self.zip_bytes)
            asset_id = int(url.rsplit('/', 1)[1])
            name = self.client.release['assets'][asset_id - 800]['name']
            self.assertEqual(kwargs, {'binary': True, 'token': 'offline-secret'})
            return io.BytesIO((self.f.output / name).read_bytes())
        # execute() patches the same primitive, so override the download hook via an inner wrapper.
        original_publish = h._publish
        def publish(*args):
            with patch.object(archive.trusted_snapshot, '_request', side_effect=stream):
                return original_publish(*args)
        result = self.execute(_publish=publish)
        self.assertEqual(result['publication_state'], 'PUBLISHED_IMMUTABLE_VERIFIED', result)

    def test_unverifiable_uploaded_digest_blocks_publication(self):
        self.client.digest_missing = True  # Default mock returns original ZIP, not asset bytes.
        result = self.execute()
        self.assertEqual(result['publication_state'], 'DRAFT_CREATED_NOT_PUBLISHED')

    def test_published_but_mutable_is_not_success(self):
        self.client.mutable = True
        result = self.execute()
        self.assertEqual(result['publication_state'], 'PUBLISHED_BUT_UNVERIFIED')

    def test_wrong_release_tag_commit_is_not_verified(self):
        self.client.wrong_target = True
        result = self.execute()
        self.assertEqual(result['publication_state'], 'PUBLISHED_BUT_UNVERIFIED')

    def test_lost_publish_response_readback_keeps_real_publication_state(self):
        self.client.lost_patch = True
        result = self.execute()
        self.assertEqual(result['publication_state'], 'PUBLISHED_BUT_UNVERIFIED')
        self.assertEqual(sum(method == 'PATCH' for method, _ in self.client.calls), 1)

    def test_lost_draft_response_readback_preserves_draft(self):
        self.client.lost_post = True
        self.assertEqual(self.execute()['publication_state'], 'DRAFT_CREATED_NOT_PUBLISHED')

    def test_failed_create_and_readback_reports_unknown_and_sanitizes(self):
        self.client.fail_post = self.client.fail_readback = True
        result = self.execute()
        self.assertEqual(result['publication_state'], 'PUBLICATION_STATE_UNKNOWN')
        raw = json.dumps(result)
        self.assertNotIn('offline-secret', raw)
        self.assertNotIn('unsafe.example', raw)

    def test_receipt_failure_never_erases_verified_publication(self):
        def fail(*args):
            raise OSError('receipt failure')
        result = self.execute(_persist=fail)
        self.assertEqual(result['publication_state'], 'PUBLISHED_IMMUTABLE_VERIFIED')
        self.assertFalse(result['audit_saved'])
        self.assertEqual(result['audit_error'], 'AUDIT_PERSISTENCE_FAILED')
        with patch.object(h, 'run', return_value=result), redirect_stdout(io.StringIO()) as out:
            self.assertEqual(h.main([]), 1)
        self.assertEqual(json.loads(out.getvalue())['publication_state'], 'PUBLISHED_IMMUTABLE_VERIFIED')

    def test_revalidation_before_draft_and_publish(self):
        original = h._context
        count = 0
        def context(*args):
            nonlocal count
            count += 1
            if count == 3:
                raise h.HistoricalArchiveError('DISPATCH_SUBJECT_MISMATCH')
            return original(*args)
        result = self.execute(_context=context)
        self.assertEqual(count, 3)
        self.assertEqual(result['publication_state'], 'DRAFT_CREATED_NOT_PUBLISHED')
        self.assertFalse(any(method == 'PATCH' for method, _ in self.client.calls))

    def test_revalidation_before_first_remote_write(self):
        original = h._context
        count = 0
        def context(*args):
            nonlocal count
            count += 1
            if count == 2:
                raise h.HistoricalArchiveError('STALE_WORKFLOW_COMMIT')
            return original(*args)
        result = self.execute(_context=context)
        self.assertEqual(result['publication_state'], 'BLOCKED_BEFORE_PUBLICATION')
        self.assertFalse(any(method != 'GET' for method, _ in self.client.calls))

    def test_staged_asset_mutation_leaves_draft_unpublished(self):
        upload = self.client._upload
        def mutate(url, release_id, path):
            value = upload(url, release_id, path)
            if path.name == 'release-manifest.json':
                # Alter a previously uploaded local asset before the final recheck.
                (path.parent / 'candidate.tar.gz').write_bytes(b'changed')
            return value
        self.client._upload = mutate
        result = self.execute()
        self.assertEqual(result['publication_state'], 'DRAFT_CREATED_NOT_PUBLISHED')
        self.assertFalse(any(method == 'PATCH' for method, _ in self.client.calls))

    def test_annotated_tag_form_is_rejected(self):
        api = self.client._api
        def changed_tag(method, endpoint, *args, **kwargs):
            value = api(method, endpoint, *args, **kwargs)
            if method == 'GET' and '/git/ref/tags/' in endpoint and value is not None:
                value['object']['type'] = 'tag'
            return value
        self.client._api = changed_tag
        self.assertEqual(self.execute()['publication_state'], 'PUBLISHED_BUT_UNVERIFIED')

    def test_incomplete_sealed_evidence_never_reaches_draft_creation(self):
        (self.f.artifact / 'run/result.json').unlink()
        source = self.f.root / 'changed.zip'
        with zipfile.ZipFile(source, 'w') as z:
            for p in sorted(self.f.artifact.rglob('*')):
                if p.is_file():
                    z.write(p, p.relative_to(self.f.artifact).as_posix())
        self.zip_bytes = source.read_bytes()
        self.request['original'].update(artifact_size=len(self.zip_bytes), artifact_sha256=h._hash(self.zip_bytes))
        self.refresh()
        self.client = FakeGitHub(self.d, self.request, self.zip_bytes)
        self.assert_blocked()

    def test_missing_gh_and_github_authorization_fail_closed(self):
        with patch.object(h.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(h.HistoricalArchiveError, 'GITHUB_CLI_UNAVAILABLE'):
                h._download(self.client, self.request, self.f.root / 'no-gh.zip')
        with self.assertRaisesRegex(h.HistoricalArchiveError, 'MISSING_GITHUB_AUTHORIZATION'):
            h._Publisher(None, self.d['repository'])

    def test_zero_exit_requires_both_publication_and_audit(self):
        for state, saved, expected in [('PUBLISHED_IMMUTABLE_VERIFIED', True, 0),
            ('PUBLISHED_IMMUTABLE_VERIFIED', False, 1), ('PUBLISHED_BUT_UNVERIFIED', True, 1),
            ('PUBLICATION_STATE_UNKNOWN', True, 1), ('DRAFT_CREATED_NOT_PUBLISHED', True, 1)]:
            with self.subTest(state=state, saved=saved), patch.object(h, 'run', return_value={'publication_state': state, 'audit_saved': saved}), redirect_stdout(io.StringIO()) as out:
                self.assertEqual(h.main([]), expected)
                self.assertEqual(json.loads(out.getvalue())['publication_state'], state)

    def test_cli_has_no_authority_or_generic_uploader_arguments(self):
        self.assertFalse(hasattr(self.client, 'publish'))
        self.assertFalse(hasattr(self.client, 'verify_origin'))
        for args in (['--approved'], ['--actor-id', '13'], ['--token', 'offline-secret'], ['--repository', 'elsewhere/repo'], ['--simulate'], ['--assets', '/tmp']):
            with self.subTest(args=args), patch.object(h, 'run') as run, redirect_stdout(io.StringIO()) as out:
                self.assertEqual(h.main(args), 1)
                run.assert_not_called()
                self.assertNotIn('offline-secret', out.getvalue())

    def test_environment_alone_and_unconfigured_pins_never_authorize(self):
        self.env.pop('HISTORICAL_ARCHIVE_DEPLOYMENT_SHA256')
        self.assert_blocked('DEPLOYMENT_NOT_CONFIGURED_OR_PIN_MISMATCH')

    def test_api_rejects_spoofed_environment_actor(self):
        self.env['GITHUB_ACTOR_ID'] = '99'
        self.assert_blocked('GITHUB_WORKFLOW_ACTOR_MISMATCH')

    def test_unreviewed_checkout_is_blocked_even_with_valid_api(self):
        with patch.object(h, 'PROJECT', self.project), patch.dict(os.environ, self.env, clear=True), \
             patch.object(h, '_Publisher', return_value=self.client), patch.object(h, '_git', side_effect=OSError('no reviewed checkout')):
            result = h.run()
        self.assertEqual(result['publication_state'], 'BLOCKED_BEFORE_PUBLICATION')
        self.assertFalse(self.client.calls)

    def test_subject_deterministic_and_every_binding_changes_digest(self):
        original, digest = h.archival_subject(self.d, self.request, self.prepared['manifest'])
        self.assertEqual((original, digest), h.archival_subject(deepcopy(self.d), deepcopy(self.request), deepcopy(self.prepared['manifest'])))
        for key in ('implementation_revision', 'policy_sha256', 'request_sha256', 'repository_id'):
            d = {**self.d, key: 99 if key == 'repository_id' else '0' * (40 if key == 'implementation_revision' else 64)}
            self.assertNotEqual(h.archival_subject(d, self.request, self.prepared['manifest'])[1], digest)

    def test_strict_configuration_rejects_unknown_duplicate_nan_and_symlink(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.assertRaises(ValueError):
                h._json(raw)
        self.request['unexpected'] = True
        self.refresh()
        self.assert_blocked('INVALID_REQUEST_FIELDS')

    def test_config_symlink_rejected(self):
        path = self.project / self.d['policy_path']
        saved = path.read_bytes()
        path.unlink()
        target = self.f.root / 'policy.json'
        target.write_bytes(saved)
        path.symlink_to(target)
        self.assert_blocked()

    def test_gh_original_zip_download_is_pinned_and_credentials_not_in_command(self):
        # Fake executable produces synthetic bytes only; no GitHub/network calls.
        executable = self.f.root / 'fake-gh'
        source = self.f.root / 'original.zip'
        import sys
        executable.write_text('#!' + sys.executable + '\nimport sys\nfrom pathlib import Path\nsys.stdout.buffer.write(Path(' + repr(str(source)) + ').read_bytes())\n')
        executable.chmod(0o700)
        with patch.object(h.shutil, 'which', return_value=str(executable)), patch.dict(os.environ, {'GH_DEBUG': 'api'}), \
             patch.object(h.subprocess, 'Popen', wraps=subprocess.Popen) as popen:
            h._download(self.client, self.request, self.f.root / 'downloaded.zip')
            command = popen.call_args.args[0]
            env = popen.call_args.kwargs['env']
            self.assertNotIn('offline-secret', ' '.join(command))
            self.assertNotIn('GH_DEBUG', env)
            self.assertEqual(env['GH_TOKEN'], 'offline-secret')
            self.assertFalse(Path(env['GH_CONFIG_DIR']).exists())
        self.assertEqual((self.f.root / 'downloaded.zip').read_bytes(), self.zip_bytes)

    def test_gh_download_rejects_permission_error_and_hash_size_mismatch(self):
        executable = self.f.root / 'fake-gh'
        executable.write_text('#!/bin/sh\nexit 1\n')
        executable.chmod(0o700)
        with patch.object(h.shutil, 'which', return_value=str(executable)):
            with self.assertRaisesRegex(h.HistoricalArchiveError, 'ARTIFACT_DOWNLOAD_FAILED'):
                h._download(self.client, self.request, self.f.root / 'denied.zip')
        executable.write_text('#!/bin/sh\nprintf wrong\n')
        with patch.object(h.shutil, 'which', return_value=str(executable)):
            with self.assertRaisesRegex(h.HistoricalArchiveError, 'ARTIFACT_DOWNLOAD_HASH_MISMATCH'):
                h._download(self.client, self.request, self.f.root / 'wrong.zip')
            request = deepcopy(self.request)
            request['original']['artifact_size'] = 1
            with self.assertRaisesRegex(h.HistoricalArchiveError, 'ARTIFACT_DOWNLOAD_SIZE_MISMATCH'):
                h._download(self.client, request, self.f.root / 'oversized.zip')


class HistoricalWorkflowTests(unittest.TestCase):
    def test_manual_only_pinned_actions_minimal_permissions_no_input_interpolation(self):
        raw = (h.PROJECT / h.WORKFLOW).read_text()
        triggers = raw.split('\non:\n', 1)[1].split('\npermissions:', 1)[0]
        self.assertEqual(re.findall(r'^  ([a-z_]+):', triggers, re.M), ['workflow_dispatch'])
        self.assertEqual(re.findall(r'^      ([a-z0-9_]+):', triggers, re.M), ['archival_subject_sha256'])
        self.assertNotIn('${{ inputs.', raw)
        for action in re.findall(r'uses: ([^\s]+)', raw):
            self.assertRegex(action, r'^actions/[a-z-]+@[0-9a-f]{40}$')
        for text in ('contents: write', 'actions: read', 'persist-credentials: false', 'if: always()', 'retention-days: 30', 'cancel-in-progress: false'):
            self.assertIn(text, raw)
        self.assertEqual(raw.count('secrets.GITHUB_TOKEN'), 1)
        for text in ('id-token:', 'workflows: write', 'git push', 'execute-plan', 'run_local('):
            self.assertNotIn(text, raw)
        for block in re.findall(r'^        run: \|\n((?:          .*\n|\n)+)', raw, re.M):
            code = '\n'.join(line[10:] if line.startswith('          ') else line for line in block.splitlines()) + '\n'
            self.assertEqual(subprocess.run(['bash', '-n'], input=code, text=True, capture_output=True).returncode, 0)
            if "<<'PY'" in code:
                compile(code.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0], h.WORKFLOW, 'exec')


if __name__ == '__main__':
    unittest.main()
