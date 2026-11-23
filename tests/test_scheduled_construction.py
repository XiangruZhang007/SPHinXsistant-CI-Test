"""Real miniature construction/verification; explicit mocked GitHub transport.

None of these contexts, decisions or Releases establishes Hosted authorization.
"""
from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from unittest.mock import patch

import yaml
import test_genuine_continuous_execution as genuine_fixtures
from test_genuine_continuous_execution import write
from test_upstream_provenance import commit
from src import genuine_continuous_execution as g, scheduled_construction as s, continuous_completion as store
from src.corpus_snapshot import digest, file_digest, read_json
from scripts import publish_continuous_candidate as publisher
from scripts import run_continuous_ci_v2 as entry

P = Path(__file__).resolve().parents[1]


class MemoryRelease(store.Client):
    """API-only fixture. Does not claim real GitHub atomicity or durability."""
    def __init__(self, config):
        super().__init__(config['repository'], 'offline-fixture-token')
        self.config = config; self.release = None; self.data = {}; self.mutations = []
        self.fail_upload = None; self.calls = []; self.job_status = 'success'; self.run_id = 401

    def _api(self, method, endpoint, payload=None, *, allow_404=False):
        self.calls.append((method, endpoint))
        if method != 'GET': self.mutations.append((method, endpoint))
        base = '/repos/' + self.repository; cfg = self.config
        if endpoint == base:
            return {'id': cfg['repository_id'], 'full_name': cfg['repository'], 'private': True}
        if '/actions/runs/' in endpoint and '/jobs?' in endpoint:
            jobs = [{'id': 601, 'name': 'continuous-candidate', 'run_id': self.run_id, 'head_sha': cfg['implementation_revision'],
                     'status': 'completed', 'conclusion': self.job_status}]
            return {'total_count': len(jobs), 'jobs': jobs}
        if '/actions/runs/' in endpoint:
            return {'id': self.run_id, 'run_attempt': 1, 'event': getattr(self, 'event', 'workflow_dispatch'),
                    'status': 'in_progress', 'head_sha': cfg['implementation_revision'], 'head_branch': cfg['default_branch'],
                    'path': cfg['workflow_path'], 'repository': {'id': cfg['repository_id'], 'full_name': cfg['repository']},
                    'workflow_id': 501}
        if '/actions/workflows/' in endpoint: return {'id': 501, 'path': cfg['workflow_path']}
        if '/git/ref/tags/' in endpoint: return None
        if method == 'POST' and endpoint == base + '/releases':
            if self.release is not None: raise ValueError('Fixture duplicate release')
            self.release = {**payload, 'id': 701, 'immutable': False, 'assets': [],
                            'upload_url': 'https://uploads.github.com/repos/' + self.repository + '/releases/701/assets{?name,label}'}
            return deepcopy(self.release)
        if method == 'PATCH':
            self.release.update(draft=False, immutable=True); return deepcopy(self.release)
        if '/releases/tags/' in endpoint: return deepcopy(self.release)
        if '/releases/' in endpoint: return deepcopy(self.release)
        raise AssertionError('Unexpected fixture endpoint: ' + endpoint)

    def _upload(self, url, release_id, path):
        if Path(path).name == self.fail_upload: raise ValueError('Simulated upload interruption')
        value = Path(path).read_bytes(); aid = 801 + len(self.data); self.data[aid] = value
        asset = {'id': aid, 'name': Path(path).name, 'state': 'uploaded', 'size': len(value),
                 'digest': 'sha256:' + hashlib.sha256(value).hexdigest()}
        self.release['assets'].append(asset); return deepcopy(asset)

    def request(self, url, *, binary=False, token=None):
        return io.BytesIO(self.data[int(url.rsplit('/', 1)[-1])])


class ScheduledTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = genuine_fixtures.GenuineFormatTests
        cls.harness.setUpClass(); cls.addClassCleanup(cls.harness.doClassCleanups)

    def setUp(self):
        self.fx = self.harness(); self.fx.setUp(); self.addCleanup(self.fx.doCleanups)
        self.root = self.fx.root
        self.client = MemoryRelease(self.fx.config)

    def prepared(self):
        origin = store.origin(self.client, self.fx.config, 401, 1)
        return store.prepare(self.fx.project, self.fx.original, self.root / 'prepared', pins=self.fx.pins,
            transport_sha256=file_digest(self.fx.original / 'candidate.tar.gz'), verified_origin=origin)

    def published(self):
        prepared = self.prepared()
        with patch.object(g.trust, '_request', side_effect=self.client.request):
            result = store.publish(self.fx.project, self.client, self.fx.config, prepared, prefix='fixture-complete')
        return prepared, result

    def schedule(self, *, changes=None, enabled=True):
        """Reviewed local Git checkout + API fixture; no successful gate is mocked."""
        stack = ExitStack(); project = self.root / 'schedule-project'
        subprocess.run(['git', 'clone', '--no-hardlinks', str(self.fx.project), str(project)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        now = datetime.now(timezone.utc)
        policy = {'schema_version': 1, 'operation': s.OPERATION, 'enabled': enabled,
            'repository': self.fx.repo, 'repository_id': self.fx.repo_id,
            'workflow_path': self.fx.config['workflow_path'], 'continuous_policy_sha256': self.fx.config['continuous_policy_sha256'],
            'registry_sha256': self.fx.config['registry_sha256'],
            'valid_from': (now - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'expires_at': (now + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'release_prefix': 'fixture-complete', 'research_approval': 'NOT_GRANTED',
            'production_promotion': 'NOT_AUTHORIZED', 'automatic_registration': False, 'publication_enabled': True,
            **(changes or {})}
        path = project / 'configs/mock-scheduled-policy.json'; write(path, policy)
        head = commit(project)
        config = {**self.fx.config, 'schema_version': 3, 'implementation_revision': head,
                  'build_events': ['workflow_dispatch', 'schedule'], 'scheduled_policy_path': 'configs/mock-scheduled-policy.json',
                  'scheduled_policy_sha256': file_digest(path), 'completion_witness': None}
        self.client.config = config; self.client.event = 'schedule'
        for field, value in (('project', project), ('head', head), ('config', config)):
            stack.enter_context(patch.object(self.harness, field, value))
        endpoint = 'repos/' + self.fx.repo
        stack.enter_context(patch.dict(self.fx.api[endpoint + '/actions/runs/401'], {'event': 'schedule', 'head_sha': head}))
        stack.enter_context(patch.dict(self.fx.api[endpoint + '/git/ref/heads/research']['object'], {'sha': head}))
        stack.enter_context(patch.dict(self.fx.api, {endpoint + '/contents/configs/mock-registry.json?ref=' + head:
            {'path': 'configs/mock-registry.json', 'type': 'file', 'encoding': 'base64',
             'content': base64.b64encode((project / 'configs/mock-registry.json').read_bytes()).decode()}}))
        stack.enter_context(self.fx.boundaries())
        stack.enter_context(patch.dict(os.environ, {'GITHUB_EVENT_NAME': 'schedule',
            'CONTINUOUS_CONSTRUCTION_ENABLED': 'true', 'CONTINUOUS_PUBLICATION_ENABLED': 'true'}))
        stack.enter_context(patch.object(store, 'Client', return_value=self.client))
        self.addCleanup(stack.close)
        return project, config

    def test_actual_scheduled_incremental_full_and_frozen_replays(self):
        project, config = self.schedule()
        result = g.execute(project, self.fx.detection_path, self.root / 'work', self.root / 'out')
        self.assertEqual(result['format'], g.SCHEDULED_FORMAT); self.assertTrue(result['scheduled_execution'])
        self.assertEqual(result['parity'], 'PARITY_PASS'); self.assertEqual(result['independent_replay'], 'VERIFIED')
        self.assertEqual(result['research_approval'], 'NOT_GRANTED'); self.assertEqual(result['trusted_parent_eligibility'], 'NOT_GRANTED')
        self.assertEqual(read_json(self.root / 'out/run/q1-status.json')['status'], 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
        reuse = read_json(self.root / 'out/run/candidate/reuse-summary.json'); self.assertEqual(reuse['re_extracted_files'], 2)
        self.assertGreater(reuse['reused_files'], 0)
        self.assertEqual(len(read_json(self.root / 'out/run/incremental-replay.json')), 128)
        pins = read_json(self.root / 'out/verification-inputs.json')
        self.assertEqual(g.verify_package(project, self.root / 'out/run', **pins)['replay'], 'SEALED_REPLAY_INSPECTED')

    def test_scheduled_scope_is_explicit_and_cannot_change_approval(self):
        project, _ = self.schedule(enabled=False)
        with self.assertRaisesRegex(ValueError, 'INVALID_SCHEDULED_CONSTRUCTION_POLICY'):
            g.execute(project, self.fx.detection_path, self.root / 'work', self.root / 'out')
        self.assertFalse((self.root / 'work').exists())

    def test_expired_scheduled_authorization_rejects_before_storage_or_build(self):
        project, _ = self.schedule(changes={'valid_from': '2000-01-01T00:00:00Z', 'expires_at': '2001-01-01T00:00:00Z'})
        with self.assertRaisesRegex(ValueError, 'SCHEDULED_POLICY_NOT_CURRENT'):
            g.execute(project, self.fx.detection_path, self.root / 'work', self.root / 'out')
        self.assertEqual(self.client.calls, [])

    def test_operational_flags_cannot_be_inferred_from_offline_test_success(self):
        project, _ = self.schedule()
        with patch.dict(os.environ, {'CONTINUOUS_CONSTRUCTION_ENABLED': ''}), self.assertRaisesRegex(ValueError, 'SCHEDULED_OPERATIONAL_ACTIVATION_DISABLED'):
            g.execute(project, self.fx.detection_path, self.root / 'work', self.root / 'out')
        self.assertFalse((self.root / 'work').exists())

    def test_public_repository_is_rejected_before_construction_or_artifact_delivery(self):
        project, _ = self.schedule()
        self.fx.api['repos/' + self.fx.repo]['private'] = False
        with self.assertRaisesRegex(ValueError, 'GITHUB_REPOSITORY_IDENTITY_MISMATCH'):
            g.execute(project, self.fx.detection_path, self.root / 'work', self.root / 'out')
        self.assertFalse((self.root / 'work').exists()); self.assertFalse((self.root / 'out').exists())

    def test_scheduled_completed_duplicate_skips_only_with_independent_witness(self):
        project, config = self.schedule()
        delivery = self.root / 'scheduled'
        g.execute(project, self.fx.detection_path, self.root / 'work', delivery)
        prepared = store.prepare(project, delivery, self.root / 'prepared', pins=read_json(delivery / 'verification-inputs.json'),
            transport_sha256=file_digest(delivery / 'candidate.tar.gz'), verified_origin=store.origin(self.client, config, 401, 1))
        with patch.object(g.trust, '_request', side_effect=self.client.request):
            published = store.publish(project, self.client, config, prepared, prefix='fixture-complete')
            with self.assertRaisesRegex(ValueError, 'INDEPENDENT_COMPLETION_WITNESS_REQUIRED'):
                g.execute(project, self.fx.detection_path, self.root / 'retry-work', self.root / 'retry')
            self.assertFalse((self.root / 'retry-work').exists())
            # Explicitly independent test deployment witness, never copied into a
            # real deployment or inferred from Candidate metadata by the executor.
            pinned = {**config, 'completion_witness': {'execution_key': published['execution_key'],
                                                      'receipt_sha256': prepared['receipt_sha256']}}
            raw = json.dumps(pinned, sort_keys=True)
            with patch.dict(os.environ, {'CONTINUOUS_BUILD_DEPLOYMENT_JSON': raw,
                    'CONTINUOUS_BUILD_DEPLOYMENT_SHA256': hashlib.sha256(raw.encode()).hexdigest()}):
                result = g.execute(project, self.fx.detection_path, self.root / 'retry-work', self.root / 'retry')
            self.assertEqual(result['status'], 'NO_BUILD')
            self.assertFalse((self.root / 'retry-work').exists())

    def test_draft_reservation_does_not_suppress_retry_build(self):
        project, config = self.schedule()
        observed = g.preflight(project, self.fx.detection_path)
        key = observed['authority_observation']['parent_comparison']['execution_key']
        self.client.release = {'id': 701, 'draft': True, 'immutable': False,
                               'tag_name': store.tag('fixture-complete', key), 'assets': []}
        result = g.execute(project, self.fx.detection_path, self.root / 'retry-work', self.root / 'retry')
        self.assertEqual(result['status'], 'GENUINE_CONTINUOUS_CANDIDATE_BUILT')
        self.assertEqual(self.client.mutations, [])

    def test_workflow_mutex_checked_before_durable_lookup_and_build(self):
        project, _ = self.schedule(); events = []
        actual_mutex, actual_api = s.mutex, self.client._api
        def mutex(*args): events.append('mutex'); return actual_mutex(*args)
        def api(*args, **kwargs): events.append('lookup'); return actual_api(*args, **kwargs)
        with patch.object(s, 'mutex', side_effect=mutex), patch.object(self.client, '_api', side_effect=api):
            result = g.preflight(project, self.fx.detection_path)
        self.assertEqual(events[:2], ['mutex', 'lookup']); self.assertFalse(result['execute_candidate'])
        self.assertEqual(result['completion_observation']['state'], 'NOT_STARTED')

    def test_prepare_manifest_and_receipt_are_deterministic(self):
        first = self.prepared()
        second = store.prepare(self.fx.project, self.fx.original, self.root / 'other', pins=self.fx.pins,
            transport_sha256=file_digest(self.fx.original / 'candidate.tar.gz'), verified_origin=first['manifest']['build_origin'])
        self.assertEqual(first['receipt_sha256'], second['receipt_sha256'])
        self.assertEqual(first['manifest'], second['manifest'])
        self.assertEqual(first['receipt']['state'], 'BUILD_VERIFIED')

    def test_same_run_publication_verifies_finished_build_not_whole_workflow(self):
        prepared, result = self.published()
        self.assertEqual(result['state'], 'PUBLISHED_AND_VERIFIED')
        self.assertTrue(self.client.release['immutable']); self.assertFalse(self.client.release['draft'])
        self.assertEqual(result['receipt_sha256'], prepared['receipt_sha256'])
        self.assertEqual(result['production_promotion'], 'NOT_AUTHORIZED')

    def test_completed_duplicate_requires_external_witness_and_full_verification(self):
        prepared, result = self.published(); key = result['execution_key']; before = list(self.client.mutations)
        with self.assertRaisesRegex(ValueError, 'INDEPENDENT_COMPLETION_WITNESS_REQUIRED'):
            store.lookup(self.fx.project, self.client, self.fx.config, 'fixture-complete', key)
        with patch.object(g.trust, '_request', side_effect=self.client.request):
            checked = store.lookup(self.fx.project, self.client, self.fx.config, 'fixture-complete', key,
                                   expected_receipt_sha256=prepared['receipt_sha256'])
        self.assertEqual(checked['state'], 'PUBLISHED_AND_VERIFIED'); self.assertEqual(before, self.client.mutations)

    def test_wrong_completion_witness_and_corrupt_asset_are_rejected(self):
        prepared, result = self.published()
        with patch.object(g.trust, '_request', side_effect=self.client.request):
            with self.assertRaises(ValueError):
                store.lookup(self.fx.project, self.client, self.fx.config, 'fixture-complete', result['execution_key'],
                             expected_receipt_sha256='0' * 64)
            aid = next(a['id'] for a in self.client.release['assets'] if a['name'] == 'candidate.tar.gz')
            self.client.data[aid] = self.client.data[aid][:-1] + b'!'
            with self.assertRaisesRegex(ValueError, 'COMPLETION_ASSET_HASH_MISMATCH'):
                store.lookup(self.fx.project, self.client, self.fx.config, 'fixture-complete', result['execution_key'],
                             expected_receipt_sha256=prepared['receipt_sha256'])

    def test_failed_cancelled_or_skipped_build_is_not_publication_authority(self):
        for state in ('failure', 'cancelled', 'skipped', None):
            self.client.job_status = state
            with self.subTest(state=state), self.assertRaisesRegex(ValueError, 'BUILD_JOB_NOT_SUCCESSFUL'):
                store.origin(self.client, self.fx.config, 401, 1)
        self.assertEqual(self.client.mutations, [])

    def test_ambiguous_missing_or_mismatched_build_jobs_are_rejected(self):
        original = self.client._api
        good = {'id': 601, 'name': 'continuous-candidate', 'run_id': 401,
                'head_sha': self.fx.config['implementation_revision'], 'status': 'completed', 'conclusion': 'success'}
        for rows in ([], [good, good], [{**good, 'run_id': 999}], [{**good, 'head_sha': '0' * 40}],
                     [{**good, 'status': 'in_progress'}]):
            def response(method, endpoint, *args, **kwargs):
                if '/jobs?' in endpoint: return {'total_count': len(rows), 'jobs': rows}
                return original(method, endpoint, *args, **kwargs)
            with self.subTest(rows=rows), patch.object(self.client, '_api', side_effect=response), self.assertRaises(ValueError):
                store.origin(self.client, self.fx.config, 401, 1)
        self.assertEqual(self.client.mutations, [])

    def test_source_changes_during_scheduled_construction_cannot_emit_candidate(self):
        project, _ = self.schedule(); assemble = g.v1._assemble
        def mutate(*args):
            result = assemble(*args)
            (Path(args[3]) / 'repos/SPHinXsys/src/a.cpp').write_text('uncommitted alteration\n')
            return result
        with patch.object(g.v1, '_assemble', side_effect=mutate), self.assertRaises(ValueError):
            g.execute(project, self.fx.detection_path, self.root / 'work', self.root / 'out')
        self.assertFalse((self.root / 'out').exists()); self.assertEqual(self.client.mutations, [])

    def test_cancelled_run_cannot_finish_after_losing_its_workflow_context(self):
        project, _ = self.schedule(); assemble = g.v1._assemble
        def cancel(*args):
            result = assemble(*args)
            self.fx.api['repos/' + self.fx.repo + '/actions/runs/401'].update(status='completed', conclusion='cancelled')
            return result
        with patch.object(g.v1, '_assemble', side_effect=cancel), self.assertRaises(ValueError):
            g.execute(project, self.fx.detection_path, self.root / 'work', self.root / 'out')
        self.assertFalse((self.root / 'out').exists()); self.assertEqual(self.client.mutations, [])

    def test_partial_upload_is_not_completed_and_draft_is_not_duplicate(self):
        prepared = self.prepared(); self.client.fail_upload = 'release-manifest.json'
        with self.assertRaises(ValueError): store.publish(self.fx.project, self.client, self.fx.config, prepared, prefix='fixture-complete')
        self.assertTrue(self.client.release['draft'])
        checked = store.lookup(self.fx.project, self.client, self.fx.config, 'fixture-complete', prepared['manifest']['execution_key'])
        self.assertEqual(checked['state'], 'PUBLISHING')
        self.assertFalse(any(m == 'PATCH' for m, _ in self.client.mutations))

    def test_completed_publication_is_not_overwritten_on_repeated_request(self):
        prepared, _ = self.published(); before = list(self.client.mutations)
        with self.assertRaises(ValueError): store.publish(self.fx.project, self.client, self.fx.config, prepared, prefix='fixture-complete')
        self.assertEqual(before, self.client.mutations)

    def test_read_only_recovery_after_publication_is_idempotent(self):
        prepared, result = self.published(); before = list(self.client.mutations)
        with patch.object(g.trust, '_request', side_effect=self.client.request):
            for _ in range(2):
                recovered = store.verify_completed(self.fx.project, self.client, self.fx.config, self.client.release,
                    result['execution_key'], expected_receipt_sha256=prepared['receipt_sha256'])
                self.assertEqual(recovered, result)
        self.assertEqual(before, self.client.mutations)

    def test_permission_denial_and_corrupt_transport_fail_without_mutation(self):
        with patch.object(self.client, '_api', side_effect=ValueError('Denied')), self.assertRaises(ValueError):
            store.origin(self.client, self.fx.config, 401, 1)
        with self.assertRaises(ValueError):
            store.prepare(self.fx.project, self.fx.original, self.root / 'bad', pins=self.fx.pins,
                transport_sha256='0' * 64, verified_origin={})
        self.assertFalse((self.root / 'bad').exists()); self.assertEqual(self.client.mutations, [])

    def test_workflow_permissions_and_defaults_preserve_the_boundaries(self):
        doc = yaml.safe_load((P / '.github/workflows/upstream_refresh.yml').read_text())
        self.assertEqual(doc['concurrency']['cancel-in-progress'], False)
        self.assertEqual(doc['permissions'], {'contents': 'read'})
        writers = [name for name, job in doc['jobs'].items() if job.get('permissions', {}).get('contents') == 'write']
        self.assertEqual(writers, ['publish-continuous-candidate'])
        job = doc['jobs']['publish-continuous-candidate']
        self.assertIn("vars.CONTINUOUS_PUBLICATION_ENABLED == 'true'", job['if'])
        self.assertIn("outputs.candidate_built == 'true'", job['if'])
        for section in (doc['jobs']['continuous-candidate'], job):
            for step in section['steps']:
                if 'run' in step:
                    self.assertEqual(subprocess.run(['bash', '-n'], input=step['run'], text=True, capture_output=True).returncode, 0)

    def test_publisher_cli_missing_independent_deployment_is_blocked(self):
        out = io.StringIO()
        with patch.dict(os.environ, {'CONTINUOUS_BUILD_DEPLOYMENT_JSON': ''}), redirect_stdout(out):
            code = publisher.main(['--output', str(self.root / 'publication')])
        self.assertEqual(code, 1); self.assertEqual(json.loads(out.getvalue())['status'], 'BLOCKED')
        self.assertNotIn('token', out.getvalue())

    def test_failed_job_output_write_emits_only_one_blocked_json(self):
        stdout = io.StringIO()
        with (self.fx.boundaries(), patch.object(entry, 'P', self.fx.project), redirect_stdout(stdout),
              patch.dict(os.environ, {'GITHUB_OUTPUT': str(self.root)})):
            code = entry.main(['--detection', str(self.fx.detection_path), '--work', str(self.root / 'work'),
                               '--output', str(self.root / 'out')])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(stdout.getvalue())['status'], 'BLOCKED')
        # A real verified miniature package may exist, but a failed job cannot
        # publish it and stdout must not also announce successful handoff.
        self.assertTrue((self.root / 'out/candidate.tar.gz').is_file())

    def build_zip(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            for path in self.fx.original.rglob('*'):
                if path.is_file(): archive.write(path, path.relative_to(self.fx.original).as_posix())
        return data.getvalue()

    def artifact_api(self, payload, **changes):
        api = self.client._api
        asset = {'id': 901, 'name': 'ci-v2-continuous-401-1', 'expired': False, 'size_in_bytes': len(payload),
                 'digest': 'sha256:' + hashlib.sha256(payload).hexdigest(),
                 'workflow_run': {'id': 401, 'repository_id': self.fx.repo_id, 'head_sha': self.fx.config['implementation_revision']},
                 **changes}
        def get(method, endpoint, *args, **kwargs):
            if '/artifacts?' in endpoint: return {'total_count': 1, 'artifacts': [asset]}
            return api(method, endpoint, *args, **kwargs)
        return get

    def test_original_artifact_zip_binding_and_actual_safe_extraction(self):
        from src import historical_candidate_archive as historical
        payload = self.build_zip()
        def download(client, request, destination): destination.write_bytes(payload)
        with patch.object(self.client, '_api', side_effect=self.artifact_api(payload)), patch.object(historical, '_download', side_effect=download):
            _, artifact = store.retrieve_build(self.client, self.fx.config, 401, 1, self.root / 'downloaded')
        self.assertEqual(artifact['artifact_sha256'], hashlib.sha256(payload).hexdigest())
        self.assertEqual(g.v1._files(self.root / 'downloaded'), g.v1._files(self.fx.original))

    def test_expired_mismatched_corrupt_and_unsafe_artifact_rejected(self):
        from src import historical_candidate_archive as historical
        payload = self.build_zip()
        for index, changes in enumerate(({'expired': True}, {'name': 'wrong-attempt-2'},
                {'workflow_run': {'id': 999}}, {'digest': None})):
            with patch.object(self.client, '_api', side_effect=self.artifact_api(payload, **changes)), self.assertRaises(ValueError):
                store.retrieve_build(self.client, self.fx.config, 401, 1, self.root / ('bad-' + str(index)))
        def bad_download(client, request, destination): destination.write_bytes(payload[:-1])
        with (patch.object(self.client, '_api', side_effect=self.artifact_api(payload)),
              patch.object(historical, '_download', side_effect=bad_download),
              self.assertRaisesRegex(ValueError, 'ORIGINAL_BUILD_ZIP_HASH_MISMATCH')):
            store.retrieve_build(self.client, self.fx.config, 401, 1, self.root / 'corrupt')
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive: archive.writestr('../escape', b'unsafe')
        unsafe = data.getvalue()
        def unsafe_download(client, request, destination): destination.write_bytes(unsafe)
        with (patch.object(self.client, '_api', side_effect=self.artifact_api(unsafe)),
              patch.object(historical, '_download', side_effect=unsafe_download), self.assertRaises(ValueError)):
            store.retrieve_build(self.client, self.fx.config, 401, 1, self.root / 'unsafe')
        self.assertFalse((self.root / 'escape').exists())


class PreflightRuntimeTests(unittest.TestCase):
    """Offline runtime probes, not a clean Hosted runner acceptance claim."""

    def job(self):
        return yaml.safe_load((P / '.github/workflows/upstream_refresh.yml').read_text())['jobs']['continuous-schedule-preflight']

    def test_prepared_interpreter_imports_real_entry_without_inherited_pythonpath(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith('PYTHON')}
        env.update(PYTHONDONTWRITEBYTECODE='1', PYTHONHASHSEED='0')
        result = subprocess.run([str(P / 'tools/treesitter-chunker/.venv/bin/python'), '-B',
                                 'scripts/run_continuous_ci_v2.py', '--help'], cwd=P, env=env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--preflight-only', result.stdout)

    def test_real_workflow_shell_records_missing_authority_without_work_or_secrets(self):
        shell = next(step['run'] for step in self.job()['steps']
                     if 'scripts/run_continuous_ci_v2.py' in step.get('run', ''))
        with tempfile.TemporaryDirectory(prefix='preflight runtime ') as tmp:
            env = {**os.environ, 'RUNNER_TEMP': tmp, 'PYTHONPATH': '',
                   'CONTINUOUS_BUILD_DEPLOYMENT_JSON': '', 'CONTINUOUS_BUILD_DEPLOYMENT_SHA256': '',
                   'GH_TOKEN': 'offline-secret-must-not-appear'}
            result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', shell], cwd=P,
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            receipt = read_json(Path(tmp) / 'continuous-result/failure.json')
            self.assertEqual(receipt['reason'], 'CONTINUOUS_DEPLOYMENT_NOT_CONFIGURED')
            self.assertEqual(json.loads(result.stdout), receipt)
            self.assertFalse(receipt['execute_candidate'])
            self.assertFalse((Path(tmp) / 'continuous-work').exists())
            self.assertNotIn(env['GH_TOKEN'], result.stdout + result.stderr + json.dumps(receipt))

    def test_runtime_setup_failure_stops_before_entry_and_does_not_report_success(self):
        job = self.job()
        runtime = next(step for step in job['steps'] if step.get('name') == 'Prepare pinned extraction runtime')
        self.assertNotIn('continue-on-error', runtime)
        with tempfile.TemporaryDirectory(prefix='preflight-setup-failure-') as tmp:
            root = Path(tmp); stub = root / 'git'
            stub.write_text('#!/bin/sh\nexit 37\n'); stub.chmod(0o755)
            marker = root / 'unexpected-entry'
            result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c',
                                     runtime['run'] + '\nprintf unexpected > "$ENTRY_MARKER"\n'],
                                    cwd=root, env={**os.environ, 'PATH': str(root) + os.pathsep + os.defpath,
                                                   'ENTRY_MARKER': str(marker)}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 37)
            self.assertFalse(marker.exists())
            self.assertFalse((root / 'continuous-result').exists())

    def test_only_preflight_job_changed_and_frozen_runtime_selection_is_preserved(self):
        current = yaml.safe_load((P / '.github/workflows/upstream_refresh.yml').read_text())
        original = yaml.safe_load(subprocess.check_output(
            ['git', 'show', '092d4f8aa6cfec53bcbbb669b66f197327352062:.github/workflows/upstream_refresh.yml'],
            cwd=P, text=True))
        job = current['jobs'].pop('continuous-schedule-preflight')
        original['jobs'].pop('continuous-schedule-preflight')
        # The six reviewed manual-only guards preserve the historical schedule payload.
        legacy = {'Clone upstream source repositories', 'Clone pinned treesitter-chunker',
                  'Install isolated chunk-generation runtime', 'Generate candidate corpus',
                  'Run deterministic retrieval regression', 'Upload candidate refresh artifacts'}
        guard = "${{ !(github.event_name == 'workflow_dispatch' && inputs.build_continuous_ci_v2 && !inputs.build_ci_v2) }}"
        guarded = [s for s in current['jobs']['candidate-refresh']['steps'] if s['name'] in legacy]
        self.assertEqual({s['name'] for s in guarded}, legacy)
        for step in guarded:
            self.assertEqual(step.pop('if', None), guard)
        self.assertEqual(current, original)
        self.assertEqual(job['permissions'], {'contents': 'read', 'actions': 'read'})
        self.assertEqual(job['runs-on'], 'ubuntu-24.04-arm')
        setup = next(step for step in job['steps'] if step.get('name') == 'Select exact frozen interpreter')
        self.assertEqual(setup['with'], {'python-version': '3.12.3', 'architecture': 'arm64'})


if __name__ == '__main__': unittest.main()
