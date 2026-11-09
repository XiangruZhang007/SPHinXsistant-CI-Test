"""Isolated Actions transport tests. All GitHub requests are mocked."""
from copy import deepcopy
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib

from src import github_artifact_delivery as delivery
from src import corpus_update_integration as integration
from src.corpus_switching_test_session import TestWorkspace
from test_update_eligibility_gate import fixture, put


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        run = self.root / 'run'
        run.mkdir()

        def put_jsonl(root, name, value):
            if name.endswith('/corpus.jsonl'):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value) + '\n')
            else:
                put(root, name, value)

        with patch('test_update_eligibility_gate.put', side_effect=put_jsonl):
            fixture(run)
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
            for path in sorted(run.rglob('*')):
                if path.is_file():
                    z.write(path, 'run/' + path.relative_to(run).as_posix())
        self.raw = archive.getvalue()
        self.digest = hashlib.sha256(self.raw).hexdigest()
        self.head = 'a' * 40
        self.run = {
            'id': 123, 'run_attempt': 2, 'head_sha': self.head,
            'repository': {'id': 10, 'full_name': delivery.REPOSITORY},
            'head_repository': {'id': 10, 'full_name': delivery.REPOSITORY},
            'path': delivery.WORKFLOW, 'event': 'workflow_dispatch',
            'status': 'completed', 'conclusion': 'success',
            'run_started_at': '2026-11-01T12:00:00Z', 'updated_at': '2026-11-01T12:10:00Z',
        }
        self.artifact = {
            'id': 99, 'name': 'ci-v2-research-123-2', 'expired': False,
            'size_in_bytes': len(self.raw), 'digest': 'sha256:' + self.digest,
            'created_at': '2026-11-01T12:09:00Z',
            'workflow_run': {'id': 123, 'repository_id': 10, 'head_repository_id': 10,
                             'head_sha': self.head},
        }
        self.artifacts = [self.artifact]
        self.downloads = []
        self.api = []
        for target, options in (
            ('shutil.which', {'return_value': '/mock/gh'}),
            ('GitHub.json', {'side_effect': self.response}),
            ('GitHub.download', {'side_effect': self.download}),
            ('integration._load_gradio', {'side_effect': AssertionError('P8 must prevent loading')}),
            ('subprocess.run', {'side_effect': AssertionError('No real remote requests in tests')}),
        ):
            context = patch('src.github_artifact_delivery.' + target, **options)
            context.start()
            self.addCleanup(context.stop)

    def response(self, endpoint):
        self.api.append(endpoint)
        if endpoint == f'repos/{delivery.REPOSITORY}/actions/runs/123/attempts/2':
            return deepcopy(self.run)
        prefix = f'repos/{delivery.REPOSITORY}/actions/runs/123/artifacts?per_page=100&page='
        self.assertTrue(endpoint.startswith(prefix), endpoint)
        page = int(endpoint.removeprefix(prefix))
        return {'total_count': len(self.artifacts), 'artifacts': deepcopy(self.artifacts[(page-1)*100:page*100])}

    def download(self, artifact_id, path):
        self.assertEqual(artifact_id, 99)
        self.downloads.append(path)
        path.write_bytes(self.raw)

    def execute(self, **overrides):
        args = {'repository': delivery.REPOSITORY, 'run_id': 123, 'attempt': 2,
                'artifact_name': 'ci-v2-research-123-2', 'evidence_root': self.root / 'receipts'}
        args.update(overrides)
        result = delivery.deliver(**args)
        self.assertEqual(result['decision'], 'BLOCKED')
        self.assertEqual(result['activation'], 'DENIED')
        self.assertEqual(result['gradio_reinitialization'], 'NOT_ATTEMPTED')
        self.assertEqual(result['production_promotion'], 'NOT_AUTHORIZED')
        self.assertTrue(result['temporary_download_removed'])
        for path in self.downloads:
            self.assertFalse(path.parent.exists())
        receipt = Path(result['evidence_directory'])
        self.assertEqual(json.loads((receipt / 'delivery-result.json').read_text()), result)
        for line in (receipt / 'SHA256SUMS').read_text().splitlines():
            digest, name = line.split('  ')
            self.assertEqual(hashlib.sha256((receipt / name).read_bytes()).hexdigest(), digest)
        return result

    def test_delivery_uses_original_zip_and_real_integration_gate(self):
        original = integration.run
        seen = []

        def inspect(path):
            seen.append(path.read_bytes())
            return original(path)

        with patch.object(integration, 'run', side_effect=inspect):
            result = self.execute()
        self.assertEqual(seen, [self.raw])
        self.assertEqual(result['delivery'], 'VERIFIED')
        self.assertEqual(result['internal_artifact_integrity'], 'PASS')
        self.assertEqual(result['artifact_sha256'], self.digest)
        self.assertEqual(result['p8_decision'], 'BLOCKED')
        self.assertTrue(result['selection_unchanged'])
        self.assertIn('RELEASE_AUTHORIZATION_UNAVAILABLE', str(result['p8_reasons']))
        saved = json.loads((Path(result['evidence_directory']) / 'integration-result.json').read_text())
        self.assertEqual(saved['registration']['status'], 'STORED')
        self.assertTrue(saved['temporary_store_removed'])

    def test_wrong_repository_rejected_before_network_or_writes(self):
        with self.assertRaisesRegex(delivery.DeliveryError, 'allowlist'):
            self.execute(repository='another-owner/another-repository')
        self.assertEqual(self.api, [])
        self.assertFalse((self.root / 'receipts').exists())

    def test_wrong_name_and_invalid_numbers_rejected_before_network(self):
        for override in ({'artifact_name': 'other'}, {'run_id': -1}, {'attempt': 0}, {'run_id': True}):
            with self.subTest(override=override), self.assertRaises(delivery.DeliveryError):
                self.execute(**override)
        self.assertEqual(self.api, [])

    def test_wrong_run_attempt_repo_or_workflow_response_rejected(self):
        for key, value in (('id', 456), ('run_attempt', 1), ('path', 'other.yml'),
                           ('event', 'push'), ('status', 'in_progress')):
            original = self.run[key]
            with self.subTest(key=key):
                self.run[key] = value
                self.assertEqual(self.execute()['delivery'], 'FAILED')
                self.run[key] = original
        self.run['repository']['full_name'] = 'another-owner/another-repository'
        self.assertEqual(self.execute()['delivery'], 'FAILED')
        self.assertEqual(self.downloads, [])

    def test_fork_head_repository_is_rejected(self):
        self.run['head_repository']['id'] = 11
        self.assertEqual(self.execute()['delivery'], 'FAILED')
        self.assertEqual(self.downloads, [])

    def test_wrong_artifact_workflow_bindings_rejected(self):
        for key, value in (('id', 456), ('repository_id', 11), ('head_repository_id', 11), ('head_sha', 'b'*40)):
            original = self.artifact['workflow_run'][key]
            with self.subTest(key=key):
                self.artifact['workflow_run'][key] = value
                self.assertEqual(self.execute()['delivery'], 'FAILED')
                self.artifact['workflow_run'][key] = original
        self.assertEqual(self.downloads, [])

    def test_wrong_attempt_name_or_upload_time_rejected(self):
        self.artifact['name'] = 'ci-v2-research-123-1'
        self.assertEqual(self.execute()['delivery'], 'FAILED')
        self.artifact['name'] = 'ci-v2-research-123-2'
        for created in ('2026-11-01T11:59:59Z', '2026-11-01T12:10:01Z'):
            self.artifact['created_at'] = created
            self.assertEqual(self.execute()['delivery'], 'FAILED')
        self.assertEqual(self.downloads, [])

    def test_missing_expired_or_duplicate_artifact_rejected(self):
        self.artifacts = []
        self.assertEqual(self.execute()['delivery'], 'FAILED')
        self.artifacts = [self.artifact]
        self.artifact['expired'] = True
        self.assertEqual(self.execute()['delivery'], 'FAILED')
        self.artifact['expired'] = False
        self.artifacts.append(deepcopy(self.artifact))
        self.assertEqual(self.execute()['delivery'], 'FAILED')
        self.assertEqual(self.downloads, [])

    def test_pagination_checks_all_exact_matches(self):
        self.artifacts = [dict(self.artifact, id=i+100, name=f'other-{i}') for i in range(100)] + [self.artifact]
        self.assertEqual(self.execute()['delivery'], 'VERIFIED')
        self.assertTrue(any('page=2' in e for e in self.api))
        self.artifacts[0] = deepcopy(self.artifact)
        self.assertEqual(self.execute()['delivery'], 'FAILED')

    def test_unavailable_gh_does_not_login_or_request_credentials(self):
        with patch('src.github_artifact_delivery.shutil.which', return_value=None):
            self.assertEqual(self.execute()['delivery'], 'FAILED')
        self.assertEqual(self.api, [])

    def test_metadata_or_download_failure_has_no_fallback_and_cleans(self):
        with patch.object(delivery.GitHub, 'json', side_effect=delivery.DeliveryError('GITHUB_UNAVAILABLE')):
            self.assertEqual(self.execute()['delivery'], 'FAILED')

        def fail(artifact_id, path):
            self.download(artifact_id, path)
            raise OSError('https://signed-download.example/SECRET')

        with patch.object(delivery.GitHub, 'download', side_effect=fail):
            result = self.execute()
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertEqual(result['delivery'], 'FAILED')

    def test_independent_sha_required_when_github_digest_missing(self):
        del self.artifact['digest']
        self.assertEqual(self.execute()['delivery'], 'FAILED')
        self.assertEqual(self.execute(expected_sha256=self.digest)['delivery'], 'VERIFIED')

    def test_invalid_or_conflicting_pins_rejected(self):
        with self.assertRaises(delivery.DeliveryError):
            self.execute(expected_sha256='not-a-sha')
        self.assertEqual(self.execute(expected_sha256='0'*64)['delivery'], 'FAILED')
        self.artifact['digest'] = 'sha256:not-a-sha'
        self.assertEqual(self.execute()['delivery'], 'FAILED')
        self.assertEqual(self.downloads, [])

    def test_download_digest_or_size_mismatch_prevents_integration(self):
        with patch.object(integration, 'run') as run:
            self.artifact['digest'] = 'sha256:' + '0'*64
            self.assertEqual(self.execute()['delivery'], 'FAILED')
            self.artifact['digest'] = 'sha256:' + self.digest
            self.artifact['size_in_bytes'] += 1
            self.assertEqual(self.execute()['delivery'], 'FAILED')
        run.assert_not_called()

    def replace_zip(self, raw):
        self.raw = raw
        self.artifact.update(size_in_bytes=len(raw), digest='sha256:' + hashlib.sha256(raw).hexdigest())

    def test_corrupted_zip_rejected_even_with_matching_transport_digest(self):
        self.replace_zip(b'not a zip')
        with patch.object(integration, 'run') as run:
            self.assertEqual(self.execute()['delivery'], 'FAILED')
        run.assert_not_called()

    def test_unsafe_zip_rejected_without_extraction(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr('../escape', 'unsafe')
        self.replace_zip(archive.getvalue())
        with patch.object(integration, 'run') as run:
            self.assertEqual(self.execute()['delivery'], 'FAILED')
        run.assert_not_called()
        self.assertFalse((self.root / 'escape').exists())

    def test_zip_crc_failure_and_size_limits_rejected(self):
        with patch.object(zipfile.ZipFile, 'testzip', return_value='run/bad'):
            self.assertEqual(self.execute()['delivery'], 'FAILED')
        with patch.object(delivery, 'MAX_EXPANDED_BYTES', 1):
            self.assertEqual(self.execute()['delivery'], 'FAILED')
        self.artifact['size_in_bytes'] = delivery.MAX_ZIP_BYTES + 1
        self.assertEqual(self.execute()['delivery'], 'FAILED')

    def test_malformed_metadata_and_deflate_errors_fail_closed(self):
        with patch.object(delivery.GitHub, 'json', return_value={}):
            self.assertEqual(self.execute()['delivery'], 'FAILED')
        with patch.object(delivery.GitHub, 'json', side_effect=json.JSONDecodeError('bad', '', 0)):
            self.assertEqual(self.execute()['delivery'], 'FAILED')
        with patch.object(zipfile.ZipFile, 'testzip', side_effect=zlib.error('corrupted deflate stream')):
            self.assertEqual(self.execute()['delivery'], 'FAILED')

    def test_transport_success_does_not_claim_internal_provenance_success(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, 'w') as z:
            z.writestr('run/checksums.json', '{}')
        self.replace_zip(archive.getvalue())
        result = self.execute()
        self.assertEqual(result['delivery'], 'VERIFIED')
        self.assertEqual(result['internal_artifact_integrity'], 'FAIL')
        self.assertIsNone(result['candidate_id'])

    def test_p8_blocked_preserves_existing_selection(self):
        with TestWorkspace() as workspace:
            raw = b'{"chunk_id":"previous"}\n'
            integration._register(workspace, 'previous', raw, hashlib.sha256(raw).hexdigest())
            workspace.switch('previous')
            before = workspace.current()
            with patch.object(integration, 'TestWorkspace', return_value=workspace):
                result = self.execute()
            self.assertTrue(result['selection_unchanged'])
            saved = json.loads((Path(result['evidence_directory']) / 'integration-result.json').read_text())
            self.assertEqual(saved['selection_before'], before)
            self.assertEqual(saved['selection_after'], before)

    def test_integration_failure_cleans_download_and_preserves_transport_receipt(self):
        with patch.object(integration, 'run', side_effect=RuntimeError('SECRET')):
            result = self.execute()
        self.assertEqual(result['delivery'], 'VERIFIED')
        self.assertEqual(result['p8_decision'], 'NOT_EVALUATED')
        self.assertNotIn('SECRET', json.dumps(result))

    def test_cli_json_and_blocked_exit_not_a_transport_failure(self):
        original = delivery.deliver

        def isolated(*args, **kwargs):
            kwargs['evidence_root'] = self.root / 'receipts'
            return original(*args, **kwargs)

        output = io.StringIO()
        with patch.object(delivery, 'deliver', side_effect=isolated), redirect_stdout(output):
            code = delivery.main(['--repository', delivery.REPOSITORY, '--run-id', '123',
                                  '--attempt', '2', '--artifact-name', 'ci-v2-research-123-2'])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(result['delivery'], 'VERIFIED')
        self.assertEqual(result['p8_decision'], 'BLOCKED')
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(delivery.main([]), 1)
        self.assertEqual(json.loads(output.getvalue())['decision'], 'BLOCKED')


class GhAdapterTests(unittest.TestCase):
    def test_uses_existing_auth_raw_zip_and_suppresses_sensitive_stderr(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(delivery.shutil, 'which', return_value='/mock/gh'):
            client = delivery.GitHub()
            path = Path(temporary) / 'download.zip'

            def write(command, **kwargs):
                self.assertIn('--hostname', command)
                self.assertIn('github.com', command)
                self.assertEqual(command[-1], f'repos/{delivery.REPOSITORY}/actions/artifacts/99/zip')
                self.assertNotIn('token', command)
                kwargs['stdout'].write(b'original ZIP')
                return subprocess.CompletedProcess(command, 0)

            with patch.object(delivery.subprocess, 'run', side_effect=write):
                client.download(99, path)
            self.assertEqual(path.read_bytes(), b'original ZIP')
            with patch.object(delivery.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, stderr=b'SECRET')):
                with self.assertRaisesRegex(delivery.DeliveryError, 'GITHUB_UNAVAILABLE') as caught:
                    client.json(f'repos/{delivery.REPOSITORY}/actions/runs/123')
            self.assertNotIn('SECRET', str(caught.exception))
            with patch.object(delivery.subprocess, 'run', side_effect=subprocess.TimeoutExpired('gh', 30)):
                with self.assertRaises(delivery.DeliveryError):
                    client.json(f'repos/{delivery.REPOSITORY}/actions/runs/123')


if __name__ == '__main__':
    unittest.main()
