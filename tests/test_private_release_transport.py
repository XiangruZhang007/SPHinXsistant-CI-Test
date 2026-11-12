"""Private GitHub Release transport tests use mocked API and redirect responses."""
from email.message import Message
import io
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

from src import ci_v2_research as c, trusted_snapshot as t


class PrivateReleaseTransportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = b'private immutable baseline transport fixture'
        self.sha = c.hashlib.sha256(self.data).hexdigest()
        self.token = 'fixture-token-must-never-appear-in-logs'
        self.repo = {'id': 99001, 'full_name': 'research-owner/research-ci', 'private': True}
        self.storage = {'kind': t.PRIVATE_RELEASE_KIND, 'repository': self.repo['full_name'],
            'repository_id': self.repo['id'], 'release_id': 4567, 'asset_id': 8910,
            'tag': 'c1-parent-approved-2026', 'asset_name': 'c1-parent.tar.gz',
            'asset_size': len(self.data), 'immutable_required': True}
        self.release = {'id': self.storage['release_id'], 'tag_name': self.storage['tag'],
            'immutable': True, 'draft': False, 'assets': [{'id': self.storage['asset_id'],
            'name': self.storage['asset_name'], 'size': len(self.data), 'state': 'uploaded'}]}
        self.asset = {'id': self.storage['asset_id'], 'name': self.storage['asset_name'],
            'size': len(self.data), 'state': 'uploaded', 'digest': 'sha256:' + self.sha}
        self.env = patch.dict('os.environ', {'GITHUB_REPOSITORY': self.repo['full_name'],
            'GITHUB_REPOSITORY_ID': str(self.repo['id'])})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.calls = []

    def api(self, url, *, binary=False, token=None):
        self.calls.append((url, binary, token))
        self.assertEqual(token, self.token)
        if url.endswith('/releases/assets/' + str(self.storage['asset_id'])):
            value = self.data if binary else self.asset
        elif url.endswith('/releases/' + str(self.storage['release_id'])):
            value = self.release
        elif url.endswith('/repos/' + self.storage['repository']):
            value = self.repo
        else:
            raise AssertionError('Unexpected URL: ' + url)
        return io.BytesIO(value if isinstance(value, bytes) else json.dumps(value).encode())

    def download(self):
        with patch.object(t, '_request', side_effect=self.api):
            return t.download(self.storage, self.root / 'download', self.sha, token=self.token)

    def test_authenticated_download_verifies_repository_release_asset_and_bytes(self):
        receipt = self.download()
        self.assertEqual((self.root / 'download').read_bytes(), self.data)
        self.assertEqual(receipt, {'release_id': 4567, 'asset_id': 8910,
            'sha256': self.sha, 'immutable': True})
        self.assertEqual(len(self.calls), 4)
        self.assertTrue(all(call[2] == self.token for call in self.calls))

    def test_missing_or_invalid_token_fails_before_request(self):
        for token in (None, '', 'bad token'):
            with self.subTest(token=token), patch.object(t, '_request') as request, self.assertRaises(c.GateError):
                t.download(self.storage, self.root / ('missing-' + str(token)), self.sha, token=token)
            request.assert_not_called()

    def test_workflow_repo_and_repository_id_must_match_exactly(self):
        for key, value in [('GITHUB_REPOSITORY', 'someone/else'), ('GITHUB_REPOSITORY_ID', '99002')]:
            with self.subTest(key=key), patch.dict('os.environ', {key: value}), self.assertRaises(c.GateError):
                t.release_locator(self.storage)

    def test_private_locator_requires_repository_id_and_asset_size(self):
        for key in ('repository_id', 'asset_size'):
            value = self.storage.pop(key)
            with self.subTest(key=key), self.assertRaises(c.GateError):
                t.release_locator(self.storage)
            self.storage[key] = value

    def test_wrong_repository_id_name_or_visibility_rejected(self):
        for key, value in [('id', 99002), ('full_name', 'research-owner/other'), ('private', False)]:
            original = self.repo[key]
            self.repo[key] = value
            with self.subTest(key=key), patch.object(t, '_request', side_effect=self.api), self.assertRaises(c.GateError):
                t.download(self.storage, self.root / ('repo-' + key), self.sha, token=self.token)
            self.repo[key] = original

    def test_mutable_or_wrong_release_identity_rejected(self):
        for key, value in [('id', 9999), ('tag_name', 'other'), ('immutable', False), ('draft', True)]:
            original = self.release[key]
            self.release[key] = value
            with self.subTest(key=key), patch.object(t, '_request', side_effect=self.api), self.assertRaises(c.GateError):
                t.download(self.storage, self.root / ('release-' + key), self.sha, token=self.token)
            self.release[key] = original

    def test_wrong_asset_identity_size_membership_and_api_digest_rejected(self):
        cases = [
            ('asset-id', lambda: self.asset.update(id=9999)),
            ('asset-name', lambda: self.asset.update(name='other.tar.gz')),
            ('asset-size', lambda: self.asset.update(size=len(self.data) + 1)),
            ('asset-membership', lambda: self.release.update(assets=[])),
            ('api-digest', lambda: self.asset.update(digest='sha256:' + '0' * 64)),
        ]
        for label, mutate in cases:
            release, asset = json.loads(json.dumps(self.release)), json.loads(json.dumps(self.asset))
            mutate()
            with self.subTest(case=label), patch.object(t, '_request', side_effect=self.api), self.assertRaises(c.GateError):
                t.download(self.storage, self.root / label, self.sha, token=self.token)
            self.release, self.asset = release, asset

    def test_downloaded_checksum_is_independent_of_api_digest(self):
        wrong = '0' * 64
        with patch.object(t, '_request', side_effect=self.api), self.assertRaises(c.GateError):
            t.download(self.storage, self.root / 'wrong-hash', wrong, token=self.token)

    def test_redirect_strips_token_and_rejects_untrusted_hosts(self):
        api_url = 'https://api.github.com/repos/research-owner/research-ci/releases/assets/8910'
        good = 'https://release-assets.githubusercontent.com/opaque/signed?token=secret-url'

        class RedirectingOpener:
            def __init__(self, location): self.location, self.requests = location, []
            def open(self, request, timeout):
                self.requests.append(request)
                if len(self.requests) == 1:
                    self_test.assertEqual(request.get_header('Authorization'), 'Bearer ' + self_test.token)
                    headers = Message(); headers['Location'] = self.location
                    raise urllib.error.HTTPError(request.full_url, 302, 'Found', headers, io.BytesIO())
                self_test.assertIsNone(request.get_header('Authorization'))
                self_test.assertEqual(request.full_url, good)
                return io.BytesIO(self_test.data)

        self_test = self
        opener = RedirectingOpener(good)
        with patch('src.trusted_snapshot.urllib.request.build_opener', return_value=opener):
            response = t._request(api_url, binary=True, token=self.token)
            self.assertEqual(response.read(), self.data)
        self.assertEqual(len(opener.requests), 2)
        bad = RedirectingOpener('https://evil.example/steal')
        with patch('src.trusted_snapshot.urllib.request.build_opener', return_value=bad), self.assertRaises(c.GateError):
            t._request(api_url, binary=True, token=self.token)
        self.assertEqual(len(bad.requests), 1)

    def test_http_only_redirect_and_signed_url_are_never_exposed_in_errors(self):
        api_url = 'https://api.github.com/repos/research-owner/research-ci/releases/assets/8910'
        malicious = 'http://release-assets.githubusercontent.com/signed-secret'

        class RedirectingOpener:
            def open(self, request, timeout):
                headers = Message(); headers['Location'] = malicious
                raise urllib.error.HTTPError(request.full_url, 302, 'Found', headers, io.BytesIO())

        with patch('src.trusted_snapshot.urllib.request.build_opener', return_value=RedirectingOpener()):
            with self.assertRaises(c.GateError) as caught:
                t._request(api_url, binary=True, token=self.token)
        self.assertNotIn(self.token, str(caught.exception))
        self.assertNotIn('signed-secret', str(caught.exception))

    def test_authentication_and_permission_http_failures_are_sanitized(self):
        api_url = 'https://api.github.com/repos/research-owner/research-ci/releases/4567'

        class FailingOpener:
            def __init__(self, status): self.status = status
            def open(self, request, timeout):
                raise urllib.error.HTTPError(request.full_url, self.status, 'denied', Message(), io.BytesIO())

        for status in (401, 403, 404, 500):
            with self.subTest(status=status), patch('src.trusted_snapshot.urllib.request.build_opener',
                    return_value=FailingOpener(status)), self.assertRaises(c.GateError) as caught:
                t._request(api_url, token=self.token)
            self.assertNotIn(self.token, str(caught.exception))
            self.assertNotIn('4567', str(caught.exception))

    def test_public_p2_registry_reference_and_unauthenticated_path_unchanged(self):
        registry = t.c.read(t.REGISTRY)
        entry = registry['baselines']['p2-initial-bootstrap']
        self.assertEqual(t.registry_reference(registry, 'p2-initial-bootstrap'), entry)
        self.assertEqual(entry['reference']['storage']['kind'], t.PUBLIC_RELEASE_KIND)
        self.assertNotIn('repository_id', entry['reference']['storage'])

    def test_workflow_keeps_contents_read_and_scopes_token_to_execute_step(self):
        import yaml
        workflow = yaml.safe_load((t.c.ROOT / '.github/workflows/ci_v2_manual_research.yml').read_text())
        steps = workflow['jobs']['candidate']['steps']
        execute = next(step for step in steps if step['name'] == 'Restore, build and evaluate research candidate')
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        self.assertEqual(execute['env'], {'TRUSTED_RELEASE_TOKEN': '${{ secrets.GITHUB_TOKEN }}'})
        self.assertNotIn('TRUSTED_RELEASE_TOKEN', workflow['jobs']['candidate'].get('env', {}))


if __name__ == '__main__':
    unittest.main()
