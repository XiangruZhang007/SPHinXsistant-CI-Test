"""Mandatory delivery tests: synthetic locators/ZIPs, no live assets or approval."""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from src import ci_v2_research as c, trusted_snapshot as t, schema2_workflow as workflow
from src.corpus_snapshot import digest, file_digest, read_json, write_json

P = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


class NoticesDeliveryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name); self.counter = 0
        self.ref = deepcopy(read_json(t.REGISTRY)['baselines']['c1-research-parent-09b91a36']['reference'])
        self.ref.update(schema_version=3, node_id='sha256-' + 'a' * 64,
                        transport_sha256=sha(b'synthetic Parent archive'), parent_rows_sha256=sha(b'[]\n'))
        self.ref['authorization']['experiment_id'] = 'OFFLINE_NOTICES_FIXTURE_NOT_AUTHORIZATION'
        def storage(name, asset, data):
            return {'kind': t.PRIVATE_RELEASE_KIND, 'repository': 'FixtureOwner/NoticesTest',
                'repository_id': 42, 'release_id': 43, 'tag': 'offline-notices-fixture',
                'asset_id': asset, 'asset_name': name, 'asset_size': len(data), 'immutable_required': True}
        self.ref['storage'] = storage('parent.tar.gz', 51, b'synthetic Parent archive')
        self.ref['parent_rows_storage'] = storage('rows.json', 52, b'[]\n')
        self.ref['notices'] = {'schema_version': 1, 'baseline_id': self.ref['node_id'],
            'parent_transport_sha256': self.ref['transport_sha256'], 'sha256': '0' * 64,
            'storage': storage('notices.zip', 53, b'pending')}
        self.data = {51: b'synthetic Parent archive', 52: b'[]\n'}
        self.api_changes = {}; self.requests = []
        self.make_zip()
        self.env = {'GITHUB_REPOSITORY': 'FixtureOwner/NoticesTest', 'GITHUB_REPOSITORY_ID': '42',
                    'TRUSTED_RELEASE_TOKEN': 'synthetic-token-never-log'}
        self.registry = self.root / 'registry.json'; write_json(self.root / 'policy.json', {})

    def make_zip(self, *, mutate=None, bad_checks=False, duplicate=False, symlink=False):
        files = {'README.txt': b'Synthetic notice fixture only\n', 'DELIVERY.md': b'Deliver together\n',
                 'licenses/fixture.txt': b'Explicit synthetic license text, not real legal evidence\n',
                 'source-and-license-mapping.json': json.dumps({'baseline_id': self.ref['node_id'],
                     'transport_sha256': self.ref['transport_sha256']}).encode()}
        if mutate: mutate(files)
        files['SHA256SUMS'] = ''.join(sha(v) + '  ' + n + '\n' for n, v in files.items()).encode()
        if bad_checks: files['SHA256SUMS'] = b'0' * 64 + files['SHA256SUMS'][64:]
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as z:
            for name, data in files.items():
                info = zipfile.ZipInfo(name); info.create_system = 3
                info.external_attr = ((stat.S_IFLNK if symlink and name.startswith('licenses/') else stat.S_IFREG) | 0o644) << 16
                z.writestr(info, data)
            if duplicate:
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', UserWarning); z.writestr('README.txt', b'duplicate')
        self.data[53] = buffer.getvalue()
        self.ref['notices']['sha256'] = sha(self.data[53])
        self.ref['notices']['storage']['asset_size'] = len(self.data[53])
        self.path = self.root / 'input.zip'; self.path.write_bytes(self.data[53])

    def request(self, url, *, binary=False, token=None):
        self.requests.append(url)
        stores = [self.ref['storage'], self.ref['parent_rows_storage']]
        if 'notices' in self.ref: stores.append(self.ref['notices']['storage'])
        def asset(s):
            aid = s['asset_id']
            return {'id': aid, 'name': s['asset_name'], 'size': len(self.data.get(aid, b'')),
                    'state': 'uploaded', 'digest': 'sha256:' + sha(self.data.get(aid, b''))}
        if '/releases/assets/' in url:
            aid = int(url.rsplit('/', 1)[1]); s = next((s for s in stores if s['asset_id'] == aid), None)
            # The service's genuine asset identity is fixed; a repinned wrong locator must not pass.
            if aid not in self.data: raise c.GateError('AUTHENTICATION_FAILED', 'Fixture asset unavailable')
            if binary: return io.BytesIO(self.data[aid])
            value = asset(s)
            if aid == 53: value.update(self.api_changes)
        elif '/releases/' in url:
            value = {'id': 43, 'tag_name': 'offline-notices-fixture', 'immutable': True,
                     'draft': False, 'assets': [asset(s) for s in stores]}
            if 'release' in self.api_changes: value.update(self.api_changes['release'])
        else:
            value = {'id': 42, 'full_name': 'FixtureOwner/NoticesTest', 'private': True}
            if 'repository' in self.api_changes: value.update(self.api_changes['repository'])
        return io.BytesIO(json.dumps(value).encode())

    def verify(self):
        return t.verify_notices(self.ref, digest(self.ref), self.path)

    def test_valid_pinned_companion_and_retention_receipt(self):
        receipt = self.verify(); self.assertEqual(receipt['status'], 'NOTICES_VERIFIED')
        t.retain_notices(self.ref, digest(self.ref), self.path, self.root)
        self.assertEqual(t.verify_retained_notices(self.ref, digest(self.ref), self.root), receipt)
        self.assertEqual((self.root / 'notices/companion.zip').read_bytes(), self.data[53])
        self.assertEqual(receipt['production_promotion'], 'NOT_AUTHORIZED')

    def test_existing_private_downloader_fetches_exact_third_asset(self):
        with patch.dict(os.environ, self.env), patch.object(t, '_request', side_effect=self.request):
            path = t.fetch_notices(self.ref, digest(self.ref), self.root / 'download.zip')
        self.assertEqual(path.read_bytes(), self.data[53])
        self.assertEqual(len([u for u in self.requests if u.endswith('/assets/53')]), 2)

    def test_missing_required_binding(self):
        self.ref.pop('notices')
        with self.assertRaises(c.GateError): t.validate_reference(self.ref, digest(self.ref))

    def test_missing_file(self):
        with self.assertRaises(c.GateError): t.verify_notices(self.ref, digest(self.ref), None)

    def assert_restore_rejected_before_staging(self, *, notices_path=None, expected_pin=None):
        destination = self.root / 'direct-parent'
        with (patch.object(t.tempfile, 'TemporaryDirectory') as staging,
              patch.object(t, 'extract_regular') as extract,
              patch.object(t, 'verify_package') as package,
              self.assertRaises(c.GateError)):
            t.restore(P, self.root / 'unused-parent.tar.gz', destination, self.ref,
                      expected_pin or digest(self.ref), notices_path=notices_path)
        staging.assert_not_called(); extract.assert_not_called(); package.assert_not_called()
        self.assertFalse(destination.exists())

    def test_direct_v3_restore_missing_notices_fails_before_staging(self):
        self.assert_restore_rejected_before_staging()

    def test_direct_v3_restore_corrupt_notices_fails_before_staging(self):
        self.path.write_bytes(b'corrupt notices')
        self.assert_restore_rejected_before_staging(notices_path=self.path)

    def test_direct_v3_restore_wrong_parent_content_fails_before_staging(self):
        def wrong_parent(files):
            subject = json.loads(files['source-and-license-mapping.json'])
            subject['baseline_id'] = 'sha256-' + 'b' * 64
            files['source-and-license-mapping.json'] = json.dumps(subject).encode()
        # Even a correctly hashed ZIP cannot substitute another Parent's notices.
        self.make_zip(mutate=wrong_parent)
        self.assert_restore_rejected_before_staging(notices_path=self.path)

    def test_direct_v3_restore_requires_independent_reference_pin(self):
        self.assert_restore_rejected_before_staging(notices_path=self.path, expected_pin='0' * 64)

    def test_direct_v3_restore_valid_notices_reaches_normal_restore(self):
        destination = self.root / 'direct-parent'
        def extract(archive, staged, checksum):
            self.assertFalse(destination.exists())
            staged.mkdir()
        with (patch.object(t, 'extract_regular', side_effect=extract) as unpack,
              patch.object(t, 'verify_package', return_value={'fixture': 'VERIFIED'}) as package):
            result = t.restore(P, self.root / 'unused-parent.tar.gz', destination,
                               self.ref, digest(self.ref), notices_path=self.path)
        self.assertEqual(result, {'fixture': 'VERIFIED'})
        unpack.assert_called_once(); package.assert_called_once()
        self.assertTrue(destination.is_dir())

    def test_direct_v2_restore_keeps_no_notices_behavior(self):
        self.ref['schema_version'] = 2; self.ref.pop('notices')
        destination = self.root / 'legacy-parent'
        with (patch.object(t, 'extract_regular', side_effect=lambda a, staged, h: staged.mkdir()) as unpack,
              patch.object(t, 'verify_package', return_value={'fixture': 'LEGACY_VERIFIED'}) as package):
            result = t.restore(P, self.root / 'unused-parent.tar.gz', destination, self.ref, digest(self.ref))
        self.assertEqual(result, {'fixture': 'LEGACY_VERIFIED'})
        unpack.assert_called_once(); package.assert_called_once()
        self.assertTrue(destination.is_dir())

    def test_direct_v2_restore_rejects_unsupported_notices_binding(self):
        self.ref['schema_version'] = 2
        self.assert_restore_rejected_before_staging(notices_path=self.path)

    def test_external_reference_pin_is_required(self):
        self.ref['notices']['sha256'] = '1' * 64
        with self.assertRaises(c.GateError): t.verify_notices(self.ref, '0' * 64, self.path)

    def test_wrong_bytes_or_size(self):
        for bad in (self.data[53][:-1], b'X' + self.data[53][1:]):
            with self.subTest(size=len(bad)):
                self.path.write_bytes(bad)
                with self.assertRaises(c.GateError): self.verify()

    def test_wrong_declared_parent_and_transport(self):
        for field in ('baseline_id', 'parent_transport_sha256'):
            saved = self.ref['notices'][field]; self.ref['notices'][field] = '0' * 64
            with self.subTest(field=field), self.assertRaises(c.GateError): self.verify()
            self.ref['notices'][field] = saved

    def test_wrong_internal_parent_and_transport(self):
        for field in ('baseline_id', 'transport_sha256'):
            def mutate(files):
                obj = json.loads(files['source-and-license-mapping.json']); obj[field] = 'wrong'
                files['source-and-license-mapping.json'] = json.dumps(obj).encode()
            self.make_zip(mutate=mutate)
            with self.subTest(field=field), self.assertRaises(c.GateError): self.verify()

    def test_wrong_release_repository_and_duplicate_assets(self):
        for field, value in (('repository', 'OtherOwner/OtherRepo'), ('repository_id', 999),
                             ('release_id', 999), ('tag', 'another-tag'), ('asset_id', 51),
                             ('asset_name', 'parent.tar.gz'), ('immutable_required', False), ('asset_size', True)):
            old = self.ref['notices']['storage'][field]; self.ref['notices']['storage'][field] = value
            with self.subTest(field=field), self.assertRaises(c.GateError): self.verify()
            self.ref['notices']['storage'][field] = old

    def test_invalid_checksums_and_missing_notice_documents(self):
        self.make_zip(bad_checks=True)
        with self.assertRaises(c.GateError): self.verify()
        self.make_zip(mutate=lambda files: files.pop('README.txt'))
        with self.assertRaises(c.GateError): self.verify()

    def test_unsafe_zip_paths(self):
        for name in ('.', '../escape', '/absolute', 'licenses/../escape', 'dir\\escape', 'C:escape'):
            self.make_zip(mutate=lambda files: files.update({name: b'unsafe'}))
            with self.subTest(name=name), self.assertRaises(c.GateError): self.verify()

    def test_symlink_and_duplicate_zip_members(self):
        for options in ({'symlink': True}, {'duplicate': True}):
            self.make_zip(**options)
            with self.subTest(options=options), self.assertRaises(c.GateError): self.verify()

    def test_symlink_input_and_corrupt_zip(self):
        link = self.root / 'link.zip'; link.symlink_to(self.path)
        with self.assertRaises(c.GateError): t.verify_notices(self.ref, digest(self.ref), link)
        self.path.write_bytes(b'not ZIP')
        self.ref['notices']['sha256'] = file_digest(self.path); self.ref['notices']['storage']['asset_size'] = self.path.stat().st_size
        with self.assertRaises(c.GateError): self.verify()

    def test_duplicate_json_and_checksum_entries(self):
        self.make_zip(mutate=lambda files: files.update({'source-and-license-mapping.json':
            b'{"baseline_id":"one","baseline_id":"two"}'}))
        with self.assertRaises(c.GateError): self.verify()
        self.make_zip()
        with zipfile.ZipFile(self.path) as z: files = {n: z.read(n) for n in z.namelist()}
        files['SHA256SUMS'] += files['SHA256SUMS'].splitlines(keepends=True)[0]
        with zipfile.ZipFile(self.path, 'w') as z:
            for n, data in files.items(): z.writestr(n, data)
        self.ref['notices']['sha256'] = file_digest(self.path); self.ref['notices']['storage']['asset_size'] = self.path.stat().st_size
        with self.assertRaises(c.GateError): self.verify()

    def test_retained_missing_altered_or_wrong_receipt_rejected(self):
        t.retain_notices(self.ref, digest(self.ref), self.path, self.root)
        receipt = self.root / 'notices/verification.json'; original = receipt.read_bytes()
        receipt.write_text('{}')
        with self.assertRaises(c.GateError): t.verify_retained_notices(self.ref, digest(self.ref), self.root)
        receipt.write_bytes(original); (self.root / 'notices/companion.zip').unlink()
        with self.assertRaises(c.GateError): t.verify_retained_notices(self.ref, digest(self.ref), self.root)

    def test_historical_public_and_private_references_unchanged(self):
        for entry in read_json(t.REGISTRY)['baselines'].values():
            ref = entry['reference']
            with self.subTest(format=ref['package_format']), patch.object(t, 'download') as download:
                self.assertEqual(t.validate_reference(ref, entry['expected_reference_sha256']), ref)
                self.assertIsNone(t.fetch_notices(ref, entry['expected_reference_sha256'], self.root / 'unused'))
                self.assertIsNone(t.verify_notices(ref, entry['expected_reference_sha256'], None))
                download.assert_not_called()

    def test_schema2_cannot_silently_claim_notices_via_unknown_field(self):
        self.ref['schema_version'] = 2
        with self.assertRaises(c.GateError): t.validate_reference(self.ref, digest(self.ref))

    def schema2_execution(self):
        self.counter += 1; name = 's2-' + str(self.counter)
        entry = {'reference': self.ref, 'expected_reference_sha256': digest(self.ref),
                 'build_policy_path': 'policy.json', 'build_policy_sha256': file_digest(self.root / 'policy.json')}
        self.registry.write_text(json.dumps({'schema_version': 2, 'baselines': {'fixture': entry}}))
        planned = {'key': 'fixture', 'upstreams': self.ref['upstreams']}
        (self.root / 'plan.json').write_text(json.dumps(planned))
        def local(*args, **kwargs):
            out = args[4]; out.mkdir()
            t.retain_notices(args[5], args[6], kwargs['notices_path'], out)
            return {'status': 'OFFLINE_EXECUTION_STUB_NOT_A_BUILD'}
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, self.env))
            stack.enter_context(patch.object(t, 'REGISTRY', self.registry))
            stack.enter_context(patch.object(t, '_request', side_effect=self.request))
            stack.enter_context(patch.object(workflow, 'plan', return_value=planned))
            stack.enter_context(patch.object(c, 'frozen_runtime', return_value={}))
            stack.enter_context(patch.object(workflow.shutil, 'disk_usage', return_value=type('Space', (), {'free': 100 * 1024**3})()))
            stack.enter_context(patch.object(workflow.subprocess, 'run'))
            self.local = stack.enter_context(patch.object(workflow, 'run_local', side_effect=local))
            self.pack = stack.enter_context(patch.object(c, 'package_candidate'))
            out = self.root / (name + '-output')
            result = workflow.execute_plan(self.root, self.root / 'plan.json', self.root / name, out)
        return result, out

    def test_schema2_three_assets_reach_execution_and_are_retained(self):
        result, out = self.schema2_execution()
        self.assertEqual(result['status'], 'OFFLINE_EXECUTION_STUB_NOT_A_BUILD')
        self.assertEqual(t.verify_retained_notices(self.ref, digest(self.ref), out)['status'], 'NOTICES_VERIFIED')
        self.assertTrue(all(any(u.endswith('/assets/' + str(i)) for u in self.requests) for i in (51, 52, 53)))
        self.local.assert_called_once(); self.pack.assert_called_once()

    def test_schema2_notices_failures_prevent_execution(self):
        for changes in ({'id': 999}, {'size': len(self.data[53]) + 1}, {'release': {'immutable': False}},
                        {'repository': {'private': False}}):
            self.api_changes = changes
            with self.subTest(changes=changes), self.assertRaises(c.GateError): self.schema2_execution()
            self.local.assert_not_called(); self.pack.assert_not_called()

    def test_schema2_missing_v3_binding_prevents_execution(self):
        self.ref.pop('notices')
        with self.assertRaises(c.GateError): self.schema2_execution()
        self.local.assert_not_called(); self.pack.assert_not_called()

    def test_direct_local_execution_blocks_before_restore_without_notices(self):
        from src import upstream_provenance as source
        rows = self.root / 'rows.json'; rows.write_bytes(b'[]\n')
        policy = {'provenance_type': 'GENUINE_UPSTREAM'}
        with (patch.object(c, 'frozen_runtime', return_value={}), patch.object(source, '_policy', return_value=policy),
              patch.object(workflow, '_research_parent_scope'), patch.object(t, 'restore') as restore,
              patch.object(source, 'build') as build, self.assertRaises(c.GateError)):
            workflow.run_local(P, self.root / 'parent.tar.gz', self.root / 'base', self.root / 'target',
                self.root / 'unused-output', self.ref, digest(self.ref), self.root / 'policy.json',
                file_digest(self.root / 'policy.json'), rows)
        restore.assert_not_called(); build.assert_not_called()

    def genuine_notices_failure(self, *, missing=False):
        from src import genuine_continuous_execution as run
        self.make_zip(bad_checks=True)
        if missing: self.ref.pop('notices')
        config = {'registry_path': 'registry.json', 'continuous_policy_path': 'scope.json',
                  'continuous_policy_sha256': '0' * 64}
        entry = {'reference': self.ref, 'expected_reference_sha256': digest(self.ref)}
        project = self.root / 'project'; project.mkdir()
        write_json(project / 'registry.json', {'schema_version': 2, 'baselines': {'fixture': entry}})
        authority = {'parent_comparison': {'update_available': True}, 'workflow_run': {'event': 'workflow_dispatch'}}
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, self.env))
            stack.enter_context(patch.object(t, '_request', side_effect=self.request))
            stack.enter_context(patch.object(run, 'deployment', return_value=(config, '{}', '0' * 64)))
            stack.enter_context(patch.object(run, '_authority', return_value=authority))
            stack.enter_context(patch.object(run.scope, 'load_policy', return_value={}))
            stack.enter_context(patch.object(run, '_detected', return_value={'upstreams': self.ref['upstreams']}))
            stack.enter_context(patch.object(run.scope, '_parent', return_value=('fixture', entry, [])))
            stack.enter_context(patch.object(run.shutil, 'disk_usage', return_value=type('Space', (), {'free': 100 * 1024**3})()))
            clone = stack.enter_context(patch.object(run, '_clone_sources'))
            restore = stack.enter_context(patch.object(t, 'restore'))
            qualify = stack.enter_context(patch.object(run.anchor, 'qualify_parent_anchor'))
            with self.assertRaises(c.GateError) as error:
                run.execute(project, self.root / 'detected.json', self.root / 'work', self.root / 'output')
            self.assertEqual(error.exception.status, 'NOTICES_REQUIRED' if missing else 'NOTICES_INVALID')
        clone.assert_not_called(); restore.assert_not_called(); qualify.assert_not_called()

    def test_genuine_failure_precedes_clone_restore_and_qualification(self):
        self.genuine_notices_failure()

    def test_genuine_missing_v3_binding_prevents_parent_use(self):
        self.genuine_notices_failure(missing=True)


class NoticesPackageIntegrationTests(unittest.TestCase):
    """Existing miniature pipeline; all source/Owner/API observations are mocks."""
    @classmethod
    def setUpClass(cls):
        from test_genuine_continuous_execution import GenuineFormatTests
        from test_upstream_provenance import commit
        from src import genuine_continuous_execution as run
        import base64
        # Isolate the existing fixture factory; never touch retained real assets.
        f = cls.fixture = type('IsolatedNoticesFixture', (GenuineFormatTests,), {})
        f.setUpClass(); cls.addClassCleanup(f.doClassCleanups)
        helper = NoticesDeliveryTests(); helper.setUp(); cls.addClassCleanup(helper.doCleanups)
        f.ref = deepcopy(f.ref); f.ref['schema_version'] = 3
        locator = {**f.ref['storage'], 'asset_id': 303, 'asset_name': 'fixture-notices.zip', 'asset_size': 1}
        f.ref['notices'] = {'schema_version': 1, 'baseline_id': f.ref['node_id'],
            'parent_transport_sha256': f.ref['transport_sha256'], 'sha256': '0' * 64, 'storage': locator}
        helper.ref = f.ref; helper.make_zip(); cls.notice_bytes = helper.data[53]
        registry = read_json(f.registry); entry = registry['baselines']['fixture-parent']
        entry.update(reference=f.ref, expected_reference_sha256=digest(f.ref)); f.registry.write_text(json.dumps(registry))
        policy = read_json(f.policy_path); policy['eligible_parents'][0]['expected_reference_sha256'] = digest(f.ref)
        f.policy_path.write_text(json.dumps(policy))
        f.config.update(registry_sha256=file_digest(f.registry), continuous_policy_sha256=file_digest(f.policy_path))
        f.head = commit(f.project); f.config['implementation_revision'] = f.head
        prefix = 'repos/' + f.repo
        f.responses[prefix + '/actions/runs/401']['head_sha'] = f.head
        f.responses[prefix + '/git/ref/heads/research']['object']['sha'] = f.head
        f.responses[prefix + '/contents/configs/mock-registry.json?ref=' + f.head] = {
            'path': 'configs/mock-registry.json', 'type': 'file', 'encoding': 'base64',
            'content': base64.b64encode(f.registry.read_bytes()).decode()}
        original_download = t.download
        def download(storage, destination, expected_sha, **kwargs):
            if storage['asset_id'] == 303:
                # Transport metadata/identity failures are covered through the real
                # downloader in NoticesDeliveryTests. Here only the network is stubbed.
                Path(destination).write_bytes(cls.notice_bytes)
                if file_digest(destination) != expected_sha: raise AssertionError('Fixture pin mismatch')
                return {'immutable': True}
            return original_download(storage, destination, expected_sha, **kwargs)
        cls.delivered = f.shared / 'with-notices'
        with f.boundaries(), patch.object(t, 'download', side_effect=download):
            cls.result = run.execute(f.project, f.detection_path, f.shared / 'notices-work', cls.delivered)
        cls.pins = read_json(cls.delivered / 'verification-inputs.json')

    def test_verified_package_and_transport_retain_notices_outside_parent(self):
        from src import genuine_continuous_execution as run
        root = self.delivered / 'run'; ref = self.fixture.ref
        result = run.verify_package(self.fixture.project, root, **self.pins)
        self.assertEqual(result['verification'], 'PACKAGE_INTEGRITY_VERIFIED')
        self.assertEqual(result['research_approval'], 'NOT_GRANTED')
        self.assertEqual((root / 'notices/companion.zip').read_bytes(), self.notice_bytes)
        self.assertFalse((root / 'parent/notices').exists())
        self.assertEqual(t.verify_retained_notices(ref, digest(ref), root)['status'], 'NOTICES_VERIFIED')
        identity = read_json(root / 'candidate/genuine-candidate.json')['identity']
        self.assertIn('notices/companion.zip', identity['artifacts'])
        self.assertIn('notices/verification.json', identity['artifacts'])
        with tarfile.open(self.delivered / 'candidate.tar.gz') as archive:
            self.assertEqual(archive.extractfile('notices/companion.zip').read(), self.notice_bytes)

    def test_resealed_copy_cannot_omit_required_notice_receipt(self):
        from src import genuine_continuous_execution as run
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'run'; shutil.copytree(self.delivered / 'run', root)
            (root / 'notices/verification.json').unlink(); (root / 'checksums.json').unlink()
            run.v1._seal(root)
            pins = {**self.pins, 'expected_manifest_sha256': file_digest(root / 'checksums.json')}
            with self.assertRaises(c.GateError) as error:
                run.verify_package(self.fixture.project, root, **pins)
            self.assertEqual(error.exception.status, 'NOTICES_REQUIRED')


if __name__ == '__main__':
    unittest.main()
