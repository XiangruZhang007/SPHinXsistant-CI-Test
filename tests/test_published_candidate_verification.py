"""Offline transport and binding tests; synthetic qualification is never authority."""
from copy import deepcopy
import io
import json
from pathlib import Path
import tarfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import test_candidate_release_archive as fixtures
from src import published_candidate_verification as v
from src import trusted_snapshot as transport, trusted_baseline_registration as registration
from src import upstream_provenance, approval_evidence
from src.corpus_snapshot import digest, file_digest


class PublishedCandidateVerificationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.CandidateArchiveTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        f.prepare()
        self.root = f.root
        self.project = self.root / 'project'
        self.project.mkdir()
        self.build = fixtures.put(self.project, 'configs/build.json', {'synthetic': True})
        self.registry = fixtures.put(self.root, 'registry.json', {'schema_version': 2, 'baselines': {}})
        self.registry_bytes = self.registry.read_bytes()
        self.repo = {'id': f.repo_id, 'full_name': v.archive.REPOSITORY, 'private': True}
        self.env = patch.dict('os.environ', {'GITHUB_REPOSITORY': self.repo['full_name'],
                                           'GITHUB_REPOSITORY_ID': str(f.repo_id)})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.assets, self.releases, self.data = {}, {}, {}
        self.release_ref = {'schema_version': 1, 'assets': {}}
        for number, name in enumerate(sorted(v.ASSETS), 10):
            self.release_ref['assets'][name] = self.asset(f.output / name, number, 100)
        candidate = f.artifact / 'run/candidate'
        baseline = self.root / 'baseline-original'
        baseline.mkdir()
        (baseline / 'corpus.jsonl').write_bytes(f.corpus)
        (baseline / 'upstream-candidate.json').write_bytes((candidate / 'upstream-candidate.json').read_bytes())
        fixtures.put(baseline, 'upstream-baseline.json', {'synthetic': True})
        fixtures.put(baseline, 'quality.json', {'status': 'QUALITY_REVIEW_REQUIRED'})
        # The real schema-2 authorization contract does not require a production
        # field; restrictions are sealed in its Candidate and approval policy.
        fixtures.put(baseline, 'authorization.json', {'quality_status': 'QUALITY_REVIEW_REQUIRED'})
        fixtures.seal(baseline)
        baseline_tar = self.root / 'baseline.tar.gz'
        with tarfile.open(baseline_tar, 'w:gz') as tar:
            for p in sorted(baseline.iterdir()):
                tar.add(p, arcname=p.name)
        baseline_asset = self.asset(baseline_tar, 30, 200)
        rows = f.artifact / 'run/quality/incremental-raw-results.json'
        row_asset = self.asset(rows, 31, 200)
        self.ref = {
            'schema_version': 2, 'package_format': 'schema2-research-baseline',
            'accepted_package_schema': 2, 'node_id': 'sha256-' + 'f' * 64,
            'package_checksum': '1' * 64, 'manifest_sha256': file_digest(baseline / 'checksums.json'),
            'transport_sha256': baseline_asset['sha256'],
            'source_state': f.result['target_source_state'], 'upstreams': f.upstreams,
            'build_fingerprint': 'c' * 64, 'corpus_sha256': f.corpus_sha,
            'authorization': {'type': 'EXPLICIT_RESEARCH_BASELINE_REUSE',
                'scope': 'ISOLATED_RESEARCH_PARENT_REUSE', 'research_only': True,
                'experiment_id': 'offline-fixture', 'automatic_research_approval': False,
                'production_promotion': 'NOT_AUTHORIZED'},
            'storage': baseline_asset['storage'], 'parent_rows_storage': row_asset['storage'],
            'parent_rows_sha256': row_asset['sha256'],
        }
        self.entry = {'build_policy_path': 'configs/build.json',
            'build_policy_sha256': file_digest(self.build),
            'expected_reference_sha256': digest(self.ref), 'reference': self.ref}
        self.upstream_report = {'node_id': self.ref['node_id'], 'candidate_id': f.cid,
            'generation': 2, 'target_source_state': self.ref['source_state'], 'upstreams': f.upstreams,
            'receipt': {'kind': 'RESEARCH_BASELINE', 'package_checksum': '1' * 64},
            'provenance_type': 'GENUINE_UPSTREAM', 'P4_1_verification': 'P4_1_VERIFIED',
            'automatic_reuse': False, 'production_promotion': 'NOT_AUTHORIZED'}
        self.qualified = {'status': 'QUALIFIED', 'execution': 'NO_FRESH_REPLAY',
            'production_promotion': 'NOT_AUTHORIZED', 'quality_acceptance': 'NOT_GRANTED',
            'controlled_fixture': False, 'bindings': {
                'baseline_id': self.ref['node_id'], 'candidate_id': f.cid,
                'parent_corpus_sha256': f.corpus_sha, 'source_state': self.ref['source_state'],
                'upstreams': f.upstreams, 'build_fingerprint': 'c' * 64,
                'benchmark_sha256': f.result['bindings']['benchmark_sha256'],
                'parent_rows_sha256': row_asset['sha256'],
                'historical_rows_sha256': f.result['bindings']['base_rows_sha256'],
                'R2_fingerprint': {'synthetic': True}, 'quality_policy_sha256': '3' * 64,
                'metrics_sha256': '4' * 64}}
        self.arguments = dict(candidate_release=self.release_ref,
            expected_candidate_release_sha256=digest(self.release_ref),
            expected_reference_sha256=digest(self.ref),
            expected_build_policy_sha256=file_digest(self.build),
            expected_registry_sha256=file_digest(self.registry), approval_policy_sha256='5' * 64,
            token='offline-fixture-token')
        self.paths = []
        self.package = Mock(return_value={})
        self.anchor = Mock(return_value=self.qualified)
        self.upstream = Mock(return_value=self.upstream_report)
        # Qualification internals are mocked, not the real download/extraction,
        # reference validator, registration preflight, or binding implementation.
        self.validators = (SimpleNamespace(verify_baseline=Mock(side_effect=AssertionError('legacy route'))),
                           SimpleNamespace(_research_parent_scope=Mock()), transport)
        for p in (patch.object(transport, '_request', side_effect=self.api),
                  patch.object(transport, 'verify_package', self.package),
                  patch.object(upstream_provenance, 'verify', self.upstream),
                  patch.object(registration, '_validators', return_value=self.validators),
                  patch.object(v.anchor, 'qualify_parent_anchor', self.anchor),
                  patch.object(approval_evidence, 'replay', side_effect=AssertionError('No replay'))):
            p.start()
            self.addCleanup(p.stop)
        self.protected = {p: file_digest(p) for p in (transport.REGISTRY,
                         Path('configs/ci_v2_runtime_lock.json'))}

    def tearDown(self):
        self.assertEqual(self.registry.read_bytes(), self.registry_bytes)
        for p, sha in self.protected.items():
            self.assertEqual(file_digest(p), sha)
        for p in self.paths:
            self.assertFalse(p.exists())

    def asset(self, path, asset_id, release_id):
        raw = path.read_bytes()
        storage = {'kind': transport.PRIVATE_RELEASE_KIND,
            'repository': self.repo['full_name'], 'repository_id': self.repo['id'],
            'release_id': release_id, 'asset_id': asset_id, 'tag': f'research-{release_id}',
            'asset_name': path.name, 'asset_size': len(raw), 'immutable_required': True}
        self.data[asset_id] = raw
        self.assets[asset_id] = {'id': asset_id, 'name': path.name, 'size': len(raw),
            'state': 'uploaded', 'digest': 'sha256:' + file_digest(path)}
        release = self.releases.setdefault(release_id, {'id': release_id,
            'tag_name': storage['tag'], 'draft': False, 'immutable': True, 'assets': []})
        release['assets'].append(self.assets[asset_id])
        return {'storage': storage, 'sha256': file_digest(path)}

    def api(self, url, *, binary=False, token=None):
        self.assertEqual(token, 'offline-fixture-token')
        if '/releases/assets/' in url:
            asset_id = int(url.rsplit('/', 1)[1])
            obj = self.data[asset_id] if binary else self.assets[asset_id]
        elif '/releases/' in url:
            obj = self.releases[int(url.rsplit('/', 1)[1])]
        else:
            self.assertEqual(url, 'https://api.github.com/repos/' + self.repo['full_name'])
            obj = self.repo
        return io.BytesIO(obj if isinstance(obj, bytes) else json.dumps(obj).encode())

    def run_verification(self, **overrides):
        args = {**self.arguments, **overrides}
        original = v.tempfile.TemporaryDirectory
        def temporary(*a, **kw):
            td = original(*a, **kw)
            self.paths.append(Path(td.name))
            return td
        with patch.object(v.tempfile, 'TemporaryDirectory', side_effect=temporary):
            return v.verify(self.project, self.registry, 'proposed-baseline', self.entry, **args)

    def repin(self, name, raw):
        item = self.release_ref['assets'][name]
        aid = item['storage']['asset_id']
        self.data[aid] = raw
        sha = v.hashlib.sha256(raw).hexdigest()
        item['sha256'] = sha
        item['storage']['asset_size'] = len(raw)
        self.assets[aid].update(size=len(raw), digest='sha256:' + sha)
        self.arguments['expected_candidate_release_sha256'] = digest(self.release_ref)

    def test_valid_deterministic_subject_preserves_restrictions_and_no_replay(self):
        one = self.run_verification()
        two = self.run_verification(candidate_release=dict(reversed(list(self.release_ref.items()))))
        self.assertEqual(one, two)
        self.assertEqual(one['status'], 'EVIDENCE_VERIFIED')
        self.assertEqual(one['execution'], 'NO_FRESH_REPLAY')
        self.assertEqual(one['authorization'], 'NOT_VERIFIED')
        self.assertEqual(one['registration'], 'NOT_PERFORMED')
        s = one['registration_subject']
        self.assertEqual(one['registration_subject_sha256'], digest(s))
        self.assertEqual(s['candidate']['q1_status'], 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
        self.assertEqual(s['candidate']['quality_status'], 'QUALITY_REVIEW_REQUIRED')
        self.assertEqual(s['registry_entry'], self.entry)
        self.assertEqual(s['production_promotion'], 'NOT_AUTHORIZED')
        self.assertIs(self.anchor.call_args.kwargs['fresh_replay'], False)
        self.validators[0].verify_baseline.assert_not_called()

    def test_independent_pins_and_registry_are_required(self):
        for name in ('expected_candidate_release_sha256', 'expected_reference_sha256',
                     'expected_build_policy_sha256', 'expected_registry_sha256', 'approval_policy_sha256'):
            for bad in (None, 'malformed'):
                with self.subTest(name=name, bad=bad), self.assertRaises(v.VerificationError):
                    self.run_verification(**{name: bad})
        for name in ('expected_candidate_release_sha256', 'expected_reference_sha256',
                     'expected_build_policy_sha256', 'expected_registry_sha256'):
            with self.subTest(name=name), self.assertRaises(v.VerificationError):
                self.run_verification(**{name: '0' * 64})

    def test_missing_and_extra_release_assets(self):
        original = self.releases[100]['assets'][:]
        for assets in (original[:-1], original + [dict(original[0])]):
            self.releases[100]['assets'] = assets
            with self.assertRaises(v.VerificationError):
                self.run_verification()

    def test_wrong_asset_identity_name_size_digest_and_bytes(self):
        aid = self.release_ref['assets']['candidate.tar.gz']['storage']['asset_id']
        for key, value in [('id', 999), ('name', 'wrong'), ('size', 1), ('digest', 'sha256:' + '0' * 64)]:
            old = self.assets[aid][key]
            self.assets[aid][key] = value
            with self.subTest(key=key), self.assertRaises(v.VerificationError):
                self.run_verification()
            self.assets[aid][key] = old
        self.data[aid] = b'corrupted'
        with self.assertRaises(v.VerificationError):
            self.run_verification()

    def test_wrong_release_repository_mutability_and_missing_token(self):
        for obj, key, value in [(self.repo, 'id', 999), (self.repo, 'private', False),
                               (self.releases[100], 'immutable', False),
                               (self.releases[100], 'draft', True),
                               (self.releases[100], 'id', 99),
                               (self.releases[100], 'tag_name', 'wrong')]:
            old = obj[key]
            obj[key] = value
            with self.subTest(key=key), self.assertRaises(v.VerificationError):
                self.run_verification()
            obj[key] = old
        with self.assertRaises(v.VerificationError):
            self.run_verification(token=None)

    def test_incomplete_or_conflicting_release_reference(self):
        for mutate in (lambda r: r['assets'].pop('candidate.tar.gz'),
                       lambda r: r['assets']['candidate.tar.gz']['storage'].update(release_id=999),
                       lambda r: r['assets']['candidate.tar.gz']['storage'].update(asset_name='wrong'),
                       lambda r: r['assets']['candidate.tar.gz']['storage'].update(asset_id=11)):
            ref = deepcopy(self.release_ref)
            mutate(ref)
            with self.assertRaises(v.VerificationError):
                self.run_verification(candidate_release=ref, expected_candidate_release_sha256=digest(ref))

    def test_changed_manifest_even_with_new_transport_pin_fails_against_evidence(self):
        manifest = json.loads((self.fixture.output / 'release-manifest.json').read_bytes())
        manifest['candidate_id'] = 'sha256-' + '0' * 64
        self.repin('release-manifest.json', json.dumps(manifest).encode())
        with self.assertRaisesRegex(v.VerificationError, 'MANIFEST_EVIDENCE'):
            self.run_verification()

    def test_duplicate_manifest_fields_are_rejected(self):
        raw = (self.fixture.output / 'release-manifest.json').read_bytes()
        self.repin('release-manifest.json', b'{"schema_version":1,' + raw.lstrip()[1:])
        with self.assertRaisesRegex(v.VerificationError, 'DUPLICATE_JSON_KEY'):
            self.run_verification()

    def test_unsafe_and_unexpected_archive_members(self):
        for name, link in (('../escape', False), ('/absolute', False), ('link', True), ('unexpected', False)):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode='w:gz') as tar:
                member = tarfile.TarInfo(name)
                if link:
                    member.type = tarfile.SYMTYPE
                    member.linkname = '/tmp/escape'
                    tar.addfile(member)
                else:
                    member.size = 1
                    tar.addfile(member, io.BytesIO(b'x'))
            self.repin('research-evidence.tar.gz', output.getvalue())
            with self.subTest(name=name), self.assertRaises(v.VerificationError):
                self.run_verification()

    def test_corrupt_tar_with_valid_transport_hash_is_rejected(self):
        for name in ('candidate.tar.gz', 'research-evidence.tar.gz'):
            self.repin(name, b'not a tar')
            with self.subTest(name=name), self.assertRaises(v.VerificationError):
                self.run_verification()

    def test_wrong_baseline_candidate_generation_and_p41(self):
        for key, value in [('candidate_id', 'sha256-' + '0' * 64), ('generation', 3),
                           ('P4_1_verification', 'NOT_APPROVED')]:
            old = self.upstream_report[key]
            self.upstream_report[key] = value
            with self.subTest(key=key), self.assertRaises(v.VerificationError):
                self.run_verification()
            self.upstream_report[key] = old
        self.upstream.side_effect = FileNotFoundError('missing P4.1 evidence')
        with self.assertRaises(v.VerificationError):
            self.run_verification()

    def test_qualification_failure_or_wrong_anchor_binding(self):
        for key, value in [('status', 'BLOCKED'), ('execution', 'FRESH_R2_REPLAY_VERIFIED'),
                           ('controlled_fixture', True), ('production_promotion', 'AUTHORIZED'),
                           ('quality_acceptance', 'GRANTED')]:
            old = self.qualified[key]
            self.qualified[key] = value
            with self.subTest(key=key), self.assertRaises(v.VerificationError):
                self.run_verification()
            self.qualified[key] = old
        for key in ('baseline_id', 'parent_rows_sha256', 'benchmark_sha256', 'source_state', 'upstreams'):
            old = self.qualified['bindings'][key]
            self.qualified['bindings'][key] = 'wrong'
            with self.subTest(key=key), self.assertRaises(v.VerificationError):
                self.run_verification()
            self.qualified['bindings'][key] = old

    def test_incomplete_anchor_bindings_fail_closed(self):
        for key in list(self.qualified['bindings']):
            old = self.qualified['bindings'].pop(key)
            with self.subTest(key=key), self.assertRaises(v.VerificationError):
                self.run_verification()
            self.qualified['bindings'][key] = old

    def test_independent_baseline_package_failure_stops_before_anchor(self):
        self.package.side_effect = ValueError('invalid sealed package')
        with self.assertRaisesRegex(v.VerificationError, 'BASELINE_VERIFICATION_FAILED'):
            self.run_verification()
        self.anchor.assert_not_called()

    def test_tampered_baseline_transport_stops_before_qualification(self):
        self.data[30] = b'changed baseline bytes'
        with self.assertRaises(v.VerificationError):
            self.run_verification()
        self.upstream.assert_not_called()
        self.anchor.assert_not_called()

    def test_parent_rows_download_cannot_substitute_other_evidence(self):
        self.data[31] = b'wrong r2 results'
        with self.assertRaises(v.VerificationError):
            self.run_verification()
        self.anchor.assert_not_called()

    def test_preserved_candidate_metadata_must_match_exactly(self):
        original = v._read
        def altered(path):
            value = original(path)
            if Path(path).parts[-2:] == ('baseline', 'upstream-candidate.json'):
                value['identity']['generation'] = 999
            return value
        with patch.object(v, '_read', side_effect=altered), self.assertRaisesRegex(
                v.VerificationError, 'ORIGINAL_CANDIDATE_METADATA_MISMATCH'):
            self.run_verification()

    def test_quality_or_q1_upgrade_is_not_silently_accepted(self):
        original = registration.prepare
        for field, value in [('quality_status', 'QUALITY_ACCEPTED'), ('q1_status', 'QUALIFIED')]:
            def altered(*a, **kw):
                report = original(*a, **kw)
                report[field] = value
                return report
            with self.subTest(field=field), patch.object(registration, 'prepare', side_effect=altered):
                with self.assertRaises(v.VerificationError):
                    self.run_verification()

    def test_schema2_explicit_production_grant_is_rejected(self):
        original = registration.read_json
        def altered(path):
            value = original(path)
            if Path(path).name == 'authorization.json':
                value['production_promotion'] = 'AUTHORIZED'
            return value
        with patch.object(registration, 'read_json', side_effect=altered):
            with self.assertRaises(v.VerificationError):
                self.run_verification()

    def test_schema2_controlled_or_unapproved_candidate_is_not_baseline(self):
        self.upstream_report['provenance_type'] = 'CONTROLLED_GIT_FIXTURE'
        with self.assertRaises(v.VerificationError):
            self.run_verification()
        self.upstream_report['provenance_type'] = 'GENUINE_UPSTREAM'
        self.upstream_report['receipt']['kind'] = 'CANDIDATE'
        with self.assertRaises(v.VerificationError):
            self.run_verification()

    def test_changed_policy_subject_hash_changes_without_claiming_approval(self):
        one = self.run_verification()
        two = self.run_verification(approval_policy_sha256='6' * 64)
        self.assertNotEqual(one['registration_subject_sha256'], two['registration_subject_sha256'])
        self.assertEqual(two['authorization'], 'NOT_VERIFIED')

    def test_missing_registry_entry_field_and_changed_registry_fail(self):
        path = self.entry.pop('build_policy_path')
        with self.assertRaises(v.VerificationError):
            self.run_verification()
        self.entry['build_policy_path'] = path
        def change_registry(*a, **kw):
            self.registry.write_bytes(self.registry_bytes + b' ')
            return self.qualified
        self.anchor.side_effect = change_registry
        try:
            with self.assertRaisesRegex(v.VerificationError, 'REGISTRY_CHANGED'):
                self.run_verification()
            self.assertEqual(self.registry.read_bytes(), self.registry_bytes + b' ')
        finally:
            self.registry.write_bytes(self.registry_bytes)

    def test_transport_errors_never_expose_token_or_remote_body(self):
        with patch.object(transport, '_request', side_effect=RuntimeError('offline-fixture-token')):
            with self.assertRaises(v.VerificationError) as caught:
                self.run_verification()
        self.assertNotIn('offline-fixture-token', str(caught.exception))
