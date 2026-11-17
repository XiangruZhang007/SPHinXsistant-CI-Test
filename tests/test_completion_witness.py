"""Repository-governed witness tests; GitHub observations are explicit mocks.

Actual miniature build/parity/R2/package verification is reused, never replaced
with a mocked successful verifier. These fixtures grant no Hosted authority.
"""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_scheduled_construction as fixtures
from src import continuous_completion as store, genuine_continuous_execution as g
from src.corpus_snapshot import file_digest, read_json


class PublishedAPI(fixtures.MemoryRelease):
    def _api(self, method, endpoint, payload=None, *, allow_404=False):
        if '/git/ref/tags/' in endpoint:
            self.calls.append((method, endpoint))
            return None if self.release is None else {'object': {'type': 'commit', 'sha': self.config['implementation_revision']}}
        value = super()._api(method, endpoint, payload, allow_404=allow_404)
        if '/actions/runs/' in endpoint and '/jobs?' in endpoint:
            value['jobs'][0].update(started_at='2026-01-01T00:01:00Z', completed_at='2026-01-01T00:02:00Z')
            value['jobs'].append({'id': 602, 'name': 'publish-continuous-candidate', 'run_id': self.run_id,
                'head_sha': self.config['implementation_revision'], 'status': 'completed', 'conclusion': 'success',
                'started_at': '2026-01-01T00:03:00Z', 'completed_at': '2026-01-01T00:05:00Z'})
            value['total_count'] = len(value['jobs'])
        elif '/actions/runs/' in endpoint:
            value.update(status='completed', conclusion='success', created_at='2026-01-01T00:00:00Z')
        return value


class WitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.ScheduledTests.setUpClass()
        cls.addClassCleanup(fixtures.ScheduledTests.doClassCleanups)
        case = cls.case = fixtures.ScheduledTests(); case.setUp(); cls.addClassCleanup(case.doCleanups)
        project, config = case.schedule()
        config.update(schema_version=4, completion_authority={
            'schema_version': 1, 'trust_model': store.TRUST_MODEL, 'workflow_id': 501,
            'publisher_actor_id': 7010, 'release_prefix': 'fixture-complete', 'previous_producers': []})
        cls.project, cls.config = project, config
        cls.raw = json.dumps(config, sort_keys=True); cls.pin = hashlib.sha256(cls.raw.encode()).hexdigest()
        cls.stack = ExitStack(); cls.addClassCleanup(cls.stack.close)
        cls.stack.enter_context(patch.dict(os.environ, {
            'CONTINUOUS_BUILD_DEPLOYMENT_JSON': cls.raw, 'CONTINUOUS_BUILD_DEPLOYMENT_SHA256': cls.pin}))
        client = PublishedAPI(config); client.event = 'schedule'
        cls.stack.enter_context(patch.object(store, 'Client', return_value=client))
        delivery = case.root / 'verified-producer'
        cls.result = g.execute(project, case.fx.detection_path, case.root / 'work', delivery)
        cls.prepared = store.prepare(project, delivery, case.root / 'prepared',
            pins=read_json(delivery / 'verification-inputs.json'), transport_sha256=file_digest(delivery / 'candidate.tar.gz'),
            verified_origin=store.origin(client, config, 401, 1))
        with patch.object(g.trust, '_request', side_effect=client.request):
            store.publish(project, client, config, cls.prepared, prefix='fixture-complete')
        client.release.update(author={'id': 7010, 'type': 'Bot'}, created_at='2026-01-01T00:03:01Z',
                              published_at='2026-01-01T00:04:00Z')
        for asset in client.release['assets']:
            asset.update(uploader={'id': 7010, 'type': 'Bot'}, created_at='2026-01-01T00:03:02Z', updated_at='2026-01-01T00:03:30Z')
        cls.prototype = client

    def setUp(self):
        self.client = deepcopy(self.prototype)
        self.temp = tempfile.TemporaryDirectory(prefix='completion-witness-case-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(store, 'Client', return_value=self.client))
        parent_request = g.trust._request
        def request(url, **kwargs):
            if any(url.endswith('/assets/' + str(aid)) for aid in self.client.data):
                return self.client.request(url, **kwargs)
            return parent_request(url, **kwargs)
        self.stack.enter_context(patch.object(g.trust, '_request', side_effect=request))
        self.before = self.case.fx.registry.read_bytes()

    def tearDown(self):
        self.assertEqual(self.before, self.case.fx.registry.read_bytes())
        self.assertEqual(self.client.mutations, self.prototype.mutations)

    def lookup(self, config=None, project=None):
        return store.lookup(project or self.project, self.client, config or self.config,
                            'fixture-complete', self.prepared['manifest']['execution_key'])

    def dispatch_consumer(self, run_id, config=None, project=None):
        config, project = config or self.config, project or self.project
        api = self.case.fx.api; base = 'repos/' + config['repository']
        current = {**api[base + '/actions/runs/401'], 'id': run_id, 'head_sha': config['implementation_revision']}
        raw = json.dumps(config, sort_keys=True)
        self.stack.enter_context(patch.dict(api, {base + '/actions/runs/' + str(run_id): current,
            base + '/contents/' + config['registry_path'] + '?ref=' + config['implementation_revision']:
                api[base + '/contents/' + config['registry_path'] + '?ref=' + self.config['implementation_revision']]}))
        self.stack.enter_context(patch.dict(api[base + '/git/ref/heads/research']['object'], {'sha': config['implementation_revision']}))
        self.stack.enter_context(patch.dict(os.environ, {'GITHUB_RUN_ID': str(run_id),
            'GITHUB_SHA': config['implementation_revision'], 'GITHUB_WORKFLOW_SHA': config['implementation_revision'],
            'GITHUB_WORKSPACE': str(project), 'CONTINUOUS_BUILD_DEPLOYMENT_JSON': raw,
            'CONTINUOUS_BUILD_DEPLOYMENT_SHA256': hashlib.sha256(raw.encode()).hexdigest()}))

    def test_repository_authority_automatically_verifies_all_bytes_without_receipt_repin(self):
        result = self.lookup()
        self.assertEqual(result['state'], 'PUBLISHED_AND_VERIFIED')
        self.assertEqual(result['completion_trust'], store.TRUST_MODEL)
        self.assertFalse(result['cryptographic_producer_attestation'])
        self.assertEqual(result['replay'], 'SEALED_REPLAY_INSPECTED')
        self.assertIsNone(self.config['completion_witness'])
        self.assertEqual(result['research_approval'], 'NOT_GRANTED')
        self.assertEqual(result['production_promotion'], 'NOT_AUTHORIZED')

    def test_distinct_runs_and_candidate_ids_same_key_skip_without_another_build(self):
        original = deepcopy(self.client.release); self.client.release = None
        self.dispatch_consumer(402)
        second = g.execute(self.project, self.case.fx.detection_path, self.root / 'work-second', self.root / 'second')
        self.assertNotEqual(second['candidate_id'], self.result['candidate_id'])
        key = read_json(self.root / 'second/run/evidence/authorization-context.json')['parent_comparison']['execution_key']
        self.assertEqual(key, self.prepared['manifest']['execution_key'])
        self.client.release = original
        self.dispatch_consumer(403)
        with patch.object(g, '_clone_sources', side_effect=AssertionError('Duplicate must not clone or construct')):
            result = g.execute(self.project, self.case.fx.detection_path, self.root / 'work-third', self.root / 'third')
        self.assertEqual(result['status'], 'NO_BUILD')
        self.assertEqual(result['completion']['producer_run_id'], 401)
        self.assertFalse((self.root / 'work-third').exists())

    def test_reviewed_old_producer_commit_and_new_consumer_are_separate(self):
        consumer = self.root / 'consumer'
        subprocess.run(['git', 'clone', '--no-hardlinks', str(self.project), str(consumer)], check=True, capture_output=True)
        subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        'commit', '--allow-empty', '-qm', 'Reviewed consumer-only deployment'], cwd=consumer, check=True)
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=consumer).decode().strip()
        config = deepcopy(self.config); config['implementation_revision'] = head
        config['completion_authority']['previous_producers'] = [{
            'implementation_revision': self.config['implementation_revision'], 'deployment_sha256': self.pin,
            'execution_contract_sha256': self.config['execution_contract_sha256']}]
        self.dispatch_consumer(402, config, consumer)
        result = g.execute(consumer, self.case.fx.detection_path, self.root / 'work', self.root / 'out')
        self.assertEqual(result['status'], 'NO_BUILD')
        self.assertNotEqual(result['completion']['consumer_commit'], result['completion']['producer_commit'])
        for field, reason in (('execution_contract_sha256', 'HISTORICAL_PRODUCER_ORIGINAL_VERIFIER_REQUIRED'),
                              ('deployment_sha256', 'UNREVIEWED_PRODUCER_DEPLOYMENT')):
            bad = deepcopy(config); bad['completion_authority']['previous_producers'][0][field] = '0' * 64
            raw = json.dumps(bad, sort_keys=True)
            with (self.subTest(field=field), patch.dict(os.environ, {
                    'CONTINUOUS_BUILD_DEPLOYMENT_JSON': raw,
                    'CONTINUOUS_BUILD_DEPLOYMENT_SHA256': hashlib.sha256(raw.encode()).hexdigest()}),
                  self.assertRaisesRegex(ValueError, reason)):
                self.lookup(bad, consumer)

    def test_unreviewed_consumer_or_authority_cannot_adopt_a_release(self):
        for field in ('trust_model', 'publisher_actor_id', 'workflow_id', 'release_prefix'):
            config = deepcopy(self.config); config['completion_authority'][field] = 'UNTRUSTED'
            with self.subTest(field=field), self.assertRaises(ValueError): self.lookup(config)
        config = deepcopy(self.config); config.pop('completion_authority')
        with self.assertRaises(ValueError): g._shape(config)

    def test_untrusted_writer_missing_digest_and_forged_receipt_fail_closed(self):
        original = deepcopy(self.client.release)
        for mutate in (lambda r: r['author'].update(id=900), lambda r: r['assets'][0]['uploader'].update(id=900),
                       lambda r: r['assets'][0].pop('digest'), lambda r: r.update(immutable=False),
                       lambda r: r.update(target_commitish='0' * 40)):
            self.client.release = deepcopy(original); mutate(self.client.release)
            with self.assertRaises(ValueError): self.lookup()
        self.client.release = deepcopy(original)
        receipt = next(a for a in self.client.release['assets'] if a['name'] == 'completion.json')
        data = json.loads(self.client.data[receipt['id']]); data['build_origin']['implementation_revision'] = '0' * 40
        raw = json.dumps(data).encode(); self.client.data[receipt['id']] = raw
        receipt.update(size=len(raw), digest='sha256:' + hashlib.sha256(raw).hexdigest())
        with self.assertRaisesRegex(ValueError, 'HISTORICAL_PRODUCER_NOT_REVIEWED'): self.lookup()

    def test_publisher_success_job_and_exact_attempt_are_required(self):
        actual = self.client._api
        for change in ('failure', 'cancelled', 'skipped', 'missing', 'duplicate', 'attempt'):
            def api(method, endpoint, *args, **kwargs):
                value = actual(method, endpoint, *args, **kwargs)
                if '/jobs?' in endpoint:
                    if change == 'missing': value['jobs'].pop()
                    elif change == 'duplicate': value['jobs'].append(deepcopy(value['jobs'][-1]))
                    elif change != 'attempt': value['jobs'][-1]['conclusion'] = change
                    value['total_count'] = len(value['jobs'])
                elif '/actions/runs/' in endpoint and change == 'attempt': value['run_attempt'] = 2
                return value
            with self.subTest(change=change), patch.object(self.client, '_api', side_effect=api), self.assertRaises(ValueError): self.lookup()

    def test_resealed_manifest_cannot_substitute_a_self_issued_deployment_pin(self):
        def replace(name, value):
            asset = next(a for a in self.client.release['assets'] if a['name'] == name)
            raw = json.dumps(value, sort_keys=True).encode(); self.client.data[asset['id']] = raw
            sha = hashlib.sha256(raw).hexdigest(); asset.update(size=len(raw), digest='sha256:' + sha)
            return sha
        manifest = deepcopy(self.prepared['manifest'])
        manifest['verification_pins']['expected_deployment_sha256'] = '0' * 64
        manifest_pin = replace('release-manifest.json', manifest)
        receipt = deepcopy(self.prepared['receipt']); receipt['manifest_sha256'] = manifest_pin
        replace('completion.json', receipt)
        with self.assertRaisesRegex(ValueError, 'UNREVIEWED_PRODUCER_DEPLOYMENT'): self.lookup()

    def test_cancelled_current_consumer_has_no_authority_to_skip_or_construct(self):
        self.dispatch_consumer(402)
        current = self.case.fx.api['repos/' + self.config['repository'] + '/actions/runs/402']
        with (patch.dict(current, {'status': 'completed', 'conclusion': 'cancelled'}),
              patch.object(self.client, '_api', side_effect=AssertionError('Consumer must fail before storage')),
              self.assertRaisesRegex(ValueError, 'GITHUB_WORKFLOW_RUN_BINDING_MISMATCH')):
            g.execute(self.project, self.case.fx.detection_path, self.root / 'work', self.root / 'out')
        self.assertFalse((self.root / 'work').exists()); self.assertFalse((self.root / 'out').exists())

    def test_current_scope_namespace_must_match_independently_reviewed_authority(self):
        config = deepcopy(self.config); config['completion_authority']['release_prefix'] = 'other-namespace'
        with self.assertRaisesRegex(ValueError, 'COMPLETION_NAMESPACE_NOT_AUTHORIZED'):
            g.scheduled.load(self.project, config)

    def test_published_but_failed_publisher_requires_explicit_manual_recovery(self):
        actual = self.client._api
        def api(method, endpoint, *args, **kwargs):
            value = actual(method, endpoint, *args, **kwargs)
            if '/jobs?' in endpoint: value['jobs'][-1]['conclusion'] = 'failure'
            return value
        with patch.object(self.client, '_api', side_effect=api), self.assertRaisesRegex(ValueError, 'MANUAL_RECOVERY_REQUIRED'):
            self.lookup()
        # Independent retained digest remains a separate, read-only recovery path.
        recovered = store.verify_completed(self.project, self.client, self.config, self.client.release,
            self.prepared['manifest']['execution_key'], expected_receipt_sha256=self.prepared['receipt_sha256'])
        self.assertEqual(recovered['state'], 'PUBLISHED_AND_VERIFIED')

    def test_asset_corruption_and_bad_inventory_are_not_completed(self):
        original = deepcopy(self.client.release)
        self.client.release['assets'].pop()
        with self.assertRaisesRegex(ValueError, 'INVENTORY'): self.lookup()
        self.client.release = original
        archive = next(a for a in self.client.release['assets'] if a['name'] == 'candidate.tar.gz')
        self.client.data[archive['id']] += b'corruption'
        with self.assertRaises(ValueError): self.lookup()

    def test_mismatched_tag_workflow_identity_and_times_are_rejected(self):
        actual = self.client._api
        for change in ('tag', 'workflow', 'repository', 'timestamps'):
            def api(method, endpoint, *args, **kwargs):
                value = actual(method, endpoint, *args, **kwargs)
                if '/git/ref/tags/' in endpoint and change == 'tag': value['object']['sha'] = '0' * 40
                if '/actions/workflows/' in endpoint and change == 'workflow': value['path'] = '.github/workflows/other.yml'
                if endpoint == '/repos/' + self.config['repository'] and change == 'repository': value['id'] = 999
                if '/releases/' in endpoint and change == 'timestamps': value['published_at'] = '2025-01-01T00:00:00Z'
                return value
            with self.subTest(change=change), patch.object(self.client, '_api', side_effect=api), self.assertRaises(ValueError): self.lookup()

    def test_schema3_still_requires_independent_digest_and_never_infers_new_trust(self):
        config = {**self.config, 'schema_version': 3}; config.pop('completion_authority')
        with self.assertRaisesRegex(ValueError, 'INDEPENDENT_COMPLETION_WITNESS_REQUIRED'): self.lookup(config)

    def test_explicit_authority_schema_rejects_unknown_duplicate_and_bool_ids(self):
        for modify in (lambda a: a.update(unexpected=True), lambda a: a.update(workflow_id=True),
                       lambda a: a.update(trust_model='SELF_ISSUED'), lambda a: a.update(previous_producers=[{
                           'implementation_revision': self.config['implementation_revision'],
                           'deployment_sha256': self.pin, 'execution_contract_sha256': self.config['execution_contract_sha256']}])):
            config = deepcopy(self.config); modify(config['completion_authority'])
            with self.assertRaises(ValueError): g._shape(config)

    def test_lost_final_response_read_only_recovery_is_idempotent(self):
        first = self.lookup(); self.assertEqual(first, self.lookup())
        self.assertEqual(first['publisher_job_id'], 602)
        self.assertEqual(first['consumer_deployment_sha256'], self.pin)

    def test_release_created_at_is_commit_date_not_a_publication_event(self):
        self.client.release['created_at'] = '2020-01-01T00:00:00Z'
        self.assertEqual(self.lookup()['state'], 'PUBLISHED_AND_VERIFIED')


if __name__ == '__main__':
    unittest.main()
