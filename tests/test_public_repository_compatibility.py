"""Offline identity/transport compatibility; no real Hosted approval or API write."""
from copy import deepcopy
import hashlib
import os
import unittest
from unittest.mock import patch

import test_notices_delivery as notices
import test_parent_authority_transition as transition_fixture
import test_hosted_parent_authority_transition as hosted_fixture
import test_parent_authority_git_audit as audit_fixture
import test_local_registration_integration as registration_fixture
from src import trusted_snapshot as trust, ci_v2_research as c
from src import parent_authority_git_audit as audit
from src import hosted_parent_authority_transition as hosted
from src.corpus_snapshot import digest, read_json

NAME = 'XiangruZhang007/SPHinXsistant-CI-Test'
ID = 1455203884


class PublicIdentityTests(unittest.TestCase):
    def test_only_exact_pinned_public_pair_and_historical_private_pairs(self):
        for private in (True, False):
            self.assertTrue(trust.repository_identity(
                {'id': ID, 'full_name': NAME, 'private': private}, NAME, ID))
        self.assertTrue(trust.repository_identity(
            {'id': 42, 'full_name': 'Fixture/Private', 'private': True}, 'Fixture/Private', 42))
        self.assertFalse(trust.repository_identity(
            {'id': 42, 'full_name': 'Fixture/Private', 'private': False}, 'Fixture/Private', 42))

    def test_wrong_public_repository_or_id_rejected_even_if_self_consistent(self):
        for name, number in ((NAME, ID + 1), ('Other/Repository', ID), (NAME.lower(), ID)):
            repo = {'id': number, 'full_name': name, 'private': False}
            self.assertFalse(trust.repository_identity(repo, name, number))
            self.assertFalse(trust.repository_identity(repo, NAME, ID))

    def test_explicit_visibility_policy_can_only_narrow(self):
        public = {'id': ID, 'full_name': NAME, 'private': False, 'visibility': 'public'}
        private = {**public, 'private': True, 'visibility': 'private'}
        self.assertFalse(trust.repository_identity(public, NAME, ID, required_visibility='private'))
        self.assertFalse(trust.repository_identity(private, NAME, ID, required_visibility='public'))
        self.assertTrue(trust.repository_identity(public, NAME, ID, required_visibility='public'))
        self.assertFalse(trust.repository_identity(public, NAME, ID, required_visibility='internal'))

    def test_missing_or_inconsistent_visibility_and_noninteger_ids_rejected(self):
        valid = {'id': ID, 'full_name': NAME, 'private': False}
        for change in ({'id': True}, {'id': str(ID)}, {'private': None}, {'private': 0},
                       {'visibility': 'private'}, {'visibility': 'internal'}):
            self.assertFalse(trust.repository_identity({**valid, **change}, NAME, ID))


class PublicTransportTests(unittest.TestCase):
    def setUp(self):
        self.f = notices.NoticesDeliveryTests(); self.f.setUp(NAME, ID)
        self.addCleanup(self.f.doCleanups)
        self.f.api_changes['repository'] = {'private': False, 'visibility': 'public'}
        self.env = patch.dict(os.environ, self.f.env); self.env.start(); self.addCleanup(self.env.stop)
        self.api = patch.object(trust, '_request', side_effect=self.f.request)
        self.mock = self.api.start(); self.addCleanup(self.api.stop)

    def fetch(self, **kwargs):
        return trust.download(self.f.ref['notices']['storage'], self.f.root / 'download.zip',
            self.f.ref['notices']['sha256'], token='synthetic-token-never-log', **kwargs)

    def test_existing_v3_kind_downloads_all_three_pinned_assets_from_public_target(self):
        ref = self.f.ref; original = digest(ref)
        for i, (storage, pin) in enumerate(((ref['storage'], ref['transport_sha256']),
                (ref['parent_rows_storage'], ref['parent_rows_sha256']),
                (ref['notices']['storage'], ref['notices']['sha256']))):
            path = self.f.root / ('asset-' + str(i))
            trust.download(storage, path, pin, token='synthetic-token-never-log')
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), pin)
        self.assertEqual(digest(ref), original)
        self.assertEqual(ref['storage']['kind'], 'GITHUB_PRIVATE_RELEASE_ASSET')

    def test_public_notices_fetch_and_restore_gate_keep_exact_binding(self):
        path = trust.fetch_notices(self.f.ref, digest(self.f.ref), self.f.root / 'public.zip')
        self.assertEqual(trust.verify_notices(self.f.ref, digest(self.f.ref), path)['status'], 'NOTICES_VERIFIED')
        self.f.assert_restore_rejected_before_staging()

    def test_public_target_does_not_drop_token_or_runtime_repository_binding(self):
        with self.assertRaises(c.GateError):
            trust.download(self.f.ref['notices']['storage'], self.f.root / 'none',
                           self.f.ref['notices']['sha256'])
        self.mock.assert_not_called()
        with patch.dict(os.environ, {'GITHUB_REPOSITORY_ID': '999'}), self.assertRaises(c.GateError):
            self.fetch()

    def test_transport_explicit_private_policy_rejects_public_before_asset_download(self):
        with self.assertRaises(c.GateError): self.fetch(required_visibility='private')
        self.assertFalse((self.f.root / 'download.zip').exists())
        self.assertFalse(any('/releases/' in u for u in self.f.requests))

    def test_wrong_public_metadata_identity_and_visibility_rejected(self):
        for change in ({'id': ID + 1}, {'full_name': 'Other/Repository'}, {'visibility': 'internal'}):
            self.f.api_changes['repository'] = {'private': False, **change}
            with self.subTest(change=change), self.assertRaises(c.GateError): self.fetch()

    def test_wrong_public_asset_id_rejected(self):
        self.f.api_changes['id'] = 999
        with self.assertRaises(c.GateError): self.fetch()
        self.assertFalse((self.f.root / 'download.zip').exists())

    def test_wrong_public_asset_digest_or_bytes_rejected(self):
        self.f.data[53] = b'X' * len(self.f.data[53])
        self.f.api_changes['digest'] = None  # Real byte hash still mandatory.
        with self.assertRaises(c.GateError): self.fetch()
        self.assertFalse((self.f.root / 'download.zip').exists())

    def test_wrong_public_release_identity_or_mutability_rejected(self):
        for change in ({'id': 999}, {'immutable': False}, {'draft': True}):
            self.f.api_changes['release'] = change
            with self.subTest(change=change), self.assertRaises(c.GateError): self.fetch()

    def test_reference_and_registry_pins_cannot_be_rebound(self):
        ref = self.f.ref
        with self.assertRaises(c.GateError): trust.validate_reference(ref, '0' * 64, remote=True)
        registry = {'schema_version': 2, 'baselines': {'fixture': {
            'entry_kind': 'REGISTRATION_ONLY', 'reference': ref, 'expected_reference_sha256': '0' * 64}}}
        with self.assertRaises(c.GateError): trust.registry_reference(registry, 'fixture')

    def test_original_registered_reference_bytes_need_no_migration(self):
        ref = read_json(trust.REGISTRY)['baselines']['official-research-parent-9519233d']['reference']
        pin = '83df3259b292e3e0323b19fbe1bb5b01afd4f74cfdb8b96f452b1da2468d8724'
        self.assertEqual(digest(ref), pin)
        trust.validate_reference(ref, pin, remote=True)
        self.assertEqual(ref['storage']['repository'], NAME)
        self.assertEqual(ref['notices']['storage']['repository_id'], ID)


class PublicOwnerAndAuditTests(unittest.TestCase):
    def fixture(self):
        f = hosted_fixture.InvocationTests(); f.setUp(NAME, ID); self.addCleanup(f.doCleanups)
        f.repo.update(private=False, visibility='public')
        return f

    def test_actual_observer_accepts_exact_public_subject_without_granting_authority(self):
        f = self.fixture(); result = f.observe()
        self.assertEqual(result['status'], 'API_OWNER_TRANSITION_SUBJECT_VERIFIED')
        self.assertEqual(result['authorization'], 'NOT_GRANTED')
        self.assertFalse(result['durable_transaction_reserved'])

    def test_public_observer_still_rejects_wrong_identity_actor_attempt_and_checkout(self):
        f = self.fixture()
        for row, key, bad in ((f.repo, 'id', 7), (f.repo, 'full_name', 'Other/Repository'),
                             (f.run['actor'], 'id', 7), (f.run['triggering_actor'], 'id', 7),
                             (f.run, 'run_attempt', 2), (f.run, 'head_sha', '0' * 40)):
            original = row[key]; row[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError): f.observe()
            row[key] = original

    def test_public_observer_cannot_enable_live_apply_with_valid_subject(self):
        f = self.fixture()
        with f.boundaries(), patch.dict(os.environ, f.deploy_env()): result = hosted._run(f.root)
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(result['reason'], 'DURABLE_CROSS_RUN_TRANSACTION_BACKEND_NOT_CONFIGURED')

    def test_public_audit_preserves_direct_child_consumption_and_duplicate_denial(self):
        f = transition_fixture.TransitionTests(); f.setUp(NAME, ID); self.addCleanup(f.doCleanups)
        proposal, decision, expected = f.proposal_and_decision()
        subject_pin = digest(hosted.subject(proposal['request'], digest(proposal), decision['workflow_id']))
        binding = audit._binding(proposal, decision, expected_proposal_sha256=digest(proposal),
            expected_subject_sha256=subject_pin, expected_actor_id=101, expected_run_id=102)
        config = {'schema_version': 1, 'repository': NAME, 'repository_id': ID,
            'ref': 'refs/heads/ci-v2-authority-audit/' + decision['transaction_id'],
            'genesis_sha': 'a' * 40, 'tree_sha': 'b' * 40, 'governance_sha256': 'c' * 64}
        model = audit_fixture.GitModel(config, binding); model.repo.update(private=False, visibility='public')
        client = audit._IsolatedGitProtocol(model, config, binding)
        self.assertEqual(client.reserve()['status'], 'RESERVED')
        self.assertEqual(client.consume()['status'], 'CONSUMED_OFFLINE')
        self.assertEqual(client.consume()['status'], 'CONSUMPTION_DENIED')
        self.assertEqual(audit._IsolatedGitProtocol(model, config, binding).reserve()['status'], 'RESERVATION_NOT_GRANTED')
        for method, _, body in model.calls:
            if method == 'POST': self.assertEqual(len(body['parents']), 1)
            if method == 'PATCH': self.assertIs(body['force'], False)
        self.assertEqual(audit.backend_status()['status'], 'BLOCKED')

    def test_public_local_origin_registration_owner_check_uses_existing_subject(self):
        f = registration_fixture.LocalRegistrationTests(); f.setUp(NAME, ID); self.addCleanup(f.doCleanups)
        f.api_repo.update(private=False, visibility='public')
        self.assertEqual(f.approval()['status'], 'OWNER_APPROVAL_VERIFIED')
        f.run['triggering_actor']['id'] = 99
        self.assertEqual(f.approval()['status'], 'BLOCKED')
        self.assertEqual(f.registry.read_bytes(), f.old)


class RemainingIdentityGateTests(unittest.TestCase):
    def test_public_build_publication_and_historical_gates_preserve_subsequent_validation(self):
        from src import continuous_completion as completion, genuine_continuous_execution as genuine
        from src import candidate_release_archive as archive, historical_candidate_archive as historical
        from src import owner_manual_baseline_approval as owner
        class AfterIdentity(Exception): pass
        class Client:
            calls = 0
            def _api(self, *args, **kwargs):
                self.calls += 1
                if self.calls == 1:
                    return {'id': ID, 'full_name': NAME, 'private': False, 'default_branch': 'main'}
                raise AfterIdentity('subsequent validation reached')
            def json(self, *args): return self._api(*args)
        policy = {'repository': NAME, 'repository_id': ID, 'default_branch': 'main'}
        context = {'run_id': 1, 'run_attempt': 1, 'actor_id': 1, 'ref': 'refs/heads/main'}
        publisher = archive.GitHubReleasePublisher('synthetic-token')
        for operation in ('schedule', 'completion', 'historical', 'archive-origin', 'archive-publication'):
            client = Client()
            error = owner.OwnerApprovalError if operation == 'schedule' else AfterIdentity
            with self.subTest(operation=operation), self.assertRaises(error) as caught:
                if operation == 'schedule': genuine._scheduled_identity(client, policy, context)
                elif operation == 'completion': completion.origin(client, policy, 1, 1)
                elif operation == 'historical': historical.verify_original(client, policy, {'original': {'run_id': 1}})
                else:
                    with patch.object(publisher, '_api', side_effect=client._api):
                        if operation == 'archive-origin':
                            publisher.verify_origin(run_id=1, attempt=1, head_sha='a' * 40,
                                artifact_id=1, artifact_digest='sha256:' + 'b' * 64)
                        else: publisher.publish({}, run_id=1, attempt=1, head_sha='a' * 40,
                                                candidate_id='sha256-' + 'b' * 64)
            if operation == 'schedule':
                self.assertIsInstance(caught.exception.__cause__, AfterIdentity)
                self.assertEqual(str(caught.exception), 'GITHUB_WORKFLOW_RUN_UNAVAILABLE')


if __name__ == '__main__':
    unittest.main()
