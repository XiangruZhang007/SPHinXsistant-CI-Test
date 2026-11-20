"""Offline V1 proposals and unauthenticated decisions; no real Owner/build.

Synthetic publication identities and notices are explicitly inherited from the
existing notices fixture. No live APIs, genuine packages or R2 are invoked.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import test_notices_delivery as notices_fixtures
from src import parent_authority_transition as transition
from src import continuous_build_policy as continuous, ci_v2_research as research
from src import schema2_workflow as workflow, upstream_provenance as provenance
from src.corpus_snapshot import digest

P = Path(__file__).resolve().parents[1]


class TransitionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = notices_fixtures.NoticesDeliveryTests()
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        (self.root / 'configs').mkdir()
        self.ref = deepcopy(self.fixture.ref)
        scoped_environment = patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'FixtureOwner/NoticesTest', 'GITHUB_REPOSITORY_ID': '42'})
        scoped_environment.start(); self.addCleanup(scoped_environment.stop)
        self.entry = {'entry_kind': 'REGISTRATION_ONLY', 'reference': self.ref,
                      'expected_reference_sha256': digest(self.ref)}
        self.registry = {'schema_version': 2, 'retained_registration_audit': {'id': 'synthetic-old'},
                         'baselines': {'fixture-parent': self.entry}}
        self.registry_path = 'configs/registry.json'
        self.save(self.registry_path, self.registry)
        self.targets = {'SPHinXsys': 'd' * 40, 'SPHinXsim': 'e' * 40}
        self.build = {'schema_version': 2, 'operation': 'BUILD_CANDIDATE',
            'research_only': True, 'experiment_id': 'SYNTHETIC_NOT_AUTHORIZATION',
            'provenance_type': 'GENUINE_UPSTREAM', 'automatic_reuse': False,
            'automatic_research_approval': False, 'production_promotion': 'NOT_AUTHORIZED',
            'scope': {'parent': {'kind': 'RESEARCH_BASELINE', 'node_id': self.ref['node_id'],
                                'package_checksum': self.ref['package_checksum']},
                'base_source_state': self.ref['source_state'],
                'target_source_state': 'sha256-' + 'f' * 64,
                'base_upstreams': self.ref['upstreams'], 'target_upstreams': self.targets,
                'build_fingerprint': self.ref['build_fingerprint'],
                'orchestration_fingerprint': digest(provenance.contract(P))}}
        self.save('configs/build.json', self.build)
        now = datetime.now(timezone.utc)
        self.scope = {'schema_version': 1, 'mode': 'CONTINUOUS_SCOPE', 'operation': 'BUILD_CANDIDATE',
            'policy_id': 'synthetic-not-approved', 'enabled': True, 'research_only': True,
            'valid_from': (now - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'expires_at': (now + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'upstreams': {name: {'url': url, 'repository_id': i,
                                'branch': 'master' if name == 'SPHinXsys' else 'main'}
                          for i, (name, url) in enumerate(research.SOURCES.items(), 1)},
            'eligible_parents': [{'key': 'fixture-parent', 'node_id': self.ref['node_id'],
                'package_checksum': self.ref['package_checksum'],
                'expected_reference_sha256': digest(self.ref)}],
            'build_fingerprint': self.ref['build_fingerprint'],
            'orchestration_fingerprint': self.build['scope']['orchestration_fingerprint'],
            'max_advance_commits': 32, 'requirements': deepcopy(continuous.REQUIREMENTS),
            'automatic_registration': False, **research.RESTRICTIONS}
        self.save('configs/continuous.json', self.scope)
        self.owner = {'schema_version': 1, 'enabled': True,
            'repository': 'FixtureOwner/NoticesTest', 'repository_id': 42,
            'default_branch': 'ci-upstream-refresh',
            'workflow_path': '.github/workflows/transition-fixture.yml',
            'registry_path': self.registry_path, 'allow_repository_owner': True,
            'authorized_approver_ids': []}
        self.save('configs/owner.json', self.owner)
        proposed = {'reference': self.ref, 'expected_reference_sha256': digest(self.ref),
                    'build_policy_path': 'configs/build.json',
                    'build_policy_sha256': self.pin('configs/build.json')}
        result = deepcopy(self.registry); result['baselines']['fixture-parent'] = proposed
        self.expected_result = self.serialize(result)
        self.request = {'schema_version': 1, 'operation': transition.OPERATION,
            **{k: self.owner[k] for k in ('repository', 'repository_id', 'default_branch',
                                           'workflow_path', 'registry_path')},
            'implementation_revision': '1' * 40, 'registry_key': 'fixture-parent',
            'old_registry_sha256': self.pin(self.registry_path), 'baseline_id': self.ref['node_id'],
            'reference_sha256': digest(self.ref), 'notices_sha256': self.ref['notices']['sha256'],
            'build_policy_path': 'configs/build.json', 'build_policy_sha256': self.pin('configs/build.json'),
            'continuous_policy_path': 'configs/continuous.json',
            'continuous_policy_sha256': self.pin('configs/continuous.json'),
            'owner_policy_path': 'configs/owner.json', 'owner_policy_sha256': self.pin('configs/owner.json'),
            'target_upstreams': self.targets, 'target_source_state': self.build['scope']['target_source_state'],
            'result_registry_sha256': hashlib.sha256(self.expected_result).hexdigest(),
            'transaction_id': '2' * 32, 'resulting_authority': 'RESTRICTED_BUILD_CANDIDATE_ONLY'}

    @staticmethod
    def serialize(obj):
        return (json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()

    def save(self, name, obj):
        (self.root / name).write_bytes(self.serialize(obj))

    def pin(self, name):
        return hashlib.sha256((self.root / name).read_bytes()).hexdigest()

    def prepare(self, request=None, **overrides):
        request = self.request if request is None else request
        return transition.prepare(self.root, request, **{
            'expected_request_sha256': digest(request),
            'expected_implementation_revision': '1' * 40,
            'notices_path': self.fixture.path, **overrides})

    def proposal_and_decision(self):
        p = self.prepare(); r = p['request']
        d = {'schema_version': 1, 'operation': transition.OPERATION,
            'decision': 'APPROVE_RESTRICTED_BUILD_AUTHORITY_TRANSITION',
            'proposal_sha256': digest(p), 'request_sha256': p['request_sha256'],
            **{k: r[k] for k in ('transaction_id', 'repository', 'repository_id',
               'implementation_revision', 'old_registry_sha256', 'result_registry_sha256',
               'continuous_policy_sha256', 'workflow_path')},
            'actor_id': 101, 'triggering_actor_id': 101, 'run_id': 102,
            'run_attempt': 1, 'workflow_id': 103, 'event': 'workflow_dispatch'}
        expected = dict(expected_proposal_sha256=digest(p), expected_transaction_id='2' * 32,
                        expected_actor_id=101, expected_run_id=102)
        return p, d, expected

    def test_prepare_is_deterministic_nonoperative_and_does_not_write(self):
        before = {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        one = self.prepare(); self.assertEqual(one, self.prepare())
        self.assertEqual(one['authorization'], 'NOT_GRANTED'); self.assertFalse(one['operative'])
        self.assertNotIn('baselines', one)
        self.assertEqual(one['result_registry_sha256'], hashlib.sha256(self.expected_result).hexdigest())
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_request_pin_is_independent(self):
        with self.assertRaisesRegex(transition.TransitionError, 'REQUEST_PIN'):
            self.prepare(expected_request_sha256='0' * 64)

    def test_registration_request_versions_are_not_transition_requests(self):
        for version in (1, 2, 3):
            with self.subTest(version=version), self.assertRaises(transition.TransitionError):
                self.prepare({'schema_version': version, 'registry_key': 'fixture-parent',
                              'proposed_entry': self.entry})

    def test_wrong_operation(self):
        r = deepcopy(self.request); r['operation'] = 'TRUSTED_RESEARCH_PARENT_REGISTRATION'
        with self.assertRaisesRegex(transition.TransitionError, 'WRONG_TRANSITION_OPERATION'):
            self.prepare(r)

    def test_repository_and_implementation_binding(self):
        for name, value in [('repository', 'Wrong/Repository'), ('repository_id', 99),
                            ('implementation_revision', '9' * 40)]:
            r = deepcopy(self.request); r[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError): self.prepare(r)

    def test_wrong_old_registry_digest(self):
        r = deepcopy(self.request); r['old_registry_sha256'] = '0' * 64
        with self.assertRaises(ValueError): self.prepare(r)

    def test_wrong_parent_key_or_baseline(self):
        for name, value in [('registry_key', 'new-alias'), ('baseline_id', 'sha256-' + '0' * 64)]:
            r = deepcopy(self.request); r[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError): self.prepare(r)

    def test_wrong_reference_or_notices_pin(self):
        for name in ('reference_sha256', 'notices_sha256'):
            r = deepcopy(self.request); r[name] = '0' * 64
            with self.subTest(name=name), self.assertRaises(ValueError): self.prepare(r)

    def test_missing_corrupt_or_misbound_notices(self):
        with self.assertRaises(ValueError): self.prepare(notices_path=None)
        original = self.fixture.path.read_bytes()
        self.fixture.path.write_bytes(b'bad ZIP')
        with self.assertRaises(ValueError): self.prepare()
        self.fixture.path.write_bytes(original)
        self.fixture.make_zip(mutate=lambda files: files.update({
            'source-and-license-mapping.json': b'{"baseline_id":"wrong","transport_sha256":"wrong"}'}))
        with self.assertRaises(ValueError): self.prepare()

    def test_wrong_build_or_continuous_policy_pin(self):
        for name in ('build_policy_sha256', 'continuous_policy_sha256', 'owner_policy_sha256'):
            r = deepcopy(self.request); r[name] = '0' * 64
            with self.subTest(name=name), self.assertRaises(ValueError): self.prepare(r)

    def test_wrong_target_revision_or_source_state(self):
        for name, value in [('target_upstreams', {**self.targets, 'SPHinXsim': '0' * 40}),
                            ('target_source_state', 'sha256-' + '0' * 64)]:
            r = deepcopy(self.request); r[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError): self.prepare(r)

    def test_bounded_scope_and_parent_binding_required(self):
        for field, value in [('max_advance_commits', 0), ('eligible_parents', []),
                             ('scheduled_execution', True), ('automatic_registration', True)]:
            changed = deepcopy(self.scope); changed[field] = value
            self.save('configs/continuous.json', changed)
            r = deepcopy(self.request); r['continuous_policy_sha256'] = self.pin('configs/continuous.json')
            with self.subTest(field=field), self.assertRaises(ValueError): self.prepare(r)

    def test_wrong_result_digest_and_unrelated_changes(self):
        r = deepcopy(self.request); r['result_registry_sha256'] = '0' * 64
        with self.assertRaises(ValueError): self.prepare(r)
        result = json.loads(self.expected_result)
        result['retained_registration_audit']['id'] = 'tampered'
        r['result_registry_sha256'] = hashlib.sha256(self.serialize(result)).hexdigest()
        with self.assertRaises(ValueError): self.prepare(r)

    def test_duplicate_baseline_cannot_be_bypassed_with_alias(self):
        self.registry['baselines']['alias'] = deepcopy(self.entry)
        self.save(self.registry_path, self.registry)
        r = deepcopy(self.request); r['old_registry_sha256'] = self.pin(self.registry_path)
        with self.assertRaisesRegex(transition.TransitionError, 'DUPLICATE_PARENT_BINDING'):
            self.prepare(r)

    def test_changed_registry_bytes_or_reference_fail(self):
        (self.root / self.registry_path).write_bytes(self.serialize(self.registry) + b' ')
        with self.assertRaises(ValueError): self.prepare()

    def test_repinning_a_changed_reference_does_not_preserve_parent_binding(self):
        changed = deepcopy(self.registry)
        changed['baselines']['fixture-parent']['reference']['corpus_sha256'] = '0' * 64
        changed['baselines']['fixture-parent']['expected_reference_sha256'] = digest(
            changed['baselines']['fixture-parent']['reference'])
        self.save(self.registry_path, changed)
        r = deepcopy(self.request); r['old_registry_sha256'] = self.pin(self.registry_path)
        with self.assertRaises(ValueError): self.prepare(r)

    def test_existing_consumers_reject_old_registry_and_proposal(self):
        with self.assertRaises(research.GateError):
            workflow.plan(self.root, self.registry, 'fixture-parent', self.targets)
        with self.assertRaises(research.GateError):
            continuous._parent(self.root, self.registry, self.scope)
        proposal = self.prepare()
        with self.assertRaises(ValueError):
            workflow.plan(self.root, proposal, 'fixture-parent', self.targets)

    def test_synthetic_decision_is_consistency_only_not_owner_approval(self):
        p, d, expected = self.proposal_and_decision()
        inspected = transition.inspect_owner_decision(p, d, **expected)
        self.assertFalse(inspected['live_owner_verified']); self.assertFalse(inspected['replay_consumed'])
        self.assertEqual(inspected['authorization'], 'NOT_GRANTED')
        before = (self.root / self.registry_path).read_bytes()
        for entrypoint in (transition.authorize, transition.apply):
            with self.assertRaisesRegex(transition.TransitionError, 'TRUSTED_OWNER_TRANSITION_INVOCATION_NOT_IMPLEMENTED'):
                entrypoint(p, d, **expected)
        self.assertEqual(before, (self.root / self.registry_path).read_bytes())

    def test_actual_registered_parent_still_has_no_build_authority(self):
        actual = json.loads((P / 'configs/ci_v2_schema2_trusted_baselines.json').read_text())
        key = 'official-research-parent-9519233d'
        ref = actual['baselines'][key]['reference']
        with patch.dict(os.environ, {'GITHUB_REPOSITORY': ref['storage']['repository'],
                                     'GITHUB_REPOSITORY_ID': str(ref['storage']['repository_id'])}):
            with self.assertRaises(research.GateError) as error:
                workflow.plan(P, actual, key, ref['upstreams'])
        self.assertEqual(error.exception.status, 'AUTHORIZATION_FAILED')

    def test_missing_self_declared_and_registration_approvals_fail(self):
        p, d, expected = self.proposal_and_decision()
        for bad in (None, {'approved': True}, {'status': 'OWNER_APPROVAL_VERIFIED',
                      'decision': 'APPROVED_FOR_TRUSTED_RESEARCH_PARENT_REGISTRATION_ONLY'}):
            with self.subTest(bad=bad), self.assertRaises(transition.TransitionError):
                transition.authorize(p, bad, **expected)

    def test_wrong_owner_operation_actor_repository_and_implementation_fail(self):
        p, d, expected = self.proposal_and_decision()
        for field, value in [('operation', 'TRUSTED_RESEARCH_PARENT_REGISTRATION'),
            ('actor_id', 999), ('triggering_actor_id', 999), ('repository', 'Wrong/Repo'),
            ('repository_id', 1), ('implementation_revision', '9' * 40),
            ('workflow_path', '.github/workflows/old-registration.yml')]:
            bad = deepcopy(d); bad[field] = value
            with self.subTest(field=field), self.assertRaises(transition.TransitionError):
                transition.inspect_owner_decision(p, bad, **expected)

    def test_replay_attempt_transaction_and_run_mismatch_fail(self):
        p, d, expected = self.proposal_and_decision()
        for field, value in [('run_attempt', 2), ('run_attempt', True),
                              ('transaction_id', '9' * 32), ('run_id', 999)]:
            bad = deepcopy(d); bad[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(transition.TransitionError):
                transition.inspect_owner_decision(p, bad, **expected)

    def test_tampered_proposal_or_result_not_reapproved_by_saved_decision(self):
        p, d, expected = self.proposal_and_decision()
        modified = deepcopy(p); modified['proposed_entry']['build_policy_sha256'] = '0' * 64
        with self.assertRaises(transition.TransitionError):
            transition.inspect_owner_decision(modified, d, **expected)
        bad = deepcopy(d); bad['result_registry_sha256'] = '0' * 64
        with self.assertRaises(transition.TransitionError):
            transition.inspect_owner_decision(p, bad, **expected)

    def test_production_or_general_authority_request_denied(self):
        r = deepcopy(self.request); r['resulting_authority'] = 'PRODUCTION_ACTIVATION'
        with self.assertRaises(transition.TransitionError): self.prepare(r)

    def test_rehashed_internally_inconsistent_proposal_is_rejected(self):
        p, d, expected = self.proposal_and_decision()
        for field, value in [('schema_version', True), ('production_promotion', 'AUTHORIZED'),
                              ('result_registry_sha256', '0' * 64)]:
            bad = deepcopy(p); bad[field] = value
            altered = {**expected, 'expected_proposal_sha256': digest(bad)}
            changed_decision = {**d, 'proposal_sha256': digest(bad)}
            with self.subTest(field=field), self.assertRaises(transition.TransitionError):
                transition.inspect_owner_decision(bad, changed_decision, **altered)

    def test_decision_cannot_rebind_notice_receipt(self):
        p, d, expected = self.proposal_and_decision()
        p['notices_verification']['notices_sha256'] = '0' * 64
        changed = {**expected, 'expected_proposal_sha256': digest(p)}
        d['proposal_sha256'] = digest(p)
        with self.assertRaisesRegex(transition.TransitionError, 'NOTICES_RECEIPT_BINDING_MISMATCH'):
            transition.inspect_owner_decision(p, d, **changed)

    def test_result_metadata_and_unrelated_entries_remain_unchanged(self):
        proposal = self.prepare()
        result = json.loads(transition._result_bytes(self.registry, 'fixture-parent', proposal['proposed_entry']))
        self.assertEqual(result['retained_registration_audit'], self.registry['retained_registration_audit'])
        self.assertEqual(result['baselines']['fixture-parent']['reference'], self.ref)
        self.assertEqual(self.entry['entry_kind'], 'REGISTRATION_ONLY')

    def test_unrelated_registered_parent_is_preserved_exactly(self):
        other = deepcopy(self.entry); other_ref = other['reference']
        other_ref['node_id'] = 'sha256-' + '9' * 64
        other_ref['corpus_sha256'] = '8' * 64
        other_ref['notices']['baseline_id'] = other_ref['node_id']
        other['expected_reference_sha256'] = digest(other_ref)
        self.registry['baselines']['unrelated'] = other
        self.save(self.registry_path, self.registry)
        result = json.loads(self.expected_result); result['baselines']['unrelated'] = other
        r = deepcopy(self.request)
        r['old_registry_sha256'] = self.pin(self.registry_path)
        r['result_registry_sha256'] = hashlib.sha256(self.serialize(result)).hexdigest()
        proposal = self.prepare(r)
        new = json.loads(transition._result_bytes(self.registry, 'fixture-parent', proposal['proposed_entry']))
        self.assertEqual(new['baselines']['unrelated'], other)
        self.assertEqual(new['retained_registration_audit'], self.registry['retained_registration_audit'])


if __name__ == '__main__':
    unittest.main()
