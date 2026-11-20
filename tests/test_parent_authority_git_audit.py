"""Deterministic isolated Git REST model; no remote calls or genuine approvals."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

import test_parent_authority_transaction as core_tests
from src import parent_authority_git_audit as audit
from src import hosted_parent_authority_transition as hosted
from src.corpus_snapshot import canonical, digest


class GitModel:
    """Models Git ancestry fast-forward, deliberately NOT an expected-old CAS.

    Statuses are API fixtures, not proof of real GitHub storage/governance.
    The fake has shared server state across independent client instances.
    """
    def __init__(self, config, binding):
        self.config = config
        self.lock = threading.RLock()
        self.repo = {'full_name': config['repository'], 'id': config['repository_id'], 'private': True}
        root = {'sha': config['genesis_sha'], 'tree': {'sha': config['tree_sha']},
                'parents': [], 'message': audit._message(audit._genesis(config, binding))}
        self.objects = {root['sha']: root}
        self.head = root['sha']
        self.calls = []
        self.before_patch = None
        self.failure = None
        self.fail_reads = False
        self.barrier = None

    def ancestor(self, old, new):
        if old == new:
            return True
        return any(self.ancestor(old, p['sha']) for p in self.objects[new]['parents'])

    def request(self, method, endpoint, body):
        self.calls.append((method, endpoint, deepcopy(body)))
        if method == 'PATCH' and self.barrier:
            self.barrier.wait(timeout=5)
        with self.lock:
            if method == 'GET' and self.fail_reads:
                raise OSError('simulated sensitive transport error, must not be retained')
            suffix = endpoint.removeprefix('repos/' + self.config['repository'])
            if method == 'GET' and suffix == '':
                return 200, deepcopy(self.repo)
            if method == 'GET' and suffix == '/git/ref/' + self.config['ref'][5:]:
                return 200, {'ref': self.config['ref'], 'object': {'type': 'commit', 'sha': self.head}}
            if method == 'GET' and suffix.startswith('/git/commits/'):
                return 200, deepcopy(self.objects[suffix.rsplit('/', 1)[1]])
            if method == 'POST' and suffix == '/git/commits':
                if self.failure == 'create_timeout_before':
                    raise TimeoutError()
                # Fake object hashes are fixture IDs, not raw Git-object verification.
                sha = hashlib.sha1(canonical(body)).hexdigest()
                self.objects[sha] = {'sha': sha, 'tree': {'sha': body['tree']},
                    'parents': [{'sha': p, 'url': 'https://api.github.com/fixture'} for p in body['parents']],
                    'message': body['message']}
                if self.failure == 'create_timeout_after':
                    raise TimeoutError()
                return 201, {'sha': sha}
            if method == 'PATCH' and suffix == '/git/refs/' + self.config['ref'][5:]:
                if self.before_patch:
                    self.before_patch()
                if self.failure == 'timeout_before':
                    raise TimeoutError()
                if self.failure in (403, 409, 422):
                    return self.failure, {}
                if body['force'] is not False or not self.ancestor(self.head, body['sha']):
                    return 422, {}
                self.head = body['sha']
                if self.failure == 'timeout_after':
                    raise TimeoutError()
                if self.failure == 'readback':
                    self.fail_reads = True
                return 200, {'ref': self.config['ref'], 'object': {'sha': self.head, 'type': 'commit'}}
            raise AssertionError((method, suffix))


class DurableAuditTests(unittest.TestCase):
    def setUp(self):
        # Reuse the actual B4 synthetic Parent/Proposal/Owner and isolated writer.
        self.f = core_tests.TransactionTests(); self.f.setUp(); self.addCleanup(self.f.doCleanups)
        self.p = self.f.proposal
        r = self.p['request']; observed = self.f.observed; actor = observed['workflow_run']
        self.decision = {'schema_version': 1, 'operation': audit.transition.OPERATION,
            'decision': 'APPROVE_RESTRICTED_BUILD_AUTHORITY_TRANSITION',
            'proposal_sha256': digest(self.p), 'request_sha256': self.p['request_sha256'],
            **{k: r[k] for k in ('transaction_id', 'repository', 'repository_id',
               'implementation_revision', 'old_registry_sha256', 'result_registry_sha256',
               'continuous_policy_sha256', 'workflow_path')},
            'actor_id': actor['actor_id'], 'triggering_actor_id': actor['actor_id'],
            'run_id': actor['run_id'], 'run_attempt': 1, 'workflow_id': actor['workflow_id'],
            'event': 'workflow_dispatch'}
        self.subject = observed['subject_sha256']
        self.kwargs = {'expected_proposal_sha256': digest(self.p),
            'expected_subject_sha256': self.subject, 'expected_actor_id': actor['actor_id'],
            'expected_run_id': actor['run_id']}
        self.binding = audit._binding(self.p, self.decision, **self.kwargs)
        self.config = {'schema_version': 1, 'repository': r['repository'],
            'repository_id': r['repository_id'],
            'ref': 'refs/heads/ci-v2-authority-audit/' + r['transaction_id'],
            'genesis_sha': 'a' * 40, 'tree_sha': 'b' * 40, 'governance_sha256': 'c' * 64}
        self.model = GitModel(self.config, self.binding)

    def client(self, model=None, **overrides):
        return audit._IsolatedGitProtocol(model or self.model,
            overrides.get('config', self.config), overrides.get('binding', self.binding))

    def test_successful_reservation_cross_run_visibility_and_no_authority(self):
        first = self.client(); result = first.reserve()
        self.assertEqual(result['status'], 'RESERVED')
        self.assertEqual(result['authorization'], 'NOT_GRANTED')
        self.assertFalse(result['live_apply'])
        self.assertEqual(self.client().inspect()['status'], 'RESERVED_REVIEW_REQUIRED')
        self.assertEqual(self.client().reserve()['status'], 'RESERVATION_NOT_GRANTED')
        self.assertEqual(first.reserve()['status'], 'DUPLICATE_OR_UNCERTAIN_RESERVATION')

    def test_two_simultaneous_stale_head_writers_only_one_reserves(self):
        self.model.barrier = threading.Barrier(2)
        clients = [self.client(), self.client()]; results = []
        threads = [threading.Thread(target=lambda c=c: results.append(c.reserve())) for c in clients]
        for thread in threads: thread.start()
        for thread in threads: thread.join(timeout=10); self.assertFalse(thread.is_alive())
        self.assertEqual(sorted(r['status'] for r in results), ['RESERVATION_NOT_GRANTED', 'RESERVED'])
        posts = [body for method, _, body in self.model.calls if method == 'POST']
        self.assertEqual(len(posts), 2)
        self.assertTrue(all(p['parents'] == [self.config['genesis_sha']] for p in posts))
        self.assertNotEqual(posts[0]['message'], posts[1]['message'])

    def test_consumption_is_single_use_even_in_same_run_or_after_restart(self):
        c = self.client(); self.assertEqual(c.reserve()['status'], 'RESERVED')
        self.assertEqual(c.consume()['status'], 'CONSUMED_OFFLINE')
        self.assertEqual(c.consume()['status'], 'CONSUMPTION_DENIED')
        restarted = self.client()
        self.assertEqual(restarted.inspect()['status'], 'CONSUMED_REVIEW_REQUIRED')
        self.assertEqual(restarted.consume()['status'], 'CONSUMPTION_DENIED')
        self.assertEqual(restarted.reserve()['status'], 'RESERVATION_NOT_GRANTED')

    def test_existing_private_apply_core_and_exact_completion_bytes(self):
        c = self.client(); c.reserve(); c.consume()
        result = self.f.apply()
        self.assertEqual(result['status'], 'COMPLETED')
        raw = (self.f.work / 'registry.json').read_bytes()
        self.assertEqual(c.complete(raw, result)['status'], 'COMPLETED_OFFLINE')
        self.assertEqual(self.client().inspect()['status'], 'COMPLETED_REVIEW_REQUIRED')
        self.assertEqual(self.f.authoritative.read_bytes(), self.f.old)

    def test_restarted_transport_retains_state_without_cached_client_data(self):
        c = self.client(); c.reserve(); c.consume()
        # Serialize the synthetic server, not a client authorization receipt.
        saved = json.loads(json.dumps({'head': self.model.head, 'objects': self.model.objects}))
        other_server = GitModel(self.config, self.binding)
        other_server.head, other_server.objects = saved['head'], saved['objects']
        c2 = self.client(other_server)
        self.assertEqual(c2.inspect()['status'], 'CONSUMED_REVIEW_REQUIRED')
        self.assertEqual(c2.consume()['status'], 'CONSUMPTION_DENIED')

    def test_conflict_responses_never_retry_mutation(self):
        for status in (409, 422):
            with self.subTest(status=status):
                model = GitModel(self.config, self.binding); model.failure = status
                self.assertEqual(self.client(model).reserve()['status'], 'RESERVATION_NOT_GRANTED')
                self.assertEqual(sum(m == 'PATCH' for m, _, _ in model.calls), 1)

    def test_timeout_before_write_reconciles_without_regrant_or_retry(self):
        self.model.failure = 'timeout_before'; c = self.client(); result = c.reserve()
        self.assertEqual(result['status'], 'RESERVATION_NOT_GRANTED')
        self.assertEqual(result['reconciliation']['status'], 'NOT_RESERVED_REVIEW_REQUIRED')
        self.model.failure = None
        self.assertEqual(c.reserve()['status'], 'DUPLICATE_OR_UNCERTAIN_RESERVATION')
        self.assertEqual(sum(m == 'PATCH' for m, _, _ in self.model.calls), 1)

    def test_timeout_after_write_readback_never_creates_an_approval(self):
        self.model.failure = 'timeout_after'; c = self.client(); result = c.reserve()
        self.assertEqual(result['status'], 'RESERVATION_NOT_GRANTED')
        self.assertEqual(result['reconciliation']['status'], 'RESERVED_REVIEW_REQUIRED')
        self.assertFalse(result['reconciliation']['recovered_authorization'])
        self.assertEqual(c.consume()['status'], 'CONSUMPTION_DENIED')
        self.assertEqual(self.client().reserve()['status'], 'RESERVATION_NOT_GRANTED')

    def test_timeout_after_consumption_irrevocably_burns_without_apply(self):
        c = self.client(); c.reserve(); self.model.failure = 'timeout_after'
        result = c.consume()
        self.assertEqual(result['status'], 'CONSUMPTION_NOT_GRANTED')
        self.assertEqual(result['reconciliation']['status'], 'CONSUMED_REVIEW_REQUIRED')
        self.assertEqual(c.consume()['status'], 'CONSUMPTION_DENIED')
        self.assertEqual((self.f.work / 'registry.json').read_bytes(), self.f.old)

    def test_failed_read_is_not_absence_or_permission(self):
        self.model.fail_reads = True
        result = self.client().reserve()
        self.assertEqual(result['status'], 'RESERVATION_NOT_GRANTED')
        self.assertEqual(result['reconciliation']['status'], 'STATE_UNCERTAIN')
        self.assertFalse(any(m != 'GET' for m, _, _ in self.model.calls))

    def test_malformed_api_response_cannot_pass_or_leak_transport_error(self):
        for value in (None, [], {'ref': self.config['ref'], 'object': None}):
            with self.subTest(value=value), patch.object(self.model, 'request', return_value=(200, value)):
                result = self.client().reserve()
                self.assertEqual(result['status'], 'RESERVATION_NOT_GRANTED')
                self.assertEqual(result['reconciliation']['status'], 'STATE_UNCERTAIN')

    def test_wrong_created_commit_metadata_prevents_reference_mutation(self):
        original = self.model.request
        def request(method, endpoint, body):
            status, value = original(method, endpoint, body)
            if method == 'POST':
                self.model.objects[value['sha']]['tree'] = None
            return status, value
        with patch.object(self.model, 'request', side_effect=request):
            self.assertEqual(self.client().reserve()['status'], 'RESERVATION_NOT_GRANTED')
        self.assertFalse(any(m == 'PATCH' for m, _, _ in self.model.calls))

    def test_readback_failure_leaves_uncertain_and_does_not_retry(self):
        self.model.failure = 'readback'; c = self.client(); result = c.reserve()
        self.assertEqual(result['status'], 'RESERVATION_NOT_GRANTED')
        self.assertEqual(result['reconciliation']['status'], 'STATE_UNCERTAIN')
        self.model.fail_reads = False
        self.assertEqual(c.inspect()['status'], 'RESERVED_REVIEW_REQUIRED')
        self.assertEqual(c.consume()['status'], 'CONSUMPTION_DENIED')

    def test_unauthorized_mutation_rejected_and_live_surface_stays_closed(self):
        self.model.failure = 403
        self.assertEqual(self.client().reserve()['status'], 'RESERVATION_NOT_GRANTED')
        self.assertEqual(audit.backend_status()['status'], 'BLOCKED')
        self.assertEqual(self.model.head, self.config['genesis_sha'])

    def test_incorrect_repository_or_genesis_or_ref_or_tree_fail_before_consumption(self):
        self.model.repo['id'] += 1
        self.assertEqual(self.client().reserve()['status'], 'RESERVATION_NOT_GRANTED')
        self.model.repo['id'] -= 1
        root = self.model.objects[self.config['genesis_sha']]
        root['message'] = '{}'
        self.assertEqual(self.client().reserve()['status'], 'RESERVATION_NOT_GRANTED')
        for key, value in [('ref', 'refs/heads/other'), ('tree_sha', 'bad'), ('genesis_sha', 'bad')]:
            with self.subTest(key=key), self.assertRaises(audit.AuditError):
                self.client(config={**self.config, key: value})

    def test_incorrect_owner_proposal_or_subject_uses_existing_B3_B4_validation(self):
        for field, value in [('actor_id', 909), ('run_attempt', 2), ('proposal_sha256', '0' * 64)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                audit._binding(self.p, {**self.decision, field: value}, **self.kwargs)
        with self.assertRaises(audit.AuditError):
            audit._binding(self.p, self.decision, **{**self.kwargs, 'expected_subject_sha256': '0' * 64})

    def test_existing_reservation_cannot_be_rebound_to_new_owner_run(self):
        self.client().reserve()
        decision = {**self.decision, 'run_id': 204}
        binding = audit._binding(self.p, decision, **{**self.kwargs, 'expected_run_id': 204})
        result = self.client(binding=binding).reserve()
        self.assertEqual(result['status'], 'RESERVATION_NOT_GRANTED')
        self.assertEqual(result['reconciliation']['status'], 'STATE_UNCERTAIN')

    def test_partial_isolated_failure_retains_consumed_state_without_retry(self):
        c = self.client(); c.reserve(); c.consume()
        with patch.object(core_tests.core.os, 'replace', side_effect=OSError):
            result = self.f.apply()
        self.assertNotEqual(result['status'], 'COMPLETED')
        self.assertEqual(c.complete(self.f.old, result)['status'], 'COMPLETION_UNCERTAIN')
        self.assertEqual(self.client().inspect()['status'], 'CONSUMED_REVIEW_REQUIRED')
        self.assertEqual(self.client().consume()['status'], 'CONSUMPTION_DENIED')

    def test_exact_result_digest_mismatch_cannot_record_completion(self):
        c = self.client(); c.reserve(); c.consume(); result = self.f.apply()
        self.assertEqual(c.complete(b'wrong', result)['status'], 'COMPLETION_UNCERTAIN')
        self.assertEqual(self.client().inspect()['status'], 'CONSUMED_REVIEW_REQUIRED')

    def test_ambiguous_completion_may_be_committed_but_is_not_retried(self):
        c = self.client(); c.reserve(); c.consume(); result = self.f.apply()
        self.model.failure = 'timeout_after'
        answer = c.complete((self.f.work / 'registry.json').read_bytes(), result)
        self.assertEqual(answer['status'], 'COMPLETION_UNCERTAIN')
        self.assertEqual(answer['reconciliation']['status'], 'COMPLETED_REVIEW_REQUIRED')
        self.assertEqual(c.complete(b'', result)['status'], 'COMPLETION_DENIED')

    def test_merge_or_history_truncation_or_tampered_binding_is_not_accepted(self):
        self.client().reserve(); event = self.model.objects[self.model.head]
        event['parents'].append({'sha': self.config['genesis_sha']})
        self.assertEqual(self.client().inspect()['status'], 'STATE_UNCERTAIN')
        event['parents'].pop(); value = json.loads(event['message'])
        value['previous_event_sha256'] = '0' * 64; event['message'] = audit._message(value)
        self.assertEqual(self.client().inspect()['status'], 'STATE_UNCERTAIN')

    def test_governance_anchor_mismatch_fails_and_pin_is_not_live_verification(self):
        config = {**self.config, 'governance_sha256': 'd' * 64}
        self.assertEqual(self.client(config=config).reserve()['status'], 'RESERVATION_NOT_GRANTED')
        self.assertEqual(audit.backend_status()['authorization'], 'NOT_GRANTED')

    def test_force_false_alone_does_not_mean_exact_old_compare_and_swap(self):
        # The model deliberately permits an arbitrary fast-forward descendant,
        # though the protocol restricts every submitted candidate to one child.
        c = self.client(); c.reserve(); old = self.model.head
        middle = self.model.request('POST', 'repos/' + self.config['repository'] + '/git/commits',
            {'tree': self.config['tree_sha'], 'parents': [old], 'message': 'middle'})[1]['sha']
        last = self.model.request('POST', 'repos/' + self.config['repository'] + '/git/commits',
            {'tree': self.config['tree_sha'], 'parents': [middle], 'message': 'last'})[1]['sha']
        self.model.head = middle
        status, _ = self.model.request('PATCH', 'repos/' + self.config['repository'] +
            '/git/refs/' + self.config['ref'][5:], {'sha': last, 'force': False})
        self.assertEqual(status, 200)  # no expected-old argument exists
        self.assertEqual(self.client().inspect()['status'], 'STATE_UNCERTAIN')

    def test_public_hosted_entry_not_connected_to_offline_adapter(self):
        with patch.dict('os.environ', {'PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_JSON': ''}):
            self.assertEqual(hosted.run()['status'], 'BLOCKED')
        self.assertFalse(any(m != 'GET' for m, _, _ in self.model.calls))

    def test_commit_creation_timeout_never_retries_or_moves_reference(self):
        for failure in ('create_timeout_before', 'create_timeout_after'):
            with self.subTest(failure=failure):
                model = GitModel(self.config, self.binding); model.failure = failure
                c = self.client(model); answer = c.reserve()
                self.assertEqual(answer['status'], 'RESERVATION_NOT_GRANTED')
                self.assertEqual(model.head, self.config['genesis_sha'])
                self.assertEqual(c.reserve()['status'], 'DUPLICATE_OR_UNCERTAIN_RESERVATION')
                self.assertFalse(any(m == 'PATCH' for m, _, _ in model.calls))
                self.assertEqual(sum(m == 'POST' for m, _, _ in model.calls), 1)

    def test_other_transaction_receipt_cannot_complete_same_result(self):
        c = self.client(); c.reserve(); c.consume(); result = self.f.apply()
        result['receipt']['transaction_id'] = '9' * 32
        self.assertEqual(c.complete((self.f.work / 'registry.json').read_bytes(), result)['status'],
                         'COMPLETION_UNCERTAIN')
        self.assertEqual(self.client().inspect()['status'], 'CONSUMED_REVIEW_REQUIRED')

    def test_missing_governance_allows_rollback_in_model_so_live_gate_must_stay_closed(self):
        c = self.client(); c.reserve(); c.consume()
        # Counterexample: Git metadata alone cannot discover malicious rollback
        # when an independent new runner has only genesis pin and current ref.
        self.model.head = self.config['genesis_sha']
        result = self.client().reserve()
        self.assertEqual(result['status'], 'RESERVED')
        self.assertEqual(result['authorization'], 'NOT_GRANTED')
        self.assertEqual(audit.backend_status()['status'], 'BLOCKED')

    def test_actual_new_process_can_only_inspect_consumed_server_state(self):
        import os
        import subprocess
        import sys
        c = self.client(); c.reserve(); c.consume()
        saved = self.f.work / 'synthetic-server.json'
        saved.write_text(json.dumps({'config': self.config, 'binding': self.binding,
                                    'head': self.model.head, 'objects': self.model.objects}))
        program = '''import json,sys
from pathlib import Path
from test_parent_authority_git_audit import GitModel
from src.parent_authority_git_audit import _IsolatedGitProtocol
s=json.loads(Path(sys.argv[1]).read_text());m=GitModel(s['config'],s['binding'])
m.head=s['head'];m.objects=s['objects'];c=_IsolatedGitProtocol(m,s['config'],s['binding'])
print(json.dumps({'inspection':c.inspect(),'consume':c.consume()}))
'''
        project = Path(__file__).resolve().parents[1]
        env = {**os.environ, 'PYTHONPATH': str(project) + os.pathsep + str(project / 'tests')}
        result = subprocess.run([sys.executable, '-B', '-c', program, str(saved)],
                                env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['inspection']['status'], 'CONSUMED_REVIEW_REQUIRED')
        self.assertEqual(data['consume']['status'], 'CONSUMPTION_DENIED')


if __name__ == '__main__':
    unittest.main()
