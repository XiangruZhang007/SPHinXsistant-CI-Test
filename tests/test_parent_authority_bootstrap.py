"""Synthetic first-run composition; never Hosted capability or authorization.

Only platform checkout/runtime and GitHub API boundaries are fixtures. Real
deployment, preparation, pre-token gate, Owner observation, governance, HTTP
allowlists, one-shot initialization, protocol and isolated APPLY are composed.
"""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_hosted_parent_authority_transition as invocation
import test_parent_authority_writer_workflow as gates
import test_parent_authority_github_transport as http
from test_runtime_ruleset_observation import EvidenceFixture
from scripts import parent_authority_writer_bootstrap as bootstrap
from scripts import parent_authority_writer_prepare as preparation
from scripts import parent_authority_writer_gate as gate
from scripts import runtime_ruleset_observation as observation
from src import hosted_parent_authority_transition as hosted
from src import parent_authority_github_transport as transport
from src import parent_authority_git_audit as audit
from src.corpus_snapshot import digest

P = Path(__file__).resolve().parents[1]


class EmptyServer(http.Server):
    def __init__(self, config, binding):
        super().__init__(config, binding)
        self.objects = {}; self.head = None; self.absent = True; self.tree_exists = False
        self.repo.update(private=False, visibility='public')
        self.override = self.first_run
        self.fail_genesis = False; self.fail_ref_readback = False

    def first_run(self, req):
        suffix = req.full_url.removeprefix(transport.API + 'repos/' + bootstrap.REPOSITORY)
        if req.method == 'GET' and suffix.startswith('/git/trees/') and not self.tree_exists:
            # A premature pre-existing-genesis assumption fails the composition.
            raise AssertionError('TREE_DOES_NOT_EXIST_BEFORE_FIRST_POST')
        if req.method == 'POST' and suffix == '/git/trees':
            payload = json.loads(req.data)
            assert payload == bootstrap.tree_request(bootstrap.TREE)
            # A server with no empty-tree support must still pass this path.
            assert len(payload['tree']) == 1 and payload['tree'][0]['content'] == ''
            row = payload['tree'][0]
            blob = subprocess.check_output(['git', 'hash-object', '--stdin'], input=row['content'].encode()).decode().strip()
            tree_bytes = row['mode'].encode() + b' ' + row['path'].encode() + b'\0' + bytes.fromhex(blob)
            native_tree = subprocess.check_output(['git', 'hash-object', '-t', 'tree', '--stdin'], input=tree_bytes).decode().strip()
            assert native_tree == self.config['tree_sha']
            self.tree_exists = True
        if req.method == 'POST' and suffix == '/git/commits':
            body = json.loads(req.data)
            if body['parents'] == []:
                self.calls.append(('POST', suffix, body))
                who = body['author']
                assert who == body['committer'] == bootstrap.PERSON
                identity = who['name'] + ' <' + who['email'] + '> 946684800 +0000'
                raw = ('tree ' + body['tree'] + '\nauthor ' + identity + '\ncommitter '
                       + identity + '\n\n' + body['message']).encode()
                # Git itself hashes the actual commit bytes independently.
                sha = subprocess.check_output(['git', 'hash-object', '-t', 'commit', '--stdin'], input=raw).decode().strip()
                self.objects[sha] = {'sha': sha, 'tree': {'sha': body['tree']}, 'parents': [], 'message': body['message']}
                if self.fail_genesis:
                    raise TimeoutError('must never retain transport text')
                return http.Response(201, {'sha': sha}, req.full_url)
        if self.fail_ref_readback and not self.absent and req.method == 'GET' and '/git/ref/' in suffix:
            raise TimeoutError()
        return None


class BootstrapIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.f = invocation.InvocationTests(); self.f.setUp(bootstrap.REPOSITORY, bootstrap.REPOSITORY_ID)
        self.addCleanup(self.f.doCleanups)
        self.root = self.f.root
        self.f.f.request['transaction_id'] = bootstrap.REF.rsplit('/', 1)[1]
        proposal = self.f.f.prepare()
        self.config = deepcopy(self.f.config)
        self.config.update(schema_version=3, request=deepcopy(self.f.f.request), proposal_sha256=digest(proposal))
        self.manifest = hosted.contract(P)
        self.config['implementation_contract_sha256'] = digest(self.manifest)
        self.evidence = EvidenceFixture(self.root, protected_id=5)
        policy = self.evidence.policy
        policy['implementation_contract_sha256'] = self.config['implementation_contract_sha256']
        policy_path = self.root / 'configs/governance.json'
        policy_path.write_text(json.dumps(policy))
        subprocess.run(['git', '-C', str(self.root), 'add', 'configs'], check=True, capture_output=True)
        self.config['governance'] = {'trust_model': observation.MODEL, 'policy_path': 'configs/governance.json',
            'policy_sha256': hashlib.sha256(policy_path.read_bytes()).hexdigest()}
        self.config['transaction_backend'] = {'kind': bootstrap.KIND,
            'audit': {'schema_version': 3, 'repository': bootstrap.REPOSITORY, 'repository_id': bootstrap.REPOSITORY_ID,
                'ref': bootstrap.REF, 'tree_sha': bootstrap.TREE, 'governance_sha256': self.evidence.governance},
            'history_ruleset_id': 1, 'writer_ruleset_id': 2, 'writer_integration_id': gate.APP_ID}
        self.repin()
        self.f.repo.update(private=False, visibility='public'); self.f.repo['owner']['id'] = gate.OWNER_ID
        for key in ('actor', 'triggering_actor'): self.f.run[key]['id'] = gate.OWNER_ID
        self.f.env['GITHUB_ACTOR_ID'] = str(gate.OWNER_ID)
        self.g = gates.WriterGateTests(); self.g.setUp(); self.addCleanup(self.g.doCleanups)
        sha = self.config['request']['implementation_revision']
        def replace_sha(value):
            if isinstance(value, dict): return {k: replace_sha(v) for k, v in value.items()}
            if isinstance(value, list): return [replace_sha(v) for v in value]
            return sha if value == self.g.sha else value
        self.g.responses = replace_sha(self.g.responses)
        self.live = {r['id']: deepcopy(r) for r in self.evidence.evidence['rulesets']}
        for row in self.live.values(): del row['bypass_actors']
        self.live[2].update(node_id='RRS_fixture', rules=[{'type': 'creation'}, {'type': 'update'}])
        for number, row in self.live.items(): self.g.responses[self.g.base + '/rulesets/' + str(number)] = row
        self.g.responses[self.g.base + '/rules/branches/ci-upstream-refresh'] = [
            {**r, 'ruleset_id': 5} for r in self.evidence.evidence['rulesets'][2]['rules']]
        self.g.responses['installation/repositories?per_page=100'] = {'total_count': 1,
            'repositories': [{'id': gate.REPOSITORY_ID, 'full_name': gate.REPOSITORY}]}
        self.f.responses.update(self.g.responses)
        self.f.responses[self.g.base + '/actions/workflows/103']['state'] = 'active'
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.env = {**self.g.env, **self.f.env, 'GITHUB_JOB': 'trusted-audit-writer',
            'GITHUB_SHA': sha, 'GITHUB_WORKFLOW_SHA': sha, 'RUNNER_TEMP': temp.name,
            'GH_TOKEN': 'synthetic-hosted-reader', 'PARENT_AUTHORITY_AUDIT_TOKEN': 'synthetic-app',
            'ACTUAL_WRITER_INSTALLATION_ID': str(gate.INSTALLATION_ID)}
        self.raw_deployment()
        self.server = None; self.instances = []; self.graphql_tokens = []; self.fail_app_graphql = False
        self.real_transport = transport.GitHubAuditTransport

    def repin(self):
        self.config['subject_sha256'] = digest(hosted.subject(self.config['request'], self.config['proposal_sha256'],
            self.config['workflow_id'], governance_policy_sha256=self.config['governance']['policy_sha256'],
            bootstrap_sha256=digest(self.config['transaction_backend'])))
        self.f.config = self.config
        self.f.inputs.update(request_sha256=digest(self.config['request']), proposal_sha256=self.config['proposal_sha256'],
            transition_subject_sha256=self.config['subject_sha256'], transaction_id=self.config['request']['transaction_id'])
        self.f.event.write_text(json.dumps({'inputs': self.f.inputs}))

    def raw_deployment(self):
        self.env.update(self.f.deploy_env())

    def graphql(self, token, node, number):
        self.graphql_tokens.append(token)
        if token == 'synthetic-app' and self.fail_app_graphql:
            raise ValueError('RUNTIME_UPDATE_PARAMETER_UNVERIFIED')
        self.assertIn(token, ('synthetic-hosted-reader', 'synthetic-app'))
        self.assertEqual((node, number), ('RRS_fixture', 2))
        if token == 'synthetic-app' and self.server and not self.server.tree_exists:
            self.assertFalse(any(m != 'GET' for m, _, _ in self.server.http))
        return False

    def factory(self, config, binding, token, *, write_scope=None):
        self.assertEqual(token, 'synthetic-app')
        if self.server is None:
            self.server = EmptyServer(config, binding); self.server.rules = self.live
        instance = self.real_transport(config, binding, token, write_scope=write_scope)
        instance._opener = self.server; self.instances.append(instance)
        return instance

    def boundaries(self):
        stack = ExitStack(); stack.enter_context(self.f.boundaries())
        stack.enter_context(patch.dict(os.environ, self.env))
        stack.enter_context(patch.dict(sys.modules, {'runtime_ruleset_observation': observation,
            'parent_authority_writer_bootstrap': bootstrap}))
        stack.enter_context(patch.object(hosted, 'PROJECT', self.root))
        stack.enter_context(patch.object(preparation, 'PROJECT', self.root))
        stack.enter_context(patch.object(hosted, 'contract', return_value=self.manifest))
        stack.enter_context(patch.object(gate, 'checkout'))
        stack.enter_context(patch.object(gate, 'GitHubRead', return_value=self.g.api))
        stack.enter_context(patch.object(observation, 'live_update', side_effect=self.graphql))
        stack.enter_context(patch.object(hosted, 'sys', SimpleNamespace(flags=SimpleNamespace(isolated=1, no_site=1))))
        stack.enter_context(patch.object(hosted.platform, 'python_version', return_value='3.12.3'))
        stack.enter_context(patch.object(hosted.platform, 'machine', return_value='aarch64'))
        stack.enter_context(patch.object(transport, 'GitHubAuditTransport', side_effect=self.factory))
        return stack

    def prepare_and_gate(self):
        receipt, files = preparation.prepare()
        os.environ.update(OWNER_PREPARATION_RECEIPT=json.dumps(receipt), OWNER_IMPLEMENTATION_FILES=json.dumps(files))
        gated = gate.verify(os.environ, self.root, self.g.api)
        self.assertEqual(gated['authorization'], 'NOT_GRANTED')
        self.assertIsNone(self.server)  # No existing genesis/ref required by preparation or gate.
        return receipt

    def test_first_empty_remote_through_preparation_gate_bootstrap_and_complete(self):
        old = (self.root / self.config['request']['registry_path']).read_bytes()
        with self.boundaries():
            receipt = self.prepare_and_gate()
            result = hosted.run_writer()
        self.assertEqual(result['status'], 'COMPLETED', result)
        self.assertEqual(result['bootstrap']['genesis_sha'], receipt['bootstrap']['genesis_sha'])
        self.assertEqual(result['bootstrap']['phase'], 'VERIFIED')
        self.assertFalse(result['authoritative_registry_applied'])
        self.assertEqual(result['authorization'], 'NOT_GRANTED')
        self.assertEqual((self.root / self.config['request']['registry_path']).read_bytes(), old)
        self.assertEqual(sum(m == 'PATCH' for m, _, _ in self.server.http), 3)
        initializers = [t for t in self.instances if t._scope == 'INITIALIZE']
        self.assertEqual(len(initializers), 2)
        self.assertIsNot(initializers[0], initializers[1])
        self.assertTrue(all(t._initialization_attempted for t in initializers))
        self.assertIn('synthetic-app', self.graphql_tokens)
        self.assertIn('synthetic-hosted-reader', self.graphql_tokens)
        with self.assertRaises(audit.AuditError): initializers[0].initialize_ref()
        with self.assertRaises(audit.AuditError): initializers[1].create_genesis(bootstrap.PERSON)
        self.assertEqual(audit._IsolatedGitProtocol(self.instances[-1], self.instances[-1].config,
            self.instances[-1].binding).inspect()['status'], 'COMPLETED_REVIEW_REQUIRED')

    def test_owner_or_reader_graphql_success_does_not_authorize_app_without_live_capability(self):
        self.fail_app_graphql = True
        with self.boundaries():
            self.prepare_and_gate(); result = hosted.run_writer()
        self.assertEqual(result['status'], 'BLOCKED', result)
        self.assertEqual(result['reason'], 'RUNTIME_UPDATE_PARAMETER_UNVERIFIED')
        self.assertFalse(any(m != 'GET' for m, _, _ in self.server.http))
        self.assertFalse(any(t._scope for t in self.instances))

    def test_existing_ref_blocks_before_creating_objects(self):
        original = self.factory
        def existing(*args, **kwargs):
            instance = original(*args, **kwargs); self.server.absent = False
            self.server.head = instance.config['genesis_sha']; return instance
        with self.boundaries(), patch.object(transport, 'GitHubAuditTransport', side_effect=existing):
            self.prepare_and_gate(); result = hosted.run_writer()
        self.assertEqual(result['reason'], 'AUDIT_REF_NOT_PROVEN_ABSENT', result)
        self.assertFalse(any(m != 'GET' for m, _, _ in self.server.http))

    def test_absence_requires_both_404_and_empty_matching_inventory(self):
        original = self.factory
        def ambiguous(*args, **kwargs):
            instance = original(*args, **kwargs)
            first_run = self.server.first_run
            def override(req):
                if '/git/matching-refs/' in req.full_url:
                    return http.Response(200, [{'ref': bootstrap.REF + '-unexpected'}], req.full_url)
                return first_run(req)
            self.server.override = override
            return instance
        with self.boundaries(), patch.object(transport, 'GitHubAuditTransport', side_effect=ambiguous):
            self.prepare_and_gate(); result = hosted.run_writer()
        self.assertEqual(result['reason'], 'AUDIT_REF_NOT_PROVEN_ABSENT', result)
        self.assertFalse(any(m != 'GET' for m, _, _ in self.server.http))

    def test_uncertain_genesis_never_creates_ref_or_opens_append(self):
        original = self.factory
        def interrupted(*args, **kwargs):
            instance = original(*args, **kwargs); self.server.fail_genesis = True; return instance
        with self.boundaries(), patch.object(transport, 'GitHubAuditTransport', side_effect=interrupted):
            self.prepare_and_gate(); result = hosted.run_writer()
        self.assertEqual(result['status'], 'STATE_UNCERTAIN', result)
        self.assertFalse(result['automatic_retry'])
        self.assertTrue(self.server.absent)
        self.assertFalse(any(t._scope == 'APPEND' for t in self.instances))
        self.assertNotIn('must never retain', json.dumps(result))

    def test_governance_drift_after_genesis_stops_before_ref_creation(self):
        real_create = self.real_transport.create_genesis
        def drift(instance, person):
            result = real_create(instance, person)
            self.live[2]['enforcement'] = 'disabled'
            return result
        with self.boundaries(), patch.object(self.real_transport, 'create_genesis', drift):
            self.prepare_and_gate(); result = hosted.run_writer()
        self.assertEqual(result['status'], 'STATE_UNCERTAIN', result)
        self.assertTrue(self.server.absent)
        self.assertFalse(any(t._scope == 'APPEND' for t in self.instances))
        self.assertEqual(sum(m == 'POST' and url.endswith('/git/refs') for m, url, _ in self.server.http), 0)

    def test_inexact_genesis_readback_never_creates_ref(self):
        first_run = EmptyServer.first_run
        def corrupt(server, req):
            result = first_run(server, req)
            if req.method == 'GET' and '/git/commits/' in req.full_url:
                sha = req.full_url.rsplit('/', 1)[1]
                value = deepcopy(server.objects[sha]); value['message'] = '{}'
                return http.Response(200, value, req.full_url)
            return result
        with self.boundaries(), patch.object(EmptyServer, 'first_run', corrupt):
            self.prepare_and_gate(); result = hosted.run_writer()
        self.assertEqual(result['status'], 'STATE_UNCERTAIN', result)
        self.assertTrue(self.server.absent)
        self.assertFalse(any(t._scope == 'APPEND' for t in self.instances))

    def test_persisted_ref_with_lost_response_is_not_retried_or_appended(self):
        first_run = EmptyServer.first_run
        def lost(server, req):
            if req.method == 'POST' and req.full_url.endswith('/git/refs'):
                server.absent = False; server.head = json.loads(req.data)['sha']
                raise TimeoutError()
            return first_run(server, req)
        with self.boundaries(), patch.object(EmptyServer, 'first_run', lost):
            self.prepare_and_gate(); result = hosted.run_writer()
        self.assertEqual(result['status'], 'STATE_UNCERTAIN', result)
        self.assertFalse(self.server.absent)
        self.assertFalse(result['automatic_retry'])
        self.assertEqual(sum(m == 'POST' and url.endswith('/git/refs') for m, url, _ in self.server.http), 1)
        self.assertFalse(any(t._scope == 'APPEND' for t in self.instances))

    def test_invalid_proposal_and_subject_fail_in_preparation_without_remote_objects(self):
        with self.boundaries():
            original = self.config['proposal_sha256']
            self.config['proposal_sha256'] = 'f' * 64; self.repin(); os.environ.update(self.f.deploy_env())
            with self.assertRaisesRegex(ValueError, 'PROPOSAL_PIN_MISMATCH'): preparation.prepare()
            self.config['proposal_sha256'] = original; self.repin()
            self.config['subject_sha256'] = 'f' * 64; os.environ.update(self.f.deploy_env())
            with self.assertRaisesRegex(ValueError, 'SUBJECT_PIN_MISMATCH'): preparation.prepare()
        self.assertIsNone(self.server)

    def test_existing_genesis_pin_cannot_be_smuggled_into_bootstrap_mode(self):
        self.config['transaction_backend']['audit']['genesis_sha'] = 'a' * 40
        self.repin(); self.raw_deployment()
        with self.boundaries(), self.assertRaisesRegex(ValueError, 'INVALID_RUN_BOUND_BOOTSTRAP_DEPLOYMENT'):
            preparation.prepare()
        self.assertIsNone(self.server)

    def test_reviewed_mode_scope_and_authenticated_run_bind_genesis(self):
        with self.boundaries():
            receipt, _ = preparation.prepare()
            actor = receipt['workflow_run']
            first, _, _ = bootstrap.resolve(self.config, actor)
            second, _, _ = bootstrap.resolve(self.config, {**actor, 'run_id': 103})
            self.assertNotEqual(first['transaction_backend']['audit']['genesis_sha'],
                                second['transaction_backend']['audit']['genesis_sha'])
            for key, value in (('actor_id', 1), ('run_attempt', 2), ('event', 'schedule'), ('workflow_id', 1)):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    bootstrap.resolve(self.config, {**actor, key: value})
            self.config['transaction_backend']['audit']['ref'] += '0'; self.repin(); self.raw_deployment()
            os.environ.update(self.f.deploy_env())
            with self.assertRaisesRegex(ValueError, 'SCOPE_MISMATCH'): hosted._deployment()

    def test_pre_token_rejects_modified_predicted_identity(self):
        with self.boundaries():
            receipt = self.prepare_and_gate()
            receipt['bootstrap']['genesis_sha'] = 'f' * 40
            os.environ['OWNER_PREPARATION_RECEIPT'] = json.dumps(receipt)
            with self.assertRaisesRegex(ValueError, 'BOOTSTRAP_PREPARATION_MISMATCH'):
                gate.verify(os.environ, self.root, self.g.api)

    def test_historical_uncertain_transaction_is_not_reused(self):
        self.config['request']['transaction_id'] = 'ed20b392594046db84a6f2306053440e'
        self.config['transaction_backend']['audit']['ref'] = 'refs/heads/ci-v2-authority-audit/ed20b392594046db84a6f2306053440e'
        self.repin(); self.raw_deployment()
        with self.boundaries(), self.assertRaisesRegex(ValueError, 'SCOPE_MISMATCH'):
            preparation.prepare()
        self.assertIsNone(self.server)

    def test_tree_http_failure_surfaces_sanitized_status_and_never_enters_append(self):
        first_run = EmptyServer.first_run
        secret = 'SYNTHETIC_CREDENTIAL_MUST_NOT_LEAK'
        def rejected(server, req):
            if req.method == 'POST' and req.full_url.endswith('/git/trees'):
                import io, urllib.error
                body = json.dumps({'message': 'Tree does not contain any files',
                    'token': secret, 'documentation_url': 'https://invalid/?token='+secret}).encode()
                raise urllib.error.HTTPError(req.full_url, 422, secret, {'Authorization': secret}, io.BytesIO(body))
            return first_run(server, req)
        with self.boundaries(), patch.object(EmptyServer, 'first_run', rejected):
            self.prepare_and_gate(); result = hosted.run_writer()
        self.assertEqual(result['status'], 'STATE_UNCERTAIN', result)
        self.assertEqual(result['reason'], 'AUDIT_TREE_CREATION_FAILED')
        failures = [r for r in result['api_diagnostics'] if r['http_status'] == 422]
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0]['api_error_code'], 'TREE_HAS_NO_FILES')
        self.assertLessEqual(len(result['api_diagnostics']), 8)
        self.assertNotIn(secret, json.dumps(result))
        self.assertTrue(self.server.absent)
        self.assertFalse(any(t._scope == 'APPEND' for t in self.instances))


if __name__ == '__main__':
    unittest.main()
