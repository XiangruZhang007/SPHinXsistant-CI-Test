"""Deterministic REST-boundary tests; never real GitHub writes or Owner grants."""
from copy import deepcopy
import hashlib
import io
import json
import threading
import unittest
import urllib.error
from unittest.mock import patch

import test_hosted_parent_authority_transition as hosted_tests
import test_parent_authority_git_audit as audit_tests
from src import parent_authority_git_audit as audit
from src import parent_authority_github_transport as rest
from src import hosted_parent_authority_transition as hosted
from src.corpus_snapshot import canonical, digest

NAME = 'XiangruZhang007/SPHinXsistant-CI-Test'
ID = 1455203884


class Response(io.BytesIO):
    def __init__(self, status, value, url):
        super().__init__(canonical(value)); self.status = status; self.url = url
    def geturl(self): return self.url


class Server(audit_tests.GitModel):
    def __init__(self, config, binding):
        super().__init__(config, binding)
        self.absent = False; self.rules = {}; self.http = []; self.override = None

    def open(self, request, timeout):
        self.http.append((request.method, request.full_url, timeout))
        if self.override:
            value = self.override(request)
            if value is not None: return value
        endpoint = request.full_url.removeprefix(rest.API)
        body = json.loads(request.data) if request.data else None
        suffix = endpoint.removeprefix('repos/' + self.config['repository'])
        if request.method == 'GET' and suffix.startswith('/git/trees/'):
            status, value = 200, {'sha': self.config['tree_sha'], 'tree': [], 'truncated': False}
        elif request.method == 'POST' and suffix == '/git/trees':
            status, value = 201, {'sha': self.config['tree_sha']}
        elif request.method == 'GET' and suffix.startswith('/rulesets/'):
            status, value = 200, self.rules[int(suffix.rsplit('/', 1)[1])]
        elif request.method == 'GET' and suffix.startswith('/git/matching-refs/'):
            status, value = 200, [] if self.absent else [{'ref': self.config['ref']}]
        elif request.method == 'GET' and suffix.startswith('/git/ref/') and self.absent:
            status, value = 404, {}
        elif request.method == 'POST' and suffix == '/git/refs':
            self.calls.append((request.method, endpoint, body))
            if not self.absent: status, value = 422, {}
            else:
                self.absent = False; self.head = body['sha']
                status, value = 201, {'ref': body['ref'], 'object': {'type': 'commit', 'sha': self.head}}
        else:
            status, value = self.request(request.method, endpoint, body)
        if status >= 400:
            raise urllib.error.HTTPError(request.full_url, status, 'sanitized fixture error', {}, io.BytesIO(b'not retained'))
        return Response(status, value, request.full_url)


class GitHubTransportTests(unittest.TestCase):
    def setUp(self):
        self.f = hosted_tests.InvocationTests(); self.f.setUp(NAME, ID); self.addCleanup(self.f.doCleanups)
        self.proposal, self.decision, _ = self.f.f.proposal_and_decision()
        self.binding = audit._binding(self.proposal, self.decision,
            expected_proposal_sha256=digest(self.proposal),
            expected_subject_sha256=digest(hosted.subject(self.proposal['request'], digest(self.proposal), 103)),
            expected_actor_id=101, expected_run_id=102)
        self.config = {'schema_version': 1, 'repository': NAME, 'repository_id': ID,
            'ref': 'refs/heads/ci-v2-authority-audit/' + self.decision['transaction_id'],
            'genesis_sha': 'a' * 40, 'tree_sha': rest.EMPTY_TREE, 'governance_sha256': 'c' * 64}
        self.server = Server(self.config, self.binding)
        self.server.repo.update(private=False, visibility='public')

    def transport(self, scope=None, server=None):
        t = rest.GitHubAuditTransport(self.config, self.binding, 'synthetic-token', write_scope=scope)
        t._opener = server or self.server
        return t

    def client(self, scope='APPEND', server=None):
        return audit._IsolatedGitProtocol(self.transport(scope, server), self.config, self.binding)

    def test_exact_public_and_private_support_through_actual_http_boundary(self):
        for private in (False, True):
            self.server.repo.update(private=private, visibility='private' if private else 'public')
            self.assertEqual(self.client().inspect()['status'], 'NOT_RESERVED_REVIEW_REQUIRED')
        self.assertTrue(all(url.startswith(rest.API + 'repos/' + NAME) and timeout == 15
                            for _, url, timeout in self.server.http))

    def test_wrong_repository_id_and_name_fail_without_writes(self):
        for key, wrong in (('id', 1), ('full_name', 'Other/Repo')):
            old = self.server.repo[key]; self.server.repo[key] = wrong
            self.assertEqual(self.client().reserve()['status'], 'RESERVATION_NOT_GRANTED')
            self.server.repo[key] = old
        self.assertFalse(any(method != 'GET' for method, _, _ in self.server.http))

    def test_read_only_default_and_no_generic_proxy_or_force_delete(self):
        t = self.transport()
        for method, endpoint, body in (
            ('POST', '/git/commits', {}), ('DELETE', '/git/refs/' + self.config['ref'][5:], None),
            ('GET', '/contents/token', None), ('GET', '?redirect=https://evil.invalid', None),
            ('PATCH', '/git/refs/heads/main', {'sha': 'b'*40, 'force': True})):
            with self.subTest(method=method), self.assertRaises(audit.AuditError):
                t.request(method, 'repos/' + NAME + endpoint, body)
        self.assertEqual(self.server.http, [])

    def test_missing_token_rejected_before_network(self):
        for token in ('', None, 'a\nb'):
            with self.assertRaises(audit.AuditError): rest.GitHubAuditTransport(self.config, self.binding, token)
        self.assertEqual(self.server.http, [])

    def test_exact_initial_ref_creation_once_and_readback(self):
        self.server.absent = True; t = self.transport('INITIALIZE')
        self.assertEqual(t.initialize_ref()['status'], 'AUDIT_REF_INITIALIZED')
        with self.assertRaises(audit.AuditError): t.initialize_ref()
        self.assertEqual(sum(m == 'POST' and ep.endswith('/git/refs') for m, ep, _ in self.server.calls), 1)

    def test_initialization_404_is_not_absence_without_matching_ref_evidence(self):
        self.server.absent = True
        def override(req):
            if '/git/matching-refs/' in req.full_url:
                raise urllib.error.HTTPError(req.full_url, 403, '', {}, io.BytesIO())
        self.server.override = override
        with self.assertRaisesRegex(audit.AuditError, 'NOT_PROVEN_ABSENT'): self.transport('INITIALIZE').initialize_ref()
        self.assertFalse(any(m == 'POST' for m, _, _ in self.server.http))

    def test_existing_ref_never_reset_or_recreated(self):
        with self.assertRaises(audit.AuditError): self.transport('INITIALIZE').initialize_ref()
        self.assertFalse(any(m != 'GET' for m, _, _ in self.server.http))

    def test_raw_ref_creation_cannot_bypass_provisioning_verification(self):
        t=self.transport('INITIALIZE');t._initialization_attempted=True
        with self.assertRaisesRegex(audit.AuditError,'AUDIT_REF_CREATION_DENIED'):
            t.request('POST','repos/'+NAME+'/git/refs',
                {'ref':self.config['ref'],'sha':self.config['genesis_sha']})
        self.assertEqual(self.server.http,[])

    def test_reviewed_genesis_creation_pin_mismatch_stops_before_ref_creation(self):
        with self.assertRaisesRegex(audit.AuditError, 'GENESIS_PIN_MISMATCH'):
            self.transport('INITIALIZE').create_genesis({'name': 'Synthetic',
                'email': 'fixture@example.invalid', 'date': '2026-11-20T00:00:00Z'})
        self.assertFalse(any(ep.endswith('/git/refs') for _, ep, _ in self.server.calls))

    def test_genesis_object_creation_with_exact_retained_pin_and_no_automatic_ref(self):
        person = {'name':'Synthetic','email':'fixture@example.invalid','date':'2026-11-20T00:00:00Z'}
        body = {'message':audit._message(audit._genesis(self.config,self.binding)),
            'tree':rest.EMPTY_TREE,'parents':[],'author':person,'committer':person}
        # The deterministic server models object IDs; not a genuine Git object hash proof.
        self.config['genesis_sha'] = hashlib.sha1(canonical(body)).hexdigest()
        self.server = Server(self.config,self.binding)
        self.server.repo.update(private=False,visibility='public')
        t=self.transport('INITIALIZE')
        self.assertEqual(t.create_genesis(person)['status'],'GENESIS_OBJECT_VERIFIED')
        with self.assertRaises(audit.AuditError): t.create_genesis(person)
        self.assertFalse(any(ep.endswith('/git/refs') for _,ep,_ in self.server.calls))

    def test_direct_child_reservation_consumption_and_duplicate_denial(self):
        c = self.client(); self.assertEqual(c.reserve()['status'], 'RESERVED')
        self.assertEqual(c.consume()['status'], 'CONSUMED_OFFLINE')
        self.assertEqual(c.consume()['status'], 'CONSUMPTION_DENIED')
        self.assertEqual(self.client().reserve()['status'], 'RESERVATION_NOT_GRANTED')
        for m, _, b in self.server.calls:
            if m == 'POST': self.assertEqual(len(b['parents']), 1)
            if m == 'PATCH': self.assertIs(b['force'], False)

    def test_two_racing_sibling_writers_at_ref_update_one_loses(self):
        self.server.barrier = threading.Barrier(2)
        clients = [self.client(), self.client()]; results = []
        threads = [threading.Thread(target=lambda c=c: results.append(c.reserve())) for c in clients]
        for t in threads: t.start()
        for t in threads: t.join(10); self.assertFalse(t.is_alive())
        self.assertEqual(sorted(x['status'] for x in results), ['RESERVATION_NOT_GRANTED', 'RESERVED'])
        self.assertEqual(sum(m == 'PATCH' for m, _, _ in self.server.calls), 2)

    def test_stale_parent_and_ref_retry_denied_before_second_patch(self):
        t = self.transport('APPEND'); c = audit._IsolatedGitProtocol(t, self.config, self.binding)
        self.assertEqual(c.reserve()['status'], 'RESERVED')
        patch_body = next(b for m, _, b in self.server.calls if m == 'PATCH')
        with self.assertRaises(audit.AuditError):
            t.request('PATCH', 'repos/' + NAME + '/git/refs/' + self.config['ref'][5:], patch_body)
        self.assertEqual(sum(m == 'PATCH' for m, _, _ in self.server.calls), 1)

    def test_changed_parent_between_commit_creation_and_update_precheck_rejected(self):
        def override(req):
            if '/git/ref/' in req.full_url and any(m=='POST' for m,_,_ in self.server.calls):
                return Response(200,{'ref':self.config['ref'],
                    'object':{'type':'commit','sha':'9'*40}},req.full_url)
        self.server.override=override
        self.assertEqual(self.client().reserve()['status'],'RESERVATION_NOT_GRANTED')
        self.assertFalse(any(m=='PATCH' for m,_,_ in self.server.calls))

    def test_created_object_readback_tampering_prevents_reference_update(self):
        def override(req):
            if '/git/commits/' in req.full_url and req.full_url.rsplit('/',1)[1]!=self.config['genesis_sha']:
                return Response(200,{'sha':req.full_url.rsplit('/',1)[1],
                    'tree':{'sha':'0'*40},'parents':[],'message':'{}'},req.full_url)
        self.server.override=override
        self.assertEqual(self.client().reserve()['status'],'RESERVATION_NOT_GRANTED')
        self.assertFalse(any(m=='PATCH' for m,_,_ in self.server.calls))

    def test_mid_process_forced_rollback_detected_but_new_run_requires_governance(self):
        c = self.client(); c.reserve(); c.consume(); self.server.head = self.config['genesis_sha']
        self.assertEqual(c.inspect()['status'], 'STATE_UNCERTAIN')
        self.assertEqual(self.client().inspect()['status'], 'NOT_RESERVED_REVIEW_REQUIRED')
        self.assertEqual(audit.backend_status()['status'], 'BLOCKED')

    def test_missing_previously_observed_ref_cannot_reinitialize(self):
        t = self.transport('INITIALIZE'); c = audit._IsolatedGitProtocol(t, self.config, self.binding)
        c.inspect(); self.server.absent = True
        with self.assertRaises(audit.AuditError): t.initialize_ref()
        self.assertFalse(any(m != 'GET' for m, _, _ in self.server.http))

    def test_ambiguous_write_burns_claim_and_does_not_retry(self):
        c = self.client(); self.server.failure = 'timeout_after'
        self.assertEqual(c.reserve()['status'], 'RESERVATION_NOT_GRANTED')
        self.assertEqual(c.consume()['status'], 'CONSUMPTION_DENIED')
        self.assertEqual(c.reserve()['status'], 'DUPLICATE_OR_UNCERTAIN_RESERVATION')
        self.assertEqual(sum(m == 'PATCH' for m, _, _ in self.server.calls), 1)
        self.assertEqual(self.client().inspect()['status'], 'RESERVED_REVIEW_REQUIRED')

    def test_forbidden_token_permissions_never_retried_or_converted_to_success(self):
        self.server.failure = 403; c = self.client()
        self.assertEqual(c.reserve()['status'], 'RESERVATION_NOT_GRANTED')
        self.assertEqual(c.consume()['status'], 'CONSUMPTION_DENIED')
        self.assertEqual(sum(m == 'PATCH' for m, _, _ in self.server.calls), 1)

    def test_invalid_record_object_and_content_tree_fail_closed(self):
        root = self.server.objects[self.config['genesis_sha']]; root['message'] = '{}'
        self.assertEqual(self.client().reserve()['status'], 'RESERVATION_NOT_GRANTED')
        t = self.transport()
        self.server.override = lambda req: Response(200, {'sha': rest.EMPTY_TREE, 'tree': [1],
            'truncated': False}, req.full_url) if '/git/trees/' in req.full_url else None
        with self.assertRaises(audit.AuditError): t.verify_tree()

    def test_redirect_duplicate_keys_oversize_and_timeout_sanitized(self):
        t = self.transport()
        for response in (Response(200, {}, 'https://evil.invalid/'),
                         io.BytesIO(b'{"id":1,"id":2}'), io.BytesIO(b'x'*(rest.MAX_RESPONSE+1))):
            if not hasattr(response, 'status'): response.status=200; response.geturl=lambda: rest.API+'repos/'+NAME
            self.server.override=lambda req, r=response: r
            with self.assertRaisesRegex(audit.AuditError, '^AUDIT_API_OUTCOME_UNCERTAIN$'):
                t.request('GET', 'repos/'+NAME)

    def governance(self):
        target={'ref_name': {'include': ['refs/heads/ci-v2-authority-audit/*'], 'exclude': []}}
        self.server.rules={1:{'id':1,'target':'branch','enforcement':'active','conditions':target,
            'bypass_actors':[],'rules':[{'type':x} for x in ('deletion','non_fast_forward','required_linear_history')]},
            2:{'id':2,'target':'branch','enforcement':'active','conditions':target,
            'bypass_actors':[{'actor_id':3,'actor_type':'Integration','bypass_mode':'always'}],
            'rules':[{'type':'creation'},{'type':'update','parameters':{'update_allows_fetch_and_merge':False}}]}}
        self.config['governance_sha256']=digest({'schema_version':1,'rulesets':list(self.server.rules.values())})
        self.server.config=deepcopy(self.config)
        self.server.objects[self.config['genesis_sha']]['message']=audit._message(audit._genesis(self.config,self.binding))

    def test_matching_rulesets_do_not_establish_credential_or_control_plane_trust(self):
        self.governance(); result=self.transport().observe_governance(1,2,3)
        self.assertEqual(result['status'],'PINNED_RULESETS_OBSERVED')
        self.assertEqual(result['writer_credential_isolation'],'NOT_VERIFIED')
        self.assertEqual(result['independent_governance'],'NOT_VERIFIED')
        self.server.rules[1]['bypass_actors']=[{'actor_type':'RepositoryRole','actor_id':5,'bypass_mode':'always'}]
        with self.assertRaises(audit.AuditError): self.transport().observe_governance(1,2,3)

    def test_connected_hosted_v2_reader_still_refuses_live_apply(self):
        self.governance(); f=self.f
        f.config.update(schema_version=2,transaction_backend={'kind':'GITHUB_GIT_AUDIT_V1',
            'audit':self.config,'history_ruleset_id':1,'writer_ruleset_id':2,'writer_integration_id':3})
        with f.boundaries(), patch.dict('os.environ',{**f.deploy_env(),'GH_TOKEN':'synthetic-token'}), \
             patch.object(rest.urllib.request,'build_opener',return_value=self.server):
            result=hosted._run(f.root)
        self.assertEqual(result['reason'],'AUDIT_WRITER_AND_INDEPENDENT_GOVERNANCE_NOT_VERIFIED')
        self.assertEqual(result['audit_backend']['status'],'GITHUB_AUDIT_READBACK_VERIFIED')
        self.assertEqual(result['audit_backend']['state']['scope'],'AUTHENTICATED_GITHUB_READBACK_ONLY')
        self.assertFalse(result['registry_committed'])
        self.assertFalse(any(m!='GET' for m,_,_ in self.server.http))

    def test_wrong_owner_or_workflow_blocks_before_audit_transport(self):
        f=self.f
        for row,key in ((f.run['actor'],'id'),(f.workflow,'id')):
            old=row[key];row[key]=999
            with f.boundaries(),patch.dict('os.environ',f.deploy_env()),patch.object(rest,'GitHubAuditTransport') as factory:
                self.assertEqual(hosted._run(f.root)['status'],'BLOCKED');factory.assert_not_called()
            row[key]=old

    def test_full_protocol_completion_with_existing_isolated_core(self):
        f=audit_tests.DurableAuditTests();f.setUp();self.addCleanup(f.doCleanups)
        c={**f.config,'tree_sha':rest.EMPTY_TREE};model=Server(c,f.binding)
        t=rest.GitHubAuditTransport(c,f.binding,'synthetic-token',write_scope='APPEND');t._opener=model
        client=audit._IsolatedGitProtocol(t,c,f.binding)
        self.assertEqual(client.reserve()['status'],'RESERVED')
        self.assertEqual(client.consume()['status'],'CONSUMED_OFFLINE')
        result=f.f.apply();raw=(f.f.work/'registry.json').read_bytes()
        self.assertEqual(client.complete(raw,result)['status'],'COMPLETED_OFFLINE')
        self.assertEqual(f.f.authoritative.read_bytes(),f.f.old)
        self.assertEqual(client.complete(raw,result)['status'],'COMPLETION_DENIED')


if __name__=='__main__': unittest.main()
