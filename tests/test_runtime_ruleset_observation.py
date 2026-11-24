"""Synthetic contract/API integration only; no Owner approval or Hosted science."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import subprocess
import io
import unittest
from unittest.mock import patch

from scripts import runtime_ruleset_observation as observation


class EvidenceFixture:
    def __init__(self, project, *, operation='MANUAL_R4', protected_id=3):
        self.project=project
        target={'ref_name':{'include':['refs/heads/ci-v2-authority-audit/*'],'exclude':[]}}
        a={'id':1,'target':'branch','enforcement':'active','conditions':target,'bypass_actors':[],
           'rules':[{'type':x} for x in ('deletion','non_fast_forward','required_linear_history')]}
        b={**deepcopy(a),'id':2,'bypass_actors':[{'actor_id':observation.APP_ID,'actor_type':'Integration','bypass_mode':'always'}],
           'rules':[{'type':'creation'},{'type':'update','parameters':{'update_allows_fetch_and_merge':False}}]}
        protected={'id':protected_id,'target':'branch','enforcement':'active',
           'conditions':{'ref_name':{'include':['refs/heads/ci-upstream-refresh'],'exclude':[]}},'bypass_actors':[],
           'rules':[{'type':'deletion'},{'type':'non_fast_forward'},{'type':'pull_request','parameters':{
               'required_approving_review_count':1,'require_code_owner_review':True,'dismiss_stale_reviews_on_push':True}}]}
        self.evidence={'schema_version':1,'kind':'OWNER_RUNTIME_RULESET_OBSERVATION_V1',
            'purpose':'RUNTIME_GOVERNANCE_POLICY_INPUT','repository':observation.REPOSITORY,
            'repository_id':observation.REPOSITORY_ID,'owner_id':observation.OWNER_ID,'default_branch':'ci-upstream-refresh',
            'observer':{'id':observation.OWNER_ID,'login':'XiangruZhang007','repository_admin_observed':True},
            'observed_at':'2020-01-01T00:00:00Z','expires_at':'2099-01-01T00:00:00Z',
            'history_ruleset_id':1,'writer_ruleset_id':2,'default_ruleset_id':protected_id,
            'writer_integration_id':observation.APP_ID,'rulesets':[a,b,protected]}
        self.policy={'schema_version':2,'trust_model':observation.MODEL,'repository':observation.REPOSITORY,
            'repository_id':observation.REPOSITORY_ID,'owner_id':observation.OWNER_ID,
            'workflow_path':'.github/workflows/ci_v2_parent_authority_transition.yml','default_branch':'ci-upstream-refresh',
            'implementation_contract_sha256':'0'*64,'valid_from':'2020-01-01T00:00:00Z','expires_at':'2099-01-01T00:00:00Z',
            'history_ruleset_id':1,'writer_ruleset_id':2,'writer_integration_id':observation.APP_ID,
            'risk_acceptance':observation.OWNER_RISK,
            'ruleset_observation':{'mode':observation.MODE,'evidence_path':'configs/runtime-observation.json',
                'evidence_sha256':'0'*64,'risk_acceptance':observation.RISK,'operation':operation}}
        self.operation=operation
        self.save()

    def save(self):
        path=self.project/'configs/runtime-observation.json';path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(self.evidence))
        if not (self.project/'.git').exists():
            subprocess.run(['git','init','-q',str(self.project)],check=True,capture_output=True)
        subprocess.run(['git','-C',str(self.project),'add','configs'],check=True,capture_output=True)
        self.policy['ruleset_observation']['evidence_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        self.governance=observation.digest({'schema_version':1,'rulesets':self.evidence['rulesets'][:2]})

    def load(self):
        return observation.load(self.project,self.policy,default_branch='ci-upstream-refresh',
            governance_sha256=self.governance,operation=self.operation)


class ObservationTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.f=EvidenceFixture(Path(t.name));self.live={r['id']:deepcopy(r) for r in self.f.evidence['rulesets']}

    def observe(self):
        return observation.observe(self.f.load(),lambda n:self.live[n])

    def test_all_explicit_bypass_lists_match_but_never_claim_complete_verification(self):
        result=self.observe()
        self.assertEqual({r['bypass_observation'] for r in result['bypass_visibility']},{'RETURNED_EXACT_MATCH'})
        self.assertFalse(result['complete_current_ruleset_verification'])
        self.assertEqual(result['authorization'],'NOT_GRANTED')

    def test_omitted_and_mixed_fields_are_unverified_without_mutating_live_data(self):
        for number in (1,2):del self.live[number]['bypass_actors']
        original=deepcopy(self.live);result=self.observe()
        self.assertEqual(result['bypass_visibility'][0]['bypass_observation'],'NOT_RETURNED_LIVE_BYPASS_UNVERIFIED')
        self.assertEqual(result['bypass_visibility'][2]['bypass_observation'],'RETURNED_EXACT_MATCH')
        self.assertEqual(original,self.live)
        self.assertNotIn('bypass_actors',self.live[1])

    def test_null_object_string_and_mismatched_visible_bypass_block(self):
        for bad in (None,{},'',False,[{'actor_id':observation.APP_ID}]):
            self.live[1]['bypass_actors']=bad
            with self.subTest(bad=bad),self.assertRaisesRegex(ValueError,'VISIBLE_BYPASS_MISMATCH'):self.observe()

    def test_observable_drift_and_missing_required_fields_block(self):
        for field,bad in (('enforcement','disabled'),('conditions',{}),('rules',[]),('id',True),('target',None)):
            old=deepcopy(self.live[1]);self.live[1][field]=bad
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'PUBLIC_RULESET_DRIFT'):self.observe()
            self.live[1]=old
        del self.live[1]['rules']
        with self.assertRaisesRegex(ValueError,'MALFORMED'):self.observe()

    def test_drift_after_an_initial_success_is_rejected(self):
        self.observe();self.live[2]['rules']=[]
        with self.assertRaisesRegex(ValueError,'DRIFT'):self.observe()

    def test_rest_update_omission_requires_actual_graphql_false_and_keeps_bypass_unverified(self):
        live=self.live[2];live['rules']=[{'type':'creation'},{'type':'update'}];live['node_id']='RRS_fixture'
        del live['bypass_actors'];original=deepcopy(live)
        with self.assertRaisesRegex(ValueError,'UPDATE_PARAMETER_UNVERIFIED'):self.observe()
        calls=[]
        def read(node,number):calls.append((node,number));return False
        result=observation.observe(self.f.load(),lambda n:self.live[n],update_read=read)
        self.assertEqual(calls,[('RRS_fixture',2)])
        self.assertEqual(result['update_parameters_observation'],'LIVE_GRAPHQL_FALSE_REST_PARAMETERS_OMITTED')
        self.assertEqual(result['bypass_visibility'][1]['bypass_observation'],'NOT_RETURNED_LIVE_BYPASS_UNVERIFIED')
        self.assertEqual(live,original)
        for bad in (True,None,0):
            with self.subTest(bad=bad),self.assertRaisesRegex(ValueError,'PARAMETER_UNSAFE'):
                observation.observe(self.f.load(),lambda n:self.live[n],update_read=lambda *a:bad)
        live['rules'][1]['parameters']=None
        with self.assertRaisesRegex(ValueError,'DRIFT'):
            observation.observe(self.f.load(),lambda n:self.live[n],update_read=read)

    def test_fixed_graphql_reader_requires_explicit_typed_value_scope_and_complete_result(self):
        value={'data':{'node':{'databaseId':2,'rules':{'pageInfo':{'hasNextPage':False},'nodes':[
            {'type':'CREATION','parameters':None},{'type':'UPDATE','parameters':{
                '__typename':'UpdateParameters','updateAllowsFetchAndMerge':False}}]}}}}
        class Response(io.BytesIO):
            def geturl(self):return 'https://api.github.com/graphql'
        def query(data):
            with patch.object(observation.urllib.request,'build_opener') as opener:
                opener.return_value.open.return_value=Response(json.dumps(data).encode())
                result=observation.live_update('synthetic-token','RRS_fixture',2)
                request=opener.return_value.open.call_args.args[0]
                body=json.loads(request.data)
                self.assertTrue(body['query'].startswith('query '));self.assertNotIn('mutation',body['query'])
                self.assertEqual(body['variables'],{'id':'RRS_fixture'})
                self.assertEqual(request.full_url,'https://api.github.com/graphql')
                return result
        self.assertIs(query(value),False)
        for mutation in ('id','missing','errors','page','type'):
            bad=deepcopy(value)
            if mutation=='id':bad['data']['node']['databaseId']=3
            if mutation=='missing':del bad['data']['node']['rules']['nodes'][1]['parameters']['updateAllowsFetchAndMerge']
            if mutation=='errors':bad['errors']=[{'message':'Synthetic denied'}]
            if mutation=='page':bad['data']['node']['rules']['pageInfo']['hasNextPage']=True
            if mutation=='type':bad['data']['node']['rules']['nodes'][1]['parameters']['updateAllowsFetchAndMerge']=0
            with self.subTest(mutation=mutation),self.assertRaisesRegex(ValueError,'PARAMETER_UNVERIFIED'):query(bad)
        with patch.object(observation.urllib.request,'build_opener',side_effect=OSError('synthetic')):
            with self.assertRaisesRegex(ValueError,'PARAMETER_UNVERIFIED'):
                observation.live_update('synthetic-token','RRS_fixture',2)

    def test_effective_default_origin_and_parameters_cannot_contradict_owner_pin(self):
        rows=[{**deepcopy(r),'ruleset_id':3} for r in self.f.evidence['rulesets'][2]['rules']]
        observation.effective_default(self.f.evidence,rows)
        for bad in ([],[{**r,'ruleset_id':1} for r in rows],
                    [{**r,'parameters':{}} if r['type']=='pull_request' else r for r in rows]):
            with self.subTest(bad=bad),self.assertRaisesRegex(ValueError,'EFFECTIVE_DEFAULT'):
                observation.effective_default(self.f.evidence,bad)

    def test_invalid_owner_evidence_and_credential_only_purpose_rejected_even_if_repinned(self):
        for key,bad in (('purpose','CREDENTIAL_VERIFICATION_ONLY'),('kind','OTHER'),
                ('owner_id',1),('observer',{'id':observation.OWNER_ID}),('repository_id',1),
                ('writer_integration_id',1),('rulesets',[]),('default_ruleset_id',1),('schema_version',True),('extra',True)):
            old=deepcopy(self.f.evidence);self.f.evidence[key]=bad;self.f.save()
            with self.subTest(key=key),self.assertRaises((ValueError,KeyError)):self.f.load()
            self.f.evidence=old;self.f.save()

    def test_owner_evidence_must_explicitly_include_all_bypass_lists(self):
        del self.f.evidence['rulesets'][0]['bypass_actors'];self.f.save()
        with self.assertRaisesRegex(ValueError,'OWNER_RULESET'):self.f.load()

    def test_owner_pin_cannot_approve_unsafe_default_or_audit_rules(self):
        for number in (0,1,2):
            old=deepcopy(self.f.evidence)
            self.f.evidence['rulesets'][number]['bypass_actors']=[] if number==1 else [{'actor_id':1}]
            self.f.save()
            with self.subTest(number=number),self.assertRaises(ValueError):self.f.load()
            self.f.evidence=old;self.f.save()
        self.f.evidence['rulesets'][1]['rules'][1]['parameters']['update_allows_fetch_and_merge']=0
        self.f.save()
        with self.assertRaisesRegex(ValueError,'AUDIT_RULES_UNSAFE'):self.f.load()

    def test_raw_pin_duplicate_json_and_symlink_rejected(self):
        path=self.f.project/'configs/runtime-observation.json';raw=path.read_bytes()
        path.write_bytes(raw+b' ')
        with self.assertRaisesRegex(ValueError,'PIN_MISMATCH'):self.f.load()
        path.write_bytes(b'{"schema_version":1,"schema_version":1}')
        self.f.policy['ruleset_observation']['evidence_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError,'JSON'):self.f.load()
        path.unlink();target=self.f.project/'target.json';target.write_bytes(raw);path.symlink_to(target)
        with self.assertRaisesRegex(ValueError,'SYMLINK'):self.f.load()

    def test_even_correctly_pinned_untracked_runtime_evidence_is_rejected(self):
        subprocess.run(['git','-C',str(self.f.project),'rm','--cached','configs/runtime-observation.json'],check=True,capture_output=True)
        with self.assertRaisesRegex(ValueError,'MUST_BE_TRACKED'):self.f.load()

    def test_read_only_git_tracking_probe_does_not_inherit_credentials(self):
        import os
        with patch.dict(os.environ,{'PARENT_AUTHORITY_AUDIT_TOKEN':'synthetic-token','GH_TOKEN':'synthetic-token'}), \
                patch.object(observation.subprocess,'run',wraps=subprocess.run) as run:
            self.f.load()
        env=run.call_args.kwargs['env']
        self.assertNotIn('PARENT_AUTHORITY_AUDIT_TOKEN',env)
        self.assertNotIn('GH_TOKEN',env)

    def test_expired_future_and_policy_outside_evidence_window_rejected(self):
        for target,key,bad in ((self.f.evidence,'expires_at','2000-01-01T00:00:00Z'),
                (self.f.evidence,'observed_at','2098-01-01T00:00:00Z'),
                (self.f.policy,'expires_at','2099-12-01T00:00:00Z'),
                (self.f.policy,'valid_from','2098-01-01T00:00:00Z')):
            old=target[key];target[key]=bad;self.f.save()
            with self.subTest(key=key,bad=bad),self.assertRaisesRegex(ValueError,'NOT_CURRENT'):self.f.load()
            target[key]=old;self.f.save()

    def test_policy_mode_operation_risk_and_governance_pin_are_required(self):
        descriptor=self.f.policy['ruleset_observation']
        for key,bad in (('mode','OTHER'),('operation','AUTOMATIC_LIFECYCLE'),('risk_acceptance','VERIFIED')):
            old=descriptor[key];descriptor[key]=bad
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'RISK_AND_SCOPE'):self.f.load()
            descriptor[key]=old
        self.f.governance='0'*64
        with self.assertRaisesRegex(ValueError,'GOVERNANCE_PIN'):self.f.load()


class SharedIntegrationTests(unittest.TestCase):
    def test_legacy_manual_automatic_and_transport_do_not_gain_missing_field_fallback(self):
        import test_parent_authority_writer_workflow as manual_fixture
        import test_automatic_writer as automatic_fixture
        import test_parent_authority_github_transport as transport_fixture
        manual=manual_fixture.WriterGateTests();manual.setUp();self.addCleanup(manual.doCleanups)
        del manual.responses[manual.base+'/rulesets/5']['bypass_actors']
        with self.assertRaises(ValueError):manual.verify()
        automatic=automatic_fixture.WriterGateTests();automatic.setUp();self.addCleanup(automatic.doCleanups)
        del automatic.responses['/repos/'+observation.REPOSITORY+'/rulesets/1']['bypass_actors']
        with self.assertRaises(ValueError):automatic.observe()
        transport=transport_fixture.GitHubTransportTests();transport.setUp();self.addCleanup(transport.doCleanups)
        transport.governance();del transport.server.rules[1]['bypass_actors']
        with self.assertRaises(ValueError):transport.transport().observe_governance(1,2,3)

    def test_manual_gate_uses_shared_observation_and_retains_actor_environment_and_subject_checks(self):
        import test_parent_authority_writer_workflow as fixtures
        f=fixtures.WriterGateTests();f.setUp();self.addCleanup(f.doCleanups)
        evidence=EvidenceFixture(f.root,protected_id=5)
        evidence.evidence['rulesets'][2]=deepcopy(f.responses[f.base+'/rulesets/5'])
        for r in evidence.evidence['rulesets'][2]['rules']:r.pop('ruleset_id',None)
        evidence.save()
        evidence.policy['implementation_contract_sha256']=f.config['implementation_contract_sha256']
        path=f.root/'configs/governance.json';path.write_text(json.dumps(evidence.policy))
        subprocess.run(['git','-C',str(f.root),'add','configs'],check=True,capture_output=True)
        f.config.update(schema_version=3,governance={'trust_model':observation.MODEL,'policy_path':'configs/governance.json',
            'policy_sha256':hashlib.sha256(path.read_bytes()).hexdigest()},transaction_backend={
                'history_ruleset_id':1,'writer_ruleset_id':2,'writer_integration_id':observation.APP_ID,
                'audit':{'governance_sha256':evidence.governance}})
        raw=json.dumps(f.config);f.env.update(PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_JSON=raw,
            PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_SHA256=hashlib.sha256(raw.encode()).hexdigest())
        for row in evidence.evidence['rulesets']:
            live=deepcopy(row);del live['bypass_actors'];f.responses[f.base+'/rulesets/'+str(row['id'])]=live
        result=f.verify();self.assertEqual(result['authorization'],'NOT_GRANTED')
        self.assertFalse(result['ruleset_observation']['complete_current_ruleset_verification'])
        self.assertTrue(all(token is None for _,token in f.calls))
        f.env['GITHUB_ACTOR_ID']='1'
        with self.assertRaisesRegex(ValueError,'IDENTITY'):f.verify()
        f.env['GITHUB_ACTOR_ID']=str(observation.OWNER_ID)
        f.responses[f.base+'/environments/ci-v2-audit-writer']['can_admins_bypass']=True
        with self.assertRaisesRegex(ValueError,'ENVIRONMENT'):f.verify()

    def test_automatic_writer_and_each_reobservation_use_same_contract(self):
        import test_automatic_writer as fixtures
        f=fixtures.WriterGateTests();f.setUp();self.addCleanup(f.doCleanups)
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);f.project=Path(t.name)
        f.environment['GITHUB_WORKSPACE']=str(f.project)
        evidence=EvidenceFixture(f.project,operation='AUTOMATIC_LIFECYCLE')
        f.policy.update(schema_version=2,ruleset_observation=evidence.policy['ruleset_observation'],
            valid_from=evidence.policy['valid_from'],expires_at=evidence.policy['expires_at'],governance_sha256=evidence.governance)
        for row in evidence.evidence['rulesets']:
            live=deepcopy(row);del live['bypass_actors']
            f.responses['/repos/'+observation.REPOSITORY+'/rulesets/'+str(row['id'])]=live
        f.responses['/repos/'+observation.REPOSITORY+'/rules/branches/ci-upstream-refresh']=[
            {**deepcopy(r),'ruleset_id':3} for r in evidence.evidence['rulesets'][2]['rules']]
        with patch.object(fixtures.manual,'verify_token') as token:
            result=f.observe();token.assert_not_called()
        self.assertFalse(result['ruleset_observation']['complete_current_ruleset_verification'])
        f.responses['/repos/'+observation.REPOSITORY+'/rulesets/2']['rules']=[]
        with self.assertRaisesRegex(ValueError,'DRIFT'):f.observe()

    def test_actual_audit_transport_and_owner_policy_loader_keep_write_authority_separate(self):
        import test_parent_authority_github_transport as fixtures
        from src import owner_managed_governance as governance
        f=fixtures.GitHubTransportTests();f.setUp();self.addCleanup(f.doCleanups)
        evidence=EvidenceFixture(f.f.root)
        f.config['governance_sha256']=evidence.governance
        for row in evidence.evidence['rulesets']:
            live=deepcopy(row);del live['bypass_actors'];f.server.rules[row['id']]=live
        transport=f.transport()
        result=transport.observe_governance(1,2,observation.APP_ID,project=f.f.root,
            policy=evidence.policy,operation='MANUAL_R4')
        self.assertEqual(result['authorization'],'NOT_GRANTED')
        self.assertTrue(all(method=='GET' for method,_,_ in f.server.http))
        bad=deepcopy(evidence.policy);bad['repository_id']=1
        with self.assertRaisesRegex(ValueError,'REPOSITORY_MISMATCH'):
            transport.observe_governance(1,2,observation.APP_ID,project=f.f.root,policy=bad,operation='MANUAL_R4')
        backend={'history_ruleset_id':1,'writer_ruleset_id':2,'writer_integration_id':observation.APP_ID,'audit':{'governance_sha256':evidence.governance}}
        policy_path=f.f.root/'configs/governance.json';policy_path.write_text(json.dumps(evidence.policy))
        subprocess.run(['git','-C',str(f.f.root),'add','configs'],check=True,capture_output=True)
        config={'request':{k:evidence.policy[k] for k in ('repository','repository_id','workflow_path','default_branch')},
            'transaction_backend':backend,'implementation_contract_sha256':'0'*64,
            'governance':{'trust_model':observation.MODEL,'policy_path':'configs/governance.json',
                'policy_sha256':hashlib.sha256(policy_path.read_bytes()).hexdigest()}}
        self.assertEqual(governance.load(f.f.root,config),evidence.policy)
        from scripts import parent_authority_writer_gate as gate
        with patch.object(gate,'verify'),patch.object(gate,'verify_token',return_value={'authorization':'NOT_GRANTED'}):
            observed=governance.observe(f.f.root,config,transport)
        self.assertFalse(observed['complete_current_ruleset_verification'])
        f.server.rules[1]['bypass_actors']=[{'actor_id':1}]
        with self.assertRaisesRegex(ValueError,'BYPASS_MISMATCH'):
            transport.observe_governance(1,2,observation.APP_ID,project=f.f.root,policy=evidence.policy,operation='MANUAL_R4')

    def test_existing_manual_effectful_revalidation_stops_on_shared_projection_drift(self):
        import test_parent_authority_writer_execution as fixtures
        for fail_on in (1,2,3,4):
            with self.subTest(revalidation=fail_on):
                f=fixtures.WriterExecutionTests();f.setUp();self.addCleanup(f.doCleanups)
                evidence=EvidenceFixture(f.f.project)
                live={r['id']:deepcopy(r) for r in evidence.evidence['rulesets']}
                for row in live.values():del row['bypass_actors']
                calls=[];failures=[]
                def revalidate():
                    calls.append(True)
                    if len(calls)==fail_on:live[2]['enforcement']='disabled'
                    try:observation.observe(evidence.load(),lambda n:live[n])
                    except ValueError as error:
                        failures.append(str(error));raise
                    return deepcopy(f.observed)
                result=f.execute(revalidate=revalidate)
                self.assertNotEqual(result['status'],'COMPLETED')
                self.assertEqual(failures,['RUNTIME_PUBLIC_RULESET_DRIFT'])
                self.assertIn(result['reason'],('WRITER_TRANSACTION_FAILED_OR_UNCERTAIN','ISOLATED_APPLY_NOT_COMPLETED'))
                self.assertFalse(result['authoritative_registry_applied'])
                f.assert_unchanged()
                self.assertEqual(sum(m=='PATCH' for m,_,_ in f.fixture.model.calls),min(fail_on-1,2))

    def test_automatic_policy_version_and_existing_generation_bounds_remain_mandatory(self):
        from test_automatic_lifecycle import policy as fixture_policy
        from src import automatic_lifecycle_policy as policies
        value={k:v for k,v in fixture_policy().items() if k in policies.FIELDS}
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        evidence=EvidenceFixture(Path(t.name),operation='AUTOMATIC_LIFECYCLE')
        value.update(schema_version=2,ruleset_observation=evidence.policy['ruleset_observation'])
        self.assertEqual(policies.validate(value,'a'*64)['schema_version'],2)
        for field,bad in (('schema_version',1),('max_generations',9),('max_generations',0),('max_advance_commits',4097)):
            invalid={**value,field:bad}
            with self.subTest(field=field,bad=bad),self.assertRaises(ValueError):policies.validate(invalid,'a'*64)
        with self.assertRaises(ValueError):policies.validate({k:v for k,v in value.items() if k!='ruleset_observation'},'a'*64)


if __name__=='__main__':unittest.main()
