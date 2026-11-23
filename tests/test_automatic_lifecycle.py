"""Offline integration: real lineage/protocol code, modeled GitHub and drivers.

Positive scientific decisions use controlled rows and mocked transition helper;
these are not a real qualified Candidate or genuine Hosted proof.
"""
from copy import deepcopy
from datetime import datetime,timezone
import base64,hashlib,json,threading,unittest
from unittest.mock import patch
from pathlib import Path
import tempfile
from src import derived_parent_registry as state,automatic_writer as writer
from src import automatic_candidate as native,automatic_lifecycle_policy as policy_api
from src import parent_authority_git_audit as audit
from src.corpus_snapshot import digest
from test_parent_authority_git_audit import GitModel
from test_gradio_deployment_adapter import Driver
from src.gradio_deployment_adapter import _replace


class StateModel:
    def __init__(self,registry,lineage):
        self.lock=threading.RLock();self.rows={};self.current='a'*40
        self.rows[self.current]={'sha':self.current,'parent':None,'registry.json':deepcopy(registry),'lineage.json':deepcopy(lineage)}
        self.fail=None
    def head(self):return self.current
    def read(self,sha):return deepcopy(self.rows[sha])
    def append(self,expected,registry,lineage):
        with self.lock:
            if expected!=self.current:raise ValueError('STALE_DERIVED_HEAD')
            if self.fail=='before':raise TimeoutError()
            sha=hashlib.sha1(state.serialize({'registry':registry,'lineage':lineage})).hexdigest()
            self.rows[sha]={'sha':sha,'parent':expected,'registry.json':deepcopy(registry),'lineage.json':deepcopy(lineage)}
            self.current=sha
            if self.fail=='after':raise TimeoutError()
            return sha


def policy():
    value={k:'c'*64 for k in policy_api.FIELDS if k.endswith('_sha256')}
    value.update(schema_version=1,kind='AUTOMATIC_LIFECYCLE_V1',enabled=True,repository='FixtureOwner/ContinuousTest',
        repository_id=10001,root_revision='b'*40,initial_parent_key='root',genesis_sha='a'*40,
        valid_from='2020-01-01T00:00:00Z',expires_at='2099-01-01T00:00:00Z',max_generations=8,max_advance_commits=10,
        build_fingerprint='d'*64,release_prefix='admitted',writer_environment='ci-v2-audit-writer',
        history_ruleset_id=1,writer_ruleset_id=2,writer_integration_id=5855475,installation_id=184185108,
        deployment_path='configs/deployment.json',permissions={k:True for k in ('construction','admission','publication','derived_registry','deployment')},
        licenses=[{'name':'license'+str(i)+'.txt','repository':'PROJECT','path':'LICENSE','sha256':'f'*64} for i in range(7)])
    return policy_api.validate(value,'e'*64)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.policy=policy();self.registry={'schema_version':2,'baselines':{'root':{'authority':'BUILD_CANDIDATE'}}}
        self.policy['root_registry_canonical_sha256']=digest(self.registry)
        self.store=StateModel(self.registry,state.genesis(self.registry,self.policy))
        self.models={};self.entries={}
        self.actor={'run_id':1,'run_attempt':1,'actor_id':9,'workflow_id':10,'workflow_path':'.github/workflows/upstream_refresh.yml',
            'event':'schedule','commit_sha':'b'*40}
        self.config={'implementation_revision':'b'*40}
        self.release={'assets':{'notices.zip':{'sha256':'c'*64}}}
    def view(self):
        return state.consume(self.store,self.policy,self.registry,self.verify_entry)
    def verify_entry(self,item,entry,previous,sha):
        old={'head':previous['sha'],'registry':previous['registry.json'],'selected_parent':item['previous_parent_key']}
        expected,cfg,binding,_=writer.transaction(self.policy,self.config,old,item['parent_key'],entry,item['release'],
            {'actor':item['writer_actor'],'origin':item['producer']})
        self.assertEqual({k:v for k,v in item.items() if k!='audit_consumption_head'},expected)
        protocol=audit._IsolatedGitProtocol(self.models[item['transition_id']],cfg,binding)
        if protocol.inspect()['status']!='COMPLETED_REVIEW_REQUIRED':raise ValueError('INCOMPLETE_DERIVED_TRANSACTION')
        _,events=protocol._scan()
        self.assertEqual(events[1][0],item['audit_consumption_head'])
        receipt={'operation':'AUTOMATIC_PARENT_ADVANCEMENT_V1','transaction_id':item['transition_id'],
            'state_sha':sha,'registry_sha256':item['new_registry_sha256']}
        self.assertEqual(events[-1][1]['receipt_sha256'],digest(receipt))
        return True
    def proposal(self,view,key='next',run=1):
        actor={**self.actor,'run_id':run}
        entry={'reference':{'node_id':'sha256-'+digest(key)},'expected_reference_sha256':'d'*64}
        item,cfg,binding,_=writer.transaction(self.policy,self.config,view,key,entry,self.release,{'actor':actor,'origin':{'run_id':run}})
        model=self.models.setdefault(item['transition_id'],GitModel(cfg,binding))
        protocol=audit._IsolatedGitProtocol(model,cfg,binding)
        return entry,item,protocol,model
    def advance(self,view,key='next',run=1):
        entry,item,protocol,model=self.proposal(view,key,run)
        return state.advance(self.store,view,key,entry,item,protocol,lambda:None),model
    def test_two_successive_generations_and_real_protocol_completion(self):
        before=deepcopy(self.registry)
        for i in (1,2):
            result,_=self.advance(self.view(),'parent'+str(i),i)
            self.assertEqual(result['status'],'PARENT_ADVANCED')
            self.assertEqual(self.view()['selected_parent'],'parent'+str(i))
            self.assertEqual(self.view()['generation'],i)
        self.assertEqual(self.registry,before)
    def test_stale_snapshot_cannot_consume_or_write(self):
        old=self.view();self.advance(old,'first');entry,item,protocol,model=self.proposal(old,'second',2)
        result=state.advance(self.store,old,'second',entry,item,protocol,lambda:None)
        self.assertNotEqual(result['status'],'PARENT_ADVANCED')
        self.assertFalse(any(method!='GET' for method,_,_ in model.calls))
    def test_duplicate_delivery_does_not_advance(self):
        old=self.view();self.advance(old)
        result,_=self.advance(old)
        self.assertNotEqual(result['status'],'PARENT_ADVANCED');self.assertEqual(self.view()['generation'],1)
    def test_concurrent_successor_only_one_can_advance(self):
        old=self.view();proposals=[self.proposal(old,k,i+1) for i,k in enumerate(('one','two'))]
        barrier=threading.Barrier(2);out=[]
        def act(index):
            entry,item,protocol,model=proposals[index]
            first=True
            def validate():
                nonlocal first
                if first:first=False;barrier.wait(timeout=5)
            out.append(state.advance(self.store,old,('one','two')[index],entry,item,protocol,validate))
        threads=[threading.Thread(target=act,args=(i,)) for i in (0,1)]
        for t in threads:t.start()
        for t in threads:t.join(timeout=10);self.assertFalse(t.is_alive())
        self.assertEqual(sum(r['status']=='PARENT_ADVANCED' for r in out),1)
        self.assertEqual(self.view()['generation'],1)
    def test_interrupted_after_consumption_stays_burned(self):
        self.store.fail='before';result,model=self.advance(self.view())
        self.assertEqual(result['status'],'STATE_UNCERTAIN')
        self.assertEqual(result['audit_state'],'CONSUMED_REVIEW_REQUIRED')
        self.assertEqual(self.view()['generation'],0)
    def test_uncertain_data_write_is_not_accepted_by_consumer(self):
        self.store.fail='after';result,_=self.advance(self.view())
        self.assertEqual(result['status'],'STATE_UNCERTAIN')
        with self.assertRaisesRegex(ValueError,'INCOMPLETE_DERIVED_TRANSACTION'):self.view()
    def test_completion_timeout_does_not_issue_second_mutation(self):
        old=self.view();entry,item,protocol,model=self.proposal(old)
        def validate():
            if protocol.inspect()['status']=='CONSUMED_REVIEW_REQUIRED' and self.store.head()!=old['head']:
                model.failure='timeout_after'
        result=state.advance(self.store,old,'next',entry,item,protocol,validate)
        self.assertEqual(result['status'],'STATE_UNCERTAIN')
        self.assertEqual(sum(m=='PATCH' for m,_,_ in model.calls),3)
    def test_old_registry_entry_mutation_rejected(self):
        self.advance(self.view());self.store.rows[self.store.head()]['registry.json']['baselines']['root']['authority']='BAD'
        with self.assertRaisesRegex(ValueError,'REGISTRY_REWRITE'):self.view()
    def test_lineage_rewrite_rejected(self):
        self.advance(self.view());self.store.rows[self.store.head()]['lineage.json']['root_revision']='0'*40
        with self.assertRaisesRegex(ValueError,'LINEAGE_REWRITE'):self.view()
    def test_uncompleted_generation_never_becomes_parent(self):
        self.store.fail='after';self.advance(self.view());self.store.fail=None
        with self.assertRaises(ValueError):self.view()
    def test_generation_limit(self):
        self.advance(self.view());self.policy['max_generations']=0
        with self.assertRaisesRegex(ValueError,'DERIVED_GENERATION_LIMIT'):self.view()
    def test_policy_expiry_and_missing_scope_fail_closed(self):
        raw={k:v for k,v in self.policy.items() if k in policy_api.FIELDS}
        for change in ({'expires_at':'2020-01-02T00:00:00Z'},{'permissions':{}},{'writer_environment':'other'}):
            with self.subTest(change=change),self.assertRaises(ValueError):policy_api.validate({**raw,**change},'f'*64)
    def test_empty_or_noncanonical_state_rejected(self):
        for raw in (b'{}',b'{"x":1,"x":2}\n',b'x'*(128*1024+1)):
            with self.subTest(raw=raw[:20]),self.assertRaises(ValueError):state.parse(raw)
    def test_read_only_state_transport_cannot_write(self):
        transport=state.GitState('FixtureOwner/Test',1,'fixture-token')
        with self.assertRaisesRegex(ValueError,'DERIVED_WRITE_NOT_AUTHORIZED'):transport.append('a'*40,{}, {})
    def test_transport_denies_other_refs_and_deletion(self):
        transport=state.GitState('FixtureOwner/Test',1,'fixture-token',writable=True)
        for method,path in (('GET','/git/ref/heads/main'),('DELETE','/git/refs/x'),('POST','/git/refs')):
            with self.subTest(method=method),self.assertRaisesRegex(ValueError,'UNSUPPORTED_DERIVED'):transport._call(method,path,{})
    def test_deployment_two_generations_and_rollback(self):
        driver=Driver();initial=driver.current()
        first=_replace(driver,initial,'v1');self.assertIn(first['status'],('ACTIVE_VERIFIED','ACTIVE_CLEANUP_PENDING'))
        driver.fail='verification'
        failed=_replace(driver,driver.current(),'v2')
        self.assertNotEqual(failed['status'],'ACTIVE_VERIFIED');self.assertEqual(driver.current(),'v1')


class ScientificDecisionTests(unittest.TestCase):
    def setUp(self):
        self.mapping={'summary':{k:0 for k in ('unsupported_instances','ambiguous_instances','unresolved_instances',
            'semantic_review_instances','applicability_review_instances')}}
        self.rows=[{'strict':{'hit_at_5':True,'hit_at_10':True}}]
        self.patch=patch.object(native.ev,'compare_outcomes',return_value=[]);self.patch.start();self.addCleanup(self.patch.stop)
    def test_controlled_positive_kernel_is_not_real_scientific_approval(self):
        self.assertEqual(native._reasons(self.rows,{'base':[],'historical':[]},self.mapping,{}),[])
    def test_strict_failure_rejected(self):
        self.rows[0]['strict']['hit_at_5']=False
        self.assertIn('FROZEN_STRICT_FAILURE',native._reasons(self.rows,{'base':[],'historical':[]},self.mapping,{}))
    def test_new_loss_cannot_be_offset(self):
        native.ev.compare_outcomes.return_value=[{'hit5':'PASS→FAIL','hit10':'FAIL→PASS'}]
        self.assertIn('NEW_RETRIEVAL_REGRESSION',native._reasons(self.rows,{'base':[],'historical':[]},self.mapping,{}))
    def test_every_ambiguous_or_unresolved_q1_rejected(self):
        for key in self.mapping['summary']:
            changed=deepcopy(self.mapping);changed['summary'][key]=1
            self.assertIn('Q1_REVIEW_REQUIRED',native._reasons(self.rows,{'base':[],'historical':[]},changed,{}))
    def test_incomplete_seal_rejected_before_decision(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(Exception):native.verify(Path(d),Path(d),policy(),'sha256-'+'a'*64,{})
