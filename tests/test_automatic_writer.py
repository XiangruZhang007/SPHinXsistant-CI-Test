"""Real gate logic with explicit mocked API responses; no real token or writes."""
from copy import deepcopy
from pathlib import Path
import os,tempfile,unittest
from unittest.mock import patch,Mock
from src import automatic_writer as writer
from src.corpus_snapshot import digest
from scripts import parent_authority_writer_gate as manual
from test_automatic_lifecycle import policy as fixture_policy


class WriterGateTests(unittest.TestCase):
    def setUp(self):
        self.policy=fixture_policy();self.policy.update(repository=manual.REPOSITORY,repository_id=manual.REPOSITORY_ID)
        self.config={'repository':manual.REPOSITORY,'repository_id':manual.REPOSITORY_ID,'default_branch':'ci-upstream-refresh',
            'workflow_path':'.github/workflows/upstream_refresh.yml','implementation_revision':'a'*40}
        self.project=Path(__file__).resolve().parents[1];base='/repos/'+manual.REPOSITORY
        a={'id':1,'target':'branch','enforcement':'active','conditions':{'ref_name':{'include':['refs/heads/ci-v2-authority-audit/*'],'exclude':[]}},
            'bypass_actors':[],'rules':[{'type':k} for k in ('deletion','non_fast_forward','required_linear_history')]}
        b={**deepcopy(a),'id':2,'bypass_actors':[{'actor_id':manual.APP_ID,'actor_type':'Integration','bypass_mode':'always'}],
            'rules':[{'type':'creation'},{'type':'update','parameters':{'update_allows_fetch_and_merge':False}}]}
        params={'required_approving_review_count':1,'require_code_owner_review':True,'dismiss_stale_reviews_on_push':True}
        protected={'id':3,'target':'branch','enforcement':'active','bypass_actors':[],
            'conditions':{'ref_name':{'include':['refs/heads/ci-upstream-refresh'],'exclude':[]}},
            'rules':[{'type':'deletion'},{'type':'non_fast_forward'},{'type':'pull_request','parameters':params}]}
        env={'id':self.policy['writer_environment_id'],'name':self.policy['writer_environment'],'can_admins_bypass':False,'protection_rules':[{'id':1,'type':'branch_policy'}],
            'deployment_branch_policy':{'protected_branches':False,'custom_branch_policies':True}}
        self.responses={base:{'owner':{'id':manual.OWNER_ID}},base+'/environments/'+self.policy['writer_environment']:env,
            base+'/environments/'+self.policy['writer_environment']+'/deployment-branch-policies?per_page=100':{'total_count':1,'branch_policies':[{'name':'ci-upstream-refresh','type':'branch'}]},
            base+'/rules/branches/ci-upstream-refresh':[{'type':k,'ruleset_id':3} for k in ('deletion','non_fast_forward','pull_request')],
            base+'/rulesets/1':a,base+'/rulesets/2':b,base+'/rulesets/3':protected}
        self.policy['governance_sha256']=digest({'schema_version':1,'rulesets':[a,b]})
        self.client=Mock();self.client._api.side_effect=lambda method,path:deepcopy(self.responses[path]) if method=='GET' else self.fail('API WRITE')
        self.environment={'GITHUB_JOB':'automatic-parent-writer','GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_ARCH':'ARM64',
            'GITHUB_RUN_ATTEMPT':'1','GITHUB_WORKSPACE':str(self.project),'GITHUB_SHA':'a'*40,'GITHUB_WORKFLOW_SHA':'a'*40,
            'GITHUB_WORKFLOW_REF':manual.REPOSITORY+'/.github/workflows/upstream_refresh.yml@refs/heads/ci-upstream-refresh'}
        self.stack=[]
        for obj,name,kwargs in ((writer.genuine,'_checkout',{}),(writer.genuine,'_scheduled_context',{'return_value':{}}),
                (writer.genuine,'_scheduled_identity',{'return_value':{'run_id':10}}),
                (writer.completion,'origin',{'return_value':{'event':'schedule'}})):
            mock=patch.object(obj,name,**kwargs);mock.start();self.addCleanup(mock.stop)
    def observe(self,**kw):
        with patch.dict(os.environ,self.environment,clear=True):return writer.observe(self.project,self.config,self.policy,self.client,**kw)
    def test_pre_token_verifies_without_requesting_credentials(self):
        with patch.object(manual,'verify_token') as token:
            result=self.observe();self.assertEqual(result['origin']['event'],'schedule');token.assert_not_called()
        self.assertTrue(all(call.args[0]=='GET' for call in self.client._api.call_args_list))
    def test_existing_manual_environment_blocks_unattended_mode(self):
        self.responses['/repos/'+manual.REPOSITORY+'/environments/'+self.policy['writer_environment']]['protection_rules']=[{'type':'required_reviewers'}]
        with self.assertRaisesRegex(ValueError,'AUTOMATIC_ENVIRONMENT_CONFIGURATION_REQUIRED'):self.observe()
    def test_missing_branch_rule_or_additional_protection_is_not_unattended(self):
        env=self.responses['/repos/'+manual.REPOSITORY+'/environments/'+self.policy['writer_environment']]
        for rules in ([],[{'type':'branch_policy'},{'type':'wait_timer'}],
                [{'type':'branch_policy'},{'type':'required_reviewers'}],
                [{'type':'branch_policy'},{'type':'branch_policy'}]):
            with self.subTest(rules=rules):
                env['protection_rules']=rules
                with self.assertRaisesRegex(ValueError,'AUTOMATIC_ENVIRONMENT_CONFIGURATION_REQUIRED'):self.observe()
    def test_missing_or_wrong_app_installation_cannot_write(self):
        with patch.object(manual,'verify_token',side_effect=ValueError('WRITER_INSTALLATION_TOKEN_REQUIRED')):
            with self.assertRaisesRegex(ValueError,'WRITER_INSTALLATION_TOKEN_REQUIRED'):self.observe(token=True)
    def test_ruleset_b_absent_is_not_absent_security(self):
        del self.responses['/repos/'+manual.REPOSITORY+'/rulesets/2']
        with self.assertRaises(KeyError):self.observe()
    def test_history_bypass_rejected_even_if_policy_pin_updated(self):
        self.responses['/repos/'+manual.REPOSITORY+'/rulesets/1']['bypass_actors']=[{'actor_id':1}]
        with self.assertRaisesRegex(ValueError,'GOVERNANCE'):self.observe()
    def test_default_branch_bypass_rejected(self):
        self.responses['/repos/'+manual.REPOSITORY+'/rulesets/3']['bypass_actors']=[{'actor_id':1}]
        with self.assertRaisesRegex(ValueError,'BRANCH_PROTECTION'):self.observe()
    def test_wrong_environment_or_unexpected_branch_denied(self):
        self.responses['/repos/'+manual.REPOSITORY+'/environments/'+self.policy['writer_environment']]['id']=1
        with self.assertRaises(ValueError):self.observe()
    def test_manual_environment_identity_cannot_replace_automatic_environment(self):
        env=self.responses['/repos/'+manual.REPOSITORY+'/environments/'+self.policy['writer_environment']]
        env.update(id=manual.ENVIRONMENT_ID,name=manual.ENVIRONMENT)
        with self.assertRaisesRegex(ValueError,'AUTOMATIC_ENVIRONMENT_CONFIGURATION_REQUIRED'):self.observe()
    def test_wrong_job_or_revision_denied_before_api(self):
        for change in ({'GITHUB_JOB':'inspect-transition'},{'GITHUB_SHA':'b'*40},{'GITHUB_RUN_ATTEMPT':'2'}):
            with self.subTest(change=change),patch.dict(self.environment,change),self.assertRaises(ValueError):self.observe()
    def test_rule_change_after_observation_denied(self):
        self.observe();self.responses['/repos/'+manual.REPOSITORY+'/rulesets/2']['rules']=[]
        with self.assertRaises(ValueError):self.observe()
    def test_producer_must_be_scheduled(self):
        writer.completion.origin.return_value={'event':'workflow_dispatch'}
        with self.assertRaisesRegex(ValueError,'PRODUCER_NOT_SCHEDULED'):self.observe()


class WorkflowTests(unittest.TestCase):
    def test_separate_writer_job_and_no_key_in_build_job(self):
        import yaml
        project=Path(__file__).resolve().parents[1]
        value=yaml.safe_load((project/'.github/workflows/upstream_refresh.yml').read_text())
        jobs=value['jobs'];build=jobs['continuous-candidate'];privileged=jobs['automatic-parent-writer']
        self.assertEqual(build['permissions'],{'contents':'read','actions':'read'})
        self.assertNotIn('CI_V2_AUDIT_APP_PRIVATE_KEY',str(build));self.assertNotIn('environment',build)
        self.assertEqual(privileged['environment'],'ci-v2-automatic-writer')
        manual_workflow=yaml.safe_load((project/'.github/workflows/ci_v2_parent_authority_transition.yml').read_text())
        self.assertIn('ci-v2-audit-writer',[j.get('environment') for j in manual_workflow['jobs'].values()])
        steps=privileged['steps'];gate=next(i for i,s in enumerate(steps) if 'pre-token' in s.get('run',''))
        mint=next(i for i,s in enumerate(steps) if s.get('id')=='app-token')
        execute=next(i for i,s in enumerate(steps) if 'automatic_lifecycle.py advance' in s.get('run',''))
        self.assertLess(gate,mint);self.assertLess(mint,execute)
        self.assertEqual(steps[mint]['with']['permission-contents'],'write')
        self.assertNotIn('permission-administration',steps[mint]['with'])
        self.assertIn("github.event_name == 'schedule'",privileged['if'])
        self.assertIn("vars.AUTOMATIC_LIFECYCLE_ENABLED == 'true'",privileged['if'])
        self.assertIn("vars.AUTOMATIC_LIFECYCLE_ENABLED != 'true'",jobs['publish-continuous-candidate']['if'])


class OriginTests(unittest.TestCase):
    def setUp(self):
        from src import automatic_lifecycle as lifecycle
        self.lifecycle=lifecycle
        self.config={'repository':'FixtureOwner/Test','repository_id':1,'workflow_path':'.github/workflows/upstream_refresh.yml','default_branch':'research'}
        self.origin={**{k:self.config[k] for k in ('repository','repository_id','workflow_path')},'implementation_revision':'a'*40,
            'run_id':10,'run_attempt':1,'workflow_id':20,'event':'schedule','job_id':30}
        self.actor={**{k:self.origin[k] for k in ('repository','repository_id','workflow_path','workflow_id','run_id','run_attempt','event')},
            'branch':'research','commit_sha':'a'*40,'actor_id':9,'actor_login':'FixtureOwner','run_created_at':'2026-01-01T00:00:00+00:00'}
        self.receipt={'producer':self.origin,'writer_actor':self.actor,'implementation_revision':'a'*40}
        self.run={'actor':{'id':9,'type':'User','login':'FixtureOwner'},'triggering_actor':{'id':9,'type':'User'},
            'created_at':'2026-01-01T00:00:00Z','workflow_id':20}
        self.jobs={'total_count':1,'jobs':[{'name':'automatic-parent-writer','head_sha':'a'*40,'conclusion':'success','status':'completed'}]}
        self.client=Mock();self.client._api.side_effect=lambda method,path:deepcopy(self.jobs if '/jobs?' in path else self.run)
        p=patch.object(lifecycle.completion,'origin',return_value=self.origin);p.start();self.addCleanup(p.stop)
    def test_actual_first_attempt_and_exact_actor_record(self):
        result=self.lifecycle._origin(self.client,self.config,self.receipt)
        self.assertEqual(result,{'origin':self.origin,'actor':self.actor})
        self.assertTrue(any('/attempts/1' in c.args[1] for c in self.client._api.call_args_list))
    def test_changed_saved_actor_cannot_become_authorization(self):
        for field,value in (('workflow_path','other'),('actor_id',8),('run_attempt',2),('run_created_at','changed')):
            bad=deepcopy(self.receipt);bad['writer_actor'][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'DERIVED_ACTOR_MISMATCH'):
                self.lifecycle._origin(self.client,self.config,bad)
    def test_failed_writer_job_cannot_complete_a_parent(self):
        self.jobs['jobs'][0]['conclusion']='failure'
        with self.assertRaisesRegex(ValueError,'DERIVED_WRITER_NOT_COMPLETED'):
            self.lifecycle._origin(self.client,self.config,self.receipt)
