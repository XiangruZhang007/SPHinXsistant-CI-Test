import importlib.util
from pathlib import Path
from copy import deepcopy
from unittest.mock import patch
import os
import json
import tempfile
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
import unittest
spec=importlib.util.spec_from_file_location('verifier',Path(__file__).resolve().parents[1]/'scripts/verify_ci_v2_writer_credentials.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)

class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.calls=[];self.change=None
    def api(self,method,path,token,body=None):
        self.calls.append((method,path,token,body))
        if path.startswith('/repos/'+v.REPOSITORY+'/rulesets/'):
            _,rows,_=self.context()
            result=deepcopy(rows[path])
            if self.change=='hidden-bypass':result.pop('bypass_actors')
            if self.change=='changed-bypass':result['bypass_actors']=[{'actor_id':1}]
            return result
        if path=='/app':return {'id':v.APP_ID,'slug':'sphinxsistant-audit-writer','permissions':v.PERMISSIONS}
        if path=='/app/installations/'+str(v.INSTALLATION_ID):
            r={'id':v.INSTALLATION_ID,'app_id':v.APP_ID,'account':{'id':v.OWNER_ID},'repository_selection':'selected','suspended_at':None,'permissions':deepcopy(v.PERMISSIONS)}
            if self.change=='extra-permission':r['permissions']['administration']='write'
            if self.change=='wrong-installation':r['id']=1
            if self.change=='suspended':r['suspended_at']='2026-11-24T00:00:00Z'
            return r
        if method=='POST':
            perm={**body['permissions'],'metadata':'read'}
            if self.change=='token-permission':perm['contents']='read'
            return {'token':'synthetic-'+body['permissions']['contents'],'permissions':perm}
        if method=='DELETE':
            if self.change=='revoke-failure':raise ValueError('SYNTHETIC_REVOKE_FAILURE')
            return {}
        if path=='/installation/repositories?per_page=100':
            repos=[{'id':v.REPOSITORY_ID,'full_name':v.REPOSITORY}]
            if self.change=='extra-repo':repos.append({'id':2,'full_name':'Fixture/Other'})
            if self.change=='wrong-repo':repos[0]['id']=2
            return {'total_count':len(repos),'repositories':repos}
        if path=='/repos/'+v.REPOSITORY:
            if self.change=='unusable':raise ValueError('SYNTHETIC_API_FAILURE')
            return {'id':v.REPOSITORY_ID,'full_name':v.REPOSITORY}
        raise AssertionError('UNEXPECTED_API')
    def context(self, name='ci-v2-automatic-writer'):
        env={'WRITER_ENVIRONMENT':name,'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted',
            'GITHUB_REPOSITORY':v.REPOSITORY,'GITHUB_REPOSITORY_ID':str(v.REPOSITORY_ID),
            'GITHUB_ACTOR_ID':str(v.OWNER_ID),'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_RUN_ATTEMPT':'1',
            'GITHUB_REF':'refs/heads/ci-upstream-refresh','GITHUB_WORKFLOW_REF':v.REPOSITORY+'/'+v.WORKFLOW+'@refs/heads/ci-upstream-refresh',
            'GITHUB_SHA':'a'*40,'GITHUB_WORKFLOW_SHA':'a'*40,'GITHUB_RUN_ID':'10','GH_TOKEN':'fixture-reader'}
        base='/repos/'+v.REPOSITORY
        rows={base:{'id':v.REPOSITORY_ID,'owner':{'id':v.OWNER_ID},'default_branch':'ci-upstream-refresh'},
            base+'/actions/runs/10/attempts/1':{'event':'workflow_dispatch','run_attempt':1,'head_sha':'a'*40,'path':v.WORKFLOW,'actor':{'id':v.OWNER_ID},'triggering_actor':{'id':v.OWNER_ID}},
            base+'/git/ref/heads/ci-upstream-refresh':{'object':{'sha':'a'*40}},
            base+'/environments/'+name:{'id':v.ENVIRONMENTS[name],'name':name,'can_admins_bypass':False,'deployment_branch_policy':{'protected_branches':False,'custom_branch_policies':True},'protection_rules':[{'type':'branch_policy'}]},
            base+'/environments/'+name+'/deployment-branch-policies?per_page=100':{'total_count':1,'branch_policies':[{'name':'ci-upstream-refresh','type':'branch'}]}}
        for number,target,types in [(27770139,'ci-v2-authority-audit/*',['deletion','non_fast_forward','required_linear_history']),(27793434,'ci-upstream-refresh',['deletion','non_fast_forward','pull_request'])]:
            rules=[{'type':k} for k in types]
            if number==27793434:rules[-1]['parameters']={'required_approving_review_count':1,'require_code_owner_review':True,'dismiss_stale_reviews_on_push':True}
            rows[base+'/rulesets/'+str(number)]={'id':number,'target':'branch','enforcement':'active','conditions':{'ref_name':{'include':['refs/heads/'+target],'exclude':[]}},'bypass_actors':[],'rules':rules}
        if name=='ci-v2-audit-writer':rows[base+'/environments/'+name]['protection_rules'].append({'type':'required_reviewers','reviewers':[{'type':'User','reviewer':{'id':v.OWNER_ID}}]})
        def call(method,path,token,body=None):
            self.assertEqual(method,'GET');return deepcopy(rows[path])
        return env,rows,call
    def observation(self):
        _,rows,_=self.context()
        now=datetime.now(timezone.utc).replace(microsecond=0)
        return {'schema_version':1,'purpose':'CREDENTIAL_VERIFICATION_ONLY','repository':v.REPOSITORY,
            'repository_id':v.REPOSITORY_ID,'observer':{'id':v.OWNER_ID,'login':'XiangruZhang007','repository_admin_observed':True},
            'source':'AUTHENTICATED_OWNER_CLI','reviewed_base_sha':'a'*40,
            'observed_at':(now-timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'expires_at':(now+timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'authorization':'NOT_GRANTED','repository_data_writes':'NOT_AUTHORIZED',
            'rulesets':[rows['/repos/'+v.REPOSITORY+'/rulesets/'+str(n)] for n in v.RULESET_IDS]}
    def test_missing_bypass_is_explicitly_unverified_for_credential_only(self):
        env,rows,call=self.context()
        for n in v.RULESET_IDS:rows['/repos/'+v.REPOSITORY+'/rulesets/'+str(n)].pop('bypass_actors')
        result=v.preflight(env,call,observation=self.observation())['read_only_github_token_observation']
        self.assertEqual(result['repository_data_write_authorization'],'NOT_GRANTED')
        self.assertTrue(all(r['bypass_observation']=='NOT_RETURNED_LIVE_BYPASS_UNVERIFIED' for r in result['bypass_visibility']))
    def test_null_bypass_is_not_missing_or_empty(self):
        env,rows,call=self.context();rows['/repos/'+v.REPOSITORY+'/rulesets/27770139']['bypass_actors']=None
        with self.assertRaisesRegex(ValueError,'LIVE_BYPASS_ACTORS_CHANGED'):v.preflight(env,call,observation=self.observation())
    def test_changed_live_projection_blocks_before_key_access(self):
        env,rows,call=self.context();rows['/repos/'+v.REPOSITORY+'/rulesets/27770139']['enforcement']='disabled'
        with self.assertRaisesRegex(ValueError,'LIVE_RULESET_PROJECTION_CHANGED'):v.preflight(env,call,observation=self.observation())
    def test_stale_owner_observation_blocks(self):
        observation=self.observation();observation['observed_at']='2020-01-01T00:00:00Z';observation['expires_at']='2020-01-01T01:00:00Z'
        with self.assertRaisesRegex(ValueError,'OWNER_OBSERVATION_EXPIRED_OR_INVALID'):v.validate_observation(observation)
    def test_owner_observation_never_authorizes_writes(self):
        observation=self.observation();observation['repository_data_writes']='AUTHORIZED'
        with self.assertRaisesRegex(ValueError,'INVALID_OWNER_OBSERVATION'):v.validate_observation(observation)
    def test_tampered_snapshot_file_fails_raw_pin(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(v,'PROJECT',Path(folder)):
            path=Path(folder)/v.OBSERVATION_PATH;path.parent.mkdir();path.write_text('{}')
            with self.assertRaisesRegex(ValueError,'OWNER_OBSERVATION_PIN_MISMATCH'):v.load_observation()
    def test_hidden_app_bypass_is_reported_without_runtime_authority(self):
        self.change='hidden-bypass'
        result=v.verify_credentials('synthetic-jwt',self.api,observation=self.observation())
        self.assertEqual(result['runtime_governance_authorization'],'NOT_GRANTED')
        for observation in result['ruleset_observation_capabilities'].values():
            self.assertTrue(all(r['bypass_observation']=='NOT_RETURNED_LIVE_BYPASS_UNVERIFIED' for r in observation['bypass_visibility']))
        self.assertEqual(len([c for c in self.calls if c[0]=='DELETE']),2)
    def test_changed_app_visible_bypass_revokes_and_blocks(self):
        self.change='changed-bypass'
        with self.assertRaisesRegex(ValueError,'LIVE_BYPASS_ACTORS_CHANGED'):v.verify_credentials('synthetic-jwt',self.api,observation=self.observation())
        self.assertEqual(self.calls[-1][0],'DELETE')
    def test_both_environment_contexts_pass_without_credential_requests(self):
        for name in v.ENVIRONMENTS:
            env,rows,call=self.context(name)
            self.assertEqual(v.preflight(env,call,observation=self.observation())['environment_id'],v.ENVIRONMENTS[name])
    def test_manual_review_required(self):
        env,rows,call=self.context('ci-v2-audit-writer')
        rows['/repos/'+v.REPOSITORY+'/environments/ci-v2-audit-writer']['protection_rules']=[]
        with self.assertRaisesRegex(ValueError,'MANUAL_REVIEWER_MISMATCH'):v.preflight(env,call,observation=self.observation())
    def test_admin_bypass_denies_key_access(self):
        env,rows,call=self.context();rows['/repos/'+v.REPOSITORY+'/environments/ci-v2-automatic-writer']['can_admins_bypass']=True
        with self.assertRaisesRegex(ValueError,'ENVIRONMENT_MISMATCH'):v.preflight(env,call,observation=self.observation())
    def test_default_branch_bypass_rejected(self):
        env,rows,call=self.context();rows['/repos/'+v.REPOSITORY+'/rulesets/27793434']['bypass_actors']=[{'actor_id':1}]
        with self.assertRaisesRegex(ValueError,'LIVE_BYPASS_ACTORS_CHANGED'):v.preflight(env,call,observation=self.observation())
    def test_stale_revision_rejected(self):
        env,rows,call=self.context();rows['/repos/'+v.REPOSITORY+'/git/ref/heads/ci-upstream-refresh']['object']['sha']='b'*40
        with self.assertRaisesRegex(ValueError,'STALE_PROTECTED_REVISION'):v.preflight(env,call,observation=self.observation())
    def test_key_signing_uses_anonymous_memory_and_no_inherited_credentials(self):
        observed = []
        def sign(args, **kwargs):
            fd = kwargs['pass_fds'][0]
            observed.append(fd)
            self.assertEqual(os.read(fd, 100), b'fixture-key-not-a-real-private-key')
            self.assertEqual(args[-1], '/proc/self/fd/' + str(fd))
            self.assertEqual(kwargs['env'], {'PATH': '/usr/bin:/bin'})
            return SimpleNamespace(returncode=0, stdout=b'fixture-signature')
        with patch.object(v.subprocess, 'run', side_effect=sign):
            self.assertEqual(len(v.jwt('fixture-key-not-a-real-private-key').split('.')), 3)
        with self.assertRaises(OSError):
            os.fstat(observed[0])
    def test_full_installation_observed_before_repository_narrowing(self):
        result=v.verify_credentials('synthetic-jwt',self.api,observation=self.observation())
        self.assertEqual(result['status'],'WRITER_CREDENTIALS_VERIFIED')
        posts=[c[3] for c in self.calls if c[0]=='POST']
        self.assertEqual(posts,[{'permissions':{'contents':'read'}},{'repository_ids':[v.REPOSITORY_ID],'permissions':{'contents':'write'}}])
        self.assertEqual(len([c for c in self.calls if c[0]=='DELETE']),2)
        self.assertTrue(all(c[1] in ('/app/installations/'+str(v.INSTALLATION_ID)+'/access_tokens','/installation/token') for c in self.calls if c[0]!='GET'))
    def test_extra_installation_repository_fails_and_revokes(self):
        self.change='extra-repo'
        with self.assertRaises(ValueError):v.verify_credentials('synthetic-jwt',self.api,observation=self.observation())
        self.assertEqual(len([c for c in self.calls if c[0]=='DELETE']),1)
    def test_wrong_repository_fails_and_revokes(self):
        self.change='wrong-repo'
        with self.assertRaises(ValueError):v.verify_credentials('synthetic-jwt',self.api,observation=self.observation())
        self.assertEqual(self.calls[-1][0],'DELETE')
    def test_metadata_failure_never_mints_token(self):
        for change in ('extra-permission','wrong-installation','suspended'):
            self.calls=[];self.change=change
            with self.subTest(change=change),self.assertRaises(ValueError):v.verify_credentials('synthetic-jwt',self.api,observation=self.observation())
            self.assertFalse(any(c[0]=='POST' for c in self.calls))
    def test_writer_permission_required_and_revoked_on_failure(self):
        self.change='token-permission'
        with self.assertRaises(ValueError):v.verify_credentials('synthetic-jwt',self.api,observation=self.observation())
        self.assertEqual(len([c for c in self.calls if c[0]=='DELETE']),2)
    def test_unusable_token_revoked(self):
        self.change='unusable'
        with self.assertRaises(ValueError):v.verify_credentials('synthetic-jwt',self.api,observation=self.observation())
        self.assertEqual(self.calls[-1][0],'DELETE')
    def test_revoke_failure_blocks_success_and_second_token(self):
        self.change='revoke-failure'
        with self.assertRaises(ValueError):v.verify_credentials('synthetic-jwt',self.api,observation=self.observation())
        self.assertEqual(len([c for c in self.calls if c[0]=='POST']),1)
    def test_wrong_runtime_fails_before_api(self):
        with self.assertRaises(ValueError):v.preflight({},lambda *args:self.fail('API_ACCESSED'))
    def test_api_rejects_data_mutation_before_network(self):
        for method,path in [('POST','/repos/'+v.REPOSITORY+'/git/refs'),('PATCH','/repos/'+v.REPOSITORY+'/git/refs/heads/main'),('POST','/repos/'+v.REPOSITORY+'/releases')]:
            with self.subTest(path=path),self.assertRaisesRegex(ValueError,'API_OPERATION_DENIED'):v.api(method,path,'synthetic')

if __name__=='__main__':unittest.main()
