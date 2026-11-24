"""Offline Writer credential boundaries; no keys, token minting or GitHub writes."""
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

import yaml
import test_hosted_parent_authority_transition as owner_fixture
from scripts import parent_authority_writer_gate as gate
from scripts import parent_authority_writer_prepare as prepare
from src import hosted_parent_authority_transition as hosted
from src.corpus_snapshot import digest

P=Path(__file__).resolve().parents[1]


class WriterWorkflowTests(unittest.TestCase):
    def workflow(self):return yaml.load((P/hosted.WORKFLOW).read_text(),Loader=yaml.BaseLoader)

    def test_writer_is_fresh_environment_job_with_no_project_dependency_execution(self):
        data=self.workflow();writer=data['jobs']['trusted-audit-writer']
        self.assertEqual(writer['environment'],'ci-v2-audit-writer')
        self.assertEqual(writer['needs'],'inspect-transition')
        self.assertEqual(writer['permissions'],{'contents':'read','actions':'read'})
        self.assertEqual(writer['runs-on'],'ubuntu-24.04-arm')
        text=json.dumps(writer)
        for bad in ('pip install','download-artifact','npm install','pull_request_target'):
            self.assertNotIn(bad,text)
        self.assertNotIn('CI_V2_AUDIT_APP_PRIVATE_KEY',json.dumps(data['jobs']['inspect-transition']))
        self.assertIn("PARENT_AUTHORITY_WRITER_PREPARATION_ENABLED == 'true'",writer['if'])
        for pin in ("github.repository_id == '1455203884'","github.actor_id == '239840087'",
                    "github.ref == 'refs/heads/ci-upstream-refresh'",'github.run_attempt == 1'):
            self.assertIn(pin,writer['if'])

    def test_only_pinned_action_receives_key_and_token_is_step_scoped_and_revoked(self):
        data=self.workflow();writer=data['jobs']['trusted-audit-writer'];steps=writer['steps']
        key_steps=[s for s in steps if 'CI_V2_AUDIT_APP_PRIVATE_KEY' in json.dumps(s)]
        self.assertEqual(len(key_steps),1);mint=key_steps[0]
        self.assertEqual(mint['uses'],'actions/create-github-app-token@f418cff399f7aef4c2f0ad47e25ca7a6abbdd6fc')
        self.assertEqual(mint['with']['app-id'],'5855475')
        self.assertEqual(mint['with']['owner'],'XiangruZhang007')
        self.assertEqual(mint['with']['repositories'],'SPHinXsistant-CI-Test')
        self.assertEqual(mint['with']['permission-contents'],'write')
        self.assertEqual([k for k in mint['with'] if k.startswith('permission-')],['permission-contents'])
        self.assertEqual(mint['with']['skip-token-revoke'],'false')
        self.assertEqual(mint['with']['github-api-url'],'https://api.github.com')
        self.assertLess(next(i for i,s in enumerate(steps) if s.get('run')=='python -I -S -B scripts/parent_authority_writer_gate.py'),steps.index(mint))
        self.assertNotIn('PARENT_AUTHORITY_AUDIT_TOKEN',writer['env'])
        self.assertNotIn('outputs',writer)
        privileged=[s for s in steps if 'PARENT_AUTHORITY_AUDIT_TOKEN' in s.get('env',{})]
        self.assertEqual(len(privileged),2)
        for step in privileged:
            self.assertEqual(step['env']['GH_TOKEN'],'${{ secrets.GITHUB_TOKEN }}')
            self.assertIn('steps.app-token.outputs.token',step['env']['PARENT_AUTHORITY_AUDIT_TOKEN'])
        execute=next(s for s in steps if s.get('run')=='python -I -S -B scripts/parent_authority_writer_execute.py')
        self.assertEqual(execute['env']['TRUSTED_RELEASE_TOKEN'],'${{ secrets.GITHUB_TOKEN }}')
        self.assertGreater(steps.index(execute),steps.index(mint))
        self.assertEqual(steps[-1]['if'],'always()')
        self.assertNotIn('env',steps[-1])
        self.assertFalse(any(s.get('continue-on-error') for s in steps))

    def test_original_manual_contract_preserved_all_shell_and_action_pins(self):
        data=self.workflow();self.assertEqual(set(data['on']),{'workflow_dispatch'})
        self.assertEqual(set(data['on']['workflow_dispatch']['inputs']),hosted.DISPATCH_FIELDS)
        for job in data['jobs'].values():
            for step in job['steps']:
                if 'uses' in step:self.assertRegex(step['uses'],r'@[0-9a-f]{40}$')
                if 'run' in step:
                    self.assertNotIn('${{',step['run'])
                    self.assertEqual(subprocess.run(['bash','-n'],input=step['run'],text=True,capture_output=True).returncode,0)
        self.assertIn('scripts/parent_authority_writer_gate.py',hosted.CODE)
        self.assertIn('scripts/parent_authority_writer_prepare.py',hosted.CODE)
        self.assertIn('.github/CODEOWNERS',hosted.CODE)

    def test_gate_uses_only_stdlib_and_never_reads_private_key(self):
        import ast
        tree=ast.parse((P/'scripts/parent_authority_writer_gate.py').read_text())
        roots=set()
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):roots.update(x.name.split('.')[0] for x in node.names)
            if isinstance(node,ast.ImportFrom):roots.add(node.module.split('.')[0])
        self.assertTrue(roots<={'hashlib','json','os','pathlib','re','subprocess','sys',
                               'runtime_ruleset_observation'})
        helper=ast.parse((P/'scripts/runtime_ruleset_observation.py').read_text())
        helper_roots=set()
        for node in ast.walk(helper):
            if isinstance(node,ast.Import):helper_roots.update(x.name.split('.')[0] for x in node.names)
            if isinstance(node,ast.ImportFrom):helper_roots.add(node.module.split('.')[0])
        self.assertTrue(helper_roots<={'datetime','hashlib','json','pathlib','re','os','subprocess'})
        self.assertNotIn('PRIVATE_KEY',(P/'scripts/parent_authority_writer_gate.py').read_text())
        for prefix in ('/.github/','/scripts/','/src/','/configs/'):
            self.assertIn(prefix,(P/'.github/CODEOWNERS').read_text())

    def test_actual_isolated_gate_ignores_repository_module_and_pythonpath_shadowing(self):
        import sys
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);script=root/'parent_authority_writer_gate.py'
            script.write_bytes((P/'scripts/parent_authority_writer_gate.py').read_bytes())
            marker=root/'UNTRUSTED_CODE_EXECUTED'
            (root/'json.py').write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("bad")\n')
            env={**os.environ,'PYTHONPATH':str(root),'GITHUB_ACTIONS':'false'}
            result=subprocess.run([sys.executable,'-I','-S','-B',str(script)],env=env,
                cwd=root,capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,1)
            self.assertIn('WRITER_RUNTIME_IDENTITY_MISMATCH',result.stdout)
            self.assertFalse(marker.exists())


class WriterGateTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        self.sha='a'*40;self.run_id=102
        r={'implementation_revision':self.sha,'repository':gate.REPOSITORY,'repository_id':gate.REPOSITORY_ID,
           'workflow_path':gate.WORKFLOW,'default_branch':'ci-upstream-refresh','transaction_id':'2'*32}
        self.files={k:'0'*64 for k in hosted.CODE}
        self.config={'request':r,'proposal_sha256':'b'*64,'subject_sha256':'c'*64,'workflow_id':103,
            'implementation_contract_sha256':gate.digest({'schema_version':1,'operation':gate.OPERATION,'files':self.files})}
        actor={'repository':gate.REPOSITORY,'repository_id':gate.REPOSITORY_ID,'actor_id':gate.OWNER_ID,
            'run_id':102,'run_attempt':1,'workflow_id':103,'workflow_path':gate.WORKFLOW,
            'commit_sha':self.sha,'event':'workflow_dispatch'}
        self.receipt={'status':'OWNER_VERIFIED_WRITER_PREPARATION_ONLY','authorization':'NOT_GRANTED',
            'registry_committed':False,'request_sha256':gate.digest(r),
            **{k:self.config[k] for k in ('proposal_sha256','subject_sha256','implementation_contract_sha256')},'workflow_run':actor}
        raw=json.dumps(self.config);self.event=self.root/'event.json'
        self.inputs={'operation':gate.OPERATION,'decision':'APPROVE_RESTRICTED_BUILD_AUTHORITY_TRANSITION',
            'request_sha256':gate.digest(r),'proposal_sha256':'b'*64,'transition_subject_sha256':'c'*64,'transaction_id':'2'*32}
        self.event.write_text(json.dumps({'inputs':self.inputs}))
        self.env={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted','RUNNER_ARCH':'ARM64',
            'GITHUB_JOB':'trusted-audit-writer','GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REPOSITORY':gate.REPOSITORY,
            'GITHUB_REPOSITORY_ID':str(gate.REPOSITORY_ID),'GITHUB_ACTOR_ID':str(gate.OWNER_ID),'GITHUB_RUN_ATTEMPT':'1',
            'GITHUB_RUN_ID':'102','GITHUB_REF':'refs/heads/ci-upstream-refresh','GITHUB_SHA':self.sha,'GITHUB_WORKFLOW_SHA':self.sha,
            'GITHUB_WORKFLOW_REF':gate.REPOSITORY+'/'+gate.WORKFLOW+'@refs/heads/ci-upstream-refresh',
            'GITHUB_EVENT_PATH':str(self.event),'PARENT_AUTHORITY_WRITER_PREPARATION_ENABLED':'true',
            'PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_JSON':raw,
            'PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_SHA256':hashlib.sha256(raw.encode()).hexdigest(),
            'OWNER_PREPARATION_RECEIPT':json.dumps(self.receipt),'OWNER_IMPLEMENTATION_FILES':json.dumps(self.files)}
        self.base='repos/'+gate.REPOSITORY
        self.rules=[{'type':'deletion','ruleset_id':5},{'type':'non_fast_forward','ruleset_id':5},
            {'type':'pull_request','ruleset_id':5,'parameters':{'required_approving_review_count':1,
            'require_code_owner_review':True,'dismiss_stale_reviews_on_push':True}}]
        self.responses={self.base:{'full_name':gate.REPOSITORY,'id':gate.REPOSITORY_ID,'owner':{'id':gate.OWNER_ID,'type':'User'},
            'default_branch':'ci-upstream-refresh','private':False},
            self.base+'/actions/runs/102/attempts/1':{'id':102,'run_attempt':1,'event':'workflow_dispatch','status':'in_progress',
            'head_sha':self.sha,'head_branch':'ci-upstream-refresh','repository':{'id':gate.REPOSITORY_ID,'full_name':gate.REPOSITORY},
            'actor':{'id':gate.OWNER_ID,'type':'User'},'triggering_actor':{'id':gate.OWNER_ID,'type':'User'},'workflow_id':103},
            self.base+'/actions/workflows/103':{'id':103,'path':gate.WORKFLOW,'state':'active'},
            self.base+'/git/ref/heads/ci-upstream-refresh':{'ref':'refs/heads/ci-upstream-refresh','object':{'sha':self.sha}},
            self.base+'/actions/runs/102/attempts/1/jobs?per_page=100':{'total_count':2,'jobs':[{'name':'inspect-transition',
            'head_sha':self.sha,'status':'completed','conclusion':'success','steps':[{'name':'Prepare verified Owner context for isolated Writer','conclusion':'success'}]}]},
            self.base+'/environments/'+gate.ENVIRONMENT:{'id':gate.ENVIRONMENT_ID,'name':gate.ENVIRONMENT,'can_admins_bypass':False,
            'protection_rules':[{'type':'required_reviewers','prevent_self_review':False,
                'reviewers':[{'type':'User','reviewer':{'id':gate.OWNER_ID}}]}],
            'deployment_branch_policy':{'protected_branches':False,'custom_branch_policies':True}},
            self.base+'/environments/'+gate.ENVIRONMENT+'/deployment-branch-policies?per_page=100':{'total_count':1,
            'branch_policies':[{'name':'ci-upstream-refresh','type':'branch'}]},
            self.base+'/rules/branches/ci-upstream-refresh':self.rules,
            self.base+'/rulesets/5':{'id':5,'target':'branch','enforcement':'active','bypass_actors':[],
                'conditions':{'ref_name':{'include':['refs/heads/ci-upstream-refresh'],'exclude':[]}},'rules':deepcopy(self.rules)}}
        self.calls=[]
    def api(self,ep,token=None):self.calls.append((ep,token));return deepcopy(self.responses[ep])
    def verify(self):
        with patch.object(gate,'checkout'):return gate.verify(self.env,self.root,self.api)

    def test_valid_context_is_preparation_only_and_never_mints(self):
        self.assertEqual(self.verify()['authorization'],'NOT_GRANTED')
        self.assertFalse(self.verify()['live_apply'])
        self.assertTrue(all(token is None for _,token in self.calls))

    def test_untrusted_runtime_actor_branch_event_attempt_or_commit_denied(self):
        for key,bad in [('GITHUB_ACTOR_ID','999'),('GITHUB_RUN_ATTEMPT','2'),('GITHUB_REF','refs/pull/1/merge'),
            ('GITHUB_EVENT_NAME','pull_request_target'),('GITHUB_REPOSITORY_ID','1'),('RUNNER_ARCH','X64'),('GITHUB_SHA','f'*40)]:
            old=self.env[key];self.env[key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):self.verify()
            self.env[key]=old

    def test_missing_or_modified_manifest_and_receipt_denied(self):
        for key,value in [('OWNER_IMPLEMENTATION_FILES','{}'),('OWNER_PREPARATION_RECEIPT','{}')]:
            old=self.env[key];self.env[key]=value
            with self.assertRaises(ValueError):self.verify()
            self.env[key]=old
        self.receipt['workflow_run']['run_id']=999;self.env['OWNER_PREPARATION_RECEIPT']=json.dumps(self.receipt)
        with self.assertRaisesRegex(ValueError,'PREPARATION_RUN_MISMATCH'):self.verify()

    def test_missing_optin_or_tampered_dispatch_denied(self):
        self.env['PARENT_AUTHORITY_WRITER_PREPARATION_ENABLED']='false'
        with self.assertRaisesRegex(ValueError,'DISABLED'):self.verify()
        self.env['PARENT_AUTHORITY_WRITER_PREPARATION_ENABLED']='true'
        self.event.write_text(json.dumps({'inputs':{**self.inputs,'transaction_id':'9'*32}}))
        with self.assertRaisesRegex(ValueError,'DISPATCH_BINDING'):self.verify()

    def test_actual_api_wrong_owner_workflow_trigger_and_stale_default_denied(self):
        for path,key,value in [(self.base+'/actions/workflows/103','path','other.yml'),
            (self.base+'/actions/runs/102/attempts/1','head_sha','f'*40)]:
            old=self.responses[path][key];self.responses[path][key]=value
            with self.assertRaises(ValueError):self.verify()
            self.responses[path][key]=old
        self.responses[self.base+'/git/ref/heads/ci-upstream-refresh']['object']['sha']='f'*40
        with self.assertRaisesRegex(ValueError,'STALE_DEFAULT'):self.verify()

    def test_failed_owner_job_or_step_cannot_release_credentials(self):
        job=self.responses[self.base+'/actions/runs/102/attempts/1/jobs?per_page=100']['jobs'][0]
        for row,key in ((job,'conclusion'),(job['steps'][0],'conclusion')):
            row[key]='failure'
            with self.assertRaises(ValueError):self.verify()
            row[key]='success'

    def test_environment_id_reviewer_bypass_and_branch_policy_enforced(self):
        target=self.responses[self.base+'/environments/'+gate.ENVIRONMENT]
        for key,bad in [('id',1),('can_admins_bypass',True)]:
            old=target[key];target[key]=bad
            with self.assertRaisesRegex(ValueError,'ENVIRONMENT_PROTECTION'):self.verify()
            target[key]=old
        target['protection_rules'][0]['reviewers'][0]['reviewer']['id']=999
        with self.assertRaises(ValueError):self.verify()

    def test_absent_branch_rules_or_broad_bypass_blocks_before_token(self):
        path=self.base+'/rules/branches/ci-upstream-refresh';old=self.responses[path];self.responses[path]=[]
        with self.assertRaisesRegex(ValueError,'BRANCH_PROTECTION_REQUIRED'):self.verify()
        self.responses[path]=old;self.responses[self.base+'/rulesets/5']['bypass_actors']=[{'actor_type':'RepositoryRole','actor_id':5,'bypass_mode':'always'}]
        with self.assertRaisesRegex(ValueError,'BYPASS_OR_SCOPE_UNSAFE'):self.verify()

    def test_wrong_rule_origin_or_weakened_review_not_sufficient(self):
        self.responses[self.base+'/rulesets/5']['rules'][-1]['parameters']['required_approving_review_count']=0
        with self.assertRaises(ValueError):self.verify()

    def test_token_wrong_installation_or_repository_scope_denied_without_logging(self):
        env={'ACTUAL_WRITER_INSTALLATION_ID':str(gate.INSTALLATION_ID),'PARENT_AUTHORITY_AUDIT_TOKEN':'synthetic-never-log'}
        self.responses['installation/repositories?per_page=100']={'total_count':1,'repositories':[{'id':gate.REPOSITORY_ID,'full_name':gate.REPOSITORY}]}
        result=gate.verify_token(env,self.api)
        self.assertEqual(result['status'],'WRITER_INSTALLATION_TOKEN_SCOPE_VERIFIED');self.assertNotIn('synthetic',json.dumps(result))
        env['ACTUAL_WRITER_INSTALLATION_ID']='1'
        with self.assertRaisesRegex(ValueError,'INSTALLATION_MISMATCH'):gate.verify_token(env,self.api)
        env['ACTUAL_WRITER_INSTALLATION_ID']=str(gate.INSTALLATION_ID)
        self.responses['installation/repositories?per_page=100']['repositories'][0]['id']=1
        with self.assertRaises(ValueError):gate.verify_token(env,self.api)

    def test_real_checkout_checks_commit_tracked_hashes_and_untracked_code(self):
        files={}
        for name in (gate.WORKFLOW,'.github/CODEOWNERS','src/hosted_parent_authority_transition.py',
                     'scripts/parent_authority_writer_prepare.py','scripts/parent_authority_writer_gate.py',
                     'scripts/parent_authority_writer_execute.py','scripts/runtime_ruleset_observation.py'):
            p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('synthetic\n')
            files[name]=hashlib.sha256(p.read_bytes()).hexdigest()
        def git(*a):return subprocess.check_output(['git','--no-optional-locks','-c','user.name=Fixture','-c','user.email=fixture@example.invalid','-C',str(self.root),*a],stderr=subprocess.PIPE)
        git('init','-q');git('add','--all');git('commit','-qm','synthetic')
        sha=git('rev-parse','HEAD').decode().strip();gate.checkout(self.root,sha,files)
        (self.root/'src/injected.py').write_text('untrusted')
        with self.assertRaisesRegex(ValueError,'UNTRACKED_CODE'):gate.checkout(self.root,sha,files)
        (self.root/'src/injected.py').unlink();(self.root/gate.WORKFLOW).write_text('tampered')
        with self.assertRaisesRegex(ValueError,'BYTES_MISMATCH'):gate.checkout(self.root,sha,files)


class PreparationTests(unittest.TestCase):
    def test_actual_existing_owner_observer_used_without_new_authority(self):
        f=owner_fixture.InvocationTests();f.setUp();self.addCleanup(f.doCleanups)
        with f.boundaries(),patch.dict(os.environ,f.deploy_env()),patch.object(prepare,'PROJECT',f.root),\
             patch.object(hosted,'contract',return_value={'files':{'synthetic':'0'*64}}):
            receipt,files=prepare.prepare()
        self.assertEqual(receipt['status'],'OWNER_VERIFIED_WRITER_PREPARATION_ONLY')
        self.assertEqual(receipt['authorization'],'NOT_GRANTED')
        self.assertFalse(receipt['registry_committed'])
        self.assertEqual(receipt['workflow_run']['run_id'],102)


if __name__=='__main__':unittest.main()
