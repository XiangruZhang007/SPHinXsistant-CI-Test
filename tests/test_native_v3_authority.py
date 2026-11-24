"""Synthetic Hosted identity boundaries; no credential/API operations."""
from contextlib import ExitStack
from pathlib import Path
import tempfile,unittest
from unittest.mock import patch
from src import native_runtime_contract as runtime,genuine_continuous_execution as g
from src import automatic_lifecycle_policy as policies

class AuthorityTests(unittest.TestCase):
    def invoke(self,*,workflow_sha='b'*40):
        with tempfile.TemporaryDirectory() as directory,ExitStack() as stack:
            p=Path(directory);(p/'configs').mkdir();(p/'configs/registry.json').write_bytes(b'{}\n')
            config={'schema_version':4,'repository':'Owner/Test','repository_id':1,'default_branch':'protected',
                'workflow_path':'.github/workflows/upstream_refresh.yml','registry_path':'configs/registry.json',
                'authority_policy_path':'configs/authority.json','authority_policy_sha256':'a'*64,
                'continuous_policy_path':'configs/source.json','continuous_policy_sha256':'a'*64,
                'registry_sha256':'a'*64,'implementation_revision':'b'*40,
                'execution_contract_sha256':'c'*64,'build_events':['schedule'],'scheduled_policy_sha256':'d'*64}
            actor={'commit_sha':'b'*40};context={'repository':'Owner/Test','repository_id':1,'head_sha':'b'*40}
            environment={'GITHUB_EVENT_NAME':'schedule','GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted',
                'RUNNER_ARCH':'ARM64','GITHUB_WORKSPACE':str(p),'GITHUB_WORKFLOW_SHA':workflow_sha,
                'GITHUB_WORKFLOW_REF':'Owner/Test/.github/workflows/upstream_refresh.yml@refs/heads/protected'}
            stack.enter_context(patch.dict('os.environ',environment))
            for owner,name,kwargs in [
                (g,'deployment',{'return_value':(config,'{}','e'*64)}),
                (policies,'load',{'return_value':{'schema_version':3}}),
                (g,'_checkout',{}),(g,'_implementation',{'side_effect':AssertionError('LEGACY_CONTRACT_USED')}),
                (g.owner,'_policy',{'return_value':config}),(g.owner,'GitHubCLI',{'return_value':object()}),
                (g.owner,'_remote_registry_bytes',{'return_value':b'{}\n'}),
                (g.scope,'load_policy',{'return_value':{}}),(g.scope,'_read_pinned',{'return_value':{}}),
                (g.scope,'_parent',{'return_value':('root',{'expected_reference_sha256':'f'*64},None)}),
                (g,'_detected',{'return_value':{'detection_sha256':'f'*64,'upstreams':{}}}),
                (g,'_scheduled_context',{'return_value':context}),
                (g,'_scheduled_identity',{'return_value':actor}),
                (g,'_comparison',{'return_value':{}}),(g.scheduled,'load',{'return_value':{}}),
                (runtime,'contract',{'return_value':{}}),(runtime,'digest',{'return_value':'c'*64})]:
                stack.enter_context(patch.object(owner,name,**kwargs))
            stack.enter_context(patch('src.ci_v2_research.frozen_runtime'))
            return runtime.authority(p,p/'detection.json',config,'e'*64)
    def test_actual_native_boundary_reuses_identity_without_legacy_contract(self):
        result=self.invoke()
        self.assertEqual(result['authority'],'AUTHORIZED_SCHEDULED_BUILD_CONTEXT')
        self.assertEqual(result['production_promotion'],'NOT_AUTHORIZED')
    def test_workflow_revision_mismatch_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'TRUSTED_CONTINUOUS_WORKFLOW_NOT_ESTABLISHED'):
            self.invoke(workflow_sha='0'*40)

if __name__=='__main__':unittest.main()
