"""Offline composition of existing Git model and isolated APPLY; no live grants."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import test_parent_authority_git_audit as fixtures
import test_parent_authority_github_transport as http_fixtures
from src import hosted_parent_authority_transition as hosted
from src import parent_authority_transaction as core
from src.corpus_snapshot import digest

P=Path(__file__).resolve().parents[1]


class WriterExecutionTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.DurableAuditTests();self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.f=self.fixture.f;self.observed=deepcopy(self.f.observed)
        self.config=deepcopy(self.f.f.config)
        self.config.update(schema_version=2,transaction_backend={
            'kind':'GITHUB_GIT_AUDIT_V1','audit':self.fixture.config,
            'history_ruleset_id':1,'writer_ruleset_id':2,'writer_integration_id':3})
        self.protocol=self.fixture.client()

    def execute(self,protocol=None,revalidate=None):
        return hosted._execute_transaction(self.f.project,self.f.work,self.config,
            self.observed,protocol or self.protocol,
            _revalidate=revalidate or (lambda:deepcopy(self.observed)))

    def assert_unchanged(self):
        self.assertEqual(self.f.authoritative.read_bytes(),self.f.old)
        self.assertEqual((self.f.work/'registry.json').read_bytes(),self.f.old)

    def test_complete_existing_protocol_and_apply_independent_readbacks(self):
        result=self.execute()
        self.assertEqual(result['status'],'COMPLETED',result)
        self.assertEqual(result['phase'],'VERIFIED')
        self.assertEqual(result['authorization'],'NOT_GRANTED')
        self.assertEqual(result['build_candidate_authority'],'NOT_GRANTED')
        self.assertFalse(result['authoritative_registry_applied'])
        self.assertTrue(result['transaction_consumed'])
        self.assertTrue(result['registry_committed'])
        self.assertEqual(self.f.authoritative.read_bytes(),self.f.old)
        self.assertEqual(self.fixture.client().inspect()['status'],'COMPLETED_REVIEW_REQUIRED')
        self.assertEqual(sum(m=='PATCH' for m,_,_ in self.fixture.model.calls),3)
        self.assertEqual(result['result_registry_sha256'],self.config['request']['result_registry_sha256'])
        self.assertEqual(len({result[k] for k in ('reservation_head','consumption_head','completion_head')}),3)

    def test_missing_or_changed_owner_observation_never_reserves(self):
        result=self.execute(revalidate=lambda:{})
        self.assertEqual(result['reason'],'TRANSITION_AUTHORITY_CHANGED_DURING_EXECUTION')
        self.assertFalse(any(m!='GET' for m,_,_ in self.fixture.model.calls));self.assert_unchanged()

    def test_invalid_owner_decision_binding_denied_before_mutation(self):
        self.observed['workflow_run']['actor_id']+=1
        result=self.execute()
        self.assertEqual(result['status'],'BLOCKED')
        self.assertFalse(any(m!='GET' for m,_,_ in self.fixture.model.calls));self.assert_unchanged()

    def test_old_registry_mismatch_denied_before_mutation(self):
        self.f.authoritative.write_bytes(self.f.old+b' ')
        result=self.execute()
        self.assertEqual(result['reason'],'STALE_OR_UNBOUND_REGISTRY')
        self.assertFalse(any(m!='GET' for m,_,_ in self.fixture.model.calls))

    def test_existing_consumed_transaction_cannot_be_replayed(self):
        self.protocol.reserve();self.protocol.consume()
        before=sum(m=='PATCH' for m,_,_ in self.fixture.model.calls)
        result=self.execute(protocol=self.fixture.client())
        self.assertNotEqual(result['status'],'COMPLETED')
        self.assertEqual(sum(m=='PATCH' for m,_,_ in self.fixture.model.calls),before)
        self.assert_unchanged()

    def test_uncertain_reservation_never_consumes_or_retries(self):
        self.fixture.model.failure='timeout_after'
        result=self.execute()
        self.assertEqual(result['status'],'STATE_UNCERTAIN')
        self.assertIsNone(result['durable_transaction_reserved'])
        self.assertEqual(result['reconciliation']['status'],'RESERVED_REVIEW_REQUIRED')
        self.assertFalse(result['automatic_retry'])
        self.assertEqual(sum(m=='PATCH' for m,_,_ in self.fixture.model.calls),1);self.assert_unchanged()

    def test_uncertain_consumption_burns_claim_without_apply(self):
        original=self.protocol.consume
        def interrupted():
            self.fixture.model.failure='timeout_after'
            return original()
        with patch.object(self.protocol,'consume',side_effect=interrupted):result=self.execute()
        self.assertIsNone(result['transaction_consumed'])
        self.assertEqual(result['reconciliation']['status'],'CONSUMED_REVIEW_REQUIRED')
        self.assertEqual(sum(m=='PATCH' for m,_,_ in self.fixture.model.calls),2);self.assert_unchanged()

    def test_readback_failure_stops_before_consumption(self):
        with patch.object(hosted,'_readback',side_effect=ValueError('SIMULATED_READBACK_FAILURE')):
            result=self.execute()
        self.assertNotEqual(result['status'],'COMPLETED')
        self.assertEqual(self.fixture.client().inspect()['status'],'RESERVED_REVIEW_REQUIRED')
        self.assertEqual(sum(m=='PATCH' for m,_,_ in self.fixture.model.calls),1);self.assert_unchanged()

    def test_interrupted_apply_never_records_completion_or_replays(self):
        with patch.object(core,'_local_apply',side_effect=OSError('sensitive synthetic error')):result=self.execute()
        self.assertEqual(result['status'],'STATE_UNCERTAIN')
        self.assertIsNone(result['registry_committed'])
        self.assertNotIn('sensitive',json.dumps(result))
        self.assertEqual(self.fixture.client().inspect()['status'],'CONSUMED_REVIEW_REQUIRED')
        self.assertEqual(sum(m=='PATCH' for m,_,_ in self.fixture.model.calls),2);self.assert_unchanged()

    def test_committed_with_error_never_records_success_or_retries(self):
        original=core._local_apply
        def committed(*a,**kw):
            result=original(*a,**kw);result['status']='COMMITTED_WITH_ERROR';return result
        with patch.object(core,'_local_apply',side_effect=committed):result=self.execute()
        self.assertEqual(result['status'],'COMMITTED_WITH_ERROR')
        self.assertTrue(result['registry_committed'])
        self.assertEqual(self.fixture.client().inspect()['status'],'CONSUMED_REVIEW_REQUIRED')
        self.assertEqual(sum(m=='PATCH' for m,_,_ in self.fixture.model.calls),2)
        self.assertEqual(self.f.authoritative.read_bytes(),self.f.old)

    def test_modified_completion_receipt_never_appends_completion(self):
        original=core._local_apply
        def changed(*a,**kw):
            result=original(*a,**kw);result['receipt']['transaction_id']='9'*32;return result
        with patch.object(core,'_local_apply',side_effect=changed):result=self.execute()
        self.assertEqual(result['reason'],'ISOLATED_COMPLETION_BYTES_MISMATCH')
        self.assertEqual(result['status'],'STATE_UNCERTAIN')
        self.assertEqual(self.fixture.client().inspect()['status'],'CONSUMED_REVIEW_REQUIRED')

    def test_uncertain_completion_retains_exact_committed_isolation(self):
        original=self.protocol.complete
        def interrupted(*a):
            self.fixture.model.failure='timeout_after';return original(*a)
        with patch.object(self.protocol,'complete',side_effect=interrupted):result=self.execute()
        self.assertEqual(result['status'],'STATE_UNCERTAIN')
        self.assertTrue(result['registry_committed'])
        self.assertEqual(result['reconciliation']['status'],'COMPLETED_REVIEW_REQUIRED')
        self.assertFalse(result['automatic_retry'])
        self.assertEqual(sum(m=='PATCH' for m,_,_ in self.fixture.model.calls),3)
        self.assertEqual(self.f.authoritative.read_bytes(),self.f.old)

    def test_concurrent_adapters_at_most_one_reservation_and_apply(self):
        self.fixture.model.barrier=threading.Barrier(2);results=[]
        # Only reservation participates in the synchronized race. Remove the
        # barrier once both first PATCHes have entered; subsequent phases serial.
        barrier=self.fixture.model.barrier
        class FirstPatchBarrier:
            def wait(inner,timeout):
                barrier.wait(timeout=timeout);self.fixture.model.barrier=None
        self.fixture.model.barrier=FirstPatchBarrier()
        clients=[self.fixture.client(),self.fixture.client()]
        threads=[threading.Thread(target=lambda c=c:results.append(self.execute(protocol=c))) for c in clients]
        for t in threads:t.start()
        for t in threads:t.join(timeout=15);self.assertFalse(t.is_alive())
        self.assertEqual(sum(r['status']=='COMPLETED' for r in results),1,results)
        self.assertEqual(sum(m=='PATCH' for m,_,_ in self.fixture.model.calls),4)
        self.assertEqual(self.f.authoritative.read_bytes(),self.f.old)

    def test_rollback_of_observed_history_is_rejected(self):
        self.protocol.reserve();self.fixture.model.head=self.fixture.config['genesis_sha']
        self.assertEqual(self.protocol.inspect()['status'],'STATE_UNCERTAIN')
        self.assertNotEqual(self.execute()['status'],'COMPLETED');self.assert_unchanged()


class WriterBoundaryTests(unittest.TestCase):
    def test_real_governance_observer_does_not_certify_independence(self):
        fixture=http_fixtures.GitHubTransportTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.governance()
        with self.assertRaisesRegex(ValueError,'INDEPENDENT_GOVERNANCE_NOT_VERIFIED'):
            hosted._writer_governance(fixture.transport(),{'history_ruleset_id':1,
                'writer_ruleset_id':2,'writer_integration_id':3})

    def test_missing_ruleset_cannot_satisfy_gate(self):
        fixture=http_fixtures.GitHubTransportTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.governance();fixture.server.rules.pop(2)
        with self.assertRaises(ValueError):
            hosted._writer_governance(fixture.transport(),{'history_ruleset_id':1,
                'writer_ruleset_id':2,'writer_integration_id':3})

    def test_missing_writer_authorization_precedes_transport(self):
        with patch.object(hosted,'_writer_context',side_effect=ValueError('WRITER_TOKEN_REQUIRED')), \
             patch('src.parent_authority_github_transport.GitHubAuditTransport') as transport:
            result=hosted.run_writer()
        self.assertEqual(result['status'],'BLOCKED');transport.assert_not_called()

    def test_governance_blocks_before_append_transport_or_isolation(self):
        with patch.object(hosted,'_writer_context',return_value=({},{})), \
             patch.object(hosted,'_audit_binding',return_value={}), \
             patch('src.parent_authority_github_transport.GitHubAuditTransport') as transport:
            config={'transaction_backend':{'audit':{},'history_ruleset_id':1,
                'writer_ruleset_id':2,'writer_integration_id':3}}
            with patch.object(hosted,'_writer_context',return_value=(config,{})):
                result=hosted.run_writer()
        self.assertEqual(result['status'],'BLOCKED')
        self.assertEqual(transport.call_count,1)
        self.assertNotIn('write_scope',transport.call_args.kwargs)

    def test_stdlib_only_import_closure_without_scientific_dependencies(self):
        script="import sys;sys.path.insert(0,"+repr(str(P))+");from src import hosted_parent_authority_transition,baseline_registration_transaction;assert not any(n.startswith(('chunker','tree_sitter')) for n in sys.modules)"
        result=subprocess.run([sys.executable,'-I','-S','-B','-c',script],cwd='/tmp',capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_success_cannot_survive_missing_diagnostic_persistence(self):
        import importlib.util
        from types import SimpleNamespace
        from src import baseline_registration_transaction as tx
        spec=importlib.util.spec_from_file_location('writer_entry_fixture',P/'scripts/parent_authority_writer_execute.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            env={'RUNNER_TEMP':directory,'GITHUB_RUN_ID':'102','GITHUB_RUN_ATTEMPT':'1'}
            with patch.dict(os.environ,env),patch.object(module.sys,'argv',['writer']), \
                 patch.object(module.sys,'flags',SimpleNamespace(isolated=1,no_site=1)), \
                 patch.object(module.gate,'verify'),patch.object(module.gate,'verify_token'), \
                 patch.object(hosted,'run_writer',return_value={'status':'COMPLETED','phase':'VERIFIED','registry_committed':True}), \
                 patch.object(tx,'_write_once',side_effect=OSError('synthetic disk failure')), \
                 patch('builtins.print') as printed:
                self.assertEqual(module.main(),1)
            result=json.loads(printed.call_args.args[0])
            self.assertEqual(result['status'],'STATE_UNCERTAIN')
            self.assertTrue(result['registry_committed'])
            self.assertEqual(result['reason'],'WRITER_EVIDENCE_PERSISTENCE_FAILED')

    def test_actual_unauthorized_writer_entry_never_imports_project_or_creates_result(self):
        with tempfile.TemporaryDirectory() as directory:
            env={k:os.environ[k] for k in ('PATH','HOME') if k in os.environ}
            env.update(GITHUB_ACTIONS='false',RUNNER_TEMP=directory,GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1')
            result=subprocess.run([sys.executable,'-I','-S','-B',str(P/'scripts/parent_authority_writer_execute.py')],
                cwd=directory,env=env,capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,1)
            self.assertEqual(list(Path(directory).iterdir()),[])
            self.assertIn('WRITER_RUNTIME_IDENTITY_MISMATCH',result.stdout)


if __name__=='__main__':unittest.main()
