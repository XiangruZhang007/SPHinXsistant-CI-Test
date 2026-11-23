"""Controlled driver tests; not live Gradio/SSH/proxy or deployment approval."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from src import gradio_deployment_adapter as adapter
from src import versioned_corpus_storage as storage


class Driver:
    def __init__(self):
        self.active='A';self.handles={};self.fail=None;self.calls=[]
    def current(self): return self.active
    def verify_current(self,version):return self.active==version and self.fail!='previous_health'
    def start(self,version):
        self.calls.append(('start',version))
        if self.fail=='startup':raise ValueError('FIXTURE_STARTUP_FAILED')
        handle=object();self.handles[handle]=version;return handle
    def owns(self,handle):return handle in self.handles
    def verify(self,handle,version):
        return self.handles.get(handle)==version and self.fail!='verification'
    def activate(self,old,new,handle):
        self.calls.append(('activate',old,new))
        if self.fail=='concurrent':self.active='X';raise ValueError('COMPARE_FAILED')
        if self.active!=old:raise ValueError('COMPARE_FAILED')
        self.active=new
        if self.fail in ('activation','rollback'):raise TimeoutError('UNCERTAIN_ACTIVATION')
    def restore(self,expected,previous):
        self.calls.append(('restore',expected,previous))
        if self.fail=='rollback':raise ValueError('FIXTURE_ROLLBACK_FAILED')
        if self.active!=expected:raise ValueError('COMPARE_FAILED')
        self.active=previous
    def stop(self,handle):
        if self.handles[handle]==self.active:raise ValueError('ACTIVE_HANDLE')
        self.calls.append(('stop',self.handles.pop(handle)))
    def retire(self,previous,*,expected_active):
        if self.active!=expected_active:raise ValueError('COMPARE_FAILED')
        self.calls.append(('retire',previous));return True


class ReplacementTests(unittest.TestCase):
    def test_two_cycles_are_controlled_driver_not_hosted(self):
        driver=Driver()
        for old,new in [('A','B'),('B','C')]:
            result=adapter._replace(driver,old,new)
            self.assertEqual(result['status'],'ACTIVE_VERIFIED');self.assertEqual(driver.current(),new)
        self.assertEqual([call for call in driver.calls if call[0]=='activate'],
                         [('activate','A','B'),('activate','B','C')])

    def test_identical_delivery_is_idempotent(self):
        driver=Driver();result=adapter._replace(driver,'A','A')
        self.assertEqual(result['status'],'ALREADY_ACTIVE');self.assertEqual(driver.calls,[])

    def test_stale_parent_never_starts(self):
        driver=Driver()
        with self.assertRaisesRegex(ValueError,'STALE_DEPLOYMENT'):adapter._replace(driver,'old','B')
        self.assertEqual(driver.calls,[])

    def test_failed_startup_or_verification_keeps_previous(self):
        for failure in ('startup','verification'):
            driver=Driver();driver.fail=failure
            result=adapter._replace(driver,'A','B')
            self.assertEqual(result['status'],'REJECTED_PREVIOUS_RETAINED')
            self.assertEqual(driver.active,'A')
            self.assertFalse(any(c[0] in ('activate','retire') for c in driver.calls))

    def test_uncertain_activation_readback_and_restore_without_retry(self):
        driver=Driver();driver.fail='activation';result=adapter._replace(driver,'A','B')
        self.assertEqual(result['status'],'REJECTED_PREVIOUS_RETAINED');self.assertEqual(driver.active,'A')
        self.assertEqual(sum(c[0]=='activate' for c in driver.calls),1)
        self.assertIn(('restore','B','A'),driver.calls)

    def test_failed_rollback_reports_uncertain_does_not_kill_possible_active_child(self):
        driver=Driver();driver.fail='rollback';result=adapter._replace(driver,'A','B')
        self.assertEqual(result['status'],'STATE_UNCERTAIN');self.assertEqual(result['active'],'B')
        self.assertFalse(any(c[0] in ('stop','retire') for c in driver.calls))
        self.assertFalse(result['retry'])

    def test_concurrent_activation_never_rolls_back_another_version(self):
        driver=Driver();driver.fail='concurrent';result=adapter._replace(driver,'A','B')
        self.assertEqual(result['status'],'STATE_UNCERTAIN');self.assertEqual(driver.active,'X')
        self.assertFalse(any(c[0] in ('restore','stop','retire') for c in driver.calls))

    def test_unowned_process_never_stopped(self):
        driver=Driver()
        with patch.object(driver,'owns',return_value=False):result=adapter._replace(driver,'A','B')
        self.assertEqual(result['status'],'CLEANUP_REQUIRES_REVIEW')
        self.assertFalse(any(c[0] in ('activate','stop','retire') for c in driver.calls))

    def test_retirement_error_does_not_undo_successful_activation(self):
        driver=Driver()
        with patch.object(driver,'retire',side_effect=OSError('FIXTURE_ERROR')):
            result=adapter._replace(driver,'A','B')
        self.assertEqual(result['status'],'ACTIVE_CLEANUP_PENDING');self.assertEqual(driver.active,'B')

    def test_unverified_previous_instance_never_starts_replacement(self):
        driver=Driver();driver.fail='previous_health'
        with self.assertRaisesRegex(ValueError,'PREVIOUS_INSTANCE_NOT_VERIFIED'):
            adapter._replace(driver,'A','B')
        self.assertEqual(driver.calls,[])

    def test_restored_routing_without_health_is_not_successful_rollback(self):
        driver=Driver();driver.fail='activation'
        with patch.object(driver,'verify_current',side_effect=[True,False]):
            result=adapter._replace(driver,'A','B')
        self.assertEqual(result['status'],'STATE_UNCERTAIN')
        self.assertFalse(any(call[0]=='stop' for call in driver.calls))


class StagingTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.store=self.root/'versions';self.store.mkdir()
        self.source=self.root/'source';self.source.write_bytes(b'fixture-only\n')
        self.sha=hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.project=Path(__file__).resolve().parents[1]
        import sys
        self.python=Path(sys.executable)

    def result(self):
        return {'isolation':{'separate_network_namespace':True,'capabilities':'ALL_ZERO'},
            'application':{'records':1,'sha256':self.sha,'corpus_path':str(self.store/'B/corpus.jsonl'),
                'complete_records_equal':True,'callbacks_share_assistant':True,'application_closed':True,
                'retriever_class':'src.retrieval_v1.RetrievalV1','retrieval':[{'query':'fixture'}]}}

    def stage(self):
        return adapter.stage_and_verify(self.project,self.store,'B',self.source,
            corpus_sha256=self.sha,record_count=1,app_python=self.python,queries=['fixture'])

    def test_actual_byte_storage_with_mocked_isolated_app_boundary(self):
        # Storage is real. The Gradio result/OS launcher is mocked only here;
        # genuine application verification is a separate external invocation.
        with patch('scripts.check_hosted_gradio_loading.isolated_python',return_value=self.result()) as launch:
            result=self.stage()
        self.assertEqual(result['status'],'RESEARCH_STAGING_VERIFIED')
        self.assertEqual(result['activation'],'NOT_ATTEMPTED')
        self.assertEqual(storage.inspect(self.store,'B')['metadata']['sha256'],self.sha)
        code=launch.call_args.args[2]
        self.assertLess(code.index("os.environ['SPHINX_CORPUS_PATH']"),code.index('from src.corpus_update_integration'))
        self.assertEqual(self.source.read_bytes(),b'fixture-only\n')

    def test_wrong_digest_rejected_before_app(self):
        self.source.write_bytes(b'changed')
        with patch('scripts.check_hosted_gradio_loading.isolated_python') as launch,self.assertRaises(ValueError):
            self.stage()
        launch.assert_not_called()

    def test_namespace_failure_has_no_activation_or_fallback(self):
        with patch('scripts.check_hosted_gradio_loading.isolated_python',side_effect=ValueError('NO_NAMESPACE')), \
             self.assertRaisesRegex(ValueError,'NO_NAMESPACE'):
            self.stage()
        self.assertEqual(storage.inspect(self.store,'B')['metadata']['sha256'],self.sha)

    def test_wrong_loaded_count_or_binding_rejected(self):
        for key,value in [('records',2),('sha256','0'*64),('callbacks_share_assistant',False),
                          ('application_closed',False)]:
            result=self.result();result['application'][key]=value
            with self.subTest(key=key),patch('scripts.check_hosted_gradio_loading.isolated_python',return_value=result), \
                 self.assertRaises(ValueError):self.stage()

    def test_unsafe_interpreter_rejected_before_storage(self):
        self.python=self.root/'missing'
        with self.assertRaisesRegex(ValueError,'INTERPRETER_REQUIRED'):self.stage()
        self.assertEqual(list(self.store.iterdir()),[])


if __name__=='__main__':unittest.main()
