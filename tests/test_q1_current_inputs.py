"""Current-run descriptors; lightweight fixtures mock only the existing deep loader.

Real exact-pair reproduction is a separate recorded invocation on retained assets.
"""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from src import q1_current_inputs as q
from src import schema2_workflow as w
from src.corpus_snapshot import file_digest, read_json, write_json


class CurrentInputsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.bindings={'build_fingerprint':'f'*64,'parent_id':'parent',
            'candidate_id':'candidate','base_source_state':'base-source','target_source_state':'target-source',
            'base_upstreams':{'SPHinXsys':'a'*40},'target_upstreams':{'SPHinXsys':'b'*40}}
        for name,value in [('parent/manifest.json',{'identity':{'upstreams':self.bindings['base_upstreams']}}),
                           ('candidate/upstream-candidate.json',{'identity':{'upstreams':self.bindings['target_upstreams']}}),
                           ('parent-raw-results.json',[]),('quality/incremental-raw-results.json',[]),('benchmark.json',{})]:
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);write_json(path,value)
        for label,folder in [('base','parent'),('target','candidate')]:
            for suffix,name in [('corpus_sha256','corpus.jsonl'),('documentation_sha256','components/documentation.jsonl')]:
                path=self.root/folder/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixture\n')
                if suffix=='corpus_sha256':self.bindings[label+'_'+suffix]=file_digest(path)
            self.bindings[label+'_rows_sha256']=file_digest(self.root/('parent-raw-results.json' if label=='base' else 'quality/incremental-raw-results.json'))
        self.bindings['benchmark_sha256']=file_digest(self.root/'benchmark.json')

    def test_exact_current_paths_and_loader_called(self):
        with patch.object(q.q,'load_inputs') as load:
            manifest,pin=q.prepare(self.root,self.root,self.bindings)
        self.assertEqual(pin,file_digest(manifest));load.assert_called_once_with(self.root,manifest,pin)
        d=read_json(manifest);self.assertEqual(d['pins']['target_candidate_id'],'candidate')
        self.assertEqual(d['paths']['target_rows'],'quality/incremental-raw-results.json')
        self.assertNotIn('approval',d)

    def test_mismatched_byte_bindings_fail_before_descriptor(self):
        for key in ['base_corpus_sha256','target_corpus_sha256','base_rows_sha256','target_rows_sha256','benchmark_sha256']:
            with self.subTest(key=key):
                bindings={**self.bindings,key:'wrong'}
                with self.assertRaises(ValueError):q.prepare(self.root,self.root,bindings)
                self.assertFalse((self.root/'q1-auto-inputs.json').exists())

    def test_upstream_mismatch(self):
        with self.assertRaises(ValueError):q.prepare(self.root,self.root,{**self.bindings,'target_upstreams':{}})

    def test_missing_rows(self):
        (self.root/'quality/incremental-raw-results.json').unlink()
        with self.assertRaises(ValueError):q.prepare(self.root,self.root,self.bindings)

    def test_identity_mismatch_propagates_from_real_loader_boundary(self):
        for key in ['parent_id','candidate_id','base_source_state','target_source_state']:
            with self.subTest(key=key),patch.object(q.q,'load_inputs',side_effect=ValueError('Wrong version pair')):
                with self.assertRaises(ValueError):q.prepare(self.root,self.root,{**self.bindings,key:'wrong'})
                (self.root/'q1-auto-inputs.json').unlink()

    def test_existing_descriptor_not_overwritten(self):
        path=self.root/'q1-auto-inputs.json';path.write_bytes(b'original')
        with self.assertRaises(ValueError):q.prepare(self.root,self.root,self.bindings)
        self.assertEqual(path.read_bytes(),b'original')

    def test_duplicate_binding_json_rejected(self):
        (self.root/'parent/manifest.json').write_text('{"identity":{},"identity":{}}')
        with self.assertRaises(ValueError):q.prepare(self.root,self.root,self.bindings)

    def test_invalid_auto_inputs_remain_explicit_unqualified(self):
        spec={'questions':[{'id':'unit','evidence_mode':'ALL_OF','requirements':[]}]}
        row={'id':'unit','mode':'combined','strict':{'hit_at_5':False,'hit_at_10':False},'top_10':[]}
        with patch.object(q,'prepare',side_effect=ValueError('Current-run rows mismatch')):
            status,report=w.diagnostics(self.root,self.root,spec,[row],[row],{},automatic=True)
        self.assertEqual(status['status'],'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
        self.assertIn('rows mismatch',status['reason']);self.assertFalse(report['blocking'])
        self.assertFalse(report['automatic_research_approval'])

    def test_run_local_enables_auto_but_transport_api_remains_supported(self):
        source=Path(w.__file__).read_text();self.assertIn('q1_inputs=q1_inputs, q1_sha=q1_sha, automatic=True)',source)
        self.assertIn('if q1_inputs is None:',source)


    def test_unsupported_candidate_format_cannot_be_marked_qualified(self):
        (self.root/'candidate/upstream-candidate.json').unlink()
        with self.assertRaisesRegex(ValueError,'UNSUPPORTED_CANDIDATE_FORMAT'):
            q.prepare(self.root,self.root,self.bindings)
        self.assertFalse((self.root/'q1-auto-inputs.json').exists())

    def test_auto_helper_is_in_execution_contract(self):
        from src import continuous_execution
        self.assertIn('src/q1_current_inputs.py',continuous_execution.FILES)


    def test_unpaired_checksum_cannot_trigger_auto_fallback(self):
        spec={'questions':[{'id':'unit','evidence_mode':'ALL_OF','requirements':[]}]}
        row={'id':'unit','mode':'combined','strict':{'hit_at_5':False,'hit_at_10':False},'top_10':[]}
        with patch.object(q,'prepare') as prepare:
            status,_=w.diagnostics(self.root,self.root,spec,[row],[row],{},automatic=True,q1_sha='bad')
        prepare.assert_not_called();self.assertEqual(status['status'],'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
        self.assertIn('paired',status['reason'])
