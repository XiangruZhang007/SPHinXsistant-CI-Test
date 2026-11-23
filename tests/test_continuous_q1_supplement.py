"""Offline miniature builds; publication, Hosted API and Owner are fixtures."""
import ast
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from src import genuine_continuous_execution as g, version_aware_evidence as q
from src import q1_current_inputs as inputs, approval_evidence as ev, continuous_completion as completion
from src.corpus_snapshot import read_json, file_digest, write_json
import test_q1_current_inputs as adapters

P = Path(__file__).resolve().parents[1]

class SupplementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        adapters.FormatCompatibilityTests.setUpClass()
        cls.addClassCleanup(adapters.FormatCompatibilityTests.doClassCleanups)
        cls.fixture = adapters.FormatCompatibilityTests

    def setUp(self):
        t = tempfile.TemporaryDirectory(prefix='continuous-q1-supplement-'); self.addCleanup(t.cleanup)
        self.home = Path(t.name); self.delivery = self.home / 'delivery'
        shutil.copytree(self.fixture.manual_root.parent, self.delivery)
        self.pins = dict(self.fixture.manual_pins)

    def receipt(self): return read_json(self.delivery / 'q1-supplement.json')
    def verify(self):
        return g.verify_supplement(P, self.delivery, self.pins, file_digest(self.delivery / 'q1-supplement.json'))
    def clear(self):
        for n in ('q1-auto-inputs.json', 'q1-report', 'q1-supplement.json'):
            p = self.delivery / n
            if p.is_dir(): shutil.rmtree(p)
            elif p.exists(): p.unlink()
    def original(self):
        return {p.relative_to(self.delivery).as_posix(): file_digest(p) for p in self.delivery.rglob('*')
            if p.is_file() and (p.is_relative_to(self.delivery / 'run') or p.name == 'candidate.tar.gz')}

    def test_v2_automatic_after_seal_and_final_move(self):
        r = self.receipt(); self.assertEqual(r['status'], 'QUALIFIED')
        self.assertEqual(r['candidate_format'], g.FORMAT)
        self.assertEqual(self.verify()['status'], 'VERIFIED')
        self.assertFalse((self.delivery / 'run/q1-auto-inputs.json').exists())
        self.assertEqual(read_json(self.delivery / 'run/q1-status.json'), {'status':'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR'})

    def test_v3_automatic(self):
        shutil.rmtree(self.delivery); shutil.copytree(self.fixture.scheduled_root.parent, self.delivery)
        self.pins = dict(self.fixture.scheduled_pins)
        self.assertEqual(self.receipt()['candidate_format'], g.SCHEDULED_FORMAT)
        self.assertEqual(self.receipt()['status'], 'QUALIFIED'); self.assertEqual(self.verify()['status'], 'VERIFIED')

    def test_original_bytes_and_archive_preserved_no_replay(self):
        self.clear(); before = self.original()
        with patch.object(ev, 'replay', side_effect=AssertionError('No replay allowed for supplementary Q1')):
            r = g.supplementary_q1(P, self.delivery, self.pins)
        self.assertEqual(r['status'], 'QUALIFIED'); self.assertEqual(before, self.original())
        self.assertEqual(g.verify_package(P, self.delivery/'run', **self.pins)['verification'], 'PACKAGE_INTEGRITY_VERIFIED')

    def test_descriptor_relative_paths_survive_relocation(self):
        dest = self.home / 'relocated'; self.delivery.rename(dest); self.delivery = dest
        self.assertEqual(self.verify()['status'], 'VERIFIED')
        self.assertEqual(read_json(dest/'q1-auto-inputs.json')['paths']['run'], 'run')

    def test_identity_generation_and_independent_pins(self):
        r = self.receipt(); i = read_json(self.delivery/'run/candidate/genuine-candidate.json')['identity']
        self.assertEqual(r['generation'], i['generation']); self.assertEqual(r['parent'], i['parent'])
        self.assertEqual(r['execution_pins'], self.pins)
        self.assertEqual(r['bindings']['target_upstreams'], i['upstreams'])
        for key in g.PIN_FIELDS:
            bad = {**self.pins, key: 'sha256-'+'0'*64 if key=='expected_candidate_id' else '0'*64}
            with self.subTest(pin=key), self.assertRaises(ValueError):
                g.verify_supplement(P, self.delivery, bad, file_digest(self.delivery/'q1-supplement.json'))

    def test_deterministic_report_and_independent_regeneration(self):
        m = self.delivery/'q1-auto-inputs.json'; h = file_digest(m)
        self.assertEqual(q.generate(P,m,h), q.generate(P,m,h))
        with patch.object(q, 'generate', wraps=q.generate) as regenerate:
            self.verify(); self.assertGreaterEqual(regenerate.call_count, 1)

    def test_wrong_receipt_digest_and_changed_code(self):
        with self.assertRaisesRegex(ValueError,'RECEIPT_MISMATCH'):
            g.verify_supplement(P,self.delivery,self.pins,'0'*64)
        with patch.object(q,'implementation',return_value={'stale':'implementation'}):
            with self.assertRaisesRegex(ValueError,'SUPPLEMENT_BINDING'): self.verify()

    def test_missing_or_corrupt_supplement_files(self):
        trusted_receipt = file_digest(self.delivery/'q1-supplement.json')
        for rel in ('q1-supplement.json','q1-auto-inputs.json','q1-report/checksums.json',
                    'q1-report/version_aware_evidence_report.json','q1-report/summary.md'):
            p=self.delivery/rel; raw=p.read_bytes(); p.unlink()
            with self.subTest(missing=rel), self.assertRaises((ValueError,FileNotFoundError)):
                g.verify_supplement(P,self.delivery,self.pins,trusted_receipt)
            p.write_bytes(raw+b' ')
            with self.subTest(corrupt=rel), self.assertRaises(ValueError):
                g.verify_supplement(P,self.delivery,self.pins,trusted_receipt)
            p.write_bytes(raw)

    def test_descriptor_cannot_select_another_run(self):
        m=self.delivery/'q1-auto-inputs.json'; d=read_json(m); d['paths']['run']='elsewhere'
        m.unlink(); write_json(m,d)
        p=self.delivery/'q1-supplement.json'; r=read_json(p); r['descriptor_sha256']=file_digest(m)
        p.unlink(); write_json(p,r)
        with self.assertRaisesRegex(ValueError,'DESCRIPTOR_BINDING'): self.verify()

    def test_source_revision_or_archived_rows_mismatch(self):
        for key in ('target_upstreams','target_rows_sha256'):
            m=self.delivery/'q1-auto-inputs.json'; raw=m.read_bytes(); d=read_json(m)
            d['pins'][key] = {} if key.endswith('upstreams') else '0'*64
            m.unlink(); write_json(m,d)
            p=self.delivery/'q1-supplement.json'; old=p.read_bytes(); r=read_json(p); r['descriptor_sha256']=file_digest(m)
            p.unlink(); write_json(p,r)
            with self.subTest(key=key), self.assertRaises(ValueError): self.verify()
            m.write_bytes(raw); p.write_bytes(old)

    def test_original_package_failure_propagates_without_receipt(self):
        self.clear(); (self.delivery/'run/quality/incremental-raw-results.json').write_text('{}\n')
        with self.assertRaises(ValueError): g.supplementary_q1(P,self.delivery,self.pins)
        self.assertFalse((self.delivery/'q1-supplement.json').exists())

    def test_unsupported_format_explicit_and_original_preserved(self):
        self.clear(); before=self.original()
        with patch.object(inputs,'prepare',side_effect=ValueError('Q1_UNSUPPORTED_CANDIDATE_FORMAT')):
            r=g.supplementary_q1(P,self.delivery,self.pins)
        self.assertEqual(r['status'],'Q1_UNSUPPORTED_FORMAT'); self.assertEqual(before,self.original())
        with self.assertRaises(ValueError): self.verify()

    def test_input_qualification_failure_explicit(self):
        self.clear()
        with patch.object(inputs,'prepare',side_effect=ValueError('wrong independent row pin')):
            r=g.supplementary_q1(P,self.delivery,self.pins)
        self.assertEqual(r['status'],'Q1_INPUT_QUALIFICATION_FAILED')

    def test_generation_failure_explicit(self):
        self.clear()
        with patch.object(q,'generate',side_effect=ValueError('mapper failure')):
            r=g.supplementary_q1(P,self.delivery,self.pins)
        self.assertEqual(r['status'],'Q1_REPORT_GENERATION_FAILED')

    def test_report_verification_failure_explicit(self):
        self.clear()
        with patch.object(q,'verify_report',side_effect=ValueError('regeneration mismatch')):
            r=g.supplementary_q1(P,self.delivery,self.pins)
        self.assertEqual(r['status'],'Q1_REPORT_VERIFICATION_FAILED')

    def test_no_rewrite_duplicate_diagnostic(self):
        before=self.original(); old=file_digest(self.delivery/'q1-supplement.json')
        with self.assertRaisesRegex(ValueError,'SUPPLEMENT_ALREADY_EXISTS'):
            g.supplementary_q1(P,self.delivery,self.pins)
        self.assertEqual(old,file_digest(self.delivery/'q1-supplement.json')); self.assertEqual(before,self.original())

    def test_no_approval_and_mapping_classes_are_not_acceptance(self):
        self.assertEqual(self.verify()['diagnostic_qualification'],'QUALIFIED')
        report=read_json(self.delivery/'q1-report/version_aware_evidence_report.json')
        self.assertIn('classification_distribution',report['summary'])
        for record in (self.receipt(),report,self.verify()):
            self.assertFalse(record['automatic_research_approval']); self.assertFalse(record['official_score_adjustment'])
            self.assertEqual(record['production_promotion'],'NOT_AUTHORIZED')
        result=read_json(self.delivery/'run/result.json')
        self.assertEqual(result['Q1'],'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR'); self.assertEqual(result['P8'],'BLOCKED')

    def test_existing_completion_fixed_format_remains_compatible(self):
        a=read_json(self.delivery/'run/evidence/authorization-context.json')['workflow_run']
        config=read_json(self.delivery/'run/evidence/deployment.json')
        origin={k:config[k] for k in ('repository','repository_id','workflow_path','implementation_revision')}
        origin.update({k:a[k] for k in ('run_id','run_attempt','workflow_id','event')}); origin['job_id']=999
        result=completion.prepare(P,self.delivery,self.home/'completion',pins=self.pins,
            transport_sha256=file_digest(self.delivery/'candidate.tar.gz'),verified_origin=origin)
        self.assertEqual(set(p.name for p in (self.home/'completion').iterdir()),set(completion.ASSETS))
        self.assertEqual(result['manifest']['Q1'],'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
        self.assertEqual(self.verify()['status'],'VERIFIED')

    def test_execution_order_and_full_result_artifact(self):
        tree=ast.parse((P/'src/genuine_continuous_execution.py').read_text())
        fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='execute')
        calls=[n for n in ast.walk(fn) if isinstance(n,ast.Call)]
        supplement=next(n for n in calls if isinstance(n.func,ast.Name) and n.func.id=='supplementary_q1')
        verify=next(n for n in calls if isinstance(n.func,ast.Name) and n.func.id=='verify_package')
        relocation=next(n for n in calls if isinstance(n.func,ast.Attribute) and n.func.attr=='replace' and ast.unparse(n.func.value)=='delivery')
        self.assertGreater(supplement.lineno,relocation.lineno); self.assertGreater(relocation.lineno,verify.lineno)
        workflow=(P/'.github/workflows/upstream_refresh.yml').read_text()
        self.assertEqual(workflow.count('path: ${{ runner.temp }}/continuous-result/'),2)
