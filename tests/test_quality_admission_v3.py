"""Synthetic boundary tests, never Hosted or scientific acceptance evidence."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from src import quality_admission as quality, admission_evidence as evidence
from src import automatic_candidate as native,automatic_lifecycle_policy as policies
from src import native_runtime_contract as runtime,derived_parent_registry as derived
from src.corpus_snapshot import digest
ROOT=Path(__file__).resolve().parents[1]
def rules():
    return {**json.loads((ROOT/'configs/ci_v2_quality_admission_v3.json').read_text()),'enabled':True}
def facts():
    return {mode+'/'+str(i):{'id':str(i),'mode':mode,'critical':False,'primary':True,
        'unknown':False,'hits':{'5':True,'10':True}} for mode in quality.MODES for i in range(40)}
class DecisionTests(unittest.TestCase):
    def test_disabled_policy_is_not_authorization(self):
        value={**rules(),'enabled':False}
        with self.assertRaises(ValueError):quality.validate(value)
        self.assertFalse(quality.validate(value,require_enabled=False)['enabled'])
    def test_bounded_loss_and_inherited_failure(self):
        base=facts();target=deepcopy(base);target['combined/0']['hits']['5']=False
        self.assertTrue(quality.decision(rules(),base,target,base)['accepted'])
        target['combined/1']['hits']['5']=False
        self.assertIn('RETRIEVAL_REGRESSION_BUDGET_EXCEEDED',quality.decision(rules(),base,target,base)['reasons'])
        self.assertTrue(quality.decision(rules(),target,target,target)['accepted'])
        base['combined/2']['hits']['5']=False;target['combined/2']['hits']['5']=True
        self.assertFalse(quality.decision(rules(),base,target,base)['accepted'])
    def test_fixed_anchor_prevents_ratchet(self):
        anchor=facts();base=deepcopy(anchor);target=deepcopy(anchor)
        base['combined/0']['hits']['5']=False
        for i in (0,1):target['combined/'+str(i)]['hits']['5']=False
        reasons=quality.decision(rules(),base,target,anchor)['reasons']
        self.assertNotIn('RETRIEVAL_REGRESSION_BUDGET_EXCEEDED',reasons)
        self.assertIn('CUMULATIVE_REGRESSION_BUDGET_EXCEEDED',reasons)
    def test_absolute_floor_blocks_bad_baseline(self):
        data=facts()
        for i in range(30):data['combined/'+str(i)]['hits']={'5':False,'10':False}
        self.assertIn('ABSOLUTE_QUALITY_FLOOR_FAILED',quality.decision(rules(),data,data,data)['reasons'])
    def test_unknowns_keep_denominator(self):
        data=facts();target=deepcopy(data)
        target['combined/0'].update(unknown=True,hits={'5':False,'10':False})
        result=quality.decision(rules(),data,target,data)
        self.assertTrue(result['accepted']);self.assertEqual(result['metrics']['combined']['n'],40)
        target['combined/1'].update(unknown=True,hits={'5':False,'10':False})
        self.assertIn('MAPPING_UNCERTAINTY_BUDGET_EXCEEDED',quality.decision(rules(),data,target,data)['reasons'])
    def critical_facts(self):
        data=facts()
        # Two required units: the second is inherited ranking debt. The first
        # still has to be retained even though the question already fails.
        data['combined/0'].update(critical=True,primary=False, hits={'5':False,'10':False},
            requirements=[{'status':'RESOLVED','reason':None,'units':[['a'],['b']],
                'coverage':{'5':[True,False],'10':[True,False]}}])
        return data
    def lose_unit(self,data,cutoff='10'):
        row=data['combined/0'];row['requirements'][0]['coverage'][cutoff][0]=False
        if cutoff=='10':row['requirements'][0]['coverage']['5'][0]=False
    def test_verified_debt_is_not_kb_blocker_or_application_pass(self):
        data=self.critical_facts();result=quality.decision(rules(),data,data,data)
        self.assertTrue(result['accepted']);self.assertEqual(result['critical_failures'],[])
        self.assertEqual(result['baseline_debt'][0]['question'],'combined/0')
        self.assertEqual(len(result['baseline_debt'][0]['missing_units']),2)
        self.assertFalse(result['application_quality']['critical_top10_complete'])
    def test_partial_critical_loss_blocks_against_either_baseline(self):
        for comparator in ('base','anchor'):
            for cutoff in ('5','10'):
                good=self.critical_facts();bad=deepcopy(good);self.lose_unit(bad,cutoff)
                base,anchor=(good,bad) if comparator=='base' else (bad,good)
                result=quality.decision(rules(),base,bad,anchor)
                self.assertIn('CRITICAL_RETRIEVAL_DEGRADATION',result['reasons'])
                self.assertEqual({r['baseline'] for r in result['critical_retrieval_regressions']},{comparator})
                self.assertEqual(result['baseline_debt'],[])
    def test_new_complete_question_failure_is_unconditional(self):
        data=self.critical_facts()
        row=data['combined/0'];row['requirements'][0]['coverage']={'5':[True,True],'10':[True,True]}
        row['hits']={'5':True,'10':True}
        target=deepcopy(data);self.lose_unit(target);target['combined/0']['hits']={'5':False,'10':False}
        self.assertIn('CRITICAL_RETRIEVAL_DEGRADATION',quality.decision(rules(),data,target,data)['reasons'])
    def unresolved(self,data,reason):
        row=data['combined/0'];row.update(unknown=True,hits={'5':False,'10':False})
        row['requirements']=[{'status':'UNRESOLVED','reason':reason,'units':[],
            'coverage':{'5':[],'10':[]}}]
    def test_critical_corpus_failure_or_conflict_is_never_debt(self):
        for reason in ('REFERENCE_SCOPE_NOT_INDEXED','REQUIRED_LITERAL_NOT_INDEXED','AMBIGUOUS_REFERENCE_SCOPE'):
            data=self.critical_facts();target=deepcopy(data);self.unresolved(target,reason)
            result=quality.decision(rules(),data,target,data)
            self.assertIn('CRITICAL_CORPUS_EVIDENCE_FAILURE',result['reasons'])
            self.assertEqual(result['baseline_debt'],[])
    def test_unverifiable_baseline_never_grants_debt_exception(self):
        for comparator in ('base','anchor'):
            data=self.critical_facts();unknown=deepcopy(data);self.unresolved(unknown,'AMBIGUOUS_REFERENCE_SCOPE')
            base,anchor=(unknown,data) if comparator=='base' else (data,unknown)
            self.assertIn('CRITICAL_BASELINE_UNVERIFIED',quality.decision(rules(),base,data,anchor)['reasons'])
    def test_malformed_or_conflicting_coverage_fails_closed(self):
        changes=[lambda r:r.pop('requirements'),
            lambda r:r['requirements'][0]['coverage']['5'].__setitem__(0,1),
            lambda r:r['requirements'][0]['coverage']['10'].__setitem__(0,False),
            lambda r:r['hits'].__setitem__('10',True),
            lambda r:r['requirements'][0]['coverage']['10'].append(False)]
        for change in changes:
            data=self.critical_facts();target=deepcopy(data);change(target['combined/0'])
            with self.assertRaises(ValueError):quality.decision(rules(),data,target,data)
        data=self.critical_facts();target=deepcopy(data)
        target['combined/0']['requirements'].append(deepcopy(target['combined/0']['requirements'][0]))
        with self.assertRaisesRegex(ValueError,'CRITICAL_EVIDENCE_DOMAIN_CHANGED'):
            quality.decision(rules(),data,target,data)
    def test_critical_gains_do_not_offset_another_unit_loss(self):
        data=self.critical_facts();target=deepcopy(data);self.lose_unit(target)
        target['combined/0']['requirements'][0]['coverage']['10'][1]=True
        self.assertFalse(quality.decision(rules(),data,target,data)['accepted'])
    def test_missing_row_and_boolean_threshold_rejected(self):
        data=facts();bad=deepcopy(data);bad.pop(next(iter(bad)))
        with self.assertRaises(ValueError):quality.decision(rules(),data,bad,data)
        value=rules();value['max_new_losses']['combined']['5']=True
        with self.assertRaises(ValueError):quality.validate(value)
class EvidenceTests(unittest.TestCase):
    def records(self):return [{'chunk_id':str(i),'source_path':'repos/SPHinXsim/docs/a.md',
        'source_role':'documentation','symbol':'scope','section_title':'Scope',
        'start_line':i+1,'end_line':i+1,'content':v} for i,v in enumerate(('alpha','beta'))]
    def ref(self):return {'path':'repos/SPHinXsim/docs/a.md','symbol':None,'section_title':None,'contains_all':['alpha','beta']}
    def rows(self):return [{'id':'Q','mode':'combined','primary_score_eligible':True,'top_10_ids':['0','1']}]
    def refs(self):return {'Q':{'critical':False,'requirements':[self.ref()]}}
    def test_multi_chunk_all_of_at_fixed_k(self):
        self.assertTrue(evidence.outcomes(self.records(),self.rows(),self.refs())['combined/Q']['hits']['5'])
        rows=self.rows();rows[0]['top_10_ids']=['0']
        outcome=evidence.outcomes(self.records(),rows,self.refs())['combined/Q']
        self.assertFalse(outcome['hits']['10'])
        self.assertEqual(outcome['requirements'][0]['coverage'],{'5':[True,False],'10':[True,False]})
    def test_stale_lines_do_not_change_predicate(self):
        records=self.records()
        for r in records:r['start_line']+=100;r['end_line']+=100
        self.assertTrue(evidence.outcomes(records,self.rows(),self.refs())['combined/Q']['hits']['10'])
    def test_unknown_literal_is_not_pass(self):
        refs=self.refs();refs['Q']['requirements'][0]['contains_all'].append('absent')
        result=evidence.outcomes(self.records(),self.rows(),refs)['combined/Q']
        self.assertTrue(result['unknown']);self.assertFalse(result['hits']['10'])
    def test_missing_scope_and_ambiguous_scope(self):
        ref=self.ref();ref['path']='repos/SPHinXsim/missing.py'
        self.assertEqual(evidence.resolve(self.records(),ref)['reason'],'REFERENCE_SCOPE_NOT_INDEXED')
        ref=self.ref();ref['symbol']='scope';records=self.records();records[1].update(start_line=20,end_line=20)
        self.assertEqual(evidence.resolve(records,ref)['reason'],'AMBIGUOUS_REFERENCE_SCOPE')
    def test_enum_predicate_excludes_incidental_words_and_detects_ambiguity(self):
        document=json.loads((ROOT/'configs/ci_v2_admission_references_v1.json').read_text())
        ref=next(q for q in document['questions'] if q['id']=='C-12')['requirements'][0]
        records=self.records()
        for r in records:r.update(source_path=ref['path'],content='fluid_dynamics continuum_dynamics',symbol='OtherClass')
        self.assertEqual(evidence.resolve(records,ref)['reason'],'REFERENCE_SCOPE_NOT_INDEXED')
        for r in records:r['symbol']='SimulationType'
        self.assertEqual(evidence.resolve(records,ref)['status'],'RESOLVED')
        records[1].update(start_line=20,end_line=20)
        self.assertEqual(evidence.resolve(records,ref)['reason'],'AMBIGUOUS_REFERENCE_SCOPE')
    def test_unbound_and_duplicate_rank_ids_rejected(self):
        for ids in (['unbound'],['0','0']):
            rows=self.rows();rows[0]['top_10_ids']=ids
            with self.assertRaises(ValueError):evidence.outcomes(self.records(),rows,self.refs())
class FingerprintTests(unittest.TestCase):
    def test_application_and_scoring_changes_do_not_change_runtime_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            project=Path(temp)
            for name in runtime.FILES:
                path=project/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(name)
            expected=digest(runtime.contract(project))
            for name in ('apps/gradio_app_v1.py','src/retrieval_v1.py','src/grounded_answer_v1.py','src/quality_admission.py','src/version_aware_evidence.py'):
                path=project/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('new')
                self.assertEqual(expected,digest(runtime.contract(project)))
            (project/'src/automatic_writer.py').write_text('trust change')
            self.assertNotEqual(expected,digest(runtime.contract(project)))
    def test_initial_anchor_preflight_precedes_construction(self):
        from unittest.mock import patch
        with patch.object(native.v1,'_assemble',side_effect=AssertionError('CONSTRUCTION_STARTED')):
            with self.assertRaisesRegex(ValueError,'V3_INITIAL_ANCHOR_REQUIRED'):
                native.produce(ROOT,ROOT,ROOT,ROOT,{}, {'schema_version':3},{},ROOT,
                    ROOT/'never-created',ROOT,ROOT)

    def test_v4_and_v5_are_explicit(self):
        self.assertEqual(native.package_format({'schema_version':2}),native.FORMAT)
        self.assertEqual(native.package_format({'schema_version':3}),native.FORMAT_V5)
        self.assertEqual(policies.observation_policy({'schema_version':3,'x':1}),{'schema_version':2,'x':1})
    def test_ref_is_restricted_and_not_write_authorization(self):
        with self.assertRaises(ValueError):derived.GitState('Owner/Test',1,'fixture',ref='refs/heads/main')
        store=derived.GitState('Owner/Test',1,'fixture',ref='refs/heads/ci-v2-authority-audit/derived-parent-state-v2')
        with self.assertRaises(ValueError):store._call('GET','/git/ref/heads/ci-v2-authority-audit/derived-parent-state-v1')
        with self.assertRaises(ValueError):store.append('a'*40,{}, {})
class IntegrationTests(unittest.TestCase):
    def test_v3_publication_and_two_completed_parent_transactions(self):
        # Reuse the real coordinator/packaging/audit fixture. Its positive
        # science/HTTP observations remain synthetic, never Hosted acceptance.
        from unittest.mock import patch
        import test_automatic_transport as transport
        original=transport.PublicationTests.setUp
        def v3_setup(case):
            original(case)
            case.policy.update(schema_version=3,derived_ref='refs/heads/ci-v2-authority-audit/derived-parent-state-v2')
            case.verified['report'].update(contract='AUTOMATIC_QUALITY_V3',q1='ADMISSION_EVIDENCE_V3_CHECKED')
        from test_automatic_lifecycle import LifecycleTests
        old_lineage=LifecycleTests.setUp
        def v3_lineage(case):
            old_lineage(case)
            case.policy.update(schema_version=3,derived_ref='refs/heads/ci-v2-authority-audit/derived-parent-state-v2')
        case=transport.CompleteOrchestrationTests('test_two_parent_generations_publication_selection_and_driver_rollback')
        with patch.object(transport.PublicationTests,'setUp',v3_setup),patch.object(LifecycleTests,'setUp',v3_lineage):
            case.debug()

    def test_v2_state_ref_full_git_object_readback_and_no_retry(self):
        from unittest.mock import patch
        import test_automatic_transport as transport
        case=transport.StateHTTPTests();case.setUp();self.addCleanup(case.doCleanups)
        with patch.object(derived,'REF','refs/heads/ci-v2-authority-audit/derived-parent-state-v2'):
            case.transport=derived.GitState('FixtureOwner/Test',1,'fixture-token',writable=True,ref=derived.REF)
            case.test_real_gitstate_append_and_full_blob_readback()
            with self.assertRaises(ValueError):case.transport.append(case.head,{}, {})

    def test_policy_change_requires_explicit_genesis_migration(self):
        import test_automatic_lifecycle as fixtures
        old=fixtures.policy();raw={k:v for k,v in old.items() if k in policies.FIELDS}
        raw.update(schema_version=3,derived_ref='refs/heads/ci-v2-authority-audit/derived-parent-state-v2',
            ruleset_observation={},component_fingerprints={k:'a'*64 for k in
                ('construction','retrieval','benchmark','evaluation','admission','lifecycle')},
            quality_v3={k:{'path':'configs/'+k+'.json','sha256':'a'*64} for k in ('policy','references')})
        first=policies.validate(raw,'b'*64)
        changed=deepcopy(raw);changed['quality_v3']['policy']['sha256']='c'*64
        second=policies.validate(changed,'d'*64)
        self.assertNotEqual(first['scope_sha256'],second['scope_sha256'])
        self.assertNotEqual(first['policy_sha256'],second['policy_sha256'])
        changed['max_generations']=7
        self.assertNotEqual(first['scope_sha256'],policies.validate(changed,'e'*64)['scope_sha256'])

if __name__=='__main__':unittest.main()
