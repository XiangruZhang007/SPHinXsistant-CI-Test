"""Policy kernels use synthetic facts only; public readers never grant authority."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from src import automatic_quality_admission as admission
from src.corpus_snapshot import digest


class AutomaticAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.policy={'schema_version':1,'kind':admission.KIND,
            'repository':'Fixture/Research','repository_id':42,
            'valid_from':'2020-01-01T00:00:00Z','expires_at':'2099-01-01T00:00:00Z',
            'benchmark_sha256':'b'*64,'build_fingerprint':'f'*64,
            'required_modes':['combined','documentation_only'],'required_rows':2,
            'requirements':deepcopy(admission.REQUIREMENTS)}
        self.path=self.root/'policy.json';self.save()
        self.facts={'integrity':'VERIFIED_ARCHIVED_BINDINGS','parity':'PARITY_PASS',
            'quality':'QUALITY_ACCEPTED','accepted':True,'q1':'QUALIFIED_FOR_VERSION_PAIR',
            'p8':'ELIGIBLE','p8_mode':'ACCEPTING_CONTRACT','prohibitions':[],
            'provenance':'AUTHENTICATED_GITHUB_ACTIONS',
            'bindings':{'benchmark_sha256':'b'*64,'build_fingerprint':'f'*64,
                'candidate_id':'sha256-'+'c'*64,'corpus_sha256':'d'*64},
            'rows':[{'mode':mode,'id':'Q1','strict':{'hit_at_5':True,'hit_at_10':True}}
                for mode in self.policy['required_modes']], 'new_losses':[]}

    def save(self):
        self.path.write_text(json.dumps(self.policy));self.pin=hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_policy_only_success_never_grants_authority(self):
        self.assertEqual(admission.policy(self.path,self.pin),self.policy)
        result=admission._decide(self.facts,self.policy)
        self.assertEqual(result['eligibility'],'ELIGIBLE')
        self.assertEqual(result['authorization'],'NOT_GRANTED')
        self.assertEqual(result['authority_scope'],'POLICY_CALCULATION_ONLY')
        self.assertEqual(result,admission._decide(deepcopy(self.facts),deepcopy(self.policy)))
        changed=deepcopy(self.facts);changed['bindings']['corpus_sha256']='e'*64
        self.assertNotEqual(result['decision_sha256'],admission._decide(changed,self.policy)['decision_sha256'])

    def test_each_historical_restriction_is_non_overridable(self):
        for field,value,reason in [
            ('parity','PARITY_FAIL','PARITY_NOT_PASS'),
            ('quality','QUALITY_REVIEW_REQUIRED','QUALITY_NOT_ACCEPTED'),
            ('accepted',False,'QUALITY_NOT_ACCEPTED'),
            ('q1','Q1_NOT_QUALIFIED_FOR_VERSION_PAIR','Q1_NOT_QUALIFIED'),
            ('p8','P8_BLOCKED','P8_BLOCKED'),('p8_mode','BLOCKING_ONLY','P8_BLOCKED'),
            ('prohibitions',['PRODUCTION_NOT_AUTHORIZED'],'EXPLICIT_RELEASE_RESTRICTION'),
            ('provenance','SYNTHETIC','PRODUCER_NOT_AUTHENTICATED'),
            ('integrity','NOT_VERIFIED','INTEGRITY_NOT_VERIFIED')]:
            facts={**deepcopy(self.facts),field:value}
            result=admission._decide(facts,self.policy)
            with self.subTest(field=field):
                self.assertEqual(result['eligibility'],'BLOCKED');self.assertIn(reason,result['reasons'])

    def test_strict_failure_and_new_loss_never_waived(self):
        facts=deepcopy(self.facts);facts['rows'][0]['strict']['hit_at_5']=False
        result=admission._decide(facts,self.policy)
        self.assertIn('FROZEN_STRICT_FAILURE',result['reasons']);self.assertEqual(result['strict_failure_count'],1)
        facts=deepcopy(self.facts);facts['new_losses']=[{'id':'Q1'}]
        self.assertIn('NEW_RETRIEVAL_REGRESSION',admission._decide(facts,self.policy)['reasons'])

    def test_invalid_row_domain_missing_duplicate_and_wrong_mode(self):
        for rows in [[],self.facts['rows'][:1],[self.facts['rows'][0]]*2,
                     [{**row,'mode':'unreviewed'} for row in self.facts['rows']]]:
            result=admission._decide({**self.facts,'rows':rows},self.policy)
            self.assertIn('R2_ROW_DOMAIN_MISMATCH',result['reasons'])
        facts=deepcopy(self.facts);facts['rows'][0]['strict']['hit_at_5']=1
        self.assertIn('FROZEN_STRICT_FAILURE',admission._decide(facts,self.policy)['reasons'])

    def test_wrong_benchmark_or_build_domain_denied(self):
        for field in ('benchmark_sha256','build_fingerprint'):
            facts=deepcopy(self.facts);facts['bindings'][field]='0'*64
            self.assertIn('SCIENTIFIC_DOMAIN_MISMATCH',admission._decide(facts,self.policy)['reasons'])

    def test_policy_cannot_waive_science(self):
        self.policy['requirements']['strict_failures']=1;self.save()
        with self.assertRaisesRegex(ValueError,'UNSUPPORTED_ADMISSION_REQUIREMENTS'):
            admission.policy(self.path,self.pin)

    def test_policy_pin_time_closed_schema_and_symlink(self):
        with self.assertRaises(ValueError):admission.policy(self.path,'0'*64)
        for key,value in [('expires_at','2000-01-01T00:00:00Z'),('extra',True),('repository_id',True),
                          ('benchmark_sha256','invalid')]:
            old=deepcopy(self.policy);self.policy[key]=value;self.save()
            with self.subTest(key=key),self.assertRaises(ValueError):admission.policy(self.path,self.pin)
            self.policy=old;self.save()
        link=self.root/'link';link.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(OSError):admission.policy(link/'policy.json',self.pin)

    def test_missing_or_uploaded_json_cannot_become_approval(self):
        for artifact in (self.root/'missing',self.path):
            result=admission.evaluate(artifact,self.path,self.pin)
            self.assertEqual(result['eligibility'],'BLOCKED')
            self.assertEqual(result['authorization'],'NOT_GRANTED')

    def test_genuine_reader_uses_actual_existing_verifier_no_replay(self):
        # Only an invalid verifier fixture is used here; no synthetic success
        # is represented as real Genuine package or producer verification.
        from src import genuine_continuous_execution as genuine
        with patch.object(genuine,'verify_package',side_effect=ValueError('INVALID')) as verify:
            result=admission.evaluate_genuine(self.root,self.root,{},self.path,self.pin)
        verify.assert_called_once_with(self.root,self.root/'run',fresh_replay=False)
        self.assertEqual(result['eligibility'],'BLOCKED')


class GenuineAutomaticAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Existing fully sealed MOCK publication fixture, never a real producer.
        import test_genuine_continuous_execution as fixtures
        cls.fixture=fixtures.GenuineFormatTests
        cls.fixture.setUpClass();cls.addClassCleanup(cls.fixture.doClassCleanups)

    def test_complete_genuine_package_reads_original_restrictions_without_replay(self):
        from src.corpus_snapshot import read_json
        from src import genuine_continuous_execution as genuine
        f=self.fixture;root=f.original/'run'
        config=read_json(root/'evidence/deployment.json')
        quality=read_json(root/'quality/quality-report.json')
        policy={'schema_version':1,'kind':admission.KIND,
            'repository':config['repository'],'repository_id':config['repository_id'],
            'valid_from':'2020-01-01T00:00:00Z','expires_at':'2099-01-01T00:00:00Z',
            'benchmark_sha256':quality['policy']['benchmark_sha256'],
            'build_fingerprint':f.fp,'required_modes':['combined','documentation_only'],
            'required_rows':128,'requirements':deepcopy(admission.REQUIREMENTS)}
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'policy.json';path.write_text(json.dumps(policy))
            pin=hashlib.sha256(path.read_bytes()).hexdigest()
            with patch.object(genuine.ev,'replay',side_effect=AssertionError('FRESH_REPLAY_FORBIDDEN')):
                result=admission.evaluate_genuine(f.project,f.original,f.pins,path,pin)
            self.assertEqual(result['eligibility'],'BLOCKED',result)
            self.assertEqual(result['scientific_execution'],'NO_FRESH_REPLAY',result)
            self.assertEqual(result['original_q1_status'],'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
            self.assertEqual(result['observed']['quality'],'QUALITY_REVIEW_REQUIRED')
            self.assertIn('P8_BLOCKED',result['reasons'])
            self.assertEqual(result['authorization'],'NOT_GRANTED')


if __name__=='__main__':unittest.main()
