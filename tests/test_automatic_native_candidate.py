"""Synthetic native construction using real frozen algorithms and local Git.

Only upstream publication HTTP responses are mocked, using the existing fixture.
This never constructs a new genuine research experiment or approves its science.
"""
from copy import deepcopy
from pathlib import Path
import shutil,tempfile,unittest
from unittest.mock import patch
from src import automatic_candidate as native,automatic_lifecycle_policy as policies
from src import version_aware_evidence as q,approval_evidence as ev,continuous_execution as v1
from src.corpus_snapshot import read_json,file_digest,digest,write_json
import test_genuine_continuous_execution as genuine_fixtures
from test_automatic_lifecycle import policy as template


class NativeCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Factory=genuine_fixtures.GenuineFormatTests
        Factory.setUpClass();cls.addClassCleanup(Factory.doClassCleanups)
        cls.temporary=tempfile.TemporaryDirectory(prefix='native-offline-fixture-');cls.addClassCleanup(cls.temporary.cleanup)
        cls.work=Path(cls.temporary.name);cls.project=Factory.project
        parent=Factory.shared/'mock-publication-parent';proof=Factory.original/'run'
        cls.parent=native.parent_descriptor(parent,Factory.ref['node_id'],Factory.ref['upstreams'],Factory.ref['source_state'],
            read_json(parent/'upstream-baseline.json')['identity']['generation'])
        raw={k:v for k,v in template().items() if k in policies.FIELDS}
        history=proof/'evidence/historical-rows.json'
        raw.update(build_fingerprint=Factory.fp,continuous_policy_sha256=file_digest(Factory.policy_path),
            benchmark_sha256=ev.BENCHMARK_SHA,q1_implementation_sha256=digest(q.implementation(cls.project)),
            historical_rows_sha256=file_digest(history))
        # Repeated fixture text serves only to exercise byte/source bindings. It
        # is not a real license review or a publishable Candidate package.
        path='configs/ci_v2_runtime_lock.json';pin=file_digest(cls.project/path)
        raw['licenses']=[{'name':'fixture-license-'+str(i)+'.txt','path':path,'repository':'PROJECT','sha256':pin} for i in range(7)]
        cls.policy_path=cls.work/'fixture-policy.json';write_json(cls.policy_path,raw)
        cls.policy=policies.validate(raw,file_digest(cls.policy_path));cls.root=cls.work/'native'
        with Factory.boundaries():
            cls.result=native.produce(cls.project,parent,Factory.factory.base,Factory.factory.target,Factory.factory.revisions,
                cls.policy,cls.parent,history,cls.root,Factory.policy_path,cls.policy_path)
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'package';shutil.copytree(self.root_original,self.root)
    @property
    def root_original(self):return type(self).root
    def verify(self):return native.verify(self.project,self.root,self.policy,self.result['candidate_id'],self.parent)
    def reseal(self):
        (self.root/'checksums.json').unlink();v1._seal(self.root)
    def test_real_synthetic_build_full_r2_q1_are_not_accepted(self):
        self.assertFalse(self.verify()['eligible'])
        self.assertEqual(self.result['report']['status'],'QUALITY_REVIEW_REQUIRED')
        self.assertIn('FROZEN_STRICT_FAILURE',self.result['report']['reasons'])
    def test_modified_corpus_fails_even_after_resealing(self):
        with (self.root/'candidate/corpus.jsonl').open('ab') as f:f.write(b'{}\n')
        self.reseal()
        with self.assertRaises(ValueError):self.verify()
    def test_rewritten_admission_pass_json_cannot_approve(self):
        target=self.root/'quality/admission.json';target.unlink();write_json(target,{'accepted':True,'status':'QUALITY_ACCEPTED'})
        self.reseal()
        with self.assertRaises(ValueError):self.verify()
    def test_rewritten_parity_pass_json_rejected(self):
        target=self.root/'parity.json';target.unlink();write_json(target,{'status':'PARITY_PASS'})
        self.reseal()
        with self.assertRaises(ValueError):self.verify()
    def test_historical_rows_pin_is_independent(self):
        (self.root/'quality/historical-rows.json').write_bytes(b'[]\n');self.reseal()
        with self.assertRaises(ValueError):self.verify()
    def test_missing_source_proof_rejected(self):
        target=self.root/'source-proofs.json';target.unlink();write_json(target,{})
        self.reseal()
        with self.assertRaises((ValueError,KeyError)):self.verify()
    def test_missing_license_proof_rejected(self):
        target=self.root/'license-sources.json';target.unlink();write_json(target,{})
        self.reseal()
        with self.assertRaises(ValueError):self.verify()
    def test_raw_policy_bytes_are_exactly_bound(self):
        with (self.root/'policy.json').open('ab') as f:f.write(b' ')
        self.reseal()
        with self.assertRaises(ValueError):self.verify()

    def test_unexpected_run_member_rejected_even_after_reseal(self):
        (self.root/'unreviewed.json').write_bytes(b'{}\n');self.reseal()
        with self.assertRaisesRegex(ValueError,'UNEXPECTED_NATIVE_RUN_MEMBERS'):self.verify()
    def test_evaluator_projection_is_bound(self):
        (self.root/'candidate/candidate.json').write_bytes(b'{}\n');self.reseal()
        with self.assertRaisesRegex(ValueError,'NATIVE_PROJECTION_MISMATCH'):self.verify()
