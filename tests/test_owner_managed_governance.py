"""Offline Owner-managed v1 policy tests; no genuine Owner grants or API writes."""
from copy import deepcopy
import hashlib
import json
import os
from unittest.mock import patch
import unittest

import test_hosted_parent_authority_transition as invocation
import test_parent_authority_github_transport as transport_fixtures
from scripts import parent_authority_writer_gate as gate
from src import owner_managed_governance as governance
from src import hosted_parent_authority_transition as hosted
from src import parent_authority_git_audit as audit
from src.corpus_snapshot import digest


class OwnerManagedTests(unittest.TestCase):
    def setUp(self):
        self.fixture = invocation.InvocationTests(); self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.config = deepcopy(self.fixture.config)
        self.config.update(schema_version=3, transaction_backend={
            'kind':'GITHUB_GIT_AUDIT_V1',
            'audit':{'schema_version':1,'repository':self.config['request']['repository'],
                'repository_id':self.config['request']['repository_id'],
                'ref':'refs/heads/ci-v2-authority-audit/' + self.config['request']['transaction_id'],
                'genesis_sha':'a'*40,'tree_sha':'b'*40,'governance_sha256':'c'*64},
            'history_ruleset_id':1,'writer_ruleset_id':2,'writer_integration_id':gate.APP_ID})
        r = self.config['request']
        self.policy = {'schema_version':1,'trust_model':governance.MODEL,
            **{k:r[k] for k in ('repository','repository_id','workflow_path','default_branch')},
            'owner_id':gate.OWNER_ID,'implementation_contract_sha256':'0'*64,
            'valid_from':'2020-01-01T00:00:00Z','expires_at':'2099-01-01T00:00:00Z',
            'history_ruleset_id':1,'writer_ruleset_id':2,'writer_integration_id':gate.APP_ID,
            'risk_acceptance':governance.RISK}
        self.save()

    def save(self):
        path=self.root/'configs/governance.json'
        path.write_text(json.dumps(self.policy))
        self.config['governance']={'trust_model':governance.MODEL,
            'policy_path':'configs/governance.json',
            'policy_sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
        self.config['subject_sha256']=digest(hosted.subject(self.config['request'],
            self.config['proposal_sha256'],self.config['workflow_id'],
            governance_policy_sha256=self.config['governance']['policy_sha256']))

    def test_exact_versioned_policy_and_new_subject(self):
        self.assertEqual(governance.load(self.root,self.config),self.policy)
        old=hosted.subject(self.config['request'],self.config['proposal_sha256'],103)
        new=hosted.subject(self.config['request'],self.config['proposal_sha256'],103,
            governance_policy_sha256=self.config['governance']['policy_sha256'])
        self.assertEqual(old['schema_version'],1);self.assertEqual(new['schema_version'],2)
        self.assertNotEqual(digest(old),digest(new))
        raw=json.dumps(self.config)
        with patch.object(hosted,'PROJECT',self.root),patch.dict(os.environ,{
            'PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_JSON':raw,
            'PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_SHA256':hashlib.sha256(raw.encode()).hexdigest()}):
            self.assertEqual(hosted._deployment(),self.config)

    def test_old_subject_cannot_authorize_new_governance(self):
        self.config['subject_sha256']=self.fixture.config['subject_sha256']
        raw=json.dumps(self.config)
        with patch.object(hosted,'PROJECT',self.root),patch.dict(os.environ,{
            'PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_JSON':raw,
            'PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_SHA256':hashlib.sha256(raw.encode()).hexdigest()}), \
             self.assertRaisesRegex(ValueError,'TRANSITION_SUBJECT_PIN_MISMATCH'):
            hosted._deployment()

    def test_expired_future_unknown_and_wrong_domain_policies_rejected(self):
        cases={'expires_at':'2000-01-01T00:00:00Z','valid_from':'2098-01-01T00:00:00Z',
            'repository_id':999,'workflow_path':'.github/workflows/other.yml',
            'risk_acceptance':'INDEPENDENT_GOVERNANCE_VERIFIED',
            'implementation_contract_sha256':'1'*64,'writer_integration_id':4,'extra':True}
        old=deepcopy(self.policy)
        for key,value in cases.items():
            self.policy={**old,key:value};self.save()
            with self.subTest(key=key),self.assertRaises((ValueError,KeyError)):
                governance.load(self.root,self.config)

    def test_raw_file_pin_and_symlink_fail(self):
        path=self.root/'configs/governance.json';raw=path.read_bytes()
        path.write_bytes(raw+b' ')
        with self.assertRaises(ValueError):governance.load(self.root,self.config)
        path.unlink();path.symlink_to(self.fixture.event)
        with self.assertRaises(ValueError):governance.load(self.root,self.config)

    def test_actual_rules_observer_and_mandatory_credential_gate(self):
        fixture=transport_fixtures.GitHubTransportTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.governance()
        # Real policy load and actual HTTP Ruleset validator; only authenticated
        # GitHub gate/API boundaries are synthetic. Not Hosted acceptance.
        self.policy['writer_integration_id']=3;self.config['transaction_backend']['writer_integration_id']=3;self.save()
        with patch.object(gate,'APP_ID',3),patch.object(gate,'verify') as verify, \
             patch.object(gate,'verify_token',return_value={'status':'SYNTHETIC_SCOPE'}) as token:
            observed=governance.observe(self.root,self.config,fixture.transport())
            verify.assert_called_once();token.assert_called_once()
        self.assertEqual(observed['status'],'OWNER_MANAGED_CONTROLS_OBSERVED')
        self.assertEqual(observed['administrator_rollback_prevention'],'NOT_GUARANTEED')
        self.assertNotEqual(observed['independent_governance'],'VERIFIED')
        self.assertEqual(observed['authorization'],'NOT_GRANTED')
        self.assertTrue(all(method=='GET' for method,_,_ in fixture.server.http))
        with patch.object(gate,'verify',side_effect=ValueError('SYNTHETIC_GATE_DENIED')):
            with self.assertRaisesRegex(ValueError,'GATE_DENIED'):
                governance.observe(self.root,self.config,fixture.transport())

    def test_missing_ruleset_b_rejected_even_with_valid_gate_fixture(self):
        fixture=transport_fixtures.GitHubTransportTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.governance();fixture.server.rules.pop(2)
        self.policy['writer_integration_id']=3;self.config['transaction_backend']['writer_integration_id']=3;self.save()
        with patch.object(gate,'APP_ID',3),patch.object(gate,'verify'),patch.object(gate,'verify_token'):
            with self.assertRaises((ValueError,KeyError)):
                governance.observe(self.root,self.config,fixture.transport())
        self.assertFalse(any(method!='GET' for method,_,_ in fixture.server.http))

    def test_owner_identity_is_not_an_approving_boolean(self):
        self.policy['owner_id']=1;self.save()
        with patch.object(gate,'verify'),patch.object(gate,'verify_token'):
            with self.assertRaisesRegex(ValueError,'WRITER_IDENTITY_MISMATCH'):
                governance.observe(self.root,self.config,None)

    def test_new_policy_digest_is_bound_by_existing_audit_subject_validation(self):
        proposal,decision,_=self.fixture.f.proposal_and_decision()
        pin=self.config['governance']['policy_sha256']
        subject=digest(hosted.subject(proposal['request'],digest(proposal),decision['workflow_id'],
            governance_policy_sha256=pin))
        binding=audit._binding(proposal,decision,expected_proposal_sha256=digest(proposal),
            expected_subject_sha256=subject,expected_actor_id=101,expected_run_id=102,
            governance_policy_sha256=pin)
        self.assertEqual(binding['subject_sha256'],subject)
        with self.assertRaisesRegex(ValueError,'AUDIT_SUBJECT_MISMATCH'):
            audit._binding(proposal,decision,expected_proposal_sha256=digest(proposal),
                expected_subject_sha256=subject,expected_actor_id=101,expected_run_id=102,
                governance_policy_sha256='0'*64)


if __name__=='__main__':unittest.main()
