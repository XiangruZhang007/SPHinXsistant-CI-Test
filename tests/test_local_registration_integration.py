"""L2-B2b entirely offline: actual writer/recovery, synthetic API and science.

No synthetic approval represents genuine Hosted authorization. Network entry
points are intercepted by the reused L2-B2a fixture throughout every test.
"""
import base64
from copy import deepcopy
import json
import io
import os
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
import zipfile
from unittest.mock import patch

import test_local_candidate_verification as fixtures
from scripts import register_trusted_baseline as cli
from src import local_registration_subject as subject, baseline_registration_transaction as tx
from src import owner_manual_baseline_approval as owner, hosted_registration as hosted
from src.corpus_snapshot import canonical, digest, file_digest


class Crash(BaseException):
    pass


class LocalRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.r=fixtures.RemoteLocalEvidenceTests();self.r.setUp();self.addCleanup(self.r.doCleanups)
        r=self.r;f=r.f;self.project=r.project
        self.configs=self.project/'configs';self.configs.mkdir()
        self.registry=self.configs/'ci_v2_schema2_trusted_baselines.json'
        self.old=canonical(dict(schema_version=2,baselines={},preserved='top-level metadata'))
        self.registry.write_bytes(self.old)
        self.isolation=r.t.root/'isolated';self.isolation.mkdir();self.copy=self.isolation/'registry.json';self.copy.write_bytes(self.old)
        self.policy=dict(schema_version=1,enabled=True,repository=r.repository,repository_id=r.repository_id,
            default_branch='main',workflow_path='.github/workflows/approve.yml',
            registry_path='configs/ci_v2_schema2_trusted_baselines.json',allow_repository_owner=True,authorized_approver_ids=[])
        self.policy_path=self.configs/'owner.json';self.policy_path.write_bytes(canonical(self.policy))
        f.parity.update(full_reference_independently_built=True,comparisons={n:dict(sha256='a'*64,exact_bytes_equal=True)
                        for n in subject.transport.l1.provenance.PARITY_FILES})
        f.write(f.run,'parity.json',f.parity);f.write(f.run,'result.json',f.result);f.reseal()
        f.path.write_bytes(canonical(f.d));r.t.kwargs['expected_descriptor_sha256']=file_digest(f.path)
        prepared=r.t.prepare(r.t.root/'subject-ready');raw=Path(prepared['archive']).read_bytes()
        r.data[21]=raw;r.stores[21]['asset_size']=len(raw)
        t=r.local['transport'];t.update(storage=r.stores[21],archive_size=len(raw),
            archive_sha256=prepared['expected_archive_sha256'],descriptor_sha256=prepared['expected_descriptor_sha256'],
            manifest_sha256=prepared['expected_manifest_sha256'])
        r.local.update(descriptor_sha256=t['descriptor_sha256'],archive_sha256=t['archive_sha256'],transport_sha256=digest(t))
        anchor={k:'d'*64 for k in tx.evidence.ANCHOR_FIELDS}
        anchor.update(baseline_id=f.d['baseline_id'],candidate_id=f.d['candidate_id'],
            parent_corpus_sha256=f.d['corpus_sha256'],upstreams=f.d['upstreams'],source_state=f.d['source_state'],
            build_fingerprint=f.d['build_fingerprint'],benchmark_sha256=f.d['benchmark_sha256'],
            parent_rows_sha256=f.d['candidate_rows_sha256'],R2_fingerprint=f.quality['policy']['R2_fingerprint'])
        f.anchor_receipt['bindings']=anchor
        self.entry=dict(entry_kind='REGISTRATION_ONLY',reference=r.ref,expected_reference_sha256=digest(r.ref))
        self.request=dict(schema_version=3,registry_key='synthetic-local-parent',proposed_entry=self.entry,
            expected_reference_sha256=digest(r.ref),expected_registry_sha256=file_digest(self.registry),
            approval_policy_path='configs/owner.json',approval_policy_sha256=file_digest(self.policy_path),local_evidence=r.local)
        self.path=self.configs/'request.json';self.path.write_bytes(canonical(self.request));self.pin=file_digest(self.path)
        self.report=dict(P4_1_verification='P4_1_VERIFIED',candidate_id=f.d['candidate_id'],baseline_id=f.d['baseline_id'],
            generation=f.d['generation'],quality_status='QUALITY_REVIEW_REQUIRED',q1_status='Q1_NOT_QUALIFIED_FOR_VERSION_PAIR',
            bindings=dict(corpus_sha256=f.d['corpus_sha256'],upstreams=f.d['upstreams']),
            blocking_reasons=['INDEPENDENT_REGISTRATION_AUTHORITY_NOT_CONFIGURED'])
        for p in (patch.object(cli,'PROJECT',self.project),
                  patch.object(subject.registration,'prepare',return_value=self.report)):
            p.start();self.addCleanup(p.stop)
        self.seed=subject.prepare(self.project,self.registry,self.path,self.pin,token=r.token)
        self.addCleanup(shutil.rmtree,self.seed['retained_directory'],True)
        self.s=self.seed['registration_subject']
        self.context=dict(repository=r.repository,repository_id=r.repository_id,run_id=9001,run_attempt=1,
            actor_id=2,head_sha='c'*40,ref='refs/heads/main',registration_subject_version=2,
            dispatch_inputs=dict(registry_key=self.request['registry_key'],baseline_id=f.d['baseline_id'],
                candidate_id=f.d['candidate_id'],corpus_sha256=f.d['corpus_sha256'],registry_entry_sha256=digest(self.entry),
                registration_subject_sha256=digest(self.s)))
        self.run=dict(id=9001,event='workflow_dispatch',status='in_progress',run_attempt=1,head_branch='main',
            head_sha='c'*40,repository=dict(id=r.repository_id,full_name=r.repository),
            actor=dict(id=2,type='User',login='synthetic-owner'),triggering_actor=dict(id=2,type='User',login='synthetic-owner'),
            workflow_id=88,created_at='2026-11-19T10:00:00Z')
        self.workflow=dict(id=88,path=self.policy['workflow_path']);self.api_calls=[]
        self.api_repo=dict(id=r.repository_id,full_name=r.repository,private=True,default_branch='main',
            owner=dict(id=2,type='User',login='synthetic-owner'))
        test=self
        class Client:
            def json(self,endpoint):return test.api(endpoint)
        self.client=Client()
        for p in (patch.object(tx,'_trusted_dispatch_context',return_value=self.context),
                  patch.object(owner,'GitHubCLI',return_value=self.client)):
            p.start();self.addCleanup(p.stop)
        self.real_registry=tx.PROJECT/'configs/ci_v2_schema2_trusted_baselines.json'
        self.real_hash=file_digest(self.real_registry)

    def tearDown(self):
        self.assertEqual(self.registry.read_bytes(),self.old)
        self.assertEqual(file_digest(self.real_registry),self.real_hash)

    def api(self,endpoint):
        self.api_calls.append(endpoint);base='repos/'+self.r.repository
        if endpoint==base:return self.api_repo
        if endpoint==base+'/actions/runs/9001':return self.run
        if endpoint==base+'/actions/workflows/88':return self.workflow
        if endpoint==base+'/git/ref/heads/main':return dict(ref='refs/heads/main',object=dict(sha='c'*40))
        if endpoint==base+'/contents/'+self.policy['registry_path']+'?ref='+'c'*40:
            return dict(path=self.policy['registry_path'],type='file',encoding='base64',content=base64.b64encode(self.old).decode())
        raise AssertionError('Unexpected mock endpoint')

    def register(self):
        return tx.register_local(self.project,self.isolation,request_path=self.path,expected_request_sha256=self.pin,token=self.r.token)

    def approval(self,s=None):
        return owner.verify(self.project,Path(self.seed['retained_directory'])/'baseline',self.registry,
            self.request['registry_key'],self.entry,policy_path=self.policy_path,policy_sha256=file_digest(self.policy_path),
            expected_reference_sha256=digest(self.r.ref),q1_status=self.report['q1_status'],context=self.context,
            client=self.client,registration_subject=self.s if s is None else s)

    def recover(self,tid):return tx.recover(self.project,self.isolation,transaction_id=tid)

    def test_deterministic_closed_subject_and_actual_reconstruction(self):
        again=subject.prepare(self.project,self.registry,self.path,self.pin,token=self.r.token)
        self.addCleanup(shutil.rmtree,again['retained_directory'],True)
        self.assertEqual(self.s,again['registration_subject'])
        self.assertEqual(digest(self.s),again['registration_subject_sha256'])
        self.assertEqual(self.s['candidate']['upstreams'],self.r.f.d['upstreams'])
        self.assertEqual(self.s['candidate']['orchestration_fingerprint'],self.r.f.d['orchestration_fingerprint'])
        for key in subject.FIELDS:
            s=deepcopy(self.s);del s[key]
            with self.subTest(field=key),self.assertRaises(ValueError):subject.validate(s)
        for schema in (1,3,True):
            s=deepcopy(self.s);s['schema_version']=schema
            with self.assertRaises(ValueError):subject.validate(s)
        s=deepcopy(self.s);s['approved']=True
        with self.assertRaises(ValueError):subject.validate(s)

    def test_nested_scientific_transport_and_identity_mutations_fail(self):
        for group,key,value in [('candidate','candidate_id','sha256-'+'0'*64),
                ('candidate','parent_id','sha256-'+'0'*64),('candidate','generation',True),
                ('candidate','corpus_sha256','0'*64),('candidate','build_fingerprint','0'*64),
                ('candidate','upstreams',{'SPHinXsys':'a'*40,'SPHinXsim':'b'*40}),
                ('candidate','orchestration_fingerprint','0'*64),('baseline','baseline_id','sha256-'+'0'*64),
                ('scientific','P8','APPROVED'),('scientific','baseline_anchor_status','NOT_QUALIFIED'),
                ('scientific','approval_manifest_sha256','0'*64)]:
            s=deepcopy(self.s);s[group][key]=value
            with self.subTest(group=group,key=key),self.assertRaises(ValueError):subject.validate(s)
        for group in ('candidate','baseline','scientific','trust_domain','local_evidence'):
            s=deepcopy(self.s);s[group]['unknown']=True
            with self.assertRaises(ValueError):subject.validate(s)

    def test_valid_synthetic_owner_and_cross_version_or_wrong_digest_rejected(self):
        self.assertEqual(self.approval()['status'],'OWNER_APPROVAL_VERIFIED')
        self.context.pop('registration_subject_version')
        self.assertEqual(self.approval()['status'],'BLOCKED')
        self.context['registration_subject_version']=2
        self.context['dispatch_inputs']['registration_subject_sha256']='0'*64
        self.assertEqual(self.approval()['status'],'BLOCKED')
        s=deepcopy(self.s);s['schema_version']=1
        self.assertEqual(self.approval(s)['status'],'BLOCKED')

    def test_actor_run_attempt_workflow_branch_and_private_domain_rejected(self):
        original=deepcopy(self.run)
        for field,value in [('actor',dict(id=99,type='User')),('run_attempt',2),
                            ('event','push'),('head_sha','d'*40),('status','completed')]:
            self.run=deepcopy(original);self.run[field]=value
            self.assertEqual(self.approval()['status'],'BLOCKED')
        self.run=original;self.workflow['path']='.github/workflows/other.yml'
        self.assertEqual(self.approval()['status'],'BLOCKED')
        self.workflow['path']=self.policy['workflow_path'];self.api_repo['private']=False
        self.assertEqual(self.approval()['status'],'BLOCKED')

    def test_rebound_publication_or_policy_cannot_reuse_previous_dispatch(self):
        for key in ('publication_commit','archive_sha256','descriptor_sha256'):
            s=deepcopy(self.s);local=s['local_evidence'];t=local['transport']
            t[key]='d'*40 if key=='publication_commit' else 'd'*64
            if key in local:local[key]=t[key]
            local['transport_sha256']=digest(t)
            self.assertEqual(self.approval(s)['status'],'BLOCKED')
        s=deepcopy(self.s);s['approval_policy_sha256']='0'*64
        self.assertEqual(self.approval(s)['status'],'BLOCKED')
        self.policy_path.write_bytes(self.policy_path.read_bytes()+b' ')
        result=self.register();self.assertEqual(result['status'],'BLOCKED')
        self.assertEqual(self.copy.read_bytes(),self.old)

    def test_simulated_local_registration_uses_single_writer_and_retains_small_audit(self):
        before=self.copy.read_bytes();result=self.register()
        self.assertEqual(result['status'],'COMPLETED',result)
        after=json.loads(self.copy.read_bytes());self.assertEqual(after['preserved'],'top-level metadata')
        self.assertEqual(after['baselines'],{self.request['registry_key']:self.entry})
        tid=result['transaction_id'];record=json.loads((self.isolation/(tid+'.prepared.json')).read_bytes())
        self.assertEqual(record['schema_version'],2);self.assertEqual(record['registration_subject'],self.s)
        self.assertEqual(record['request_sha256'],self.pin)
        self.assertEqual(record['old_registry_sha256'],tx._sha(before))
        self.assertTrue(any(self.isolation.glob('*.notices.zip')))
        self.assertTrue(any(self.isolation.glob('*.evidence.json')))
        self.assertFalse(any(self.isolation.glob('*.tar.gz')))
        self.assertEqual(self.recover(tid)['status'],'COMPLETED')
        self.assertEqual(self.register()['status'],'BLOCKED')

    def test_ordinary_cli_and_public_boundary_cannot_be_enabled_by_environment(self):
        def blocked():raise tx.TransactionError('TRUSTED_WORKFLOW_EXECUTION_NOT_ESTABLISHED')
        with patch.object(tx,'_trusted_dispatch_context',side_effect=blocked), \
                patch.object(subject,'prepare') as prepare:
            result=self.register()
        self.assertEqual(result['reason'],'TRUSTED_WORKFLOW_EXECUTION_NOT_ESTABLISHED');prepare.assert_not_called()
        self.assertEqual(self.copy.read_bytes(),self.old)

    def test_changed_remote_evidence_at_second_verification_prevents_commit(self):
        original=subject.prepare;count=0
        def altered(*args,**kwargs):
            nonlocal count
            count+=1
            if count==2:self.r.changes['bytes-21']=b'corrupt changed remote fixture'
            return original(*args,**kwargs)
        with patch.object(subject,'prepare',side_effect=altered):result=self.register()
        self.assertEqual(result['status'],'BLOCKED');self.assertFalse(result['registry_committed'])
        self.assertEqual(self.copy.read_bytes(),self.old);self.assertEqual(count,2)

    def test_recovery_committed_audit_only_without_remote_or_owner(self):
        with patch.object(tx,'_complete',side_effect=OSError('Injected completion failure')):result=self.register()
        self.assertEqual(result['status'],'COMMITTED_WITH_ERROR',result)
        before=self.copy.read_bytes();tid=result['transaction_id']
        with patch.object(owner,'verify',side_effect=AssertionError('No renewed approval')), \
             patch.object(self.r.client if hasattr(self.r,'client') else self.client,'json',side_effect=AssertionError('No API')), \
             patch.object(subject.remote,'verify',side_effect=AssertionError('No redownload')):
            self.assertEqual(self.recover(tid)['status'],'COMPLETED')
            self.assertEqual(self.recover(tid)['status'],'COMPLETED')
        self.assertEqual(self.copy.read_bytes(),before)

    def test_recovery_old_bytes_and_conflict_never_rewrite_registry(self):
        original=tx._stage
        def crash(fd,raw,prefix):
            if prefix=='registry':raise Crash()
            return original(fd,raw,prefix)
        with patch.object(tx,'_stage',side_effect=crash),self.assertRaises(Crash):self.register()
        tid=next(self.isolation.glob('*.prepared.json')).name[:64]
        self.assertEqual(self.recover(tid)['status'],'NOT_COMMITTED');self.assertEqual(self.copy.read_bytes(),self.old)
        self.copy.write_bytes(b'unexpected concurrent bytes')
        self.assertEqual(self.recover(tid)['status'],'CONFLICT');self.assertEqual(self.copy.read_bytes(),b'unexpected concurrent bytes')

    def test_missing_or_corrupt_durable_notice_evidence_and_unknown_journal_fail(self):
        result=self.register();tid=result['transaction_id']
        notice=next(self.isolation.glob('*.notices.zip'));raw=notice.read_bytes();notice.write_bytes(b'bad')
        damaged=self.recover(tid)
        self.assertEqual(damaged['status'],'COMMITTED_WITH_ERROR');self.assertTrue(damaged['registry_committed'])
        notice.write_bytes(raw)
        path=self.isolation/(tid+'.prepared.json');record=json.loads(path.read_bytes())
        record['schema_version']=99;path.write_bytes(canonical(record))
        self.assertEqual(self.recover(tid)['status'],'BLOCKED')

    def test_independently_pinned_mixed_or_unknown_journal_versions_rejected(self):
        result=self.register();tid=result['transaction_id']
        original=json.loads((self.isolation/(tid+'.prepared.json')).read_bytes());original.pop('transaction_id')
        for schema,subject_schema in ((99,2),(1,2),(2,1),(True,2)):
            record=deepcopy(original);record['schema_version']=schema
            record['registration_subject']['schema_version']=subject_schema
            pin=digest(record);(self.isolation/(pin+'.prepared.json')).write_bytes(canonical(dict(record,transaction_id=pin)))
            recovered=self.recover(pin)
            self.assertEqual(recovered['status'],'BLOCKED')
            self.assertEqual(recovered['reason'],'UNSUPPORTED_AUDIT_VERSION')

    def test_wrong_registry_before_pin_cannot_commit(self):
        self.copy.write_bytes(canonical(dict(schema_version=2,baselines={},changed=True)))
        before=self.copy.read_bytes();result=self.register()
        self.assertEqual(result['reason'],'STALE_OR_UNBOUND_REGISTRY')
        self.assertEqual(self.copy.read_bytes(),before)

    def test_duplicate_check_routes_v3_through_notices_delivery(self):
        entry=deepcopy(self.entry);ref=entry['reference']
        ref['node_id']='sha256-'+'f'*64;ref['notices']['baseline_id']=ref['node_id']
        ref['candidate_id']='sha256-'+'e'*64;ref['corpus_sha256']='e'*64
        entry['expected_reference_sha256']=digest(ref)
        work=self.r.t.root/'duplicate-routing';work.mkdir()
        def restored(project,reference,pin,root,**kwargs):
            self.assertEqual(kwargs['stem'],'old-0');p=root/'old-0';p.mkdir()
            (p/'upstream-candidate.json').write_bytes(canonical(dict(candidate_id='sha256-'+'e'*64)))
            return p
        with patch.object(tx.local_remote,'restore_delivery',side_effect=restored) as delivery:
            tx._duplicate_check(self.project,dict(baselines={'old':entry}),self.s,work,self.r.token)
        delivery.assert_called_once()

    def test_historical_v3_notices_survive_transaction_and_offline_recovery(self):
        oldref=deepcopy(self.r.ref);oldref.update(node_id='sha256-'+'e'*64,
            candidate_id='sha256-'+'f'*64,corpus_sha256='e'*64)
        package=io.BytesIO()
        with fixtures.tarfile.open(fileobj=package,mode='w:gz') as t:
            raw=canonical(dict(candidate_id=oldref['candidate_id']));m=fixtures.tarfile.TarInfo('upstream-candidate.json')
            m.size=len(raw);t.addfile(m,io.BytesIO(raw))
        def asset(aid,name,raw):
            s=dict(self.r.ref['storage'],release_id=30,tag='synthetic-release-30',asset_id=aid,
                asset_name=name,asset_size=len(raw))
            self.r.stores[aid]=s;self.r.data[aid]=raw;return s
        oldref['storage']=asset(31,'old.tar.gz',package.getvalue())
        oldref['transport_sha256']=tx._sha(package.getvalue())
        oldref['parent_rows_storage']=asset(32,'old-r2.json',self.r.data[12])
        files={}
        with zipfile.ZipFile(io.BytesIO(self.r.data[13])) as z:
            for n in z.namelist():
                if n!='SHA256SUMS':files[n]=z.read(n)
        files['source-and-license-mapping.json']=canonical(dict(baseline_id=oldref['node_id'],transport_sha256=oldref['transport_sha256']))
        files['SHA256SUMS']=''.join(tx._sha(b)+'  '+n+'\n' for n,b in files.items()).encode()
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as z:
            for n,b in files.items():z.writestr(n,b)
        oldref['notices']=dict(schema_version=1,baseline_id=oldref['node_id'],parent_transport_sha256=oldref['transport_sha256'],
            sha256=tx._sha(out.getvalue()),storage=asset(33,'old-notices.zip',out.getvalue()))
        history=dict(entry_kind='REGISTRATION_ONLY',reference=oldref,expected_reference_sha256=digest(oldref))
        self.old=canonical(dict(schema_version=2,baselines={'old':history},preserved='top-level metadata'))
        self.registry.write_bytes(self.old);self.copy.write_bytes(self.old)
        self.request['expected_registry_sha256']=tx._sha(self.old)
        self.path.write_bytes(canonical(self.request));self.pin=file_digest(self.path)
        seed=subject.prepare(self.project,self.registry,self.path,self.pin,token=self.r.token)
        self.addCleanup(shutil.rmtree,seed['retained_directory'],True)
        self.context['dispatch_inputs']['registration_subject_sha256']=seed['registration_subject_sha256']
        result=self.register();self.assertEqual(result['status'],'COMPLETED',result)
        self.assertEqual(len(list(self.isolation.glob('*.notices.zip'))),2)
        with patch.object(subject.remote.trusted,'_request',side_effect=AssertionError('No remote recovery')):
            self.assertEqual(self.recover(result['transaction_id'])['status'],'COMPLETED')

    def test_concurrent_local_registration_keeps_stable_lock(self):
        entered=threading.Event();release=threading.Event();original=subject.prepare;results=[]
        def wait(*a,**kw):
            entered.set();self.assertTrue(release.wait(10));return original(*a,**kw)
        with patch.object(subject,'prepare',side_effect=wait):
            worker=threading.Thread(target=lambda:results.append(self.register()));worker.start()
            self.assertTrue(entered.wait(10));second=self.register();release.set();worker.join(10)
        self.assertFalse(worker.is_alive());self.assertEqual(second['reason'],'TRANSACTION_BUSY')
        self.assertEqual(results[0]['status'],'COMPLETED',results)

    def test_duplicate_v3_path_requires_three_asset_notices_restore(self):
        work=self.r.t.root/'duplicate-work';work.mkdir()
        historical=deepcopy(self.entry)
        # Test the shared real v3 delivery primitive, including restore boundary.
        with patch.object(tx.transport,'restore',wraps=tx.transport.restore) as restore:
            tx.local_remote.restore_delivery(self.project,historical['reference'],historical['expected_reference_sha256'],
                                              work,token=self.r.token,stem='old-0')
        self.assertEqual(restore.call_args.kwargs['notices_path'],work/'old-0-notices.zip')
        self.assertTrue((work/'old-0-notices-verification.json').is_file())
        self.r.changes['bytes-13']=b'corrupt notices'
        with patch.object(tx.transport,'restore') as restore,self.assertRaises(Exception):
            tx.local_remote.restore_delivery(self.project,historical['reference'],historical['expected_reference_sha256'],
                                              work,token=self.r.token,stem='old-1')
        restore.assert_not_called()


class LocalHostedTests(unittest.TestCase):
    def setUp(self):
        self.f=LocalRegistrationTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.addCleanup(self.f.tearDown)
        f=self.f
        self.deployment=dict(schema_version=2,registration_subject_version=2,repository=f.r.repository,
            repository_id=f.r.repository_id,default_branch='main',workflow_path=f.policy['workflow_path'],
            implementation_revision='c'*40,request_path='configs/request.json',request_sha256=f.pin,
            approval_policy_path='configs/owner.json',approval_policy_sha256=file_digest(f.policy_path))
        self.event=f.r.t.root/'event.json';self.event.write_bytes(canonical(dict(inputs=f.context['dispatch_inputs'])))
        self.runner=f.r.t.root/'runner';self.runner.mkdir()
        self.env=dict(GITHUB_ACTIONS='true',RUNNER_ENVIRONMENT='github-hosted',GITHUB_REPOSITORY=f.r.repository,
            GITHUB_REPOSITORY_ID=str(f.r.repository_id),GITHUB_SHA='c'*40,GITHUB_WORKFLOW_SHA='c'*40,
            GITHUB_WORKFLOW_REF=f.r.repository+'/'+f.policy['workflow_path']+'@refs/heads/main',
            GITHUB_REF='refs/heads/main',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_EVENT_PATH=str(self.event),
            GITHUB_RUN_ID='9001',GITHUB_RUN_ATTEMPT='1',GITHUB_ACTOR_ID='2',GITHUB_WORKSPACE=str(f.project),
            RUNNER_TEMP=str(self.runner),TRUSTED_RELEASE_TOKEN=f.r.token)
        for p in (patch.object(hosted,'PROJECT',f.project),patch.object(hosted,'_checkout'),
                  patch.object(hosted,'frozen_runtime'),patch.dict(os.environ,self.env)):
            p.start();self.addCleanup(p.stop)

    def invoke(self,d=None):
        raw=canonical(self.deployment if d is None else d).decode()
        with patch.dict(os.environ,OWNER_REGISTRATION_DEPLOYMENT_JSON=raw,
                         OWNER_REGISTRATION_DEPLOYMENT_SHA256=tx._sha(raw.encode())):
            return hosted.run()

    def test_version2_hosted_composition_with_mocked_runtime_and_api(self):
        result=self.invoke();self.assertEqual(result['status'],'COMPLETED',result)
        self.assertTrue(result['authoritative_registry_unchanged'])
        audit=json.loads(next((Path(result['output_directory'])/'isolated').glob('*.prepared.json')).read_bytes())
        self.assertEqual(audit['schema_version'],2)
        self.assertEqual(audit['owner_approval']['schema_version'],2)
        self.assertEqual(audit['registration_subject']['local_evidence']['hosted_validation'],'HOSTED_NOT_RUN')

    def test_legacy_deployment_does_not_adopt_schema3(self):
        d=deepcopy(self.deployment);d['schema_version']=1;d.pop('registration_subject_version')
        result=self.invoke(d)
        self.assertEqual(result['status'],'BLOCKED')
        self.assertEqual(result['reason'],'LOCAL_EVIDENCE_TRANSPORT_CONTRACT_NOT_FINALIZED')

    def test_unknown_or_mixed_deployment_version_rejected(self):
        for version in (1,3,True):
            d=deepcopy(self.deployment);d['schema_version']=version
            # New owned runner directory per attempted invocation.
            root=self.f.r.t.root/('runner-'+str(version));root.mkdir()
            with patch.dict(os.environ,RUNNER_TEMP=str(root)):
                self.assertEqual(self.invoke(d)['status'],'BLOCKED')

    def test_wrong_dispatch_digest_blocks_before_registry_commit(self):
        inputs=deepcopy(self.f.context['dispatch_inputs']);inputs['registration_subject_sha256']='0'*64
        self.event.write_bytes(canonical(dict(inputs=inputs)))
        result=self.invoke();self.assertEqual(result['status'],'BLOCKED',result)
        self.assertFalse(result['registry_committed'])



if __name__=='__main__':unittest.main()
