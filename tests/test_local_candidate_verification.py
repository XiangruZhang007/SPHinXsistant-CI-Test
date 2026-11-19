"""Offline L2-B2a: mocked GitHub, real transport/ZIP/restore/L1 composition.

Scientific validators use the existing synthetic L1 fixture. No real HTTP,
retrieval experiment, approval, transaction or Registry write is permitted.
"""
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import unittest
from unittest.mock import patch
import zipfile

import test_local_candidate_transport as fixtures
import test_local_registration_request as requests
from scripts import register_trusted_baseline as cli
from src import local_candidate_verification as v
from src.corpus_snapshot import canonical, digest, file_digest

REAL_VALIDATE = v.trusted.validate_reference


class RemoteLocalEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.t = fixtures.LocalTransportTests(); self.t.setUp()
        self.addCleanup(self.t.doCleanups)
        self.f = self.t.f
        self.project = self.t.root / 'project'; self.project.mkdir()
        self.registry = self.project / 'registry.json'; self.registry.write_bytes(b'unchanged')
        self.repository = 'SyntheticOwner/LocalEvidence'; self.repository_id = 777
        self.token = 'synthetic-secret-do-not-print'
        env = patch.dict(os.environ, GITHUB_REPOSITORY=self.repository,
                         GITHUB_REPOSITORY_ID=str(self.repository_id))
        env.start(); self.addCleanup(env.stop)
        self.data = {}; self.stores = {}; self.calls = []; self.changes = {}
        def add(asset, release, name, raw):
            self.data[asset] = raw
            s = dict(kind='GITHUB_PRIVATE_RELEASE_ASSET', repository=self.repository,
                repository_id=self.repository_id, release_id=release, asset_id=asset,
                tag='synthetic-release-' + str(release), asset_name=name,
                asset_size=len(raw), immutable_required=True)
            self.stores[asset] = s
            return s
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as tar:
            for path in sorted(self.f.baseline.rglob('*')):
                if path.is_file(): tar.add(path, arcname=path.relative_to(self.f.baseline).as_posix())
        baseline = buffer.getvalue()
        rows = (self.f.run / 'quality/incremental-raw-results.json').read_bytes()
        d = self.f.d
        self.ref = dict(schema_version=3, package_format='schema2-research-baseline',
            accepted_package_schema=2, node_id=d['baseline_id'], candidate_id=d['candidate_id'],
            package_checksum='1'*64, manifest_sha256=d['baseline_manifest_sha256'],
            transport_sha256=v.transport._hash(baseline), source_state=d['source_state'],
            upstreams=d['upstreams'], build_fingerprint=d['build_fingerprint'],
            corpus_sha256=d['corpus_sha256'], authorization=dict(type='EXPLICIT_RESEARCH_BASELINE_REUSE',
                scope='ISOLATED_RESEARCH_PARENT_REUSE', research_only=True,
                experiment_id='SYNTHETIC_OFFLINE_ONLY', automatic_research_approval=False,
                production_promotion='NOT_AUTHORIZED'), storage=add(11, 10, 'baseline.tar.gz', baseline),
            parent_rows_storage=add(12, 10, 'parent-r2.json', rows), parent_rows_sha256=v.transport._hash(rows))
        self.set_notices()
        d['reference_sha256'] = digest(self.ref)
        self.f.refpath.write_bytes(canonical(self.ref)); self.f.path.write_bytes(canonical(d))
        self.t.descriptor_pin = file_digest(self.f.path)
        self.t.kwargs['expected_descriptor_sha256'] = self.t.descriptor_pin
        result = self.t.prepare(self.t.root / 'final-prepared')
        raw = Path(result['archive']).read_bytes()
        t = dict(schema_version=1, kind='LOCAL_RESEARCH_EVIDENCE_TRANSPORT',
            evidence_origin='LOCAL_RESEARCH_EXECUTION', hosted_validation='HOSTED_NOT_RUN',
            **{k:d[k] for k in ('candidate_id','baseline_id','parent_id','corpus_sha256','reference_sha256')},
            descriptor_sha256=self.t.descriptor_pin, manifest_sha256=result['expected_manifest_sha256'],
            archive_sha256=result['expected_archive_sha256'], archive_size=len(raw),
            publication_commit='c'*40, storage=add(21, 20, 'local-evidence.tar.gz', raw))
        self.local = {k:t[k] for k in ('evidence_origin','hosted_validation','candidate_id',
            'baseline_id','corpus_sha256','descriptor_sha256','archive_sha256')}
        self.local.update(transport=t, transport_sha256=digest(t))
        # The L1 fixture mocks science only; exercise real reference validation.
        p = patch.object(v.trusted, 'validate_reference', side_effect=REAL_VALIDATE)
        p.start(); self.addCleanup(p.stop)
        self.no_http = patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('No network'))
        self.no_http.start(); self.addCleanup(self.no_http.stop)
        self.api = patch.object(v.trusted, '_request', side_effect=self.request)
        self.api.start(); self.addCleanup(self.api.stop)

    def set_notices(self, wrong=False):
        files={'README.txt':b'Synthetic notices only','DELIVERY.md':b'Together',
            'licenses/fixture.txt':b'Synthetic legal test data',
            'source-and-license-mapping.json':canonical(dict(
                baseline_id='sha256-'+'0'*64 if wrong else self.ref['node_id'],
                transport_sha256=self.ref['transport_sha256']))}
        files['SHA256SUMS']=''.join(hashlib.sha256(b).hexdigest()+'  '+n+'\n' for n,b in files.items()).encode()
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as z:
            for n,b in files.items():z.writestr(n,b)
        raw=out.getvalue();self.data[13]=raw
        s=dict(self.ref['storage'],asset_id=13,asset_name='notices.zip',asset_size=len(raw))
        self.stores[13]=s
        self.ref['notices']=dict(schema_version=1,baseline_id=self.ref['node_id'],
            parent_transport_sha256=self.ref['transport_sha256'],sha256=v.transport._hash(raw),storage=s)

    def request(self, url, *, binary=False, token=None):
        self.assertEqual(token,self.token);self.calls.append((url,binary))
        if '/releases/assets/' in url:
            aid=int(url.rsplit('/',1)[1]);s=self.stores[aid]
            if binary:return io.BytesIO(self.changes.get('bytes-'+str(aid),self.data[aid]))
            result=dict(id=aid,name=s['asset_name'],size=len(self.data[aid]),state='uploaded',
                        digest='sha256:'+v.transport._hash(self.data[aid]))
            result.update(self.changes.get('asset-'+str(aid),{}))
        elif '/releases/' in url:
            rid=int(url.rsplit('/',1)[1]);stores=[s for s in self.stores.values() if s['release_id']==rid]
            result=dict(id=rid,tag_name='synthetic-release-'+str(rid),immutable=True,draft=False,
                assets=[dict(id=s['asset_id'],name=s['asset_name'],size=s['asset_size'],state='uploaded') for s in stores])
            result.update(self.changes.get('release-'+str(rid),{}))
        elif '/git/ref/tags/' in url:
            result=dict(ref='refs/tags/synthetic-release-20',object=dict(type='commit',sha='c'*40))
            result.update(self.changes.get('tag',{}))
        else:
            self.assertEqual(url,'https://api.github.com/repos/'+self.repository)
            result=dict(id=self.repository_id,full_name=self.repository,private=True)
            result.update(self.changes.get('repository',{}))
        return io.BytesIO(canonical(result))

    def verify(self):
        return v.verify(self.project,self.local,self.ref,digest(self.ref),
            expected_repository=self.repository,expected_repository_id=self.repository_id,token=self.token)

    def test_full_offline_integration_retains_notices_without_authority(self):
        with patch.object(v.trusted,'restore',wraps=v.trusted.restore) as restore:
            result=self.verify()
        root=Path(result['retained_directory']);self.addCleanup(shutil.rmtree,root)
        self.assertEqual(root.parent,Path('/tmp'))
        self.assertEqual(root.stat().st_mode & 0o777,0o700)
        self.assertEqual(result['status'],'LOCAL_REMOTE_EVIDENCE_VERIFIED')
        self.assertEqual(result['replay'],'NO_FRESH_REPLAY')
        self.assertEqual(result['hosted_validation'],'HOSTED_NOT_RUN')
        self.assertEqual(result['owner_authorization'],'NOT_GRANTED')
        self.assertNotIn('registration_subject_sha256',result)
        self.assertEqual(restore.call_args.kwargs['notices_path'],root/'notices.zip')
        self.assertEqual((root/'notices.zip').read_bytes(),self.data[13])
        self.assertEqual(json.loads((root/'notices-verification.json').read_bytes())['status'],'NOTICES_VERIFIED')
        self.assertEqual(self.registry.read_bytes(),b'unchanged')
        self.assertFalse(self.f.mocks['verify_bundle'].call_args.kwargs['fresh_replay'])
        self.assertTrue(all(not c.kwargs.get('fresh_replay', True) for c in self.f.mocks['qualify_parent_anchor'].call_args_list))

    def test_each_independent_transport_pin_or_identity_rejected(self):
        original=deepcopy(self.local)
        for key in ('candidate_id','baseline_id','corpus_sha256','archive_sha256','descriptor_sha256'):
            self.local=deepcopy(original);self.local['transport'][key]='sha256-'+'0'*64 if key.endswith('_id') else '0'*64
            self.local['transport_sha256']=digest(self.local['transport'])
            with self.subTest(key=key),self.assertRaises(v.VerificationError):self.verify()
        self.assertFalse(self.calls)

    def test_foreign_domain_even_with_matching_runtime_environment_rejected(self):
        with self.assertRaises(v.VerificationError):
            v.verify(self.project,self.local,self.ref,digest(self.ref),
                expected_repository='OtherOwner/OtherRepo',expected_repository_id=self.repository_id,token=self.token)
        self.assertFalse(self.calls)

    def test_missing_token_fails_without_remote_requests(self):
        with self.assertRaises(v.VerificationError):
            v.verify(self.project,self.local,self.ref,digest(self.ref),
                expected_repository=self.repository,expected_repository_id=self.repository_id)
        self.assertFalse(self.calls)

    def test_unsafe_helper_temp_root_rejected_before_writes_or_network(self):
        with patch.object(v.tempfile,'gettempdir',return_value=str(self.f.run)), \
             patch.object(v.tempfile,'mkdtemp') as mkdir, self.assertRaisesRegex(
                 v.VerificationError,'UNSAFE_WORKSPACE'):
            self.verify()
        mkdir.assert_not_called();self.assertFalse(self.calls)

    def test_invalid_manifest_descriptor_archive_pins_do_not_reach_l1(self):
        original=deepcopy(self.local)
        for key in ('manifest_sha256','descriptor_sha256','archive_sha256'):
            self.local=deepcopy(original);self.local['transport'][key]='0'*64
            if key in self.local:self.local[key]='0'*64
            self.local['transport_sha256']=digest(self.local['transport'])
            with self.subTest(pin=key),patch.object(v.transport,'verify_extracted') as l1, self.assertRaises(v.VerificationError):self.verify()
            l1.assert_not_called()

    def test_local_paths_unknown_locator_fields_and_bad_sizes_rejected(self):
        original=deepcopy(self.local)
        for change in ({'kind':'LOCAL_QUALIFICATION_ONLY'}, {'repository_id':True},
                       {'asset_size':True}, {'asset_size':2**32},
                       {'path':'/tmp/local.tar.gz'}, {'immutable_required':False},
                       {'asset_name':'../unsafe.tar.gz'}, {'repository':'Other/Repo'}):
            self.local=deepcopy(original);self.local['transport']['storage'].update(change)
            self.local['transport_sha256']=digest(self.local['transport'])
            with self.subTest(change=change),self.assertRaises(v.VerificationError):self.verify()
        self.assertFalse(self.calls)

    def test_annotated_publication_tag_is_resolved_to_exact_commit(self):
        normal=self.request
        def annotated(url,**kwargs):
            if '/git/ref/tags/' in url:
                return io.BytesIO(canonical(dict(ref='refs/tags/synthetic-release-20',
                    object=dict(type='tag',sha='d'*40))))
            if '/git/tags/' in url:
                return io.BytesIO(canonical(dict(sha='d'*40,object=dict(type='commit',sha='c'*40))))
            return normal(url,**kwargs)
        with patch.object(v.trusted,'_request',side_effect=annotated):result=self.verify()
        self.addCleanup(shutil.rmtree,Path(result['retained_directory']))
        self.assertEqual(result['archive_release']['release_id'],20)

    def test_remote_identity_and_corrupt_bytes_fail_before_restore(self):
        for changes in ({'repository':{'id':999}}, {'repository':{'private':False}},
                {'release-20':{'immutable':False}}, {'release-20':{'draft':True}},
                {'release-20':{'id':999}}, {'release-20':{'assets':[]}},
                {'asset-21':{'name':'wrong.tar.gz'}}, {'asset-21':{'size':1}},
                {'asset-21':{'digest':'sha256:'+'0'*64}}, {'bytes-21':b'corrupt'},
                {'release-10':{'assets':[]}}, {'bytes-13':b'corrupt'},
                {'asset-13':{'id':999}}, {'bytes-12':b'corrupt'},
                {'tag':{'object':{'type':'commit','sha':'a'*40}}}):
            self.changes=changes
            with self.subTest(change=changes),patch.object(v.trusted,'restore') as restore, self.assertRaises(v.VerificationError):self.verify()
            restore.assert_not_called()
        self.assertEqual(self.registry.read_bytes(),b'unchanged')

    def test_repinned_foreign_notices_still_fail_gate(self):
        self.set_notices(wrong=True)
        self.local['transport']['reference_sha256']=digest(self.ref)
        self.local['transport_sha256']=digest(self.local['transport'])
        # Descriptor pin still binds the original reference; reject even before
        # restoration. Direct wrong-subject ZIP gate is independently exercised.
        with patch.object(v.trusted,'restore') as restore,self.assertRaises(v.VerificationError):self.verify()
        restore.assert_not_called()
        p=self.t.root/'foreign-notices.zip';p.write_bytes(self.data[13])
        with self.assertRaises(ValueError):v.trusted.verify_notices(self.ref,digest(self.ref),p)

    def test_resource_metadata_failure_is_sanitized(self):
        with patch.object(v.trusted,'_request',side_effect=RuntimeError(self.token+' https://example.invalid/?token=secret')):
            with self.assertRaises(v.VerificationError) as error:self.verify()
        self.assertNotIn(self.token,str(error.exception));self.assertNotIn('https',str(error.exception))


class LocalEvidenceCLITests(unittest.TestCase):
    def setUp(self):
        self.f=requests.LocalRegistrationRequestTests();self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.addCleanup(self.f.f.doCleanups)

    def test_only_new_command_routes_to_local_evidence_using_pinned_policy_domain(self):
        with patch.object(cli.local_verification,'verify',return_value=dict(
                status='LOCAL_REMOTE_EVIDENCE_VERIFIED',owner_authorization='NOT_GRANTED')) as local, \
             patch.object(cli.owner,'verify') as owner,patch.object(cli.transaction,'register') as tx, \
             patch.object(cli.evidence,'verify') as hosted:
            code,result=self.f.f.call('verify-local-evidence')
            self.assertEqual(code,0);self.assertEqual(result['owner_authorization'],'NOT_GRANTED')
            self.assertEqual(local.call_args.kwargs['expected_repository'],self.f.f.f.repo['full_name'])
            self.assertEqual(local.call_args.kwargs['expected_repository_id'],self.f.f.f.repo['id'])
            for command in ('register','verify-subject'):
                code,result=self.f.f.call(command);self.assertEqual(code,1)
                self.assertEqual(result['reason'],'TRUSTED_WORKFLOW_EXECUTION_NOT_ESTABLISHED'
                    if command=='register' else 'LOCAL_EVIDENCE_TRANSPORT_CONTRACT_NOT_FINALIZED')
        self.assertEqual(local.call_count,1);owner.assert_not_called();tx.assert_not_called();hosted.assert_not_called()

    def test_local_failure_never_falls_back_and_stdout_is_sanitized(self):
        with patch.object(cli.local_verification,'verify',side_effect=v.VerificationError('INVALID_ARCHIVE')), \
             patch.object(cli.evidence,'verify') as hosted:
            code,result=self.f.f.call('verify-local-evidence')
        self.assertEqual(code,1);self.assertEqual(result['reason'],'INVALID_ARCHIVE');hosted.assert_not_called()

    def test_remote_exception_text_cannot_leak_to_json(self):
        with patch.object(cli.local_verification,'verify',side_effect=RuntimeError(
                'offline-fixture-token https://example.invalid/?token=secret')):
            code,result=self.f.f.call('verify-local-evidence')
        self.assertEqual(code,1)
        rendered=json.dumps(result)
        self.assertNotIn('offline-fixture-token',rendered)
        self.assertNotIn('https://',rendered)
        self.assertNotIn('token=secret',rendered)

    def test_old_seven_field_schema3_and_wrong_canonical_pin_rejected(self):
        r=self.f.f.request;old=deepcopy(r)
        for name in ('transport','transport_sha256'):r['local_evidence'].pop(name)
        self.f.f.write_request()
        with self.assertRaises(ValueError):self.f.load()
        self.f.f.request=old;old['local_evidence']['transport_sha256']='0'*64;self.f.f.write_request()
        with self.assertRaises(ValueError):self.f.load()

    def test_new_command_does_not_accept_hosted_request_or_bad_request_pin(self):
        self.f.f.request=deepcopy(self.f.hosted_request);self.f.f.write_request()
        with patch.object(cli.local_verification,'verify') as local:
            code,result=self.f.f.call('verify-local-evidence')
        self.assertEqual(code,1);self.assertEqual(result['reason'],'LOCAL_REQUEST_REQUIRED');local.assert_not_called()
        self.f.f.sha='0'*64
        code,result=self.f.f.call('verify-local-evidence')
        self.assertEqual(code,1);self.assertEqual(result['reason'],'REQUEST_SHA256_MISMATCH')

    def test_closed_transport_fields_and_unknown_actions_identity_rejected(self):
        original=deepcopy(self.f.f.request)
        for field in v.TRANSPORT_FIELDS | {'run_id','artifact_id','approved'}:
            r=deepcopy(original);t=r['local_evidence']['transport']
            if field in t:del t[field]
            else:t[field]=123
            r['local_evidence']['transport_sha256']=digest(t)
            self.f.f.request=r;self.f.f.write_request()
            with self.subTest(field=field),self.assertRaises(ValueError):self.f.load()


if __name__=='__main__':unittest.main()
