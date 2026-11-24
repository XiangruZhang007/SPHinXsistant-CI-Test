"""Real Git object/ZIP/byte checks; HTTP and host drivers are controlled fixtures."""
from copy import deepcopy
from pathlib import Path
import base64,hashlib,tempfile,unittest,zipfile
from unittest.mock import patch
from src import automatic_release as release,upstream_provenance as source,derived_parent_registry as state
from src.corpus_snapshot import file_digest,write_json
from src import gradio_deployment_adapter as adapter
from test_gradio_deployment_adapter import Driver


class NoticeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.policy={'licenses':[]};values={};entries=[]
        for i in range(7):
            name='license'+str(i)+'.txt';raw=('Retained license '+str(i)+'\n').encode();oid=source._object(raw,'blob')
            entries.append(b'100644 '+name.encode()+b'\0'+bytes.fromhex(oid))
            self.policy['licenses'].append({'name':name,'path':name,'repository':'SPHinXsys','sha256':hashlib.sha256(raw).hexdigest()})
            values[name]={'raw':base64.b64encode(raw).decode(),'trees':{}}
        tree=b''.join(entries);tree_sha=source._object(tree,'tree')
        proofs={}
        for label in ('base','target'):
            commit=('tree '+tree_sha+'\nauthor Fixture <fixture@example.invalid> 0 +0000\ncommitter Fixture <fixture@example.invalid> 0 +0000\n\n'+label).encode()
            proofs[label]={'SPHinXsys':{'commit':source._object(commit,'commit'),'commit_raw':base64.b64encode(commit).decode()}}
            for v in values.values():v['trees'][label]={tree_sha:base64.b64encode(tree).decode()}
        write_json(self.root/'source-proofs.json',proofs);write_json(self.root/'license-sources.json',values)
        self.values=values
    def save(self):
        import json
        (self.root/'license-sources.json').write_text(json.dumps(self.values))
    def test_both_source_versions_and_all_seven_texts_verified(self):
        self.assertEqual(len(release.verify_license_sources(self.root,self.root,self.policy)),7)
    def test_notice_zip_real_nine_members_and_exact_bytes(self):
        expected=release.notices(self.root,self.root,self.policy,self.root/'notices.zip','sha256-'+'a'*64)
        self.assertEqual(len(expected),9);release.verify_notices(self.root/'notices.zip',expected)
    def test_wrong_base_tree_rejected(self):
        self.values['license0.txt']['trees']['base']={'a'*40:base64.b64encode(b'bad').decode()}
        self.save()
        with self.assertRaises((ValueError,KeyError)):release.verify_license_sources(self.root,self.root,self.policy)
    def test_wrong_target_license_text_rejected(self):
        self.values['license0.txt']['raw']=base64.b64encode(b'not the reviewed license').decode()
        self.save()
        with self.assertRaises(ValueError):release.verify_license_sources(self.root,self.root,self.policy)
    def test_unbound_extra_tree_rejected(self):
        self.values['license0.txt']['trees']['target']['a'*40]='YQ=='
        self.save()
        with self.assertRaises(ValueError):release.verify_license_sources(self.root,self.root,self.policy)
    def test_missing_source_version_rejected(self):
        self.values['license0.txt']['trees'].pop('base');self.save()
        with self.assertRaises(ValueError):release.verify_license_sources(self.root,self.root,self.policy)
    def test_extra_or_missing_zip_member_rejected(self):
        expected=release.notices(self.root,self.root,self.policy,self.root/'notices.zip','sha256-'+'a'*64)
        with zipfile.ZipFile(self.root/'bad.zip','w') as z:
            for name,raw in expected.items():z.writestr(name,raw)
            z.writestr('../unexpected',b'bad')
        with self.assertRaises(ValueError):release.verify_notices(self.root/'bad.zip',expected)
    def test_complete_remote_bytes_always_required_even_with_matching_api_digest(self):
        assets=[{'id':i+1,'name':name,'size':1,'digest':'sha256:'+'a'*64} for i,name in enumerate(release.ASSETS)]
        with patch.object(release.completion,'_download') as download:
            release._download_all(object(),{'draft':False,'immutable':True,'assets':assets},
                {n:{'sha256':'a'*64,'size':1} for n in release.ASSETS},self.root)
            self.assertEqual(download.call_count,3)
    def test_missing_or_unexpected_release_asset_denied_before_download(self):
        for assets in ([],[{'id':1,'name':'candidate.tar.gz'}]):
            with patch.object(release.completion,'_download') as download,self.assertRaises(ValueError):
                release._download_all(object(),{'draft':False,'immutable':True,'assets':assets},{},self.root)
            download.assert_not_called()
    def test_mutable_release_denied_before_download(self):
        with self.assertRaises(ValueError):release._download_all(object(),{'draft':False,'immutable':False},{},self.root)


class StateHTTPTests(unittest.TestCase):
    def setUp(self):
        self.transport=state.GitState('FixtureOwner/Test',1,'fixture-token',writable=True)
        self.rows={};self.trees={};self.blobs={};self.head='a'*40;self.calls=[];self.fail=None
        self._make(self.head,None,{'schema_version':2,'baselines':{}},{'entries':[]})
        self.patch=patch.object(state.GitHubAuditTransport,'_exchange',side_effect=self.exchange);self.patch.start();self.addCleanup(self.patch.stop)
    def _tree(self,items):
        rows=[]
        for name,value in items.items():
            raw=state.serialize(value);sha=source._object(raw,'blob');self.blobs[sha]=raw
            rows.append({'path':name,'mode':'100644','type':'blob','size':len(raw),'sha':sha})
        tree=hashlib.sha1(state.serialize(rows)).hexdigest();self.trees[tree]=rows;return tree
    def _make(self,sha,parent,registry,lineage):
        tree=self._tree({'registry.json':registry,'lineage.json':lineage})
        self.rows[sha]={'sha':sha,'tree':{'sha':tree},'parents':[] if parent is None else [{'sha':parent}]}
    def exchange(self,transport,method,endpoint,body):
        suffix=endpoint.removeprefix('repos/FixtureOwner/Test');self.calls.append((method,suffix,body))
        if method=='GET':
            if suffix=='':return 200,{'id':1,'full_name':'FixtureOwner/Test','private':True}
            if suffix=='/git/ref/'+state.REF[5:]:return 200,{'ref':state.REF,'object':{'type':'commit','sha':self.head}}
            sha=suffix.rsplit('/',1)[1]
            if '/commits/' in suffix:return 200,deepcopy(self.rows[sha])
            if '/trees/' in suffix:return 200,{'sha':sha,'tree':deepcopy(self.trees[sha]),'truncated':False}
            if '/blobs/' in suffix:
                return 200,{'sha':sha,'encoding':'base64','content':base64.b64encode(self.blobs[sha]).decode()}
        if method=='POST' and suffix=='/git/trees':
            import json
            sha=self._tree({r['path']:json.loads(r['content']) for r in body['tree']});return 201,{'sha':sha}
        if method=='POST' and suffix=='/git/commits':
            sha=hashlib.sha1(state.serialize(body)).hexdigest()
            self.rows[sha]={'sha':sha,'tree':{'sha':body['tree']},'parents':[{'sha':x} for x in body['parents']]}
            return 201,{'sha':sha}
        if method=='PATCH':
            if self.fail=='before':raise TimeoutError()
            self.assertFalse(body['force']);self.head=body['sha']
            if self.fail=='after':raise TimeoutError()
            return 200,{'object':{'sha':self.head}}
        raise AssertionError((method,suffix))
    def test_real_gitstate_append_and_full_blob_readback(self):
        sha=self.transport.append(self.head,{'schema_version':2,'baselines':{'one':{}}},{'entries':[1]})
        self.assertEqual(self.transport.head(),sha)
        self.assertEqual(self.transport.read(sha)['registry.json']['baselines'],{'one':{}})
        self.assertEqual(sum(m=='PATCH' for m,_,_ in self.calls),1)
    def test_corrupt_blob_cannot_become_state(self):
        sha=next(iter(self.blobs));self.blobs[sha]=b'{}\n'
        with self.assertRaises(ValueError):self.transport.read(self.head)
    def test_extra_tree_member_denied(self):
        tree=self.rows[self.head]['tree']['sha'];self.trees[tree].append({'path':'evil.py'})
        with self.assertRaises(ValueError):self.transport.read(self.head)
    def test_executable_or_symlink_member_denied(self):
        tree=self.rows[self.head]['tree']['sha'];self.trees[tree][0]['mode']='120000'
        with self.assertRaises(ValueError):self.transport.read(self.head)
    def test_multi_parent_history_denied(self):
        self.rows[self.head]['parents']=[{'sha':'b'*40},{'sha':'c'*40}]
        with self.assertRaises(ValueError):self.transport.read(self.head)
    def test_uncertain_update_burns_transport_without_retry(self):
        self.fail='after'
        with self.assertRaises(TimeoutError):self.transport.append(self.head,{'baselines':{}},{'entries':[]})
        with self.assertRaises(ValueError):self.transport.append(self.head,{'baselines':{}},{'entries':[]})
        self.assertEqual(sum(m=='PATCH' for m,_,_ in self.calls),1)


class DeploymentIntegrationTests(unittest.TestCase):
    def test_verified_selection_to_existing_driver_and_rollback(self):
        # Explicitly modeled selection/app boundary; real staging is covered by
        # the unchanged adapter tests. No real server, SSH or Gradio process.
        class ControlledDriver(Driver,adapter.DeploymentDriver):pass
        driver=ControlledDriver()
        with tempfile.TemporaryDirectory() as d:
            path=Path(d);(path/'corpus.jsonl').write_bytes(b'{}\n')
            policy={'deployment_path':'configs/driver.json','deployment_sha256':'a'*64,'policy_sha256':'b'*64}
            current={'head':'c'*40,'generation':1};parent={'corpus_sha256':file_digest(path/'corpus.jsonl'),'node_id':'sha256-'+'d'*64}
            settings={'schema_version':1,'kind':'VERIFIED_GRADIO_DRIVER_V1','enabled':True,'storage_root':str(path/'store'),'queries':['test']}
            with patch('src.genuine_continuous_execution._checkout'),patch('src.automatic_lifecycle_policy.load',return_value=policy),patch('src.continuous_build_policy._read_pinned',return_value=settings), \
                 patch('src.automatic_lifecycle.select',return_value=(current,parent,path,None)),patch.object(adapter,'stage_and_verify',return_value={'status':'RESEARCH_STAGING_VERIFIED'}),patch('src.corpus_snapshot.read_records',return_value=[{}]):
                store=type('Store',(),{'head':lambda self:'c'*40})()
                result=adapter.deploy_selected(path,{},policy,object(),store,path,driver,app_python='/fixture/python')
                self.assertEqual(result['status'],'ACTIVE_VERIFIED')
                active=driver.current();driver.fail='activation'
                parent['corpus_sha256']='f'*64;current['head']='e'*40;store.head=lambda:'e'*40
                result=adapter.deploy_selected(path,{},policy,object(),store,path,driver,app_python='/fixture/python')
                self.assertEqual(result['status'],'REJECTED_PREVIOUS_RETAINED');self.assertEqual(driver.current(),active)


class PublicationTests(unittest.TestCase):
    """Real packaging/digests/ZIP reads; science and GitHub are modeled."""
    def setUp(self):
        import json
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name)
        root=self.root=self.work/'run';root.mkdir()
        write_json(root/'result.json',{'research_baseline_created':False,'automatic_research_approval':False})
        write_json(root/'checksums.json',{'result.json':file_digest(root/'result.json')})
        self.verified={'eligible':True,'candidate_id':'sha256-'+'a'*64,'parent':{'generation':1},'report':{'accepted':True}}
        self.policy={'repository':'FixtureOwner/Test','repository_id':1,'policy_sha256':'b'*64,'release_prefix':'approved'}
        self.config={'implementation_revision':'c'*40};self.data={};self.mutations=[];self.release=None;self.failure=None
        self.client=type('Client',(),{})();self.client.repository=self.policy['repository'];self.client.token='fixture'
        self.client._api=self.api;self.client._upload=self.upload
        self.patch=patch('src.automatic_candidate.verify',return_value=self.verified);self.patch.start();self.addCleanup(self.patch.stop)
        self.verified['report'].update(contract='AUTOMATIC_QUALITY_V2',status='QUALITY_ACCEPTED',q1='QUALIFIED_FOR_VERSION_PAIR',P8='ELIGIBLE',reasons=[])
        self.patch2=patch.object(release,'verify_license_sources',return_value={f'license{i}.txt':b'fixture license' for i in range(7)})
        self.patch2.start();self.addCleanup(self.patch2.stop)
        self.policy['licenses']=[];write_json(root/'source-proofs.json',{'base':{},'target':{}})
        # Seal is deliberately genuine only as bytes; native verification above
        # is explicitly mocked. No synthetic quality claim is made operational.
        (root/'checksums.json').unlink();write_json(root/'checksums.json',{p.name:file_digest(p) for p in root.iterdir()})
        self.patch3=patch.object(release.completion,'_download',side_effect=self.download)
        self.download_mock=self.patch3.start();self.addCleanup(self.patch3.stop)
    def api(self,method,path,payload=None,**kwargs):
        if method=='GET':
            if path.endswith('/immutable-releases'):return {'enabled':True}
            if '/releases/tags/' in path:return None
            if '/git/ref/tags/' in path:
                return None if self.release is None or self.release['draft'] else {'object':{'type':'commit','sha':self.config['implementation_revision']}}
            if '/releases/' in path:return deepcopy(self.release)
            raise AssertionError(path)
        self.mutations.append((method,path))
        if method=='POST':
            self.release={'id':4,'draft':True,'immutable':False,'tag_name':payload['tag_name'],
                'target_commitish':payload['target_commitish'],'upload_url':'https://uploads.github.com/fixture','assets':[]}
            return deepcopy(self.release)
        if method=='PATCH':
            self.release.update(draft=False,immutable=True)
            if self.failure=='publish-timeout':raise TimeoutError()
            return deepcopy(self.release)
        raise AssertionError(method)
    def upload(self,url,release_id,path):
        raw=path.read_bytes();oid=10+len(self.data);self.data[oid]=raw
        asset={'id':oid,'name':path.name,'size':len(raw),'digest':'sha256:'+hashlib.sha256(raw).hexdigest(),'state':'uploaded'}
        self.release['assets'].append(asset);self.mutations.append(('UPLOAD',path.name))
        if self.failure=='upload-timeout':raise TimeoutError()
        return deepcopy(asset)
    def download(self,client,asset,path,expected):
        raw=self.data[asset['id']]
        if self.failure=='corrupt-bytes':raw+=b'changed'
        path.write_bytes(raw)
        if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('COMPLETION_ASSET_HASH_MISMATCH')
    def execute(self):
        return release.publish(self.work,self.client,self.config,self.policy,self.root,self.verified,{},lambda:None,self.work/'publication')
    def test_complete_positive_orchestration_and_six_full_downloads(self):
        result=self.execute()
        self.assertEqual(result['release_id'],4);self.assertEqual(len(result['assets']),3)
        self.assertEqual([m for m,_ in self.mutations],['POST','UPLOAD','UPLOAD','UPLOAD','PATCH'])
        self.assertEqual(len(self.data),3);self.assertEqual(self.download_mock.call_count,6)
    def test_quality_rejection_cannot_create_release(self):
        self.verified['eligible']=False
        with self.assertRaises(ValueError):self.execute()
        self.assertEqual(self.mutations,[])
    def test_corrupt_draft_download_stops_before_publication(self):
        self.failure='corrupt-bytes'
        with self.assertRaises(ValueError):self.execute()
        self.assertTrue(self.release['draft']);self.assertNotIn('PATCH',[m for m,_ in self.mutations])
    def test_upload_uncertainty_preserves_draft_no_second_asset_or_retry(self):
        self.failure='upload-timeout'
        with self.assertRaises(ValueError):self.execute()
        self.assertTrue(self.release['draft']);self.assertEqual(len(self.release['assets']),1)
    def test_publication_uncertainty_reconciles_without_second_patch(self):
        self.failure='publish-timeout'
        with self.assertRaises(ValueError):self.execute()
        self.assertFalse(self.release['draft']);self.assertEqual(sum(m=='PATCH' for m,_ in self.mutations),1)
        from src.corpus_snapshot import read_json
        journal=read_json(self.work/'publication/publication-state.json')
        self.assertEqual(journal['read_only_observation']['draft'],False)
        self.assertEqual(journal['status'],'REMOTE_STATE_UNCERTAIN')


class CompleteOrchestrationTests(unittest.TestCase):
    def test_two_parent_generations_publication_selection_and_driver_rollback(self):
        """Real coordinator, P8/promotion, packaging, audit and deployment flow.

        Hosted context/Artifact/accepted science/app-process boundaries are
        explicitly modeled. This is not a real accepted Corpus or deployment.
        """
        import shutil
        from src import automatic_lifecycle as lifecycle
        from src import automatic_candidate as native
        from test_automatic_lifecycle import LifecycleTests
        case=PublicationTests();case.setUp();self.addCleanup(case.doCleanups)
        lineage=LifecycleTests();lineage.setUp()
        case.policy.update(lineage.policy)
        case.client.repository=case.policy['repository']
        case.config.update(repository=case.policy['repository'],repository_id=case.policy['repository_id'],implementation_revision=lineage.config['implementation_revision'])
        current={'generation':0,'node_id':'sha256-'+'e'*64,'corpus_sha256':'f'*64}
        context={'ruleset_observation':{'mode':'CONTROLLED_FIXTURE'}}
        project=Path(__file__).resolve().parents[1]
        def selected(*args):
            view=lineage.view()
            return view,deepcopy(current),case.root,None
        def delivery(client,config,run_id,attempt,destination):
            view=lineage.view();shutil.copytree(case.root,destination/'run')
            write_json(destination/'selection.json',{'view':view,'parent':deepcopy(current),
                'policy_sha256':case.policy['policy_sha256'],'candidate_id':case.verified['candidate_id'],
                'producer':context['actor']})
            return context['origin'],{'artifact_id':run_id}
        def protocol(config,binding,person,token,revalidate):
            from test_parent_authority_git_audit import GitModel
            from src.parent_authority_git_audit import _IsolatedGitProtocol
            model=GitModel(config,binding);lineage.models[binding['decision']['transaction_id']]=model
            revalidate();return _IsolatedGitProtocol(model,config,binding)
        class ControlledDriver(Driver,adapter.DeploymentDriver):pass
        driver=ControlledDriver();previous=driver.current()
        with patch.object(lifecycle.genuine,'deployment',return_value=(case.config,'{}','0'*64)), \
             patch.object(lifecycle.policy_api,'load',return_value=case.policy), \
             patch.object(lifecycle.completion,'Client',return_value=case.client), \
             patch.object(lifecycle.writer,'observe',side_effect=lambda *a,**kw:deepcopy(context)), \
             patch.object(lifecycle.completion,'retrieve_build',side_effect=delivery), \
             patch.object(lifecycle,'select',side_effect=selected), \
             patch.object(lifecycle.derived,'GitState',return_value=lineage.store), \
             patch.object(lifecycle.writer,'protocol',side_effect=protocol), \
             patch.dict('os.environ',{'PARENT_AUTHORITY_AUDIT_TOKEN':'fixture-token'}):
            for i in (1,2):
                case.release=None
                case.verified['candidate_id']='sha256-'+str(i)*64
                case.verified['parent']={'generation':i,'node_id':case.verified['candidate_id'],'corpus_sha256':str(i)*64}
                case.verified['report']['candidate_id']=case.verified['candidate_id']
                context.update(actor={**lineage.actor,'run_id':i},origin={'run_id':i})
                result=lifecycle.publish_and_advance(project,case.work/('cycle'+str(i)))
                self.assertEqual(result['status'],'PARENT_ADVANCED')
                self.assertEqual(lineage.view()['generation'],i)
                current=deepcopy(case.verified['parent'])
                settings={'schema_version':1,'kind':'VERIFIED_GRADIO_DRIVER_V1','enabled':True,
                    'storage_root':str(case.work/'store'),'queries':['fixture']}
                if i==2:driver.fail='activation'
                with patch.object(lifecycle.genuine,'_checkout'), \
                     patch.object(lifecycle.scope,'_read_pinned',return_value=settings), \
                     patch('src.corpus_snapshot.read_records',return_value=[{}]), \
                     patch.object(adapter,'stage_and_verify',return_value={'status':'RESEARCH_STAGING_VERIFIED'}):
                    output=adapter.deploy_selected(project,case.config,case.policy,case.client,lineage.store,
                        case.work,driver,app_python='/fixture/python')
                if i==1:
                    self.assertEqual(output['status'],'ACTIVE_VERIFIED');previous=driver.current()
                else:
                    self.assertEqual(output['status'],'REJECTED_PREVIOUS_RETAINED');self.assertEqual(driver.current(),previous)
            case.verified['eligible']=False
            before=list(case.mutations)
            result=lifecycle.publish_and_advance(project,case.work/'quality-rejection')
            self.assertEqual(result['status'],'QUALITY_REJECTED')
            self.assertEqual(case.mutations,before);self.assertEqual(lineage.view()['generation'],2)
