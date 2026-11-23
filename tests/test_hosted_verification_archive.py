"""Offline GitHub fixtures; no real networking, credentials, commits or PRs."""
import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from src import hosted_verification_archive as a

P=Path(__file__).resolve().parents[1]
REV='2'*40
RUN=901


def fixture():
    config=(P/'configs/ci_v2_research_candidate_loading.json').read_bytes();subject=json.loads(config)['subject']
    report={'status':'RESEARCH_CANDIDATE_GRADIO_VERIFIED','scope':'RESEARCH_LOADING_ONLY','subject':subject,
        'review_sha256':a.sha(config),'restrictions':a.RESTRICTIONS,
        'original_execution':'LOCAL_RESEARCH_EXECUTION / HOSTED_NOT_RUN','scientific_verification':'NO_FRESH_REPLAY',
        'production_promotion':'NOT_AUTHORIZED','LLM_calls':0,'HTTP_server_started':False,
        'temporary_run_and_application_cleaned':True,'notices':'VERIFIED_SOURCE_AND_LICENSE_BINDINGS',
        'evidence':{'candidate_id':subject['candidate_id'],'records':subject['records'],'parity':'PARITY_PASS',
                    'P8':'BLOCKED','sealed_R2':'VERIFIED / NO_FRESH_REPLAY'},
        'application':{'sha256':subject['corpus_sha256'],'records':subject['records'],
            'complete_records_equal':True,'callbacks_share_assistant':True,'application_closed':True,
            'retriever_class':'src.retrieval_v1.RetrievalV1',
            'isolation':{'uid':1001,'gid':1001,'capabilities':'ALL_ZERO','no_new_privs':True,
                'separate_network_namespace':True,'interfaces':['lo'],'external_route_probe':'ENETUNREACH'},
            'retrieval':[{'query':'How does SPHinXsim migrate_legacy_configuration preserve the saved document?',
                'top_k':5,'results':[{'rank':1,'chunk_id':'d5e0de43d804b1790811c5d1295b13ac3c957afb',
                                    'source_path':'repos/SPHinXsim/sphinxsim/config/migrations.py'}]}]}}
    run={'id':RUN,'path':a.WORKFLOW,'repository':{'id':a.RID},'head_repository':{'id':a.RID},
        'workflow_id':77,'event':'workflow_dispatch','head_branch':a.BRANCH,'status':'completed',
        'conclusion':'success','run_attempt':1,'actor':{'id':a.OWNER},'triggering_actor':{'id':a.OWNER},'head_sha':REV}
    raw=json.dumps(report).encode();stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w') as z:z.writestr('verification.json',raw)
    zipped=stream.getvalue();asset={'id':888,'name':'candidate-gradio-loading-901-1','digest':'sha256:'+a.sha(zipped),
        'expired':False,'size_in_bytes':len(zipped),'workflow_run':{'id':RUN,'repository_id':a.RID,
        'head_repository_id':a.RID,'head_sha':REV}}
    return config,report,run,asset,zipped


class Api:
    def __init__(self):
        self.config,self.report,self.run,self.asset,self.zipped=fixture();self.calls=[];self.posts=[]
        self.blobs={};self.written={};self.refs=[];self.prs=[];self.tree=[]
        self.fail_write=None
    def __call__(self,method,path,data=None,binary=False):
        self.calls.append((method,path))
        if method=='POST':
            self.posts.append((path,data))
            if self.fail_write and self.fail_write in path:raise ValueError('UNCERTAIN_WRITE')
            if path.endswith('/git/blobs'):
                raw=base64.b64decode(data['content']);oid=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest();self.blobs[oid]=raw;return {'sha':oid}
            if path.endswith('/git/trees'):
                self.written={e['path']:self.blobs[e['sha']] for e in data['tree']};return {'sha':'c'*40}
            if path.endswith('/git/commits'):return {'sha':'d'*40,'tree':{'sha':data['tree']},'parents':[{'sha':REV}]}
            if path.endswith('/git/refs'):
                value={'ref':data['ref'],'object':{'sha':data['sha']}};self.refs=[value];return value
            if path.endswith('/pulls'):
                value={'number':9,'state':'open','user':{'login':'github-actions[bot]','type':'Bot'},
                    'head':{'sha':'d'*40,'ref':data['head']},'base':{'ref':a.BRANCH}};self.prs=[value];return value
        if path==a.ROOT:return {'id':a.RID,'full_name':a.REPO,'default_branch':a.BRANCH,'owner':{'id':a.OWNER}}
        if '/contents/' in path:
            relative=path.split('/contents/',1)[1].split('?')[0]
            raw=self.written.get(relative,(P/relative).read_bytes() if (P/relative).exists() else b'')
            return {'type':'file','encoding':'base64','size':len(raw),'content':base64.b64encode(raw).decode()}
        if path.endswith('/actions/runs/901'):return copy.deepcopy(self.run)
        if path.endswith('/actions/workflows/ci_v2_candidate_gradio_loading.yml'):return {'id':77,'path':a.WORKFLOW}
        if '/jobs?' in path:
            names=['Check out exact trusted dispatch revision','Select frozen ARM64 Python','Prepare frozen package verifier',
                   'Prepare separate application interpreter','Verify immutable Candidate evidence and run isolated real Gradio BM25',
                   'Retain sanitized verification report only']
            return {'total_count':1,'jobs':[{'run_id':RUN,'conclusion':self.run['conclusion'],
                'steps':[{'name':n,'conclusion':'success'} for n in names]}]}
        if '/artifacts?' in path:return {'total_count':1,'artifacts':[copy.deepcopy(self.asset)]}
        if path.endswith('/zip'):return self.zipped
        if '/git/commits/' in path:return {'sha':REV,'tree':{'sha':'b'*40}}
        if '/git/trees/' in path:return {'sha':'b'*40,'truncated':False,'tree':self.tree}
        if '/git/matching-refs/' in path:return self.refs
        if '/pulls?' in path:return self.prs
        if '/git/ref/heads/' in path:
            return {'object':{'sha':REV if path.endswith('/'+a.BRANCH) else 'd'*40}}
        if '/compare/' in path:return {'status':'identical' if not self.refs else 'ahead','behind_by':0,
            'ahead_by':1,'merge_base_commit':{'sha':REV},'files':[{'filename':p,'status':'added'} for p in self.written]}
        raise AssertionError(path)


class ArchiveTests(unittest.TestCase):
    def setUp(self):self.api=Api()
    def files(self):return a.archive_files(self.api.run,self.api.asset,self.api.zipped,self.api.config)
    def test_real_validation_fetches_no_writes(self):
        self.assertEqual(a.fetch(self.api,P,RUN),self.files());self.assertEqual(self.api.posts,[])
    def test_zip_digest_mismatch(self):
        with self.assertRaisesRegex(ValueError,'DIGEST'):a.report_from_zip(self.api.zipped,'sha256:'+'0'*64)
    def test_unsafe_duplicate_extra_and_oversized_zip(self):
        for names in [['../verification.json'],['verification.json','extra'],['verification.json','verification.json']]:
            stream=io.BytesIO()
            with zipfile.ZipFile(stream,'w') as z:
                for n in names:z.writestr(n,b'{}')
            raw=stream.getvalue()
            with self.assertRaises(ValueError):a.report_from_zip(raw,'sha256:'+a.sha(raw))
        with self.assertRaises(ValueError):a.report_from_zip(b'x'*(2*1024**2+1),'wrong')
    def test_zip_symlink_rejected(self):
        stream=io.BytesIO();item=zipfile.ZipInfo('verification.json');item.external_attr=(stat.S_IFLNK|0o777)<<16
        with zipfile.ZipFile(stream,'w') as z:z.writestr(item,b'{}')
        raw=stream.getvalue()
        with self.assertRaises(ValueError):a.report_from_zip(raw,'sha256:'+a.sha(raw))
    def test_duplicate_and_nonfinite_json_rejected(self):
        for raw in [b'{"id":1,"id":2}',b'{"x":NaN}']:
            with self.assertRaises(ValueError):a.decode(raw)
    def test_report_candidate_corpus_scope_cleanup_and_isolation_negatives(self):
        cases=[('subject','candidate_id','wrong'),('application','sha256','wrong'),('application','records',1),
            ('application','application_closed',False),('application','callbacks_share_assistant',False),
            ('evidence','parity','PARITY_FAIL'),('evidence','P8','PASS')]
        for section,key,value in cases:
            report=copy.deepcopy(self.api.report);report[section][key]=value
            with self.subTest(section=section,key=key),self.assertRaises(ValueError):a.validate_report(report,self.api.run,json.loads(self.api.config))
        report=copy.deepcopy(self.api.report);report['application']['isolation']['uid']=0
        with self.assertRaises(ValueError):a.validate_report(report,self.api.run,json.loads(self.api.config))
    def test_wrong_run_attempt_owner_origin_workflow(self):
        for key,value in [('run_attempt',2),('event','pull_request'),('path','other.yml'),('head_branch','untrusted')]:
            old=self.api.run[key];self.api.run[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):a.fetch(self.api,P,RUN)
            self.api.run[key]=old
        self.api.run['triggering_actor']['id']=1
        with self.assertRaises(ValueError):a.fetch(self.api,P,RUN)
        self.assertEqual(self.api.posts,[])
    def test_wrong_artifact_run_id_sha_name_digest(self):
        for key,value in [('id',1),('head_sha','0'*40),('repository_id',1)]:
            old=self.api.asset['workflow_run'][key];self.api.asset['workflow_run'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):a.fetch(self.api,P,RUN)
            self.api.asset['workflow_run'][key]=old
        self.api.asset['name']='other'
        with self.assertRaises(ValueError):a.fetch(self.api,P,RUN)
    def test_failed_run_preserves_blocked_not_pass(self):
        self.api.run['conclusion']='failure';report={'status':'BLOCKED','reason':'CANDIDATE_RESEARCH_CONSUMPTION_FAILED','production_promotion':'NOT_AUTHORIZED'}
        a.validate_report(report,self.api.run,json.loads(self.api.config))
        with self.assertRaises(ValueError):a.validate_report(self.api.report,self.api.run,json.loads(self.api.config))
    def test_manifest_deterministic_and_original_bytes_preserved(self):
        files=self.files();self.assertEqual(files,self.files());self.assertEqual(json.loads(files['verification.json']),self.api.report)
        self.assertEqual(json.loads(files['manifest.json'])['run_conclusion'],'success')
    def test_local_idempotency_and_conflicting_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'archive';f=self.files();self.assertEqual(a.retain(p,f),'ARCHIVE_PREPARED')
            self.assertEqual(a.retain(p,f),'ALREADY_ARCHIVED_IDENTICAL');f['README.md']=b'conflict'
            with self.assertRaisesRegex(ValueError,'CONFLICT'):a.retain(p,f)
    def test_unsafe_local_parent_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'link').symlink_to(p,target_is_directory=True)
            with self.assertRaises(ValueError):a.retain(p/'link'/'child',self.files())
    def test_propose_only_three_added_docs_and_bot_pr(self):
        f=self.files();result=a.propose(self.api,P,f,RUN,a.sha(f['manifest.json']),REV)
        self.assertEqual(result['status'],'ARCHIVE_PR_CREATED_REVIEW_REQUIRED');self.assertEqual(len(self.api.written),3)
        self.assertTrue(all(p.startswith(a.relative_directory(RUN)+'/') for p in self.api.written))
        self.assertEqual(len([p for p,d in self.api.posts if p.endswith('/pulls')]),1)
        created_tree=next(data for path,data in self.api.posts if path.endswith('/git/trees'))
        self.assertEqual(created_tree['base_tree'],'b'*40)
        self.assertNotEqual(created_tree['base_tree'],REV)
    def test_existing_identical_pr_is_idempotent(self):
        f=self.files();pin=a.sha(f['manifest.json']);a.propose(self.api,P,f,RUN,pin,REV);count=len(self.api.posts)
        result=a.propose(self.api,P,f,RUN,pin,REV);self.assertEqual(result['status'],'EXISTING_IDENTICAL_ARCHIVE_PR');self.assertEqual(count,len(self.api.posts))
    def test_validation_digest_required_before_write(self):
        with self.assertRaises(ValueError):a.propose(self.api,P,self.files(),RUN,'0'*64,REV)
        self.assertEqual(self.api.posts,[])
    def test_uncertain_write_stops_without_retry(self):
        self.api.fail_write='/git/refs';f=self.files()
        with self.assertRaisesRegex(ValueError,'UNCERTAIN'):a.propose(self.api,P,f,RUN,a.sha(f['manifest.json']),REV)
        self.assertEqual(len([p for p,d in self.api.posts if p.endswith('/git/refs')]),1)
        self.assertFalse(any(p.endswith('/pulls') for p,d in self.api.posts))
    def test_existing_conflicting_archive_fails_without_write(self):
        relative=a.relative_directory(RUN);self.api.tree=[{'path':relative+'/extra','type':'blob','mode':'100644'}]
        f=self.files()
        with self.assertRaisesRegex(ValueError,'CONFLICT'):a.propose(self.api,P,f,RUN,a.sha(f['manifest.json']),REV)
        self.assertEqual(self.api.posts,[])
    def test_workflow_separates_read_and_write_and_preserves_owner_bot(self):
        import yaml
        workflow=yaml.load((P/'.github/workflows/ci_v2_hosted_evidence_archive.yml').read_text(),Loader=yaml.BaseLoader)
        self.assertEqual(set(workflow['on']),{'workflow_run'});self.assertEqual(workflow['permissions'],{})
        self.assertEqual(workflow['jobs']['validate']['permissions'],{'contents':'read','actions':'read'})
        self.assertEqual(workflow['jobs']['propose']['needs'],'validate')
        self.assertEqual(workflow['jobs']['propose']['permissions'],{'contents':'write','actions':'read','pull-requests':'write'})
        for job in workflow['jobs'].values():
            for step in job['steps']:
                if 'run' in step:self.assertNotIn('${{',step['run'])
                if 'uses' in step:self.assertRegex(step['uses'],r'@[0-9a-f]{40}$')
        bot=(P/'.github/workflows/ci_v2_bot_proposal.yml').read_text()
        self.assertIn("github.actor_id == '239840087'",bot)
        self.assertIn('retention-days: 30',(P/a.WORKFLOW).read_text())
    def test_cli_untrusted_context_cannot_call_transport(self):
        from scripts import archive_hosted_verification as cli
        with patch.dict('os.environ',{},clear=True),patch.object(cli,'api') as transport:
            with self.assertRaises(ValueError):cli.context(RUN)
        transport.assert_not_called()


class AdditionalSecurityTests(unittest.TestCase):
    setUp = ArchiveTests.setUp
    files = ArchiveTests.files
    def test_unreviewed_workflow_or_code_rejected(self):
        for target in ['src/research_candidate_consumer.py',a.WORKFLOW,'configs/ci_v2_research_candidate_loading.json']:
            def changed(method,path,data=None,binary=False):
                result=self.api(method,path,data,binary)
                if '/contents/'+target+'?' in path:
                    result={'type':'file','encoding':'base64','size':4,'content':base64.b64encode(b'evil').decode()}
                return result
            with self.subTest(path=target),self.assertRaises(ValueError):a.fetch(changed,P,RUN)
        self.assertEqual(self.api.posts,[])

    def test_nonancestor_run_rejected(self):
        def changed(method,path,data=None,binary=False):
            if '/compare/' in path:return {'status':'diverged','behind_by':1,'merge_base_commit':{'sha':'a'*40}}
            return self.api(method,path,data,binary)
        with self.assertRaises(ValueError):a.fetch(changed,P,RUN)

    def test_wrong_job_or_skipped_loading_rejected(self):
        def changed(method,path,data=None,binary=False):
            result=self.api(method,path,data,binary)
            if '/jobs?' in path:result['jobs'][0]['steps'][4]['conclusion']='skipped'
            return result
        with self.assertRaisesRegex(ValueError,'INCOMPLETE_SUCCESS'):a.fetch(changed,P,RUN)

    def test_missing_expired_or_extra_artifact_rejected(self):
        self.api.asset['expired']=True
        with self.assertRaises(ValueError):a.fetch(self.api,P,RUN)
        self.api.asset['expired']=False
        for assets in [[],[self.api.asset,self.api.asset]]:
            def changed(method,path,data=None,binary=False):
                if '/artifacts?' in path:return {'total_count':len(assets),'artifacts':assets}
                return self.api(method,path,data,binary)
            with self.assertRaises(ValueError):a.fetch(changed,P,RUN)

    def test_corrupt_zip_crc_is_rejected(self):
        raw=bytearray(self.api.zipped);start=raw.find(b'RESEARCH_CANDIDATE_GRADIO_VERIFIED');self.assertGreater(start,0);raw[start]^=1
        with self.assertRaises(zipfile.BadZipFile):a.report_from_zip(bytes(raw),'sha256:'+a.sha(raw))

    def test_report_scope_and_science_restrictions_rejected(self):
        for key,value in [('LLM_calls',1),('HTTP_server_started',True),('scientific_verification','FRESH_REPLAY'),
                          ('restrictions',[]),('scope','PRODUCTION'),('temporary_run_and_application_cleaned',False)]:
            report=copy.deepcopy(self.api.report);report[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):a.validate_report(report,self.api.run,json.loads(self.api.config))

    def test_partial_ref_without_pr_stops_without_writes(self):
        self.api.refs=[{'ref':'refs/heads/partial','object':{'sha':'d'*40}}];files=self.files()
        with self.assertRaisesRegex(ValueError,'PARTIAL'):a.propose(self.api,P,files,RUN,a.sha(files['manifest.json']),REV)
        self.assertEqual(self.api.posts,[])

    def test_identical_merged_archive_requires_no_mutations(self):
        files=self.files();relative=a.relative_directory(RUN);self.api.written={relative+'/'+n:raw for n,raw in files.items()}
        self.api.tree=[{'path':p,'type':'blob','mode':'100644'} for p in self.api.written]
        self.assertEqual(a.propose(self.api,P,files,RUN,a.sha(files['manifest.json']),REV)['status'],'ALREADY_ARCHIVED_IDENTICAL')
        self.assertEqual(self.api.posts,[])

    def test_default_branch_change_stops_before_first_write(self):
        def changed(method,path,data=None,binary=False):
            if path.endswith('/git/ref/heads/'+a.BRANCH):return {'object':{'sha':'0'*40}}
            return self.api(method,path,data,binary)
        files=self.files()
        with self.assertRaisesRegex(ValueError,'MOVED'):a.propose(changed,P,files,RUN,a.sha(files['manifest.json']),REV)
        self.assertEqual(self.api.posts,[])

    def test_no_unapproved_merge_or_release_write_endpoint(self):
        files=self.files();a.propose(self.api,P,files,RUN,a.sha(files['manifest.json']),REV)
        self.assertEqual({path.rsplit('/',1)[-1] for path,data in self.api.posts}, {'blobs','trees','commits','refs','pulls'})


    def test_expired_artifact_uses_identical_reviewed_archive_without_download(self):
        import shutil
        with tempfile.TemporaryDirectory() as tmp:
            project=Path(tmp)
            for relative in ['src/research_candidate_consumer.py','scripts/check_hosted_candidate_gradio.py',
                'scripts/check_hosted_gradio_loading.py','src/corpus_update_integration.py',
                'apps/gradio_app_v1.py','src/retrieval_v1.py',a.WORKFLOW,'configs/ci_v2_research_candidate_loading.json']:
                target=project/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(P/relative,target)
            files=self.files();a.retain(project/a.relative_directory(RUN),files);self.api.asset['expired']=True
            self.assertEqual(a.fetch(self.api,project,RUN),files)
            self.assertFalse(any(path.endswith('/zip') for method,path in self.api.calls))
