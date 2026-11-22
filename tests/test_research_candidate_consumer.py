"""Offline research consumer fixtures: no genuine build, replay or authorization.

Scientific validators, transport and app are mocked explicitly. Archive, review,
notices, original seal, binding checks and cleanup execute for real fixtures.
"""
import copy
import gzip
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from src import research_candidate_consumer as c
from scripts import check_hosted_candidate_gradio as cli


class CandidateConsumerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.project = self.root / 'project'; self.project.mkdir()
        self.inputs = self.root / 'inputs'; self.inputs.mkdir()
        self.run = self.inputs / 'original'; self.run.mkdir()
        self.review_path = self.inputs / 'review.json'
        self.output = self.root / 'output'
        self.python = self.root / 'app-python'
        self.python.write_text('#!/bin/sh\nexit 0\n')
        self.python.chmod(0o755)
        self.subject = copy.deepcopy(c.SUBJECT)
        p = patch.object(c, 'SUBJECT', self.subject); p.start(); self.addCleanup(p.stop)
        self.row = {'chunk_id': c.EXPECTED_CHUNK, 'source_path': c.EXPECTED_SOURCE,
                    'repository': 'SPHinXsim', 'source_role': 'python_library',
                    'content': 'def migrate_legacy_configuration(payload): pass',
                    'start_line': 1, 'end_line': 1, 'chunk_type': 'function',
                    'node_type': 'function_definition', 'symbol': 'migrate_legacy_configuration',
                    'byte_start': 0, 'byte_end': 1, 'parent_context': {}}
        self.row['byte_end'] = len(self.row['content'].encode())
        raw = (json.dumps(self.row) + '\n').encode()
        self.subject['records'] = 1; self.subject['corpus_size'] = len(raw)
        self.subject['corpus_sha256'] = c.hash_bytes(raw)
        self.parity = {'status': 'PARITY_PASS', 'candidate_id': self.subject['candidate_id']}
        self.result = {'bindings': {k: self.subject[k] for k in ('candidate_id', 'parent_id',
             'base_source_state', 'target_source_state', 'base_upstreams', 'target_upstreams', 'build_fingerprint')},
             'hosted_validation': 'HOSTED_NOT_RUN', 'RESEARCH_BASELINE_APPROVED': False,
             'research_baseline_created': False, 'automatic_reuse': False,
             'automatic_research_approval': False, 'production_promotion': 'NOT_AUTHORIZED',
             'retrieval_quality': 'QUALITY_REVIEW_REQUIRED', 'quality_metrics': {}}
        self.result['bindings']['four_artifact_parity'] = self.parity
        self.put('result.json', self.result)
        self.put('q1-status.json', {'status': 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR'})
        self.put('parity.json', self.parity)
        self.put('candidate/upstream-candidate.json', {'identity': {
            'orchestration_fingerprint': self.subject['orchestration_fingerprint'],
            'policy_sha256': self.subject['build_policy_sha256']}})
        self.put('build-policy.json', {'fixture': True})
        self.subject['build_policy_sha256'] = c.snapshot.file_digest(self.run / 'build-policy.json')
        self.put('candidate/upstream-candidate.json', {'identity': {
            'orchestration_fingerprint': self.subject['orchestration_fingerprint'],
            'policy_sha256': self.subject['build_policy_sha256']}})
        self.put('benchmark.json', {})
        self.put('trusted-reference.json', {})
        self.put('parent-raw-results.json', [])
        for label,folder in [('incremental','candidate'),('full','full')]:
            path=self.run/folder/'corpus.jsonl';path.parent.mkdir(exist_ok=True)
            path.write_bytes(raw)
            path=self.run/folder/'components/documentation.jsonl';path.parent.mkdir()
            path.write_bytes(raw)
            self.put('quality/'+label+'-raw-results.json', [])
            self.put('execution-verification/'+label+'-replay.json', [])
        (self.run/'parent').mkdir()
        cfg=self.project/'configs/ci_v2_runtime_lock.json';cfg.parent.mkdir()
        cfg.write_text(json.dumps({'quality_policy': {}}))
        self.seal()
        self.mockers=[
            patch.object(c.research,'frozen_runtime',return_value={'fixture':True}),
            patch.object(c.snapshot,'verify_snapshot',return_value={'snapshot_id':self.subject['parent_id']}),
            patch.object(c.provenance,'verify',return_value={'candidate_id':self.subject['candidate_id'],'P4_1_verification':'NOT_APPROVED'}),
            patch.object(c.provenance,'compare_full',return_value=self.parity),
            patch.object(c.gate,'evaluate',return_value={'decision':'BLOCKED','gate_mode':'BLOCKING_ONLY','evidence_consistency':'VERIFIED_ARCHIVED_BINDINGS'}),
            patch.object(c.evaluation,'frozen_implementation',return_value={}),
            patch.object(c.evaluation,'rescore',return_value={}),
            patch.object(c,'qualify_parent_anchor',return_value={'status':'PINNED_ANCHOR_INSPECTED','execution':'NO_FRESH_REPLAY'}),
            patch.object(c,'verify_source_notices'),
            patch.object(c,'application_check',side_effect=self.app),
            patch.object(c.trust,'download',side_effect=self.download)]
        self.mocks=[p.start() for p in self.mockers]
        for p in self.mockers:self.addCleanup(p.stop)
        p=patch.dict(os.environ,{'GITHUB_REPOSITORY':c.REPOSITORY,'GITHUB_REPOSITORY_ID':str(c.REPOSITORY_ID)})
        p.start();self.addCleanup(p.stop)
        self.license_bytes={n:('SYNTHETIC TEST LICENSE '+n).encode() for n in c.LICENSES}
        p=patch.object(c,'LICENSES',{n:c.hash_bytes(raw) for n,raw in self.license_bytes.items()})
        p.start();self.addCleanup(p.stop)
        self.package()

    def put(self,name,data):
        path=self.run/name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(data)+'\n')

    def seal(self):
        self.put('checksums.json',{p.relative_to(self.run).as_posix():c.snapshot.file_digest(p)
            for p in self.run.rglob('*') if p.is_file() and p.name!='checksums.json'})
        self.subject['run_manifest_sha256']=c.snapshot.file_digest(self.run/'checksums.json')

    def package(self,extra=None):
        self.archive=self.inputs/'run.tar.gz'
        with tarfile.open(self.archive,'w:gz') as t:
            for p in sorted(self.run.rglob('*')):
                if p.is_file():t.add(p,arcname=p.relative_to(self.run).as_posix(),recursive=False)
            if extra:
                info,raw=extra;t.addfile(info,io.BytesIO(raw) if raw is not None else None)
        def loc(name,ident,size):return dict(kind=c.trust.PRIVATE_RELEASE_KIND,repository=c.REPOSITORY,
            repository_id=c.REPOSITORY_ID,release_id=123,asset_id=ident,tag='synthetic-test-only',
            asset_name=name,asset_size=size,immutable_required=True)
        self.review={'schema_version':1,'kind':'RESEARCH_CANDIDATE_LOADING_INPUTS','purpose':c.PURPOSE,
            'subject':copy.deepcopy(self.subject),'archive':{'sha256':c.snapshot.file_digest(self.archive),
            'storage':loc('run.tar.gz',1,self.archive.stat().st_size)},'notices':{'sha256':'0'*64,'storage':loc('notices.zip',2,1)}}
        self.mapping={'schema_version':1,'kind':'RESEARCH_CANDIDATE_NOTICES','subject':copy.deepcopy(self.subject),
            'archive_sha256':self.review['archive']['sha256'],
            'license_texts':{n:{'sha256':c.hash_bytes(raw),'size':len(raw)} for n,raw in self.license_bytes.items()},
            'source_license_bindings':{},'project_license_bindings':[],
            'license_tree_proofs':{'base':{'SPHinXsys':{},'SPHinXsim':{}},'target':{'SPHinXsys':{},'SPHinXsim':{}}}}
        self.notices=self.inputs/'notices.zip';self.write_notices()

    def write_notices(self,extra=None):
        with zipfile.ZipFile(self.notices,'w') as z:
            z.writestr('README.md',c.notices_readme(self.review))
            z.writestr('source-and-license-mapping.json',json.dumps(self.mapping))
            for n,raw in self.license_bytes.items():z.writestr('licenses/'+n,raw)
            if extra:z.writestr(*extra)
        self.review['notices']['sha256']=c.snapshot.file_digest(self.notices)
        self.review['notices']['storage']['asset_size']=self.notices.stat().st_size
        self.pin_review()

    def pin_review(self):
        self.review_path.write_text(json.dumps(self.review))
        self.pin=c.snapshot.file_digest(self.review_path)

    def download(self,loc,path,pin,**kwargs):
        source=self.archive if loc['asset_id']==1 else self.notices
        path.write_bytes(source.read_bytes())

    def app(self,project,python,work,root):
        self.extracted=root
        return {'sha256':self.subject['corpus_sha256'],'records':1,'corpus_path':str(root/'candidate/corpus.jsonl'),
            'complete_records_equal':True,'callbacks_share_assistant':True,'application_closed':True,
            'retriever_class':'src.retrieval_v1.RetrievalV1','isolation':{'fixture':True},
            'retrieval':[{'query':c.QUERY,'top_k':5,'results':[{'rank':1,'chunk_id':c.EXPECTED_CHUNK,
            'source_path':c.EXPECTED_SOURCE}]}]}

    def consume(self,**kwargs):
        options={'authorized_review_sha256':self.pin,'purpose':c.PURPOSE};options.update(kwargs)
        return c.consume(self.project,self.review_path,self.pin,self.output,self.python,**options)

    def test_interpreter_rejected_before_runtime_download_or_extraction(self):
        for python in [Path('relative-python'), self.root/'missing', self.root]:
            with self.subTest(python=python), patch.object(c, 'extracted_run') as extract:
                with self.assertRaisesRegex(c.ConsumptionError, 'APPLICATION_INTERPRETER_REQUIRED'):
                    c.consume(self.project,self.review_path,self.pin,self.output,python,
                        authorized_review_sha256=self.pin,purpose=c.PURPOSE)
                extract.assert_not_called()
        self.python.chmod(0o644)
        with self.assertRaisesRegex(c.ConsumptionError, 'APPLICATION_INTERPRETER_REQUIRED'):
            self.consume()
        self.mocks[0].assert_not_called()
        self.mocks[-1].assert_not_called()
        self.mocks[9].assert_not_called()
        self.assertFalse(self.output.exists())

    def test_venv_interpreter_symlink_is_supported_without_execution(self):
        link=self.root/'venv-python';link.symlink_to(self.python)
        self.assertEqual(c.application_interpreter(link),link)
        with patch.object(cli.subprocess,'run') as execute:
            c.application_interpreter(link)
            execute.assert_not_called()

    def test_oversized_extensions_rejected_before_standard_parser_allocation(self):
        for kind,method in [(tarfile.XHDTYPE,'_proc_pax'),(tarfile.XGLTYPE,'_proc_pax'),
                            (tarfile.GNUTYPE_LONGNAME,'_proc_gnulong'),
                            (tarfile.GNUTYPE_LONGLINK,'_proc_gnulong')]:
            info=tarfile.TarInfo('metadata');info.type=kind;info.size=c.METADATA_LIMIT+1
            # Header only: success depends on rejecting its size BEFORE reading
            # the absent oversized payload, not an exception after extraction.
            self.archive.write_bytes(gzip.compress(info.tobuf()))
            self.review['archive']['sha256']=c.snapshot.file_digest(self.archive)
            self.review['archive']['storage']['asset_size']=self.archive.stat().st_size
            with self.subTest(kind=kind), patch.object(tarfile.TarInfo,method) as parser, \
                    patch.object(c.tempfile,'TemporaryDirectory') as destination:
                with self.assertRaisesRegex(c.ConsumptionError,'ARCHIVE_METADATA_LIMIT_EXCEEDED'):
                    with c.extracted_run(self.archive,self.root,self.review):pass
                parser.assert_not_called();destination.assert_not_called()

    def test_cumulative_metadata_budget_before_destination_creation(self):
        with patch.object(c,'METADATA_TOTAL_LIMIT',1), \
                patch.object(c.tempfile,'TemporaryDirectory') as destination:
            with self.assertRaisesRegex(c.ConsumptionError,'ARCHIVE_METADATA_LIMIT_EXCEEDED'):
                with c.extracted_run(self.archive,self.root,self.review):pass
            destination.assert_not_called()

    def test_normal_pax_long_path_compatible(self):
        path='extra/'+('segment/'*16)+'file.txt'
        info=tarfile.TarInfo(path);info.size=2
        self.package(extra=(info,b'ok'))
        with c.extracted_run(self.archive,self.root,self.review) as root:
            self.assertEqual((root/path).read_bytes(),b'ok')
        self.assertFalse(root.exists())

    def test_sparse_extensions_rejected_before_unbounded_sparse_parser(self):
        info=tarfile.TarInfo('regular');info.size=1
        info.pax_headers={'GNU.sparse.major':'1','GNU.sparse.minor':'0'}
        self.package(extra=(info,b'x'))
        with patch.object(tarfile.TarInfo,'_proc_gnusparse_10') as sparse, \
                patch.object(c.tempfile,'TemporaryDirectory') as destination:
            with self.assertRaisesRegex(c.ConsumptionError,'UNSAFE_ARCHIVE_MEMBER'):
                with c.extracted_run(self.archive,self.root,self.review):pass
            sparse.assert_not_called();destination.assert_not_called()

    def test_valid_candidate_consumption_and_cleanup(self):
        result=self.consume()
        self.assertEqual(result['status'],'RESEARCH_CANDIDATE_GRADIO_VERIFIED')
        self.assertEqual(result['original_execution'],'LOCAL_RESEARCH_EXECUTION / HOSTED_NOT_RUN')
        self.assertEqual(result['scientific_verification'],'NO_FRESH_REPLAY')
        self.assertIn('P8_BLOCKED',result['restrictions'])
        self.assertTrue(result['temporary_run_and_application_cleaned'])
        self.assertFalse(self.extracted.exists())
        self.assertFalse(self.mocks[7].call_args.kwargs['fresh_replay'])

    def test_wrong_candidate_digest_and_count_in_review(self):
        for field,value in [('candidate_id','sha256-'+'0'*64),('corpus_sha256','0'*64),('records',2)]:
            with self.subTest(field=field):
                old=self.review['subject'][field];self.review['subject'][field]=value;self.pin_review()
                with self.assertRaisesRegex(c.ConsumptionError,'CANDIDATE_SUBJECT_MISMATCH'):self.consume()
                self.review['subject'][field]=old
        self.mocks[-1].assert_not_called()

    def test_missing_or_mismatched_loading_authorization(self):
        for auth in [None,'','0'*64]:
            with self.subTest(auth=auth),self.assertRaisesRegex(c.ConsumptionError,'LOADING_AUTHORIZATION_REQUIRED'):
                self.consume(authorized_review_sha256=auth)
        self.mocks[-1].assert_not_called()

    def test_nonresearch_purposes_rejected(self):
        for purpose in ['BUILD_CANDIDATE','PRODUCTION_ACTIVATION','PUBLISH',None]:
            with self.subTest(purpose=purpose),self.assertRaisesRegex(c.ConsumptionError,'RESEARCH_PURPOSE_REQUIRED'):
                self.consume(purpose=purpose)
        self.mocks[-1].assert_not_called()

    def test_baseline_or_self_approval_fields_rejected(self):
        for field in ['baseline_id','approved','authorization']:
            self.review[field]=True;self.pin_review()
            with self.assertRaisesRegex(c.ConsumptionError,'INVALID_REVIEW_FIELDS'):self.consume()
            del self.review[field]

    def test_independent_review_pin_mismatch(self):
        self.review_path.write_bytes(self.review_path.read_bytes()+b' ')
        with self.assertRaisesRegex(c.ConsumptionError,'REVIEW_PIN_MISMATCH'):self.consume()

    def test_asset_release_and_identity_separation(self):
        for key,value in [('asset_id',1),('asset_name','run.tar.gz'),('release_id',456)]:
            old=self.review['notices']['storage'][key];self.review['notices']['storage'][key]=value;self.pin_review()
            with self.assertRaisesRegex(c.ConsumptionError,'ASSET_SET_MISMATCH'):self.consume()
            self.review['notices']['storage'][key]=old

    def test_missing_or_modified_run_member_rejected(self):
        for operation in ['delete','modify','add']:
            self.set_run_operation(operation)
            with self.assertRaises((ValueError,OSError)):c.verify_run(self.project,self.run)
            self.set_run_operation('restore')
        self.mocks[9].assert_not_called()

    def set_run_operation(self,operation):
        path=self.run/'benchmark.json'
        if operation=='delete':path.unlink()
        if operation=='modify':path.write_bytes(b'broken')
        if operation=='add':(self.run/'extra.txt').write_text('unreviewed')
        if operation=='restore':
            path.write_text('{}\n');(self.run/'extra.txt').unlink(missing_ok=True)

    def test_corpus_digest_and_record_count_checks(self):
        for field,value in [('corpus_sha256','0'*64),('records',2),('corpus_size',1)]:
            old=self.subject[field];self.subject[field]=value
            with self.subTest(field=field),self.assertRaises(c.ConsumptionError):c.verify_run(self.project,self.run)
            self.subject[field]=old

    def test_invalid_full_parity_rejected_even_if_objects_agree(self):
        self.parity['status']='PARITY_FAIL';self.put('parity.json',self.parity)
        self.put('result.json',self.result);self.seal()
        with self.assertRaisesRegex(c.ConsumptionError,'FULL_PARITY_MISMATCH'):c.verify_run(self.project,self.run)

    def test_archived_replay_mismatch_is_not_replayed(self):
        self.put('execution-verification/incremental-replay.json',[{'changed':True}]);self.seal()
        with patch.object(c.evaluation,'replay',side_effect=AssertionError('must not execute')) as replay:
            with self.assertRaisesRegex(c.ConsumptionError,'ARCHIVED_R2_MISMATCH'):c.verify_run(self.project,self.run)
            replay.assert_not_called()

    def test_baseline_file_substitution_denied(self):
        self.put('candidate/upstream-baseline.json',{'forged':True});self.seal()
        with self.assertRaisesRegex(c.ConsumptionError,'BASELINE_SUBSTITUTION_DENIED'):c.verify_run(self.project,self.run)

    def test_original_q1_quality_and_origin_cannot_be_relabelled(self):
        for field,value in [('hosted_validation','HOSTED_VERIFIED'),('RESEARCH_BASELINE_APPROVED',True),('retrieval_quality','QUALITY_ACCEPTED')]:
            old=self.result[field];self.result[field]=value;self.put('result.json',self.result);self.seal()
            with self.subTest(field=field),self.assertRaisesRegex(c.ConsumptionError,'ORIGINAL_RESEARCH_SCOPE_MISMATCH'):
                c.verify_run(self.project,self.run)
            self.result[field]=old

    def test_missing_invalid_and_mismatched_notices_before_extraction(self):
        for mode in ['missing','corrupt','wrong-subject']:
            with self.subTest(mode=mode):
                if mode=='missing':self.notices.unlink()
                elif mode=='corrupt':self.notices.write_bytes(b'not a zip')
                else:
                    self.mapping['subject']['candidate_id']='sha256-'+'0'*64;self.write_notices()
                with patch.object(c,'extracted_run') as extract:
                    with self.assertRaises((ValueError,OSError,zipfile.BadZipFile)):self.consume()
                    extract.assert_not_called()
                self.package()

    def test_missing_extra_license_and_unsafe_zip_members(self):
        for name in ['licenses/extra.txt','../escape']:
            self.write_notices(extra=(name,b'bad'))
            with self.assertRaisesRegex(c.ConsumptionError,'INVALID_NOTICES_MEMBERS'):self.consume()
        self.license_bytes[next(iter(self.license_bytes))]=b'altered text';self.write_notices()
        with self.assertRaisesRegex(c.ConsumptionError,'LICENSE_TEXT_MISMATCH'):self.consume()

    def test_unsafe_archive_members_before_destination_created(self):
        for name,kind in [('../escape',tarfile.REGTYPE),('/absolute',tarfile.REGTYPE),('link',tarfile.SYMTYPE),('hard',tarfile.LNKTYPE),('fifo',tarfile.FIFOTYPE),('result.json',tarfile.REGTYPE)]:
            info=tarfile.TarInfo(name);info.type=kind;info.linkname='../escape'
            raw=b'x' if kind==tarfile.REGTYPE else None;info.size=1 if raw else 0
            self.package(extra=(info,raw))
            with self.subTest(name=name),self.assertRaisesRegex(c.ConsumptionError,'UNSAFE_ARCHIVE_MEMBER'):self.consume()
            self.assertFalse(self.output.exists())
        self.mocks[9].assert_not_called()

    def test_archive_expansion_and_file_limits(self):
        with patch.object(c,'COUNT_LIMIT',1):
            with self.assertRaisesRegex(c.ConsumptionError,'ARCHIVE_LIMIT_EXCEEDED'):self.consume()
        with patch.object(c,'FILE_LIMIT',1):
            with self.assertRaisesRegex(c.ConsumptionError,'UNSAFE_ARCHIVE_MEMBER'):self.consume()

    def test_notice_source_failure_stops_app(self):
        self.mocks[8].side_effect=c.ConsumptionError('SOURCE_LICENSE_BINDING_MISMATCH')
        with self.assertRaisesRegex(c.ConsumptionError,'SOURCE_LICENSE_BINDING_MISMATCH'):self.consume()
        self.mocks[9].assert_not_called()

    def test_application_failure_and_invalid_loading_cleanup(self):
        for mode in ['exception','wrong-count','wrong-chunk']:
            def invalid(*args):
                x=self.app(*args)
                if mode=='exception':raise RuntimeError('synthetic')
                if mode=='wrong-count':x['records']=2
                if mode=='wrong-chunk':x['retrieval'][0]['results'][0]['chunk_id']='not-in-corpus'
                return x
            self.mocks[9].side_effect=invalid
            with self.subTest(mode=mode),self.assertRaises((ValueError,RuntimeError)):self.consume()
            self.assertFalse(self.extracted.exists());self.assertFalse(self.output.exists())

    def test_application_mutating_sealed_evidence_is_rejected(self):
        def alter(*args):
            x=self.app(*args);(self.extracted/'benchmark.json').write_bytes(b'changed');return x
        self.mocks[9].side_effect=alter
        with self.assertRaises(ValueError):self.consume()
        self.assertFalse(self.extracted.exists());self.assertFalse(self.output.exists())

    def test_existing_output_is_preserved(self):
        self.output.mkdir();marker=self.output/'existing';marker.write_text('keep')
        with self.assertRaisesRegex(c.ConsumptionError,'NEW_EXTERNAL_OUTPUT_REQUIRED'):self.consume()
        self.assertEqual(marker.read_text(),'keep')

    def test_app_uses_existing_namespace_launcher(self):
        self.mockers[9].stop()
        with patch('scripts.check_hosted_gradio_loading.isolated_python',return_value={'fixture':True}) as launch:
            c.application_check(self.project,Path('/app-python'),self.root,self.run)
        code=launch.call_args.args[2]
        self.assertLess(code.index("os.environ['SPHINX_CORPUS_PATH']"),code.index('from src.corpus_update_integration'))
        self.assertIn('_gradio_check',code)
        self.assertEqual(launch.call_args.args[0],Path('/app-python'))

    def test_cli_rejects_untrusted_dispatch_before_transport(self):
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaisesRegex(c.ConsumptionError,'TRUSTED_DISPATCH_REQUIRED'):cli.trusted_checkout(self.review_path,'a'*40)
        self.mocks[-1].assert_not_called()

    def test_cli_requires_tracked_review_and_exact_workflow_revision(self):
        config=self.project/'configs/review.json';config.write_bytes(self.review_path.read_bytes())
        environment={'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':c.REPOSITORY,
            'GITHUB_REPOSITORY_ID':str(c.REPOSITORY_ID),'GITHUB_EVENT_NAME':'workflow_dispatch',
            'GITHUB_REF':'refs/heads/ci-upstream-refresh','GITHUB_ACTOR_ID':'239840087',
            'GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':'a'*40,'GITHUB_WORKFLOW_SHA':'a'*40}
        environment['GITHUB_WORKFLOW_REF']=cli.WORKFLOW_REF
        with patch.object(cli,'PROJECT',self.project),patch.dict(os.environ,environment,clear=True):
            with patch.object(cli.subprocess,'check_output',side_effect=[b'a'*40,config.read_bytes()]):
                cli.trusted_checkout(config,'a'*40)
            with patch.object(cli.subprocess,'check_output',side_effect=[b'a'*40,b'wrong tracked bytes']):
                with self.assertRaisesRegex(c.ConsumptionError,'TRACKED_REVIEW_REQUIRED'):cli.trusted_checkout(config,'a'*40)
            with patch.object(cli.subprocess,'check_output',return_value=b'b'*40):
                with self.assertRaisesRegex(c.ConsumptionError,'CHECKOUT_REVISION_MISMATCH'):cli.trusted_checkout(config,'a'*40)
            with patch.object(cli.subprocess,'check_output',return_value=b'a'*40):
                with self.assertRaisesRegex(c.ConsumptionError,'CHECKOUT_REVISION_MISMATCH'):
                    cli.trusted_checkout(config,'b'*40)
            environment['GITHUB_WORKFLOW_REF']='untrusted/workflow@refs/heads/ci-upstream-refresh'
            with patch.dict(os.environ,environment,clear=True):
                with self.assertRaisesRegex(c.ConsumptionError,'TRUSTED_DISPATCH_REQUIRED'):
                    cli.trusted_checkout(config,'a'*40)

    def cli_arguments(self):
        return ['--review',str(self.review_path),'--expected-review-sha256',self.pin,
                '--authorized-review-sha256',self.pin,'--expected-implementation-revision','a'*40,
                '--purpose',c.PURPOSE,'--app-python',str(self.python),'--output',str(self.output)]

    def test_cli_isolation_preflight_requires_digest_and_calls_existing_launcher(self):
        with patch.object(cli,'trusted_checkout'), \
                patch('scripts.check_hosted_gradio_loading.isolated_python',return_value={'fixture':True}) as isolate, \
                patch('builtins.print'):
            self.assertEqual(cli.main(self.cli_arguments()+['--isolation-preflight']),0)
            self.assertEqual(isolate.call_args.args[0],self.python)
            self.assertIn('print(json.dumps(isolation))',isolate.call_args.args[2])
            self.assertFalse(self.output.exists())
            args=self.cli_arguments();args[args.index('--authorized-review-sha256')+1]='0'*64
            isolate.reset_mock()
            self.assertEqual(cli.main(args+['--isolation-preflight']),1)
            isolate.assert_not_called()
        self.mocks[-1].assert_not_called()

    def test_cli_missing_interpreter_cannot_start_isolation_or_downloads(self):
        self.python.unlink()
        with patch.object(cli,'trusted_checkout'), \
                patch('scripts.check_hosted_gradio_loading.isolated_python') as isolate, \
                patch('builtins.print'):
            self.assertEqual(cli.main(self.cli_arguments()+['--isolation-preflight']),1)
            isolate.assert_not_called()
        self.mocks[0].assert_not_called();self.mocks[-1].assert_not_called()

    def test_cli_preflight_rejects_unsafe_output_before_isolation(self):
        for target in [self.root,self.project/'new-output',Path('relative-output')]:
            args=self.cli_arguments();args[args.index('--output')+1]=str(target)
            with self.subTest(target=target),patch.object(cli,'PROJECT',self.project), \
                    patch.object(cli,'trusted_checkout'), \
                    patch('scripts.check_hosted_gradio_loading.isolated_python') as isolate, \
                    patch('builtins.print'):
                self.assertEqual(cli.main(args+['--isolation-preflight']),1)
                isolate.assert_not_called()
        self.assertFalse((self.project/'new-output').exists())

    def test_cli_failure_retains_sanitized_report_only(self):
        with patch.object(cli,'trusted_checkout',side_effect=ValueError('secret must not leak')), \
                patch('builtins.print') as output:
            self.assertEqual(cli.main(self.cli_arguments()),1)
        raw=(self.output/'verification.json').read_text()
        self.assertNotIn('secret',raw)
        self.assertEqual(json.loads(raw)['status'],'BLOCKED')
        self.assertNotIn('secret',output.call_args.args[0])

    def test_cli_failure_never_overwrites_existing_output(self):
        self.output.mkdir();(self.output/'keep').write_text('preserve')
        with patch.object(cli,'trusted_checkout',side_effect=ValueError('fixture')),patch('builtins.print'):
            self.assertEqual(cli.main(self.cli_arguments()),1)
        self.assertEqual((self.output/'keep').read_text(),'preserve')
        self.assertFalse((self.output/'verification.json').exists())

    def test_wrong_repository_and_oversized_notice_locators_rejected(self):
        self.review['archive']['storage']['repository_id']=1;self.pin_review()
        with self.assertRaisesRegex(c.ConsumptionError,'REPOSITORY_SCOPE_MISMATCH'):self.consume()
        self.review['archive']['storage']['repository_id']=c.REPOSITORY_ID
        self.review['notices']['storage']['asset_size']=c.trust.MAX_NOTICES_BYTES+1;self.pin_review()
        with self.assertRaisesRegex(c.ConsumptionError,'NOTICES_TOO_LARGE'):self.consume()

    def test_empty_app_results_and_wrong_source_rejected(self):
        for mode in ['empty','wrong-source']:
            def invalid(*args):
                x=self.app(*args)
                if mode=='empty':x['retrieval'][0]['results']=[]
                else:x['retrieval'][0]['results'][0]['source_path']='unrelated'
                return x
            self.mocks[9].side_effect=invalid
            with self.assertRaisesRegex(c.ConsumptionError,'BOUND_BM25_EVIDENCE_REQUIRED'):self.consume()
            self.assertFalse(self.extracted.exists())

    def license_fixture(self):
        import base64
        def tree(entries):
            raw=b''.join(mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(oid)
                         for mode,name,oid in entries)
            return c.provenance._object(raw,'tree'),base64.b64encode(raw).decode()
        apache='fb82ba1eb1b72dcab96a2542a207d978c9d7c985'
        mit='55ecec75a9c0978b5b4db598764e454bd26f62ec'
        leaf,leafraw=tree([('100644','LICENSE',apache)])
        middle,middleraw=tree([('40000','sphinxsys',leaf)])
        sim,simraw=tree([('100644','LICENSE',mit),('40000','sphinxsim',middle)])
        proofs={}
        for phase in ('base','target'):
            proofs[phase]={}
            for repo,root,raw in [('SPHinXsys',leaf,leafraw),('SPHinXsim',sim,simraw)]:
                commit=('tree '+root+'\n\nsynthetic test\n').encode()
                proofs[phase][repo]={'commit':c.provenance._object(commit,'commit'),
                    'commit_raw':base64.b64encode(commit).decode(),'trees':{root:raw}}
                if repo=='SPHinXsim':
                    self.mapping['license_tree_proofs'][phase][repo]={middle:middleraw,leaf:leafraw}
                for path in (['LICENSE'] if repo=='SPHinXsys' else ['LICENSE','sphinxsim/sphinxsys/LICENSE']):
                    self.mapping['project_license_bindings'].append(dict(phase=phase,repository=repo,
                        path=path,revision=self.subject[phase+'_upstreams'][repo],
                        license='MIT-SPHinXsim.txt' if repo=='SPHinXsim' and path=='LICENSE' else 'Apache-2.0-SPHinXsys.txt'))
        self.put('candidate/git-proofs.json',proofs)
        for path,license in c.VENDOR_NOTICES.items():
            names=['parent/sources/'+path,'candidate/input/repos/'+path,'full/sources/'+path]
            for n in names:
                f=self.run/n;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(b'synthetic vendor')
            self.mapping['source_license_bindings'][path]={'license':license,'members':{
                n:c.snapshot.file_digest(self.run/n) for n in names}}

    def test_actual_source_and_license_mapping_validator(self):
        self.mockers[8].stop();self.license_fixture()
        c.verify_source_notices(self.run,self.mapping)
        self.mapping['project_license_bindings'][0]['revision']='0'*40
        with self.assertRaisesRegex(c.ConsumptionError,'PROJECT_LICENSE_SUBJECT_MISMATCH'):
            c.verify_source_notices(self.run,self.mapping)

    def test_corrupt_missing_extra_license_tree_objects(self):
        self.mockers[8].stop();self.license_fixture()
        obj=self.mapping['license_tree_proofs']['base']['SPHinXsim']
        key=next(iter(obj));raw=obj[key]
        obj[key]='Y29ycnVwdA=='
        with self.assertRaises(ValueError):c.verify_source_notices(self.run,self.mapping)
        obj[key]=raw
        del obj[key]
        with self.assertRaisesRegex(c.ConsumptionError,'LICENSE_GIT_PROOF_MISSING'):
            c.verify_source_notices(self.run,self.mapping)
        obj[key]=raw;obj['0'*40]='Y29ycnVwdA=='
        with self.assertRaisesRegex(c.ConsumptionError,'UNUSED_LICENSE_TREE_PROOF'):
            c.verify_source_notices(self.run,self.mapping)

    def test_source_notice_must_cover_parent_candidate_and_full(self):
        self.mockers[8].stop();self.license_fixture()
        first=next(iter(self.mapping['source_license_bindings'].values()))
        first['members'].pop(next(iter(first['members'])))
        with self.assertRaisesRegex(c.ConsumptionError,'SOURCE_LICENSE_BINDING_MISMATCH'):
            c.verify_source_notices(self.run,self.mapping)

    def test_missing_license_member_rejected(self):
        with zipfile.ZipFile(self.notices) as z:
            files={n:z.read(n) for n in z.namelist() if not n.endswith(next(iter(c.LICENSES)))}
        with zipfile.ZipFile(self.notices,'w') as z:
            for name,raw in files.items():z.writestr(name,raw)
        self.review['notices']['sha256']=c.snapshot.file_digest(self.notices)
        self.review['notices']['storage']['asset_size']=self.notices.stat().st_size;self.pin_review()
        with self.assertRaisesRegex(c.ConsumptionError,'INVALID_NOTICES_MEMBERS'):self.consume()

    def test_archive_digest_and_size_mismatch_rejected(self):
        for key,value in [('sha256','0'*64),('size',1)]:
            if key=='sha256':self.review['archive']['sha256']=value
            else:self.review['archive']['storage']['asset_size']=value
            self.pin_review()
            with self.assertRaisesRegex(c.ConsumptionError,'ARCHIVE_PIN_MISMATCH'):
                with c.extracted_run(self.archive,self.root,self.review):pass
            self.package()

    def test_genuine_source_notices_helper_rejects_missing_coverage(self):
        self.mockers[8].stop()
        with self.assertRaisesRegex(c.ConsumptionError,'INCOMPLETE_SOURCE_NOTICES'):
            c.verify_source_notices(self.run,self.mapping)


class PublishedHostedCandidateContractTests(unittest.TestCase):
    """Real tracked-proposal bytes, offline schema checks; NOT owner approval."""

    def setUp(self):
        self.project=Path(__file__).resolve().parents[1]
        self.config=self.project/'configs/ci_v2_research_candidate_loading.json'
        self.pin='c5a060a2d4e2fb3232ad0dbfa9c63b040277406190972099306616fdf8f4ed83'

    def test_published_input_bytes_and_actual_contract(self):
        self.assertEqual(c.snapshot.file_digest(self.config),self.pin)
        with patch.dict(os.environ,{'GITHUB_REPOSITORY':c.REPOSITORY,
                'GITHUB_REPOSITORY_ID':str(c.REPOSITORY_ID)},clear=True):
            # Synthetic caller authorization tests only the interface; it does
            # not create/record a human execution decision.
            review=c.review_inputs(self.config,self.pin,authorized_review_sha256=self.pin,purpose=c.PURPOSE)
        for key,ident,size,pin in [('archive',780676875,54568087,
                '95397523de2bd6c70813604fc828430fd9e6494da14696f4fa486af118b152c4'),
                ('notices',780683404,12757,
                'dbfc7fba58f65616f5e00e27804ff6943d7f85174320ba5307169ed86c5196eb')]:
            loc=review[key]['storage']
            self.assertEqual((loc['asset_id'],loc['asset_size'],review[key]['sha256']),(ident,size,pin))
            self.assertEqual(loc['release_id'],454787335)
            self.assertEqual(loc['tag'],'ci-v2-research-candidate-76105a0d')
        self.assertEqual(review['subject']['records'],12123)

    def test_published_inputs_are_not_loading_authorization(self):
        with self.assertRaisesRegex(c.ConsumptionError,'LOADING_AUTHORIZATION_REQUIRED'):
            c.review_inputs(self.config,self.pin,purpose=c.PURPOSE)

    def workflow(self):
        import yaml
        return yaml.load((self.project/'.github/workflows/ci_v2_candidate_gradio_loading.yml').read_text(),
                         Loader=yaml.BaseLoader)

    def test_manual_workflow_requires_separate_digest_and_revision(self):
        w=self.workflow();self.assertEqual(set(w['on']),{'workflow_dispatch'})
        inputs=w['on']['workflow_dispatch']['inputs']
        self.assertEqual(set(inputs),{'authorized_review_sha256','expected_implementation_revision'})
        self.assertTrue(all(v['required']=='true' and 'default' not in v for v in inputs.values()))
        self.assertEqual(w['permissions'],{'contents':'read'})
        job=w['jobs']['research-loading'];self.assertEqual(job['runs-on'],'ubuntu-24.04-arm')
        self.assertEqual(job['env']['REVIEW_SHA256'],self.pin)
        for gate in [c.REPOSITORY,'1455203884','refs/heads/ci-upstream-refresh','239840087','github.run_attempt == 1']:
            self.assertIn(gate,job['if'])
        self.assertNotIn('environment',job)

    def test_workflow_preserves_pins_credential_isolation_and_report_scope(self):
        job=self.workflow()['jobs']['research-loading'];steps=job['steps']
        uses=[s for s in steps if 'uses' in s]
        for step in uses:self.assertRegex(step['uses'],r'@[0-9a-f]{40}$')
        checkout=next(s for s in uses if s['uses'].startswith('actions/checkout@'))
        self.assertEqual(checkout['with']['ref'],'${{ github.sha }}')
        self.assertEqual(checkout['with']['persist-credentials'],'false')
        credential_steps=[s for s in steps if 'TRUSTED_RELEASE_TOKEN' in s.get('env',{})]
        self.assertEqual(len(credential_steps),1)
        self.assertIn('check_hosted_candidate_gradio.py',credential_steps[0]['run'])
        for step in steps:
            if 'run' not in step:continue
            self.assertNotIn('${{',step['run'])
            self.assertNotIn('sudo -E',step['run'])
            if 'check_hosted_candidate_gradio.py' in step['run']:
                for flag in ['--purpose RESEARCH_LOADING_ONLY','--authorized-review-sha256 "$AUTHORIZED_REVIEW_SHA256"',
                             '--expected-implementation-revision "$EXPECTED_IMPLEMENTATION_REVISION"']:
                    self.assertIn(flag,step['run'])
        retained=next(s for s in uses if s['uses'].startswith('actions/upload-artifact@'))
        self.assertEqual(retained['with']['path'],'${{ runner.temp }}/candidate-gradio-verification/verification.json')
        self.assertEqual(retained['if'],'always()')


if __name__=='__main__':unittest.main()
