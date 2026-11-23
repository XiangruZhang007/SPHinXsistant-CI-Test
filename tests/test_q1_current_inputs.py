"""Current-run descriptors; lightweight fixtures mock only the existing deep loader.

Real exact-pair reproduction is a separate recorded invocation on retained assets.
"""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from src import q1_current_inputs as q
from src import schema2_workflow as w
from src.corpus_snapshot import file_digest, read_json, write_json


class CurrentInputsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.bindings={'build_fingerprint':'f'*64,'parent_id':'parent',
            'candidate_id':'candidate','base_source_state':'base-source','target_source_state':'target-source',
            'base_upstreams':{'SPHinXsys':'a'*40},'target_upstreams':{'SPHinXsys':'b'*40}}
        for name,value in [('parent/manifest.json',{'identity':{'upstreams':self.bindings['base_upstreams']}}),
                           ('candidate/upstream-candidate.json',{'identity':{'upstreams':self.bindings['target_upstreams']}}),
                           ('parent-raw-results.json',[]),('quality/incremental-raw-results.json',[]),('benchmark.json',{})]:
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);write_json(path,value)
        for label,folder in [('base','parent'),('target','candidate')]:
            for suffix,name in [('corpus_sha256','corpus.jsonl'),('documentation_sha256','components/documentation.jsonl')]:
                path=self.root/folder/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixture\n')
                if suffix=='corpus_sha256':self.bindings[label+'_'+suffix]=file_digest(path)
            self.bindings[label+'_rows_sha256']=file_digest(self.root/('parent-raw-results.json' if label=='base' else 'quality/incremental-raw-results.json'))
        self.bindings['benchmark_sha256']=file_digest(self.root/'benchmark.json')

    def test_exact_current_paths_and_loader_called(self):
        with patch.object(q.q,'load_inputs') as load:
            manifest,pin=q.prepare(self.root,self.root,self.bindings)
        self.assertEqual(pin,file_digest(manifest));load.assert_called_once_with(self.root,manifest,pin)
        d=read_json(manifest);self.assertEqual(d['pins']['target_candidate_id'],'candidate')
        self.assertEqual(d['paths']['target_rows'],'quality/incremental-raw-results.json')
        self.assertNotIn('approval',d)

    def test_mismatched_byte_bindings_fail_before_descriptor(self):
        for key in ['base_corpus_sha256','target_corpus_sha256','base_rows_sha256','target_rows_sha256','benchmark_sha256']:
            with self.subTest(key=key):
                bindings={**self.bindings,key:'wrong'}
                with self.assertRaises(ValueError):q.prepare(self.root,self.root,bindings)
                self.assertFalse((self.root/'q1-auto-inputs.json').exists())

    def test_upstream_mismatch(self):
        with self.assertRaises(ValueError):q.prepare(self.root,self.root,{**self.bindings,'target_upstreams':{}})

    def test_missing_rows(self):
        (self.root/'quality/incremental-raw-results.json').unlink()
        with self.assertRaises(ValueError):q.prepare(self.root,self.root,self.bindings)

    def test_identity_mismatch_propagates_from_real_loader_boundary(self):
        for key in ['parent_id','candidate_id','base_source_state','target_source_state']:
            with self.subTest(key=key),patch.object(q.q,'load_inputs',side_effect=ValueError('Wrong version pair')):
                with self.assertRaises(ValueError):q.prepare(self.root,self.root,{**self.bindings,key:'wrong'})
                (self.root/'q1-auto-inputs.json').unlink()

    def test_existing_descriptor_not_overwritten(self):
        path=self.root/'q1-auto-inputs.json';path.write_bytes(b'original')
        with self.assertRaises(ValueError):q.prepare(self.root,self.root,self.bindings)
        self.assertEqual(path.read_bytes(),b'original')

    def test_duplicate_binding_json_rejected(self):
        (self.root/'parent/manifest.json').write_text('{"identity":{},"identity":{}}')
        with self.assertRaises(ValueError):q.prepare(self.root,self.root,self.bindings)

    def test_invalid_auto_inputs_remain_explicit_unqualified(self):
        spec={'questions':[{'id':'unit','evidence_mode':'ALL_OF','requirements':[]}]}
        row={'id':'unit','mode':'combined','strict':{'hit_at_5':False,'hit_at_10':False},'top_10':[]}
        with patch.object(q,'prepare',side_effect=ValueError('Current-run rows mismatch')):
            status,report=w.diagnostics(self.root,self.root,spec,[row],[row],{},automatic=True)
        self.assertEqual(status['status'],'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
        self.assertIn('rows mismatch',status['reason']);self.assertFalse(report['blocking'])
        self.assertFalse(report['automatic_research_approval'])

    def test_run_local_enables_auto_but_transport_api_remains_supported(self):
        source=Path(w.__file__).read_text();self.assertIn('q1_inputs=q1_inputs, q1_sha=q1_sha, automatic=True)',source)
        self.assertIn('if q1_inputs is None:',source)


    def test_unsupported_candidate_format_cannot_be_marked_qualified(self):
        (self.root/'candidate/upstream-candidate.json').unlink()
        with self.assertRaisesRegex(ValueError,'UNSUPPORTED_CANDIDATE_FORMAT'):
            q.prepare(self.root,self.root,self.bindings)
        self.assertFalse((self.root/'q1-auto-inputs.json').exists())

    def test_auto_helper_is_in_execution_contract(self):
        from src import continuous_execution
        self.assertIn('src/q1_current_inputs.py',continuous_execution.FILES)


    def test_unpaired_checksum_cannot_trigger_auto_fallback(self):
        spec={'questions':[{'id':'unit','evidence_mode':'ALL_OF','requirements':[]}]}
        row={'id':'unit','mode':'combined','strict':{'hit_at_5':False,'hit_at_10':False},'top_10':[]}
        with patch.object(q,'prepare') as prepare:
            status,_=w.diagnostics(self.root,self.root,spec,[row],[row],{},automatic=True,q1_sha='bad')
        prepare.assert_not_called();self.assertEqual(status['status'],'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
        self.assertIn('paired',status['reason'])


class FormatCompatibilityTests(unittest.TestCase):
    """Real independent verifiers; miniature Git/API fixtures, NOT Hosted proof.

    Existing factories perform small test-only builds and R2 computations. No
    retained scientific package is rebuilt, rescored by a new method or edited.
    """
    @classmethod
    def setUpClass(cls):
        import shutil
        import test_scheduled_construction as scheduled_fixtures
        from src import genuine_continuous_execution as continuous
        cls.schedule = scheduled_fixtures.ScheduledTests()
        scheduled_fixtures.ScheduledTests.setUpClass()
        cls.addClassCleanup(scheduled_fixtures.ScheduledTests.doClassCleanups)
        cls.schedule.setUp(); cls.addClassCleanup(cls.schedule.doCleanups)
        fixture = cls.schedule.fx
        cls.manual_project = fixture.project
        cls.manual_root = fixture.original / 'run'; cls.manual_pins = dict(fixture.pins)
        cls.scheduled_project, _ = cls.schedule.schedule()
        continuous.execute(cls.scheduled_project, fixture.detection_path,
            cls.schedule.root / 'q1-schedule-work', cls.schedule.root / 'q1-schedule-output')
        cls.scheduled_root = cls.schedule.root / 'q1-schedule-output/run'
        cls.scheduled_pins = read_json(cls.schedule.root / 'q1-schedule-output/verification-inputs.json')
        cls.fp = fixture.fp

    def setUp(self):
        import shutil
        self.temp = tempfile.TemporaryDirectory(prefix='q1-format-adapter-test-'); self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name); self.run = self.home / 'run'
        shutil.copytree(self.manual_root, self.run)
        self.project = Path(__file__).resolve().parents[1]; self.execution = dict(self.manual_pins)

    def bindings(self):
        from src import upstream_provenance as u, approval_evidence as ev
        meta = read_json(self.run / 'candidate/genuine-candidate.json')['identity']
        return {'build_fingerprint': self.fp, 'parent_id': meta['parent']['node_id'],
            'candidate_id': 'sha256-' + q.digest(meta), 'base_source_state': meta['parent']['source_state'],
            'target_source_state': meta['target_source_state'], 'base_upstreams': meta['parent']['upstreams'],
            'target_upstreams': meta['upstreams'], 'base_corpus_sha256': file_digest(self.run / 'parent/corpus.jsonl'),
            'target_corpus_sha256': file_digest(self.run / 'candidate/corpus.jsonl'),
            'base_rows_sha256': file_digest(self.run / 'evidence/parent-rows.json'),
            'target_rows_sha256': file_digest(self.run / 'quality/incremental-raw-results.json'),
            'benchmark_sha256': file_digest(self.project / ev.BENCHMARK)}

    def packages(self):
        from src import upstream_provenance as u
        p = u.verify(self.project, self.run / 'parent', self.fp)
        return {'base_manifest_sha256': file_digest(self.run / 'parent/checksums.json'),
            'target_manifest_sha256': self.execution['expected_manifest_sha256'],
            'base_package_checksum': p['receipt']['package_checksum']}

    def descriptor(self):
        return q.prepare(self.project, self.run, self.bindings(), package_pins=self.packages(),
                         execution_pins=self.execution, output=self.home)

    def modify_descriptor(self, change):
        manifest, _ = self.descriptor(); d = read_json(manifest); change(d); manifest.unlink(); write_json(manifest, d)
        return manifest, file_digest(manifest)

    def test_valid_v2_real_verifiers_no_api_no_replay_or_approval(self):
        from src import approval_evidence as ev, owner_manual_baseline_approval as owner
        before = {p.relative_to(self.run).as_posix(): file_digest(p) for p in self.run.rglob('*') if p.is_file()}
        with (patch.object(ev, 'replay', side_effect=AssertionError('No replay during Q1')),
              patch.object(owner, 'GitHubCLI', side_effect=AssertionError('No live authority during Q1'))):
            m, h = self.descriptor(); _, base, target, _, _ = q.q.load_inputs(self.project, m, h)
        self.assertEqual(base.origin['package_format'], 'schema2-research-baseline')
        self.assertEqual(target.origin['package_format'], 'genuine-continuous-candidate-v2')
        self.assertEqual(before, {p.relative_to(self.run).as_posix(): file_digest(p) for p in self.run.rglob('*') if p.is_file()})
        self.assertFalse((self.run / 'q1-auto-inputs.json').exists())
        self.assertEqual(read_json(self.run / 'q1-status.json')['status'], 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')

    def test_valid_v3_with_unchanged_full_run_verifier(self):
        import shutil
        shutil.rmtree(self.run); shutil.copytree(self.scheduled_root, self.run)
        self.execution = dict(self.scheduled_pins); self.project = Path(__file__).resolve().parents[1]
        m, h = self.descriptor(); _, _, target, _, _ = q.q.load_inputs(self.project, m, h)
        self.assertEqual(target.origin['package_format'], 'genuine-continuous-candidate-v3')

    def test_report_regeneration_deterministic_and_diagnostic_only(self):
        m, h = self.descriptor(); first = q.q.generate(self.project, m, h); second = q.q.generate(self.project, m, h)
        self.assertEqual(first, second)
        q.q.write_report(self.home / 'diagnosis', first)
        self.assertEqual(q.q.verify_report(self.project, m, h, self.home / 'diagnosis')['status'], 'VERIFIED')
        self.assertFalse(first['automatic_research_approval']); self.assertFalse(first['official_score_adjustment'])
        self.assertEqual(first['production_promotion'], 'NOT_AUTHORIZED')

    def test_independent_input_digest_required(self):
        m, h = self.descriptor()
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'): q.q.load_inputs(self.project, m, '0' * 64)

    def test_wrong_parent_candidate_source_revisions_and_fingerprint(self):
        for key in ('base_snapshot_id', 'target_candidate_id', 'base_source_state_id', 'target_source_state_id',
                    'base_upstreams', 'target_upstreams', 'build_fingerprint'):
            with self.subTest(key=key):
                m, h = self.modify_descriptor(lambda d: d['pins'].__setitem__(key, {} if key.endswith('upstreams') else 'wrong'))
                with self.assertRaises((ValueError, KeyError)): q.q.load_inputs(self.project, m, h)
                m.unlink()

    def test_wrong_corpus_documentation_rows_and_benchmark_pins(self):
        for key in ('base_corpus_sha256', 'target_corpus_sha256', 'base_documentation_sha256',
                    'target_documentation_sha256', 'base_rows_sha256', 'target_rows_sha256', 'benchmark_sha256'):
            with self.subTest(key=key):
                m, h = self.modify_descriptor(lambda d: d['pins'].__setitem__(key, '0' * 64))
                with self.assertRaises(ValueError): q.q.load_inputs(self.project, m, h)
                m.unlink()

    def test_missing_and_corrupt_package_seals(self):
        for rel in ('checksums.json', 'parent/checksums.json'):
            with self.subTest(rel=rel):
                path = self.run / rel; raw = path.read_bytes(); path.unlink()
                with self.assertRaises(ValueError): self.descriptor()
                path.write_bytes(raw + b' ')
                with self.assertRaises(ValueError): self.descriptor()
                path.write_bytes(raw)

    def test_full_parity_and_provenance_members_tampering_rejected(self):
        from src import continuous_execution as seal
        old = (self.run / 'checksums.json').read_bytes()
        for rel in ('parity.json', 'evidence/assessment.json', 'candidate/genuine-candidate.json',
                    'quality/incremental-raw-results.json'):
            with self.subTest(rel=rel):
                path = self.run / rel; raw = path.read_bytes(); path.write_bytes(b'{}\n')
                (self.run / 'checksums.json').unlink(); seal._seal(self.run); self.execution['expected_manifest_sha256'] = file_digest(self.run / 'checksums.json')
                with self.assertRaises((ValueError, KeyError)): self.descriptor()
                path.write_bytes(raw); (self.run / 'checksums.json').write_bytes(old)
        self.execution = dict(self.manual_pins)

    def test_incorrect_generation_and_lineage_rejected_after_new_outer_seal(self):
        from src import continuous_execution as seal
        path = self.run / 'candidate/genuine-candidate.json'; original = path.read_bytes()
        for field in ('generation', 'parent'):
            value = read_json(path)
            if field == 'generation': value['identity']['generation'] = 999
            else: value['identity']['parent']['generation'] = 999
            value['candidate_id'] = 'sha256-' + q.digest(value['identity'])
            self.execution['expected_candidate_id'] = value['candidate_id']
            path.unlink(); write_json(path, value); (self.run / 'checksums.json').unlink(); seal._seal(self.run)
            self.execution['expected_manifest_sha256'] = file_digest(self.run / 'checksums.json')
            with self.assertRaisesRegex(ValueError, 'GENERATION_MISMATCH'): self.descriptor()
            path.write_bytes(original)

    def test_unknown_or_incompatible_formats_and_approval_injection(self):
        for change in (
            lambda d: d['formats'].__setitem__('base', 'p2-snapshot-v1'),
            lambda d: d['formats'].__setitem__('target', 'continuous-controlled-candidate-v1'),
            lambda d: d['formats'].__setitem__('target', 'genuine-continuous-candidate-v3'),
            lambda d: d.__setitem__('approved', True),
            lambda d: d.__setitem__('schema_version', True)):
            m, h = self.modify_descriptor(change)
            with self.assertRaises(ValueError): q.q.load_inputs(self.project, m, h)
            m.unlink()

    def test_missing_pins_and_external_descriptor_requirement(self):
        with self.assertRaises(ValueError): q.prepare(self.project, self.run, self.bindings(), output=self.home)
        with self.assertRaises(ValueError): q.prepare(self.project, self.run, self.bindings(),
            package_pins=self.packages(), execution_pins=self.execution)
        self.assertFalse((self.run / 'q1-auto-inputs.json').exists())

    def test_safe_paths_no_symlink_or_parent_traversal(self):
        for path in ('../run/parent', '/tmp', 'run/../run/parent'):
            m, h = self.modify_descriptor(lambda d: d['paths'].__setitem__('base', path))
            with self.assertRaises(ValueError): q.q.load_inputs(self.project, m, h)
            m.unlink()
        (self.home / 'alias').symlink_to(self.run, target_is_directory=True)
        m, h = self.modify_descriptor(lambda d: d['paths'].__setitem__('base', 'alias/parent'))
        with self.assertRaises(ValueError): q.q.load_inputs(self.project, m, h)

    def test_historical_p2_genuine_shaped_package_with_real_loader(self):
        import shutil
        import test_parent_r2_anchor as ancestors
        from src import approval_evidence as ev
        root = self.home / 'historical'; root.mkdir()
        shutil.copytree(ancestors.AnchorTests.shared / 'p2', root / 'parent')
        shutil.copytree(self.schedule.fx.shared / 'new-parent-candidate', root / 'candidate')
        (root / 'quality').mkdir()
        shutil.copyfile(ancestors.AnchorTests.shared / 'p2-rows.json', root / 'parent-raw-results.json')
        shutil.copyfile(self.schedule.fx.shared / 'quality/incremental-raw-results.json', root / 'quality/incremental-raw-results.json')
        shutil.copyfile(self.project / ev.BENCHMARK, root / 'benchmark.json')
        meta = read_json(root / 'candidate/upstream-candidate.json'); i = meta['identity']
        bindings = {'build_fingerprint': self.fp, 'parent_id': i['base_snapshot_id'], 'candidate_id': meta['candidate_id'],
            'base_source_state': i['base_source_state'], 'target_source_state': i['target_source_state'],
            'base_upstreams': i['base_upstreams'], 'target_upstreams': i['upstreams'],
            'base_corpus_sha256': file_digest(root / 'parent/corpus.jsonl'),
            'target_corpus_sha256': file_digest(root / 'candidate/corpus.jsonl'),
            'base_rows_sha256': file_digest(root / 'parent-raw-results.json'),
            'target_rows_sha256': file_digest(root / 'quality/incremental-raw-results.json'),
            'benchmark_sha256': file_digest(root / 'benchmark.json')}
        m, h = q.prepare(self.project, root, bindings)
        self.assertEqual(read_json(m)['schema_version'], 1)
        self.assertEqual(q.q.load_inputs(self.project, m, h)[1].origin['verification'], 'VERIFIED_P2_P5A1_PAIR')

    def test_research_baseline_to_upstream_candidate_real_proofs(self):
        import base64, shutil
        from test_upstream_provenance import policy_for
        from src import upstream_provenance as u, approval_evidence as ev
        root = self.home / 'upstream'; root.mkdir(); shutil.copytree(self.run / 'parent', root / 'parent')
        source = self.schedule.fx.factory.target; base = self.schedule.fx.factory.base
        revisions = self.schedule.fx.factory.revisions; pubs = {}
        parent = u.verify(self.project, root / 'parent', self.fp)
        for repo, url in u.REPOSITORIES.items():
            full = url.removeprefix('https://github.com/').removesuffix('.git'); pubs[repo] = {}
            for oid in {parent['upstreams'][repo], revisions[repo]}:
                tree, parents = u._commit(u._git(source / 'repos' / repo, 'cat-file', 'commit', oid))
                raw = json.dumps({'sha': oid, 'html_url': 'https://github.com/' + full + '/commit/' + oid,
                    'commit': {'tree': {'sha': tree}}, 'parents': [{'sha': p} for p in parents]}).encode()
                pubs[repo][oid] = {'api_url': 'https://api.github.com/repos/' + full + '/commits/' + oid,
                    'response_base64': base64.b64encode(raw).decode(), 'response_sha256': q.q.sha(raw)}
        policy = policy_for(root / 'parent', base, source, revisions, self.fp, genuine=True, publications=pubs)
        policy['experiment_id'] = 'Q1_ADAPTER_SYNTHETIC_PUBLICATION_FIXTURE_NOT_OWNER_APPROVAL'
        path = self.home / 'fixture-exact-policy.json'; write_json(path, policy)
        u.build(self.project, root / 'parent', base, source, root / 'candidate', policy_path=path,
                expected_policy_sha256=file_digest(path), expected_fingerprint=self.fp)
        self.assertEqual(file_digest(root / 'candidate/corpus.jsonl'), file_digest(self.run / 'candidate/corpus.jsonl'))
        (root / 'quality').mkdir()
        shutil.copyfile(self.run / 'evidence/parent-rows.json', root / 'parent-raw-results.json')
        shutil.copyfile(self.run / 'quality/incremental-raw-results.json', root / 'quality/incremental-raw-results.json')
        meta = read_json(root / 'candidate/upstream-candidate.json'); i = meta['identity']
        bindings = {**self.bindings(), 'candidate_id': meta['candidate_id'], 'parent_id': i['base_snapshot_id']}
        pins = {'base_manifest_sha256': file_digest(root / 'parent/checksums.json'),
            'target_manifest_sha256': file_digest(root / 'candidate/checksums.json'),
            'base_package_checksum': parent['receipt']['package_checksum']}
        m, h = q.prepare(self.project, root, bindings, package_pins=pins)
        _, b, t, _, _ = q.q.load_inputs(self.project, m, h)
        self.assertEqual(b.origin['package_format'], 'schema2-research-baseline')
        self.assertEqual(t.origin['package_format'], 'upstream-research-candidate')


    def test_ambiguous_markers_rejected_by_helper_and_reader(self):
        m, h = self.descriptor()
        (self.run / 'candidate/upstream-candidate.json').write_text('{}\n')
        with self.assertRaisesRegex(ValueError, 'ambiguous'): self.descriptor()
        with self.assertRaisesRegex(ValueError, 'Ambiguous'): q.q.load_inputs(self.project, m, h)

    def test_legacy_preparation_rejects_ambiguous_markers(self):
        import shutil
        import test_parent_r2_anchor as ancestors
        root = self.home / 'mixed'; root.mkdir()
        shutil.copytree(ancestors.AnchorTests.shared / 'p2', root / 'parent')
        shutil.copytree(self.schedule.fx.shared / 'new-parent-candidate', root / 'candidate')
        (root / 'candidate/genuine-candidate.json').write_text('{}\n')
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            q.prepare(self.project, root, {})
