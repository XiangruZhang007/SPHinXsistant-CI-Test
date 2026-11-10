"""Frozen 128-row evaluation on miniature Corpora; no real benchmark reruns."""
import copy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scripts import ci_v2_schema2_research as cli
from src import parent_r2_anchor as anchor, schema2_workflow as w
from src import approval_evidence as ev, upstream_provenance as u, ci_v2_research as c
from src import continuous_corpus as chain, incremental_corpus as inc
from src.corpus_snapshot import digest, file_digest, read_json
from src.corpus_snapshot_build import build_full_snapshot
from src.research_quality import evaluate_quality
from test_continuous_corpus import reference, entry, structural_approval, write_json
from test_incremental_corpus import make_sources
from test_upstream_provenance import git, commit, policy_for
from test_trusted_snapshot import pack

P = Path(__file__).resolve().parents[1]


class StopAfterAnchor(RuntimeError):
    pass


class AnchorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory(); cls.addClassCleanup(tmp.cleanup)
        r = cls.shared = Path(tmp.name); source = r / 'source0'; make_sources(source)
        cls.revs = {}
        for repo, url in u.REPOSITORIES.items():
            root = source / 'repos' / repo; git(root, 'init'); git(root, 'remote', 'add', 'origin', url)
            cls.revs[repo] = commit(root)
        lock = c.read(c.LOCK); cls.fp = digest(lock['P2']); cls.spec = read_json(P / ev.BENCHMARK)
        selection, _ = u.verify_sources(P, source, cls.revs)
        build_full_snapshot(P, source, r / 'p2', {'chunker_commit': lock['external_chunker_commit'],
            'project_head': 'EXPLICIT_R2_ANCHOR_SYNTHETIC_FIXTURE', 'build_contract': lock['P2'],
            'upstreams': cls.revs, 'selection': selection}, identity_scheme='portable-v1')
        pack(r / 'p2', r / 'p2.tar.gz')
        original = ev.replay(cls.spec, r / 'p2/corpus.jsonl', r / 'p2/components/documentation.jsonl')
        write_json(r / 'p2-rows.json', original)
        cls.p2ref = reference(r / 'p2', r / 'p2.tar.gz', cls.fp)
        cls.p2ref['parent_rows_sha256'] = file_digest(r / 'p2-rows.json')
        shutil.copytree(source, r / 'source1')
        path = r / 'source1/repos/SPHinXsim/docs/cli-usage.md'
        path.write_text('# CLI usage\n\nUse sphinxsim to run simulations, configure JSON cases and validate input.\n')
        cls.revs['SPHinXsim'] = commit(r / 'source1/repos/SPHinXsim')
        policy = policy_for(r / 'p2', source, r / 'source1', cls.revs, cls.fp)
        write_json(r / 'build-policy.json', policy)
        u.build(P, r / 'p2', source, r / 'source1', r / 'candidate', policy_path=r / 'build-policy.json',
                expected_policy_sha256=file_digest(r / 'build-policy.json'), expected_fingerprint=cls.fp)
        u.full_reference(P, r / 'source1', r / 'full', cls.revs, cls.fp)
        candidate = read_json(r / 'candidate/upstream-candidate.json'); identity = candidate['identity']
        raw = r / 'raw'; raw.mkdir()
        for name in ev.RAW_FILES[2:]: write_json(raw / name, original)
        ap = {'schema_version': 1, 'mode': 'RETRIEVAL_EVALUATED',
            'scope': {'experiment_id': 'EXPLICIT_R2_ANCHOR_SYNTHETIC_FIXTURE',
                      'parent_baseline_id': identity['parent']['node_id'],
                      'target_source_state': identity['target_source_state'],
                      'build_fingerprint': cls.fp, 'quality_policy_sha256': digest(lock['quality_policy'])},
            'reference_rows_sha256': {name: file_digest(raw / name) for name in ev.RAW_FILES[2:]},
            'quality_status': 'QUALITY_REVIEW_REQUIRED', 'automatic_reuse': False,
            'production_promotion': 'NOT_AUTHORIZED'}
        write_json(r / 'approval-policy.json', ap)
        quality = evaluate_quality(P, r / 'candidate', r / 'full', r / 'evaluation',
            benchmark=P / ev.BENCHMARK, policy=lock['quality_policy'], expected_fingerprint=cls.fp,
            historical_rows=original, parent_rows=original, parent_corpus=r / 'p2/corpus.jsonl', parent_sources=source)
        for name in ev.RAW_FILES[:2]: shutil.copy2(r / 'evaluation' / name, raw / name)
        write_json(raw / 'inputs.json', ev.input_manifest(r / 'candidate', r / 'full', quality,
            file_digest(r / 'approval-policy.json'), raw))
        auth = {'schema_version': 1, 'research_only': True, 'approved': True,
            'candidate_id': candidate['candidate_id'], 'parent_baseline_id': identity['parent']['node_id'],
            'experiment_id': ap['scope']['experiment_id'], 'quality_status': 'QUALITY_REVIEW_REQUIRED',
            'allow_quality_review': True}
        u.approve(P, r / 'candidate', r / 'p2', r / 'full', r / 'approved',
            expected_fingerprint=cls.fp, quality=quality, authorization=auth,
            approval_policy=r / 'approval-policy.json', expected_policy_sha256=file_digest(r / 'approval-policy.json'),
            evidence=raw)
        pack(r / 'approved', r / 'approved.tar.gz')
        cls.ref = reference(r / 'approved', r / 'approved.tar.gz', cls.fp)
        cls.ref['parent_rows_sha256'] = file_digest(raw / ev.RAW_FILES[0])
        structural = r / 'structural'; structural.mkdir()
        structural_approval(structural, r / 'candidate', r / 'p2', r / 'source1', cls.revs, cls.fp)
        pack(structural / 'c1', r / 'structural.tar.gz')
        cls.structural_ref = reference(structural / 'c1', r / 'structural.tar.gz', cls.fp)
        cls.structural_ref['parent_rows_sha256'] = cls.ref['parent_rows_sha256']

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup); self.root = Path(tmp.name)
        shutil.copytree(self.shared / 'approved', self.root / 'parent')
        shutil.copyfile(self.shared / 'raw' / ev.RAW_FILES[0], self.root / 'rows.json')
        self.ref = copy.deepcopy(type(self).ref)

    def qualify(self, *, fresh=False, pin=True, controlled=True):
        return anchor.qualify_parent_anchor(P, self.root / 'parent', self.ref,
            digest(self.ref) if pin else None, self.root / 'rows.json',
            fresh_replay=fresh, controlled=controlled)

    def test_evaluated_synthetic_qualification_and_distinct_candidate_baseline_ids(self):
        result = self.qualify()
        self.assertEqual(result['status'], 'QUALIFIED')
        self.assertEqual(result['execution'], 'NO_FRESH_REPLAY')
        self.assertNotEqual(result['bindings']['baseline_id'], result['bindings']['candidate_id'])
        self.assertEqual(result['bindings']['baseline_id'], self.ref['node_id'])
        self.assertEqual(len(result['rows']), 128)
        self.assertNotEqual(result['historical_rows'], result['rows'])
        self.assertEqual(result['bindings']['historical_rows_sha256'], self.p2ref['parent_rows_sha256'])
        self.assertEqual(result['quality_acceptance'], 'NOT_GRANTED')
        self.assertEqual(result['production_promotion'], 'NOT_AUTHORIZED')
        path = os.environ.get('SPHINX_R2_ANCHOR_EVIDENCE')
        if path:
            destination = Path(path).resolve(); self.assertTrue(destination.is_relative_to(P / 'doc/artifacts'))
            with (destination / 'synthetic-qualification.json').open('x') as stream:
                json.dump({k: v for k, v in result.items() if k not in ('rows', 'historical_rows', 'spec')}, stream, indent=2)

    def test_fresh_miniature_replay_matches_sealed_inspection(self):
        stored, fresh = self.qualify(), self.qualify(fresh=True)
        self.assertEqual(stored['bindings'], fresh['bindings'])
        self.assertEqual(fresh['execution'], 'FRESH_R2_REPLAY_VERIFIED')

    def test_no_fresh_replay_during_sealed_inspection(self):
        with patch.object(ev, 'replay', side_effect=AssertionError('Unexpected retrieval execution')):
            self.qualify()

    def test_fresh_replay_mismatch_remains_mandatory_failure(self):
        with patch.object(ev, 'replay', return_value=[]), self.assertRaises(c.GateError) as caught:
            self.qualify(fresh=True)
        self.assertEqual(caught.exception.status, 'RETRIEVAL_EXECUTION_FAILED')

    def test_missing_or_untrusted_reference_cannot_qualify_research_parent(self):
        with self.assertRaises(c.GateError): self.qualify(pin=False)
        with self.assertRaises(ValueError): self.qualify(controlled=False)
        with self.assertRaises(ValueError):
            anchor.qualify_parent_anchor(P, self.root / 'parent', self.ref, '0' * 64,
                                        self.root / 'rows.json', controlled=True)

    def test_wrong_parent_corpus_commits_and_result_digest(self):
        for field, value in [('node_id', 'sha256-' + '0' * 64), ('corpus_sha256', '0' * 64),
                ('upstreams', {'SPHinXsys': '0' * 40, 'SPHinXsim': '1' * 40}),
                ('parent_rows_sha256', '0' * 64), ('build_fingerprint', '0' * 64),
                ('manifest_sha256', '0' * 64)]:
            self.ref = copy.deepcopy(type(self).ref); self.ref[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.qualify()

    def test_structural_only_approval_cannot_qualify(self):
        with self.assertRaisesRegex(ValueError, 'Structural-only'):
            anchor.qualify_parent_anchor(P, self.shared / 'structural/c1', self.structural_ref,
                digest(self.structural_ref), self.root / 'rows.json', fresh_replay=False, controlled=True)

    def test_unapproved_candidate_cannot_qualify(self):
        with self.assertRaises(ValueError):
            anchor.qualify_parent_anchor(P, self.shared / 'candidate', self.ref, digest(self.ref),
                                        self.root / 'rows.json', fresh_replay=False, controlled=True)

    def test_bad_benchmark_retriever_configuration_and_quality_policy(self):
        original = anchor.read_json; lock = c.read(c.LOCK)
        for kind in ('benchmark', 'retriever', 'configuration', 'quality_policy'):
            wrong = copy.deepcopy(lock)
            if kind == 'benchmark': wrong['quality_policy']['benchmark_sha256'] = '0' * 64
            elif kind == 'retriever': wrong['quality_policy']['R2_fingerprint']['fingerprint'] = '0' * 64
            elif kind == 'configuration': wrong['quality_policy']['R2_fingerprint']['inputs']['exclusion_contract'] = {}
            else: wrong['quality_policy']['historical_quality'] = 'UNSUPPORTED'
            def read(path): return wrong if Path(path) == c.LOCK else original(path)
            with self.subTest(kind=kind), patch.object(anchor, 'read_json', side_effect=read), self.assertRaises(ValueError):
                self.qualify()

    def test_missing_malformed_duplicate_and_conflicting_rows(self):
        target = self.root / 'rows.json'; original = read_json(target)
        for value in ('{', '[]', json.dumps(original + [original[0]])):
            target.write_text(value); self.ref['parent_rows_sha256'] = file_digest(target)
            with self.subTest(value=value[:10]), self.assertRaises(ValueError): self.qualify()
        target.unlink()
        with self.assertRaises(ValueError): self.qualify()

    def test_corrupt_result_evidence_and_summary_rejected(self):
        bundle = self.root / 'parent/approval-evidence'
        for name in ('verification.json', 'recomputed.json'):
            raw = (bundle / name).read_bytes(); (bundle / name).write_text('{}')
            with self.subTest(name=name), self.assertRaises(ValueError): self.qualify()
            (bundle / name).write_bytes(raw)

    def test_qualified_parent_feeds_existing_incremental_path(self):
        self.qualify()
        write_json(self.root / 'registry.json', {'schema_version': 2, 'baselines': {'research': entry(self.ref)}})
        policy = policy_for(self.root / 'parent', self.shared / 'source1', self.shared / 'source1', self.revs, self.fp)
        write_json(self.root / 'policy.json', policy)
        result = chain.build_next(P, self.root / 'registry.json', 'research', digest(self.ref), self.root / 'parent',
            self.shared / 'source1', self.shared / 'source1', self.root / 'next', self.root / 'policy.json',
            file_digest(self.root / 'policy.json'), controlled=True)
        self.assertEqual(result['parent']['node_id'], self.ref['node_id'])
        self.assertEqual(result['reuse']['actual_extraction_invocations'], 0)
        self.assertEqual(result['reuse']['selected_files'], result['reuse']['reused_files'])
        self.assertFalse(result['research_baseline_created'])
        self.assertEqual(result['production_promotion'], 'NOT_AUTHORIZED')

    def test_p2_external_and_archive_integrity_compatibility(self):
        for pin, status in [(digest(self.p2ref), 'QUALIFIED'), (None, 'ARCHIVE_INTEGRITY_VERIFIED')]:
            result = anchor.qualify_parent_anchor(P, self.shared / 'p2', self.p2ref, pin,
                self.shared / 'p2-rows.json', controlled=True)
            self.assertEqual(result['status'], status)
            self.assertEqual(result['rows'], result['historical_rows'])

    def test_run_and_archive_routes_call_same_real_core(self):
        # Stop immediately after actual qualification; no downstream build/replay.
        calls = []
        def verify(*args, **kwargs):
            result = anchor.qualify_parent_anchor(*args, **kwargs)
            calls.append(result['bindings'])
            raise StopAfterAnchor()
        policy = read_json(self.shared / 'build-policy.json'); policy['provenance_type'] = 'GENUINE_UPSTREAM'
        write_json(self.root / 'policy.json', policy)
        with patch.object(w, 'qualify_parent_anchor', side_effect=verify), self.assertRaises(StopAfterAnchor):
            w.run_local(P, self.shared / 'p2.tar.gz', self.shared / 'source0', self.shared / 'source1',
                self.root / 'live', self.p2ref, digest(self.p2ref), self.root / 'policy.json',
                file_digest(self.root / 'policy.json'), self.shared / 'p2-rows.json')
        result = {**c.RESTRICTIONS, 'RESEARCH_BASELINE_APPROVED': False, 'RETRIEVAL_QUALITY_ACCEPTED': False}
        write_json(self.root / 'live/result.json', result); u._seal(self.root / 'live')
        with patch.object(w, 'qualify_parent_anchor', side_effect=verify), self.assertRaises(StopAfterAnchor):
            w.verify_run(P, self.root / 'live')
        self.assertEqual(len(calls), 2); self.assertEqual(calls[0], calls[1])

    def test_archive_and_live_routes_reject_same_bad_rows_before_build(self):
        policy = read_json(self.shared / 'build-policy.json'); policy['provenance_type'] = 'GENUINE_UPSTREAM'
        write_json(self.root / 'policy.json', policy)
        (self.root / 'rows.json').write_text('[]')
        with patch.object(u, 'build') as build, self.assertRaises(c.GateError) as live:
            w.run_local(P, self.shared / 'p2.tar.gz', self.shared / 'source0', self.shared / 'source1',
                self.root / 'live', self.p2ref, digest(self.p2ref), self.root / 'policy.json',
                file_digest(self.root / 'policy.json'), self.root / 'rows.json')
        build.assert_not_called()
        # The live preflight may reject before creating its output. Build an
        # isolated minimal archive to exercise the shared archive rejection.
        r = self.root / 'archive'; r.mkdir(); shutil.copytree(self.shared / 'p2', r / 'parent')
        write_json(r / 'result.json', {**c.RESTRICTIONS, 'RESEARCH_BASELINE_APPROVED': False, 'RETRIEVAL_QUALITY_ACCEPTED': False})
        write_json(r / 'trusted-reference.json', self.p2ref); (r / 'parent-raw-results.json').write_text('[]'); u._seal(r)
        with self.assertRaises(c.GateError) as archived: w.verify_run(P, r)
        self.assertEqual(live.exception.status, archived.exception.status)

    def test_verify_cli_propagates_independent_pin(self):
        with patch.object(w, 'verify_run', return_value={}) as verify, redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['verify-run', '--root', 'archive', '--expected-reference-sha256', 'a' * 64]), 0)
        verify.assert_called_once_with(P, Path('archive'), expected_ref_sha='a' * 64)

    def test_verify_cli_without_pin_preserves_archive_inspection_default(self):
        with patch.object(w, 'verify_run', return_value={}) as verify, redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['verify-run', '--root', 'archive']), 0)
        verify.assert_called_once_with(P, Path('archive'), expected_ref_sha=None)

    def test_archived_new_binding_record_cannot_conflict_with_shared_verifier(self):
        r = self.root / 'archive'; r.mkdir(); shutil.copytree(self.shared / 'p2', r / 'parent')
        write_json(r / 'result.json', {**c.RESTRICTIONS, 'RESEARCH_BASELINE_APPROVED': False,
            'RETRIEVAL_QUALITY_ACCEPTED': False, 'parent_r2_anchor': {'baseline_id': 'wrong'}})
        write_json(r / 'trusted-reference.json', self.p2ref)
        shutil.copyfile(self.shared / 'p2-rows.json', r / 'parent-raw-results.json'); u._seal(r)
        with patch.object(u, 'verify') as candidate_verify, self.assertRaises(c.GateError) as caught:
            w.verify_run(P, r)
        candidate_verify.assert_not_called()
        self.assertEqual(caught.exception.status, 'INVALID_CANDIDATE')


if __name__ == '__main__': unittest.main()
