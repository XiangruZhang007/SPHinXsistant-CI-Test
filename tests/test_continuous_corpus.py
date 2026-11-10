"""Real miniature incremental chains; approvals are explicit synthetic fixtures."""
import copy
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import ci_v2_schema2_research as cli
from src import continuous_corpus as chain, trusted_snapshot as trust, upstream_provenance as u
from src import ci_v2_research as c, incremental_corpus as inc
from src.corpus_snapshot import digest, file_digest, read_json
from src.corpus_snapshot_build import build_full_snapshot
from src.research_baseline import read_parent
from src.research_quality import review_not_evaluated
from test_incremental_corpus import make_sources
from test_upstream_provenance import commit, git, policy_for
from test_trusted_snapshot import pack

P = Path(__file__).resolve().parents[1]


def write_json(path, value):
    # Deliberate mutations are confined to this suite's disposable fixtures.
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def reference(root, archive, fp):
    research = (root / 'upstream-candidate.json').exists()
    if research:
        report = u.verify(P, root, fp)
        node, package, commits = report['node_id'], report['receipt']['package_checksum'], report['upstreams']
    else:
        report = read_parent(P, root, fp, baseline_format='p2')
        node, package, commits = report['baseline_id'], report['package_checksum'], report['upstreams']
    return {'schema_version': 2, 'package_format': 'schema2-research-baseline' if research else 'p2-snapshot-v1',
        'accepted_package_schema': 2 if research else 1, 'node_id': node, 'package_checksum': package,
        'manifest_sha256': file_digest(root / 'checksums.json'), 'transport_sha256': file_digest(archive),
        'source_state': u.state(read_json(root / 'selection.json')), 'upstreams': commits,
        'build_fingerprint': fp, 'corpus_sha256': file_digest(root / 'corpus.jsonl'),
        'parent_rows_sha256': '0' * 64,  # Unused: this is build-only, never a hosted R2 anchor.
        'storage': {'kind': 'LOCAL_QUALIFICATION_ONLY'},
        'authorization': {'type': 'EXPLICIT_RESEARCH_BASELINE_REUSE' if research else 'EXPLICIT_P2_BOOTSTRAP',
            'scope': 'ISOLATED_RESEARCH_PARENT_REUSE', 'research_only': True,
            'experiment_id': 'EXPLICIT_SYNTHETIC_CHAIN_TEST', 'automatic_research_approval': False,
            'production_promotion': 'NOT_AUTHORIZED'}}


def entry(ref):
    return {'reference': ref, 'expected_reference_sha256': digest(ref)}


def structural_approval(root, candidate, parent, source, revisions, fp):
    """Existing P4.1 procedure and miniature full parity; no new acceptance rules."""
    u.full_reference(P, source, root / 'full', revisions, fp)
    metadata = read_json(candidate / 'upstream-candidate.json'); identity = metadata['identity']
    quality = review_not_evaluated(candidate, fp, c.read(c.LOCK)['quality_policy'])
    authorization = {'schema_version': 1, 'research_only': True, 'approved': True,
        'candidate_id': metadata['candidate_id'], 'parent_baseline_id': identity['parent']['node_id'],
        'experiment_id': 'EXPLICIT_SYNTHETIC_CHAIN_TEST', 'quality_status': 'QUALITY_REVIEW_REQUIRED',
        'allow_quality_review': True}
    policy = {'schema_version': 1, 'scope': {'experiment_id': authorization['experiment_id'],
        'parent_baseline_id': authorization['parent_baseline_id'], 'target_source_state': identity['target_source_state'],
        'build_fingerprint': fp, 'quality_policy_sha256': digest(quality['policy'])},
        'mode': 'STRUCTURAL_ONLY', 'quality_status': 'QUALITY_REVIEW_REQUIRED',
        'automatic_reuse': False, 'production_promotion': 'NOT_AUTHORIZED'}
    write_json(root / 'approval-policy.json', policy)
    return u.approve(P, candidate, parent, root / 'full', root / 'c1', expected_fingerprint=fp,
        quality=quality, authorization=authorization, approval_policy=root / 'approval-policy.json',
        expected_policy_sha256=file_digest(root / 'approval-policy.json'))


class ChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory(); cls.addClassCleanup(tmp.cleanup)
        r = cls.shared = Path(tmp.name)
        cls.fp = digest(inc.current_contract(P))
        source = r / 'source0'; make_sources(source)
        revisions = {}
        for repo, url in u.REPOSITORIES.items():
            root = source / 'repos' / repo
            git(root, 'init'); git(root, 'remote', 'add', 'origin', url)
            revisions[repo] = commit(root)
        selection, _ = u.verify_sources(P, source, revisions)
        contract = inc.current_contract(P)
        build_full_snapshot(P, source, r / 'c0', {'chunker_commit': contract['external_chunker_commit'],
            'project_head': 'EXPLICIT_SYNTHETIC_CHAIN_TEST', 'build_contract': contract,
            'upstreams': revisions, 'selection': selection}, identity_scheme='portable-v1')
        pack(r / 'c0', r / 'c0.tar.gz')
        ref0 = reference(r / 'c0', r / 'c0.tar.gz', cls.fp)
        write_json(r / 'registry.json', {'schema_version': 2, 'baselines': {'c0': entry(ref0)}})
        shutil.copytree(source, r / 'source1')
        path = r / 'source1/repos/SPHinXsys/src/a.cpp'; path.write_text('int a() { return 21; }\n')
        revisions['SPHinXsys'] = commit(path.parent.parent)
        policy = policy_for(r / 'c0', source, r / 'source1', revisions, cls.fp)
        write_json(r / 'policy0.json', policy)
        cls.first = chain.build_next(P, r / 'registry.json', 'c0', digest(ref0), r / 'c0',
            source, r / 'source1', r / 'first', r / 'policy0.json', file_digest(r / 'policy0.json'), controlled=True)
        approved = structural_approval(r, r / 'first/candidate', r / 'c0', r / 'source1', revisions, cls.fp)
        assert approved['P4_1_verification'] == 'P4_1_VERIFIED'
        pack(r / 'c1', r / 'c1.tar.gz')
        ref1 = reference(r / 'c1', r / 'c1.tar.gz', cls.fp)
        cls.registry = {'schema_version': 2, 'baselines': {'c0': entry(ref0), 'c1': entry(ref1)}}
        write_json(r / 'registry.json', cls.registry)
        shutil.copytree(r / 'source1', r / 'source2')
        path = r / 'source2/repos/SPHinXsim/sphinxsim/bindings/a.py'; path.write_text('def f():\n    return 33\n')
        revisions['SPHinXsim'] = commit(path.parents[2])
        cls.revisions = revisions

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for name in ('c0', 'c1', 'source0', 'source1', 'source2'):
            shutil.copytree(self.shared / name, self.root / name)
        write_json(self.root / 'registry.json', self.registry)
        self.key = 'c1'
        self.ref = copy.deepcopy(self.registry['baselines']['c1']['reference'])
        self.pin = digest(self.ref)
        self.policy = policy_for(self.root / 'c1', self.root / 'source1', self.root / 'source2', self.revisions, self.fp)
        write_json(self.root / 'policy.json', self.policy)

    def select(self):
        return chain.select_parent(P, self.root / 'registry.json', self.key, self.pin, self.root / 'c1', controlled=True)

    def build(self, output='next', controlled=True):
        return chain.build_next(P, self.root / 'registry.json', self.key, self.pin, self.root / 'c1',
            self.root / 'source1', self.root / 'source2', self.root / output,
            self.root / 'policy.json', file_digest(self.root / 'policy.json'), controlled=controlled)

    def change_ref(self, change):
        change(self.ref)
        value = copy.deepcopy(self.registry); value['baselines']['c1'] = entry(self.ref)
        write_json(self.root / 'registry.json', value); self.pin = digest(self.ref)

    def test_actual_c0_c1_c2_chain_and_immediate_parent_reuse(self):
        before = file_digest(self.root / 'c1/checksums.json')
        result = self.build()
        self.assertEqual(self.first['parent']['node_id'], self.registry['baselines']['c0']['reference']['node_id'])
        self.assertEqual(result['parent']['node_id'], self.ref['node_id'])
        self.assertNotEqual(result['parent']['node_id'], self.first['parent']['node_id'])
        self.assertEqual(result['candidate']['generation'], 2)
        self.assertEqual(result['candidate']['upstreams'], self.revisions)
        self.assertEqual(result['reuse']['actual_extraction_invocations'], 1)
        self.assertGreater(result['reuse']['reused_files'], 0)
        candidate = self.root / 'next/candidate'
        self.assertEqual((candidate / 'components/sys.jsonl').read_bytes(),
                         (self.root / 'c1/components/sys.jsonl').read_bytes())
        self.assertNotEqual((candidate / 'components/sys.jsonl').read_bytes(),
                            (self.root / 'c0/components/sys.jsonl').read_bytes())
        self.assertIn('return 21', (candidate / 'corpus.jsonl').read_text())
        self.assertIn('return 33', (candidate / 'corpus.jsonl').read_text())
        u.full_reference(P, self.root / 'source2', self.root / 'full2', self.revisions, self.fp)
        parity = u.compare_full(P, candidate, self.root / 'full2', self.fp)
        self.assertEqual(parity['status'], 'PARITY_PASS')
        self.assertEqual(before, file_digest(self.root / 'c1/checksums.json'))
        self.assertFalse(result['research_baseline_created'])
        self.assertFalse((candidate / 'upstream-baseline.json').exists())
        self.assertEqual(result['production_promotion'], 'NOT_AUTHORIZED')
        evidence = os.environ.get('SPHINX_CHAIN_EVIDENCE')
        if evidence:
            target = Path(evidence).resolve()
            self.assertTrue(target.is_relative_to(P / 'doc/artifacts'))
            value = {'transitions': [self.first, result], 'actual_incremental_parent_input': 'VERIFIED',
                'approved_c1_candidate_id': u.verify(P, self.root / 'c1', self.fp)['candidate_id'],
                'c1_acceptance': 'EXISTING_P4_1_STRUCTURAL_ONLY_SYNTHETIC_FIXTURE',
                'c2_full_parity': parity, 'hosted_validation': 'NOT_EXECUTED',
                'retrieval': 'NOT_EXECUTED', 'production_promotion': 'NOT_AUTHORIZED'}
            with (target / 'chain-validation.json').open('x') as stream: json.dump(value, stream, indent=2)

    def test_repeated_build_is_deterministic(self):
        self.assertEqual(self.build('one'), self.build('two'))

    def test_missing_key_has_no_bootstrap_fallback(self):
        self.key = 'unavailable'
        with patch.object(u, 'build') as build, self.assertRaisesRegex(ValueError, 'no bootstrap fallback'):
            self.build()
        build.assert_not_called(); self.assertFalse((self.root / 'next').exists())

    def test_independent_pin_is_mandatory(self):
        for pin in (None, '', '0' * 64):
            self.pin = pin
            with self.subTest(pin=pin), self.assertRaises(ValueError): self.select()

    def test_reference_bindings_rejected(self):
        for field, bad in [('node_id', 'sha256-' + 'f' * 64), ('corpus_sha256', 'f' * 64),
                ('manifest_sha256', 'f' * 64), ('source_state', 'sha256-' + 'f' * 64),
                ('package_checksum', 'f' * 64), ('build_fingerprint', 'f' * 64),
                ('upstreams', {'SPHinXsys': 'f' * 40, 'SPHinXsim': 'e' * 40}),
                ('accepted_package_schema', 1), ('schema_version', 99)]:
            with self.subTest(field=field):
                self.ref = copy.deepcopy(self.registry['baselines']['c1']['reference'])
                self.change_ref(lambda ref: ref.update({field: bad}))
                with self.assertRaises((ValueError, KeyError)): self.select()

    def test_missing_corrupt_and_incomplete_parent(self):
        parent = self.root / 'c1'
        (parent / 'corpus.jsonl').write_text('corrupt\n')
        with self.assertRaises(ValueError): self.select()
        shutil.rmtree(parent)
        with self.assertRaises(ValueError): self.select()
        parent.mkdir(); (parent / 'metadata.json').write_text('{}')
        with self.assertRaises((ValueError, OSError)): self.select()

    def test_corrupted_snapshot_schema_and_lineage_metadata(self):
        original = (self.root / 'c1/upstream-baseline.json').read_bytes()
        for field, bad in [('schema_version', 99), ('baseline_id', self.first['parent']['node_id'])]:
            value = json.loads(original); value[field] = bad
            write_json(self.root / 'c1/upstream-baseline.json', value)
            with self.subTest(field=field), self.assertRaises(ValueError): self.select()

    def test_duplicate_nodes_and_unsupported_registry(self):
        duplicate = copy.deepcopy(self.registry)
        duplicate['baselines']['alias'] = duplicate['baselines']['c1']
        for value in (duplicate, {'schema_version': 1, 'baselines': {}},
                      {'schema_version': True, 'baselines': {}}, {'schema_version': 2, 'baselines': []}, []):
            write_json(self.root / 'registry.json', value)
            with self.subTest(value=value), self.assertRaises(ValueError): self.select()

    def test_malformed_reference_structures_fail_closed(self):
        for field in ('upstreams', 'authorization', 'storage'):
            self.ref = copy.deepcopy(self.registry['baselines']['c1']['reference'])
            self.change_ref(lambda ref: ref.update({field: []}))
            with self.subTest(field=field), self.assertRaises(ValueError): self.select()

    def test_duplicate_json_keys_rejected(self):
        (self.root / 'registry.json').write_text('{"schema_version":2,"schema_version":2,"baselines":{}}')
        with self.assertRaises(ValueError): self.select()

    def test_external_registry_and_nonsymlink_parent_required(self):
        registry = self.root / 'c1/registry.json'; shutil.copyfile(self.root / 'registry.json', registry)
        with self.assertRaisesRegex(ValueError, 'independent'):
            chain.select_parent(P, registry, self.key, self.pin, self.root / 'c1', controlled=True)
        (self.root / 'alias').symlink_to(self.root / 'c1', target_is_directory=True)
        with self.assertRaises(ValueError):
            chain.select_parent(P, self.root / 'registry.json', self.key, self.pin, self.root / 'alias', controlled=True)

    def test_unapproved_candidate_is_not_accepted(self):
        shutil.rmtree(self.root / 'c1'); shutil.copytree(self.shared / 'first/candidate', self.root / 'c1')
        pack(self.root / 'c1', self.root / 'unapproved.tar.gz')
        self.ref = reference(self.root / 'c1', self.root / 'unapproved.tar.gz', self.fp)
        self.change_ref(lambda ref: None)
        with self.assertRaisesRegex(ValueError, 'Unapproved candidate'): self.select()
        self.assertFalse((self.root / 'c1/upstream-baseline.json').exists())

    def test_fixture_cannot_be_used_by_public_genuine_build_path(self):
        with self.assertRaisesRegex(ValueError, 'Controlled provenance'): self.build(controlled=False)
        self.assertFalse((self.root / 'next').exists())

    def test_wrong_parent_policy_and_upstream_binding(self):
        for field, value in [('parent', self.first['parent']), ('base_upstreams', self.revisions),
                             ('base_source_state', 'sha256-' + '0' * 64), ('build_fingerprint', '0' * 64)]:
            policy = copy.deepcopy(self.policy); policy['scope'][field] = value
            write_json(self.root / 'policy.json', policy)
            with self.subTest(field=field), self.assertRaises(ValueError): self.build()
            self.assertFalse((self.root / 'next').exists())

    def test_policy_pin_and_registry_policy_mismatch(self):
        value = copy.deepcopy(self.registry); value['baselines']['c1']['build_policy_sha256'] = '0' * 64
        write_json(self.root / 'registry.json', value)
        with self.assertRaisesRegex(ValueError, 'Build policy differs'): self.build()

    def test_no_candidate_fixture_authorization_override(self):
        policy = copy.deepcopy(self.policy); policy['controlled_chain_fixture'] = {'candidate_id': self.ref['node_id']}
        write_json(self.root / 'policy.json', policy)
        with self.assertRaisesRegex(ValueError, 'no Candidate fixture bypass'): self.build()

    def test_wrong_target_and_dirty_source_rejected_without_output(self):
        path = self.root / 'source2/repos/SPHinXsys/src/a.cpp'; path.write_text('dirty')
        with self.assertRaisesRegex(ValueError, 'Dirty source'): self.build()
        self.assertFalse((self.root / 'next').exists())

    def test_existing_output_and_overlap_never_overwritten(self):
        output = self.root / 'next'; output.mkdir(); (output / 'keep').write_text('keep')
        with self.assertRaises(ValueError): self.build()
        self.assertEqual((output / 'keep').read_text(), 'keep')
        with self.assertRaises(ValueError): self.build('c1/new-output')

    def test_parent_changed_after_build_discards_only_new_output(self):
        original = chain.select_parent; calls = []
        def changed(*args, **kwargs):
            calls.append(1)
            if len(calls) == 2: raise ValueError('Injected changed Parent/registry')
            return original(*args, **kwargs)
        with patch.object(chain, 'select_parent', side_effect=changed), self.assertRaises(ValueError): self.build()
        self.assertFalse((self.root / 'next').exists()); self.assertTrue((self.root / 'c1/corpus.jsonl').is_file())

    def test_self_parent_and_cyclic_existing_lineage_rejected(self):
        receipts = u.verify(P, self.root / 'c1', self.fp)['lineage']
        for value in ([*receipts, receipts[-1]], [receipts[-1], *receipts]):
            with self.assertRaises(ValueError): u.verify_lineage(value, self.fp)
        value = copy.deepcopy(receipts)
        value[-1]['identity']['parent'] = u._edge(value[-1])
        with self.assertRaises(ValueError): u.verify_lineage(value, self.fp)

    def test_historical_candidate_stays_blocked(self):
        from src import candidate_promotion_policy as promotion
        path = os.environ.get('SPHINX_P8_RUN_EVIDENCE')
        if not path: self.skipTest('Existing historical archive not configured')
        result = promotion.evaluate(Path(path))
        self.assertEqual(result['final_eligibility'], 'BLOCKED')
        self.assertEqual(result['p8']['gate_mode'], 'BLOCKING_ONLY')
        self.assertIn('PRODUCTION_NOT_AUTHORIZED', str(result['blocking_reasons']))
        evidence = os.environ.get('SPHINX_CHAIN_EVIDENCE')
        if evidence:
            with (Path(evidence) / 'historical-blocked.json').open('x') as stream: json.dump(result, stream, indent=2)


class CliTests(unittest.TestCase):
    def test_cli_forwards_explicit_selection_without_fixture_override(self):
        args = ['build-next', '--registry', 'registry.json', '--key', 'c1', '--parent', 'parent',
            '--base-source', 'base', '--target-source', 'target', '--output', 'output', '--policy', 'policy.json',
            '--expected-reference-sha256', 'a' * 64, '--expected-policy-sha256', 'b' * 64]
        with patch.object(chain, 'build_next', return_value=u.LIMITS) as build, redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(cli.main(args), 0)
        build.assert_called_once_with(P, Path('registry.json'), 'c1', 'a' * 64, Path('parent'),
            Path('base'), Path('target'), Path('output'), Path('policy.json'), 'b' * 64)
        self.assertEqual(json.loads(stdout.getvalue())['production_promotion'], 'NOT_AUTHORIZED')

    def test_cli_rejection_is_json_and_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Path(tmp); (r / 'parent').mkdir()
            write_json(r / 'registry.json', {'schema_version': 2, 'baselines': {}})
            result = subprocess.run([sys.executable, '-B', str(P / 'scripts/ci_v2_schema2_research.py'),
                'build-next', '--registry', 'registry.json', '--key', 'unavailable', '--parent', 'parent',
                '--base-source', 'base', '--target-source', 'target', '--output', 'output', '--policy', 'policy.json',
                '--expected-reference-sha256', 'a' * 64, '--expected-policy-sha256', 'b' * 64],
                cwd=r, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(json.loads(result.stdout)['status'], 'BOOTSTRAP_REQUIRED')
            self.assertFalse((r / 'output').exists())


if __name__ == '__main__': unittest.main()
