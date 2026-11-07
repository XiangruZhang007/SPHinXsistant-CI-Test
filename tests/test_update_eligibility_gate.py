"""P8 archive-consistency checks; fixtures never authorize a production release."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from src.corpus_snapshot import digest, read_json
from src import update_eligibility_gate as gate

PROJECT = Path(__file__).resolve().parents[1]
CURRENT_RUN = os.environ.get('SPHINX_P8_RUN_EVIDENCE')


def put(root, name, value):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n', encoding='utf-8')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def seal(root):
    put(root, 'checksums.json', {p.relative_to(root).as_posix(): sha(p)
                               for p in sorted(root.rglob('*'))
                               if p.is_file() and p != root / 'checksums.json'})


def fixture(root):
    """Tiny recorded-evidence fixture, not a corpus build or an approval format."""
    lock = read_json(PROJECT / 'configs/ci_v2_runtime_lock.json')
    benchmark = read_json(PROJECT / 'tests/retrieval_benchmarks/step_1_6_combined_frozen_v2.json')
    (root / 'benchmark.json').write_bytes(
        (PROJECT / 'tests/retrieval_benchmarks/step_1_6_combined_frozen_v2.json').read_bytes())
    fp = digest(lock['P2'])
    upstreams = {'SPHinXsys': 'a' * 40, 'SPHinXsim': 'b' * 40}
    selection = []
    state = 'sha256-' + digest(selection)
    for folder in ('candidate', 'full'):
        put(root, folder + '/corpus.jsonl', {'chunk_id': 'fixture'})
        for name in ('selection.json', 'inventory.json', 'extraction-graph.json'):
            put(root, folder + '/' + name, selection)
        put(root, folder + '/build-contract.json', lock['P2'])
    corpus_sha = sha(root / 'candidate/corpus.jsonl')
    put(root, 'parent/corpus.jsonl', {'chunk_id': 'parent-fixture'})
    put(root, 'parent/selection.json', selection)
    parent_identity = {'upstreams': upstreams}
    parent_id = 'sha256-' + digest(parent_identity)
    put(root, 'parent/manifest.json', {'identity': parent_identity, 'snapshot_id': parent_id})
    put(root, 'parent-raw-results.json', [])
    seal(root / 'parent')
    parent = {'kind': 'P2_ANCHOR', 'node_id': parent_id, 'package_checksum': 'c' * 64}
    policy = {'production_promotion': 'NOT_AUTHORIZED',
              'scope': {'parent': parent, 'target_upstreams': upstreams,
                        'target_source_state': state, 'build_fingerprint': fp}}
    put(root, 'build-policy.json', policy)
    put(root, 'candidate/research-policy-original.json', policy)
    identity = {'build_fingerprint': fp, 'upstreams': upstreams, 'base_upstreams': upstreams,
                'target_source_state': state, 'base_source_state': state, 'base_snapshot_id': parent_id,
                'parent': parent, 'policy_sha256': sha(root / 'build-policy.json'),
                'production_promotion': 'NOT_AUTHORIZED',
                'artifacts': {name: sha(root / 'candidate' / name) for name in gate.PARITY_FILES}}
    cid = 'sha256-' + digest(identity)
    candidate = {'schema_version': 2, 'kind': 'upstream-research-candidate',
                 'candidate_id': cid, 'identity': identity}
    put(root, 'candidate/candidate.json', candidate)
    put(root, 'candidate/upstream-candidate.json', {**candidate, 'ancestry': []})
    seal(root / 'candidate')
    full_identity = {'corpus': {'sha256': corpus_sha}, 'build_fingerprint': fp, 'upstreams': upstreams}
    full_id = 'sha256-' + digest(full_identity)
    put(root, 'full/validation.json', {'structural_status': 'STRUCTURALLY_VALID'})
    put(root, 'full/manifest.json', {'format': 'ci-v2-snapshot-v1', 'schema_version': 1,
        'identity': full_identity, 'snapshot_id': full_id,
        'files': {p.name: sha(p) for p in sorted((root / 'full').iterdir())},
        'validation': {'structural_status': 'STRUCTURALLY_VALID'}})
    seal(root / 'full')
    rows = [{'id': q['id'], 'mode': mode} for q in benchmark['questions']
            for mode in (('combined', 'documentation_only') if q['group'] == 'A' else ('combined',))]
    for name in ('incremental', 'full'):
        put(root, 'quality/' + name + '-raw-results.json', rows)
        put(root, 'quality/' + name + '-frozen-metrics.json', {})
    transitions = [{**row, 'hit5': 'PASS\u2192PASS', 'hit10': 'PASS\u2192PASS'} for row in rows]
    put(root, 'quality/transitions.json', {'historical': transitions, 'immediate_parent': transitions})
    raw_sha = sha(root / 'quality/incremental-raw-results.json')
    quality = {'schema_version': 1, 'candidate_id': cid, 'corpus_sha256': corpus_sha,
               'build_fingerprint': fp, 'policy': lock['quality_policy'],
               'policy_sha256': digest(lock['quality_policy']), 'raw_results_sha256': raw_sha,
               'metrics': {}, 'status': 'QUALITY_REVIEW_REQUIRED', 'assessment': 'FROZEN_128_EVALUATED',
               'combinations_each': 128, 'independent_candidate_full_rows_equal': True,
               'new_losses': {'historical': [], 'immediate_parent': []}}
    put(root, 'quality/quality-report.json', quality)
    seal(root / 'quality')
    parity = {'candidate_id': cid, 'status': 'PARITY_PASS', 'full_reference_independently_built': True,
              'comparisons': {name: {'sha256': sha(root / 'candidate' / name), 'exact_bytes_equal': True}
                              for name in gate.PARITY_FILES}}
    put(root, 'parity.json', parity)
    bindings = {'candidate_id': cid, 'target_corpus_sha256': corpus_sha, 'target_source_state': state,
                'target_upstreams': upstreams, 'base_upstreams': upstreams, 'build_fingerprint': fp,
                'parent_id': parent_id, 'base_source_state': state,
                'base_corpus_sha256': sha(root / 'parent/corpus.jsonl'),
                'base_rows_sha256': sha(root / 'parent-raw-results.json'),
                'target_rows_sha256': raw_sha, 'benchmark_sha256': sha(root / 'benchmark.json'),
                'four_artifact_parity': parity}
    put(root, 'trusted-reference.json', {'node_id': parent_id, 'source_state': state,
        'upstreams': upstreams, 'corpus_sha256': bindings['base_corpus_sha256'],
        'parent_rows_sha256': bindings['base_rows_sha256'],
        'manifest_sha256': sha(root / 'parent/checksums.json'),
        'authorization': {'production_promotion': 'NOT_AUTHORIZED', 'research_only': True}})
    put(root, 'execution-verification/verification.json', {'candidate_corpus_sha256': corpus_sha,
        'full_corpus_sha256': corpus_sha, 'status': 'VERIFIED', 'layers': ['A', 'B', 'C'],
        'original_combinations': 256, 'independent_replay_combinations': 256,
        'retrieval_quality': 'QUALITY_REVIEW_REQUIRED', 'production_promotion': 'NOT_AUTHORIZED'})
    put(root, 'result.json', {'schema_version': 2, 'candidate_id': cid, 'bindings': bindings,
        'baseline_id': parent_id, 'independent_full_snapshot_id': full_id, 'target_source_state': state,
        'STRUCTURAL_PARITY': 'PASS', 'retrieval_quality': 'QUALITY_REVIEW_REQUIRED',
        'RETRIEVAL_QUALITY_ACCEPTED': False, 'production_promotion': 'NOT_AUTHORIZED',
        'candidate_evaluation_combinations': 128, 'full_evaluation_combinations': 128,
        'independent_replay_combinations': 256, 'quality_metrics': {}})
    seal(root)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'run'
        self.root.mkdir()
        fixture(self.root)

    def alter(self, name, update):
        value = read_json(self.root / name)
        update(value)
        put(self.root, name, value)
        for folder in ('candidate', 'full', 'parent', 'quality'):
            seal(self.root / folder)
        seal(self.root)

    def blocked(self, message=None):
        result = gate.evaluate(self.root)
        self.assertEqual(result['decision'], 'BLOCKED')
        self.assertEqual(result['gate_mode'], 'BLOCKING_ONLY')
        if message:
            self.assertIn(message, json.dumps(result))
        return result

    def test_research_candidate_is_blocked_with_valid_archived_bindings(self):
        result = self.blocked('QUALITY_NOT_ACCEPTED')
        self.assertEqual(result['evidence_consistency'], 'VERIFIED_ARCHIVED_BINDINGS')
        self.assertEqual({r['code'] for r in result['reasons']},
                         {'QUALITY_NOT_ACCEPTED', 'PRODUCTION_NOT_AUTHORIZED',
                          'RELEASE_AUTHORIZATION_UNAVAILABLE'})

    def test_missing_evidence(self):
        (self.root / 'quality/quality-report.json').unlink()
        self.blocked('INVALID_EVIDENCE')

    def test_malformed_json_even_when_resealed(self):
        (self.root / 'result.json').write_text('{')
        seal(self.root)
        self.blocked('INVALID_EVIDENCE')

    def test_duplicate_json_keys(self):
        (self.root / 'result.json').write_text('{"schema_version":2,"schema_version":2}')
        seal(self.root)
        self.blocked('Duplicate JSON key')

    def test_nonfinite_json(self):
        (self.root / 'result.json').write_text('{"schema_version":NaN}')
        seal(self.root)
        self.blocked('Non-finite JSON constant')

    def test_structural_failure(self):
        self.alter('result.json', lambda d: d.update(STRUCTURAL_PARITY='FAIL'))
        self.blocked('Structural/execution verification failed')

    def test_quality_rejected(self):
        for name, field in [('quality/quality-report.json', 'status'),
                            ('result.json', 'retrieval_quality'),
                            ('execution-verification/verification.json', 'retrieval_quality')]:
            self.alter(name, lambda d, field=field: d.update({field: 'QUALITY_REJECTED'}))
        self.blocked('QUALITY_REJECTED')

    def test_identity_mismatch_even_when_resealed(self):
        self.alter('quality/quality-report.json', lambda d: d.update(candidate_id='sha256-' + '0' * 64))
        self.blocked('Candidate identity binding mismatch')

    def test_corpus_bytes_changed(self):
        (self.root / 'candidate/corpus.jsonl').write_text('changed\n')
        self.blocked('Checksum mismatch: candidate/corpus.jsonl')

    def test_corpus_report_mismatch_even_when_resealed(self):
        self.alter('quality/quality-report.json', lambda d: d.update(corpus_sha256='0' * 64))
        self.blocked('Corpus checksum binding mismatch')

    def test_policy_mismatch(self):
        self.alter('quality/quality-report.json', lambda d: d.update(policy_sha256='0' * 64))
        self.blocked('Quality policy binding mismatch')

    def test_benchmark_mismatch(self):
        self.alter('result.json', lambda d: d['bindings'].update(benchmark_sha256='0' * 64))
        self.blocked('Benchmark binding mismatch')

    def test_build_mismatch(self):
        self.alter('quality/quality-report.json', lambda d: d.update(build_fingerprint='0' * 64))
        self.blocked('Build fingerprint mismatch')

    def test_raw_result_mismatch(self):
        self.alter('quality/quality-report.json', lambda d: d.update(raw_results_sha256='0' * 64))
        self.blocked('Retrieval result binding mismatch')

    def test_unresolved_regression(self):
        loss = {'id': 'DOC-Q27', 'mode': 'combined', 'hit5': 'PASS\u2192FAIL', 'hit10': 'PASS\u2192FAIL'}
        self.alter('quality/transitions.json', lambda d: next(
            r for r in d['immediate_parent'] if r['id'] == 'DOC-Q27' and r['mode'] == 'combined').update(loss))
        self.alter('quality/quality-report.json', lambda d: d['new_losses']['immediate_parent'].append(loss))
        self.blocked('UNRESOLVED_REGRESSIONS')

    def test_truncated_regression_inventory(self):
        self.alter('quality/transitions.json', lambda d: d['immediate_parent'].clear())
        self.blocked('Incomplete regression comparison inventory')

    def test_unknown_regression_transition(self):
        self.alter('quality/transitions.json', lambda d: d['immediate_parent'][0].update(hit5='unknown'))
        self.blocked('Unsupported regression transition')

    def test_missing_regression_comparison(self):
        self.alter('quality/quality-report.json', lambda d: d.pop('new_losses'))
        self.blocked('INVALID_EVIDENCE')

    def test_research_approval_and_arbitrary_authorized_flag_cannot_release(self):
        self.alter('result.json', lambda d: d.update(RESEARCH_BASELINE_APPROVED=True, authorized=True))
        self.blocked('RELEASE_AUTHORIZATION_UNAVAILABLE')
        self.blocked('PRODUCTION_NOT_AUTHORIZED')

    def test_forged_quality_acceptance_is_not_release_authorization(self):
        for name, field in [('quality/quality-report.json', 'status'), ('result.json', 'retrieval_quality'),
                            ('execution-verification/verification.json', 'retrieval_quality')]:
            self.alter(name, lambda d, field=field: d.update({field: 'QUALITY_ACCEPTED'}))
        self.alter('result.json', lambda d: d.update(RETRIEVAL_QUALITY_ACCEPTED=True))
        result = self.blocked('RELEASE_AUTHORIZATION_UNAVAILABLE')
        self.assertNotIn('QUALITY_NOT_ACCEPTED', {r['code'] for r in result['reasons']})
        self.assertEqual(result['evidence_consistency'], 'VERIFIED_ARCHIVED_BINDINGS')

    def test_inspection_subset_and_unsupported_schema(self):
        subset = Path(self.tmp.name) / 'inspection'
        subset.mkdir()
        put(subset, 'result.json', read_json(self.root / 'result.json'))
        self.assertEqual(gate.evaluate(subset)['evidence_consistency'], 'INVALID')
        self.alter('result.json', lambda d: d.update(schema_version=99))
        self.blocked('Unsupported run schema')

    def test_symlink_rejected(self):
        (self.root / 'link').symlink_to(self.root / 'result.json')
        self.blocked('Nonregular evidence member')

    def test_deterministic_and_read_only(self):
        before = {p.relative_to(self.root).as_posix(): sha(p) for p in self.root.rglob('*') if p.is_file()}
        real_open = io.open

        def read_only(file, mode='r', *args, **kwargs):
            self.assertFalse(set(mode) & set('wax+'))
            return real_open(file, mode, *args, **kwargs)

        with patch('io.open', side_effect=read_only), patch('builtins.open', side_effect=read_only), \
                patch('subprocess.run', side_effect=AssertionError('No process execution')), \
                patch('socket.socket.connect', side_effect=AssertionError('No network')), \
                patch('zipfile.ZipFile.extractall', side_effect=AssertionError('No extraction')):
            first = self.blocked()
            self.assertEqual(first, self.blocked())
        self.assertEqual(before, {p.relative_to(self.root).as_posix(): sha(p)
                                  for p in self.root.rglob('*') if p.is_file()})

    def test_zip_matches_directory_without_extraction(self):
        archive = Path(self.tmp.name) / 'hosted.zip'
        with zipfile.ZipFile(archive, 'w') as z:
            for p in self.root.rglob('*'):
                if p.is_file():
                    z.write(p, 'run/' + p.relative_to(self.root).as_posix())
        before = sha(archive)
        self.assertEqual(gate.evaluate(archive), self.blocked())
        self.assertEqual(sha(archive), before)
        with zipfile.ZipFile(archive, 'a') as z:
            z.writestr('run/../escape', 'unsafe')
        self.assertIn('INVALID_EVIDENCE', json.dumps(gate.evaluate(archive)))

    def test_cli_json_only_and_exit_one_from_other_working_directory(self):
        for args in (['--run', str(self.root)], [], ['--help'], ['--run', str(self.root / 'missing')]):
            with self.subTest(args=args):
                result = subprocess.run([sys.executable, '-B', '-m', 'src.update_eligibility_gate', *args],
                    cwd=self.tmp.name, env={**os.environ, 'PYTHONPATH': str(PROJECT)},
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stderr, '')
                self.assertEqual(json.loads(result.stdout)['decision'], 'BLOCKED')


@unittest.skipUnless(CURRENT_RUN, 'Set SPHINX_P8_RUN_EVIDENCE for the archived candidate check')
class CurrentCandidateTests(unittest.TestCase):
    def test_existing_candidate_is_read_only_and_blocked(self):
        path = Path(CURRENT_RUN)
        before = sha(path) if path.is_file() else None
        result = gate.evaluate(path)
        self.assertEqual(result['decision'], 'BLOCKED')
        self.assertEqual(result['evidence_consistency'], 'VERIFIED_ARCHIVED_BINDINGS')
        self.assertEqual({r['code'] for r in result['reasons']},
                         {'QUALITY_NOT_ACCEPTED', 'UNRESOLVED_REGRESSIONS',
                          'PRODUCTION_NOT_AUTHORIZED', 'RELEASE_AUTHORIZATION_UNAVAILABLE'})
        if before:
            self.assertEqual(sha(path), before)


if __name__ == '__main__':
    unittest.main()
