"""P8: inspect archived schema-2 evidence without building, replaying or writing.

Usage: python3 -B -m src.update_eligibility_gate --run RUN_DIRECTORY_OR_ZIP
Directories must contain the complete sealed run; hosted ZIPs must contain run/.
An inspection/ subset is unsupported. Hashes establish consistency, not release
authority. No independently verifiable production authorization exists in the
current contracts, so this version always returns BLOCKED (exit 1). It neither
creates an authorization format nor treats research approval as release approval.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import re
import stat
import zipfile
import zlib

from .corpus_snapshot import _unique, checked_file, digest, read_json
from .indexing_scope import normalize_relative_path

PROJECT = Path(__file__).resolve().parents[1]
PARITY_FILES = ('corpus.jsonl', 'extraction-graph.json', 'inventory.json', 'selection.json')


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def _reject_constant(value):
    raise ValueError('Non-finite JSON constant: ' + value)


class _Evidence:
    """Two read-only inputs; no extraction, temporary files, network or callbacks."""

    def __init__(self, path, stack):
        self.root = Path(path).expanduser()
        self.archive = None
        _need(not self.root.is_symlink(), 'Symlink evidence root is unsupported')
        if self.root.is_dir():
            paths = list(self.root.rglob('*'))
            _need(all(not p.is_symlink() and (p.is_file() or p.is_dir()) for p in paths),
                  'Nonregular evidence member')
            self.names = {p.relative_to(self.root).as_posix() for p in paths if p.is_file()}
        else:
            self.archive = stack.enter_context(zipfile.ZipFile(self.root))
            infos = self.archive.infolist()
            names = [i.filename for i in infos]
            _need(len(names) == len(set(names)), 'Duplicate ZIP member')
            for info in infos:
                name = info.filename.rstrip('/')
                _need(normalize_relative_path(name) == name, 'Noncanonical ZIP member')
                kind = stat.S_IFMT(info.external_attr >> 16)
                _need(kind in (0, stat.S_IFDIR if info.is_dir() else stat.S_IFREG),
                      'Nonregular ZIP member')
            self.names = {i.filename[4:] for i in infos
                          if i.filename.startswith('run/') and not i.is_dir()}
        self.hashes = {}

    def raw(self, name):
        _need(normalize_relative_path(name) == name and name in self.names,
              'Missing/noncanonical evidence member: ' + name)
        if self.archive is not None:
            return self.archive.read('run/' + name)
        return checked_file(self.root, name).read_bytes()

    def json(self, name):
        return json.loads(self.raw(name).decode('utf-8'), object_pairs_hook=_unique,
                          parse_constant=_reject_constant)

    def sha(self, name):
        if name not in self.hashes:
            self.hashes[name] = hashlib.sha256(self.raw(name)).hexdigest()
        return self.hashes[name]

    def seal(self, prefix=''):
        checks = self.json(prefix + 'checksums.json')
        _need(isinstance(checks, dict), 'Malformed checksum inventory')
        actual = {n[len(prefix):] for n in self.names if n.startswith(prefix)}
        _need(actual == set(checks) | {'checksums.json'}, 'Incomplete evidence inventory: ' + prefix)
        for name, expected in checks.items():
            _need(isinstance(expected, str) and re.fullmatch('[0-9a-f]{64}', expected),
                  'Malformed checksum: ' + prefix + name)
            _need(self.sha(prefix + name) == expected, 'Checksum mismatch: ' + prefix + name)


def _inspect(e, blockers):
    """Check recorded evidence and its byte bindings, never execute its evaluator."""
    e.seal()
    for prefix in ('candidate/', 'full/', 'parent/', 'quality/'):
        e.seal(prefix)
    result = e.json('result.json')
    candidate = e.json('candidate/candidate.json')
    full = e.json('full/manifest.json')
    quality = e.json('quality/quality-report.json')
    parity = e.json('parity.json')
    execution = e.json('execution-verification/verification.json')
    policy = e.json('build-policy.json')
    ref = e.json('trusted-reference.json')
    lock = read_json(PROJECT / 'configs/ci_v2_runtime_lock.json')
    _need(type(result['schema_version']) is int and result['schema_version'] == 2,
          'Unsupported run schema')
    _need(type(candidate['schema_version']) is int and candidate['schema_version'] == 2
          and candidate['kind'] == 'upstream-research-candidate', 'Unsupported candidate schema')
    _need(type(quality['schema_version']) is int and quality['schema_version'] == 1,
          'Unsupported quality report schema')
    identity = candidate['identity']
    cid = 'sha256-' + digest(identity)
    corpus_sha = e.sha('candidate/corpus.jsonl')
    bindings = result['bindings']
    _need(all(x == cid for x in (candidate['candidate_id'], result['candidate_id'],
              quality['candidate_id'], parity['candidate_id'], bindings['candidate_id'])),
          'Candidate identity binding mismatch')
    upstream = e.json('candidate/upstream-candidate.json')
    _need(candidate == {k: v for k, v in upstream.items() if k != 'ancestry'},
          'Candidate projection mismatch')
    for name, expected in identity['artifacts'].items():
        _need(e.sha('candidate/' + name) == expected, 'Candidate artifact mismatch: ' + name)
    _need(all(x == corpus_sha for x in (identity['artifacts']['corpus.jsonl'],
              quality['corpus_sha256'], bindings['target_corpus_sha256'],
              execution['candidate_corpus_sha256'], execution['full_corpus_sha256'],
              full['identity']['corpus']['sha256'], e.sha('full/corpus.jsonl'))),
          'Corpus checksum binding mismatch')
    fingerprint = digest(lock['P2'])
    _need(all(x == fingerprint for x in (identity['build_fingerprint'], quality['build_fingerprint'],
              bindings['build_fingerprint'], full['identity']['build_fingerprint'],
              digest(e.json('candidate/build-contract.json')), digest(e.json('full/build-contract.json')))),
          'Build fingerprint mismatch')
    _need(full['format'] == 'ci-v2-snapshot-v1' and type(full['schema_version']) is int
          and full['schema_version'] == 1 and full['snapshot_id'] == 'sha256-' + digest(full['identity'])
          and full['snapshot_id'] == result['independent_full_snapshot_id'], 'Full snapshot identity mismatch')
    _need(e.json('full/checksums.json') == {**full['files'], 'manifest.json': e.sha('full/manifest.json')},
          'Full snapshot manifest binding mismatch')
    _need(result['target_source_state'] == bindings['target_source_state'] == identity['target_source_state']
          == 'sha256-' + digest(e.json('candidate/selection.json')),
          'Source-state binding mismatch')
    _need(identity['upstreams'] == bindings['target_upstreams'] == full['identity']['upstreams']
          == policy['scope']['target_upstreams'], 'Upstream binding mismatch')
    _need(e.sha('build-policy.json') == identity['policy_sha256']
          == e.sha('candidate/research-policy-original.json'), 'Build policy binding mismatch')
    _need(policy['scope']['parent'] == identity['parent']
          and policy['scope']['target_source_state'] == identity['target_source_state']
          and policy['scope']['build_fingerprint'] == fingerprint, 'Build policy scope mismatch')
    parent = e.json('parent/manifest.json')
    _need(ref['node_id'] == result['baseline_id'] == bindings['parent_id'] == identity['base_snapshot_id']
          == parent['snapshot_id'] == 'sha256-' + digest(parent['identity'])
          and ref['corpus_sha256'] == bindings['base_corpus_sha256'] == e.sha('parent/corpus.jsonl')
          and ref['parent_rows_sha256'] == bindings['base_rows_sha256'] == e.sha('parent-raw-results.json'),
          'Parent reference binding mismatch')
    _need(ref['source_state'] == bindings['base_source_state'] == identity['base_source_state']
          == 'sha256-' + digest(e.json('parent/selection.json'))
          and ref['upstreams'] == bindings['base_upstreams'] == identity['base_upstreams']
          == parent['identity']['upstreams'] and ref['manifest_sha256'] == e.sha('parent/checksums.json'),
          'Parent source/manifest binding mismatch')
    _need(digest(quality['policy']) == digest(lock['quality_policy']) == quality['policy_sha256'],
          'Quality policy binding mismatch')
    _need(e.sha('benchmark.json') == bindings['benchmark_sha256']
          == quality['policy']['benchmark_sha256'], 'Benchmark binding mismatch')
    _need(e.sha('quality/incremental-raw-results.json') == quality['raw_results_sha256']
          == bindings['target_rows_sha256'] == e.sha('quality/full-raw-results.json'),
          'Retrieval result binding mismatch')
    benchmark = e.json('benchmark.json')
    expected_rows = {(q['id'], mode) for q in benchmark['questions']
                     for mode in (('combined', 'documentation_only') if q['group'] == 'A' else ('combined',))}
    rows = e.json('quality/incremental-raw-results.json')
    _need(isinstance(rows, list) and len(rows) == len(expected_rows) == 128
          and {(r['id'], r['mode']) for r in rows} == expected_rows, 'Incomplete retrieval row inventory')
    _need(digest(quality['metrics']) == digest(result['quality_metrics'])
          == digest(e.json('quality/incremental-frozen-metrics.json'))
          == digest(e.json('quality/full-frozen-metrics.json')), 'Quality metrics binding mismatch')
    _need(digest(parity) == digest(bindings['four_artifact_parity']), 'Parity report binding mismatch')
    _need(set(parity['comparisons']) == set(PARITY_FILES), 'Incomplete structural parity evidence')
    for name in PARITY_FILES:
        comparison = parity['comparisons'][name]
        _need(comparison['exact_bytes_equal'] is True and comparison['sha256']
              == e.sha('candidate/' + name) == e.sha('full/' + name), 'Structural parity failed: ' + name)
    _need(result['STRUCTURAL_PARITY'] == 'PASS' and parity['status'] == 'PARITY_PASS'
          and parity['full_reference_independently_built'] is True
          and full['validation']['structural_status'] == 'STRUCTURALLY_VALID'
          and e.json('full/validation.json')['structural_status'] == 'STRUCTURALLY_VALID'
          and execution['status'] == 'VERIFIED' and execution['layers'] == ['A', 'B', 'C'],
          'Structural/execution verification failed')
    _need(quality['assessment'] == 'FROZEN_128_EVALUATED' and quality['combinations_each'] == 128
          and result['candidate_evaluation_combinations'] == 128 and result['full_evaluation_combinations'] == 128
          and execution['original_combinations'] == 256 and execution['independent_replay_combinations'] == 256
          and result['independent_replay_combinations'] == 256
          and quality['independent_candidate_full_rows_equal'] is True, 'Incomplete retrieval evaluation evidence')
    _need(quality['status'] == result['retrieval_quality'] == execution['retrieval_quality']
          and quality['status'] in {'QUALITY_ACCEPTED', 'QUALITY_REVIEW_REQUIRED', 'QUALITY_REJECTED',
                                   'QUALITY_NOT_EVALUATED'}, 'Inconsistent/unsupported quality status')
    if quality['status'] != 'QUALITY_ACCEPTED' or result['RETRIEVAL_QUALITY_ACCEPTED'] is not True:
        blockers.append({'code': 'QUALITY_NOT_ACCEPTED', 'message': quality['status']})
    losses = quality['new_losses']
    transitions = e.json('quality/transitions.json')
    _need(set(losses) == set(transitions) == {'historical', 'immediate_parent'},
          'Missing regression comparison evidence')
    for group, rows in transitions.items():
        _need(isinstance(rows, list) and isinstance(losses[group], list), 'Malformed regression evidence')
        _need(len(rows) == len(expected_rows) and {(r['id'], r['mode']) for r in rows} == expected_rows,
              'Incomplete regression comparison inventory')
        _need(all(r[k] in {'PASS\u2192PASS', 'PASS\u2192FAIL', 'FAIL\u2192PASS', 'FAIL\u2192FAIL'}
                  for r in rows for k in ('hit5', 'hit10')), 'Unsupported regression transition')
        recorded = [r for r in rows if r['hit5'] == 'PASS\u2192FAIL' or r['hit10'] == 'PASS\u2192FAIL']
        _need(digest(recorded) == digest(losses[group]), 'Regression report binding mismatch')
    if any(losses.values()):
        blockers.append({'code': 'UNRESOLVED_REGRESSIONS',
                         'message': 'Recorded losses require review; diagnostics do not change frozen scores.'})
    restrictions = (result, identity, execution, policy, quality['policy'], ref['authorization'])
    if any(item['production_promotion'] == 'NOT_AUTHORIZED' for item in restrictions):
        blockers.append({'code': 'PRODUCTION_NOT_AUTHORIZED',
                         'message': 'Existing evidence explicitly prohibits production promotion.'})
    return {'candidate_id': cid, 'corpus_sha256': corpus_sha}


def evaluate(run):
    """Return a deterministic blocking-only decision without modifying any input."""
    blockers = [{'code': 'RELEASE_AUTHORIZATION_UNAVAILABLE',
                 'message': 'No supported independently verifiable production release authorization exists; research approval is insufficient.'}]
    result = {'decision': 'BLOCKED', 'gate_mode': 'BLOCKING_ONLY',
              'evidence_consistency': 'INVALID', 'reasons': blockers}
    try:
        with ExitStack() as stack:
            result.update(_inspect(_Evidence(run, stack), blockers))
        result['evidence_consistency'] = 'VERIFIED_ARCHIVED_BINDINGS'
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError,
            RuntimeError, EOFError, OverflowError, zipfile.BadZipFile, zlib.error) as error:
        blockers.append({'code': 'INVALID_EVIDENCE', 'message': str(error)})
    return result


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def main(argv=None):
    try:
        parser = _Parser(description=__doc__, add_help=False)
        parser.add_argument('--run', type=Path, required=True,
                            help='Complete sealed run directory or hosted evidence ZIP')
        args = parser.parse_args(argv)
        result = evaluate(args.run)
    except (ValueError, OSError) as error:
        result = {'decision': 'BLOCKED', 'gate_mode': 'BLOCKING_ONLY',
                  'reasons': [{'code': 'INVALID_INPUT', 'message': str(error)}]}
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
