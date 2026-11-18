"""L1: pinned, read-only LOCAL_RESEARCH_EXECUTION evidence inspection.

The caller independently retains the SHA-256 of the descriptor's exact UTF-8
bytes (not its canonical reserialization). No descriptor is generated here.
Paths are caller-selected directories, never executable commands or descriptor
fields. This is inspection of sealed local records, NOT platform attestation or
registration authority. Only archived replay rows are inspected: NO_FRESH_REPLAY.

Future transport must separately define bounded archive layout, asset identities,
external archive/manifest pins, publication authority and mandatory notices
delivery. This module neither invents those fields nor extracts archives.
Inputs must be stable, caller-controlled read-only copies during verification;
concurrent hostile filesystem mutation is outside this local inspection model.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat

from . import candidate_release_archive as archive
from . import upstream_provenance as provenance, approval_evidence as approval
from . import trusted_snapshot as trusted, parent_r2_anchor as anchor
from .corpus_snapshot import canonical, digest, file_digest, checked_file

DESCRIPTOR_LIMIT = 64 * 1024
JSON_LIMIT = 64 * 1024**2
FILE_LIMIT = 256 * 1024**2
TREE_LIMIT = 2 * 1024**3
FILE_COUNT_LIMIT = 20000
RECORD_FILES = frozenset({'authorization.json', 'executed-command.txt',
    'execution-start.json', 'execution-exit.json', 'execution.stdout.log',
    'execution.stderr.log', 'report.md'})
HASH_FIELDS = frozenset({'corpus_sha256', 'build_fingerprint',
    'orchestration_fingerprint', 'benchmark_sha256', 'build_policy_sha256',
    'run_manifest_sha256', 'baseline_manifest_sha256', 'approval_manifest_sha256',
    'approval_policy_sha256', 'reference_sha256', 'parent_reference_sha256',
    'quality_sha256', 'candidate_rows_sha256', 'r2_contract_sha256'})
ID_FIELDS = frozenset({'candidate_id', 'parent_id', 'baseline_id', 'source_state'})
FIELDS = HASH_FIELDS | ID_FIELDS | {'schema_version', 'evidence_origin',
    'hosted_validation', 'generation', 'upstreams', 'execution_records'}


class EvidenceError(ValueError):
    """Sanitized diagnostic code; no evidence text, paths or credentials."""


def _need(ok, code):
    if not ok:
        raise EvidenceError(code)


def _sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def _safe(path, *, directory=False):
    path = Path(path).absolute()
    _need('..' not in path.parts, 'UNSAFE_PATH')
    for part in (*reversed(path.parents), path):
        _need(not part.is_symlink(), 'UNSAFE_PATH')
    info = path.stat()
    _need(stat.S_ISDIR(info.st_mode) if directory else
          stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'UNSAFE_PATH')
    return path


def _read(path, limit=JSON_LIMIT):
    path = _safe(path)
    _need(path.stat().st_size <= limit, 'OVERSIZED_INPUT')
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    _need(len(raw) <= limit, 'OVERSIZED_INPUT')
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, 'DUPLICATE_JSON_FIELD')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    canonical(value)  # also rejects non-finite numbers
    return value, raw


def load_descriptor(path, expected_sha256):
    """Validate a closed v1 descriptor against an independently supplied byte pin."""
    try:
        _need(_sha(expected_sha256), 'INVALID_INDEPENDENT_PIN')
        d, raw = _read(path, DESCRIPTOR_LIMIT)
        _need(hashlib.sha256(raw).hexdigest() == expected_sha256, 'DESCRIPTOR_PIN_MISMATCH')
        _need(isinstance(d, dict) and set(d) == FIELDS, 'INVALID_DESCRIPTOR_FIELDS')
        _need(type(d['schema_version']) is int and d['schema_version'] == 1,
              'UNSUPPORTED_DESCRIPTOR_VERSION')
        _need(d['evidence_origin'] == 'LOCAL_RESEARCH_EXECUTION'
              and d['hosted_validation'] == 'HOSTED_NOT_RUN', 'MIXED_ORIGIN_EVIDENCE')
        _need(all(_sha(d[n]) for n in HASH_FIELDS), 'INVALID_DESCRIPTOR_HASH')
        _need(all(isinstance(d[n], str) and d[n].startswith('sha256-')
                  and _sha(d[n][7:]) for n in ID_FIELDS), 'INVALID_DESCRIPTOR_ID')
        _need(type(d['generation']) is int and d['generation'] > 0, 'INVALID_GENERATION')
        _need(isinstance(d['upstreams'], dict)
              and set(d['upstreams']) == set(provenance.REPOSITORIES)
              and all(isinstance(v, str) and re.fullmatch('[0-9a-f]{40}', v)
                      for v in d['upstreams'].values()), 'INVALID_UPSTREAMS')
        _need(isinstance(d['execution_records'], dict)
              and set(d['execution_records']) == RECORD_FILES
              and all(_sha(v) for v in d['execution_records'].values()),
              'INVALID_EXECUTION_RECORD_PINS')
        return d
    except EvidenceError:
        raise
    except (OSError, ValueError, TypeError, RecursionError):
        raise EvidenceError('INVALID_DESCRIPTOR') from None


def _tree(root):
    root = _safe(root, directory=True)
    count = size = 0
    for path in root.rglob('*'):
        count += 1
        _need(count <= FILE_COUNT_LIMIT, 'OVERSIZED_EVIDENCE')
        _need(not path.is_symlink(), 'UNSAFE_EVIDENCE_MEMBER')
        info = path.stat()
        if stat.S_ISDIR(info.st_mode):
            continue
        _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
              'UNSAFE_EVIDENCE_MEMBER')
        size += info.st_size
        _need(info.st_size <= FILE_LIMIT and count <= FILE_COUNT_LIMIT
              and size <= TREE_LIMIT, 'OVERSIZED_EVIDENCE')
        if path.suffix == '.json':
            _need(info.st_size <= JSON_LIMIT, 'OVERSIZED_INPUT')
    return root


def _check_anchor(receipt, expected_status):
    _need(receipt.get('status') == expected_status
          and receipt.get('execution') == 'NO_FRESH_REPLAY'
          and receipt.get('reference_trust') == 'CALLER_PINNED_REFERENCE'
          and receipt.get('controlled_fixture') is False
          and receipt.get('quality_acceptance') == 'NOT_GRANTED'
          and receipt.get('production_promotion') == 'NOT_AUTHORIZED',
          'PARENT_ANCHOR_NOT_QUALIFIED')


def verify(project, run, execution_records, baseline, descriptor_path, *,
           expected_descriptor_sha256, reference_path):
    """Inspect exact retained local evidence. Never approve, build, replay or write.

    A successful receipt means pinned record integrity and existing P4.1 contract
    verification; the caller must independently decide whether to trust the local
    operator's recorded execution. Reference pin uses existing canonical semantics.
    """
    phase = 'INVALID_LOCAL_EVIDENCE'
    try:
        d = load_descriptor(descriptor_path, expected_descriptor_sha256)
        run, records, baseline = map(_tree, (run, execution_records, baseline))
        def read(root, name):
            return _read(checked_file(root, name))[0]
        def pin(root, name, expected):
            _need(file_digest(checked_file(root, name)) == expected, 'EVIDENCE_PIN_MISMATCH')
        phase = 'SEALED_EVIDENCE_INVALID'
        pin(run, 'checksums.json', d['run_manifest_sha256'])
        pin(baseline, 'checksums.json', d['baseline_manifest_sha256'])
        archive._read_sealed_run(run)
        archive._read_sealed_run(baseline)
        for name, sha in d['execution_records'].items():
            pin(records, name, sha)
        start, end = read(records, 'execution-start.json'), read(records, 'execution-exit.json')
        _need(type(end.get('exit_code')) is int and end['exit_code'] == 0
              and type(start.get('command_count')) is int and start['command_count'] == 1
              and type(end.get('command_count')) is int and end['command_count'] == 1
              and end.get('automatic_retry') is False, 'LOCAL_EXECUTION_NOT_SUCCESSFUL')
        auth = read(records, 'authorization.json')
        _need(auth.get('approved_policy_sha256') == d['build_policy_sha256']
              and auth.get('target_upstreams') == d['upstreams']
              and auth.get('production_promotion') == 'NOT_AUTHORIZED',
              'LOCAL_EXECUTION_RECORD_MISMATCH')
        phase = 'CANDIDATE_VERIFICATION_FAILED'
        candidate = provenance.verify(project, run / 'candidate', d['build_fingerprint'],
                                      expected_id=d['candidate_id'])
        identity = read(run, 'candidate/upstream-candidate.json')['identity']
        _need(candidate['provenance_type'] == 'GENUINE_UPSTREAM'
              and candidate['generation'] == d['generation']
              and candidate['upstreams'] == d['upstreams']
              and candidate['target_source_state'] == d['source_state']
              and identity['parent']['node_id'] == d['parent_id']
              and identity['orchestration_fingerprint'] == d['orchestration_fingerprint']
              and identity['policy_sha256'] == d['build_policy_sha256'],
              'CANDIDATE_BINDING_MISMATCH')
        pin(run, 'candidate/corpus.jsonl', d['corpus_sha256'])
        pin(run, 'build-policy.json', d['build_policy_sha256'])
        result = read(run, 'result.json')
        _need(result['hosted_validation'] == 'HOSTED_NOT_RUN'
              and result['candidate_id'] == d['candidate_id']
              and result['baseline_id'] == d['parent_id']
              and result['automatic_research_approval'] is False
              and result['automatic_reuse'] is False
              and result['production_promotion'] == 'NOT_AUTHORIZED', 'RUN_BINDING_MISMATCH')
        phase = 'FULL_PARITY_INVALID'
        parity = provenance.compare_full(project, run / 'candidate', run / 'full',
                                         d['build_fingerprint'])
        _need(parity.get('status') == 'PARITY_PASS', 'FULL_PARITY_NOT_PASSED')
        _need(parity == read(run, 'parity.json') == result['bindings']['four_artifact_parity'],
              'RECORDED_PARITY_MISMATCH')
        phase = 'P4_1_VERIFICATION_FAILED'
        reference, _ = _read(reference_path)
        trusted.validate_reference(reference, d['reference_sha256'])
        _need(reference['node_id'] == d['baseline_id'], 'BASELINE_ID_MISMATCH')
        trusted.verify_package(project, baseline, reference)
        _need(read(baseline, 'upstream-candidate.json')['identity'] == identity,
              'BASELINE_CANDIDATE_MISMATCH')
        pin(baseline, 'approval-evidence/checksums.json', d['approval_manifest_sha256'])
        pin(baseline, 'approval-evidence/external-policy.json', d['approval_policy_sha256'])
        evidence = approval.verify_bundle(project, baseline / 'approval-evidence',
            expected_manifest_sha=d['approval_manifest_sha256'], fresh_replay=False)
        _need(evidence['status'] == 'P4_1_VERIFIED'
              and evidence['mode'] == 'RETRIEVAL_EVALUATED'
              and evidence['candidate_id'] == d['candidate_id']
              and evidence['parent_baseline_id'] == d['parent_id']
              and evidence['candidate_corpus_sha256'] == d['corpus_sha256'],
              'P4_1_BINDING_MISMATCH')
        phase = 'QUALITY_OR_R2_INVALID'
        pin(run, 'benchmark.json', d['benchmark_sha256'])
        pin(run, 'quality/quality-report.json', d['quality_sha256'])
        pin(run, 'quality/incremental-raw-results.json', d['candidate_rows_sha256'])
        # P4.1 independently rescores these exact archived rows and inspects its
        # archived replay, without executing retrieval. Connect it to original run.
        for original, approved in [('benchmark.json', 'benchmark.json'),
                ('quality/quality-report.json', 'quality.json'),
                ('quality/incremental-raw-results.json', 'incremental-raw-results.json'),
                ('quality/full-raw-results.json', 'full-raw-results.json'),
                ('parent-raw-results.json', 'parent-raw-results.json')]:
            _need(file_digest(checked_file(run, original)) == file_digest(
                checked_file(baseline / 'approval-evidence', approved)), 'ORIGINAL_R2_BINDING_MISMATCH')
        for label in ('incremental', 'full'):
            _need(read(run, 'execution-verification/' + label + '-replay.json')
                  == read(run, 'quality/' + label + '-raw-results.json'), 'ARCHIVED_REPLAY_MISMATCH')
        verification = read(run, 'execution-verification/verification.json')
        _need(verification['status'] == 'VERIFIED'
              and verification['candidate_corpus_sha256'] == d['corpus_sha256']
              and verification['full_corpus_sha256'] == d['corpus_sha256'], 'RUN_REPLAY_RECEIPT_INVALID')
        quality = read(run, 'quality/quality-report.json')
        _need(quality['status'] == 'QUALITY_REVIEW_REQUIRED'
              and quality['policy']['benchmark_sha256'] == d['benchmark_sha256']
              and digest(quality['policy']['R2_fingerprint']) == d['r2_contract_sha256']
              and read(run, 'q1-status.json')['status'] == 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR',
              'QUALITY_RESTRICTIONS_MISMATCH')
        parent_ref = read(run, 'trusted-reference.json')
        _need(parent_ref['node_id'] == d['parent_id'], 'ORIGINAL_PARENT_MISMATCH')
        parent = anchor.qualify_parent_anchor(project, run / 'parent', parent_ref,
            d['parent_reference_sha256'], run / 'parent-raw-results.json', fresh_replay=False)
        # Original P2 inspection cannot claim fresh qualification. Research
        # Baselines, including the newly approved future Parent, must qualify.
        original_status = ('PINNED_ANCHOR_INSPECTED'
            if parent_ref['package_format'] == 'p2-snapshot-v1' else 'QUALIFIED')
        _check_anchor(parent, original_status)
        qualified = anchor.qualify_parent_anchor(project, baseline, reference,
            d['reference_sha256'], run / 'quality/incremental-raw-results.json', fresh_replay=False)
        _check_anchor(qualified, 'QUALIFIED')
        _need(qualified['bindings']['baseline_id'] == d['baseline_id']
              and qualified['bindings']['candidate_id'] == d['candidate_id']
              and qualified['bindings']['parent_rows_sha256'] == d['candidate_rows_sha256'],
              'BASELINE_R2_ANCHOR_MISMATCH')
        # Recheck seals after all reads; never silently accept changed evidence.
        archive._read_sealed_run(run)
        archive._read_sealed_run(baseline)
        pin(run, 'checksums.json', d['run_manifest_sha256'])
        pin(baseline, 'checksums.json', d['baseline_manifest_sha256'])
        for name, sha in d['execution_records'].items():
            pin(records, name, sha)
        load_descriptor(descriptor_path, expected_descriptor_sha256)
        _need(digest(_read(reference_path)[0]) == d['reference_sha256'], 'REFERENCE_CHANGED')
        return {'schema_version': 1, 'status': 'LOCAL_EVIDENCE_VERIFIED',
            'evidence_origin': 'LOCAL_RESEARCH_EXECUTION', 'hosted_validation': 'HOSTED_NOT_RUN',
            'descriptor_sha256': expected_descriptor_sha256,
            **{k: d[k] for k in (*ID_FIELDS, 'corpus_sha256', 'generation', 'upstreams')},
            'P4_1_verification': evidence['status'], 'parity': parity['status'],
            'original_parent_anchor_status': parent['status'],
            'baseline_anchor_status': qualified['status'],
            'replay': 'NO_FRESH_REPLAY', 'execution_authenticity': 'CALLER_PINNED_LOCAL_RECORDS',
            'quality': 'QUALITY_REVIEW_REQUIRED', 'Q1': 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR',
            'P8': 'BLOCKED', 'production_promotion': 'NOT_AUTHORIZED',
            'registration_authorization': 'NOT_GRANTED', 'publication': 'NOT_PERFORMED'}
    except EvidenceError:
        raise
    except (OSError, ValueError, TypeError, KeyError, IndexError, RecursionError):
        raise EvidenceError(phase) from None
