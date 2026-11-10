"""One offline Parent/result verifier for live research runs and archive checks.

An external reference pin is local operator trust, not a signature. Stored P4.1
receipts are not new execution. No qualification here grants quality acceptance,
baseline approval, hosted authorization or production activation.
"""
from pathlib import Path

from . import approval_evidence as ev, ci_v2_research as c, trusted_snapshot as trust
from .corpus_snapshot import checked_file, digest, file_digest, read_json, read_records


def qualify_parent_anchor(project, parent, ref, expected_ref_sha, rows_path,
                          *, fresh_replay=True, controlled=False):
    """Check existing reference/package/P4.1 contracts and frozen 128 rows.

    With no external pin, only the legacy P2 archive integrity check is allowed;
    that result is explicitly not independent source authentication. Research
    Parents always require an external pin and evaluated, not structural, P4.1.
    controlled=True exists only for isolated library tests; no CLI override.
    """
    project, parent, rows_path = map(Path, (project, parent, rows_path))
    pinned = expected_ref_sha is not None
    c.need(pinned or ref.get('package_format') == 'p2-snapshot-v1',
           'PARENT_RETRIEVAL_ANCHOR_NOT_QUALIFIED', 'Research Parent requires an independently pinned reference')
    trust.validate_reference(ref, expected_ref_sha if pinned else digest(ref), controlled=controlled)
    info = trust.verify_package(project, parent, ref, controlled=controlled)
    policy = read_json(c.LOCK)['quality_policy']
    c.need(ref['build_fingerprint'] == digest(read_json(c.LOCK)['P2']),
           'IMPLEMENTATION_INCOMPATIBLE', 'Parent build differs from frozen runtime lock')
    spec = ev.frozen_implementation(project, project / ev.BENCHMARK, policy)
    rows_path = checked_file(rows_path.parent, rows_path.name)
    rows_sha = file_digest(rows_path)
    c.need(rows_sha == ref['parent_rows_sha256'], 'AUTHORIZATION_FAILED', 'Parent R2 anchor mismatch')
    rows = read_json(rows_path)
    corpus = read_records(parent / 'corpus.jsonl')
    docs = read_records(parent / 'components/documentation.jsonl')
    c.need([r for r in corpus if r['source_role'] == 'documentation'] == docs,
           'PARENT_RETRIEVAL_ANCHOR_NOT_QUALIFIED', 'Parent documentation component differs from Corpus')
    metrics = ev.rescore(rows, spec, corpus, docs)
    history, historical_sha = rows, rows_sha
    candidate_id = None
    if ref['package_format'] == 'schema2-research-baseline':
        baseline = read_json(checked_file(parent, 'upstream-baseline.json'))
        metadata = read_json(checked_file(parent, 'upstream-candidate.json'))
        bundle = parent / 'approval-evidence'
        evidence = ev.verify_bundle(project, bundle,
            expected_manifest_sha=baseline['identity']['evidence_manifest_sha256'])
        c.need(evidence['mode'] == 'RETRIEVAL_EVALUATED'
               and evidence['execution'] == 'INDEPENDENT_R2_REPLAY_VERIFIED',
               'PARENT_RETRIEVAL_ANCHOR_NOT_QUALIFIED', 'Structural-only approval is not an R2 result anchor')
        candidate_id = metadata['candidate_id']
        quality = read_json(bundle / 'quality.json')
        c.need(baseline['baseline_id'] == ref['node_id'] and baseline['identity']['candidate_id'] == candidate_id
               and evidence['candidate_id'] == candidate_id
               and evidence['source_state'] == ref['source_state']
               and evidence['candidate_corpus_sha256'] == ref['corpus_sha256']
               and metadata['identity']['upstreams'] == ref['upstreams'],
               'PARENT_RETRIEVAL_ANCHOR_NOT_QUALIFIED', 'Approved baseline/original Candidate/result binding mismatch')
        c.need(ev.same(quality['policy'], policy) and ev.same(quality['metrics'], metrics)
               and quality['build_fingerprint'] == ref['build_fingerprint']
               and quality['raw_results_sha256'] == rows_sha
               and file_digest(bundle / ev.RAW_FILES[0]) == rows_sha,
               'PARENT_RETRIEVAL_ANCHOR_NOT_QUALIFIED', 'Result source, quality policy or aggregate binding mismatch')
        # An earlier Candidate's evaluated rows become the next Parent anchor.
        # They keep the Candidate ID; approval creates a distinct baseline ID.
        c.need(file_digest(bundle / 'candidate/corpus.jsonl') == ref['corpus_sha256']
               and file_digest(bundle / 'candidate/components/documentation.jsonl')
                   == file_digest(parent / 'components/documentation.jsonl'),
               'PARENT_RETRIEVAL_ANCHOR_NOT_QUALIFIED', 'Evaluated Corpus/components differ from approved Parent')
        historical = checked_file(bundle, ev.RAW_FILES[2])
        historical_sha = file_digest(historical)
        source_policy = read_json(bundle / 'external-policy.json')
        c.need(source_policy['reference_rows_sha256'][ev.RAW_FILES[2]] == historical_sha,
               'PARENT_RETRIEVAL_ANCHOR_NOT_QUALIFIED', 'Fixed historical anchor differs from pinned approval policy')
        history = read_json(historical)  # Never substitute this Parent's own rows.
    if fresh_replay:
        c.need(ev.same(ev.replay(spec, parent / 'corpus.jsonl', parent / 'components/documentation.jsonl'), rows),
               'RETRIEVAL_EXECUTION_FAILED', 'Pinned parent R2 anchor replay differs')
    c.need(file_digest(rows_path) == rows_sha, 'AUTHORIZATION_FAILED', 'Parent rows changed during qualification')
    # Same binding record in run_local() and verify_run(); trust/replay provenance
    # is reported separately so archive integrity cannot masquerade as authority.
    bindings = {'baseline_id': info['node_id'], 'candidate_id': candidate_id,
        'parent_corpus_sha256': ref['corpus_sha256'], 'upstreams': ref['upstreams'],
        'source_state': ref['source_state'], 'build_fingerprint': ref['build_fingerprint'],
        'benchmark_sha256': policy['benchmark_sha256'], 'R2_fingerprint': policy['R2_fingerprint'],
        'quality_policy_sha256': digest(policy), 'parent_rows_sha256': rows_sha,
        'historical_rows_sha256': historical_sha, 'metrics_sha256': digest(metrics)}
    return {'spec': spec, 'rows': rows, 'historical_rows': history, 'metrics': metrics,
        'parent_verification': info, 'bindings': bindings,
        'status': ('QUALIFIED' if pinned and (fresh_replay or candidate_id is not None)
                   else 'PINNED_ANCHOR_INSPECTED' if pinned else 'ARCHIVE_INTEGRITY_VERIFIED'),
        'reference_trust': 'CALLER_PINNED_REFERENCE' if pinned else 'ARCHIVE_INTEGRITY_ONLY',
        'execution': 'FRESH_R2_REPLAY_VERIFIED' if fresh_replay else 'NO_FRESH_REPLAY',
        'controlled_fixture': controlled, 'quality_acceptance': 'NOT_GRANTED',
        'production_promotion': 'NOT_AUTHORIZED'}
