"""Prepare current-run Q1 descriptors; provenance is verified, never authorized here."""
from pathlib import Path
from . import version_aware_evidence as q
from .corpus_snapshot import read_json, write_json, file_digest, digest, checked_file


def prepare(project, root, bindings):
    """Called only after authorized construction/evaluation, before run sealing.

    Derived checksums record current bytes, not independent human approval. The
    existing loader verifies packages/Git proofs/source spans/benchmark/rows.
    Bindings come from the mandatory caller, independently of this descriptor.
    """
    root = Path(root)
    paths = {'base': 'parent', 'target': 'candidate', 'base_rows': 'parent-raw-results.json',
             'target_rows': 'quality/incremental-raw-results.json', 'benchmark': 'benchmark.json'}
    q.need((root/'candidate/upstream-candidate.json').is_file(),
           'Q1_UNSUPPORTED_CANDIDATE_FORMAT: existing upstream Candidate proof required')
    base = read_json(checked_file(root, 'parent/manifest.json'))['identity']
    target = read_json(checked_file(root, 'candidate/upstream-candidate.json'))['identity']
    pins = {'build_fingerprint': bindings['build_fingerprint'],
            'base_snapshot_id': bindings['parent_id'], 'target_candidate_id': bindings['candidate_id'],
            'base_source_state_id': bindings['base_source_state'],
            'target_source_state_id': bindings['target_source_state'],
            'base_upstreams': bindings['base_upstreams'], 'target_upstreams': bindings['target_upstreams']}
    q.need(base['upstreams'] == pins['base_upstreams'] and target['upstreams'] == pins['target_upstreams'],
           'Current-run upstream bindings differ')
    for label, folder in [('base', 'parent'), ('target', 'candidate')]:
        for suffix, name in [('corpus_sha256', 'corpus.jsonl'),
                             ('documentation_sha256', 'components/documentation.jsonl')]:
            pins[label + '_' + suffix] = file_digest(checked_file(root, folder + '/' + name))
        q.need(pins[label + '_corpus_sha256'] == bindings[label + '_corpus_sha256'],
               'Current-run Corpus binding differs')
        pins[label + '_rows_sha256'] = file_digest(checked_file(root, paths[label + '_rows']))
        q.need(pins[label + '_rows_sha256'] == bindings[label + '_rows_sha256'],
               'Current-run archived rows binding differs')
    pins['benchmark_sha256'] = file_digest(checked_file(root, paths['benchmark']))
    q.need(pins['benchmark_sha256'] == bindings['benchmark_sha256'], 'Current-run benchmark differs')
    descriptor = {'schema_version': 1, 'kind': 'q1-verified-inputs', 'paths': paths, 'pins': pins}
    manifest = root / 'q1-auto-inputs.json'
    q.need(not manifest.exists() and not manifest.is_symlink(), 'Q1 descriptor must be new')
    write_json(manifest, descriptor)
    checksum = file_digest(manifest)
    # The independent verifier rejects package/identity/source/row inconsistencies.
    q.load_inputs(project, manifest, checksum)
    return manifest, checksum
