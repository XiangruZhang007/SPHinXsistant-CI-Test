"""Prepare current-run Q1 descriptors; provenance is verified, never authorized here."""
from pathlib import Path
from . import version_aware_evidence as q
from .corpus_snapshot import read_json, write_json, file_digest, digest, checked_file


def _prepare_legacy(project, root, bindings):
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


def prepare(project, root, bindings, *, package_pins=None, execution_pins=None, output=None):
    """Prepare a diagnostic descriptor; new sealed-run inputs remain untouched.

    New-format package/execution pins are mandatory caller trust inputs. They are
    never recovered from package metadata. An enclosing output directory keeps
    the descriptor OUTSIDE a sealed genuine run. R2 must separately integrate
    this post-seal interface; the current execution entry/gates are unchanged.
    """
    root = Path(root)
    genuine = (root / 'candidate/genuine-candidate.json').is_file()
    upstream = (root / 'candidate/upstream-candidate.json').is_file()
    q.need(genuine != upstream, 'Q1_UNSUPPORTED_CANDIDATE_FORMAT: missing or ambiguous Candidate proof')
    if (root / 'parent/manifest.json').is_file() and (root / 'candidate/upstream-candidate.json').is_file():
        q.need(not (root / 'parent/upstream-baseline.json').exists(), 'Ambiguous Parent format')
        q.need(package_pins is None and execution_pins is None and output is None,
               'Historical Q1 inputs do not accept new-format overrides')
        return _prepare_legacy(project, root, bindings)
    q.need((root / 'parent/upstream-baseline.json').is_file(), 'Unsupported research-baseline Parent format')
    if genuine:
        target_format = read_json(checked_file(root, 'candidate/genuine-candidate.json'))['format']
        q.need(target_format in q.FORMAT_CONTINUOUS and output is not None,
               'Sealed genuine run requires an external descriptor directory')
    else:
        target_format = q.FORMAT_UPSTREAM
        q.need(execution_pins is None, 'Unexpected continuous execution pins')
    destination = Path(output) if output is not None else root
    q.need(destination.is_dir() and not destination.is_symlink()
           and root.resolve().is_relative_to(destination.resolve())
           and (not genuine or root.resolve() != destination.resolve())
           and not ((root / 'checksums.json').exists() and root.resolve() == destination.resolve()),
           'Unsafe Q1 descriptor directory')
    relative = root.resolve().relative_to(destination.resolve())
    def path(name):
        return (relative / name).as_posix()
    paths = {'base': path('parent'), 'target': path('candidate'),
        'base_rows': path('evidence/parent-rows.json' if genuine else 'parent-raw-results.json'),
        'target_rows': path('quality/incremental-raw-results.json')}
    if genuine:
        paths['run'] = relative.as_posix()
    pins = {'build_fingerprint': bindings['build_fingerprint'],
        'base_snapshot_id': bindings['parent_id'], 'target_candidate_id': bindings['candidate_id'],
        'base_source_state_id': bindings['base_source_state'], 'target_source_state_id': bindings['target_source_state'],
        'base_upstreams': bindings['base_upstreams'], 'target_upstreams': bindings['target_upstreams']}
    for label in ('base', 'target'):
        for suffix, name in (('corpus_sha256', 'corpus.jsonl'), ('documentation_sha256', 'components/documentation.jsonl')):
            pins[label + '_' + suffix] = file_digest(checked_file(destination, paths[label] + '/' + name))
        q.need(pins[label + '_corpus_sha256'] == bindings[label + '_corpus_sha256'], 'Current-run Corpus binding differs')
        pins[label + '_rows_sha256'] = file_digest(checked_file(destination, paths[label + '_rows']))
        q.need(pins[label + '_rows_sha256'] == bindings[label + '_rows_sha256'], 'Current-run archived rows binding differs')
    from .approval_evidence import BENCHMARK
    pins['benchmark_sha256'] = file_digest(checked_file(project, BENCHMARK))
    q.need(pins['benchmark_sha256'] == bindings['benchmark_sha256'], 'Current-run benchmark differs')
    descriptor = {'schema_version': 2, 'kind': 'q1-verified-inputs',
        'formats': {'base': q.FORMAT_PARENT, 'target': target_format}, 'paths': paths, 'pins': pins,
        'package_pins': package_pins, 'execution_pins': execution_pins}
    # Verify in memory before writing. No descriptor is added to a package seal.
    manifest = destination / 'q1-auto-inputs.json'
    q.need(not manifest.exists() and not manifest.is_symlink(), 'Q1 descriptor must be new')
    q._load_format_inputs(Path(project), manifest, descriptor)
    write_json(manifest, descriptor)
    checksum = file_digest(manifest)
    q.load_inputs(project, manifest, checksum)
    return manifest, checksum
