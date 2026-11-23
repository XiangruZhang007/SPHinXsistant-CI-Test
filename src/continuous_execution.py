"""Versioned continuous execution experiment; public live execution fails closed.

Only the private synthetic fixture builder is wired. It can produce CONTROLLED
packages only, never genuine Candidates, research approvals or Trusted Parents.
Archive verification is distinct from live authorization and from fresh replay.
"""
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import math
import re
import shutil
import stat
import tempfile
import time

from . import approval_evidence as ev, ci_v2_research as c
from . import continuous_build_policy as scope, incremental_corpus as engine
from . import parent_r2_anchor as anchor, trusted_snapshot as trust
from . import upstream_provenance as legacy
from .corpus_snapshot import (checked_file, digest, file_digest, read_json,
                              read_records, verify_snapshot, write_json)
from .research_baseline import PARITY_FILES
from .research_quality import evaluate_quality
from .indexing_scope import normalize_relative_path

FORMAT = 'continuous-research-candidate-v1'
PROJECTION = 'continuous-evaluator-projection-v1'
SYNTHETIC = 'CONTROLLED_GIT_FIXTURE'
FILES = ('src/continuous_execution.py', 'src/continuous_build_policy.py',
         'src/ci_v2_research.py', 'src/schema2_workflow.py', 'src/q1_current_inputs.py', 'src/trusted_snapshot.py',
         'src/parent_r2_anchor.py', 'src/owner_manual_baseline_approval.py',
         'src/trusted_baseline_registration.py', 'src/trusted_parent_selection.py')
EVIDENCE = ('assessment.json', 'policy-original.json', 'registry.json', 'reference.json',
            'parent-rows.json', 'historical-rows.json', 'execution-contract.json')
MATERIAL = ('corpus.jsonl', 'selection.json', 'inventory.json', 'extraction-graph.json',
            'change-manifest.json', 'reuse-summary.json', 'extraction-trace.json',
            'components/sys.jsonl', 'components/sim.jsonl', 'components/documentation.jsonl')
IDENTITY_FIELDS = {'schema_version', 'format', 'provenance_type', 'generation', 'parent',
                   'upstreams', 'target_source_state', 'build_fingerprint',
                   'historical_orchestration_sha256', 'execution_contract_sha256',
                   'policy_raw_sha256', 'registry_raw_sha256', 'reference_sha256',
                   'scope_subject_sha256', 'artifacts', 'automatic_registration', *c.RESTRICTIONS}
ASSESSMENT_FIELDS = {'schema_version', 'mode', 'status', 'execution_authorization', 'blocker',
                     'subject', 'execution_identity', 'source_evidence', 'parent_assessments',
                     'requirements', 'parent_package_qualification', 'parent_generation',
                     'r2_replay', 'deduplication', 'automatic_registration', *c.RESTRICTIONS}
SUBJECT_FIELDS = {'upstreams', 'parent_key', 'parent_entry_sha256', 'reference_sha256', 'parent_id',
                  'parent_package_checksum', 'parent_corpus_sha256', 'parent_upstreams',
                  'parent_source_state', 'target_source_state', 'policy_path', 'policy_raw_sha256',
                  'policy_canonical_sha256', 'registry_raw_sha256', 'build_fingerprint',
                  'orchestration_fingerprint', 'source_evidence_sha256'}
QUALITY_FILES = {label + suffix for label in ('incremental', 'full')
                 for suffix in ('-raw-results.json', '-frozen-metrics.json', '-availability.json')} | {
                     'transitions.json', 'oracle-applicability.json', 'verified-target-ranks.json',
                     'quality-report.json', 'checksums.json'}


def need(ok, reason):
    c.need(ok, reason, reason)


def contract(project):
    """Compute actual implementation/dependency identity; expected pin is external."""
    project = Path(project); lock = read_json(project / 'configs/ci_v2_runtime_lock.json')
    return {'format': FORMAT, 'schema_version': 1,
            'implementation': {name: file_digest(checked_file(project, name)) for name in FILES},
            'historical': legacy.contract(project), 'P2': lock['P2'], 'P3': lock['P3'],
            'P4_1': lock['P4_1'], 'R2': lock['quality_policy']['R2_fingerprint'],
            'quality_policy_sha256': digest(lock['quality_policy'])}


def _implementation(project, expected):
    need(scope._hash(expected), 'INDEPENDENT_EXECUTION_PIN_REQUIRED')
    actual = contract(project)
    need(actual == contract(Path(__file__).resolve().parents[1]), 'PROJECT_DIFFERS_FROM_EXECUTING_IMPLEMENTATION')
    need(digest(actual) == expected, 'EXECUTION_IMPLEMENTATION_MISMATCH')
    c.frozen_runtime(project)
    return actual


def _trusted_execution_context():
    raise c.GateError('TRUSTED_CONTINUOUS_EXECUTION_NOT_ESTABLISHED',
                      'TRUSTED_CONTINUOUS_EXECUTION_NOT_ESTABLISHED')


def execute(project, registry_path, policy_path, *, expected_execution_contract_sha256,
            expected_policy_sha256, expected_registry_sha256):
    """No CLI switch, environment flag or saved approval can unlock live execution."""
    _implementation(project, expected_execution_contract_sha256)
    scope.load_policy(project, policy_path, expected_policy_sha256)
    registry_path = Path(registry_path)
    scope._read_pinned(registry_path.parent, registry_path.name, expected_registry_sha256)
    _trusted_execution_context()
    # No genuine constructor is connected until the independent trust boundary
    # and all live gates have been reviewed. Hashes alone never grant authority.


def _files(root):
    root = Path(root)
    need(root.is_dir() and not root.is_symlink(), 'UNSAFE_PACKAGE_ROOT')
    files = {}
    for path in root.rglob('*'):
        info = path.lstat(); mode = info.st_mode
        need(stat.S_ISDIR(mode) or stat.S_ISREG(mode), 'UNSAFE_PACKAGE_MEMBER')
        if stat.S_ISREG(mode):
            need(info.st_nlink == 1, 'HARDLINK_PACKAGE_MEMBER')
            files[path.relative_to(root).as_posix()] = file_digest(path)
    return files


def _seal(root):
    need(not (root / 'checksums.json').exists(), 'EXISTING_PACKAGE_SEAL')
    write_json(root / 'checksums.json', _files(root))


def _check_seal(root):
    expected = read_json(checked_file(root, 'checksums.json'))
    need(isinstance(expected, dict), 'INVALID_PACKAGE_SEAL')
    actual = _files(root); actual.pop('checksums.json', None)
    need(actual == expected, 'PACKAGE_SEAL_MISMATCH')
    # File inventories also reject unrecorded empty directories.
    parents = set()
    for name in expected:
        parents.update(p.as_posix() for p in Path(name).parents if p.as_posix() != '.')
    need({p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_dir()} == parents,
         'UNEXPECTED_PACKAGE_DIRECTORY')


def _assemble(project, work, parent, target_source, selection):
    """Small materialization adapter; extraction/chunking/validation stay frozen."""
    candidate = work / 'candidate'; candidate.mkdir()
    for repo in c.SOURCES: (candidate / 'input/repos' / repo).mkdir(parents=True)
    for item in selection:
        relative = Path('repos') / item['repository'] / item['path']
        engine._copy_source(Path(target_source) / relative, candidate / 'input' / relative, item)
    previous = read_json(parent / 'selection.json')
    changes = engine.classify_files(previous, selection)
    status = {engine.key(row): row['change'] for row in changes}
    changed = [row for row in selection if status[engine.key(row)] != 'UNCHANGED']
    emitted, evidence, events, _ = engine._extract_changed(work, changed)
    observations = work / 'extraction-observations'; observations.mkdir()
    names = ('changed-root', 'changed-sys.jsonl', 'changed-sys-summary.json',
             'changed-sim.jsonl', 'changed-sim-summary.json')
    moved = []
    for name in names:
        path = work / name
        if path.exists(): path.rename(observations / name); moved.append(name)
    # Empty scratch directories carry no processing evidence. Actual source
    # copies, generator outputs and summaries remain sealed for inspection.
    for path in sorted(observations.rglob('*'), key=lambda p: len(p.parts), reverse=True):
        if path.is_dir() and not any(path.iterdir()): path.rmdir()
    write_json(observations / 'index.json', {'generator_entries': moved, 'identity_role': 'OBSERVATION_ONLY'})
    old_inventory = {engine.key(row): row for row in read_json(parent / 'inventory.json')}
    old_graph = {engine.key(row): graph for row, graph in
                 zip(previous, read_json(parent / 'extraction-graph.json'))}
    old_components = {name: engine._records(parent / 'components' / (name + '.jsonl'))
                      for name in engine.COMPONENTS}
    components = {name: [] for name in engine.COMPONENTS}; inventory = []; graph = []
    for item in selection:
        key = engine.key(item); component = item['component']; reused = status[key] == 'UNCHANGED'
        if reused:
            old = old_inventory[key]
            records = old_components[component][old['record_start']:old['record_start'] + old['chunk_count']]
            need(digest(records) == old['record_digest'], 'REUSED_RECORD_MISMATCH')
        else: records = emitted[key]
        inventory.append({**item, 'status': 'SUCCESS_WITH_CHUNKS' if records else 'SUCCESS_ZERO_CHUNKS',
                          'error': None, 'record_start': len(components[component]),
                          'chunk_count': len(records), 'chunk_ids': [r['chunk_id'] for r in records],
                          'record_digest': digest(records)})
        components[component].extend(records); graph.append(old_graph[key] if reused else evidence[key])
    (candidate / 'components').mkdir()
    for name, records in components.items():
        engine._write_lines(candidate / 'components' / (name + '.jsonl'), records)
    engine._write_lines(candidate / 'corpus.jsonl', sum(components.values(), []))
    counts = Counter(row['change'] for row in changes)
    summary = {'selected_files': len(selection), 'reused_files': counts['UNCHANGED'],
               'reused_chunks': sum(row['chunk_count'] for row in inventory
                                    if status[engine.key(row)] == 'UNCHANGED'),
               're_extracted_files': len(changed), 'deleted_files': counts['DELETED']}
    values = {'selection.json': selection, 'inventory.json': inventory, 'extraction-graph.json': graph,
              'change-manifest.json': changes, 'reuse-summary.json': summary, 'extraction-trace.json': events}
    for name, value in values.items(): write_json(candidate / name, value)
    engine._verify_materialized(project, candidate, selection, inventory, graph)
    return summary


def _projection(candidate_id, identity):
    return {'kind': PROJECTION, 'schema_version': 1, 'candidate_id': candidate_id,
            'identity': {'base_snapshot_id': identity['parent']['node_id'],
                         'target_fixture_id': identity['target_source_state']}}


def _deterministic(root, selection):
    paths = ['candidate/' + name for name in MATERIAL] + ['evidence/' + name for name in EVIDENCE]
    paths += ['candidate/input/repos/' + row['repository'] + '/' + row['path'] for row in selection]
    return {name: file_digest(checked_file(root, name)) for name in sorted(paths)}


def _archive_policy(policy):
    """Immutable grammar checks only; never assert historical validity from a clock."""
    need(isinstance(policy, dict) and set(policy) == scope.POLICY_FIELDS
         and type(policy['schema_version']) is int and policy['schema_version'] == 1
         and policy['mode'] == scope.MODE and policy['operation'] == 'BUILD_CANDIDATE'
         and policy['enabled'] is True and policy['research_only'] is True
         and policy['requirements'] == scope.REQUIREMENTS and policy['automatic_registration'] is False,
         'INVALID_ARCHIVED_POLICY')
    need(isinstance(policy['policy_id'], str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,63}', policy['policy_id']),
         'INVALID_ARCHIVED_POLICY')
    need(all(type(policy[k]) is type(v) and policy[k] == v for k, v in c.RESTRICTIONS.items()),
         'CHANGED_RESTRICTIONS')
    need(scope._time(policy['valid_from']) < scope._time(policy['expires_at']), 'INVALID_POLICY_INTERVAL')
    need(type(policy['max_advance_commits']) is int and 1 <= policy['max_advance_commits'] <= 4096
         and isinstance(policy['upstreams'], dict) and set(policy['upstreams']) == set(c.SOURCES)
         and isinstance(policy['eligible_parents'], list) and 0 < len(policy['eligible_parents']) <= 16,
         'INVALID_ARCHIVED_POLICY')
    seen = set()
    for parent in policy['eligible_parents']:
        need(isinstance(parent, dict) and set(parent) == {
            'key', 'node_id', 'package_checksum', 'expected_reference_sha256'}, 'INVALID_PARENT_SCOPE')
        c.validate_request('formal', parent['key'], read_json(c.LOCK)['upstreams'])
        need(parent['key'] not in seen and isinstance(parent['node_id'], str)
             and re.fullmatch('sha256-[0-9a-f]{64}', parent['node_id'])
             and scope._hash(parent['package_checksum']) and scope._hash(parent['expected_reference_sha256']),
             'INVALID_PARENT_SCOPE')
        seen.add(parent['key'])


def _archived_sources(policy, evidence, identity):
    base, target = evidence['base_selection'], evidence['target_selection']
    need(all(isinstance(evidence[name], dict) and set(evidence[name]) == set(c.SOURCES)
             for name in ('base_proofs', 'target_proofs', 'relationships', 'source_refs')),
         'INVALID_PROOF_REPOSITORIES')
    need(legacy.state(base) == identity['parent']['source_state']
         and legacy.state(target) == identity['target_source_state'], 'SOURCE_STATE_MISMATCH')
    for repo, url in c.SOURCES.items():
        config = policy['upstreams'][repo]; observed = evidence['source_refs'][repo]
        full_name = url.removeprefix('https://github.com/').removesuffix('.git')
        need(set(config) == {'url', 'repository_id', 'branch'} and config['url'] == url
             and type(config['repository_id']) is int and config['repository_id'] > 0
             and isinstance(config['branch'], str)
             and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._/-]{0,127}', config['branch'])
             and not any(s in config['branch'] for s in ('..', '//', '/.', '.lock'))
             and not config['branch'].endswith(('/', '.'))
             and observed == {'repository_id': config['repository_id'], 'full_name': full_name,
                              'ref': 'refs/heads/' + config['branch'], 'commit': identity['upstreams'][repo],
                              'publications': observed['publications']}, 'ARCHIVED_REF_MISMATCH')
        ids = set()
        for label, selected, revisions in [('base', base, identity['parent']['upstreams']),
                                           ('target', target, identity['upstreams'])]:
            proof = evidence[label + '_proofs'][repo]
            need(proof['repository'] == repo and legacy.verify_proof(proof, selected) == revisions[repo],
                 'GIT_PROOF_MISMATCH')
            tree, parents = legacy._commit(legacy._decoded(proof['commit_raw'], 'commit', proof['commit']))
            receipt = {'sha': proof['commit'], 'tree': tree, 'parents': parents,
                       'html_url': 'https://github.com/' + full_name + '/commit/' + proof['commit']}
            need(observed['publications'][proof['commit']] == receipt, 'ARCHIVED_PUBLICATION_MISMATCH')
            ids.add(proof['commit'])
        need(set(observed['publications']) == ids, 'EXTRA_PUBLICATION_EVIDENCE')
        relationship = evidence['relationships'][repo]
        need(set(relationship) == {'type', 'commits'}, 'INVALID_RELATIONSHIP_FIELDS')
        legacy.verify_relationship(relationship, identity['parent']['upstreams'][repo], identity['upstreams'][repo])
        need(len(relationship['commits']) <= policy['max_advance_commits'], 'TRANSITION_BOUND_EXCEEDED')


def _candidate(project, root, *, expected_execution_contract_sha256, expected_policy_sha256,
               expected_registry_sha256, expected_reference_sha256, expected_candidate_id):
    need(_implementation(project, expected_execution_contract_sha256) ==
         read_json(checked_file(root, 'evidence/execution-contract.json')), 'ARCHIVED_CONTRACT_MISMATCH')
    for name, expected in [('policy-original.json', expected_policy_sha256),
                           ('registry.json', expected_registry_sha256)]:
        need(scope._hash(expected) and file_digest(checked_file(root, 'evidence/' + name)) == expected,
             'EXTERNAL_EVIDENCE_PIN_MISMATCH')
    metadata = read_json(checked_file(root, 'candidate/continuous-candidate.json'))
    need(set(_files(root / 'evidence')) == set(EVIDENCE), 'UNEXPECTED_EVIDENCE_FILES')
    need(isinstance(metadata, dict) and set(metadata) == {'format', 'schema_version', 'candidate_id', 'identity'}
         and metadata['format'] == FORMAT and type(metadata['schema_version']) is int
         and metadata['schema_version'] == 1, 'UNSUPPORTED_CONTINUOUS_FORMAT')
    identity = metadata['identity']
    need(isinstance(identity, dict) and set(identity) == IDENTITY_FIELDS
         and identity['format'] == FORMAT and type(identity['schema_version']) is int
         and identity['schema_version'] == 1 and identity['provenance_type'] == SYNTHETIC,
         'INVALID_CONTINUOUS_IDENTITY')
    need(metadata['candidate_id'] == expected_candidate_id == 'sha256-' + digest(identity),
         'CANDIDATE_ID_MISMATCH')
    c.validate_request('formal', 'continuous-verification', identity['upstreams'])
    need(all(type(identity[k]) is type(v) and identity[k] == v for k, v in c.RESTRICTIONS.items())
         and identity['automatic_registration'] is False, 'CHANGED_RESTRICTIONS')
    need(identity['execution_contract_sha256'] == expected_execution_contract_sha256
         and identity['policy_raw_sha256'] == expected_policy_sha256
         and identity['registry_raw_sha256'] == expected_registry_sha256
         and identity['reference_sha256'] == expected_reference_sha256, 'IDENTITY_PIN_MISMATCH')
    policy = read_json(root / 'evidence/policy-original.json'); _archive_policy(policy)
    need(identity['build_fingerprint'] == policy['build_fingerprint'] == digest(read_json(c.LOCK)['P2'])
         and identity['historical_orchestration_sha256'] == policy['orchestration_fingerprint']
         == digest(legacy.contract(project)), 'HISTORICAL_CONTRACT_MISMATCH')
    ref = read_json(checked_file(root, 'evidence/reference.json'))
    trust.validate_reference(ref, expected_reference_sha256, controlled=True)
    trust.verify_package(project, root / 'parent', ref, controlled=True)
    parent = legacy.verify(project, root / 'parent', identity['build_fingerprint'], expected_id=ref['node_id'])
    need(parent['P4_1_verification'] == 'P4_1_VERIFIED' and parent['provenance_type'] == SYNTHETIC,
         'INVALID_CONTROLLED_PARENT')
    expected_parent = {'node_id': ref['node_id'], 'package_checksum': ref['package_checksum'],
                       'generation': parent['generation'], 'source_state': ref['source_state'],
                       'upstreams': ref['upstreams'], 'corpus_sha256': ref['corpus_sha256']}
    need(identity['parent'] == expected_parent and type(identity['parent']['generation']) is int
         and type(identity['generation']) is int
         and identity['generation'] == parent['generation'] + 1, 'PARENT_GENERATION_MISMATCH')
    assessment = read_json(checked_file(root, 'evidence/assessment.json')); subject = assessment['subject']
    need(set(assessment) == ASSESSMENT_FIELDS and set(subject) == SUBJECT_FIELDS and assessment['mode'] == scope.MODE
         and type(assessment['schema_version']) is int and assessment['schema_version'] == 1
         and assessment['requirements'] == scope.REQUIREMENTS
         and assessment['automatic_registration'] is False
         and all(type(assessment[k]) is type(v) and assessment[k] == v for k, v in c.RESTRICTIONS.items())
         and assessment['status'] == scope.PLAN_STATUS and assessment['execution_authorization'] == 'BLOCKED'
         and assessment['execution_identity'] == digest(subject) == identity['scope_subject_sha256'],
         'ASSESSMENT_IDENTITY_MISMATCH')
    registry = read_json(root / 'evidence/registry.json'); entry = registry['baselines'][subject['parent_key']]
    need('entry_kind' not in entry and entry['reference'] == ref
         and entry['expected_reference_sha256'] == expected_reference_sha256
         and subject['parent_entry_sha256'] == digest(entry)
         and subject['policy_raw_sha256'] == expected_policy_sha256
         and subject['policy_canonical_sha256'] == digest(policy)
         and subject['registry_raw_sha256'] == expected_registry_sha256
         and subject['upstreams'] == identity['upstreams']
         and subject['reference_sha256'] == expected_reference_sha256
         and subject['parent_id'] == ref['node_id'] and subject['parent_package_checksum'] == ref['package_checksum']
         and subject['parent_corpus_sha256'] == ref['corpus_sha256'] and subject['parent_upstreams'] == ref['upstreams']
         and subject['parent_source_state'] == ref['source_state']
         and subject['build_fingerprint'] == identity['build_fingerprint']
         and subject['orchestration_fingerprint'] == identity['historical_orchestration_sha256']
         and subject['target_source_state'] == identity['target_source_state'], 'ARCHIVED_SCOPE_MISMATCH')
    need(normalize_relative_path(subject['policy_path']) == subject['policy_path'], 'UNSAFE_POLICY_LOCATION')
    need({'key': subject['parent_key'], 'node_id': ref['node_id'], 'package_checksum': ref['package_checksum'],
          'expected_reference_sha256': expected_reference_sha256} in policy['eligible_parents'], 'PARENT_OUTSIDE_SCOPE')
    evidence = assessment['source_evidence']
    need(set(evidence) == {'base_selection', 'target_selection', 'base_proofs', 'target_proofs',
                          'relationships', 'source_refs'}, 'UNEXPECTED_SOURCE_EVIDENCE')
    need(subject['source_evidence_sha256'] == digest(evidence), 'SOURCE_EVIDENCE_MISMATCH')
    _archived_sources(policy, evidence, identity)
    need(evidence['base_selection'] == read_json(root / 'parent/selection.json'), 'PARENT_SELECTION_MISMATCH')
    selection = read_json(root / 'candidate/selection.json')
    need(selection == evidence['target_selection'] and identity['artifacts'] == _deterministic(root, selection),
         'DETERMINISTIC_ARTIFACT_MISMATCH')
    need(read_json(root / 'candidate/candidate.json') == _projection(expected_candidate_id, identity),
         'EVALUATOR_PROJECTION_MISMATCH')
    expected_files = {name.removeprefix('candidate/') for name in identity['artifacts'] if name.startswith('candidate/')}
    need(set(_files(root / 'candidate')) == expected_files | {'candidate.json', 'continuous-candidate.json'},
         'UNEXPECTED_CANDIDATE_FILES')
    engine._verify_materialized(project, root / 'candidate', selection,
                                read_json(root / 'candidate/inventory.json'), read_json(root / 'candidate/extraction-graph.json'))
    return metadata


def _parity(project, root, metadata):
    identity = metadata['identity']; full = root / 'full'
    report = verify_snapshot(full, identity['build_fingerprint'])
    need(report['build_compatibility'] == 'COMPATIBLE'
         and read_json(full / 'manifest.json')['identity']['upstreams'] == identity['upstreams'], 'FULL_TARGET_MISMATCH')
    comparisons = {name: {'sha256': file_digest(root / 'candidate' / name),
                          'full_sha256': file_digest(full / name),
                          'exact_bytes_equal': (root / 'candidate' / name).read_bytes() == (full / name).read_bytes()}
                   for name in PARITY_FILES}
    need(all(row['exact_bytes_equal'] for row in comparisons.values()), 'PARITY_MISMATCH')
    return {'status': 'PARITY_PASS', 'candidate_id': metadata['candidate_id'], 'comparisons': comparisons,
            'full_reference_independently_built': True}


def verify_package(project, package, *, expected_execution_contract_sha256, expected_policy_sha256,
                   expected_registry_sha256, expected_reference_sha256, expected_candidate_id,
                   expected_manifest_sha256, fresh_replay=False):
    """Offline verification: no API, current branch lookup or policy-clock check."""
    need(type(fresh_replay) is bool, 'INVALID_REPLAY_MODE')
    root = Path(package)
    need(scope._hash(expected_manifest_sha256)
         and file_digest(checked_file(root, 'checksums.json')) == expected_manifest_sha256,
         'INDEPENDENT_PACKAGE_SEAL_MISMATCH')
    _check_seal(root)
    metadata = _candidate(project, root, expected_execution_contract_sha256=expected_execution_contract_sha256,
                          expected_policy_sha256=expected_policy_sha256, expected_registry_sha256=expected_registry_sha256,
                          expected_reference_sha256=expected_reference_sha256, expected_candidate_id=expected_candidate_id)
    need(read_json(root / 'parity.json') == _parity(project, root, metadata), 'PARITY_RECEIPT_MISMATCH')
    ref = read_json(root / 'evidence/reference.json')
    qualified = anchor.qualify_parent_anchor(project, root / 'parent', ref, expected_reference_sha256,
                     root / 'evidence/parent-rows.json', fresh_replay=fresh_replay, controlled=True)
    need(qualified['bindings'] == read_json(root / 'parent-anchor.json')['bindings'], 'PARENT_ANCHOR_MISMATCH')
    need(ev.same(read_json(root / 'evidence/historical-rows.json'), qualified['historical_rows']),
         'HISTORICAL_ANCHOR_MISMATCH')
    quality = read_json(root / 'quality/quality-report.json'); policy = read_json(c.LOCK)['quality_policy']
    need({p.name for p in (root / 'quality').iterdir()} == QUALITY_FILES, 'UNEXPECTED_QUALITY_FILES')
    _check_seal(root / 'quality')
    need(quality['candidate_id'] == expected_candidate_id and ev.same(quality['policy'], policy)
         and quality['status'] == 'QUALITY_REVIEW_REQUIRED' and quality['assessment'] == 'FROZEN_128_EVALUATED',
         'QUALITY_BINDING_MISMATCH')
    spec = ev.frozen_implementation(project, Path(project) / ev.BENCHMARK, policy)
    rows = {}
    for label, folder in [('incremental', root / 'candidate'), ('full', root / 'full')]:
        rows[label] = read_json(root / 'quality' / (label + '-raw-results.json'))
        metrics = ev.rescore(rows[label], spec, read_records(folder / 'corpus.jsonl'),
                             read_records(folder / 'components/documentation.jsonl'))
        need(ev.same(metrics, quality['metrics']), 'RETRIEVAL_METRICS_MISMATCH')
        replay = ev.replay(spec, folder / 'corpus.jsonl', folder / 'components/documentation.jsonl') if fresh_replay else read_json(root / (label + '-replay.json'))
        need(ev.same(rows[label], replay), 'R2_REPLAY_MISMATCH')
    need(ev.same(rows['incremental'], rows['full'])
         and quality['raw_results_sha256'] == file_digest(root / 'quality/incremental-raw-results.json'), 'RAW_RESULT_MISMATCH')
    transitions = {label: ev.compare_outcomes(previous, rows['incremental'], spec)
                   for label, previous in [('historical', qualified['historical_rows']),
                                            ('immediate_parent', qualified['rows'])]}
    need(read_json(root / 'quality/transitions.json') == transitions, 'TRANSITION_EVIDENCE_MISMATCH')
    for name, direction in [('new_losses', 'PASS→FAIL'), ('new_gains', 'FAIL→PASS')]:
        expected = {label: [row for row in values if row['hit5'] == direction or row['hit10'] == direction]
                    for label, values in transitions.items()}
        need(quality[name] == expected, 'QUALITY_TRANSITION_MISMATCH')
    applicability = ev.oracle_applicability(spec, read_records(root / 'candidate/corpus.jsonl'),
                      read_records(root / 'parent/corpus.jsonl'), root / 'candidate/input', root / 'parent/input')
    need(read_json(root / 'quality/oracle-applicability.json') == applicability
         and quality['applicability_changes'] == [a for a in applicability
              if a['previous_available'] != a['target_available']], 'APPLICABILITY_EVIDENCE_MISMATCH')
    observations = read_json(checked_file(root, 'observations.json'))
    need(set(observations) == {'context', 'started_at', 'work_directory', 'elapsed_seconds'}
         and observations['context'] == 'SYNTHETIC_OFFLINE_TEST_ONLY'
         and isinstance(observations['started_at'], str) and isinstance(observations['work_directory'], str)
         and type(observations['elapsed_seconds']) in (int, float)
         and math.isfinite(observations['elapsed_seconds']) and observations['elapsed_seconds'] >= 0,
         'INVALID_OBSERVATION_CONTEXT')
    allowed = {'candidate', 'parent', 'full', 'quality', 'evidence', 'extraction-observations', 'observations.json', 'parity.json',
               'parent-anchor.json', 'incremental-replay.json', 'full-replay.json', 'checksums.json'}
    need({p.name for p in root.iterdir()} == allowed, 'UNEXPECTED_PACKAGE_CONTENTS')
    return {'status': 'OFFLINE_PACKAGE_VERIFIED', 'candidate_id': expected_candidate_id,
            'format': FORMAT, 'provenance_type': SYNTHETIC, 'parity': 'PARITY_PASS',
            'replay': 'FRESH_SYNTHETIC_R2_REPLAY' if fresh_replay else 'SEALED_REPLAY_INSPECTED',
            'live_authorization': 'NOT_ESTABLISHED', 'historical_owner_authorization': 'NOT_ESTABLISHED',
            'policy_validity_at_execution': 'NOT_INDEPENDENTLY_ESTABLISHED',
            'source_refs': 'ARCHIVED_OBSERVATIONS_NOT_FRESH_AUTHORITY',
            'research_approval': 'NOT_GRANTED', 'trusted_parent_eligibility': 'NOT_GRANTED', **c.RESTRICTIONS}


def _build_synthetic_fixture(project, archive, base_source, target_source, output, *,
                             registry_path, policy_path, expected_execution_contract_sha256,
                             expected_policy_sha256, expected_registry_sha256,
                             ref, expected_reference_sha256, parent_rows_path, revisions):
    """Private test helper. Always CONTROLLED; no genuine mode or public switch.

    Tests may mock official API observations and local transport validation only.
    The actual local Parent must be an evaluated controlled P4.1 fixture. No
    return value from an injected authorization provider can replace that check.
    """
    project, output = Path(project), Path(output)
    implementation = _implementation(project, expected_execution_contract_sha256)
    policy = scope.load_policy(project, policy_path, expected_policy_sha256)
    need(policy['policy_id'].startswith('synthetic-')
         and ref['storage']['kind'] == 'LOCAL_QUALIFICATION_ONLY', 'CONTROLLED_FIXTURE_ONLY')
    policy_file = checked_file(project, policy_path)
    legacy._new_output(output, (project, archive, base_source, target_source, policy_file, parent_rows_path))
    arguments = dict(expected_policy_sha256=expected_policy_sha256,
                     expected_registry_sha256=expected_registry_sha256, revisions=revisions,
                     base_source=base_source, target_source=target_source)
    assessed = scope.assess_scope(project, registry_path, policy_path, **arguments)
    need(digest(ref) == expected_reference_sha256
         and assessed['subject']['reference_sha256'] == expected_reference_sha256, 'PARENT_REFERENCE_MISMATCH')
    started = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat()
    with tempfile.TemporaryDirectory(prefix='continuous-synthetic-', dir=output.parent) as temporary:
        stage = Path(temporary) / 'run'; stage.mkdir()
        trust.restore(project, archive, stage / 'parent', ref, expected_reference_sha256, controlled=True)
        qualified = anchor.qualify_parent_anchor(project, stage / 'parent', ref, expected_reference_sha256,
                                                 parent_rows_path, fresh_replay=True, controlled=True)
        parent = legacy.verify(project, stage / 'parent', ref['build_fingerprint'], expected_id=ref['node_id'])
        need(parent['provenance_type'] == SYNTHETIC and parent['P4_1_verification'] == 'P4_1_VERIFIED'
             and qualified['execution'] == 'FRESH_R2_REPLAY_VERIFIED', 'CONTROLLED_EVALUATED_PARENT_REQUIRED')
        evidence = stage / 'evidence'; evidence.mkdir()
        for name, source in [('policy-original.json', policy_file), ('registry.json', Path(registry_path)),
                              ('parent-rows.json', Path(parent_rows_path))]: shutil.copyfile(source, evidence / name)
        for name, value in [('reference.json', ref), ('assessment.json', assessed),
                             ('historical-rows.json', qualified['historical_rows']),
                             ('execution-contract.json', implementation)]: write_json(evidence / name, value)
        write_json(stage / 'parent-anchor.json', {k: qualified[k] for k in ('bindings', 'execution', 'status', 'controlled_fixture')})
        selection = assessed['source_evidence']['target_selection']
        _assemble(project, stage, stage / 'parent', target_source, selection)
        scope.revalidate_scope(assessed, project, registry_path, policy_path,
                                expected_plan_sha256=digest(assessed), **arguments)
        identity = {'schema_version': 1, 'format': FORMAT, 'provenance_type': SYNTHETIC,
                    'generation': parent['generation'] + 1,
                    'parent': {'node_id': ref['node_id'], 'package_checksum': ref['package_checksum'],
                               'generation': parent['generation'], 'source_state': ref['source_state'],
                               'upstreams': ref['upstreams'], 'corpus_sha256': ref['corpus_sha256']},
                    'upstreams': revisions, 'target_source_state': legacy.state(selection),
                    'build_fingerprint': ref['build_fingerprint'],
                    'historical_orchestration_sha256': digest(legacy.contract(project)),
                    'execution_contract_sha256': expected_execution_contract_sha256,
                    'policy_raw_sha256': expected_policy_sha256, 'registry_raw_sha256': expected_registry_sha256,
                    'reference_sha256': expected_reference_sha256, 'scope_subject_sha256': assessed['execution_identity'],
                    'artifacts': _deterministic(stage, selection), 'automatic_registration': False, **c.RESTRICTIONS}
        candidate_id = 'sha256-' + digest(identity)
        write_json(stage / 'candidate/continuous-candidate.json',
                   {'format': FORMAT, 'schema_version': 1, 'candidate_id': candidate_id, 'identity': identity})
        write_json(stage / 'candidate/candidate.json', _projection(candidate_id, identity))
        pins = dict(expected_execution_contract_sha256=expected_execution_contract_sha256,
                    expected_policy_sha256=expected_policy_sha256, expected_registry_sha256=expected_registry_sha256,
                    expected_reference_sha256=expected_reference_sha256, expected_candidate_id=candidate_id)
        metadata = _candidate(project, stage, **pins)
        legacy.full_reference(project, Path(target_source).resolve(), stage / 'full', revisions, ref['build_fingerprint'])
        write_json(stage / 'parity.json', _parity(project, stage, metadata))
        lock = read_json(c.LOCK)
        evaluate_quality(project, stage / 'candidate', stage / 'full', stage / 'quality',
                         benchmark=project / ev.BENCHMARK, policy=lock['quality_policy'],
                         expected_fingerprint=ref['build_fingerprint'], historical_rows=qualified['historical_rows'],
                         parent_rows=qualified['rows'], parent_corpus=stage / 'parent/corpus.jsonl', parent_sources=base_source)
        for label, folder in [('incremental', stage / 'candidate'), ('full', stage / 'full')]:
            actual = ev.replay(qualified['spec'], folder / 'corpus.jsonl', folder / 'components/documentation.jsonl')
            need(ev.same(actual, read_json(stage / 'quality' / (label + '-raw-results.json'))), 'R2_REPLAY_MISMATCH')
            write_json(stage / (label + '-replay.json'), actual)
        scope.revalidate_scope(assessed, project, registry_path, policy_path,
                                expected_plan_sha256=digest(assessed), **arguments)
        _implementation(project, expected_execution_contract_sha256)
        need(file_digest(archive) == ref['transport_sha256'], 'PARENT_TRANSPORT_CHANGED')
        write_json(stage / 'observations.json', {'context': 'SYNTHETIC_OFFLINE_TEST_ONLY',
                   'started_at': started_at, 'work_directory': str(stage),
                   'elapsed_seconds': time.monotonic() - started})
        _seal(stage)
        manifest_sha = file_digest(stage / 'checksums.json')
        result = verify_package(project, stage, expected_manifest_sha256=manifest_sha, **pins)
        result['manifest_sha256'] = manifest_sha
        output.mkdir(exist_ok=False)
        stage.replace(output)  # Replace only our newly created empty destination.
        return result
