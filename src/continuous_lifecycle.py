"""Controlled-fixture lifecycle compatibility; no genuine approval or registration.

The private fixture constructor exercises existing decision/evidence checks.
Its outputs never establish Owner authority or enter the old Registry format.
"""
from pathlib import Path
import shutil
import tempfile

from . import approval_evidence as ev, ci_v2_research as c
from . import continuous_execution as execution, continuous_build_policy as scope
from . import upstream_provenance as legacy
from .research_baseline import _check_decisions, package_checksum
from .corpus_snapshot import checked_file, digest, file_digest, read_json, read_records, write_json

FORMAT = 'continuous-controlled-baseline-v1'
SUBJECT = 'continuous-controlled-approval-subject-v1'
DECISION = 'controlled-lifecycle-test-decision-v1'
REFERENCE = 'continuous-controlled-parent-reference-v1'
PINS = {'expected_execution_contract_sha256', 'expected_policy_sha256',
        'expected_registry_sha256', 'expected_reference_sha256',
        'expected_candidate_id', 'expected_manifest_sha256'}
RESTRICTIONS = {**c.RESTRICTIONS, 'automatic_registration': False,
                'owner_authorization': 'NOT_ESTABLISHED', 'quality_acceptance': 'NOT_GRANTED',
                'q1_qualification': 'NOT_GRANTED', 'P8': 'BLOCKED'}


def need(ok, reason):
    c.need(ok, reason, reason)


def contract(project):
    """Separate adapter contract: does not change the execution/historical locks."""
    return {'schema_version': 1, 'format': FORMAT,
            'adapter_sha256': file_digest(checked_file(project, 'src/continuous_lifecycle.py')),
            'execution': execution.contract(project)}


def _implementation(project, expected):
    need(scope._hash(expected), 'INDEPENDENT_LIFECYCLE_PIN_REQUIRED')
    actual = contract(project)
    need(actual == contract(Path(__file__).resolve().parents[1]), 'LIFECYCLE_IMPLEMENTATION_MISMATCH')
    need(digest(actual) == expected, 'LIFECYCLE_IMPLEMENTATION_PIN_MISMATCH')
    return actual


def approve(*args, **kwargs):
    """Reserved genuine entry: neither supplied JSON nor local flags authorize it."""
    raise c.GateError('TRUSTED_CONTINUOUS_LIFECYCLE_NOT_ESTABLISHED',
                      'TRUSTED_CONTINUOUS_LIFECYCLE_NOT_ESTABLISHED')


def approval_subject(project, package, *, candidate_pins,
                     expected_lifecycle_contract_sha256, expected_approval_policy_sha256):
    """Read-only reconstruction; the resulting digest is not an authorization."""
    _implementation(project, expected_lifecycle_contract_sha256)
    need(isinstance(candidate_pins, dict) and set(candidate_pins) == PINS, 'INVALID_CANDIDATE_PINS')
    need(scope._hash(expected_approval_policy_sha256), 'INDEPENDENT_APPROVAL_POLICY_PIN_REQUIRED')
    verified = execution.verify_package(project, package, **candidate_pins, fresh_replay=False)
    root = Path(package)
    metadata = read_json(checked_file(root, 'candidate/continuous-candidate.json'))
    identity = metadata['identity']
    return {'schema_version': 1, 'kind': SUBJECT, 'provenance_type': execution.SYNTHETIC,
            'candidate_id': verified['candidate_id'], 'candidate_identity_sha256': digest(identity),
            'candidate_pins': dict(candidate_pins), 'parent': identity['parent'],
            'generation': identity['generation'], 'source_state': identity['target_source_state'],
            'upstreams': identity['upstreams'],
            'corpus_sha256': file_digest(root / 'candidate/corpus.jsonl'),
            'lifecycle_contract_sha256': expected_lifecycle_contract_sha256,
            'approval_policy_sha256': expected_approval_policy_sha256, **RESTRICTIONS}


def _decisions(project, root, subject, policy_path, policy_sha, decision_path, decision_sha):
    policy_path, decision_path = Path(policy_path), Path(decision_path)
    policy = scope._read_pinned(policy_path.parent, policy_path.name, policy_sha)
    decision = scope._read_pinned(decision_path.parent, decision_path.name, decision_sha)
    need(isinstance(decision, dict) and set(decision) == {
        'schema_version', 'kind', 'provenance_type', 'subject_sha256', 'authorization'},
        'INVALID_CONTROLLED_DECISION')
    need(type(decision['schema_version']) is int and decision['schema_version'] == 1
         and decision['kind'] == DECISION and decision['provenance_type'] == execution.SYNTHETIC
         and decision['subject_sha256'] == digest(subject), 'CONTROLLED_DECISION_SUBJECT_MISMATCH')
    auth = decision['authorization']
    need(isinstance(auth, dict) and set(auth) == {'schema_version', 'approved', 'research_only',
         'candidate_id', 'parent_baseline_id', 'experiment_id', 'quality_status', 'allow_quality_review'},
         'INVALID_FIXTURE_AUTHORIZATION')
    need(type(auth['schema_version']) is int and auth['schema_version'] == 1
         and isinstance(auth['experiment_id'], str) and auth['experiment_id'].startswith('synthetic-'),
         'CONTROLLED_EXPERIMENT_REQUIRED')
    need(isinstance(policy, dict) and set(policy) == {'schema_version', 'mode', 'scope',
         'reference_rows_sha256', 'quality_status', 'automatic_reuse', 'production_promotion'}
         and type(policy['schema_version']) is int and policy['schema_version'] == 1
         and policy['mode'] == 'RETRIEVAL_EVALUATED', 'EVALUATED_APPROVAL_POLICY_REQUIRED')
    quality = read_json(root / 'quality/quality-report.json')
    verified_parent = legacy.verify(project, root / 'parent', quality['build_fingerprint'],
                                    expected_id=subject['parent']['node_id'])
    need(verified_parent['P4_1_verification'] == 'P4_1_VERIFIED', 'EVALUATED_PARENT_REQUIRED')
    parent = {**subject['parent'], 'baseline_id': verified_parent['node_id'],
              'P4_1_verification': verified_parent['P4_1_verification']}
    _check_decisions(auth, quality, subject['candidate_id'], parent['baseline_id'],
                     subject['corpus_sha256'], quality['build_fingerprint'])
    ev.external_policy(policy_path, policy_sha, candidate=root / 'candidate',
                       parent=parent, quality=quality, authorization=auth)
    expected_rows = {ev.RAW_FILES[2]: file_digest(root / 'evidence/historical-rows.json'),
                     ev.RAW_FILES[3]: file_digest(root / 'evidence/parent-rows.json')}
    need(ev.same(policy['reference_rows_sha256'], expected_rows), 'APPROVAL_REFERENCE_ROWS_MISMATCH')
    return policy, decision, parent


def _identity(root, subject, decision_sha):
    payload = execution._files(root)
    payload.pop('baseline.json', None); payload.pop('checksums.json', None)
    return {'schema_version': 1, 'format': FORMAT, 'provenance_type': execution.SYNTHETIC,
            'candidate_id': subject['candidate_id'],
            'candidate_identity': read_json(root / 'original/candidate/continuous-candidate.json')['identity'],
            'parent': subject['parent'], 'generation': subject['generation'],
            'source_state': subject['source_state'], 'upstreams': subject['upstreams'],
            'corpus_sha256': subject['corpus_sha256'], 'approval_subject': subject,
            'decision_raw_sha256': decision_sha,
            'evidence_manifest_sha256': file_digest(root / 'approval-evidence/checksums.json'),
            'artifacts': payload, **RESTRICTIONS}


def _baseline_pins(candidate_pins, lifecycle_sha, policy_sha, decision_sha):
    return {'candidate_pins': candidate_pins, 'expected_lifecycle_contract_sha256': lifecycle_sha,
            'expected_approval_policy_sha256': policy_sha, 'expected_decision_sha256': decision_sha}


def _approve_controlled_fixture(project, package, output, *, candidate_pins,
                                expected_lifecycle_contract_sha256, approval_policy,
                                expected_approval_policy_sha256, decision_path, expected_decision_sha256):
    """Private synthetic constructor, never a genuine authorization path.

    Matching external pins and a fixture decision exercise contract compatibility;
    they do not establish real Owner approval. No CLI exposes this constructor.
    """
    project, root, output = Path(project), Path(package), Path(output)
    subject = approval_subject(project, root, candidate_pins=candidate_pins,
        expected_lifecycle_contract_sha256=expected_lifecycle_contract_sha256,
        expected_approval_policy_sha256=expected_approval_policy_sha256)
    _, decision, _ = _decisions(project, root, subject, approval_policy, expected_approval_policy_sha256,
                                decision_path, expected_decision_sha256)
    legacy._new_output(output, (project, root, approval_policy, decision_path))
    # External fixture policy/decision must be supplied independently of the package.
    for path in (approval_policy, decision_path):
        need(not Path(path).resolve().is_relative_to(root.resolve()), 'DECISION_INSIDE_CANDIDATE')
    common = _baseline_pins(candidate_pins, expected_lifecycle_contract_sha256,
                            expected_approval_policy_sha256, expected_decision_sha256)
    with tempfile.TemporaryDirectory(prefix='continuous-lifecycle-', dir=output.parent) as temporary:
        stage = Path(temporary) / 'baseline'; stage.mkdir()
        shutil.copytree(root, stage / 'original')
        shutil.copyfile(approval_policy, stage / 'approval-policy.json')
        shutil.copyfile(decision_path, stage / 'controlled-decision.json')
        # Reverify the actual copied inputs before using the frozen evidence writer.
        copied = approval_subject(project, stage / 'original', candidate_pins=candidate_pins,
            expected_lifecycle_contract_sha256=expected_lifecycle_contract_sha256,
            expected_approval_policy_sha256=expected_approval_policy_sha256)
        need(ev.same(copied, subject), 'COPIED_CANDIDATE_MISMATCH')
        _, decision, parent = _decisions(project, stage / 'original', subject, stage / 'approval-policy.json',
            expected_approval_policy_sha256, stage / 'controlled-decision.json', expected_decision_sha256)
        with tempfile.TemporaryDirectory(prefix='raw-', dir=temporary) as raw_dir:
            raw = Path(raw_dir); original = stage / 'original'
            for target, source in zip(ev.RAW_FILES, ('quality/incremental-raw-results.json',
                    'quality/full-raw-results.json', 'evidence/historical-rows.json', 'evidence/parent-rows.json')):
                shutil.copyfile(original / source, raw / target)
            quality = read_json(original / 'quality/quality-report.json')
            write_json(raw / 'inputs.json', ev.input_manifest(original / 'candidate', original / 'full',
                       quality, expected_approval_policy_sha256, raw))
            ev.create_evidence(project, original / 'candidate', original / 'parent', original / 'full',
                stage / 'approval-evidence', quality, decision['authorization'],
                stage / 'approval-policy.json', expected_approval_policy_sha256, parent_report=parent, evidence=raw)
        identity = _identity(stage, subject, expected_decision_sha256)
        baseline_id = 'sha256-' + digest(identity)
        need(baseline_id != subject['candidate_id'], 'BASELINE_CANDIDATE_ID_COLLISION')
        write_json(stage / 'baseline.json', {'format': FORMAT, 'baseline_id': baseline_id, 'identity': identity})
        execution._seal(stage)
        report = verify_baseline(project, stage, **common, expected_baseline_id=baseline_id,
                                 expected_manifest_sha256=file_digest(stage / 'checksums.json'))
        output.mkdir(exist_ok=False); stage.replace(output)
        return report


def verify_baseline(project, baseline, *, candidate_pins, expected_lifecycle_contract_sha256,
                    expected_approval_policy_sha256, expected_decision_sha256,
                    expected_baseline_id, expected_manifest_sha256, fresh_replay=False):
    """Verify a controlled package; report fixture approval separately from authority."""
    need(type(fresh_replay) is bool, 'INVALID_REPLAY_MODE')
    root = Path(baseline)
    need(scope._hash(expected_manifest_sha256) and
         file_digest(checked_file(root, 'checksums.json')) == expected_manifest_sha256,
         'INDEPENDENT_BASELINE_MANIFEST_MISMATCH')
    execution._check_seal(root)
    need({p.name for p in root.iterdir()} == {'original', 'approval-evidence', 'approval-policy.json',
         'controlled-decision.json', 'baseline.json', 'checksums.json'}, 'UNEXPECTED_BASELINE_CONTENTS')
    metadata = read_json(checked_file(root, 'baseline.json'))
    need(isinstance(metadata, dict) and set(metadata) == {'format', 'baseline_id', 'identity'}
         and metadata['format'] == FORMAT, 'UNSUPPORTED_CONTROLLED_BASELINE')
    original = root / 'original'
    subject = approval_subject(project, original, candidate_pins=candidate_pins,
        expected_lifecycle_contract_sha256=expected_lifecycle_contract_sha256,
        expected_approval_policy_sha256=expected_approval_policy_sha256)
    _, decision, _ = _decisions(project, original, subject, root / 'approval-policy.json',
        expected_approval_policy_sha256, root / 'controlled-decision.json', expected_decision_sha256)
    identity = _identity(root, subject, expected_decision_sha256)
    need(ev.same(metadata['identity'], identity)
         and metadata['baseline_id'] == expected_baseline_id == 'sha256-' + digest(identity)
         and expected_baseline_id != subject['candidate_id'], 'CONTROLLED_BASELINE_IDENTITY_MISMATCH')
    bundle = root / 'approval-evidence'
    evidence = ev.verify_bundle(project, bundle, expected_manifest_sha=identity['evidence_manifest_sha256'],
                                fresh_replay=fresh_replay)
    need(evidence['mode'] == 'RETRIEVAL_EVALUATED'
         and evidence['execution'] == 'INDEPENDENT_R2_REPLAY_VERIFIED'
         and evidence['candidate_id'] == subject['candidate_id']
         and evidence['parent_baseline_id'] == subject['parent']['node_id'], 'EVALUATED_EVIDENCE_REQUIRED')
    need(file_digest(bundle / 'external-policy.json') == expected_approval_policy_sha256
         and ev.same(read_json(bundle / 'authorization.json'), decision['authorization'])
         and ev.same(read_json(bundle / 'quality.json'), read_json(original / 'quality/quality-report.json')),
         'BUNDLE_APPROVAL_BINDING_MISMATCH')
    raw_sources = ('quality/incremental-raw-results.json', 'quality/full-raw-results.json',
                   'evidence/historical-rows.json', 'evidence/parent-rows.json')
    for name, source in zip(ev.RAW_FILES, raw_sources):
        need(file_digest(bundle / name) == file_digest(original / source), 'ORIGINAL_R2_ROWS_MISMATCH')
    for label in ('candidate', 'full'):
        for name in ('corpus.jsonl', 'components/documentation.jsonl'):
            need(file_digest(bundle / label / name) == file_digest(original / label / name),
                 'EVALUATED_CORPUS_MISMATCH')
    need(read_json(bundle / 'inputs.json') == ev.input_manifest(original / 'candidate', original / 'full',
        read_json(original / 'quality/quality-report.json'), expected_approval_policy_sha256, bundle),
        'ORIGINAL_INPUT_MANIFEST_MISMATCH')
    return {'status': 'CONTROLLED_BASELINE_VERIFIED', 'format': FORMAT,
            'baseline_id': expected_baseline_id, 'candidate_id': subject['candidate_id'],
            'package_checksum': package_checksum(expected_baseline_id, digest(identity['artifacts'])),
            'manifest_sha256': expected_manifest_sha256, 'generation': subject['generation'],
            'parent': subject['parent'], 'source_state': subject['source_state'],
            'corpus_sha256': subject['corpus_sha256'], 'upstreams': subject['upstreams'],
            'approval_subject_sha256': digest(subject), 'provenance_type': execution.SYNTHETIC,
            'evaluated_evidence': 'FROZEN_EVIDENCE_COMPATIBILITY_VERIFIED',
            'replay': 'FRESH_SYNTHETIC_R2_REPLAY' if fresh_replay else 'SEALED_REPLAY_INSPECTED',
            'research_approval': 'CONTROLLED_FIXTURE_ONLY',
            'registered_trusted_parent': False, 'old_format_parent_compatible': False, **RESTRICTIONS}


def parent_reference(report):
    """Describe controlled bindings only; caller must retain its independent pin."""
    need(report['status'] == 'CONTROLLED_BASELINE_VERIFIED', 'VERIFIED_CONTROLLED_BASELINE_REQUIRED')
    return {'schema_version': 1, 'kind': REFERENCE, 'provenance_type': execution.SYNTHETIC,
            **{k: report[k] for k in ('baseline_id', 'candidate_id', 'package_checksum', 'generation',
               'corpus_sha256', 'source_state', 'upstreams', 'manifest_sha256')},
            'production_promotion': 'NOT_AUTHORIZED'}


def qualify_controlled_parent(project, baseline, reference, expected_reference_sha256,
                             rows_path, expected_rows_sha256, *, baseline_pins, fresh_replay=True):
    """Separate controlled adapter, never accepted by the old Parent dispatcher."""
    need(type(fresh_replay) is bool, 'INVALID_REPLAY_MODE')
    need(scope._hash(expected_reference_sha256) and digest(reference) == expected_reference_sha256,
         'INDEPENDENT_CONTROLLED_REFERENCE_MISMATCH')
    report = verify_baseline(project, baseline, **baseline_pins, fresh_replay=False)
    need(ev.same(reference, parent_reference(report)), 'CONTROLLED_PARENT_REFERENCE_MISMATCH')
    root = Path(baseline); rows_path = Path(rows_path)
    need(scope._hash(expected_rows_sha256) and file_digest(checked_file(rows_path.parent, rows_path.name))
         == expected_rows_sha256 == file_digest(root / 'original/quality/incremental-raw-results.json'),
         'ORIGINAL_PARENT_R2_ANCHOR_MISMATCH')
    rows = read_json(rows_path)
    corpus = root / 'original/candidate/corpus.jsonl'
    docs = root / 'original/candidate/components/documentation.jsonl'
    policy = read_json(c.LOCK)['quality_policy']
    spec = ev.frozen_implementation(project, Path(project) / ev.BENCHMARK, policy)
    metrics = ev.rescore(rows, spec, read_records(corpus), read_records(docs))
    if fresh_replay:
        need(ev.same(ev.replay(spec, corpus, docs), rows), 'CONTROLLED_PARENT_REPLAY_MISMATCH')
    need(file_digest(rows_path) == expected_rows_sha256, 'PARENT_ROWS_CHANGED')
    return {'status': 'CONTROLLED_PARENT_QUALIFIED' if fresh_replay else 'CONTROLLED_PARENT_INSPECTED',
            'execution': 'FRESH_SYNTHETIC_R2_REPLAY' if fresh_replay else 'NO_FRESH_REPLAY',
            'bindings': {**reference, 'original_parent_rows_sha256': expected_rows_sha256},
            'metrics': metrics, 'historical_rows_sha256': file_digest(root / 'original/evidence/historical-rows.json'),
            'previous_parent_rows_sha256': file_digest(root / 'original/evidence/parent-rows.json'),
            'old_format_parent_compatible': False, 'trusted_parent_eligibility': 'NOT_GRANTED', **RESTRICTIONS}


def registration_preflight(project, baseline, *, baseline_pins):
    """Read-only controlled verification, no old Registry proposal or mutation."""
    report = verify_baseline(project, baseline, **baseline_pins, fresh_replay=False)
    return {'status': 'BLOCKED', 'blockers': ['NEW_FORMAT_REGISTRY_NOT_SUPPORTED',
            'INDEPENDENT_REGISTRATION_AUTHORITY_NOT_ESTABLISHED'],
            'controlled_preflight': 'CONTROLLED_PREFLIGHT_VERIFIED',
            'baseline_id': report['baseline_id'], 'candidate_id': report['candidate_id'],
            'authoritative_registry_modified': False, 'build_authorization': 'NOT_GRANTED', **RESTRICTIONS}
