"""Maintainer-governed continuous execution; preserved V1 formats stay separate.

The reviewed Hosted entry, independent deployment pins and live Owner API checks
form the authority boundary. Saved observations are never new authorization.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess

from scripts.prepare_ci_v2_update import detection
from . import approval_evidence as ev, ci_v2_research as c
from . import continuous_build_policy as scope, continuous_execution as v1
from . import owner_manual_baseline_approval as owner, parent_r2_anchor as anchor
from . import schema2_workflow as workflow, trusted_snapshot as trust, upstream_provenance as source
from .corpus_snapshot import checked_file, digest, file_digest, read_json, read_records, write_json
from .research_quality import evaluate_quality

FORMAT = 'genuine-continuous-candidate-v1'
PROJECTION = 'genuine-continuous-evaluator-v1'
PURPOSE = 'CONTINUOUS_CANDIDATE_BUILD_ONLY'
DEPLOYMENT_FIELDS = {'schema_version', 'purpose', 'repository', 'repository_id', 'default_branch',
    'workflow_path', 'implementation_revision', 'authority_policy_path', 'authority_policy_sha256',
    'continuous_policy_path', 'continuous_policy_sha256', 'registry_path', 'registry_sha256',
    'execution_contract_sha256'}
PIN_FIELDS = {'expected_execution_contract_sha256', 'expected_policy_sha256',
    'expected_registry_sha256', 'expected_reference_sha256', 'expected_deployment_sha256',
    'expected_candidate_id', 'expected_manifest_sha256'}
EXTRA_EVIDENCE = {'deployment.json', 'authority-policy.json', 'authorization-context.json', 'detection.json'}
FILES = ('src/genuine_continuous_execution.py', 'scripts/run_continuous_ci_v2.py',
         'scripts/prepare_ci_v2_update.py', '.github/workflows/upstream_refresh.yml')
LIMITS = {**c.RESTRICTIONS, 'automatic_registration': False,
          'Q1': 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR', 'P8': 'BLOCKED'}


def need(ok, reason):
    c.need(ok, reason, reason)


def contract(project):
    return {'schema_version': 1, 'format': FORMAT, 'files': {
        name: file_digest(checked_file(project, name)) for name in FILES}, 'controlled_v1': v1.contract(project)}


def _implementation(project, expected):
    need(scope._hash(expected) and digest(contract(project)) == expected, 'EXECUTION_CONTRACT_MISMATCH')
    need(contract(project) == contract(Path(__file__).resolve().parents[1]), 'EXECUTING_CODE_MISMATCH')
    c.frozen_runtime(project)


def _shape(value):
    need(isinstance(value, dict) and set(value) == DEPLOYMENT_FIELDS
         and type(value['schema_version']) is int and value['schema_version'] == 1
         and value['purpose'] == PURPOSE, 'INVALID_CONTINUOUS_DEPLOYMENT')
    need(isinstance(value['repository'], str)
         and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value['repository'])
         and type(value['repository_id']) is int and value['repository_id'] > 0
         and isinstance(value['implementation_revision'], str)
         and re.fullmatch('[0-9a-f]{40}', value['implementation_revision']), 'INVALID_DEPLOYMENT_IDENTITY')
    for name in ('authority_policy_path', 'continuous_policy_path', 'registry_path'):
        path = value[name]
        need(isinstance(path, str) and re.fullmatch(r'configs/[A-Za-z0-9_.-]+\.json', path),
             'UNSAFE_DEPLOYMENT_CONFIG_PATH')
    for name in ('authority_policy_sha256', 'continuous_policy_sha256', 'registry_sha256', 'execution_contract_sha256'):
        need(scope._hash(value[name]), 'INVALID_DEPLOYMENT_PIN')
    need(value['workflow_path'] == '.github/workflows/upstream_refresh.yml', 'UNSUPPORTED_CONTINUOUS_WORKFLOW')
    branch = value['default_branch']
    need(isinstance(branch, str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._/-]{0,127}', branch)
         and not any(x in branch for x in ('..', '//', '/.', '.lock')) and not branch.endswith(('/', '.')),
         'INVALID_DEPLOYMENT_BRANCH')
    return value


def deployment():
    raw = os.environ.get('CONTINUOUS_BUILD_DEPLOYMENT_JSON', '')
    expected = os.environ.get('CONTINUOUS_BUILD_DEPLOYMENT_SHA256', '')
    import hashlib
    need(isinstance(raw, str) and 0 < len(raw.encode()) <= 16384 and scope._hash(expected),
         'CONTINUOUS_DEPLOYMENT_NOT_CONFIGURED')
    need(hashlib.sha256(raw.encode()).hexdigest() == expected, 'CONTINUOUS_DEPLOYMENT_PIN_MISMATCH')
    value = owner._strict_json(raw); digest(value)
    return _shape(value), raw, expected


def _checkout(project, config):
    need(source._git(project, 'rev-parse', '--show-toplevel').decode().strip() == str(project.resolve())
         and source._git(project, 'rev-parse', 'HEAD').decode().strip() == config['implementation_revision'],
         'UNREVIEWED_EXECUTION_CHECKOUT')
    source._git(project, 'diff', '--quiet', '--no-ext-diff', 'HEAD', '--')
    need(not source._git(project, 'ls-files', '--others', '--exclude-standard', '--',
                         'src', 'scripts', 'configs', '.github').strip(), 'UNTRACKED_EXECUTION_CODE')
    for name in (*FILES, config['authority_policy_path'], config['continuous_policy_path'], config['registry_path']):
        source._git(project, 'ls-files', '--error-unmatch', '--', name)
        checked_file(project, name)


def _detected(path, policy):
    observed = detection(path)
    rows = read_json(path)
    need(all(rows[repo]['branch'] == policy['upstreams'][repo]['branch'] for repo in c.SOURCES),
         'DETECTOR_BRANCH_OUTSIDE_POLICY')
    return observed


def _authority(project, detection_path, config, config_sha):
    """Internal Hosted boundary; no injectable approval provider or CLI override."""
    current, _, current_sha = deployment()
    need(current == config and current_sha == config_sha, 'DEPLOYMENT_CHANGED_DURING_EXECUTION')
    _checkout(project, config); _implementation(project, config['execution_contract_sha256'])
    authority = owner._policy(project, project / config['authority_policy_path'], config['authority_policy_sha256'])
    need(all(authority[k] == config[k] for k in ('repository', 'repository_id', 'default_branch',
             'workflow_path', 'registry_path')), 'AUTHORITY_DOMAIN_MISMATCH')
    policy = scope.load_policy(project, config['continuous_policy_path'], config['continuous_policy_sha256'])
    registry = scope._read_pinned(project, config['registry_path'], config['registry_sha256'])
    observed = _detected(detection_path, policy)
    context = owner.context_from_environment()
    need(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
         and os.environ.get('RUNNER_ARCH') == 'ARM64'
         and os.environ.get('GITHUB_WORKSPACE') == str(project.resolve())
         and context['repository'] == config['repository']
         and context['repository_id'] == config['repository_id']
         and context['head_sha'] == config['implementation_revision']
         and os.environ.get('GITHUB_WORKFLOW_SHA') == config['implementation_revision']
         and os.environ.get('GITHUB_WORKFLOW_REF') == config['repository'] + '/' + config['workflow_path']
             + '@refs/heads/' + config['default_branch'], 'TRUSTED_CONTINUOUS_WORKFLOW_NOT_ESTABLISHED')
    inputs = context['dispatch_inputs']
    requested, exact = inputs.get('build_continuous_ci_v2'), inputs.get('build_ci_v2', False)
    need(set(inputs) <= {'build_ci_v2', 'build_continuous_ci_v2'}
         and (requested is True or type(requested) is str and requested == 'true')
         and (exact is False or type(exact) is str and exact == 'false'), 'CONTINUOUS_BUILD_NOT_EXPLICITLY_REQUESTED')
    client = owner.GitHubCLI()
    actor = owner._github_identity(client, authority, context)
    need(owner._remote_registry_bytes(client, authority, actor['commit_sha'])
         == checked_file(project, config['registry_path']).read_bytes(), 'REMOTE_REGISTRY_MISMATCH')
    selected, entry, _ = scope._parent(project, registry, policy)
    actor = {**{k: v for k, v in actor.items() if k != 'approved_at'},
             'run_created_at': actor['approved_at']}
    return {'schema_version': 1, 'purpose': PURPOSE, 'deployment_sha256': config_sha,
            'workflow_run': actor, 'detection_sha256': observed['detection_sha256'],
            'upstreams': observed['upstreams'], 'selected_parent': selected,
            'reference_sha256': entry['expected_reference_sha256'],
            'continuous_policy_sha256': config['continuous_policy_sha256'],
            'registry_sha256': config['registry_sha256'],
            'authority_policy_sha256': config['authority_policy_sha256'],
            'authority': 'MAINTAINER_GOVERNED_WORKFLOW_BUILD_CONTEXT',
            'research_approval': 'NOT_GRANTED', 'production_promotion': 'NOT_AUTHORIZED'}


def _clone_sources(work, ref, revisions):
    """Only new owned checkouts; detection SHAs never replaced by moving HEADs."""
    for label, pair in (('base-source', ref['upstreams']), ('target-source', revisions)):
        for repo, url in c.SOURCES.items():
            destination = work / label / 'repos' / repo; destination.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(['git', '-c', 'credential.helper=', 'clone', '--no-checkout', url, str(destination)],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(['git', '-C', str(destination), 'checkout', '--detach', pair[repo]],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _projection(candidate_id, identity):
    value = v1._projection(candidate_id, identity)
    return {**value, 'kind': PROJECTION}


def _artifacts(root, selection):
    return {**v1._deterministic(root, selection), **{
        'evidence/' + name: file_digest(root / 'evidence' / name) for name in sorted(EXTRA_EVIDENCE)}}


def _archive_bindings(root, config, authority, assessed, metadata):
    """Archived consistency only: never calls an API or establishes fresh authority."""
    identity = metadata['identity']; subject = assessed['subject']
    policy = read_json(root / 'evidence/policy-original.json'); v1._archive_policy(policy)
    need(set(authority) == {'schema_version', 'purpose', 'deployment_sha256', 'workflow_run',
         'detection_sha256', 'upstreams', 'selected_parent', 'reference_sha256',
         'continuous_policy_sha256', 'registry_sha256', 'authority_policy_sha256', 'authority',
         'research_approval', 'production_promotion'} and type(authority['schema_version']) is int
         and authority['schema_version'] == 1, 'INVALID_ARCHIVED_AUTHORITY_CONTEXT')
    authority_policy = read_json(root / 'evidence/authority-policy.json')
    need(set(authority_policy) == owner.POLICY_FIELDS and authority_policy['enabled'] is True
         and all(authority_policy[k] == config[k] for k in
             ('repository', 'repository_id', 'default_branch', 'workflow_path', 'registry_path')),
         'ARCHIVED_AUTHORITY_POLICY_DOMAIN_MISMATCH')
    need(set(assessed) == v1.ASSESSMENT_FIELDS and set(subject) == v1.SUBJECT_FIELDS
         and assessed['status'] == scope.PLAN_STATUS and assessed['execution_authorization'] == 'BLOCKED'
         and assessed['execution_identity'] == digest(subject) == identity['scope_subject_sha256']
         and assessed['requirements'] == scope.REQUIREMENTS
         and all(type(assessed[k]) is type(v) and assessed[k] == v for k, v in c.RESTRICTIONS.items()),
         'INVALID_ARCHIVED_SCOPE_ASSESSMENT')
    observed = _detected(root / 'evidence/detection.json', policy)
    need(observed['update_reported'] and observed['upstreams'] == identity['upstreams']
         and observed['detection_sha256'] == authority['detection_sha256'] == identity['detection_sha256']
         and authority['purpose'] == PURPOSE and authority['authority'] == 'MAINTAINER_GOVERNED_WORKFLOW_BUILD_CONTEXT'
         and authority['research_approval'] == 'NOT_GRANTED' and authority['production_promotion'] == 'NOT_AUTHORIZED'
         and authority['upstreams'] == identity['upstreams']
         and authority['deployment_sha256'] == identity['deployment_sha256']
         and authority['continuous_policy_sha256'] == config['continuous_policy_sha256'] == identity['policy_raw_sha256']
         and authority['registry_sha256'] == config['registry_sha256'] == identity['registry_raw_sha256']
         and authority['authority_policy_sha256'] == config['authority_policy_sha256'], 'ARCHIVED_AUTHORITY_BINDING_MISMATCH')
    actor = authority['workflow_run']
    need(set(actor) == {'repository', 'repository_id', 'workflow_id', 'workflow_path', 'run_id', 'run_attempt',
         'event', 'branch', 'commit_sha', 'actor_id', 'actor_login', 'run_created_at'}
         and all(owner._positive(actor[k]) for k in ('repository_id', 'workflow_id', 'run_id', 'actor_id'))
         and all(actor[k] == config[k] for k in ('repository', 'repository_id', 'workflow_path'))
         and actor['commit_sha'] == config['implementation_revision']
         and actor['branch'] == config['default_branch'] and actor['run_attempt'] == 1
         and actor['event'] == 'workflow_dispatch', 'ARCHIVED_WORKFLOW_BINDING_MISMATCH')
    ref = read_json(root / 'evidence/reference.json')
    registry = read_json(root / 'evidence/registry.json'); entry = registry['baselines'][subject['parent_key']]
    need(authority['selected_parent'] == subject['parent_key']
         and entry['reference'] == ref and entry['expected_reference_sha256'] == identity['reference_sha256']
         and digest(entry) == subject['parent_entry_sha256'] and digest(ref) == subject['reference_sha256']
         and authority['reference_sha256'] == identity['reference_sha256']
         and subject['upstreams'] == identity['upstreams']
         and subject['target_source_state'] == identity['target_source_state']
         and subject['policy_path'] == config['continuous_policy_path']
         and subject['policy_raw_sha256'] == identity['policy_raw_sha256']
         and subject['policy_canonical_sha256'] == digest(policy)
         and subject['registry_raw_sha256'] == identity['registry_raw_sha256']
         and subject['parent_id'] == ref['node_id'] and subject['parent_package_checksum'] == ref['package_checksum']
         and subject['parent_corpus_sha256'] == ref['corpus_sha256']
         and subject['parent_upstreams'] == ref['upstreams'] and subject['parent_source_state'] == ref['source_state']
         and subject['build_fingerprint'] == identity['build_fingerprint'] == policy['build_fingerprint']
         and subject['orchestration_fingerprint'] == identity['historical_orchestration_sha256']
         == policy['orchestration_fingerprint'] == digest(source.contract(Path(__file__).resolve().parents[1])),
         'ARCHIVED_PARENT_SCOPE_MISMATCH')
    need({'key': subject['parent_key'], 'node_id': ref['node_id'], 'package_checksum': ref['package_checksum'],
          'expected_reference_sha256': identity['reference_sha256']} in policy['eligible_parents'], 'UNSCOPED_PARENT')
    evidence = assessed['source_evidence']
    need(subject['source_evidence_sha256'] == digest(evidence), 'SOURCE_EVIDENCE_PIN_MISMATCH')
    v1._archived_sources(policy, evidence, identity)
    need(evidence['base_selection'] == read_json(root / 'parent/selection.json')
         and evidence['target_selection'] == read_json(root / 'candidate/selection.json'), 'ARCHIVED_SOURCE_SELECTION_MISMATCH')


def verify_package(project, root, *, expected_execution_contract_sha256, expected_policy_sha256,
                   expected_registry_sha256, expected_reference_sha256, expected_deployment_sha256,
                   expected_candidate_id, expected_manifest_sha256, fresh_replay=False):
    """External pins authenticate expected bytes, not a new human approval."""
    root, project = Path(root), Path(project)
    need(type(fresh_replay) is bool, 'INVALID_REPLAY_MODE')
    _implementation(project, expected_execution_contract_sha256)
    need(scope._hash(expected_manifest_sha256) and file_digest(checked_file(root, 'checksums.json'))
         == expected_manifest_sha256, 'INDEPENDENT_PACKAGE_SEAL_MISMATCH')
    v1._check_seal(root)
    need(set(v1._files(root / 'evidence')) == set(v1.EVIDENCE) | EXTRA_EVIDENCE, 'INVALID_GENUINE_EVIDENCE_FILES')
    for name, expected in (('policy-original.json', expected_policy_sha256), ('registry.json', expected_registry_sha256),
                           ('deployment.json', expected_deployment_sha256)):
        need(scope._hash(expected) and file_digest(root / 'evidence' / name) == expected, 'EXTERNAL_EVIDENCE_PIN_MISMATCH')
    config = _shape(read_json(root / 'evidence/deployment.json'))
    need(config['execution_contract_sha256'] == expected_execution_contract_sha256
         and config['continuous_policy_sha256'] == expected_policy_sha256
         and config['registry_sha256'] == expected_registry_sha256
         and file_digest(root / 'evidence/authority-policy.json') == config['authority_policy_sha256']
         and read_json(root / 'evidence/execution-contract.json') == contract(project), 'ARCHIVED_DEPLOYMENT_MISMATCH')
    metadata = read_json(root / 'candidate/genuine-candidate.json'); identity = metadata['identity']
    need(set(metadata) == {'format', 'schema_version', 'candidate_id', 'identity'}
         and metadata['format'] == FORMAT and type(metadata['schema_version']) is int and metadata['schema_version'] == 1
         and set(identity) == v1.IDENTITY_FIELDS | {'deployment_sha256', 'detection_sha256', 'authorization_context_sha256'}
         and identity['format'] == FORMAT and type(identity['schema_version']) is int and identity['schema_version'] == 1
         and identity['provenance_type'] == 'GENUINE_UPSTREAM'
         and metadata['candidate_id'] == expected_candidate_id == 'sha256-' + digest(identity), 'INVALID_GENUINE_CANDIDATE_IDENTITY')
    c.validate_request('formal', 'genuine-continuous', identity['upstreams'])
    need(all(type(identity[k]) is type(v) and identity[k] == v for k, v in c.RESTRICTIONS.items())
         and identity['automatic_registration'] is False, 'CHANGED_RESEARCH_RESTRICTIONS')
    need(identity['execution_contract_sha256'] == expected_execution_contract_sha256
         and identity['policy_raw_sha256'] == expected_policy_sha256
         and identity['registry_raw_sha256'] == expected_registry_sha256
         and identity['reference_sha256'] == expected_reference_sha256
         and identity['deployment_sha256'] == expected_deployment_sha256, 'CANDIDATE_EXTERNAL_PIN_MISMATCH')
    ref = read_json(root / 'evidence/reference.json'); trust.validate_reference(ref, expected_reference_sha256)
    need(identity['build_fingerprint'] == ref['build_fingerprint'] == digest(read_json(c.LOCK)['P2']),
         'FROZEN_BUILD_FINGERPRINT_MISMATCH')
    trust.verify_package(project, root / 'parent', ref)
    parent = source.verify(project, root / 'parent', ref['build_fingerprint'], expected_id=ref['node_id'])
    need(parent['P4_1_verification'] == 'P4_1_VERIFIED' and parent['provenance_type'] == 'GENUINE_UPSTREAM'
         and identity['parent'] == {'node_id': ref['node_id'], 'package_checksum': ref['package_checksum'],
              'generation': parent['generation'], 'source_state': ref['source_state'],
              'upstreams': ref['upstreams'], 'corpus_sha256': ref['corpus_sha256']}
         and type(identity['generation']) is int and type(identity['parent']['generation']) is int
         and identity['generation'] == parent['generation'] + 1, 'GENUINE_PARENT_GENERATION_MISMATCH')
    authority = read_json(root / 'evidence/authorization-context.json')
    need(digest(authority) == identity['authorization_context_sha256'], 'AUTHORITY_CONTEXT_PIN_MISMATCH')
    _archive_bindings(root, config, authority, read_json(root / 'evidence/assessment.json'), metadata)
    selection = read_json(root / 'candidate/selection.json')
    need(identity['artifacts'] == _artifacts(root, selection)
         and read_json(root / 'candidate/candidate.json') == _projection(expected_candidate_id, identity), 'GENUINE_ARTIFACT_OR_PROJECTION_MISMATCH')
    expected_files = {name.removeprefix('candidate/') for name in identity['artifacts'] if name.startswith('candidate/')}
    need(set(v1._files(root / 'candidate')) == expected_files | {'candidate.json', 'genuine-candidate.json'}, 'UNEXPECTED_CANDIDATE_CONTENTS')
    from . import incremental_corpus as engine
    engine._verify_materialized(project, root / 'candidate', selection,
        read_json(root / 'candidate/inventory.json'), read_json(root / 'candidate/extraction-graph.json'))
    need(read_json(root / 'parity.json') == v1._parity(project, root, metadata), 'PARITY_RECEIPT_MISMATCH')
    qualified = anchor.qualify_parent_anchor(project, root / 'parent', ref, expected_reference_sha256,
                   root / 'evidence/parent-rows.json', fresh_replay=fresh_replay)
    receipt = read_json(root / 'parent-anchor.json')
    need(receipt['execution'] == 'FRESH_R2_REPLAY_VERIFIED' and receipt['bindings'] == qualified['bindings']
         and ev.same(read_json(root / 'evidence/historical-rows.json'), qualified['historical_rows']), 'PARENT_REPLAY_RECEIPT_MISMATCH')
    quality = read_json(root / 'quality/quality-report.json'); v1._check_seal(root / 'quality')
    need({p.name for p in (root / 'quality').iterdir()} == v1.QUALITY_FILES
         and quality['candidate_id'] == expected_candidate_id and quality['status'] == 'QUALITY_REVIEW_REQUIRED'
         and quality['assessment'] == 'FROZEN_128_EVALUATED' and ev.same(quality['policy'], read_json(c.LOCK)['quality_policy']),
         'QUALITY_BINDING_MISMATCH')
    spec = ev.frozen_implementation(project, project / ev.BENCHMARK, quality['policy']); rows = {}
    for label, folder in (('incremental', root / 'candidate'), ('full', root / 'full')):
        rows[label] = read_json(root / 'quality' / (label + '-raw-results.json'))
        metrics = ev.rescore(rows[label], spec, read_records(folder / 'corpus.jsonl'), read_records(folder / 'components/documentation.jsonl'))
        replay = ev.replay(spec, folder / 'corpus.jsonl', folder / 'components/documentation.jsonl') if fresh_replay else read_json(root / (label + '-replay.json'))
        need(ev.same(metrics, quality['metrics']) and ev.same(replay, rows[label]), 'FROZEN_R2_REPLAY_MISMATCH')
    need(ev.same(rows['incremental'], rows['full'])
         and quality['raw_results_sha256'] == file_digest(root / 'quality/incremental-raw-results.json'), 'CANDIDATE_FULL_R2_MISMATCH')
    transitions = {label: ev.compare_outcomes(previous, rows['incremental'], spec) for label, previous in (
        ('historical', qualified['historical_rows']), ('immediate_parent', qualified['rows']))}
    need(read_json(root / 'quality/transitions.json') == transitions, 'TRANSITION_MISMATCH')
    for name, direction in (('new_losses', 'PASS→FAIL'), ('new_gains', 'FAIL→PASS')):
        need(quality[name] == {label: [r for r in values if r['hit5'] == direction or r['hit10'] == direction]
                              for label, values in transitions.items()}, 'QUALITY_TRANSITION_MISMATCH')
    applicability = ev.oracle_applicability(spec, read_records(root / 'candidate/corpus.jsonl'),
        read_records(root / 'parent/corpus.jsonl'), root / 'candidate/input', root / 'parent/input')
    need(read_json(root / 'quality/oracle-applicability.json') == applicability
         and quality['applicability_changes'] == [a for a in applicability if a['previous_available'] != a['target_available']],
         'APPLICABILITY_MISMATCH')
    bindings = {'base_source_state': ref['source_state'], 'target_source_state': identity['target_source_state'],
        'parent_id': ref['node_id'], 'candidate_id': expected_candidate_id,
        'base_corpus_sha256': ref['corpus_sha256'], 'target_corpus_sha256': file_digest(root / 'candidate/corpus.jsonl')}
    from . import regression_attribution as attribution
    attributed = attribution.summarize(spec, qualified['rows'], rows['incremental'], None, bindings=bindings)
    need(read_json(root / 'regression-attribution.json') == attributed
         and read_json(root / 'q1-status.json') == {'status': 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR'}, 'DIAGNOSTIC_BINDING_MISMATCH')
    need(read_json(root / 'review-summary.json') == {
        'report_id': attributed['report_id'], 'label_counts': attributed['label_counts'],
        'review_counts': attributed['review_counts'], 'failures': [{'id': row['id'], 'mode': row['mode'],
            'recommendations': row['review_recommendations'], 'human_decision': 'PENDING'}
            for row in attributed['failures']], **attribution.LIMITS}, 'REVIEW_HANDOFF_MISMATCH')
    result = _result(metadata)
    need(read_json(root / 'result.json') == result, 'RESULT_BINDING_MISMATCH')
    need({p.name for p in root.iterdir()} == {'candidate', 'parent', 'full', 'evidence', 'quality', 'extraction-observations',
        'parent-anchor.json', 'parity.json', 'incremental-replay.json', 'full-replay.json', 'regression-attribution.json',
        'q1-status.json', 'review-summary.json', 'result.json', 'checksums.json'}, 'UNEXPECTED_GENUINE_PACKAGE_CONTENTS')
    return {**result, 'verification': 'PACKAGE_INTEGRITY_VERIFIED',
            'replay': 'FRESH_R2_REPLAY' if fresh_replay else 'SEALED_REPLAY_INSPECTED',
            'live_authorization': 'NOT_ESTABLISHED_BY_OFFLINE_VERIFIER',
            'official_source_authenticity': 'ARCHIVED_OBSERVATIONS_NOT_FRESH_AUTHORITY'}


def _result(metadata):
    identity = metadata['identity']
    return {'status': 'GENUINE_CONTINUOUS_CANDIDATE_BUILT', 'format': FORMAT, 'candidate_id': metadata['candidate_id'],
        'generation': identity['generation'], 'parent_id': identity['parent']['node_id'],
        'upstreams': identity['upstreams'], 'source_state': identity['target_source_state'],
        'corpus_sha256': identity['artifacts']['candidate/corpus.jsonl'], 'parity': 'PARITY_PASS',
        'combinations_each': 128, 'independent_replay': 'VERIFIED', 'research_approval': 'NOT_GRANTED',
        'trusted_parent_eligibility': 'NOT_GRANTED', **LIMITS}


def execute(project, detection_path, work, output):
    """Real entry; absent deployment/identity authority blocks before downloads."""
    project, detection_path, work, output = map(Path, (project, detection_path, work, output))
    config, raw_config, config_sha = deployment()
    authority = _authority(project, detection_path, config, config_sha)
    policy = scope.load_policy(project, config['continuous_policy_path'], config['continuous_policy_sha256'])
    observed = _detected(detection_path, policy)
    source._new_output(output, (project, detection_path, work))
    if not observed['update_reported']:
        result = {'status': 'NO_UPDATE', 'execute_candidate': False, **LIMITS}
        output.mkdir(); write_json(output / 'no-update.json', result)
        return result
    registry_path = project / config['registry_path']; registry = read_json(registry_path)
    _, entry, _ = scope._parent(project, registry, policy); ref = entry['reference']
    source._new_output(work, (project, detection_path, output))
    need(shutil.disk_usage(work.parent).free >= 8 * 1024**3, 'RESOURCE_LIMIT')
    work.mkdir()
    for storage, name, checksum in ((ref['storage'], 'parent.tar.gz', ref['transport_sha256']),
              (ref['parent_rows_storage'], 'parent-rows.json', ref['parent_rows_sha256'])):
        kwargs = {'token': os.environ.get('TRUSTED_RELEASE_TOKEN')} if storage['kind'] == trust.PRIVATE_RELEASE_KIND else {}
        trust.download(storage, work / name, checksum, **kwargs)
    _clone_sources(work, ref, observed['upstreams'])
    arguments = {'expected_policy_sha256': config['continuous_policy_sha256'],
        'expected_registry_sha256': config['registry_sha256'], 'revisions': observed['upstreams'],
        'base_source': (work / 'base-source').resolve(), 'target_source': (work / 'target-source').resolve()}
    assessed = scope.assess_scope(project, registry_path, config['continuous_policy_path'], **arguments)
    def revalidate():
        need(_authority(project, detection_path, config, config_sha) == authority, 'STALE_EXECUTION_AUTHORITY')
        scope.revalidate_scope(assessed, project, registry_path, config['continuous_policy_path'],
                               expected_plan_sha256=digest(assessed), **arguments)
        need(file_digest(work / 'parent.tar.gz') == ref['transport_sha256'], 'PARENT_TRANSPORT_CHANGED')
    revalidate()
    stage = work / 'package'; stage.mkdir()
    trust.restore(project, work / 'parent.tar.gz', stage / 'parent', ref, entry['expected_reference_sha256'])
    qualified = anchor.qualify_parent_anchor(project, stage / 'parent', ref, entry['expected_reference_sha256'],
                                             work / 'parent-rows.json', fresh_replay=True)
    parent = source.verify(project, stage / 'parent', ref['build_fingerprint'], expected_id=ref['node_id'])
    evidence = stage / 'evidence'; evidence.mkdir()
    for name, origin in (('policy-original.json', project / config['continuous_policy_path']),
            ('registry.json', registry_path), ('authority-policy.json', project / config['authority_policy_path']),
            ('parent-rows.json', work / 'parent-rows.json'), ('detection.json', detection_path)):
        shutil.copyfile(origin, evidence / name)
    (evidence / 'deployment.json').write_text(raw_config, encoding='utf-8')
    for name, value in (('assessment.json', assessed), ('reference.json', ref), ('authorization-context.json', authority),
            ('historical-rows.json', qualified['historical_rows']), ('execution-contract.json', contract(project))):
        write_json(evidence / name, value)
    write_json(stage / 'parent-anchor.json', {k: qualified[k] for k in ('bindings', 'execution', 'status', 'controlled_fixture')})
    selection = assessed['source_evidence']['target_selection']
    revalidate()
    v1._assemble(project, stage, stage / 'parent', arguments['target_source'], selection)
    revalidate()
    identity = {'schema_version': 1, 'format': FORMAT, 'provenance_type': 'GENUINE_UPSTREAM',
        'generation': parent['generation'] + 1,
        'parent': {'node_id': ref['node_id'], 'package_checksum': ref['package_checksum'], 'generation': parent['generation'],
                   'source_state': ref['source_state'], 'upstreams': ref['upstreams'], 'corpus_sha256': ref['corpus_sha256']},
        'upstreams': observed['upstreams'], 'target_source_state': source.state(selection),
        'build_fingerprint': ref['build_fingerprint'], 'historical_orchestration_sha256': digest(source.contract(project)),
        'execution_contract_sha256': config['execution_contract_sha256'], 'policy_raw_sha256': config['continuous_policy_sha256'],
        'registry_raw_sha256': config['registry_sha256'], 'reference_sha256': entry['expected_reference_sha256'],
        'scope_subject_sha256': digest(assessed['subject']), 'deployment_sha256': config_sha,
        'detection_sha256': observed['detection_sha256'], 'authorization_context_sha256': digest(authority),
        'artifacts': _artifacts(stage, selection), 'automatic_registration': False, **c.RESTRICTIONS}
    candidate_id = 'sha256-' + digest(identity)
    metadata = {'schema_version': 1, 'format': FORMAT, 'candidate_id': candidate_id, 'identity': identity}
    write_json(stage / 'candidate/genuine-candidate.json', metadata)
    write_json(stage / 'candidate/candidate.json', _projection(candidate_id, identity))
    source.full_reference(project, arguments['target_source'], stage / 'full', observed['upstreams'], ref['build_fingerprint'])
    write_json(stage / 'parity.json', v1._parity(project, stage, metadata))
    evaluate_quality(project, stage / 'candidate', stage / 'full', stage / 'quality', benchmark=project / ev.BENCHMARK,
        policy=read_json(c.LOCK)['quality_policy'], expected_fingerprint=ref['build_fingerprint'],
        historical_rows=qualified['historical_rows'], parent_rows=qualified['rows'],
        parent_corpus=stage / 'parent/corpus.jsonl', parent_sources=arguments['base_source'])
    rows = {}
    for label, folder in (('incremental', stage / 'candidate'), ('full', stage / 'full')):
        rows[label] = ev.replay(qualified['spec'], folder / 'corpus.jsonl', folder / 'components/documentation.jsonl')
        need(ev.same(rows[label], read_json(stage / 'quality' / (label + '-raw-results.json'))), 'INDEPENDENT_R2_REPLAY_MISMATCH')
        write_json(stage / (label + '-replay.json'), rows[label])
    workflow.diagnostics(project, stage, qualified['spec'], qualified['rows'], rows['incremental'], {
        'base_source_state': ref['source_state'], 'target_source_state': identity['target_source_state'],
        'parent_id': ref['node_id'], 'candidate_id': candidate_id, 'base_corpus_sha256': ref['corpus_sha256'],
        'target_corpus_sha256': file_digest(stage / 'candidate/corpus.jsonl')})
    write_json(stage / 'result.json', _result(metadata)); v1._seal(stage)
    pins = {'expected_execution_contract_sha256': config['execution_contract_sha256'],
        'expected_policy_sha256': config['continuous_policy_sha256'], 'expected_registry_sha256': config['registry_sha256'],
        'expected_reference_sha256': entry['expected_reference_sha256'], 'expected_deployment_sha256': config_sha,
        'expected_candidate_id': candidate_id, 'expected_manifest_sha256': file_digest(stage / 'checksums.json')}
    result = verify_package(project, stage, **pins)
    delivery = work / 'delivery'; delivery.mkdir(); stage.replace(delivery / 'run')
    transport = c.package_candidate(delivery / 'run', delivery / 'candidate.tar.gz')
    c.check_archive(delivery / 'candidate.tar.gz', transport['transport_sha256'])
    write_json(delivery / 'verification-inputs.json', pins)
    write_json(delivery / 'transport.json', transport)
    revalidate()
    output.mkdir(exist_ok=False); delivery.replace(output)
    return {**result, 'execution_authorization': authority['authority'], 'transport': transport}
