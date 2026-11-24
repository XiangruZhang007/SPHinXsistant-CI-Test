"""Narrow native runtime contract, reusing existing authenticated boundaries.

Application code is outside construction/publication compatibility. Frozen
historical modules are not edited or interpreted under a new contract.
"""
from pathlib import Path
import os
from . import genuine_continuous_execution as g, continuous_build_policy as scope
from .corpus_snapshot import checked_file, digest, file_digest, read_json

# Actual automatic path and its trust/transport dependencies, not legacy contract
# constructors (which recursively pin unrelated applications/evaluators).
FILES = (
    'src/native_runtime_contract.py','src/automatic_lifecycle_policy.py',
    'src/automatic_lifecycle.py','src/automatic_candidate.py','src/automatic_release.py',
    'src/automatic_writer.py','src/derived_parent_registry.py',
    'src/continuous_completion.py','src/genuine_continuous_execution.py',
    'src/continuous_build_policy.py','src/scheduled_construction.py',
    'src/trusted_snapshot.py','src/parent_r2_anchor.py','src/upstream_provenance.py',
    'src/incremental_corpus.py','src/continuous_execution.py','src/ci_v2_research.py',
    'src/owner_manual_baseline_approval.py','src/trusted_parent_selection.py',
    'src/trusted_baseline_registration.py','src/schema2_workflow.py',
    'src/parent_authority_git_audit.py','src/parent_authority_github_transport.py',
    'src/update_eligibility_gate.py','src/candidate_promotion_policy.py',
    'scripts/runtime_ruleset_observation.py','scripts/parent_authority_writer_gate.py',
    'scripts/parent_authority_writer_bootstrap.py','scripts/automatic_lifecycle.py',
    '.github/workflows/upstream_refresh.yml')
EVALUATOR_FILES = ('src/approval_evidence.py','src/research_quality.py',
    'src/retrieval_evaluation_criteria.py','src/retrieval_evaluation_io.py',
    'src/retrieval_evaluation_v2.py','src/retrieval_evaluation_reports.py',
    'src/full_retrieval_regression.py','src/remediation_evaluation.py','src/retrieval_identity_diagnostics.py','src/version_aware_evidence.py')


def hashes(project, names):
    return {name: file_digest(checked_file(Path(project), name)) for name in names}


def contract(project):
    return {'schema_version': 1, 'kind': 'NATIVE_RUNTIME_V3', 'files': hashes(project, FILES)}


def components(project):
    """Independent identities; no digest embeds application or prompt files."""
    from .incremental_corpus import current_contract
    from .retrieval_identity_diagnostics import retrieval_fingerprint
    lock=read_json(Path(project)/'configs/ci_v2_runtime_lock.json')
    r2=lock['quality_policy']['R2_fingerprint']['inputs']
    # Only present files in the *declared* evaluator closure are accepted.
    return {'construction': digest(current_contract(project)),
        'retrieval': retrieval_fingerprint(project,r2['exclusion_contract'],
            r2['parameters']['k1'],r2['parameters']['b'])['fingerprint'],
        'benchmark': file_digest(Path(project)/g.ev.BENCHMARK),
        'evaluation': digest(hashes(project,EVALUATOR_FILES)),
        'admission': digest(hashes(project,('src/quality_admission.py','src/admission_evidence.py'))),
        'lifecycle': digest(contract(project))}


def authority(project,detection_path,config,config_sha):
    """Same Owner/producer/source/checkout gates; native schedule only.

    Deliberately does not call g._implementation(): that legacy contract nests
    frozen quality/application concerns. Its security checks are repeated here
    using the explicit native contract plus the unchanged frozen root runtime.
    """
    from . import automatic_lifecycle_policy as policies
    from .ci_v2_research import frozen_runtime
    need=g.need;project=Path(project)
    current,_,current_sha=g.deployment()
    need(current==config and current_sha==config_sha,'DEPLOYMENT_CHANGED_DURING_EXECUTION')
    policy=policies.load(project,config)
    need(policy['schema_version']==3 and os.environ.get('GITHUB_EVENT_NAME')=='schedule',
         'NATIVE_V3_SCHEDULE_REQUIRED')
    g._checkout(project,config)
    need(config['execution_contract_sha256']==digest(contract(project)),'NATIVE_RUNTIME_CONTRACT_MISMATCH')
    # These are still the frozen construction/R2 algorithms. A later retrieval
    # version needs an explicit evaluator migration, not permission to edit R2.
    frozen_runtime(project)
    owner=g.owner
    authorization=owner._policy(project,project/config['authority_policy_path'],config['authority_policy_sha256'])
    need(all(authorization[k]==config[k] for k in ('repository','repository_id','default_branch',
         'workflow_path','registry_path')),'AUTHORITY_DOMAIN_MISMATCH')
    source_policy=scope.load_policy(project,config['continuous_policy_path'],config['continuous_policy_sha256'])
    registry=scope._read_pinned(project,config['registry_path'],config['registry_sha256'])
    detected=g._detected(detection_path,source_policy)
    need('schedule' in config.get('build_events',[]),'BUILD_EVENT_NOT_PREAUTHORIZED')
    context=g._scheduled_context()
    need(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted'
         and os.environ.get('RUNNER_ARCH')=='ARM64'
         and os.environ.get('GITHUB_WORKSPACE')==str(project.resolve())
         and context['repository']==config['repository'] and context['repository_id']==config['repository_id']
         and context['head_sha']==config['implementation_revision']
         and os.environ.get('GITHUB_WORKFLOW_SHA')==config['implementation_revision']
         and os.environ.get('GITHUB_WORKFLOW_REF')==config['repository']+'/'+config['workflow_path']
             +'@refs/heads/'+config['default_branch'],'TRUSTED_CONTINUOUS_WORKFLOW_NOT_ESTABLISHED')
    actor=g._scheduled_identity(owner.GitHubCLI(),authorization,context)
    need(owner._remote_registry_bytes(owner.GitHubCLI(),authorization,actor['commit_sha'])
         ==checked_file(project,config['registry_path']).read_bytes(),'REMOTE_REGISTRY_MISMATCH')
    selected,entry,_=scope._parent(project,registry,source_policy)
    scheduled=g.scheduled.load(project,config)
    return {'schema_version':1,'purpose':g.PURPOSE,'deployment_sha256':config_sha,
        'workflow_run':actor,'detection_sha256':detected['detection_sha256'],'upstreams':detected['upstreams'],
        'selected_parent':selected,'reference_sha256':entry['expected_reference_sha256'],
        'continuous_policy_sha256':config['continuous_policy_sha256'],'registry_sha256':config['registry_sha256'],
        'authority_policy_sha256':config['authority_policy_sha256'],
        'parent_comparison':g._comparison(detected,selected,entry,config),
        'authority':'AUTHORIZED_SCHEDULED_BUILD_CONTEXT','scheduled_policy_sha256':config['scheduled_policy_sha256'],
        'scheduled_policy_canonical_sha256':digest(scheduled),'research_approval':'NOT_GRANTED',
        'production_promotion':'NOT_AUTHORIZED'}
