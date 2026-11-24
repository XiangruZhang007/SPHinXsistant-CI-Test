"""Protected, once-approved bounded policy; no per-update human decision flag."""
from datetime import datetime,timezone
from pathlib import Path
import os,re
from .corpus_snapshot import checked_file,digest,file_digest
from . import continuous_build_policy as scope

FIELDS={'schema_version','kind','enabled','repository','repository_id','root_revision',
    'root_registry_sha256','continuous_policy_sha256','root_registry_canonical_sha256','initial_parent_key','genesis_sha',
    'valid_from','expires_at','max_generations','max_advance_commits','build_fingerprint',
    'benchmark_sha256','q1_implementation_sha256','implementation_contract_sha256',
    'historical_rows_sha256','release_prefix','licenses',
    'history_ruleset_id','writer_ruleset_id','writer_integration_id','installation_id',
    'governance_sha256','writer_environment','writer_environment_id','deployment_path','deployment_sha256',
    'permissions'}
FILES=('src/automatic_lifecycle_policy.py','src/automatic_candidate.py','src/automatic_lifecycle.py',
    'scripts/runtime_ruleset_observation.py',
    'scripts/parent_authority_writer_gate.py',
    'scripts/parent_authority_writer_bootstrap.py',
    'src/derived_parent_registry.py','src/automatic_release.py','src/automatic_writer.py',
    'src/gradio_deployment_adapter.py','src/update_eligibility_gate.py','src/candidate_promotion_policy.py','scripts/automatic_lifecycle.py',
    '.github/workflows/upstream_refresh.yml','src/parent_authority_git_audit.py',
    'src/parent_authority_github_transport.py','src/research_candidate_consumer.py',
    'scripts/check_hosted_gradio_loading.py','src/corpus_update_integration.py',
    'src/versioned_corpus_storage.py','apps/gradio_app_v1.py','src/retrieval_v1.py',
    'src/grounded_answer_v1.py','configs/gradio_research_requirements.txt')


def need(ok,reason):
    if not ok:raise ValueError(reason)


def contract(project):
    from . import genuine_continuous_execution as genuine,version_aware_evidence as q1
    return {'schema_version':1,'kind':'AUTOMATIC_LIFECYCLE_V1',
            'files':{n:file_digest(checked_file(project,n)) for n in FILES},
            'genuine':genuine.contract(project),'q1':q1.implementation(project),
            'frozen_runtime_lock_sha256':file_digest(checked_file(project,'configs/ci_v2_runtime_lock.json'))}


def validate(value,raw_pin,*,now=None):
    need(isinstance(value,dict) and type(value.get('schema_version')) is int
         and value['schema_version'] in (1,2)
         and set(value)==FIELDS | ({'ruleset_observation'} if value['schema_version']==2 else set())
         and value['kind']=='AUTOMATIC_LIFECYCLE_V1'
         and value['enabled'] is True,'INVALID_AUTOMATIC_POLICY')
    need(scope._hash(raw_pin) and all(scope._hash(value[k]) for k in FIELDS
         if k.endswith('_sha256')),'INVALID_AUTOMATIC_POLICY_PIN')
    need(type(value['repository_id']) is int and value['repository_id']>0
         and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',value['repository'])
         and re.fullmatch('[0-9a-f]{40}',value['root_revision'])
         and re.fullmatch('[0-9a-f]{40}',value['genesis_sha']),'INVALID_AUTOMATIC_POLICY_DOMAIN')
    need(type(value['max_generations']) is int and 1<=value['max_generations']<=8
         and type(value['max_advance_commits']) is int and 1<=value['max_advance_commits']<=4096,
         'INVALID_AUTOMATIC_BOUNDS')
    need(value['permissions']=={'construction':True,'admission':True,'publication':True,
         'derived_registry':True,'deployment':True},'AUTOMATIC_SCOPES_NOT_APPROVED')
    start,end=scope._time(value['valid_from']),scope._time(value['expires_at'])
    need(start<= (now or datetime.now(timezone.utc)) <end,'AUTOMATIC_POLICY_EXPIRED_OR_NOT_CURRENT')
    need(re.fullmatch('[a-z][a-z0-9-]{0,39}',value['release_prefix']) and
         re.fullmatch(r'configs/[A-Za-z0-9_.-]+\.json',value['deployment_path']), 'UNSAFE_AUTOMATIC_PATH')
    need(value['writer_environment']=='ci-v2-automatic-writer' and all(type(value[k]) is int and value[k]>0
        for k in ('history_ruleset_id','writer_ruleset_id','writer_integration_id','installation_id','writer_environment_id')),
        'INVALID_AUTOMATIC_WRITER_DOMAIN')
    licenses=value['licenses']
    need(isinstance(licenses,list) and len(licenses)==7 and len({r['name'] for r in licenses})==7,
         'SEVEN_REVIEWED_LICENSES_REQUIRED')
    for row in licenses:
        need(set(row)=={'name','repository','path','sha256'} and row['repository'] in ('PROJECT','SPHinXsys','SPHinXsim')
             and row['name'] not in ('README.md','source-and-license-mapping.json')
             and re.fullmatch('[A-Za-z0-9_.-]+',row['name']) and scope._hash(row['sha256'])
             and not Path(row['path']).is_absolute() and '..' not in Path(row['path']).parts,
             'INVALID_REVIEWED_LICENSE_BINDING')
    result={**value,'policy_sha256':raw_pin}
    # Genesis excludes its own SHA and raw approval pin, avoiding a hash cycle.
    result['scope_sha256']=digest({k:v for k,v in value.items() if k!='genesis_sha'})
    return result


def load(project,config):
    path=os.environ.get('AUTOMATIC_LIFECYCLE_POLICY_PATH','')
    pin=os.environ.get('AUTOMATIC_LIFECYCLE_POLICY_SHA256','')
    need(re.fullmatch(r'configs/[A-Za-z0-9_.-]+\.json',path or '') and scope._hash(pin),
         'AUTOMATIC_POLICY_NOT_CONFIGURED')
    from . import upstream_provenance as source
    source._git(project,'ls-files','--error-unmatch','--',path)
    value=validate(scope._read_pinned(project,path,pin),pin)
    if value['schema_version']==2:
        from scripts import runtime_ruleset_observation as observation
        observation.load(project,value,default_branch=config['default_branch'],
            governance_sha256=value['governance_sha256'],operation='AUTOMATIC_LIFECYCLE')
    need(all(type(value[k]) is type(config[k]) and value[k]==config[k] for k in ('repository','repository_id'))
         and config['workflow_path']=='.github/workflows/upstream_refresh.yml'
         and value['root_registry_sha256']==config['registry_sha256']
         and value['continuous_policy_sha256']==config['continuous_policy_sha256']
         and value['implementation_contract_sha256']==digest(contract(project)),
         'AUTOMATIC_POLICY_DEPLOYMENT_MISMATCH')
    return value
