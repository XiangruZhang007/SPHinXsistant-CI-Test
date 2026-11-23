"""Bound existing scientific, publication and durable-Parent components.

No JSON PASS input or alternative provider is accepted by the CLI. Production
calls construct authenticated transports. Controlled drivers exist only below
this boundary and in tests. Historical Genuine v2/v3 retain their restrictions.
"""
from copy import deepcopy
from pathlib import Path
import hashlib,os,shutil,tempfile
from . import automatic_lifecycle_policy as policy_api,automatic_candidate as native
from . import automatic_release as releases,automatic_writer as writer,derived_parent_registry as derived
from . import genuine_continuous_execution as genuine,continuous_completion as completion
from . import continuous_build_policy as scope,trusted_snapshot as trust,upstream_provenance as source
from . import parent_r2_anchor as anchor,parent_authority_git_audit as audit
from .corpus_snapshot import checked_file,digest,file_digest,read_json,write_json,read_records
from .automatic_lifecycle_policy import need


def _root(project,config,policy,client,work):
    registry=scope._read_pinned(project,config['registry_path'],policy['root_registry_sha256'])
    source_policy=scope.load_policy(project,config['continuous_policy_path'],config['continuous_policy_sha256'])
    key,entry,_=scope._parent(project,registry,source_policy)
    need(key==policy['initial_parent_key'] and digest(registry)==policy['root_registry_canonical_sha256'],
         'AUTOMATIC_ROOT_MISMATCH')
    source._git(project,'merge-base','--is-ancestor',policy['root_revision'],config['implementation_revision'])
    raw=source._git(project,'show',policy['root_revision']+':'+config['registry_path'])
    need(hashlib.sha256(raw).hexdigest()==policy['root_registry_sha256'],'PROTECTED_ROOT_REVISION_MISMATCH')
    reference=entry['reference'];work.mkdir()
    for storage,name,pin in ((reference['storage'],'root.tar.gz',reference['transport_sha256']),
            (reference['parent_rows_storage'],'root-rows.json',reference['parent_rows_sha256'])):
        trust.download(storage,work/name,pin,token=client.token)
    notices=trust.fetch_notices(reference,entry['expected_reference_sha256'],work/'root-notices.zip')
    trust.restore(project,work/'root.tar.gz',work/'parent',reference,entry['expected_reference_sha256'],notices_path=notices)
    qualified=anchor.qualify_parent_anchor(project,work/'parent',reference,entry['expected_reference_sha256'],
        work/'root-rows.json',fresh_replay=False)
    need(qualified['status']=='QUALIFIED' and qualified['execution']=='NO_FRESH_REPLAY','UNQUALIFIED_AUTOMATIC_ROOT')
    verified=source.verify(project,work/'parent',policy['build_fingerprint'],expected_id=reference['node_id'])
    parent=native.parent_descriptor(work/'parent',reference['node_id'],reference['upstreams'],reference['source_state'],verified['generation'])
    history=work/'historical.json';write_json(history,qualified['historical_rows'])
    need(file_digest(history)==policy['historical_rows_sha256'],'AUTOMATIC_HISTORY_PIN_MISMATCH')
    return registry,parent,work/'parent',history


def _origin(client,config,receipt):
    actual=completion.origin(client,{**config,'implementation_revision':receipt['implementation_revision']},
        receipt['producer']['run_id'],receipt['producer']['run_attempt'])
    need(actual==receipt['producer'] and actual['event']=='schedule','DERIVED_PRODUCER_CHANGED')
    base='/repos/'+config['repository'];run=client._api('GET',base+'/actions/runs/'+str(actual['run_id'])+'/attempts/1')
    actor=receipt['writer_actor'];user=run.get('actor',{});trigger=run.get('triggering_actor',{})
    need(type(user.get('id')) is int and user['id']>0 and user.get('type')==trigger.get('type')=='User'
         and trigger.get('id')==user['id'],'DERIVED_ACTOR_MISMATCH')
    expected={'repository':config['repository'],'repository_id':config['repository_id'],
        'workflow_id':actual['workflow_id'],'workflow_path':config['workflow_path'],
        'run_id':actual['run_id'],'run_attempt':1,'event':'schedule','branch':config['default_branch'],
        'commit_sha':actual['implementation_revision'],'actor_id':user['id'],'actor_login':user.get('login'),
        'run_created_at':scope._time(run.get('created_at')).isoformat()}
    need(actor==expected and run.get('workflow_id')==actual['workflow_id'],'DERIVED_ACTOR_MISMATCH')
    jobs=client._api('GET',base+f'/actions/runs/{actual["run_id"]}/attempts/1/jobs?per_page=100&page=1')
    rows=jobs.get('jobs',[])
    need(jobs.get('total_count')==len(rows)<=100,'DERIVED_WRITER_JOBS_INCOMPLETE')
    matches=[r for r in rows if r.get('name')=='automatic-parent-writer']
    need(len(matches)==1 and matches[0].get('head_sha')==actual['implementation_revision']
         and matches[0].get('conclusion')=='success' and matches[0].get('status')=='completed',
         'DERIVED_WRITER_NOT_COMPLETED')
    return {'origin':actual,'actor':actor}


def select(project,config,policy,client,work,store):
    """Verify from protected root through every immutable admitted generation."""
    writer.observe_rules(client,policy)
    branch=client._api('GET','/repos/'+config['repository']+'/git/ref/heads/'+config['default_branch'])
    need(branch.get('ref')=='refs/heads/'+config['default_branch'] and branch.get('object',{}).get('sha')==config['implementation_revision'],
         'STALE_CONSUMER_IMPLEMENTATION')
    registry,parent,folder,history=_root(project,config,policy,client,Path(work)/'root')
    current={'parent':parent,'folder':folder}
    def verify_entry(receipt,entry,previous,state_sha):
        need(set(entry)=={'entry_kind','authority','reference','expected_reference_sha256'}
             and entry['entry_kind']=='AUTOMATIC_ADMITTED_PARENT_V1' and entry['authority']=='BUILD_CANDIDATE'
             and digest(entry['reference'])==entry['expected_reference_sha256'],'INVALID_DERIVED_PARENT_ENTRY')
        reference=entry['reference']
        need(reference['kind']=='AUTOMATIC_PARENT_REFERENCE_V1' and reference['parent']==current['parent']
             and reference['policy_sha256']==policy['policy_sha256'] and receipt['entry_sha256']==digest(entry),
             'DERIVED_REFERENCE_BINDING_MISMATCH')
        observed=_origin(client,config,receipt)
        view={'head':previous['sha'],'registry':previous['registry.json'],'selected_parent':receipt['previous_parent_key']}
        expected,cfg,binding,_=writer.transaction(policy,{**config,'implementation_revision':receipt['implementation_revision']},
            view,receipt['parent_key'],entry,reference['release'],observed)
        need({k:v for k,v in receipt.items() if k!='audit_consumption_head'}==expected,'DERIVED_TRANSACTION_SCOPE_MISMATCH')
        writer.completed(cfg,binding,client.token,receipt,state_sha,receipt['new_registry_sha256'])
        destination=Path(work)/('generation-'+str(current['parent']['generation']+1));destination.mkdir()
        result,root=releases.retrieve(project,client,policy,reference['release'],destination,current['parent'])
        need(result['parent']==reference['selected_parent'] and result['candidate_id']==reference['node_id']
             and digest(result['report'])==reference['admission_sha256'],'DERIVED_SCIENTIFIC_BINDING_MISMATCH')
        current.update(parent=result['parent'],folder=root/'candidate')
        return True
    view=derived.consume(store,policy,registry,verify_entry)
    return view,current['parent'],current['folder'],history


def build(project,detection_path,work,output):
    project,work,output=map(Path,(project,work,output))
    config,_,config_sha=genuine.deployment()
    authority=genuine._authority(project,Path(detection_path),config,config_sha)
    need(authority['workflow_run']['event']=='schedule' and config['schema_version']>=3,
         'AUTOMATIC_BUILD_REQUIRES_SCHEDULED_AUTHORITY')
    policy=policy_api.load(project,config)
    need(os.environ.get('AUTOMATIC_LIFECYCLE_ENABLED')=='true'
         and os.environ.get('CONTINUOUS_CONSTRUCTION_ENABLED')=='true'
         and os.environ.get('CONTINUOUS_PUBLICATION_ENABLED')=='true','AUTOMATIC_LIFECYCLE_DISABLED')
    genuine.scheduled.load(project,config);genuine.scheduled.mutex(project,config,authority)
    source._new_output(work,(project,output,detection_path));source._new_output(output,(project,work,detection_path));work.mkdir()
    client=completion.Client(config['repository'],os.environ.get('GH_TOKEN'))
    store=derived.GitState(config['repository'],config['repository_id'],client.token)
    view,parent,folder,history=select(project,config,policy,client,work,store)
    pair=authority['upstreams']
    if parent['upstreams']==pair:
        output.mkdir();write_json(output/'result.json',{'status':'NO_UPDATE'});return {'status':'NO_UPDATE'}
    need(view['generation']<policy['max_generations'],'AUTOMATIC_GENERATION_LIMIT')
    genuine._clone_sources(work,{'upstreams':parent['upstreams']},pair)
    need(genuine._authority(project,Path(detection_path),config,config_sha)==authority
         and store.head()==view['head'],'STALE_AUTOMATIC_BUILD_AUTHORITY')
    output.mkdir()
    verified=native.produce(project,folder,work/'base-source',work/'target-source',pair,policy,parent,history,
        output/'run',project/config['continuous_policy_path'],project/os.environ['AUTOMATIC_LIFECYCLE_POLICY_PATH'])
    need(store.head()==view['head'],'STALE_PARENT_DURING_BUILD')
    write_json(output/'selection.json',{'view':view,'parent':parent,'policy_sha256':policy['policy_sha256'],
        'candidate_id':verified['candidate_id'],'producer':authority['workflow_run']})
    result={'status':'NATIVE_CANDIDATE_BUILT','candidate_id':verified['candidate_id'],
        'eligible':verified['eligible'],'report':verified['report'],'scientific_approval':'POLICY_DECISION_ONLY'}
    write_json(output/'result.json',result);return result



def pre_token(project,work):
    """Independent scientific/lineage check before the private-key action."""
    project,work=Path(project),Path(work)
    config,_,_=genuine.deployment();policy=policy_api.load(project,config)
    client=completion.Client(config['repository'],os.environ.get('GH_TOKEN'))
    observed=writer.observe(project,config,policy,client)
    source._new_output(work,(project,));work.mkdir()
    _,artifact=completion.retrieve_build(client,config,observed['actor']['run_id'],1,work/'delivery')
    selected=read_json(work/'delivery/selection.json')
    store=derived.GitState(config['repository'],config['repository_id'],client.token)
    view,parent,_,_=select(project,config,policy,client,work,store)
    need(view==selected['view'] and parent==selected['parent'] and selected['policy_sha256']==policy['policy_sha256']
         and selected['producer']==observed['actor'],'STALE_OR_UNBOUND_BUILD_DELIVERY')
    need(view['generation']<policy['max_generations'],'AUTOMATIC_GENERATION_LIMIT')
    from .candidate_promotion_policy import assess_automatic
    assessment=assess_automatic(project,work/'delivery/run',policy,selected['candidate_id'],parent)
    need(store.head()==view['head'],'STALE_PRETOKEN_PARENT')
    result={'status':'AUTOMATIC_PRETOKEN_VERIFIED' if assessment['decision']=='APPROVED_RELEASE_ELIGIBLE' else 'QUALITY_REJECTED',
        'assessment':assessment,'artifact':artifact,'writer_credential_access':'NOT_ATTEMPTED'}
    write_json(work/'result.json',result)
    return result

def publish_and_advance(project,work):
    """Privileged job only; no build/source code execution in the read-only job."""
    project,work=Path(project),Path(work)
    config,_,_=genuine.deployment();policy=policy_api.load(project,config)
    client=completion.Client(config['repository'],os.environ.get('GH_TOKEN'))
    observed=writer.observe(project,config,policy,client,token=True)
    source._new_output(work,(project,));work.mkdir()
    origin,artifact=completion.retrieve_build(client,config,observed['actor']['run_id'],1,work/'delivery')
    selected=read_json(work/'delivery/selection.json')
    token=os.environ.get('PARENT_AUTHORITY_AUDIT_TOKEN')
    store=derived.GitState(config['repository'],config['repository_id'],token,writable=True)
    view,parent,folder,history=select(project,config,policy,client,work,store)
    need(view==selected['view'] and parent==selected['parent'] and selected['policy_sha256']==policy['policy_sha256']
         and selected['producer']==observed['actor'],'STALE_OR_UNBOUND_BUILD_DELIVERY')
    need(view['generation']<policy['max_generations'],'AUTOMATIC_GENERATION_LIMIT')
    root=work/'delivery/run';verified=native.verify(project,root,policy,selected['candidate_id'],parent)
    if not verified['eligible']:
        return {'status':'QUALITY_REJECTED','reasons':verified['report']['reasons'],'writes':'NONE'}
    def revalidate():
        need(policy_api.load(project,config)==policy and writer.observe(project,config,policy,client,token=True)==observed,
             'AUTOMATIC_WRITER_CONTEXT_CHANGED')
        need(store.head()==view['head'],'STALE_AUTOMATIC_PARENT')
    revalidate()
    binding=releases.publish(project,client,config,policy,root,verified,parent,revalidate,work/'publication')
    reference={'schema_version':1,'kind':'AUTOMATIC_PARENT_REFERENCE_V1','node_id':verified['candidate_id'],
        'parent':parent,'selected_parent':verified['parent'],'policy_sha256':policy['policy_sha256'],
        'release':binding,'admission_sha256':digest(verified['report'])}
    entry={'entry_kind':'AUTOMATIC_ADMITTED_PARENT_V1','authority':'BUILD_CANDIDATE',
        'reference':reference,'expected_reference_sha256':digest(reference)}
    key='automatic-'+verified['candidate_id'].removeprefix('sha256-')
    receipt,cfg,audit_binding,person=writer.transaction(policy,config,view,key,entry,binding,observed)
    protocol=writer.protocol(cfg,audit_binding,person,token,revalidate)
    # After the data append, revalidate policy/governance but compare the new
    # state via the protocol itself; expecting the old head would reject success.
    def repeat():
        need(policy_api.load(project,config)==policy and writer.observe(project,config,policy,client,token=True)==observed,
             'AUTOMATIC_WRITER_CONTEXT_CHANGED')
    result=derived.advance(store,view,key,entry,receipt,protocol,repeat)
    return {**result,'release':binding,'candidate_id':verified['candidate_id'],'artifact':artifact,
        'deployment':'SEPARATE_VERIFIED_DRIVER_REQUIRED','authoritative_root_registry':'UNCHANGED'}
