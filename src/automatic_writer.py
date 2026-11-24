"""Policy-bound scheduled Writer; existing manual Owner gate is unchanged.

No key is read by this module. A pre-token observation precedes the Workflow's
installation-token action; every write repeats observation. Contents write is
repository-wide. This is explicitly Owner-managed, not independent governance.
"""
from copy import deepcopy
import hashlib,os
from . import parent_authority_git_audit as audit
from .parent_authority_github_transport import GitHubAuditTransport,AUDIT_TREE
from . import genuine_continuous_execution as genuine,continuous_completion as completion
from .corpus_snapshot import canonical,digest
from .automatic_lifecycle_policy import need


def observe(project,config,policy,client,*,token=False):
    from scripts import parent_authority_writer_gate as gate
    need(os.environ.get('GITHUB_JOB')=='automatic-parent-writer' and
         os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted'
         and os.environ.get('RUNNER_ARCH')=='ARM64' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1'
         and os.environ.get('GITHUB_WORKSPACE')==str(project.resolve())
         and os.environ.get('GITHUB_SHA')==os.environ.get('GITHUB_WORKFLOW_SHA')==config['implementation_revision']
         and os.environ.get('GITHUB_WORKFLOW_REF')==config['repository']+'/'+config['workflow_path']+'@refs/heads/'+config['default_branch'],
         'AUTOMATIC_WRITER_RUNTIME_MISMATCH')
    genuine._checkout(project,config)
    context=genuine._scheduled_context()
    actor=genuine._scheduled_identity(genuine.owner.GitHubCLI(),config,context)
    base='/repos/'+policy['repository']
    need(policy['repository']==gate.REPOSITORY and policy['repository_id']==gate.REPOSITORY_ID
         and policy['writer_integration_id']==gate.APP_ID and policy['installation_id']==gate.INSTALLATION_ID,
         'AUTOMATIC_WRITER_SCOPE_MISMATCH')
    repo=client._api('GET',base)
    need(repo.get('owner',{}).get('id')==gate.OWNER_ID,'AUTOMATIC_OWNER_MISMATCH')
    environment=client._api('GET',base+'/environments/'+policy['writer_environment'])
    # An automatic policy is not a per-update Environment approval. The existing
    # required-reviewer setup therefore cannot silently enable unattended writes.
    need(environment.get('id')==policy['writer_environment_id'] and environment.get('name')==policy['writer_environment']
         and environment.get('can_admins_bypass') is False
         and isinstance(environment.get('protection_rules'),list)
         and len(environment['protection_rules'])==1
         and environment['protection_rules'][0].get('type')=='branch_policy'
         and environment.get('deployment_branch_policy')=={'protected_branches':False,'custom_branch_policies':True},
         'AUTOMATIC_ENVIRONMENT_CONFIGURATION_REQUIRED')
    branches=client._api('GET',base+'/environments/'+policy['writer_environment']+'/deployment-branch-policies?per_page=100')
    need(branches.get('total_count')==1 and len(branches.get('branch_policies',[]))==1
         and branches['branch_policies'][0].get('name')==config['default_branch']
         and branches['branch_policies'][0].get('type')=='branch','AUTOMATIC_ENVIRONMENT_BRANCH_MISMATCH')
    rules=client._api('GET',base+'/rules/branches/'+config['default_branch'])
    revised=policy['schema_version']==2
    for kind in (() if revised else ('deletion','non_fast_forward','pull_request')):
        origins=[client._api('GET',base+'/rulesets/'+str(x['ruleset_id'])) for x in rules if x.get('type')==kind]
        safe=[r for r in origins if r.get('enforcement')=='active' and r.get('target')=='branch'
            and r.get('bypass_actors')==[] and r.get('conditions')=={'ref_name':{'include':['refs/heads/'+config['default_branch']],'exclude':[]}}]
        need(any(any(x.get('type')==kind and (kind!='pull_request' or
            x.get('parameters',{}).get('required_approving_review_count',0)>=1 and
            x['parameters'].get('require_code_owner_review') is True and
            x['parameters'].get('dismiss_stale_reviews_on_push') is True) for x in r.get('rules',[])) for r in safe),
            'AUTOMATIC_TRUSTED_BRANCH_PROTECTION_REQUIRED')
    rules_observation=observe_rules(client,policy,project=project)
    if revised:
        from scripts import runtime_ruleset_observation as observation
        evidence=observation.load(project,policy,default_branch=config['default_branch'],
            governance_sha256=policy['governance_sha256'],operation='AUTOMATIC_LIFECYCLE')
        observation.effective_default(evidence,rules)
    origin=completion.origin(client,config,actor['run_id'],1)
    need(origin['event']=='schedule','AUTOMATIC_PRODUCER_NOT_SCHEDULED')
    if token:gate.verify_token(os.environ,gate.GitHubRead())
    return {'actor':actor,'origin':origin,'governance_sha256':policy['governance_sha256'],
        **({'ruleset_observation':rules_observation} if revised else {})}


def observe_rules(client,policy,*,project=None):
    """Shared read-only revocation/governance check for every consumer."""
    base='/repos/'+policy['repository']
    if policy['schema_version']==2:
        from scripts import runtime_ruleset_observation as observation
        evidence=observation.load(project,policy,default_branch='ci-upstream-refresh',
            governance_sha256=policy['governance_sha256'],operation='AUTOMATIC_LIFECYCLE')
        return observation.observe(evidence,lambda number:client._api('GET',base+'/rulesets/'+str(number)),
            update_read=lambda node,number:observation.live_update(client.token,node,number))
    rulesets=[]
    for number in (policy['history_ruleset_id'],policy['writer_ruleset_id']):
        r=client._api('GET',base+'/rulesets/'+str(number))
        rulesets.append({k:r.get(k) for k in ('id','target','enforcement','conditions','bypass_actors','rules')})
    a,b=rulesets;target={'ref_name':{'include':['refs/heads/ci-v2-authority-audit/*'],'exclude':[]}}
    need(all(r['target']=='branch' and r['enforcement']=='active' and r['conditions']==target for r in rulesets)
         and a['id']==policy['history_ruleset_id'] and a['bypass_actors']==[]
         and {r['type'] for r in a['rules']}=={'deletion','non_fast_forward','required_linear_history'}
         and b['id']==policy['writer_ruleset_id']
         and b['bypass_actors']==[{'actor_id':policy['writer_integration_id'],'actor_type':'Integration','bypass_mode':'always'}]
         and b['rules']==[{'type':'creation'},{'type':'update','parameters':{'update_allows_fetch_and_merge':False}}]
         and digest({'schema_version':1,'rulesets':rulesets})==policy['governance_sha256'],
         'AUTOMATIC_AUDIT_GOVERNANCE_MISMATCH')
    return policy['governance_sha256']


def transaction(policy,config,view,key,entry,release,observed):
    """Deterministic exact transaction scope; no invented Owner decision."""
    from .derived_parent_registry import serialize
    registry=deepcopy(view['registry']);registry['baselines'][key]=deepcopy(entry)
    actor=observed['actor']
    request={'repository':policy['repository'],'repository_id':policy['repository_id'],
        'implementation_revision':config['implementation_revision'],'policy_sha256':policy['policy_sha256'],
        'previous_state_sha':view['head'],'previous_parent_key':view['selected_parent'],
        'old_registry_sha256':hashlib.sha256(serialize(view['registry'])).hexdigest(),
        'new_registry_sha256':hashlib.sha256(serialize(registry)).hexdigest(),'parent_key':key,
        'entry_sha256':digest(entry),'release':release,'producer':observed['origin'],'writer_actor':actor}
    tx=digest(request)[:32]
    receipt={**request,'transition_id':tx}
    decision={'schema_version':1,'operation':'AUTOMATIC_PARENT_ADVANCEMENT_V1',
        'decision':'POLICY_AUTHORIZED_AUTOMATIC_ADVANCEMENT','transaction_id':tx,
        **{k:request[k] for k in ('repository','repository_id','implementation_revision','old_registry_sha256','policy_sha256')},
        'result_registry_sha256':request['new_registry_sha256'],
        **{k:actor[k] for k in ('run_id','run_attempt','actor_id','workflow_id','workflow_path','event')},
        'request_sha256':digest(request),'proposal_sha256':digest(receipt)}
    binding={'request_sha256':digest(request),'proposal_sha256':digest(receipt),'subject_sha256':digest(request),
        'policy_decision_sha256':digest(decision),'decision':decision,'baseline_id':entry['reference']['node_id'],
        'reference_sha256':entry['expected_reference_sha256'],'notices_sha256':release['assets']['notices.zip']['sha256']}
    cfg={'schema_version':2,'repository':policy['repository'],'repository_id':policy['repository_id'],
        'ref':'refs/heads/ci-v2-authority-audit/'+tx,'tree_sha':AUDIT_TREE,
        'governance_sha256':policy['governance_sha256'],'genesis_sha':'0'*40}
    person={'name':'CI V2 Policy Writer','email':'ci-v2-policy-writer@users.noreply.github.com',
            'date':'2000-01-01T00:00:00Z'}
    # Git's fixed author/committer are object metadata, not authorization claims.
    raw=('tree '+AUDIT_TREE+'\nauthor '+person['name']+' <'+person['email']+'> 946684800 +0000\ncommitter '
         +person['name']+' <'+person['email']+'> 946684800 +0000\n\n'+audit._message(audit._genesis(cfg,binding))).encode()
    cfg['genesis_sha']=hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    audit._IsolatedGitProtocol(None,cfg,binding)
    return receipt,cfg,binding,person


def protocol(config,binding,person,token,revalidate):
    """One-shot initialization is separately bounded by the approved policy."""
    revalidate()
    init=GitHubAuditTransport(config,binding,token,write_scope='INITIALIZE')
    init.create_genesis(person)
    revalidate()
    create=GitHubAuditTransport(config,binding,token,write_scope='INITIALIZE')
    create.initialize_ref()
    revalidate()
    api=GitHubAuditTransport(config,binding,token,write_scope='APPEND')
    return audit._IsolatedGitProtocol(api,config,binding)


def completed(config,binding,token,receipt,state_sha,registry_sha):
    api=GitHubAuditTransport(config,binding,token)
    protocol=audit._IsolatedGitProtocol(api,config,binding)
    need(protocol.inspect()['status']=='COMPLETED_REVIEW_REQUIRED','INCOMPLETE_DERIVED_TRANSACTION')
    _,events=protocol._scan()
    need(len(events)==3 and events[1][0]==receipt['audit_consumption_head'],'CONSUMPTION_RECEIPT_MISMATCH')
    expected={'operation':'AUTOMATIC_PARENT_ADVANCEMENT_V1','state_sha':state_sha,
        'registry_sha256':registry_sha,'transaction_id':receipt['transition_id']}
    need(events[-1][1]['receipt_sha256']==digest(expected),'COMPLETION_RECEIPT_MISMATCH')
    return True
