"""Native Genuine v4 evidence under a separately approved automatic policy.

Historical v2/v3 archives are never converted. Chunking, Full reconstruction,
frozen R2 and Q1 algorithms are reused. New original decisions are computed
from actual measurements; no policy threshold can waive a strict failure.
"""
from pathlib import Path
import hashlib
import shutil
from . import continuous_execution as v1, upstream_provenance as source
from . import approval_evidence as ev, ci_v2_research as c
from . import version_aware_evidence as q, continuous_build_policy as scope
from .corpus_snapshot import checked_file, digest, file_digest, read_json, read_records, write_json

FORMAT='genuine-continuous-candidate-v4'
FORMAT_V5='genuine-continuous-candidate-v5'

def package_format(policy):
    return FORMAT_V5 if policy.get('schema_version') == 3 else FORMAT


def need(ok,reason):
    if not ok:raise ValueError(reason)


def material(folder):
    folder=Path(folder)
    return {n:file_digest(checked_file(folder,n)) for n in sorted(v1.MATERIAL)}


def parent_descriptor(folder,node,upstreams,state,generation):
    return {'node_id':node,'upstreams':upstreams,'source_state':state,'generation':generation,
        'material':material(folder),'corpus_sha256':file_digest(Path(folder)/'corpus.jsonl')}


def _state(folder,descriptor,proofs,fp):
    selected=read_json(folder/'selection.json')
    return q.State({'verification':'VERIFIED_Q1_FORMAT_PAIR','provenance_type':'GENUINE_UPSTREAM',
        'source_state_id':descriptor['source_state'],'upstreams':descriptor['upstreams'],
        'corpus_sha256':descriptor['corpus_sha256'],'build_fingerprint':fp},selected,
        {q._path(i):checked_file(folder,'input/'+q._path(i)).read_bytes() for i in selected},
        read_records(folder/'corpus.jsonl'),proofs).validate()


def _reasons(target_rows,previous_rows,mapping,spec):
    """Pure decision kernel; only science() supplies fully verified rows."""
    reasons=[]
    if not all(row['strict'][metric] is True for row in target_rows for metric in ('hit_at_5','hit_at_10')):
        reasons.append('FROZEN_STRICT_FAILURE')
    for previous in ('base','historical'):
        if any(row['hit5']=='PASS→FAIL' or row['hit10']=='PASS→FAIL'
               for row in ev.compare_outcomes(previous_rows[previous],target_rows,spec)):
            reasons.append('NEW_RETRIEVAL_REGRESSION')
    summary=mapping['summary']
    if any(summary[k] for k in ('unsupported_instances','ambiguous_instances','unresolved_instances',
                               'semantic_review_instances','applicability_review_instances')):
        reasons.append('Q1_REVIEW_REQUIRED')
    return sorted(set(reasons))


def science(project,root,policy,parent,proofs):
    from . import incremental_corpus as engine
    root=Path(root);meta=read_json(root/'candidate/genuine-candidate.json');i=meta['identity']
    fp=policy['build_fingerprint'];lock=read_json(Path(project)/c.LOCK)
    need(fp==digest(lock['P2']),'FROZEN_BUILD_MISMATCH')
    spec=ev.frozen_implementation(project,Path(project)/ev.BENCHMARK,lock['quality_policy'])
    need(policy['benchmark_sha256']==ev.BENCHMARK_SHA and policy['q1_implementation_sha256']==digest(q.implementation(project)),
         'SCIENTIFIC_POLICY_MISMATCH')
    need(material(root/'parent')==parent['material'],'PARENT_MATERIAL_MISMATCH')
    need(i['parent']==parent and i['generation']==parent['generation']+1,'NATIVE_PARENT_BINDING_MISMATCH')
    selection=read_json(root/'candidate/selection.json')
    for label,folder,revisions in [('base',root/'parent',parent['upstreams']),('target',root/'candidate',i['upstreams'])]:
        selected=read_json(folder/'selection.json')
        for repo in c.SOURCES:
            need(source.verify_proof(proofs[label][repo],selected)==revisions[repo],'NATIVE_SOURCE_PROOF_MISMATCH')
        engine._verify_materialized(project,folder,selected,read_json(folder/'inventory.json'),read_json(folder/'extraction-graph.json'))
    need(source.state(selection)==i['source_state'],'NATIVE_SOURCE_STATE_MISMATCH')
    source_policy=read_json(root/'source-policy.json')
    need(file_digest(root/'source-policy.json')==policy['continuous_policy_sha256'],'NATIVE_SOURCE_POLICY_MISMATCH')
    v1._archive_policy(source_policy)
    v1._archived_sources(source_policy,{'base_selection':read_json(root/'parent/selection.json'),
        'target_selection':selection,'base_proofs':proofs['base'],'target_proofs':proofs['target'],
        'relationships':proofs['relationships'],'source_refs':proofs['source_refs']},
        {'parent':parent,'upstreams':i['upstreams'],'target_source_state':i['source_state']})
    for repo in c.SOURCES:
        source.verify_relationship(proofs['relationships'][repo],parent['upstreams'][repo],i['upstreams'][repo])
        need(len(proofs['relationships'][repo]['commits'])<=policy['max_advance_commits'],'SOURCE_ADVANCEMENT_OUTSIDE_POLICY')
    need(read_json(root/'parity.json')==v1._parity(project,root,meta),'INVALID_NATIVE_FULL_PARITY')
    rows={label:read_json(root/('quality/'+label+'-rows.json')) for label in ('base','target','full','historical')}
    for label,folder in [('base',root/'parent'),('target',root/'candidate'),('full',root/'full')]:
        ev.rescore(rows[label],spec,read_records(folder/'corpus.jsonl'),read_records(folder/'components/documentation.jsonl'))
    need(ev.same(rows['target'],rows['full']),'NATIVE_FULL_R2_MISMATCH')
    # Historical rows are independently pinned by protected policy/root evidence.
    need(file_digest(root/'quality/historical-rows.json')==policy['historical_rows_sha256'],'HISTORICAL_R2_PIN_MISMATCH')
    target=parent_descriptor(root/'candidate',meta['candidate_id'],i['upstreams'],i['source_state'],i['generation'])
    mapping=q.analyze(spec,_state(root/'parent',parent,proofs['base'],fp),
        _state(root/'candidate',target,proofs['target'],fp),benchmark_sha256=ev.BENCHMARK_SHA,
        implementation_contract=q.implementation(project),base_rows=rows['base'],target_rows=rows['target'])
    reasons=_reasons(rows['target'],{k:rows[k] for k in ('base','historical')},mapping,spec)
    need(read_json(root/'q1-report.json')==mapping,'NATIVE_Q1_REPORT_MISMATCH')
    report={'schema_version':1,'contract':'AUTOMATIC_QUALITY_V2','candidate_id':meta['candidate_id'],
        'policy_sha256':policy['policy_sha256'],'benchmark_sha256':ev.BENCHMARK_SHA,
        'status':'QUALITY_ACCEPTED' if not reasons else 'QUALITY_REVIEW_REQUIRED',
        'accepted':not reasons,'reasons':sorted(set(reasons)),
        'q1':'QUALIFIED_FOR_VERSION_PAIR' if 'Q1_REVIEW_REQUIRED' not in reasons else 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR',
        'P8':'ELIGIBLE' if not reasons else 'P8_BLOCKED','corpus_sha256':target['corpus_sha256']}
    if policy.get('schema_version') == 3:
        from .quality_admission import evaluate
        report=evaluate(project,root,policy,rows,report,spec)
    return report,mapping,target


def verify(project,root,policy,expected_candidate_id,parent):
    root=Path(root);v1._check_seal(root)
    if policy.get('schema_version')==3:
        from .native_runtime_contract import components
        need(policy['component_fingerprints']==components(project),'V3_COMPONENT_MISMATCH')
    need({p.name for p in root.iterdir()}=={'parent','candidate','full','extraction-observations','source-policy.json',
        'policy.json','source-proofs.json','parity.json','quality','q1-report.json','license-sources.json','result.json','checksums.json'} |
             ({'admission-policy.json','admission-references.json','admission-anchor-corpus.jsonl','admission-anchor-rows.json'} if policy.get('schema_version')==3 else set()),
        'UNEXPECTED_NATIVE_RUN_MEMBERS')
    need({p.name for p in (root/'quality').iterdir()}=={'base-rows.json','target-rows.json','full-rows.json','historical-rows.json','admission.json'},
        'UNEXPECTED_NATIVE_QUALITY_MEMBERS')
    meta=read_json(checked_file(root,'candidate/genuine-candidate.json'));i=meta['identity']
    need(set(meta)=={'schema_version','format','candidate_id','identity'} and meta['schema_version']==1
         and type(meta['schema_version']) is int and meta['format']==i['format']==package_format(policy) and meta['candidate_id']==expected_candidate_id=='sha256-'+digest(i),
         'INVALID_NATIVE_CANDIDATE_ID')
    need(set(i)=={'format','generation','parent','upstreams','source_state','build_fingerprint',
                  'policy_sha256','artifacts','purpose'} and i['purpose']=='POLICY_BOUND_AUTOMATIC_LIFECYCLE'
         and i['policy_sha256']==policy['policy_sha256'] and i['build_fingerprint']==policy['build_fingerprint'],
         'NATIVE_POLICY_BINDING_MISMATCH')
    paths={'candidate/'+n for n in v1.MATERIAL}|{'candidate/input/'+q._path(r) for r in read_json(root/'candidate/selection.json')}
    need(set(i['artifacts'])==paths,'UNEXPECTED_NATIVE_ARTIFACT_INVENTORY')
    need(set(v1._files(root/'candidate'))=={n.removeprefix('candidate/') for n in paths}|{'genuine-candidate.json','candidate.json'},
         'UNEXPECTED_NATIVE_CANDIDATE_MEMBERS')
    need(read_json(root/'candidate/candidate.json')==v1._projection(expected_candidate_id,{'parent':parent,'target_source_state':i['source_state']}),
         'NATIVE_PROJECTION_MISMATCH')
    expected={n:file_digest(checked_file(root,n)) for n in i['artifacts']}
    need(expected==i['artifacts'] and material(root/'candidate')=={n:expected['candidate/'+n] for n in v1.MATERIAL},
         'NATIVE_ARTIFACT_MISMATCH')
    need(file_digest(checked_file(root,'policy.json'))==policy['policy_sha256'],'ARCHIVED_AUTOMATIC_POLICY_PIN_MISMATCH')
    need(read_json(root/'policy.json')=={k:v for k,v in policy.items() if k not in ('policy_sha256','scope_sha256')},'ARCHIVED_AUTOMATIC_POLICY_MISMATCH')
    proof=read_json(root/'source-proofs.json')
    report,mapping,target=science(project,root,policy,parent,proof)
    need(read_json(root/'quality/admission.json')==report,'NATIVE_ADMISSION_REPORT_MISMATCH')
    need(read_json(root/'result.json')=={'research_baseline_created':False,'automatic_research_approval':False,
        'candidate_id':expected_candidate_id,'status':'NATIVE_CANDIDATE_BUILT','scientific_decision':report['status']},'NATIVE_RESULT_MISMATCH')
    from .automatic_release import verify_license_sources
    verify_license_sources(project,root,policy)
    return {'candidate_id':expected_candidate_id,'report':report,'parent':target,
            'verification':'COMPLETE_NATIVE_PACKAGE_VERIFIED','eligible':report['accepted']}


def produce(project,parent_dir,base_source,target_source,upstreams,policy,parent,history,output,source_policy_path,automatic_policy_path,*,admission_anchor_dir=None,admission_anchor_rows=None):
    """Only the trusted scheduled caller supplies authority; this builds evidence."""
    if policy.get('schema_version')==3:
        need(admission_anchor_dir is not None and admission_anchor_rows is not None,'V3_INITIAL_ANCHOR_REQUIRED')
    root=Path(output);source._new_output(root,(parent_dir,base_source,target_source,project));v1._files(Path(parent_dir));root.mkdir()
    shutil.copytree(parent_dir,root/'parent',symlinks=False)
    need(material(root/'parent')==parent['material'],'PARENT_MATERIAL_MISMATCH')
    base,base_proofs=source.verify_sources(project,base_source,parent['upstreams'])
    selection,target_proofs=source.verify_sources(project,target_source,upstreams)
    need(base==read_json(root/'parent/selection.json'),'PARENT_SOURCE_MISMATCH')
    proof={'base':base_proofs,'target':target_proofs,'relationships':{
        repo:source.relationship(Path(target_source)/'repos'/repo,parent['upstreams'][repo],upstreams[repo]) for repo in c.SOURCES}}
    source_policy=scope.load_policy(project,Path(source_policy_path).relative_to(Path(project)).as_posix(),policy['continuous_policy_sha256'])
    proof['source_refs']=scope._source_refs(source_policy,upstreams,base_proofs,target_proofs)
    shutil.copyfile(source_policy_path,root/'source-policy.json')
    v1._assemble(project,root,root/'parent',target_source,selection)
    source.full_reference(project,target_source,root/'full',upstreams,policy['build_fingerprint'])
    need(file_digest(automatic_policy_path)==policy['policy_sha256'],'AUTOMATIC_POLICY_RAW_PIN_MISMATCH')
    shutil.copyfile(automatic_policy_path,root/'policy.json')
    write_json(root/'source-proofs.json',proof)
    artifacts={'candidate/'+n:file_digest(root/'candidate'/n) for n in v1.MATERIAL}
    artifacts.update({'candidate/input/'+q._path(row):file_digest(root/'candidate/input'/q._path(row)) for row in selection})
    if policy.get('schema_version')==3:
        need(admission_anchor_dir is not None and admission_anchor_rows is not None,'V3_INITIAL_ANCHOR_REQUIRED')
        for name in ('policy','references'):
            pin=policy['quality_v3'][name]
            need(file_digest(Path(project)/pin['path'])==pin['sha256'],'V3_EXTERNAL_PIN_MISMATCH')
            shutil.copyfile(Path(project)/pin['path'],root/('admission-'+name+'.json'))
        shutil.copyfile(Path(admission_anchor_dir)/'corpus.jsonl',root/'admission-anchor-corpus.jsonl')
        shutil.copyfile(admission_anchor_rows,root/'admission-anchor-rows.json')
    i={'format':package_format(policy),'generation':parent['generation']+1,'parent':parent,'upstreams':upstreams,
       'source_state':source.state(selection),'build_fingerprint':policy['build_fingerprint'],
       'policy_sha256':policy['policy_sha256'],'artifacts':artifacts,'purpose':'POLICY_BOUND_AUTOMATIC_LIFECYCLE'}
    meta={'schema_version':1,'format':package_format(policy),'candidate_id':'sha256-'+digest(i),'identity':i}
    write_json(root/'candidate/genuine-candidate.json',meta)
    write_json(root/'candidate/candidate.json',v1._projection(meta['candidate_id'],{
        'parent':parent,'target_source_state':i['source_state']}))
    write_json(root/'parity.json',v1._parity(project,root,meta))
    (root/'quality').mkdir();lock=read_json(Path(project)/c.LOCK)
    spec=ev.frozen_implementation(project,Path(project)/ev.BENCHMARK,lock['quality_policy'])
    for label,folder in [('base','parent'),('target','candidate'),('full','full')]:
        write_json(root/('quality/'+label+'-rows.json'),ev.replay(spec,root/folder/'corpus.jsonl',root/folder/'components/documentation.jsonl'))
    shutil.copyfile(history,root/'quality/historical-rows.json')
    target=parent_descriptor(root/'candidate',meta['candidate_id'],upstreams,i['source_state'],i['generation'])
    mapping=q.analyze(spec,_state(root/'parent',parent,base_proofs,policy['build_fingerprint']),
        _state(root/'candidate',target,target_proofs,policy['build_fingerprint']),benchmark_sha256=ev.BENCHMARK_SHA,
        implementation_contract=q.implementation(project),base_rows=read_json(root/'quality/base-rows.json'),
        target_rows=read_json(root/'quality/target-rows.json'))
    write_json(root/'q1-report.json',mapping)
    report,_,_=science(project,root,policy,parent,proof)
    from .automatic_release import retain_license_sources
    retain_license_sources(project,base_source,target_source,root,policy)
    write_json(root/'quality/admission.json',report)
    write_json(root/'result.json',{'research_baseline_created':False,'automatic_research_approval':False,
        'candidate_id':meta['candidate_id'],'status':'NATIVE_CANDIDATE_BUILT','scientific_decision':report['status']})
    v1._seal(root)
    return verify(project,root,policy,meta['candidate_id'],parent)
