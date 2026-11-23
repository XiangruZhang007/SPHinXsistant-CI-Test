"""Complete immutable approved native packages and mandatory notices.

Reuses existing authenticated release and full-byte download/extraction code.
No upload is reachable through the CLI without the trusted scheduled gate.
Partial/uncertain writes stop; drafts are neither deleted nor overwritten.
"""
from pathlib import Path
import base64,hashlib,json,tempfile,zipfile,shutil
from . import upstream_provenance as source, trusted_snapshot as trust
from . import ci_v2_research as c, continuous_completion as completion
from .corpus_snapshot import checked_file,canonical,digest,file_digest,read_json,write_json
from .automatic_lifecycle_policy import need

ASSETS=('candidate.tar.gz','notices.zip','admission.json')


def retain_license_sources(project,base_source,target_source,root,policy):
    values={}
    for row in policy['licenses']:
        trees={};repo=row['repository']
        if repo=='PROJECT':
            source._git(project,'ls-files','--error-unmatch','--',row['path'])
            raw=checked_file(project,row['path']).read_bytes()
        else:
            by_version={}
            for label,source_path in [('base',base_source),('target',target_source)]:
                trees={};checkout=Path(source_path)/'repos'/repo
                commit=source._git(checkout,'rev-parse','HEAD').decode().strip()
                current,_=source._commit(source._git(checkout,'cat-file','commit',commit))
                for index,part in enumerate(Path(row['path']).parts):
                    tree=source._git(checkout,'cat-file','tree',current)
                    trees[current]=base64.b64encode(tree).decode();mode,oid=source._tree(tree).get(part,(None,None))
                    if index==len(Path(row['path']).parts)-1:
                        need(mode=='100644','UNSAFE_LICENSE_PATH');raw=source._git(checkout,'cat-file','blob',oid)
                    else:need(mode=='40000','UNSAFE_LICENSE_DIRECTORY');current=oid
                need(hashlib.sha256(raw).hexdigest()==row['sha256'],'REVIEWED_LICENSE_CHANGED')
                by_version[label]=trees
            trees=by_version
        need(hashlib.sha256(raw).hexdigest()==row['sha256'],'REVIEWED_LICENSE_CHANGED')
        values[row['name']]={'raw':base64.b64encode(raw).decode(),'trees':trees}
    write_json(Path(root)/'license-sources.json',values)


def verify_license_sources(project,root,policy):
    root=Path(root);values=read_json(checked_file(root,'license-sources.json'))
    need(set(values)=={r['name'] for r in policy['licenses']},'LICENSE_INVENTORY_MISMATCH')
    proofs=read_json(checked_file(root,'source-proofs.json'));result={}
    for row in policy['licenses']:
        value=values[row['name']];need(set(value)=={'raw','trees'},'INVALID_LICENSE_PROOF')
        raw=base64.b64decode(value['raw'],validate=True)
        need(hashlib.sha256(raw).hexdigest()==row['sha256'],'LICENSE_TEXT_MISMATCH')
        if row['repository']=='PROJECT':
            source._git(project,'ls-files','--error-unmatch','--',row['path'])
            need(not value['trees'] and checked_file(project,row['path']).read_bytes()==raw,'PROJECT_LICENSE_MISMATCH')
        else:
            need(set(value['trees'])=={'base','target'},'INCOMPLETE_LICENSE_VERSIONS')
            for label in ('base','target'):
                proof=proofs[label][row['repository']];trees=value['trees'][label]
                current,_=source._commit(source._decoded(proof['commit_raw'],'commit',proof['commit']))
                used=set()
                for index,part in enumerate(Path(row['path']).parts):
                    used.add(current);tree=source._tree(source._decoded(trees[current],'tree',current))
                    mode,oid=tree.get(part,(None,None))
                    if index==len(Path(row['path']).parts)-1:
                        need(mode=='100644' and source._object(raw,'blob')==oid,'SOURCE_LICENSE_BLOB_MISMATCH')
                    else:need(mode=='40000','SOURCE_LICENSE_PATH_MISMATCH');current=oid
                need(used==set(trees),'UNBOUND_LICENSE_TREES')
        result[row['name']]=raw
    return result


def notices(project,root,policy,path,candidate_id):
    texts=verify_license_sources(project,root,policy)
    mapping={'schema_version':1,'kind':'AUTOMATIC_CANDIDATE_NOTICES_V1','candidate_id':candidate_id,
        'scope':'Original Parent, Candidate, Full, Corpus and embedded third-party source material',
        'licenses':policy['licenses'],'source_commits':{label:{repo:p['commit'] for repo,p in values.items()}
            for label,values in read_json(root/'source-proofs.json').items() if label in ('base','target')}}
    expected={**texts,'source-and-license-mapping.json':canonical(mapping)+b'\n',
        'README.md':('Mandatory companion notices for '+candidate_id+'\n'
            'Preserve these texts and mappings with onward transfers. No relicensing or blanket legal authorization.\n').encode()}
    with zipfile.ZipFile(path,'x',compression=zipfile.ZIP_DEFLATED) as archive:
        for name,raw in sorted(expected.items()):
            info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0));info.external_attr=0o100644<<16
            archive.writestr(info,raw)
    verify_notices(path,expected)
    return expected


def verify_notices(path,expected):
    with zipfile.ZipFile(path) as archive:
        need(len(archive.infolist())==len(expected) and len(set(archive.namelist()))==len(expected)
             and set(archive.namelist())==set(expected),'INVALID_AUTOMATIC_NOTICES_INVENTORY')
        for info in archive.infolist():
            need(info.file_size==len(expected[info.filename]) and info.file_size<=1024**2
                 and (info.external_attr>>16)&0o170000==0o100000
                 and archive.read(info)==expected[info.filename],'INVALID_AUTOMATIC_NOTICES_BYTES')
        need(archive.testzip() is None,'INVALID_NOTICES_CRC')


def _download_all(client,release,manifest,destination):
    need(release.get('draft') is False and release.get('immutable') is True,'APPROVED_RELEASE_NOT_IMMUTABLE')
    assets=release.get('assets',[])
    need(len(assets)==3 and len({a['id'] for a in assets})==3 and {a['name'] for a in assets}==set(ASSETS),'APPROVED_RELEASE_INVENTORY_MISMATCH')
    for asset in assets:
        expected=manifest[asset['name']]
        need(asset['size']==expected['size'] and asset['digest']=='sha256:'+expected['sha256'],'APPROVED_ASSET_IDENTITY_MISMATCH')
        completion._download(client,asset,Path(destination)/asset['name'],expected['sha256'])


def _publish(project,client,config,policy,root,verified,parent,revalidate,output,journal):
    from . import automatic_candidate as native
    need(verified['eligible'] is True,'CANDIDATE_NOT_ADMITTED')
    root=Path(root);output=Path(output);output.mkdir()
    from .candidate_promotion_policy import assess_automatic
    admission=assess_automatic(project,root,policy,verified['candidate_id'],parent)
    need(admission['decision']=='APPROVED_RELEASE_ELIGIBLE','P8_OR_PROMOTION_BLOCKED')
    checked=admission['verified']
    need(checked==verified,'ADMISSION_CHANGED_BEFORE_PUBLICATION')
    revalidate();base='/repos/'+policy['repository']
    need(client._api('GET',base+'/immutable-releases').get('enabled') is True,'IMMUTABLE_RELEASES_DISABLED')
    tag=policy['release_prefix']+'-'+verified['candidate_id'].removeprefix('sha256-')
    need(client._api('GET',base+'/releases/tags/'+tag,allow_404=True) is None
         and client._api('GET',base+'/git/ref/tags/'+tag,allow_404=True) is None,
         'EXISTING_RELEASE_REQUIRES_VERIFIED_RECOVERY')
    transport=c.package_candidate(root,output/'candidate.tar.gz')
    notice_bytes=notices(project,root,policy,output/'notices.zip',verified['candidate_id'])
    record={'schema_version':1,'kind':'APPROVED_AUTOMATIC_CANDIDATE_V1','candidate_id':verified['candidate_id'],
        'parent':verified['parent'],'policy_sha256':policy['policy_sha256'],
        'admission_sha256':digest(verified['report']),'implementation_revision':config['implementation_revision'],
        'archive_sha256':file_digest(output/'candidate.tar.gz'),'notices_sha256':file_digest(output/'notices.zip')}
    write_json(output/'admission.json',record)
    pins={name:{'sha256':file_digest(output/name),'size':(output/name).stat().st_size} for name in ASSETS}
    revalidate()
    journal['mutation_attempted']=True
    draft=client._api('POST',base+'/releases',{'tag_name':tag,'target_commitish':config['implementation_revision'],
        'name':'Policy-admitted Corpus '+verified['candidate_id'][-12:],'draft':True,'prerelease':True,
        'body':'Exact policy-admitted native v4 Candidate. Mandatory archive, notices and admission manifest. No historical Candidate approval is implied.'})
    journal['release_id']=draft.get('id')
    need(draft.get('draft') is True and draft.get('target_commitish')==config['implementation_revision']
         and draft.get('tag_name')==tag,'DRAFT_IDENTITY_MISMATCH')
    uploaded=[]
    for name in ASSETS:
        asset=client._upload(draft['upload_url'],draft['id'],output/name)
        need(asset['name']==name and asset['size']==pins[name]['size'],'UPLOAD_IDENTITY_MISMATCH')
        uploaded.append(asset)
        with tempfile.TemporaryDirectory() as temporary:
            completion._download(client,asset,Path(temporary)/name,pins[name]['sha256'])
    current=client._api('GET',base+'/releases/'+str(draft['id']))
    need(current['draft'] and {a['id'] for a in current['assets']}=={a['id'] for a in uploaded},'DRAFT_READBACK_MISMATCH')
    revalidate();journal['publication_attempted']=True
    client._api('PATCH',base+'/releases/'+str(draft['id']),{'draft':False})
    release=client._api('GET',base+'/releases/'+str(draft['id']))
    need(release.get('id')==draft['id'] and release.get('target_commitish')==config['implementation_revision']
         and {a['id'] for a in release.get('assets',[])}=={a['id'] for a in uploaded},'PUBLISHED_RELEASE_IDENTITY_CHANGED')
    with tempfile.TemporaryDirectory() as temporary:_download_all(client,release,pins,temporary)
    ref=client._api('GET',base+'/git/ref/tags/'+tag)
    need(ref['object']['type']=='commit' and ref['object']['sha']==config['implementation_revision'],'PUBLICATION_TAG_MISMATCH')
    return {'repository':policy['repository'],'repository_id':policy['repository_id'],'release_id':release['id'],
        'tag':tag,'implementation_revision':config['implementation_revision'],
        'assets':{a['name']:{'id':a['id'],**pins[a['name']]} for a in release['assets']}}



def publish(project,client,config,policy,root,verified,parent,revalidate,output):
    """No retry or deletion. Uncertain publication is reconciled read-only."""
    journal={'status':'PREWRITE','mutation_attempted':False,'publication_attempted':False,'retry':False}
    try:
        result=_publish(project,client,config,policy,root,verified,parent,revalidate,output,journal)
        journal.update(status='PUBLISHED_BYTES_VERIFIED',binding=result)
        write_json(Path(output)/'publication-state.json',journal)
        return result
    except Exception as error:
        journal['status']='REMOTE_STATE_UNCERTAIN' if journal['mutation_attempted'] else 'PREWRITE_BLOCKED'
        if journal['mutation_attempted']:
            try:
                base='/repos/'+policy['repository']
                if type(journal.get('release_id')) is int:
                    observed=client._api('GET',base+'/releases/'+str(journal['release_id']))
                    journal['read_only_observation']={k:observed.get(k) for k in ('id','tag_name','draft','immutable')}
                    journal['observed_asset_ids']=[a.get('id') for a in observed.get('assets',[])]
                else:
                    rows=client._api('GET',base+'/releases?per_page=100&page=1')
                    tag=policy['release_prefix']+'-'+verified['candidate_id'].removeprefix('sha256-')
                    journal['matching_ids_observed']=[r.get('id') for r in rows if r.get('tag_name')==tag]
                    journal['inventory_complete']=len(rows)<100
            except Exception:journal['reconciliation']='UNVERIFIED'
        try:write_json(Path(output)/'publication-state.json',journal)
        except OSError:pass
        raise ValueError('AUTOMATIC_PUBLICATION_STOPPED_NO_RETRY') from error

def retrieve(project,client,policy,binding,work,parent):
    from . import automatic_candidate as native
    need(binding['repository']==policy['repository'] and binding['repository_id']==policy['repository_id'],
         'CROSS_REPOSITORY_APPROVED_RELEASE_DENIED')
    base='/repos/'+policy['repository'];release=client._api('GET',base+'/releases/'+str(binding['release_id']))
    need(release['id']==binding['release_id'] and release['tag_name']==binding['tag'],'APPROVED_RELEASE_ID_MISMATCH')
    need({a['name']:a['id'] for a in release['assets']}=={n:v['id'] for n,v in binding['assets'].items()},'APPROVED_ASSET_SET_CHANGED')
    pins={n:{k:v[k] for k in ('sha256','size')} for n,v in binding['assets'].items()}
    _download_all(client,release,pins,work)
    tag=client._api('GET',base+'/git/ref/tags/'+binding['tag'])
    need(tag['object']=={'type':'commit','sha':binding['implementation_revision'],**{k:v for k,v in tag['object'].items() if k not in ('type','sha')}},'INVALID_PUBLICATION_TAG')
    from .research_candidate_consumer import extracted_run
    root=Path(work)/'run'
    with extracted_run(Path(work)/'candidate.tar.gz',Path(work),{'archive':{'storage':{'asset_size':pins['candidate.tar.gz']['size']},'sha256':pins['candidate.tar.gz']['sha256']}}) as staged:
        shutil.copytree(staged,root)
    record=read_json(Path(work)/'admission.json')
    verified=native.verify(project,root,policy,record['candidate_id'],parent)
    need(set(record)=={'schema_version','kind','candidate_id','parent','policy_sha256','admission_sha256','implementation_revision','archive_sha256','notices_sha256'}
         and record['schema_version']==1 and record['kind']=='APPROVED_AUTOMATIC_CANDIDATE_V1'
         and record['implementation_revision']==binding['implementation_revision']
         and record['archive_sha256']==pins['candidate.tar.gz']['sha256']
         and record['notices_sha256']==pins['notices.zip']['sha256']
         and verified['eligible'] and record['policy_sha256']==policy['policy_sha256']
         and record['admission_sha256']==digest(verified['report'])
         and record['parent']==verified['parent'],'INVALID_APPROVED_ADMISSION')
    expected_path=Path(work)/'expected-notices.zip'
    expected=notices(project,root,policy,expected_path,record['candidate_id'])
    verify_notices(Path(work)/'notices.zip',expected)
    return verified,root
