"""Reviewed data-only Parent lineage. Authority comes from the trusted job/policy.

No generic Git proxy, code tree, ref deletion, force update, retry, or CLI exists.
The same R4 Git protocol handles reserve/consume/complete using explicit policy
bindings (config v2), never a fabricated per-run human Owner decision.
"""
from copy import deepcopy
import base64
import hashlib
import json
import re
from .corpus_snapshot import canonical, digest
from . import parent_authority_git_audit as audit
from .parent_authority_github_transport import GitHubAuditTransport, _NoRedirect
from .trusted_snapshot import repository_identity
import urllib.request

REF = 'refs/heads/ci-v2-authority-audit/derived-parent-state-v1'
MEMBERS = {'registry.json','lineage.json'}
MAX_GENERATIONS = 8


def need(ok, reason):
    if not ok: raise ValueError(reason)


def parse(raw):
    from .owner_manual_baseline_approval import _strict_json
    need(isinstance(raw, bytes) and len(raw) <= 128*1024,'OVERSIZED_DERIVED_STATE')
    value = _strict_json(raw.decode('utf-8'))
    need(canonical(value)+b'\n' == raw,'NONCANONICAL_DERIVED_STATE')
    return value


def serialize(value): return canonical(value)+b'\n'


class GitState:
    """Restricted Git DB client; mutation is exposed only as an exact append."""
    def __init__(self, repository, repository_id, token, *, writable=False):
        need(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repository) and
             type(repository_id) is int and repository_id>0 and isinstance(token,str)
             and bool(token) and not any(c.isspace() for c in token),'INVALID_STATE_TRANSPORT')
        self.repository,self.repository_id=repository,repository_id
        need(type(writable) is bool,'INVALID_WRITE_SCOPE')
        self._token,self._scope,self._requests=token,writable,0
        self._opener=urllib.request.build_opener(_NoRedirect())
        self._attempted=False;self._cache={}

    def _call(self,method,suffix,body=None):
        allowed = (method == 'GET' and (suffix == '' or suffix == '/git/ref/'+REF[5:]
            or re.fullmatch(r'/git/(commits|trees|blobs)/[0-9a-f]{40}',suffix))) or (
            self._scope and self._attempted and ((method=='POST' and suffix in ('/git/trees','/git/commits'))
                or (method=='PATCH' and suffix=='/git/refs/'+REF[5:] and body.get('force') is False)))
        need(allowed,'UNSUPPORTED_DERIVED_API_OPERATION')
        # Reuse bounded, no-redirect, sanitized authenticated R4 HTTP exchange.
        status,value=GitHubAuditTransport._exchange(self,method,'repos/'+self.repository+suffix,body)
        need(status==(201 if method=='POST' else 200),'DERIVED_API_REJECTED_OR_UNCERTAIN')
        return value

    def identity(self):
        value=self._call('GET','')
        need(repository_identity(value,self.repository,self.repository_id),'DERIVED_REPOSITORY_MISMATCH')

    def head(self):
        self.identity();value=self._call('GET','/git/ref/'+REF[5:])
        need(value.get('ref')==REF and value.get('object',{}).get('type')=='commit','INVALID_DERIVED_REF')
        sha=value['object']['sha'];need(audit._hash(sha,40),'INVALID_DERIVED_HEAD');return sha

    def read(self,sha):
        need(audit._hash(sha,40),'INVALID_STATE_COMMIT')
        if sha in self._cache:return deepcopy(self._cache[sha])
        commit=self._call('GET','/git/commits/'+sha)
        need(commit.get('sha')==sha and len(commit['parents'])<=1,'NONLINEAR_DERIVED_HISTORY')
        tree=self._call('GET','/git/trees/'+commit['tree']['sha'])
        need(tree.get('sha')==commit['tree']['sha'] and tree.get('truncated') is False
             and len(tree['tree'])==2 and {r['path'] for r in tree['tree']}==MEMBERS,'UNEXPECTED_STATE_TREE')
        content={}
        for row in tree['tree']:
            need(row['type']=='blob' and row['mode']=='100644' and row['size']<=128*1024,'UNSAFE_STATE_MEMBER')
            blob=self._call('GET','/git/blobs/'+row['sha'])
            need(blob.get('sha')==row['sha'] and blob.get('encoding')=='base64','INVALID_STATE_BLOB')
            raw=base64.b64decode(blob['content'],validate=False)
            need(len(raw)==row['size'] and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['sha'],'STATE_BLOB_IDENTITY_MISMATCH')
            content[row['path']]=parse(raw)
        result={'sha':sha,'parent':commit['parents'][0]['sha'] if commit['parents'] else None,**content}
        self._cache[sha]=result;return deepcopy(result)

    def append(self,expected,registry,lineage):
        need(self._scope and not self._attempted,'DERIVED_WRITE_NOT_AUTHORIZED_OR_RETRY')
        self._attempted=True  # Burn before *any* write; never retry uncertain objects/ref.
        need(self.head()==expected,'STALE_DERIVED_HEAD')
        tree_rows=[]
        for name,value in [('registry.json',registry),('lineage.json',lineage)]:
            raw=serialize(value);parse(raw)
            tree_rows.append({'path':name,'mode':'100644','type':'blob','content':raw.decode()})
        tree=self._call('POST','/git/trees',{'tree':tree_rows})
        need(audit._hash(tree.get('sha'),40),'INVALID_CREATED_STATE_TREE')
        commit=self._call('POST','/git/commits',{'message':'CI V2 derived Parent '+digest(lineage),
            'tree':tree['sha'],'parents':[expected]})
        sha=commit.get('sha');need(audit._hash(sha,40),'INVALID_CREATED_STATE_COMMIT')
        created=self.read(sha)
        need(created['parent']==expected and created['registry.json']==registry and created['lineage.json']==lineage,
             'CREATED_STATE_MISMATCH')
        # Sibling commits race safely: GitHub force=false rejects the loser.
        need(self.head()==expected,'STALE_DERIVED_HEAD')
        value=self._call('PATCH','/git/refs/'+REF[5:],{'sha':sha,'force':False})
        need(value.get('object',{}).get('sha')==sha and self.head()==sha,'DERIVED_WRITE_OUTCOME_UNCERTAIN')
        observed=self.read(sha)
        need(observed['registry.json']==registry and observed['lineage.json']==lineage
             and observed['parent']==expected,'DERIVED_READBACK_MISMATCH')
        return sha


def genesis(root_registry,policy):
    need(type(root_registry.get('schema_version')) is int and root_registry['schema_version']==2,'INVALID_ROOT_REGISTRY')
    need(digest(root_registry)==policy['root_registry_canonical_sha256'],'ROOT_REGISTRY_MISMATCH')
    return {'schema_version':1,'kind':'DERIVED_PARENT_LINEAGE_V1',
        'root_revision':policy['root_revision'],'root_registry_sha256':policy['root_registry_sha256'],
        'root_policy_sha256':policy['scope_sha256'],'entries':[]}


def consume(store,policy,root_registry,verify_entry):
    """Every entry is re-verified by the actual scientific/release adapter.

    verify_entry is an internal typed transport verifier, not a JSON PASS input.
    The production entry constructs it; no Workflow input names a provider.
    """
    head=store.head();cursor=head;reverse=[];seen=set()
    for _ in range(MAX_GENERATIONS+1):
        need(cursor not in seen,'DERIVED_HISTORY_CYCLE');seen.add(cursor)
        row=store.read(cursor);reverse.append(row)
        if cursor==policy['genesis_sha']:break
        need(row['parent'] is not None,'UNANCHORED_DERIVED_STATE');cursor=row['parent']
    else:raise ValueError('DERIVED_HISTORY_BOUND_EXCEEDED')
    need(len(reverse)-1<=policy['max_generations'],'DERIVED_GENERATION_LIMIT')
    rows=list(reversed(reverse));base=genesis(root_registry,policy)
    need(rows[0]['parent'] is None and rows[0]['lineage.json']==base
         and rows[0]['registry.json']==root_registry,'DERIVED_GENESIS_MISMATCH')
    previous=rows[0];used=set();selected=policy['initial_parent_key']
    for row in rows[1:]:
        line=row['lineage.json'];old=previous['lineage.json']
        need(set(line)==set(base) and {k:v for k,v in line.items() if k!='entries'}=={k:v for k,v in base.items() if k!='entries'}
             and line['entries'][:-1]==old['entries'] and len(line['entries'])==len(old['entries'])+1,'LINEAGE_REWRITE')
        entry=line['entries'][-1]
        need(entry['previous_state_sha']==previous['sha'] and entry['previous_parent_key']==selected
             and entry['transition_id'] not in used,'STALE_OR_REPLAYED_PARENT_TRANSITION')
        key=entry['parent_key'];new=row['registry.json'];prior=previous['registry.json']
        need(key not in prior['baselines'] and set(new)==set(prior)
             and {k:v for k,v in new.items() if k!='baselines'}=={k:v for k,v in prior.items() if k!='baselines'}
             and set(new['baselines'])==set(prior['baselines'])|{key}
             and all(new['baselines'][k]==v for k,v in prior['baselines'].items()),'REGISTRY_REWRITE')
        need(entry['old_registry_sha256']==hashlib.sha256(serialize(prior)).hexdigest()
             and entry['new_registry_sha256']==hashlib.sha256(serialize(new)).hexdigest(),'REGISTRY_TRANSITION_PIN_MISMATCH')
        need(verify_entry(entry,new['baselines'][key],previous,row['sha']) is True,'INVALID_ADMITTED_PARENT')
        used.add(entry['transition_id']);selected=key;previous=row
    need(store.head()==head,'DERIVED_STATE_CHANGED_DURING_READ')
    return {'head':head,'registry':previous['registry.json'],'lineage':previous['lineage.json'],
            'selected_parent':selected,'generation':len(previous['lineage.json']['entries'])}


def advance(store,view,key,entry,receipt,protocol,revalidate):
    """Use existing R4 reserve/consume/complete. No human decision is fabricated.

    The consumed audit must already bind the exact new Registry hash. A failure
    after consumption remains burned; unknown writes are only read-reconciled.
    """
    result={'status':'BLOCKED','retry':False,'authoritative_default_registry_applied':False}
    try:
        need(store.head()==view['head'],'STALE_PARENT')
        need(view['generation']<MAX_GENERATIONS,'DERIVED_GENERATION_LIMIT')
        need(key not in view['registry']['baselines'],'DUPLICATE_PARENT')
        updated=deepcopy(view['registry']);updated['baselines'][key]=deepcopy(entry)
        old=hashlib.sha256(serialize(view['registry'])).hexdigest();new=hashlib.sha256(serialize(updated)).hexdigest()
        need(receipt['old_registry_sha256']==old and receipt['new_registry_sha256']==new
             and receipt['previous_state_sha']==view['head'] and receipt['parent_key']==key,'UNBOUND_ADVANCEMENT')
        need(protocol._binding['decision']['old_registry_sha256']==old and
             protocol._binding['decision']['result_registry_sha256']==new,'UNBOUND_TRANSACTION')
        need(receipt['transition_id']==protocol._binding['decision']['transaction_id'],'TRANSACTION_ID_MISMATCH')
        need(receipt['previous_parent_key']==view['selected_parent'],'PREVIOUS_PARENT_MISMATCH')
        revalidate()
        reserved=protocol.reserve();need(reserved.get('status')=='RESERVED','RESERVATION_FAILED')
        need(protocol.inspect()['status']=='RESERVED_REVIEW_REQUIRED','RESERVATION_READBACK_FAILED')
        revalidate();consumed=protocol.consume();need(consumed.get('status')=='CONSUMED_OFFLINE','CONSUMPTION_FAILED')
        need(protocol.inspect()['status']=='CONSUMED_REVIEW_REQUIRED','CONSUMPTION_READBACK_FAILED')
        revalidate();need(store.head()==view['head'],'STALE_PARENT_AFTER_CONSUMPTION')
        # The data commit binds a durable consumed claim. Completion is appended
        # afterwards; consumers require its independent audit readback as well.
        item=deepcopy(receipt);item['audit_consumption_head']=protocol.inspect()['head']
        lineage=deepcopy(view['lineage']);lineage['entries'].append(item)
        state_sha=store.append(view['head'],updated,lineage)
        revalidate();completion={'operation':'AUTOMATIC_PARENT_ADVANCEMENT_V1','state_sha':state_sha,
            'registry_sha256':new,'transaction_id':item['transition_id']}
        done=protocol.complete(serialize(updated),{'status':'COMPLETED','scope':'DERIVED_DATA_REF_ONLY',
            'result_registry_sha256':new,'receipt':completion})
        need(done.get('status')=='COMPLETED_OFFLINE' and protocol.inspect()['status']=='COMPLETED_REVIEW_REQUIRED','COMPLETION_NOT_VERIFIED')
        revalidate()
        need(store.head()==state_sha,'DERIVED_HEAD_CHANGED_AFTER_COMPLETION')
        checked=store.read(state_sha)
        need(checked['registry.json']==updated and checked['lineage.json']==lineage,'FINAL_DERIVED_READBACK_MISMATCH')
        return {**result,'status':'PARENT_ADVANCED','state_sha':state_sha,'completion':completion}
    except Exception:
        try:result['observed_state_sha']=store.head();result['audit_state']=protocol.inspect()['status']
        except Exception:pass
        result['status']='STATE_UNCERTAIN';return result
