"""Closed Owner Subject v2; fresh local-origin verification, never approval.

Structural validation is usable offline by audit recovery. Only prepare() runs
the remote/content verifiers. Neither accepts a saved verification receipt as
input or supplies a trusted workflow context.
"""
from pathlib import Path
import re
import shutil

from . import local_candidate_verification as remote, local_candidate_transport as transport
from . import trusted_baseline_registration as registration, parent_r2_anchor as anchor
from .corpus_snapshot import canonical, digest, file_digest
from .published_candidate_verification import _json, ANCHOR_FIELDS

FIELDS = {'schema_version', 'purpose', 'registry_key', 'registry_entry',
    'registry_entry_sha256', 'expected_old_registry_sha256', 'approval_policy_sha256',
    'request_sha256', 'trust_domain', 'local_evidence', 'candidate', 'baseline',
    'scientific', 'parent_r2_anchor', 'execution', 'production_promotion'}
CANDIDATE = {'candidate_id', 'parent_id', 'corpus_sha256', 'generation', 'upstreams',
    'source_state', 'build_fingerprint', 'orchestration_fingerprint', 'benchmark_sha256',
    'quality_status', 'q1_status'}
BASELINE = {'baseline_id', 'reference_sha256', 'p4_1_verification', 'q1_status'}
DOMAIN = {'repository', 'repository_id', 'default_branch', 'workflow_path', 'registry_path'}
SCIENCE = {'descriptor', 'full_parity', 'original_parent_anchor_status',
    'baseline_anchor_status', 'quality_sha256', 'r2_contract_sha256',
    'candidate_rows_sha256', 'approval_manifest_sha256', 'approval_policy_sha256',
    'notices_verification', 'P8', 'full_snapshot_manifest_sha256', 'full_parity_sha256'}


class SubjectError(ValueError):
    pass


def need(ok, reason='INVALID_LOCAL_REGISTRATION_SUBJECT'):
    if not ok:
        raise SubjectError(reason)


def validate(s):
    """Validate a v2 subject without API, files, environment identity or authority."""
    try:
        need(isinstance(s, dict) and set(s) == FIELDS
             and type(s['schema_version']) is int and s['schema_version'] == 2)
        need(s['purpose'] == 'TRUSTED_RESEARCH_PARENT_REGISTRATION'
             and s['execution'] == 'NO_FRESH_REPLAY' and s['production_promotion'] == 'NOT_AUTHORIZED')
        need(isinstance(s['registry_key'], str) and re.fullmatch('[a-z0-9][a-z0-9_-]{0,63}', s['registry_key']))
        need(all(transport.l1._sha(s[k]) for k in ('registry_entry_sha256',
             'expected_old_registry_sha256', 'approval_policy_sha256', 'request_sha256')))
        entry = s['registry_entry']; ref = entry['reference']
        need(registration.entry_kind(entry) == registration.REGISTRATION_ONLY
             and digest(entry) == s['registry_entry_sha256'])
        need(ref['schema_version'] == 3 and entry['expected_reference_sha256'] == digest(ref))
        remote.trusted.validate_reference(ref, digest(ref))  # offline v3 binding, no locator runtime gate
        c, b, sci, dom, local = (s[k] for k in ('candidate','baseline','scientific','trust_domain','local_evidence'))
        need(set(c) == CANDIDATE and set(b) == BASELINE and set(sci) == SCIENCE and set(dom) == DOMAIN)
        need(set(local) == remote.LOCAL_FIELDS and set(local['transport']) == remote.TRANSPORT_FIELDS
             and type(local['transport']['schema_version']) is int and local['transport']['schema_version'] == 1)
        t = local['transport']; d = sci['descriptor']
        need(set(d) == transport.l1.FIELDS and type(d['schema_version']) is int and d['schema_version'] == 1)
        need(all(transport.l1._sha(d[k]) for k in transport.l1.HASH_FIELDS)
             and all(isinstance(d[k], str) and re.fullmatch('sha256-[0-9a-f]{64}',d[k]) for k in transport.l1.ID_FIELDS))
        need(set(d['execution_records']) == transport.l1.RECORD_FILES
             and all(transport.l1._sha(v) for v in d['execution_records'].values()))
        need(d['evidence_origin'] == local['evidence_origin'] == t['evidence_origin'] == 'LOCAL_RESEARCH_EXECUTION'
             and d['hosted_validation'] == local['hosted_validation'] == t['hosted_validation'] == 'HOSTED_NOT_RUN'
             and t['kind'] == 'LOCAL_RESEARCH_EVIDENCE_TRANSPORT')
        need(digest(t) == local['transport_sha256'] and transport.l1._sha(local['transport_sha256']))
        need(all(t[k] == local[k] for k in ('candidate_id','baseline_id','corpus_sha256','descriptor_sha256','archive_sha256')))
        need(all(transport.l1._sha(t[k]) for k in ('archive_sha256','descriptor_sha256','manifest_sha256','reference_sha256','corpus_sha256')))
        need(isinstance(t['publication_commit'], str) and re.fullmatch('[0-9a-f]{40}',t['publication_commit']))
        need(type(t['archive_size']) is int and 0 < t['archive_size'] <= transport.LIMIT
             and t['archive_size'] == t['storage']['asset_size'])
        need(isinstance(dom['repository'], str) and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',dom['repository'])
             and type(dom['repository_id']) is int and dom['repository_id'] > 0
             and all(isinstance(dom[k],str) and dom[k] for k in ('default_branch','workflow_path','registry_path')))
        for storage in (t['storage'],ref['storage'],ref['parent_rows_storage'],ref['notices']['storage']):
            need(set(storage) == remote.STORAGE_FIELDS and storage['kind'] == 'GITHUB_PRIVATE_RELEASE_ASSET'
                 and storage['repository'] == dom['repository'] and storage['repository_id'] == dom['repository_id']
                 and all(type(storage[k]) is int and storage[k] > 0 for k in ('repository_id','release_id','asset_id','asset_size'))
                 and storage['asset_size'] <= transport.LIMIT and storage['immutable_required'] is True
                 and storage['tag'].lower() not in ('latest','main','master')
                 and all(isinstance(storage[k],str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}', storage[k]) for k in ('tag','asset_name')))
        need(t['storage']['release_id'] != ref['storage']['release_id'])
        need(type(c['generation']) is int and type(d['generation']) is int
             and c['generation'] > 0 and c['generation'] == d['generation'])
        need(set(c['upstreams']) == {'SPHinXsys','SPHinXsim'}
             and all(isinstance(v,str) and re.fullmatch('[0-9a-f]{40}',v) for v in c['upstreams'].values()))
        need(all(c[k] == d[k] for k in ('candidate_id','parent_id','corpus_sha256','upstreams','source_state',
             'build_fingerprint','orchestration_fingerprint','benchmark_sha256')))
        need(all(ref[k] == c[k] for k in ('corpus_sha256','upstreams','source_state','build_fingerprint'))
             and c['candidate_id'] == t['candidate_id'] and c['parent_id'] == t['parent_id']
             and c['corpus_sha256'] == t['corpus_sha256'])
        need(b['baseline_id'] == d['baseline_id'] == t['baseline_id'] == ref['node_id']
             and b['reference_sha256'] == d['reference_sha256'] == t['reference_sha256'] == digest(ref)
             and b['p4_1_verification'] == 'P4_1_VERIFIED')
        need(c['quality_status'] == 'QUALITY_REVIEW_REQUIRED'
             and c['q1_status'] == 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR'
             and b['q1_status'] in (c['q1_status'],'NOT_RECORDED_IN_EXISTING_BASELINE_QUALITY_SCHEMA'))
        parity=sci['full_parity']
        need(set(parity)=={'status','candidate_id','comparisons','full_reference_independently_built'}
             and parity['full_reference_independently_built'] is True
             and set(parity['comparisons'])==set(transport.l1.provenance.PARITY_FILES)
             and all(set(v)=={'sha256','exact_bytes_equal'} and v['exact_bytes_equal'] is True
                     and transport.l1._sha(v['sha256']) for v in parity['comparisons'].values())
             and transport.l1._sha(sci['full_snapshot_manifest_sha256'])
             and transport.l1._sha(sci['full_parity_sha256']))
        need(sci['full_parity']['status'] == 'PARITY_PASS'
             and sci['full_parity']['candidate_id'] == c['candidate_id']
             and sci['original_parent_anchor_status'] in ('QUALIFIED','PINNED_ANCHOR_INSPECTED')
             and sci['baseline_anchor_status'] == 'QUALIFIED' and sci['P8'] == 'BLOCKED')
        need(all(sci[k] == d[k] for k in ('quality_sha256','r2_contract_sha256',
             'candidate_rows_sha256','approval_manifest_sha256','approval_policy_sha256')))
        a = s['parent_r2_anchor']
        need(set(a) == ANCHOR_FIELDS
             and all(transport.l1._sha(a[k]) for k in ('parent_corpus_sha256','build_fingerprint',
                 'benchmark_sha256','quality_policy_sha256','parent_rows_sha256','historical_rows_sha256','metrics_sha256'))
             and isinstance(a['R2_fingerprint'],dict) and a['R2_fingerprint']
             and a['candidate_id'] == c['candidate_id']
             and a['baseline_id'] == b['baseline_id'] and a['parent_corpus_sha256'] == c['corpus_sha256']
             and a['parent_rows_sha256'] == d['candidate_rows_sha256'] == ref['parent_rows_sha256']
             and all(a[k] == c[k] for k in ('source_state','upstreams','build_fingerprint','benchmark_sha256'))
             and digest(a['R2_fingerprint']) == d['r2_contract_sha256'])
        n = sci['notices_verification']
        need(set(n) == {'schema_version','status','baseline_id','parent_transport_sha256','reference_sha256',
             'notices_sha256','storage','internal_manifest_sha256','production_promotion'}
             and type(n['schema_version']) is int and n['schema_version']==1
             and n['status'] == 'NOTICES_VERIFIED' and n['baseline_id'] == ref['node_id']
             and n['reference_sha256'] == digest(ref) and n['parent_transport_sha256'] == ref['transport_sha256']
             and n['storage'] == ref['notices']['storage'] and n['notices_sha256'] == ref['notices']['sha256']
             and transport.l1._sha(n['internal_manifest_sha256']) and n['production_promotion'] == 'NOT_AUTHORIZED')
        return s
    except SubjectError:
        raise
    except Exception:
        raise SubjectError('INVALID_LOCAL_REGISTRATION_SUBJECT') from None


def prepare(project, registry_path, request_path, request_sha256, *, token=None):
    """Fresh pinned request + remote/L1 verification, returning an unsigned subject."""
    from scripts import register_trusted_baseline as cli
    from . import owner_manual_baseline_approval as owner
    need(Path(project).resolve() == cli.PROJECT.resolve(), 'REQUEST_PROJECT_MISMATCH')
    request, policy_path = cli.load_request(request_path, request_sha256)
    need(request['schema_version'] == 3, 'LOCAL_REQUEST_REQUIRED')
    policy = owner._policy(project, policy_path, request['approval_policy_sha256'])
    need(Path(registry_path).resolve() == (Path(project)/policy['registry_path']).resolve(), 'REGISTRY_POLICY_MISMATCH')
    need(file_digest(registry_path) == request['expected_registry_sha256'], 'STALE_REGISTRY')
    ref = request['proposed_entry']['reference']; work = None
    try:
        receipt = remote.verify(project, request['local_evidence'], ref, request['expected_reference_sha256'],
            expected_repository=policy['repository'], expected_repository_id=policy['repository_id'], token=token)
        work = Path(receipt['retained_directory'])
        d = transport.l1.load_descriptor(work/'evidence/descriptor.json',request['local_evidence']['descriptor_sha256'])
        # Reinspect the underlying bytes, never authorize from verification.json.
        checked = transport.verify_extracted(project,work/'evidence',work/'baseline',work/'reference.json',
            expected_manifest_sha256=request['local_evidence']['transport']['manifest_sha256'],
            expected_descriptor_sha256=request['local_evidence']['descriptor_sha256'])
        preflight = registration.prepare(project,registry_path,request['registry_key'],work/'baseline',
            request['proposed_entry'],expected_reference_sha256=request['expected_reference_sha256'],
            expected_workflow_repository=policy['repository'],expected_workflow_repository_id=policy['repository_id'])
        need(preflight['blocking_reasons'] == ['INDEPENDENT_REGISTRATION_AUTHORITY_NOT_CONFIGURED']
             and preflight['P4_1_verification'] == 'P4_1_VERIFIED','P4_1_PREFLIGHT_FAILED')
        qualified = anchor.qualify_parent_anchor(project,work/'baseline',ref,request['expected_reference_sha256'],
            work/'parent-r2.json',fresh_replay=False)
        transport.l1._check_anchor(qualified,'QUALIFIED')
        candidate = {k:d[k] for k in ('candidate_id','parent_id','corpus_sha256','generation','upstreams',
            'source_state','build_fingerprint','orchestration_fingerprint','benchmark_sha256')}
        candidate.update(quality_status=checked['quality'],q1_status=checked['Q1'])
        subject = dict(schema_version=2,purpose='TRUSTED_RESEARCH_PARENT_REGISTRATION',
            registry_key=request['registry_key'],registry_entry=request['proposed_entry'],
            registry_entry_sha256=digest(request['proposed_entry']),expected_old_registry_sha256=request['expected_registry_sha256'],
            approval_policy_sha256=request['approval_policy_sha256'],request_sha256=request_sha256,
            trust_domain={k:policy[k] for k in DOMAIN},local_evidence=request['local_evidence'],candidate=candidate,
            baseline=dict(baseline_id=d['baseline_id'],reference_sha256=request['expected_reference_sha256'],
                p4_1_verification=preflight['P4_1_verification'],q1_status=preflight['q1_status']),
            scientific=dict(descriptor=d,full_parity=_json((work/'evidence/run/parity.json').read_bytes()),
                full_snapshot_manifest_sha256=file_digest(work/'evidence/run/full/manifest.json'),
                full_parity_sha256=file_digest(work/'evidence/run/parity.json'),
                original_parent_anchor_status=checked['original_parent_anchor_status'],baseline_anchor_status=checked['baseline_anchor_status'],
                **{k:d[k] for k in ('quality_sha256','r2_contract_sha256','candidate_rows_sha256','approval_manifest_sha256','approval_policy_sha256')},
                notices_verification=remote.trusted.verify_notices(ref,request['expected_reference_sha256'],work/'notices.zip'),P8='BLOCKED'),
            parent_r2_anchor=qualified['bindings'],execution='NO_FRESH_REPLAY',production_promotion='NOT_AUTHORIZED')
        validate(subject)
        # Preserve request and policy bytes for the later versioned audit bundle.
        raw_request = Path(request_path).read_bytes(); raw_policy = policy_path.read_bytes()
        need(remote.transport._hash(raw_request) == request_sha256
             and remote.transport._hash(raw_policy) == request['approval_policy_sha256'],'INPUT_CHANGED')
        return dict(status='EVIDENCE_VERIFIED',execution='NO_FRESH_REPLAY',registration_subject=subject,
            registration_subject_sha256=digest(subject),retained_directory=str(work),
            request_text=raw_request.decode(),policy_text=raw_policy.decode())
    except Exception:
        if work is not None:shutil.rmtree(work)
        raise
