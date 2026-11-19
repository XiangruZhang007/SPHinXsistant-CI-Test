"""Read-only post-publication verification; no authorization or registry writes.

Expected pins are supplied by the trusted caller, never learned from downloads.
All downloaded/extracted bytes are owned temporary files. Stored replay evidence
is inspected with NO_FRESH_REPLAY; no corpus or retrieval execution occurs.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile

from . import candidate_release_archive as archive, trusted_snapshot as transport
from . import trusted_baseline_registration as registration, parent_r2_anchor as anchor
from .corpus_snapshot import canonical, digest, file_digest

ASSETS = {'candidate.tar.gz', 'research-evidence.tar.gz', 'release-manifest.json'}
ANCHOR_FIELDS = {'baseline_id', 'candidate_id', 'parent_corpus_sha256', 'upstreams',
                 'source_state', 'build_fingerprint', 'benchmark_sha256', 'R2_fingerprint',
                 'quality_policy_sha256', 'parent_rows_sha256', 'historical_rows_sha256',
                 'metrics_sha256'}
LIMIT = 4 * 1024**2


class VerificationError(ValueError):
    """Bounded diagnostic code, without credentials or remote response bodies."""


def _need(condition, code):
    if not condition:
        raise VerificationError(code)


def _sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    canonical(value)  # Reject NaN and infinities as well as duplicate fields.
    return value


def _read(path):
    path = Path(path)
    _need(path.is_file() and not path.is_symlink(), 'MISSING_OR_UNSAFE_EVIDENCE')
    return _json(path.read_bytes())


def _release_contract(reference, expected_sha):
    _need(_sha(expected_sha) and digest(reference) == expected_sha,
          'CANDIDATE_RELEASE_REFERENCE_PIN_MISMATCH')
    _need(set(reference) == {'schema_version', 'assets'}
          and type(reference['schema_version']) is int and reference['schema_version'] == 1
          and isinstance(reference['assets'], dict) and set(reference['assets']) == ASSETS,
          'INVALID_CANDIDATE_RELEASE_REFERENCE')
    shared, ids = None, set()
    for name, item in reference['assets'].items():
        _need(isinstance(item, dict) and set(item) == {'storage', 'sha256'}
              and _sha(item['sha256']), 'INVALID_ASSET_PIN')
        storage = item['storage']
        _need(storage.get('kind') == transport.PRIVATE_RELEASE_KIND,
              'PRIVATE_CANDIDATE_RELEASE_REQUIRED')
        transport.release_locator(storage)
        _need(storage['asset_name'] == name, 'ASSET_NAME_MISMATCH')
        identity = tuple(storage[k] for k in ('repository', 'repository_id', 'release_id', 'tag'))
        _need(shared is None or shared == identity, 'CONFLICTING_RELEASE_IDENTITIES')
        shared = identity
        _need(storage['asset_id'] not in ids, 'DUPLICATE_ASSET_ID')
        ids.add(storage['asset_id'])
        if name == 'release-manifest.json':
            _need(storage['asset_size'] <= LIMIT, 'OVERSIZED_MANIFEST')
    return reference['assets']['release-manifest.json']['storage']


def _exact_release_assets(reference, storage, token):
    # download() verifies each asset independently. Also reject undeclared assets
    # in the Release, rather than trusting three successful membership checks.
    url = transport.release_locator(storage) + '/releases/' + str(storage['release_id'])
    with transport._request(url, token=token) as stream:
        raw = stream.read(LIMIT + 1)
    _need(len(raw) <= LIMIT, 'OVERSIZED_RELEASE_METADATA')
    release = _json(raw)
    _need(release.get('id') == storage['release_id'] and release.get('immutable') is True
          and release.get('draft') is False and release.get('tag_name') == storage['tag'],
          'RELEASE_IDENTITY_MISMATCH')
    expected = {(v['storage']['asset_id'], name, v['storage']['asset_size'])
                for name, v in reference['assets'].items()}
    assets = release.get('assets')
    _need(isinstance(assets, list) and len(assets) == 3
          and all(isinstance(a, dict) and a.get('state') == 'uploaded' for a in assets)
          and {(a.get('id'), a.get('name'), a.get('size')) for a in assets} == expected,
          'RELEASE_ASSET_SET_MISMATCH')


def _candidate(reference, expected_sha, work, token):
    storage = _release_contract(reference, expected_sha)
    _need(isinstance(token, str) and token and not any(c.isspace() for c in token),
          'PRIVATE_RELEASE_TOKEN_REQUIRED')
    for name, item in reference['assets'].items():
        transport.download(item['storage'], work / name, item['sha256'], token=token)
        _need(file_digest(work / name) == item['sha256']
              and (work / name).stat().st_size == item['storage']['asset_size'],
              'DOWNLOADED_ASSET_MISMATCH')
    _exact_release_assets(reference, storage, token)
    manifest = _read(work / 'release-manifest.json')
    transport.extract_regular(work / 'research-evidence.tar.gz', work / 'evidence',
                              reference['assets']['research-evidence.tar.gz']['sha256'])
    evidence = work / 'evidence'
    _need({p.name for p in evidence.iterdir()} == {'plan.json', 'run'},
          'UNEXPECTED_EVIDENCE_ENTRIES')
    shutil.copyfile(work / 'candidate.tar.gz', evidence / 'candidate.tar.gz')
    verified = archive.validate_artifact(
        evidence, run_id=manifest['run_id'], attempt=manifest['run_attempt'],
        repository_id=storage['repository_id'], repository=storage['repository'],
        head_sha=manifest['workflow_commit'], artifact_id=manifest['actions_artifact_id'],
        artifact_digest=manifest['actions_artifact_digest'])
    verified['assets'] = {
        name: {'size_bytes': item['storage']['asset_size'], 'sha256': item['sha256']}
        for name, item in reference['assets'].items() if name != 'release-manifest.json'}
    _need(canonical(manifest) == canonical(verified), 'RELEASE_MANIFEST_EVIDENCE_MISMATCH')
    return verified, evidence


def verify(project, registry_path, registry_key, proposed_entry, *,
           candidate_release, expected_candidate_release_sha256,
           expected_reference_sha256, expected_build_policy_sha256=None,
           expected_registry_sha256, approval_policy_sha256, token=None):
    """Return verified evidence and an unsigned future approval subject.

    No Owner verification is performed here. Success is evidence verification,
    never eligibility or authorization for a future Candidate build.
    Failures raise VerificationError. This API has no simulation/bypass option.
    """
    phase = 'INPUT_VALIDATION_FAILED'
    try:
        project, registry_path = Path(project), Path(registry_path)
        # Freeze caller data so later mutations cannot change the returned subject.
        proposed_entry = _json(canonical(proposed_entry))
        candidate_release = _json(canonical(candidate_release))
        _need(all(_sha(v) for v in (expected_candidate_release_sha256,
              expected_reference_sha256,
              expected_registry_sha256, approval_policy_sha256)), 'INVALID_INDEPENDENT_PIN')
        kind = registration.validate_build_policy_pin(proposed_entry, expected_build_policy_sha256)
        _read(registry_path)
        registry_raw = registry_path.read_bytes()
        _need(hashlib.sha256(registry_raw).hexdigest() == expected_registry_sha256,
              'STALE_REGISTRY')
        ref = proposed_entry['reference']
        _need(proposed_entry['expected_reference_sha256'] == expected_reference_sha256,
              'ENTRY_PIN_MISMATCH')
        transport.validate_reference(ref, expected_reference_sha256, remote=True)
        _need(ref['package_format'] == 'schema2-research-baseline', 'P4_1_BASELINE_REQUIRED')
        with tempfile.TemporaryDirectory(prefix='candidate-registration-verification-') as tmp:
            work = Path(tmp)
            phase = 'CANDIDATE_RELEASE_VERIFICATION_FAILED'
            manifest, evidence = _candidate(candidate_release,
                expected_candidate_release_sha256, work, token)
            phase = 'BASELINE_VERIFICATION_FAILED'
            if ref['schema_version'] == 3:
                from .local_candidate_verification import restore_delivery
                restore_delivery(project, ref, expected_reference_sha256, work,
                                 token=token, stem='baseline')
                shutil.copyfile(work / 'baseline-r2.json', work / 'parent-r2.json')
            else:
                transport.download(ref['storage'], work / 'baseline.tar.gz',
                                   ref['transport_sha256'], token=token)
                transport.restore(project, work / 'baseline.tar.gz', work / 'baseline',
                                  ref, expected_reference_sha256)
                transport.download(ref['parent_rows_storage'], work / 'parent-r2.json',
                                   ref['parent_rows_sha256'], token=token)
            preflight = registration.prepare(project, registry_path, registry_key,
                work / 'baseline', proposed_entry,
                expected_reference_sha256=expected_reference_sha256,
                expected_build_policy_sha256=expected_build_policy_sha256,
                expected_workflow_repository=manifest['repository'],
                expected_workflow_repository_id=manifest['repository_id'])
            _need(preflight.get('blocking_reasons') ==
                  ['INDEPENDENT_REGISTRATION_AUTHORITY_NOT_CONFIGURED']
                  and preflight.get('P4_1_verification') == 'P4_1_VERIFIED',
                  'P4_1_PREFLIGHT_FAILED')
            phase = 'PARENT_R2_ANCHOR_VERIFICATION_FAILED'
            qualified = anchor.qualify_parent_anchor(project, work / 'baseline', ref,
                expected_reference_sha256, work / 'parent-r2.json', fresh_replay=False)
            _need(qualified.get('status') == 'QUALIFIED'
                  and qualified.get('execution') == 'NO_FRESH_REPLAY'
                  and qualified.get('controlled_fixture') is False
                  and qualified.get('production_promotion') == 'NOT_AUTHORIZED'
                  and qualified.get('quality_acceptance') == 'NOT_GRANTED',
                  'PARENT_R2_ANCHOR_NOT_QUALIFIED')
            phase = 'CANDIDATE_BASELINE_BINDING_FAILED'
            bindings = qualified['bindings']
            _need(isinstance(bindings, dict) and set(bindings) == ANCHOR_FIELDS
                  and all(_sha(bindings[k]) for k in ('parent_corpus_sha256', 'build_fingerprint',
                      'benchmark_sha256', 'quality_policy_sha256', 'parent_rows_sha256',
                      'historical_rows_sha256', 'metrics_sha256'))
                  and isinstance(bindings['R2_fingerprint'], dict) and bindings['R2_fingerprint'],
                  'INCOMPLETE_PARENT_R2_BINDINGS')
            _need(preflight['candidate_id'] == bindings['candidate_id'] == manifest['candidate_id']
                  and preflight['baseline_id'] == bindings['baseline_id'] == ref['node_id']
                  and preflight['generation'] == manifest['generation'],
                  'CANDIDATE_BASELINE_IDENTITY_MISMATCH')
            for name in ('corpus_sha256', 'source_state', 'upstreams', 'build_fingerprint'):
                anchor_name = 'parent_corpus_sha256' if name == 'corpus_sha256' else name
                _need(manifest[name] == ref[name] == bindings[anchor_name],
                      'CANDIDATE_BASELINE_PROVENANCE_MISMATCH')
            metadata = _read(work / 'baseline/upstream-candidate.json')
            _need(metadata == _read(evidence / 'run/candidate/upstream-candidate.json'),
                  'ORIGINAL_CANDIDATE_METADATA_MISMATCH')
            _need(file_digest(work / 'baseline/corpus.jsonl') == manifest['corpus_sha256'],
                  'BASELINE_CORPUS_MISMATCH')
            _need(bindings['benchmark_sha256'] == manifest['benchmark_sha256']
                  and bindings['parent_rows_sha256'] == ref['parent_rows_sha256']
                  == file_digest(evidence / 'run/quality/incremental-raw-results.json'),
                  'R2_EVIDENCE_BINDING_MISMATCH')
            _need(preflight['quality_status'] == manifest['quality_status'],
                  'QUALITY_STATUS_MISMATCH')
            baseline_q1 = preflight['q1_status']
            _need(baseline_q1 == 'NOT_RECORDED_IN_EXISTING_BASELINE_QUALITY_SCHEMA'
                  or baseline_q1 == manifest['q1_status'], 'Q1_STATUS_MISMATCH')
            subject = {
                'schema_version': 1, 'purpose': 'TRUSTED_RESEARCH_PARENT_REGISTRATION',
                'registry_key': registry_key, 'registry_entry': proposed_entry,
                'registry_entry_sha256': digest(proposed_entry),
                'expected_old_registry_sha256': expected_registry_sha256,
                'approval_policy_sha256': approval_policy_sha256,
                'candidate_release': candidate_release,
                'candidate_release_reference_sha256': expected_candidate_release_sha256,
                'candidate': {k: manifest[k] for k in ('candidate_id', 'corpus_sha256',
                    'source_state', 'generation', 'upstreams', 'parent_id', 'build_fingerprint',
                    'benchmark_sha256', 'quality_status', 'q1_status')},
                'baseline': {'baseline_id': ref['node_id'],
                    'reference_sha256': expected_reference_sha256,
                    'p4_1_verification': preflight['P4_1_verification'],
                    'q1_status': baseline_q1},
                'parent_r2_anchor': bindings,
                'execution': 'NO_FRESH_REPLAY',
                'production_promotion': 'NOT_AUTHORIZED',
            }
            _need(registry_path.read_bytes() == registry_raw, 'REGISTRY_CHANGED_DURING_VERIFICATION')
            # Recheck the external build policy after qualification as prepare()
            # checked it earlier. No volatile temporary paths enter the subject.
            if kind == registration.LEGACY_BUILD_BOUND:
                from .corpus_snapshot import checked_file
                _need(file_digest(checked_file(project, proposed_entry['build_policy_path']))
                      == expected_build_policy_sha256, 'BUILD_POLICY_CHANGED_DURING_VERIFICATION')
            return {'status': 'EVIDENCE_VERIFIED', 'execution': 'NO_FRESH_REPLAY',
                'registration_subject': subject, 'registration_subject_sha256': digest(subject),
                'authorization': 'NOT_VERIFIED', 'registration': 'NOT_PERFORMED',
                'registry_modified': False, 'production_promotion': 'NOT_AUTHORIZED'}
    except VerificationError:
        raise
    except Exception:
        # Do not propagate remote bodies, token-bearing URLs, or source paths.
        raise VerificationError(phase) from None
