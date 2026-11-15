"""Explicit local research Parent selection for the existing schema-2 builder.

The registry is operator-controlled and its selected reference is independently
pinned by the caller. No latest lookup, fallback, approval, transport, retrieval
execution or application activation occurs here. Full research snapshots, not
P9's corpus-only directories, are required. Existing P4.1 rules are unchanged.
"""
from pathlib import Path
import shutil

from . import ci_v2_research as c, trusted_snapshot as trust, upstream_provenance as u
from .corpus_snapshot import checked_file, digest, file_digest, read_json, write_json


def select_parent(project, registry_path, key, expected_reference_sha256, parent,
                  *, controlled=False):
    """Verify one explicit local Parent; controlled fixtures are library tests only."""
    registry_path, parent = Path(registry_path), Path(parent)
    c.need(not parent.is_symlink() and parent.is_dir(), 'INVALID_BASELINE', 'Missing or symlink Parent')
    c.need(not registry_path.resolve().is_relative_to(parent.resolve()),
           'INVALID_REFERENCE', 'Registry must be independent of the Parent package')
    registry_file = checked_file(registry_path.parent, registry_path.name)
    registry_sha = file_digest(registry_file)
    registry = read_json(registry_file)
    c.need(isinstance(registry, dict) and type(registry.get('schema_version')) is int and registry['schema_version'] == 2
           and isinstance(registry.get('baselines'), dict), 'INVALID_REFERENCE', 'Unsupported registry schema')
    # Duplicated node identities are ambiguous even if different keys are used.
    seen = set()
    for name, entry in registry['baselines'].items():
        c.need(isinstance(entry, dict) and isinstance(entry.get('reference'), dict),
               'INVALID_REFERENCE', 'Malformed baseline entry: ' + name)
        identifier = entry['reference'].get('node_id')
        c.need(isinstance(identifier, str) and identifier not in seen,
               'INVALID_REFERENCE', 'Duplicate/conflicting baseline node identity')
        seen.add(identifier)
    entry = registry['baselines'].get(key)
    c.need(entry is not None, 'BOOTSTRAP_REQUIRED', 'Explicit Parent key is unavailable; no bootstrap fallback')
    c.need('entry_kind' not in entry, 'AUTHORIZATION_FAILED',
           'Registration-only or unsupported entry kind cannot authorize a local build')
    ref = entry['reference']
    c.need(all(isinstance(ref.get(name), dict) for name in ('upstreams', 'authorization', 'storage')),
           'INVALID_REFERENCE', 'Malformed reference bindings/authorization/storage')
    c.validate_request('formal', key, ref['upstreams'])
    c.need(entry.get('expected_reference_sha256') == expected_reference_sha256,
           'INVALID_REFERENCE', 'Caller reference pin differs from registry')
    trust.validate_reference(ref, expected_reference_sha256, controlled=controlled)
    info = trust.verify_package(project, parent, ref, controlled=controlled)
    c.need(file_digest(registry_file) == registry_sha, 'INVALID_REFERENCE', 'Registry changed during verification')
    return {'key': key, 'reference_sha256': expected_reference_sha256,
            'registry_sha256': registry_sha, 'reference': ref, 'verification': info}


def build_next(project, registry_path, key, expected_reference_sha256, parent,
               base_source, target_source, output, policy_path, expected_policy_sha256,
               *, controlled=False):
    """Build only, using a verified immediate Parent. Never accept the output.

    controlled=True is for isolated synthetic Git fixtures using existing local
    P4.1 approval; the public CLI deliberately exposes no fixture override.
    """
    project, registry_path, parent, base_source, target_source, output, policy_path = map(Path,
        (project, registry_path, parent, base_source, target_source, output, policy_path))
    u._new_output(output, (project, registry_path, parent, base_source, target_source, policy_path))
    selected = select_parent(project, registry_path, key, expected_reference_sha256,
                             parent, controlled=controlled)
    ref = selected['reference']; fp = ref['build_fingerprint']
    policy = u._policy(policy_path, expected_policy_sha256)
    expected_type = 'CONTROLLED_GIT_FIXTURE' if controlled else 'GENUINE_UPSTREAM'
    c.need(policy['provenance_type'] == expected_type and not policy.get('controlled_chain_fixture'),
           'AUTHORIZATION_FAILED', 'Only approved research Parents or explicit P2 anchors; no Candidate fixture bypass')
    entry = read_json(registry_path)['baselines'][key]
    if 'build_policy_sha256' in entry:
        c.need(entry['build_policy_sha256'] == expected_policy_sha256,
               'AUTHORIZATION_FAILED', 'Build policy differs from reviewed registry entry')
    c.need(not policy_path.resolve().is_relative_to(parent.resolve()),
           'AUTHORIZATION_FAILED', 'Build policy must be independent of Parent package')
    receipt, _, _, _ = u._parent(project, parent, fp, policy, base_source)
    c.need(receipt['node_id'] == ref['node_id'] and receipt['package_checksum'] == ref['package_checksum'],
           'INVALID_BASELINE', 'Actual Parent differs from selected reference')
    scope = policy['scope']
    c.need(scope['parent'] == u._edge(receipt) and scope['base_upstreams'] == ref['upstreams']
           and scope['base_source_state'] == ref['source_state'] and scope['build_fingerprint'] == fp,
           'AUTHORIZATION_FAILED', 'Build policy is not bound to selected Parent')
    # Check target checkouts and exact commits before creating any output.
    selection, _ = u.verify_sources(project, target_source, scope['target_upstreams'])
    c.need(u.state(selection) == scope['target_source_state'],
           'AUTHORIZATION_FAILED', 'Target source-state mismatch')
    output.mkdir(exist_ok=False)
    try:
        built = u.build(project, parent, base_source, target_source, output / 'candidate',
                        policy_path=policy_path, expected_policy_sha256=expected_policy_sha256,
                        expected_fingerprint=fp)
        candidate = output / 'candidate'
        verified = u.verify(project, candidate, fp, expected_id=built['candidate_id'])
        identity = read_json(candidate / 'upstream-candidate.json')['identity']
        c.need(identity['parent'] == u._edge(receipt) and identity['base_snapshot_id'] == ref['node_id']
               and identity['base_upstreams'] == ref['upstreams']
               and identity['base_source_state'] == ref['source_state'],
               'INVALID_CANDIDATE', 'Builder did not use the selected immediate Parent')
        # Re-read the independent registry, package and policy after construction.
        c.need(select_parent(project, registry_path, key, expected_reference_sha256,
                            parent, controlled=controlled) == selected,
               'INVALID_REFERENCE', 'Parent or registry changed during build')
        c.need(file_digest(policy_path) == expected_policy_sha256,
               'AUTHORIZATION_FAILED', 'Build policy changed during build')
        contract = read_json(candidate / 'build-contract.json')
        record = {'schema_version': 1, 'kind': 'research-build-selection',
            'status': 'CANDIDATE_BUILT', 'parent_key': key,
            'reference_sha256': expected_reference_sha256,
            'registry_sha256': selected['registry_sha256'], 'policy_sha256': expected_policy_sha256,
            'parent': {**u._edge(receipt), 'corpus_sha256': ref['corpus_sha256'],
                       'manifest_sha256': ref['manifest_sha256'], 'upstreams': ref['upstreams'],
                       'source_state': ref['source_state']},
            'candidate': {'candidate_id': built['candidate_id'],
                          'corpus_sha256': file_digest(candidate / 'corpus.jsonl'),
                          'generation': verified['generation'], 'upstreams': verified['upstreams'],
                          'source_state': verified['target_source_state'],
                          'manifest_sha256': file_digest(candidate / 'checksums.json')},
            'build_fingerprint': fp, 'orchestration_fingerprint': identity['orchestration_fingerprint'],
            'chunker_commit': contract['external_chunker_commit'], 'identity_scheme': contract['identity_scheme'],
            'lineage_path': 'candidate/upstream-candidate.json',
            'reuse': read_json(candidate / 'reuse-summary.json'),
            'research_baseline_created': False, 'retrieval_evaluation': 'NOT_EXECUTED',
            'hosted_validation': 'NOT_EXECUTED', 'controlled_fixture': controlled, **u.LIMITS}
        if ref['storage']['kind'] == 'GITHUB_RELEASE_ASSET':
            record['parent_storage'] = ref['storage']  # Claimed locator; no remote verification here.
        write_json(output / 'build-selection.json', record)
        return record
    except BaseException:
        # Only this call's newly-created directory is removed; existing outputs
        # were rejected before mkdir and never enter this cleanup path.
        shutil.rmtree(output)
        raise
