"""Read-only, metadata-only selection from a maintainer-controlled Registry.

Exactly one compatible, explicitly build-authorized Parent must match the target.
This does not qualify a package, verify source bytes, approve or register anything.
The existing execution path must still perform all of those applicable checks.
"""
from pathlib import Path
import re

from . import ci_v2_research as c, trusted_snapshot as trust
from .corpus_snapshot import checked_file, digest, file_digest, read_json
from .owner_manual_baseline_approval import _candidate_binding
from .trusted_baseline_registration import entry_kind, RegistrationError, REGISTRATION_ONLY

MODE = 'AUTO_UNIQUE_AUTHORIZED'


def _hash(value, prefix=''):
    return isinstance(value, str) and re.fullmatch(re.escape(prefix) + '[0-9a-f]{64}', value) is not None


def _policy(project, entry):
    """Metadata preflight, not a replacement for upstream_provenance._policy().

    The execution module imports extraction dependencies, so planning reuses its
    scalar policy requirements here without importing the build/extraction path.
    Existing plan() and, later, the real builder independently validate authority.
    """
    c.need(_hash(entry['build_policy_sha256']), 'AUTHORIZATION_FAILED', 'Invalid build policy pin')
    path = checked_file(project, entry['build_policy_path'])
    before = file_digest(path)
    c.need(before == entry['build_policy_sha256'], 'AUTHORIZATION_FAILED', 'Reviewed build policy checksum mismatch')
    policy = read_json(path)
    digest(policy)  # Also reject non-finite JSON values.
    c.need(isinstance(policy, dict) and type(policy.get('schema_version')) is int
           and policy['schema_version'] == 2 and policy.get('operation') == 'BUILD_CANDIDATE'
           and policy.get('research_only') is True
           and isinstance(policy.get('experiment_id'), str) and bool(policy['experiment_id'])
           and policy.get('automatic_reuse') is False
           and policy.get('automatic_research_approval') is False
           and policy.get('production_promotion') == 'NOT_AUTHORIZED'
           and policy.get('provenance_type') == 'GENUINE_UPSTREAM'
           and not policy.get('controlled_chain_fixture'),
           'AUTHORIZATION_FAILED', 'Missing or invalid genuine research build authorization')
    ref = entry['reference']
    scope = policy.get('scope')
    c.need(isinstance(scope, dict), 'AUTHORIZATION_FAILED', 'Missing build policy scope')
    kind = 'P2_ANCHOR' if ref['package_format'] == 'p2-snapshot-v1' else 'RESEARCH_BASELINE'
    c.need(scope.get('parent') == {'kind': kind, 'node_id': ref['node_id'],
                                  'package_checksum': ref['package_checksum']}
           and scope.get('base_upstreams') == ref['upstreams']
           and scope.get('base_source_state') == ref['source_state']
           and scope.get('build_fingerprint') == ref['build_fingerprint']
           and _hash(scope.get('orchestration_fingerprint'))
           and _hash(scope.get('target_source_state'), 'sha256-'),
           'AUTHORIZATION_FAILED', 'Policy differs from Parent/source/build identity')
    c.need(kind != 'P2_ANCHOR' or policy.get('p2_anchor_authorized') is True,
           'AUTHORIZATION_FAILED', 'P2 bootstrap needs explicit build authorization')
    targets = scope.get('target_upstreams')
    c.need(isinstance(targets, dict), 'AUTHORIZATION_FAILED', 'Missing exact policy targets')
    c.validate_request('formal', 'selection', targets)
    c.need(file_digest(path) == before, 'AUTHORIZATION_FAILED', 'Policy changed during planning')
    return policy, path


def unique_match(assessments):
    """Pure selection rule; assessment order is never a ranking or fallback."""
    matches = [row['key'] for row in assessments if row['reason'] == 'AUTHORIZED_TARGET_MATCH']
    c.need(matches, 'NO_ELIGIBLE_PARENT', 'No registered build-authorized Parent matches the target')
    c.need(len(matches) == 1, 'AMBIGUOUS_PARENT', 'More than one build-authorized Parent matches the target')
    return matches[0]


def select_parent(project, registry_path, revisions):
    """Produce a pinned auto plan without network, package inspection or writes.

    A valid policy for another target, a valid incompatible build, or a valid
    REGISTRATION_ONLY entry is ineligible. Corrupt or contradictory evidence is
    fatal even when another entry would match. No validation errors are skipped.
    """
    from .schema2_workflow import plan

    project, registry_path = Path(project), Path(registry_path)
    c.validate_request('formal', 'selection', revisions)
    path = checked_file(registry_path.parent, registry_path.name)
    registry_sha = file_digest(path)  # Raw bytes, not canonical object hashing.
    registry = read_json(path)
    digest(registry)
    c.need(isinstance(registry, dict) and type(registry.get('schema_version')) is int
           and registry['schema_version'] == 2 and isinstance(registry.get('baselines'), dict),
           'INVALID_REFERENCE', 'Invalid Schema V2 Registry')
    required_build = digest(read_json(c.LOCK)['P2'])
    assessments, seen_nodes, seen_bindings, policies = [], set(), set(), {}
    for key, entry in registry['baselines'].items():
        try:
            kind = entry_kind(entry)
        except RegistrationError:
            raise c.GateError('INVALID_REFERENCE', 'Unsupported Registry entry contract') from None
        ref = entry['reference']
        c.need(isinstance(ref, dict) and all(isinstance(ref.get(name), dict) for name in
               ('upstreams', 'authorization', 'storage', 'parent_rows_storage')),
               'INVALID_REFERENCE', 'Malformed Parent reference metadata')
        # This reuses the exact remote locator/reference/authorization validator.
        trust.registry_reference(registry, key)
        binding = digest(_candidate_binding(ref))
        c.need(ref['node_id'] not in seen_nodes and binding not in seen_bindings,
               'INVALID_REFERENCE', 'Duplicate or conflicting Parent identity')
        seen_nodes.add(ref['node_id']); seen_bindings.add(binding)
        if kind == REGISTRATION_ONLY:
            assessments.append({'key': key, 'reason': 'NO_BUILD_AUTHORIZATION'})
            continue
        policy, policy_path = _policy(project, entry)
        # Validate against its own authorized targets first. A valid non-match
        # is distinct from a malformed policy; never catch-and-skip GateError.
        plan(project, registry, key, policy['scope']['target_upstreams'])
        policies[key] = (policy, policy_path)
        reason = ('BUILD_INCOMPATIBLE' if ref['build_fingerprint'] != required_build else
                  'TARGET_NOT_AUTHORIZED' if policy['scope']['target_upstreams'] != revisions else
                  'AUTHORIZED_TARGET_MATCH')
        assessments.append({'key': key, 'reason': reason})
    key = unique_match(assessments)
    entry = registry['baselines'][key]
    policy, _ = policies[key]
    planned = plan(project, registry, key, revisions)
    for name, (_, policy_path) in policies.items():
        c.need(file_digest(policy_path) == registry['baselines'][name]['build_policy_sha256'],
               'AUTHORIZATION_FAILED', 'Policy changed during selection')
    c.need(file_digest(path) == registry_sha, 'INVALID_REFERENCE', 'Registry changed during selection')
    return {**planned, 'status': 'SCHEMA2_AUTO_PLAN', 'selection': {
        'schema_version': 1, 'mode': MODE, 'reason': 'UNIQUE_AUTHORIZED_TARGET_MATCH',
        'registry_sha256': registry_sha,
        'reference_sha256': entry['expected_reference_sha256'],
        'build_policy_path': entry['build_policy_path'],
        'build_policy_sha256': entry['build_policy_sha256'],
        'build_fingerprint': required_build,
        'orchestration_fingerprint': policy['scope']['orchestration_fingerprint'],
        'expected_target_source_state': policy['scope']['target_source_state'],
        'assessments': sorted(assessments, key=lambda row: row['key'])}}
