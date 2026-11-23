"""Read-only continuous-scope prototype, deliberately disconnected from builders.

External policy/Registry pins are caller trust inputs, never recovered from a Plan.
Passing this evaluator does not establish a trusted execution context or qualify a
Parent package. Historical schema-2 execution remains exact-target only.
"""
from datetime import datetime, timezone
from pathlib import Path
import re
from urllib.parse import quote

from . import ci_v2_research as c, schema2_workflow as workflow
from . import trusted_snapshot as trust, trusted_parent_selection as selection
from .corpus_snapshot import checked_file, digest, file_digest, read_json
from .owner_manual_baseline_approval import GitHubCLI, _candidate_binding
from .trusted_baseline_registration import entry_kind, REGISTRATION_ONLY

MODE = 'CONTINUOUS_SCOPE'
PLAN_STATUS = 'CONTINUOUS_SCOPE_ASSESSED_EXECUTION_BLOCKED'
EXECUTION_BLOCKER = 'HISTORICAL_EXACT_TARGET_CONTRACT_REQUIRES_COMPATIBILITY_DECISION'
REQUIREMENTS = {
    'parent_qualification': 'P4_1_AND_FRESH_PARENT_R2',
    'source_verification': 'CLEAN_GIT_TREE_BLOBS_AND_SOURCE_STATE',
    'relationships': 'SAME_OR_FAST_FORWARD',
    'structural_parity': 'INDEPENDENT_FULL_BUILD_REQUIRED',
    'retrieval': 'FROZEN_R2_AND_INDEPENDENT_REPLAY',
    'q1': 'PRESERVE_VERSION_PAIR_QUALIFICATION',
    'p8': 'BLOCKED',
}
POLICY_FIELDS = {'schema_version', 'mode', 'operation', 'policy_id', 'enabled',
                 'research_only', 'valid_from', 'expires_at', 'upstreams',
                 'eligible_parents', 'build_fingerprint', 'orchestration_fingerprint',
                 'max_advance_commits', 'requirements', 'automatic_registration',
                 *c.RESTRICTIONS}


def _need(ok, reason):
    c.need(ok, reason, reason)  # Never include response bodies or input text.


def _hash(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def _read_pinned(root, relative, expected):
    _need(_hash(expected), 'INDEPENDENT_PIN_REQUIRED')
    path = checked_file(root, relative)
    _need(file_digest(path) == expected, 'PIN_MISMATCH')
    value = read_json(path)
    digest(value)  # Reject NaN/infinity as well as duplicate JSON keys.
    _need(file_digest(path) == expected, 'PIN_CHANGED_DURING_READ')
    return value


def _time(value):
    _need(isinstance(value, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value),
          'INVALID_POLICY_TIME')
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def load_policy(project, policy_path, expected_policy_sha256):
    """The location and raw pin must come from reviewed deployment configuration."""
    value = _read_pinned(project, policy_path, expected_policy_sha256)
    _need(isinstance(value, dict) and set(value) == POLICY_FIELDS, 'INVALID_CONTINUOUS_POLICY')
    _need(type(value['schema_version']) is int and value['schema_version'] == 1
          and value['mode'] == MODE and value['operation'] == 'BUILD_CANDIDATE'
          and value['research_only'] is True
          and isinstance(value['policy_id'], str)
          and re.fullmatch('[a-z0-9][a-z0-9_-]{0,63}', value['policy_id']),
          'INVALID_CONTINUOUS_POLICY')
    _need(value['enabled'] is True, 'CONTINUOUS_POLICY_DISABLED')
    _need(all(type(value[k]) is type(v) and value[k] == v for k, v in c.RESTRICTIONS.items())
          and value['automatic_registration'] is False
          and value['requirements'] == REQUIREMENTS, 'CHANGED_RESTRICTIONS')
    start, end = _time(value['valid_from']), _time(value['expires_at'])
    _need(start <= datetime.now(timezone.utc) < end, 'CONTINUOUS_POLICY_NOT_CURRENT')
    _need(type(value['max_advance_commits']) is int
          and 1 <= value['max_advance_commits'] <= 4096, 'INVALID_TRANSITION_BOUND')
    _need(_hash(value['build_fingerprint']) and _hash(value['orchestration_fingerprint']),
          'INVALID_FINGERPRINT')
    upstreams = value['upstreams']
    _need(isinstance(upstreams, dict) and set(upstreams) == set(c.SOURCES), 'INVALID_UPSTREAM_SCOPE')
    for repo, url in c.SOURCES.items():
        row = upstreams[repo]
        _need(isinstance(row, dict) and set(row) == {'url', 'repository_id', 'branch'}
              and row['url'] == url and type(row['repository_id']) is int
              and row['repository_id'] > 0, 'INVALID_UPSTREAM_SCOPE')
        branch = row['branch']
        _need(isinstance(branch, str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._/-]{0,127}', branch)
              and not any(s in branch for s in ('..', '//', '/.', '.lock'))
              and not branch.endswith(('/', '.')), 'INVALID_BRANCH_SCOPE')
    parents = value['eligible_parents']
    _need(isinstance(parents, list) and 0 < len(parents) <= 16, 'INVALID_PARENT_SCOPE')
    keys, nodes = set(), set()
    for parent in parents:
        _need(isinstance(parent, dict) and set(parent) == {
            'key', 'node_id', 'package_checksum', 'expected_reference_sha256'}, 'INVALID_PARENT_SCOPE')
        c.validate_request('formal', parent['key'], read_json(c.LOCK)['upstreams'])
        _need(isinstance(parent['node_id'], str)
              and re.fullmatch('sha256-[0-9a-f]{64}', parent['node_id'])
              and _hash(parent['package_checksum']) and _hash(parent['expected_reference_sha256'])
              and parent['key'] not in keys and parent['node_id'] not in nodes, 'INVALID_PARENT_SCOPE')
        keys.add(parent['key']); nodes.add(parent['node_id'])
    return value


def _parent(project, registry, policy):
    _need(isinstance(registry, dict) and type(registry.get('schema_version')) is int
          and registry['schema_version'] == 2 and isinstance(registry.get('baselines'), dict),
          'INVALID_REFERENCE')
    eligible = {p['key']: p for p in policy['eligible_parents']}
    _need(set(eligible) <= set(registry['baselines']), 'MISSING_SCOPED_PARENT')
    rows, nodes, bindings = [], set(), set()
    for key, entry in registry['baselines'].items():
        kind = entry_kind(entry)
        trust.registry_reference(registry, key)
        ref = entry['reference']; binding = digest(_candidate_binding(ref))
        _need(ref['node_id'] not in nodes and binding not in bindings, 'CONFLICTING_PARENT_IDENTITY')
        nodes.add(ref['node_id']); bindings.add(binding)
        if kind == REGISTRATION_ONLY:
            rows.append({'key': key, 'reason': 'NO_BUILD_AUTHORIZATION'})
            continue
        # Validate every existing exact policy against its own scope, not the new
        # target. Corruption elsewhere in the Registry must not be skipped.
        exact, _ = selection._policy(project, entry)
        workflow.plan(project, registry, key, exact['scope']['target_upstreams'])
        match = key in eligible
        if match:
            expected = eligible[key]
            _need(all(expected[k] == (entry[k] if k == 'expected_reference_sha256' else ref[k])
                      for k in ('node_id', 'package_checksum', 'expected_reference_sha256')),
                  'SCOPED_PARENT_MISMATCH')
            _need(ref['package_format'] == 'schema2-research-baseline'
                  and ref['build_fingerprint'] == policy['build_fingerprint']
                  and exact['scope']['orchestration_fingerprint'] == policy['orchestration_fingerprint'],
                  'INCOMPATIBLE_PARENT')
        rows.append({'key': key, 'reason': 'AUTHORIZED_TARGET_MATCH' if match else 'OUTSIDE_CONTINUOUS_SCOPE'})
    key = selection.unique_match(rows)
    return key, registry['baselines'][key], rows


def _get(client, endpoint):
    try:
        value = client.json(endpoint)
    except Exception:
        raise c.GateError('SOURCE_REF_UNAVAILABLE', 'SOURCE_REF_UNAVAILABLE') from None
    _need(isinstance(value, dict), 'INVALID_SOURCE_REF')
    return value


def _source_refs(policy, targets, base_proofs, target_proofs):
    """Fresh official API observations, never caller-supplied saved receipts.

    Mock GitHubCLI only in tests. Git object proofs alone do not prove publication
    or branch membership. Saved observations support audit, not fresh authority.
    """
    from . import upstream_provenance as provenance
    client = GitHubCLI(); result = {}
    for repo, scope in policy['upstreams'].items():
        full_name = scope['url'].removeprefix('https://github.com/').removesuffix('.git')
        endpoint = 'repos/' + full_name
        metadata = _get(client, endpoint)
        _need(type(metadata.get('id')) is int and metadata['id'] == scope['repository_id']
              and metadata.get('full_name') == full_name, 'SOURCE_REPOSITORY_MISMATCH')
        branch = _get(client, endpoint + '/git/ref/heads/' + quote(scope['branch'], safe=''))
        _need(branch.get('ref') == 'refs/heads/' + scope['branch']
              and isinstance(branch.get('object'), dict)
              and branch['object'].get('type') == 'commit'
              and branch['object'].get('sha') == targets[repo], 'SOURCE_BRANCH_MISMATCH')
        commits = {}
        for proof in (base_proofs[repo], target_proofs[repo]):
            oid = proof['commit']
            if oid in commits:
                continue
            response = _get(client, endpoint + '/commits/' + oid)
            tree, parents = provenance._commit(provenance._decoded(proof['commit_raw'], 'commit', oid))
            _need(response.get('sha') == oid
                  and response.get('html_url') == 'https://github.com/' + full_name + '/commit/' + oid
                  and isinstance(response.get('commit'), dict)
                  and isinstance(response['commit'].get('tree'), dict)
                  and response['commit']['tree'].get('sha') == tree
                  and isinstance(response.get('parents'), list)
                  and all(isinstance(p, dict) for p in response['parents'])
                  and [p.get('sha') for p in response['parents']] == parents,
                  'SOURCE_PUBLICATION_MISMATCH')
            commits[oid] = {'sha': oid, 'tree': tree, 'parents': parents,
                            'html_url': response['html_url']}
        result[repo] = {'repository_id': metadata['id'], 'full_name': full_name,
                        'ref': branch['ref'], 'commit': targets[repo], 'publications': commits}
    return result


def assess_scope(project, registry_path, policy_path, *, expected_policy_sha256,
                 expected_registry_sha256, revisions, base_source, target_source):
    """Return sealed scope evidence, NOT an executable schema-2 Plan.

    Caller supplies independently trusted paths/pins each time. No writes,
    restoration, extraction, replay, approval or Registry changes occur here.
    Only API GETs and read-only Git/source inventory checks may execute.
    """
    from . import upstream_provenance as provenance
    project = Path(project)
    c.validate_request('formal', 'continuous-scope', revisions)
    policy = load_policy(project, policy_path, expected_policy_sha256)
    _need(policy['build_fingerprint'] == digest(read_json(c.LOCK)['P2'])
          and policy['orchestration_fingerprint'] == digest(provenance.contract(project)),
          'INCOMPATIBLE_IMPLEMENTATION')
    registry_path = Path(registry_path)
    registry = _read_pinned(registry_path.parent, registry_path.name, expected_registry_sha256)
    key, entry, assessments = _parent(project, registry, policy)
    ref = entry['reference']
    base, base_proofs = provenance.verify_sources(project, Path(base_source).resolve(), ref['upstreams'])
    target, target_proofs = provenance.verify_sources(project, Path(target_source).resolve(), revisions)
    _need(provenance.state(base) == ref['source_state'], 'PARENT_SOURCE_MISMATCH')
    relationships = {}
    for repo in c.SOURCES:
        proof = provenance.relationship(Path(target_source).resolve() / 'repos' / repo,
                                        ref['upstreams'][repo], revisions[repo])
        provenance.verify_relationship(proof, ref['upstreams'][repo], revisions[repo])
        _need(len(proof['commits']) <= policy['max_advance_commits'], 'TRANSITION_BOUND_EXCEEDED')
        relationships[repo] = proof
    refs = _source_refs(policy, revisions, base_proofs, target_proofs)
    # Detect changes while observing publication/ref evidence.
    _need(provenance.verify_sources(project, Path(base_source).resolve(), ref['upstreams']) == (base, base_proofs)
          and provenance.verify_sources(project, Path(target_source).resolve(), revisions) == (target, target_proofs),
          'SOURCE_CHANGED_DURING_ASSESSMENT')
    _need(load_policy(project, policy_path, expected_policy_sha256) == policy
          and file_digest(registry_path) == expected_registry_sha256, 'STALE_SCOPE')
    _need(_parent(project, registry, policy) == (key, entry, assessments), 'STALE_PARENT_AUTHORIZATION')
    evidence = {'base_selection': base, 'target_selection': target,
                'base_proofs': base_proofs, 'target_proofs': target_proofs,
                'relationships': relationships, 'source_refs': refs}
    subject = {'upstreams': dict(revisions), 'parent_key': key, 'parent_entry_sha256': digest(entry),
               'reference_sha256': entry['expected_reference_sha256'],
               'parent_id': ref['node_id'], 'parent_package_checksum': ref['package_checksum'],
               'parent_corpus_sha256': ref['corpus_sha256'], 'parent_upstreams': ref['upstreams'],
               'parent_source_state': ref['source_state'], 'target_source_state': provenance.state(target),
               'policy_path': policy_path, 'policy_raw_sha256': expected_policy_sha256,
               'policy_canonical_sha256': digest(policy), 'registry_raw_sha256': expected_registry_sha256,
               'build_fingerprint': policy['build_fingerprint'],
               'orchestration_fingerprint': policy['orchestration_fingerprint'],
               'source_evidence_sha256': digest(evidence)}
    digest(subject)  # Paths must be reviewed portable JSON strings, not Path objects.
    return {'schema_version': 1, 'mode': MODE, 'status': PLAN_STATUS,
            'execution_authorization': 'BLOCKED', 'blocker': EXECUTION_BLOCKER,
            'subject': subject, 'execution_identity': digest(subject), 'source_evidence': evidence,
            'parent_assessments': assessments, 'requirements': dict(REQUIREMENTS),
            'parent_package_qualification': 'NOT_PERFORMED',
            'parent_generation': 'REQUIRES_VERIFIED_PARENT_PACKAGE',
            'r2_replay': 'NOT_PERFORMED',
            'deduplication': 'NOT_ESTABLISHED', 'automatic_registration': False,
            **c.RESTRICTIONS}


def revalidate_scope(planned, project, registry_path, policy_path, *, expected_plan_sha256,
                     expected_policy_sha256, expected_registry_sha256, revisions,
                     base_source, target_source):
    """Recheck exact source/policy bindings; never enables historical execution."""
    _need(_hash(expected_plan_sha256) and digest(planned) == expected_plan_sha256, 'PLAN_PIN_MISMATCH')
    current = assess_scope(project, registry_path, policy_path,
                           expected_policy_sha256=expected_policy_sha256,
                           expected_registry_sha256=expected_registry_sha256,
                           revisions=revisions, base_source=base_source, target_source=target_source)
    _need(current == planned, 'STALE_SCOPE')
    return {'status': 'SCOPE_REVALIDATED_EXECUTION_BLOCKED', 'execution_identity': current['execution_identity'],
            'execution_authorization': 'BLOCKED', 'blocker': EXECUTION_BLOCKER, **c.RESTRICTIONS}
