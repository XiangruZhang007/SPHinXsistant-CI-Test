"""Stdlib-only Owner-pinned runtime projection; no credential or write authority.

Historical Owner evidence is a reviewed policy input, never a live bypass claim.
The credential-only PR #14 snapshot is deliberately incompatible with this schema.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.request

MODE = 'OWNER_PINNED_WITH_LIVE_PUBLIC_PROJECTION'
MODEL = 'OWNER_MANAGED_GOVERNANCE_V1'
RISK = 'CURRENT_BYPASS_CONFIGURATION_UNVERIFIABLE'
OWNER_RISK = 'OWNER_CAN_CHANGE_RULES_AND_ROLL_BACK_BETWEEN_OBSERVATIONS'
REPOSITORY = 'XiangruZhang007/SPHinXsistant-CI-Test'
REPOSITORY_ID, OWNER_ID, APP_ID = 1455203884, 239840087, 5855475
ROW = {'id', 'target', 'enforcement', 'conditions', 'bypass_actors', 'rules'}
MANUAL_FIELDS = {'schema_version', 'trust_model', 'repository', 'repository_id', 'owner_id',
    'workflow_path', 'default_branch', 'implementation_contract_sha256', 'valid_from',
    'expires_at', 'history_ruleset_id', 'writer_ruleset_id', 'writer_integration_id',
    'risk_acceptance', 'ruleset_observation'}
EVIDENCE_FIELDS = {'schema_version', 'kind', 'purpose', 'repository', 'repository_id',
    'owner_id', 'default_branch', 'observer', 'observed_at', 'expires_at',
    'history_ruleset_id', 'writer_ruleset_id', 'default_ruleset_id',
    'writer_integration_id', 'rulesets'}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def live_update(token, node_id, number):
    """Fixed read-only GraphQL query; omitted REST parameters never mean false."""
    need(isinstance(token, str) and bool(token) and not any(c.isspace() for c in token)
         and isinstance(node_id, str) and re.fullmatch('[A-Za-z0-9_=:-]{1,160}', node_id)
         and type(number) is int and number > 0, 'RUNTIME_UPDATE_QUERY_IDENTITY_REQUIRED')
    query = 'query RuntimeUpdate($id: ID!) { node(id: $id) { ... on RepositoryRuleset { databaseId rules(first: 100) { nodes { type parameters { __typename ... on UpdateParameters { updateAllowsFetchAndMerge } } } pageInfo { hasNextPage } } } } }'
    request = urllib.request.Request('https://api.github.com/graphql', method='POST',
        data=canonical({'query': query, 'variables': {'id': node_id}}), headers={
            'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json', 'User-Agent': 'SPHinXsistant-runtime-observation'})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=15) as response:
            need(response.geturl() == 'https://api.github.com/graphql', 'RUNTIME_UPDATE_REDIRECT_DENIED')
            raw = response.read(256 * 1024 + 1)
        need(len(raw) <= 256 * 1024, 'RUNTIME_UPDATE_RESPONSE_TOO_LARGE')
        def unique(pairs):
            result = {}
            for key, value in pairs:
                need(key not in result, 'INVALID_RUNTIME_UPDATE_JSON')
                result[key] = value
            return result
        value = json.loads(raw, object_pairs_hook=unique,
            parse_constant=lambda _: need(False, 'INVALID_RUNTIME_UPDATE_JSON'))
        need(isinstance(value, dict) and not value.get('errors'), 'RUNTIME_UPDATE_QUERY_FAILED')
        node = value['data']['node']
        need(type(node['databaseId']) is int and node['databaseId'] == number
             and node['rules']['pageInfo']['hasNextPage'] is False, 'RUNTIME_UPDATE_QUERY_SCOPE_MISMATCH')
        rows = node['rules']['nodes']
        need(isinstance(rows, list) and len(rows) == 2
             and sorted(r['type'] for r in rows) == ['CREATION', 'UPDATE'], 'RUNTIME_UPDATE_QUERY_RULES_MISMATCH')
        params = next(r['parameters'] for r in rows if r['type'] == 'UPDATE')
        need(isinstance(params, dict) and params.get('__typename') == 'UpdateParameters'
             and type(params.get('updateAllowsFetchAndMerge')) is bool, 'RUNTIME_UPDATE_PARAMETER_UNVERIFIED')
        return params['updateAllowsFetchAndMerge']
    except Exception:
        raise ValueError('RUNTIME_UPDATE_PARAMETER_UNVERIFIED') from None


def time(value):
    need(isinstance(value, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value),
         'INVALID_RUNTIME_OBSERVATION_TIME')
    return datetime.fromisoformat(value[:-1] + '+00:00')


def read_pinned(project, name, pin):
    need(isinstance(name, str) and re.fullmatch(r'configs/[A-Za-z0-9_.-]+\.json', name)
         and isinstance(pin, str) and re.fullmatch('[0-9a-f]{64}', pin),
         'RUNTIME_OBSERVATION_PIN_REQUIRED')
    path = Path(project)
    for part in Path(name).parts:
        path = path / part
        need(not path.is_symlink(), 'RUNTIME_OBSERVATION_SYMLINK_DENIED')
    need(path.is_file() and path.stat().st_size <= 256 * 1024, 'RUNTIME_OBSERVATION_FILE_REQUIRED')
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == pin, 'RUNTIME_OBSERVATION_PIN_MISMATCH')
    env = {'PATH': os.defpath, 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1',
        'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_OPTIONAL_LOCKS': '0',
        'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1'}
    tracked = subprocess.run(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
        '-C', str(project), 'ls-files', '--error-unmatch', '--', name], env=env,
        capture_output=True, timeout=15)
    need(tracked.returncode == 0, 'RUNTIME_OBSERVATION_MUST_BE_TRACKED')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'INVALID_RUNTIME_OBSERVATION_JSON')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: need(False, 'INVALID_RUNTIME_OBSERVATION_JSON'))


def manual_policy(project, config):
    """The same policy binding is checked by the isolated gate and runtime."""
    pointer = config['governance']
    need(isinstance(pointer, dict) and set(pointer) == {'trust_model', 'policy_path', 'policy_sha256'}
         and pointer['trust_model'] == MODEL, 'INVALID_OWNER_MANAGED_GOVERNANCE')
    policy = read_pinned(project, pointer['policy_path'], pointer['policy_sha256'])
    # Legacy policy version 1 keeps its existing complete-live-observation gate.
    need(isinstance(policy, dict) and type(policy.get('schema_version')) is int
         and policy['schema_version'] in (1, 2), 'INVALID_RUNTIME_GOVERNANCE_VERSION')
    if policy['schema_version'] == 1:
        return policy
    need(set(policy) == MANUAL_FIELDS and policy['trust_model'] == MODEL
         and policy['risk_acceptance'] == OWNER_RISK, 'RUNTIME_GOVERNANCE_POLICY_REQUIRED')
    request, backend = config['request'], config['transaction_backend']
    need(all(type(policy[k]) is type(request[k]) and policy[k] == request[k]
             for k in ('repository', 'repository_id', 'workflow_path', 'default_branch'))
         and policy['workflow_path'] == '.github/workflows/ci_v2_parent_authority_transition.yml'
         and policy['implementation_contract_sha256'] == config['implementation_contract_sha256'],
         'RUNTIME_GOVERNANCE_POLICY_BINDING_MISMATCH')
    need(all(type(policy[k]) is int and policy[k] == backend[k] for k in
             ('history_ruleset_id', 'writer_ruleset_id', 'writer_integration_id')),
         'RUNTIME_GOVERNANCE_BACKEND_MISMATCH')
    return policy


def load(project, policy, *, default_branch, governance_sha256, operation, now=None):
    """Load full Owner evidence through the *runtime* policy's raw-byte pin."""
    need(operation in ('MANUAL_R4', 'AUTOMATIC_LIFECYCLE'), 'RUNTIME_OBSERVATION_OPERATION_DENIED')
    need(type(policy.get('schema_version')) is int and policy['schema_version'] == 2,
         'RUNTIME_OBSERVATION_VERSION_REQUIRED')
    descriptor = policy.get('ruleset_observation')
    need(isinstance(descriptor, dict) and set(descriptor) == {
        'mode', 'evidence_path', 'evidence_sha256', 'risk_acceptance', 'operation'}
         and descriptor['mode'] == MODE and descriptor['risk_acceptance'] == RISK
         and descriptor['operation'] == operation, 'RUNTIME_OBSERVATION_RISK_AND_SCOPE_REQUIRED')
    evidence = read_pinned(project, descriptor['evidence_path'], descriptor['evidence_sha256'])
    need(isinstance(evidence, dict) and set(evidence) == EVIDENCE_FIELDS
         and type(evidence['schema_version']) is int and evidence['schema_version'] == 1
         and evidence['kind'] == 'OWNER_RUNTIME_RULESET_OBSERVATION_V1'
         and evidence['purpose'] == 'RUNTIME_GOVERNANCE_POLICY_INPUT',
         'INVALID_RUNTIME_OWNER_EVIDENCE')
    need(policy['repository'] == evidence['repository'] == REPOSITORY
         and type(policy['repository_id']) is int and type(evidence['repository_id']) is int
         and policy['repository_id'] == evidence['repository_id'] == REPOSITORY_ID
         and type(evidence['owner_id']) is int and evidence['owner_id'] == OWNER_ID
         and evidence['default_branch'] == default_branch == 'ci-upstream-refresh',
         'RUNTIME_OBSERVATION_DOMAIN_MISMATCH')
    if operation == 'MANUAL_R4':
        need(type(policy['owner_id']) is int and policy['owner_id'] == OWNER_ID,
             'RUNTIME_OBSERVATION_OWNER_MISMATCH')
    need(canonical(evidence['observer']) == canonical({'id': OWNER_ID, 'login': 'XiangruZhang007',
        'repository_admin_observed': True}), 'RUNTIME_OWNER_OBSERVER_REQUIRED')
    need(all(type(evidence[k]) is int and type(policy[k]) is int and evidence[k] == policy[k] > 0
        for k in ('history_ruleset_id', 'writer_ruleset_id', 'writer_integration_id'))
         and evidence['writer_integration_id'] == APP_ID
         and type(evidence['default_ruleset_id']) is int and evidence['default_ruleset_id'] > 0
         and len({evidence[k] for k in ('history_ruleset_id', 'writer_ruleset_id', 'default_ruleset_id')}) == 3,
         'RUNTIME_OBSERVATION_RULESET_BINDING_MISMATCH')
    observed, expires = time(evidence['observed_at']), time(evidence['expires_at'])
    start, end = time(policy['valid_from']), time(policy['expires_at'])
    need(observed <= start <= (now or datetime.now(timezone.utc)) < end <= expires,
         'RUNTIME_OBSERVATION_NOT_CURRENT_OR_OUTSIDE_POLICY')
    rows = evidence['rulesets']
    ids = [evidence[k] for k in ('history_ruleset_id', 'writer_ruleset_id', 'default_ruleset_id')]
    need(isinstance(rows, list) and len(rows) == 3, 'RUNTIME_COMPLETE_RULESETS_REQUIRED')
    for row, number in zip(rows, ids):
        need(isinstance(row, dict) and set(row) == ROW and type(row['id']) is int
             and row['id'] == number and row['target'] == 'branch' and row['enforcement'] == 'active'
             and isinstance(row['bypass_actors'], list) and isinstance(row['rules'], list)
             and all(isinstance(r, dict) and isinstance(r.get('type'), str) for r in row['rules']),
             'INVALID_RUNTIME_OWNER_RULESET')
    a, b, protected = rows
    target = {'ref_name': {'include': ['refs/heads/ci-v2-authority-audit/*'], 'exclude': []}}
    need(a['conditions'] == b['conditions'] == target and a['bypass_actors'] == []
         and a['rules'] == [{'type': k} for k in ('deletion', 'non_fast_forward', 'required_linear_history')]
         and canonical(b['bypass_actors']) == canonical([{'actor_id': APP_ID, 'actor_type': 'Integration', 'bypass_mode': 'always'}])
         and canonical(b['rules']) == canonical([{'type': 'creation'}, {'type': 'update',
            'parameters': {'update_allows_fetch_and_merge': False}}]), 'RUNTIME_AUDIT_RULES_UNSAFE')
    need(protected['conditions'] == {'ref_name': {'include': ['refs/heads/' + default_branch], 'exclude': []}}
         and protected['bypass_actors'] == []
         and {'deletion', 'non_fast_forward', 'pull_request'} <= {r['type'] for r in protected['rules']}
         and any(r['type'] == 'pull_request' and isinstance(r.get('parameters'), dict)
             and type(r['parameters'].get('required_approving_review_count')) is int
             and r['parameters']['required_approving_review_count'] >= 1
             and r['parameters'].get('require_code_owner_review') is True
             and r['parameters'].get('dismiss_stale_reviews_on_push') is True for r in protected['rules']),
         'RUNTIME_DEFAULT_PROTECTION_UNSAFE')
    need(digest({'schema_version': 1, 'rulesets': rows[:2]}) == governance_sha256,
         'RUNTIME_GOVERNANCE_PIN_MISMATCH')
    return evidence


def observe(evidence, read, *, update_read=None):
    """GET A/B/default; never fill omitted live fields from historical evidence."""
    visibility = []; update_observation = 'EXPLICIT_REST_PARAMETERS'
    for expected in evidence['rulesets']:
        live = read(expected['id'])
        need(isinstance(live, dict) and all(k in live for k in ROW - {'bypass_actors'}),
             'RUNTIME_LIVE_RULESET_MALFORMED')
        projection = {k: live[k] for k in ROW - {'bypass_actors'}}
        if expected['id'] == evidence['writer_ruleset_id'] and live['rules'] == [{'type': 'creation'}, {'type': 'update'}]:
            need(callable(update_read) and isinstance(live.get('node_id'), str),
                 'RUNTIME_UPDATE_PARAMETER_UNVERIFIED')
            actual = update_read(live['node_id'], expected['id'])
            need(actual is False, 'RUNTIME_UPDATE_PARAMETER_UNSAFE')
            # This value is an actual authenticated GraphQL observation, not a
            # default substituted for a missing field. Keep live REST untouched.
            projection['rules'] = [{'type': 'creation'}, {'type': 'update',
                'parameters': {'update_allows_fetch_and_merge': actual}}]
            update_observation = 'LIVE_GRAPHQL_FALSE_REST_PARAMETERS_OMITTED'
        # Canonical bytes distinguish bool/int/null and reject non-finite JSON.
        need(canonical(projection)
             == canonical({k: expected[k] for k in ROW - {'bypass_actors'}}),
             'RUNTIME_PUBLIC_RULESET_DRIFT')
        if 'bypass_actors' in live:
            need(isinstance(live['bypass_actors'], list)
                 and canonical(live['bypass_actors']) == canonical(expected['bypass_actors']),
                 'RUNTIME_VISIBLE_BYPASS_MISMATCH')
            status = 'RETURNED_EXACT_MATCH'
        else:
            status = 'NOT_RETURNED_LIVE_BYPASS_UNVERIFIED'
        visibility.append({'ruleset_id': expected['id'], 'bypass_observation': status})
    return {'status': 'OWNER_PINNED_PUBLIC_PROJECTION_MATCHES', 'mode': MODE,
        'owner_evidence_canonical_sha256': digest(evidence), 'owner_observed_at': evidence['observed_at'],
        'owner_evidence_expires_at': evidence['expires_at'], 'live_ruleset_projection': 'MATCHES',
        'bypass_visibility': visibility, 'complete_current_ruleset_verification': False,
        'update_parameters_observation': update_observation,
        'risk_acceptance': RISK, 'authorization': 'NOT_GRANTED'}


def effective_default(evidence, rules):
    """Bind effective required rules to the pinned exclusive default Ruleset."""
    need(isinstance(rules, list) and all(isinstance(r, dict) and isinstance(r.get('type'), str)
         and type(r.get('ruleset_id')) is int and r['ruleset_id'] > 0 for r in rules),
         'RUNTIME_EFFECTIVE_RULES_MALFORMED')
    protected = evidence['rulesets'][2]
    for kind in ('deletion', 'non_fast_forward', 'pull_request'):
        expected = [r for r in protected['rules'] if r['type'] == kind]
        need(any(r['type'] == kind and r['ruleset_id'] == protected['id']
            and any(canonical({k: r[k] for k in ('type', 'parameters') if k in r}) == canonical(e)
                for e in expected) for r in rules), 'RUNTIME_EFFECTIVE_DEFAULT_RULE_MISMATCH')
