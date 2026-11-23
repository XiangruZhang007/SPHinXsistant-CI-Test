"""Versioned Owner-managed successor; never certifies historical independence."""
from datetime import datetime, timezone
from .corpus_snapshot import digest

MODEL = 'OWNER_MANAGED_GOVERNANCE_V1'
RISK = 'OWNER_CAN_CHANGE_RULES_AND_ROLL_BACK_BETWEEN_OBSERVATIONS'
FIELDS = {'schema_version', 'trust_model', 'repository', 'repository_id', 'owner_id',
          'workflow_path', 'default_branch', 'implementation_contract_sha256', 'valid_from', 'expires_at', 'history_ruleset_id',
          'writer_ruleset_id', 'writer_integration_id', 'risk_acceptance'}


def load(project, config):
    from . import parent_authority_transition as transition
    need = transition._need
    value = config['governance']; r = config['request']
    need(isinstance(value, dict) and set(value) == {'trust_model', 'policy_path', 'policy_sha256'}
         and value['trust_model'] == MODEL, 'INVALID_OWNER_MANAGED_GOVERNANCE')
    _, policy = transition._read(project, value['policy_path'], value['policy_sha256'])
    backend = config['transaction_backend']
    need(set(policy) == FIELDS and type(policy['schema_version']) is int
         and policy['schema_version'] == 1 and policy['trust_model'] == MODEL
         and policy['risk_acceptance'] == RISK, 'OWNER_MANAGED_RISK_ACKNOWLEDGEMENT_REQUIRED')
    need(all(type(policy[k]) is type(r[k]) and policy[k] == r[k] for k in (
        'repository', 'repository_id', 'workflow_path', 'default_branch'))
         and type(policy['owner_id']) is int and policy['owner_id'] > 0,
         'OWNER_MANAGED_POLICY_DOMAIN_MISMATCH')
    need(policy['implementation_contract_sha256'] == config['implementation_contract_sha256'],
         'OWNER_MANAGED_IMPLEMENTATION_MISMATCH')
    need(all(type(policy[k]) is int and policy[k] == backend[k] for k in (
        'history_ruleset_id', 'writer_ruleset_id', 'writer_integration_id')),
        'OWNER_MANAGED_RULESET_BINDING_MISMATCH')
    def time(value):
        need(isinstance(value, str) and value.endswith('Z'), 'INVALID_GOVERNANCE_TIME')
        return datetime.fromisoformat(value[:-1] + '+00:00')
    now = datetime.now(timezone.utc)
    need(time(policy['valid_from']) <= now < time(policy['expires_at']), 'GOVERNANCE_POLICY_NOT_CURRENT')
    return policy


def observe(project, config, transport):
    # Public Writer supplies no evidence provider or accepting flags. Both calls
    # authenticate the current pinned job/action and installation scope via API.
    from scripts import parent_authority_writer_gate as gate
    from .parent_authority_transition import _need as need
    import os
    policy = load(project, config)
    gate.verify(os.environ, project, gate.GitHubRead())
    token = gate.verify_token(os.environ, gate.GitHubRead())
    need(policy['owner_id'] == gate.OWNER_ID
         and policy['writer_integration_id'] == gate.APP_ID,
         'OWNER_MANAGED_WRITER_IDENTITY_MISMATCH')
    observed = transport.observe_governance(policy['history_ruleset_id'],
        policy['writer_ruleset_id'], policy['writer_integration_id'])
    need(observed['status'] == 'PINNED_RULESETS_OBSERVED', 'OWNER_MANAGED_RULES_NOT_OBSERVED')
    return {'status': 'OWNER_MANAGED_CONTROLS_OBSERVED', 'trust_model': MODEL,
        'policy_sha256': config['governance']['policy_sha256'],
        'policy_canonical_sha256': digest(policy), 'rules': observed,
        'credential_scope': token, 'independent_governance': 'NOT_REQUIRED_BY_THIS_CONTRACT',
        'administrator_rollback_prevention': 'NOT_GUARANTEED',
        'risk_acceptance': RISK, 'authorization': 'NOT_GRANTED'}
