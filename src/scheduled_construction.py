"""Versioned build-only authorization. Frozen scope/Owner contracts are unchanged."""
from pathlib import Path
import re

from . import ci_v2_research as c, continuous_build_policy as scope
from .corpus_snapshot import checked_file, digest, read_json

OPERATION = 'SCHEDULED_CONTINUOUS_CANDIDATE_BUILD'
FIELDS = {'schema_version', 'operation', 'enabled', 'repository', 'repository_id',
          'workflow_path', 'continuous_policy_sha256', 'registry_sha256',
          'valid_from', 'expires_at', 'release_prefix', 'production_promotion',
          'research_approval', 'automatic_registration', 'publication_enabled'}
MUTEX = "concurrency:\n  group: ci-v2-continuous-lifecycle-${{ github.repository_id }}\n  cancel-in-progress: false\n"


def need(ok, reason):
    c.need(ok, reason, reason)


def validate(value, config, *, current=True):
    need(isinstance(value, dict) and set(value) == FIELDS
         and type(value['schema_version']) is int and value['schema_version'] == 1
         and value['operation'] == OPERATION and value['enabled'] is True,
         'INVALID_SCHEDULED_CONSTRUCTION_POLICY')
    need(all(type(value[k]) is type(config[k]) and value[k] == config[k] for k in (
        'repository', 'repository_id', 'workflow_path', 'continuous_policy_sha256', 'registry_sha256')),
        'SCHEDULED_POLICY_BINDING_MISMATCH')
    need(value['research_approval'] == 'NOT_GRANTED' and value['production_promotion'] == 'NOT_AUTHORIZED'
         and value['automatic_registration'] is False and type(value['publication_enabled']) is bool, 'CHANGED_SCHEDULED_RESTRICTIONS')
    need(isinstance(value['release_prefix'], str)
         and re.fullmatch('[a-z][a-z0-9-]{0,39}', value['release_prefix']), 'INVALID_COMPLETION_NAMESPACE')
    start, end = scope._time(value['valid_from']), scope._time(value['expires_at'])
    need(start < end, 'INVALID_SCHEDULED_POLICY_INTERVAL')
    if current:
        from datetime import datetime, timezone
        need(start <= datetime.now(timezone.utc) < end, 'SCHEDULED_POLICY_NOT_CURRENT')
    return value


def load(project, config):
    need(config['schema_version'] >= 3 and 'schedule' in config['build_events'], 'SCHEDULED_POLICY_NOT_CONFIGURED')
    value = scope._read_pinned(project, config['scheduled_policy_path'], config['scheduled_policy_sha256'])
    if config['schema_version'] == 4:
        need(config['completion_authority']['release_prefix'] == value.get('release_prefix'),
             'COMPLETION_NAMESPACE_NOT_AUTHORIZED')
    return validate(value, config)


def mutex(project, config, authority):
    """Reviewed workflow-level serialization spans build AND publication jobs.

    This is conditional on GitHub honoring concurrency and all writers using the
    reviewed workflow. It is not a distributed lock against repository admins.
    A cancelled workflow releases its group; no reservation counts as completed.
    """
    text = checked_file(project, config['workflow_path']).read_text()
    need(text.count(MUTEX) == 1 and len(re.findall(r'^concurrency:', text, re.M)) == 1,
         'LIFECYCLE_MUTUAL_EXCLUSION_NOT_ESTABLISHED')
    actor = authority['workflow_run']
    need(actor['commit_sha'] == config['implementation_revision'] and actor['event'] == 'schedule'
         and actor['run_attempt'] == 1, 'MUTEX_RUN_BINDING_MISMATCH')
    return {'mode': 'REVIEWED_WORKFLOW_CONCURRENCY', 'run_id': actor['run_id'],
            'run_attempt': actor['run_attempt'], 'implementation_revision': actor['commit_sha'],
            'group': 'ci-v2-continuous-lifecycle-' + str(config['repository_id'])}


def archived(root, config, authority):
    """Sealed consistency only; no new live authorization or historical clock claim."""
    value = read_json(root / 'evidence/scheduled-policy.json')
    validate(value, config, current=False)
    need(digest(value) == authority['scheduled_policy_canonical_sha256'], 'ARCHIVED_SCHEDULE_POLICY_MISMATCH')
    return value
