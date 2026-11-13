"""Read-only preparation checks for schema-2 research Baseline registration.

No independently verifiable registration authority is configured. This module
can validate a proposed existing-format registry entry against a sealed P4.1
Baseline, but always returns BLOCKED and never writes to the Trusted Registry.
The diagnostic research-review interface is not an authorization source.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
from unittest.mock import patch

from .corpus_snapshot import checked_file, digest, file_digest, read_json

ENTRY_FIELDS = {'build_policy_path', 'build_policy_sha256',
                'expected_reference_sha256', 'reference'}


class RegistrationError(ValueError):
    """Invalid or conflicting registration proposal."""


def _validators():
    """Load existing qualification modules only when a preflight is run."""
    from . import research_baseline, schema2_workflow, trusted_snapshot
    return research_baseline, schema2_workflow, trusted_snapshot


def _need(condition, message):
    if not condition:
        raise RegistrationError(message)


def prepare(project, registry_path, key, baseline_path, proposed_entry, *,
            expected_reference_sha256, expected_build_policy_sha256,
            expected_workflow_repository, expected_workflow_repository_id):
    """Validate registration inputs without mutating registry or evidence.

    `proposed_entry` must use the existing schema-2 registry entry shape. The
    returned status is deliberately always BLOCKED until a trusted human
    authorization source is independently configured and implemented.
    """
    project, registry_path, baseline_path = map(Path, (project, registry_path, baseline_path))
    _need(isinstance(key, str) and re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', key),
          'INVALID_REGISTRY_KEY')
    _need(isinstance(proposed_entry, dict) and set(proposed_entry) == ENTRY_FIELDS,
          'INVALID_SCHEMA2_REGISTRY_ENTRY')
    _need(isinstance(expected_reference_sha256, str)
          and len(expected_reference_sha256) == 64
          and all(c in '0123456789abcdef' for c in expected_reference_sha256),
          'INVALID_INDEPENDENT_REFERENCE_PIN')
    _need(isinstance(expected_build_policy_sha256, str)
          and len(expected_build_policy_sha256) == 64
          and all(c in '0123456789abcdef' for c in expected_build_policy_sha256),
          'INVALID_INDEPENDENT_BUILD_POLICY_PIN')
    _need(isinstance(expected_workflow_repository, str)
          and type(expected_workflow_repository_id) is int
          and expected_workflow_repository_id > 0,
          'INVALID_EXPECTED_WORKFLOW_REPOSITORY')
    registry = read_json(registry_path)
    _need(type(registry.get('schema_version')) is int and registry['schema_version'] == 2
          and isinstance(registry.get('baselines'), dict), 'INVALID_SCHEMA2_REGISTRY')
    _need(key not in registry['baselines'], 'REGISTRY_KEY_ALREADY_EXISTS')
    research_baseline, schema2_workflow, trusted_snapshot = _validators()

    ref = proposed_entry['reference']
    expected_ref_sha = proposed_entry['expected_reference_sha256']
    _need(expected_ref_sha == expected_reference_sha256,
          'INDEPENDENT_REFERENCE_PIN_MISMATCH')
    _need(ref['package_format'] == 'schema2-research-baseline',
          'ONLY_P4_1_RESEARCH_BASELINES_CAN_BE_REGISTERED')
    # Use the existing locator validator with independently supplied intended
    # workflow identity. This is a local preflight, not proof of live GitHub
    # state; Hosted validation still repeats the checks against runner identity.
    with patch.dict(os.environ, {
        'GITHUB_REPOSITORY': expected_workflow_repository,
        'GITHUB_REPOSITORY_ID': str(expected_workflow_repository_id),
    }):
        trusted_snapshot.validate_reference(ref, expected_ref_sha, remote=True)

    policy_path = checked_file(project, proposed_entry['build_policy_path'])
    _need(proposed_entry['build_policy_sha256'] == expected_build_policy_sha256,
          'INDEPENDENT_BUILD_POLICY_PIN_MISMATCH')
    _need(file_digest(policy_path) == expected_build_policy_sha256,
          'BUILD_POLICY_CHECKSUM_MISMATCH')
    policy = read_json(policy_path)
    schema2_workflow._research_parent_scope(ref, policy)

    report = research_baseline.verify_baseline(
        project, baseline_path, ref['build_fingerprint'], expected_id=ref['node_id'])
    _need(report.get('P4_1_verification') == 'P4_1_VERIFIED',
          'P4_1_BASELINE_QUALIFICATION_REQUIRED')
    checks = {
        'node_id': report['baseline_id'],
        'package_checksum': report['package_checksum'],
        'manifest_sha256': file_digest(checked_file(baseline_path, 'checksums.json')),
        'source_state': report['target_source_state'],
        'upstreams': report['upstreams'],
        'build_fingerprint': ref['build_fingerprint'],
        'corpus_sha256': file_digest(checked_file(baseline_path, 'corpus.jsonl')),
    }
    _need(all(checks[name] == ref[name] for name in checks),
          'BASELINE_REFERENCE_BINDING_MISMATCH')
    _need(report['candidate_id'] == read_json(checked_file(baseline_path, 'upstream-candidate.json'))['candidate_id'],
          'CANDIDATE_IDENTITY_MISMATCH')

    quality = read_json(checked_file(baseline_path, 'quality.json'))
    decision = read_json(checked_file(baseline_path, 'research-decision.json'))
    authorization = read_json(checked_file(baseline_path, 'authorization.json'))
    _need(quality.get('status') in ('QUALITY_ACCEPTED', 'QUALITY_REVIEW_REQUIRED'),
          'INVALID_RECORDED_QUALITY_STATUS')
    _need(decision.get('quality_status') == quality['status']
          and authorization.get('quality_status') == quality['status'],
          'QUALITY_STATUS_BINDING_MISMATCH')
    _need(decision.get('production_promotion') == 'NOT_AUTHORIZED'
          and authorization.get('production_promotion') == 'NOT_AUTHORIZED'
          and decision.get('automatic_reuse') is False,
          'PRODUCTION_OR_AUTOMATIC_REUSE_RESTRICTION_MISMATCH')

    return {
        'schema_version': 1,
        'status': 'BLOCKED',
        'registration': 'NOT_PERFORMED',
        'registry_modified': False,
        'registry_key': key,
        'baseline_id': report['baseline_id'],
        'candidate_id': report['candidate_id'],
        'bindings': checks,
        'generation': report['generation'],
        'release_assets': {
            'baseline': ref['storage'],
            'parent_r2_results': ref['parent_rows_storage'],
        },
        'P4_1_verification': report['P4_1_verification'],
        'quality_status': quality['status'],
        'q1_status': quality.get('q1_status', 'NOT_RECORDED_IN_EXISTING_BASELINE_QUALITY_SCHEMA'),
        'research_review_status': 'NOT_AN_AUTHORIZATION_SOURCE',
        'reviewer_identity': 'NOT_INDEPENDENTLY_VERIFIED',
        'production_promotion': 'NOT_AUTHORIZED',
        'blocking_reasons': ['INDEPENDENT_REGISTRATION_AUTHORITY_NOT_CONFIGURED'],
        'entry_sha256': digest(proposed_entry),
    }
