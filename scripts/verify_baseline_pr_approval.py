#!/usr/bin/env python3
"""Read-only verification of a GitHub PR approval for a schema-2 Baseline."""
import argparse
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from src.corpus_snapshot import read_json
from src.github_baseline_approval import ApprovalError, GitHubCLI, verify


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--pull-request', type=int, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--registry', type=Path,
                        default=PROJECT / 'configs/ci_v2_schema2_trusted_baselines.json')
    parser.add_argument('--registry-key', required=True)
    parser.add_argument('--entry', type=Path, required=True)
    parser.add_argument('--base-registry-sha256', required=True)
    parser.add_argument('--proposed-registry-sha256', required=True)
    parser.add_argument('--q1-status', required=True,
                        choices=('QUALIFIED', 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR'))
    args = parser.parse_args(argv)
    try:
        result = verify(
            PROJECT, args.baseline, args.registry, args.registry_key,
            read_json(args.entry), policy_path=args.policy,
            policy_sha256=args.policy_sha256, pull_number=args.pull_request,
            expected_base_registry_sha256=args.base_registry_sha256,
            expected_proposed_registry_sha256=args.proposed_registry_sha256,
            q1_status=args.q1_status, client=GitHubCLI())
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        result = {'schema_version': 1, 'status': 'BLOCKED',
                  'registry_modified': False, 'registration': 'NOT_PERFORMED',
                  'production_promotion': 'NOT_AUTHORIZED',
                  'reasons': [str(error) if isinstance(error, ApprovalError)
                              else 'INVALID_OR_UNAVAILABLE_APPROVAL_INPUT']}
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get('status') == 'GITHUB_APPROVAL_VERIFIED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
