#!/usr/bin/env python3
"""Read-only preflight for a proposed schema-2 research baseline entry."""
import argparse
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from src.corpus_snapshot import read_json
from src.trusted_baseline_registration import RegistrationError, prepare


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registry', type=Path,
                        default=PROJECT / 'configs/ci_v2_schema2_trusted_baselines.json')
    parser.add_argument('--key', required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--entry', type=Path, required=True,
                        help='JSON object using either explicitly supported schema-2 entry form')
    parser.add_argument('--expected-reference-sha256', required=True,
                        help='Independent pin, supplied outside the proposed entry')
    parser.add_argument('--expected-build-policy-sha256',
                        help='Required for legacy entries; forbidden for registration-only entries')
    parser.add_argument('--workflow-repository', required=True)
    parser.add_argument('--workflow-repository-id', required=True, type=int)
    args = parser.parse_args(argv)
    try:
        result = prepare(
            PROJECT, args.registry, args.key, args.baseline, read_json(args.entry),
            expected_reference_sha256=args.expected_reference_sha256,
            expected_build_policy_sha256=args.expected_build_policy_sha256,
            expected_workflow_repository=args.workflow_repository,
            expected_workflow_repository_id=args.workflow_repository_id)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 1 if result['status'] == 'BLOCKED' else 0
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        code = (str(error) if isinstance(error, RegistrationError)
                else 'EVIDENCE_VALIDATION_FAILED')
        result = {'status': 'BLOCKED', 'registration': 'NOT_PERFORMED',
                  'registry_modified': False,
                  'blocking_reasons': [code]}
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
