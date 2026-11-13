#!/usr/bin/env python3
"""Publish a verified CI V2 Candidate as a private immutable research archive.

This command requires an explicit --publish flag. It never approves or registers
a Trusted Parent and never authorizes production promotion.
"""
import argparse
import json
import os
from pathlib import Path
import sys

P = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P))
from src.candidate_release_archive import ArchiveError, publish_from_environment


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-root', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--run-id', required=True, type=int)
    parser.add_argument('--attempt', required=True, type=int)
    parser.add_argument('--head-sha', required=True)
    parser.add_argument('--artifact-id', required=True, type=int)
    parser.add_argument('--artifact-digest', required=True)
    parser.add_argument('--publish', action='store_true', required=True,
                        help='Required explicit opt-in; creates and publishes a private immutable Release')
    try:
        args = parser.parse_args(argv)
        result = publish_from_environment(args.artifact_root, args.output_dir,
            repository=args.repository, run_id=args.run_id, attempt=args.attempt,
            head_sha=args.head_sha, artifact_id=args.artifact_id,
            artifact_digest=args.artifact_digest, token=os.environ.get('GITHUB_TOKEN'))
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False))
        return 0
    except (ArchiveError, OSError, ValueError, KeyError, TypeError) as error:
        # Do not relay raw HTTP errors or subprocess output; they may contain
        # signed URLs or credentials. Only our sanitized validation errors pass.
        message = str(error) if isinstance(error, ArchiveError) else type(error).__name__
        print(json.dumps({'status': 'FAILED', 'error': message,
                          'research_baseline_created': False,
                          'trusted_parent_registered': False,
                          'production_promotion': 'NOT_AUTHORIZED'}, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
