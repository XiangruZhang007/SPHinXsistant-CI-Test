#!/usr/bin/env python3
"""Owner-dispatched research Candidate consumption; no publishing or approval.

The reviewed manual workflow supplies a separate execution authorization digest
and exact deployment revision. Publication is not loading authorization.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from src import research_candidate_consumer as consumer

WORKFLOW_REF = (consumer.REPOSITORY
    + '/.github/workflows/ci_v2_candidate_gradio_loading.yml@refs/heads/ci-upstream-refresh')


def trusted_checkout(review_path, expected_revision):
    expected = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': consumer.REPOSITORY,
                'GITHUB_REPOSITORY_ID': str(consumer.REPOSITORY_ID),
                'GITHUB_EVENT_NAME': 'workflow_dispatch',
                'GITHUB_REF': 'refs/heads/ci-upstream-refresh',
                'GITHUB_ACTOR_ID': '239840087', 'GITHUB_RUN_ATTEMPT': '1',
                'GITHUB_WORKFLOW_REF': WORKFLOW_REF}
    consumer.need(all(os.environ.get(k) == v for k, v in expected.items()), 'TRUSTED_DISPATCH_REQUIRED')
    def git(*args):
        return subprocess.check_output(['git', '--no-optional-locks', *args], cwd=PROJECT)
    sha = git('rev-parse', 'HEAD').decode().strip()
    consumer.need(re.fullmatch('[0-9a-f]{40}', expected_revision or '') is not None
                  and sha == expected_revision == os.environ.get('GITHUB_SHA')
                  == os.environ.get('GITHUB_WORKFLOW_SHA'),
                  'CHECKOUT_REVISION_MISMATCH')
    path = consumer.safe(review_path)
    consumer.need(path.is_relative_to(PROJECT / 'configs'), 'TRACKED_REVIEW_REQUIRED')
    relative = path.relative_to(PROJECT).as_posix()
    consumer.need(git('show', sha + ':' + relative) == path.read_bytes(), 'TRACKED_REVIEW_REQUIRED')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--review', type=Path, required=True)
    parser.add_argument('--expected-review-sha256', required=True)
    parser.add_argument('--authorized-review-sha256', required=True)
    parser.add_argument('--expected-implementation-revision', required=True)
    parser.add_argument('--purpose', required=True, choices=[consumer.PURPOSE])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--app-python', type=Path, required=True)
    parser.add_argument('--isolation-preflight', action='store_true')
    args = parser.parse_args(argv)
    try:
        trusted_checkout(args.review, args.expected_implementation_revision)
        if args.isolation_preflight:
            consumer.review_inputs(args.review, args.expected_review_sha256,
                authorized_review_sha256=args.authorized_review_sha256, purpose=args.purpose)
            python = consumer.application_interpreter(args.app_python)
            consumer.need(args.output.is_absolute() and not args.output.exists()
                and not args.output.is_symlink()
                and not args.output.resolve().is_relative_to(PROJECT), 'NEW_EXTERNAL_OUTPUT_REQUIRED')
            consumer.safe(args.output.parent, directory=True)
            from scripts.check_hosted_gradio_loading import isolated_python
            with tempfile.TemporaryDirectory(prefix='candidate-isolation-', dir=args.output.parent) as tmp:
                probe = isolated_python(python, Path(tmp), 'print(json.dumps(isolation))\n')
            print(json.dumps({'status': 'ISOLATION_PREFLIGHT_VERIFIED', 'isolation': probe}))
            return 0
        result = consumer.consume(PROJECT, args.review, args.expected_review_sha256,
            args.output, args.app_python, authorized_review_sha256=args.authorized_review_sha256,
            purpose=args.purpose)
        print(json.dumps({'status': result['status'], 'records': result['subject']['records']}))
        return 0
    except Exception:
        # Avoid raw transport errors, signed URLs, payloads and application stderr.
        failure = {'status': 'BLOCKED', 'reason': 'CANDIDATE_RESEARCH_CONSUMPTION_FAILED',
                   'production_promotion': 'NOT_AUTHORIZED'}
        # Never overwrite existing evidence or write a failure into the checkout.
        try:
            consumer.need(args.output.is_absolute() and not args.output.exists()
                and not args.output.is_symlink()
                and not args.output.resolve().is_relative_to(PROJECT), 'NEW_EXTERNAL_OUTPUT_REQUIRED')
            consumer.safe(args.output.parent, directory=True)
            args.output.mkdir(mode=0o700)
            (args.output / 'verification.json').write_text(json.dumps(failure) + '\n')
        except Exception:
            pass
        print(json.dumps(failure))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
