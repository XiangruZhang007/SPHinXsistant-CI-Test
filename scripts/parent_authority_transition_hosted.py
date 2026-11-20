#!/usr/bin/env python3
"""No override flags; dedicated transition entry, disabled without deployment/backend."""
import json
import os
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))


def main():
    if len(sys.argv) != 1:
        result = {'status': 'BLOCKED', 'reason': 'TRANSITION_ENTRY_ARGUMENTS_NOT_ALLOWED',
                  'registry_committed': False, 'authorization': 'NOT_GRANTED'}
    else:
        try:
            from src.hosted_parent_authority_transition import run
            result = run()
        except Exception:
            result = {'status': 'BLOCKED', 'reason': 'TRANSITION_RUNTIME_UNAVAILABLE',
                      'registry_committed': False, 'authorization': 'NOT_GRANTED'}
    # A diagnostic output path is never a Registry/APPLY location.
    run_id, attempt = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
    if run_id.isdecimal() and attempt.isdecimal():
        try:
            from src.baseline_registration_transaction import _open_directory
            temp = Path(os.environ.get('RUNNER_TEMP', ''))
            if not temp.is_absolute() or temp.resolve().is_relative_to(PROJECT):
                raise ValueError('UNSAFE_TRANSITION_OUTPUT')
            fd = _open_directory(temp)
            try:
                name = 'parent-authority-transition-' + run_id + '-' + attempt
                os.mkdir(name, mode=0o700, dir_fd=fd)
            finally:
                os.close(fd)
            path = temp / name / 'result.json'
            with path.open('x') as stream:
                json.dump(result, stream, sort_keys=True, indent=2); stream.write('\n')
                stream.flush(); os.fsync(stream.fileno())
        except Exception:
            result['diagnostic_persistence'] = 'FAILED_NO_RETRY'
    print(json.dumps(result, sort_keys=True))
    return 1  # This B4 deployment cannot perform a live transition.


if __name__ == '__main__':
    raise SystemExit(main())
