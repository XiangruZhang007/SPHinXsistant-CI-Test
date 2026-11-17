#!/usr/bin/env python3
"""Reviewed Hosted continuous entry; missing independent configuration blocks."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

P = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P))
from scripts.prepare_ci_v2_update import output_directory
from src import genuine_continuous_execution as run
from src.corpus_snapshot import write_json


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--detection', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    output = None
    try:
        output = output_directory(P, args.output)
        result = run.execute(P, args.detection, args.work, output)
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError,
            subprocess.SubprocessError):
        # Do not print exception bodies, clone URLs, credentials or API responses.
        error = sys.exception()
        reason = getattr(error, 'status', str(error))
        import re
        if not isinstance(reason, str) or not re.fullmatch('[A-Z][A-Z0-9_]{0,99}', reason):
            reason = 'CONTINUOUS_EXECUTION_VALIDATION_FAILED'
        result = {'status': 'BLOCKED', 'reason': reason, 'execute_candidate': False, **run.LIMITS}
        if output is not None:
            try:
                output.mkdir(exist_ok=False)
                write_json(output / 'failure.json', result)
            except OSError:
                pass  # Never overwrite someone else's output or partial evidence.
        print(json.dumps(result, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
