#!/usr/bin/env python3
"""Pinned stdlib-only Writer entry; no CLI subject, token or approval overrides."""
import json
import os
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'scripts'))
import parent_authority_writer_gate as gate


def main():
    result = {'status': 'BLOCKED', 'authorization': 'NOT_GRANTED', 'registry_committed': False,
              'authoritative_registry_applied': False}
    try:
        gate.need(sys.argv[1:] == [], 'WRITER_EXECUTION_ARGUMENTS_DENIED')
        gate.need(sys.flags.isolated == 1 and sys.flags.no_site == 1, 'WRITER_ISOLATED_STDLIB_REQUIRED')
        gate.verify(os.environ, PROJECT, gate.GitHubRead())
        gate.verify_token(os.environ, gate.GitHubRead())
        # No project dependency is imported until exact source/Owner/Environment
        # and installation-token scope have been independently revalidated.
        sys.path.insert(0, str(PROJECT))
        from src.hosted_parent_authority_transition import run_writer
        result = run_writer()
    except Exception as error:
        import re
        result['reason'] = str(error) if re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(error)) else 'WRITER_EXECUTION_FAILED'
    try:
        import re
        run, attempt = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
        gate.need(re.fullmatch('[1-9][0-9]{0,19}', run) and attempt == '1', 'WRITER_RESULT_RUN_REQUIRED')
        temp = Path(os.environ.get('RUNNER_TEMP', ''))
        gate.need(temp.is_absolute() and temp.resolve() == temp.absolute()
                  and not temp.is_relative_to(PROJECT), 'UNSAFE_WRITER_RESULT_PATH')
        # Use the existing no-follow primitives only after the verified import;
        # unauthenticated local calls may print a failure but never create files.
        gate.need('src.hosted_parent_authority_transition' in sys.modules, 'WRITER_NOT_AUTHENTICATED')
        from src import baseline_registration_transaction as tx
        fd = tx._open_directory(temp)
        name = 'parent-authority-writer-' + run + '-' + attempt
        try:
            try: os.mkdir(name, 0o700, dir_fd=fd)
            except FileExistsError: pass
        finally: os.close(fd)
        fd = tx._open_directory(temp / name)
        try: tx._write_once(fd, 'result.json', tx._serialize(result))
        finally: os.close(fd)
    except Exception:
        result['diagnostic_persistence'] = 'FAILED_NO_RETRY'
        if result.get('status') == 'COMPLETED':
            result.update(status='STATE_UNCERTAIN', reason='WRITER_EVIDENCE_PERSISTENCE_FAILED')
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get('status') == 'COMPLETED' and result.get('phase') == 'VERIFIED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
