#!/usr/bin/env python3
"""Read-only full Owner observation for a separate credential-preparation job."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))


def prepare():
    from src import hosted_parent_authority_transition as hosted
    from src.corpus_snapshot import digest
    config = hosted._deployment()
    observed = hosted._observe(PROJECT, config)
    hosted.need(hosted._deployment() == config, 'TRANSITION_DEPLOYMENT_CHANGED')
    actor = observed['workflow_run']
    receipt = {'schema_version': 1, 'status': 'OWNER_VERIFIED_WRITER_PREPARATION_ONLY',
        'authorization': 'NOT_GRANTED', 'registry_committed': False,
        'request_sha256': digest(config['request']), 'proposal_sha256': config['proposal_sha256'],
        'subject_sha256': config['subject_sha256'],
        'implementation_contract_sha256': config['implementation_contract_sha256'],
        'workflow_run': actor}
    files = hosted.contract(PROJECT)['files']
    return receipt, files


def main():
    try:
        if len(sys.argv) != 1: raise ValueError('WRITER_PREPARATION_ARGUMENTS_DENIED')
        receipt, files = prepare()
        raw = json.dumps(receipt, sort_keys=True, separators=(',', ':'), allow_nan=False)
        output = Path(os.environ.get('GITHUB_OUTPUT', ''))
        temp = Path(os.environ.get('RUNNER_TEMP', ''))
        if not (output.is_absolute() and temp.is_absolute() and not output.is_symlink()
                and output.resolve().is_relative_to(temp.resolve())
                and not temp.resolve().is_relative_to(PROJECT.resolve())):
            raise ValueError('UNSAFE_WRITER_PREPARATION_OUTPUT')
        fd = os.open(output, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        with os.fdopen(fd, 'w') as stream:
            stream.write('writer_prepared=true\nowner_receipt=' + raw + '\nimplementation_files='
                + json.dumps(files, sort_keys=True, separators=(',', ':')) + '\n')
        print(raw)
        return 0  # Only Owner-verified preparation, never a transaction success.
    except Exception as error:
        reason = str(error) if re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(error)) else 'WRITER_PREPARATION_FAILED'
        print(json.dumps({'status': 'BLOCKED', 'reason': reason, 'authorization': 'NOT_GRANTED'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
