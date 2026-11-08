#!/usr/bin/env python3
"""Restore optional pinned Q1 inputs; transport integrity never grants approval."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

P = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P))
from src import ci_v2_research as c, trusted_snapshot as trust
from src.corpus_snapshot import checked_file, file_digest, read_json, write_json


def configuration(project, relative):
    """Pins come from the checked-out commit, independently of downloaded bytes."""
    project = Path(project)
    c.need(isinstance(relative, str) and relative.startswith('configs/') and relative.endswith('.json'),
           'INVALID_Q1_CONFIGURATION', 'Q1 configuration must be a repository-relative configs/*.json file')
    path = checked_file(project, relative)
    committed = subprocess.check_output(['git', '--no-optional-locks', 'show', 'HEAD:' + relative], cwd=project)
    c.need(path.read_bytes() == committed, 'INVALID_Q1_CONFIGURATION', 'Q1 configuration must match the checked-out commit')
    config = read_json(path)
    c.need(isinstance(config, dict) and set(config) == {'storage', 'transport_sha256', 'inputs_sha256'},
           'INVALID_Q1_CONFIGURATION', 'Q1 configuration requires storage and both independent SHA-256 pins')
    for name in ('transport_sha256', 'inputs_sha256'):
        c.need(isinstance(config[name], str) and re.fullmatch('[0-9a-f]{64}', config[name]),
               'INVALID_Q1_CONFIGURATION', 'Invalid SHA-256: ' + name)
    c.need(isinstance(config['storage'], dict), 'INVALID_Q1_CONFIGURATION', 'Invalid Q1 asset locator')
    trust.release_locator(config['storage'])
    return config


def runner_directory(project, runner_temp):
    root = Path(runner_temp)
    project = Path(project).resolve()
    c.need(root.is_dir() and not root.is_symlink()
           and not root.resolve().is_relative_to(project)
           and not project.is_relative_to(root.resolve()),
           'INVALID_OUTPUT', 'Q1 transport requires an existing RUNNER_TEMP outside the project')
    return root.resolve()


def prepare(project, relative, runner_temp):
    config = configuration(project, relative)  # Complete validation before download or staging.
    runner_temp = runner_directory(project, runner_temp)
    stage = Path(tempfile.mkdtemp(prefix='ci-v2-q1-', dir=runner_temp))
    try:
        archive = stage / 'inputs.tar.gz'
        receipt = trust.download(config['storage'], archive, config['transport_sha256'])
        trust.extract_regular(archive, stage / 'payload', config['transport_sha256'])
        manifest = checked_file(stage / 'payload', 'inputs/inputs.json')
        c.need(file_digest(manifest) == config['inputs_sha256'], 'Q1_MANIFEST_MISMATCH',
               'Extracted Q1 input manifest differs from the independent pin')
        return {'status': 'Q1_INPUTS_RESTORED', 'inputs_path': str(manifest),
                'inputs_sha256': config['inputs_sha256'], 'transport_sha256': config['transport_sha256'],
                'storage_receipt': receipt, 'diagnostic_only': True,
                'automatic_research_approval': False, 'production_promotion': 'NOT_AUTHORIZED'}
    except Exception:
        shutil.rmtree(stage)  # Only the new directory owned by this operation.
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--runner-temp', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    output_safe = False
    try:
        root = runner_directory(P, args.runner_temp)
        c.need(args.output.parent.is_dir() and args.output.resolve().is_relative_to(root)
               and not args.output.exists() and not args.output.is_symlink(),
               'INVALID_OUTPUT', 'Q1 receipt must be new and inside RUNNER_TEMP')
        output_safe = True
        result = prepare(P, args.config, root)
        write_json(args.output, result)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, tarfile.TarError,
            subprocess.CalledProcessError) as error:
        result = {'status': getattr(error, 'status', 'Q1_TRANSPORT_FAILED'), 'error': str(error),
                  'diagnostic_only': True, 'automatic_research_approval': False,
                  'production_promotion': 'NOT_AUTHORIZED'}
        if output_safe and not args.output.exists() and not args.output.is_symlink():
            write_json(args.output, result)
        print(json.dumps(result, sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
