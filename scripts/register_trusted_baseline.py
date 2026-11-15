#!/usr/bin/env python3
"""Verify registration subjects or operate on isolated Registry copies only."""
import argparse
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from src import published_candidate_verification as evidence
from src import baseline_registration_transaction as transaction
from src import owner_manual_baseline_approval as owner
from src.corpus_snapshot import digest

PINS = {'expected_candidate_release_sha256', 'expected_reference_sha256',
        'expected_build_policy_sha256', 'expected_registry_sha256', 'approval_policy_sha256'}
REQUEST_FIELDS = PINS | {'schema_version', 'registry_key', 'proposed_entry',
                        'candidate_release', 'approval_policy_path'}
STORAGE_FIELDS = {'kind', 'repository', 'repository_id', 'release_id', 'asset_id',
                  'tag', 'asset_name', 'asset_size', 'immutable_required'}
REFERENCE_FIELDS = {'schema_version', 'package_format', 'accepted_package_schema', 'node_id',
                    'package_checksum', 'manifest_sha256', 'transport_sha256', 'source_state',
                    'upstreams', 'build_fingerprint', 'corpus_sha256', 'authorization', 'storage',
                    'parent_rows_sha256', 'parent_rows_storage'}
AUTH_FIELDS = {'type', 'scope', 'research_only', 'experiment_id',
               'automatic_research_approval', 'production_promotion'}


class InputError(ValueError):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise InputError('INVALID_CLI_ARGUMENTS')


def require(value, code):
    if not value:
        raise InputError(code)


def fields(value, names, code):
    require(isinstance(value, dict) and set(value) == names, code)


def config_file(value, *, policy=False):
    require(isinstance(value, str) and re.fullmatch(r'configs/[A-Za-z0-9._/-]+', value)
            and all(p not in ('.', '..') for p in value.split('/')),
            'INVALID_CONFIG_PATH')
    path = PROJECT / value
    require(not policy or path.parent == PROJECT / 'configs', 'INVALID_POLICY_PATH')
    current = PROJECT
    for part in Path(value).parts:
        current = current / part
        require(not current.is_symlink(), 'UNSAFE_CONFIG_PATH')
    require(path.is_file() and path.resolve().is_relative_to((PROJECT / 'configs').resolve()),
            'MISSING_OR_UNSAFE_CONFIG_FILE')
    return path


def locator(value):
    fields(value, STORAGE_FIELDS, 'INVALID_ASSET_LOCATOR_FIELDS')
    require(value['kind'] == 'GITHUB_PRIVATE_RELEASE_ASSET', 'PRIVATE_RELEASE_REQUIRED')
    require(all(type(value[k]) is int and value[k] > 0 for k in
                ('repository_id', 'release_id', 'asset_id', 'asset_size'))
            and value['asset_size'] <= 2 * 1024**3
            and value['immutable_required'] is True, 'INVALID_ASSET_LOCATOR_TYPES')
    # Existing validator enforces repository runtime binding and safe names.
    evidence.transport.release_locator(value)


def load_request(path, expected_sha):
    require(evidence._sha(expected_sha), 'INVALID_REQUEST_SHA256')
    # Read once; compare and parse precisely the same bytes. No second open.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= evidence.LIMIT,
                'UNSAFE_OR_OVERSIZED_REQUEST')
        raw = stream.read(evidence.LIMIT + 1)
    require(len(raw) <= evidence.LIMIT and hashlib.sha256(raw).hexdigest() == expected_sha,
            'REQUEST_SHA256_MISMATCH')
    request = evidence._json(raw)
    fields(request, REQUEST_FIELDS, 'INVALID_REQUEST_FIELDS')
    require(type(request['schema_version']) is int and request['schema_version'] == 1,
            'UNSUPPORTED_REQUEST_SCHEMA')
    require(all(evidence._sha(request[k]) for k in PINS), 'INVALID_REQUEST_PIN')
    require(isinstance(request['registry_key'], str)
            and re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', request['registry_key']),
            'INVALID_REGISTRY_KEY')
    entry = request['proposed_entry']
    fields(entry, evidence.registration.ENTRY_FIELDS, 'INVALID_ENTRY_FIELDS')
    require(entry['expected_reference_sha256'] == request['expected_reference_sha256']
            and entry['build_policy_sha256'] == request['expected_build_policy_sha256'],
            'ENTRY_PIN_MISMATCH')
    config_file(entry['build_policy_path'])
    ref = entry['reference']
    require(isinstance(ref, dict) and set(ref) in
            (REFERENCE_FIELDS, REFERENCE_FIELDS | {'candidate_id'}), 'INVALID_REFERENCE_FIELDS')
    fields(ref['authorization'], AUTH_FIELDS, 'INVALID_REFERENCE_AUTHORIZATION_FIELDS')
    fields(ref['upstreams'], {'SPHinXsys', 'SPHinXsim'}, 'INVALID_UPSTREAM_FIELDS')
    for name in ('node_id', 'source_state'):
        require(isinstance(ref[name], str) and re.fullmatch(r'sha256-[0-9a-f]{64}', ref[name]),
                'INVALID_REFERENCE_IDENTITY')
    if 'candidate_id' in ref:
        require(isinstance(ref['candidate_id'], str)
                and re.fullmatch(r'sha256-[0-9a-f]{64}', ref['candidate_id']), 'INVALID_CANDIDATE_ID')
    require(all(evidence._sha(ref[k]) for k in ('package_checksum', 'manifest_sha256',
                'transport_sha256', 'build_fingerprint', 'corpus_sha256', 'parent_rows_sha256')),
            'INVALID_REFERENCE_HASH')
    locator(ref['storage'])
    locator(ref['parent_rows_storage'])
    evidence.transport.validate_reference(ref, request['expected_reference_sha256'], remote=True)
    require(ref['package_format'] == 'schema2-research-baseline', 'P4_1_BASELINE_REQUIRED')
    release = request['candidate_release']
    evidence._release_contract(release, request['expected_candidate_release_sha256'])
    for item in release['assets'].values():
        locator(item['storage'])
    policy_path = config_file(request['approval_policy_path'], policy=True)
    policy = owner._policy(PROJECT, policy_path, request['approval_policy_sha256'])
    require(policy['repository'] == ref['storage']['repository']
            and policy['repository_id'] == ref['storage']['repository_id'], 'POLICY_REPOSITORY_MISMATCH')
    require(policy['registry_path'] == 'configs/ci_v2_schema2_trusted_baselines.json',
            'AUTHORITATIVE_REGISTRY_PATH_MISMATCH')
    return request, policy_path


def _parser():
    parser = Parser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest='command', required=True, parser_class=Parser)
    for command in ('verify-subject', 'register'):
        sub = commands.add_parser(command, allow_abbrev=False)
        sub.add_argument('--request', type=Path, required=True)
        sub.add_argument('--request-sha256', required=True)
        if command == 'register':
            sub.add_argument('--isolation-directory', type=Path, required=True)
    sub = commands.add_parser('recover', allow_abbrev=False)
    sub.add_argument('--isolation-directory', type=Path, required=True)
    sub.add_argument('--transaction-id', required=True)
    return parser


def _invoke(args):
    if args.command == 'recover':
        require(evidence._sha(args.transaction_id), 'INVALID_TRANSACTION_ID')
        return transaction.recover(PROJECT, args.isolation_directory,
                                   transaction_id=args.transaction_id)
    request, policy = load_request(args.request, args.request_sha256)
    values = {k: request[k] for k in PINS}
    values.update(registry_key=request['registry_key'], proposed_entry=request['proposed_entry'],
                  candidate_release=request['candidate_release'])
    token = next((os.environ[k] for k in ('TRUSTED_RELEASE_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN')
                  if os.environ.get(k)), None)
    if args.command == 'register':
        return transaction.register(PROJECT, args.isolation_directory,
            approval_policy_path=policy, token=token, **values)
    return evidence.verify(PROJECT, PROJECT / 'configs/ci_v2_schema2_trusted_baselines.json',
                           token=token, **values)


def _sanitize(value):
    if isinstance(value, dict):
        return {str(k): _sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    if isinstance(value, str):
        for key in ('TRUSTED_RELEASE_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN'):
            secret = os.environ.get(key)
            if secret:
                value = value.replace(secret, '[REDACTED]')
        return re.sub(r'https?://[^\s"<>]+', '[REDACTED_URL]', value)
    return value


def main(argv=None):
    try:
        args = _parser().parse_args(argv)
        # Library diagnostics cannot contaminate machine-readable stdout.
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = _invoke(args)
        require(isinstance(result, dict), 'INVALID_OPERATION_RESULT')
        if 'reason' in result and not re.fullmatch(r'[A-Z][A-Z0-9_]{0,100}', str(result['reason'])):
            result = {**result, 'reason': 'OPERATION_FAILED'}
        status = result.get('status')
        code = (2 if status == 'COMMITTED_WITH_ERROR' else
                0 if status in ('EVIDENCE_VERIFIED', 'COMPLETED') else 1)
    except Exception as error:
        reason = str(error) if isinstance(error, (InputError, evidence.VerificationError,
                                                owner.OwnerApprovalError)) else ''
        if not re.fullmatch(r'[A-Z][A-Z0-9_]{0,100}', reason):
            reason = 'INVALID_INPUT_OR_OPERATION_FAILED'
        result = {'status': 'BLOCKED', 'registration': 'NOT_PERFORMED',
                  'production_promotion': 'NOT_AUTHORIZED', 'reason': reason}
        code = 1
    print(json.dumps(_sanitize(result), ensure_ascii=False, sort_keys=True, allow_nan=False))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
