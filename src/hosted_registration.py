"""Maintainer-governed Hosted manual approval, restricted to an isolated copy.

Deployment pins originate in repository-maintainer configuration, not Candidate
or dispatch data. API evidence confirms identity; it cannot authenticate an
arbitrary local process or constrain a malicious maintainer with equal access.
"""
from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import re
import subprocess

from scripts import register_trusted_baseline as cli
from . import baseline_registration_transaction as tx
from . import owner_manual_baseline_approval as owner
from .corpus_snapshot import file_digest
from .ci_v2_research import frozen_runtime

PROJECT = Path(__file__).resolve().parents[1]
DEPLOYMENT_FIELDS = {'schema_version', 'repository', 'repository_id', 'default_branch',
    'workflow_path', 'implementation_revision', 'request_path', 'request_sha256',
    'approval_policy_path', 'approval_policy_sha256'}
DISPATCH_FIELDS = {'registry_key', 'baseline_id', 'candidate_id', 'corpus_sha256',
                   'registry_entry_sha256', 'registration_subject_sha256'}
REQUIRED_CODE = ('src/hosted_registration.py', 'scripts/register_trusted_baseline_hosted.py',
                 'src/baseline_registration_transaction.py', 'scripts/register_trusted_baseline.py')


def _need(ok, reason):
    if not ok:
        raise tx.TransactionError(reason)


def _deployment():
    raw = os.environ.get('OWNER_REGISTRATION_DEPLOYMENT_JSON', '')
    sha = os.environ.get('OWNER_REGISTRATION_DEPLOYMENT_SHA256', '')
    _need(raw and tx.evidence._sha(sha) and len(raw.encode()) <= tx.evidence.LIMIT,
          'HOSTED_DEPLOYMENT_NOT_CONFIGURED')
    _need(tx._sha(raw.encode('utf-8')) == sha, 'HOSTED_DEPLOYMENT_PIN_MISMATCH')
    deployment = tx.evidence._json(raw)
    _need(isinstance(deployment, dict) and set(deployment) == DEPLOYMENT_FIELDS
          and type(deployment['schema_version']) is int and deployment['schema_version'] == 1,
          'INVALID_HOSTED_DEPLOYMENT')
    _need(isinstance(deployment['repository'], str)
          and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', deployment['repository'])
          and type(deployment['repository_id']) is int and deployment['repository_id'] > 0,
          'INVALID_HOSTED_REPOSITORY')
    _need(isinstance(deployment['implementation_revision'], str)
          and re.fullmatch('[0-9a-f]{40}', deployment['implementation_revision'])
          and isinstance(deployment['default_branch'], str) and deployment['default_branch']
          and isinstance(deployment['workflow_path'], str)
          and re.fullmatch(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml', deployment['workflow_path'])
          and all(tx.evidence._sha(deployment[k]) for k in
                  ('request_sha256', 'approval_policy_sha256')), 'INVALID_HOSTED_DEPLOYMENT_PINS')
    return deployment


def _git(*args):
    env = {**os.environ, 'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull}
    return subprocess.check_output(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
        '-C', str(PROJECT), *args], env=env, stderr=subprocess.PIPE)


def _checkout(deployment):
    _need(_git('rev-parse', '--show-toplevel').decode().strip() == str(PROJECT.resolve())
          and _git('rev-parse', 'HEAD').decode().strip() == deployment['implementation_revision'],
          'HOSTED_CHECKOUT_REVISION_MISMATCH')
    _git('diff', '--quiet', '--no-ext-diff', 'HEAD', '--')
    _need(not _git('ls-files', '--others', '--exclude-standard', '--',
                   'src', 'scripts', 'configs', '.github').strip(),
          'UNTRACKED_HOSTED_IMPLEMENTATION')
    # These exact files and the configuration must be in the reviewed commit,
    # not untracked code/config supplied alongside a trusted checkout.
    for name in (*REQUIRED_CODE, deployment['workflow_path'], deployment['request_path'],
                 deployment['approval_policy_path']):
        _git('ls-files', '--error-unmatch', '--', name)
        path = PROJECT / name
        _need(path.is_file() and not path.is_symlink()
              and path.resolve().is_relative_to(PROJECT.resolve()), 'UNREVIEWED_HOSTED_FILE')


def _inputs(deployment):
    request_path = cli.config_file(deployment['request_path'])
    policy_path = cli.config_file(deployment['approval_policy_path'], policy=True)
    request, checked_policy = cli.load_request(request_path, deployment['request_sha256'])
    _need(checked_policy == policy_path
          and request['approval_policy_sha256'] == deployment['approval_policy_sha256'],
          'HOSTED_REQUEST_POLICY_BINDING_MISMATCH')
    policy = owner._policy(PROJECT, policy_path, deployment['approval_policy_sha256'])
    _need(all(policy[k] == deployment[k] for k in
              ('repository', 'repository_id', 'default_branch', 'workflow_path')),
          'HOSTED_POLICY_DOMAIN_MISMATCH')
    return request, policy_path, policy


def _context(deployment, request, policy):
    env = os.environ
    _need(env.get('GITHUB_ACTIONS') == 'true'
          and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
          and env.get('GITHUB_REPOSITORY') == deployment['repository']
          and env.get('GITHUB_REPOSITORY_ID') == str(deployment['repository_id'])
          and env.get('GITHUB_SHA') == deployment['implementation_revision']
          and env.get('GITHUB_WORKFLOW_SHA') == deployment['implementation_revision']
          and env.get('GITHUB_WORKFLOW_REF') ==
              f"{deployment['repository']}/{deployment['workflow_path']}@refs/heads/{deployment['default_branch']}"
          and bool(env.get('GITHUB_WORKSPACE'))
          and Path(env.get('GITHUB_WORKSPACE', '')).resolve() == PROJECT.resolve(),
          'HOSTED_RUNTIME_BINDING_MISMATCH')
    context = owner.context_from_environment()
    inputs = context['dispatch_inputs']
    _need(set(inputs) == DISPATCH_FIELDS and all(isinstance(v, str) for v in inputs.values()),
          'HOSTED_DISPATCH_INPUTS_MISMATCH')
    entry = request['proposed_entry']
    expected = {'registry_key': request['registry_key'], 'baseline_id': entry['reference']['node_id'],
                'corpus_sha256': entry['reference']['corpus_sha256'],
                'registry_entry_sha256': tx.digest(entry)}
    _need(all(inputs[k] == v for k, v in expected.items())
          and re.fullmatch(r'sha256-[0-9a-f]{64}', inputs['candidate_id'])
          and tx.evidence._sha(inputs['registration_subject_sha256']),
          'HOSTED_DISPATCH_SUBJECT_MISMATCH')
    # Actor/default HEAD/run/attempt/workflow identity are checked against API,
    # not accepted merely from the runtime strings above.
    actor = owner._github_identity(owner.GitHubCLI(), policy, context)
    _need(actor['commit_sha'] == deployment['implementation_revision'], 'HOSTED_API_COMMIT_MISMATCH')
    return context


def _owned_output():
    run_id, attempt = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
    _need(re.fullmatch('[1-9][0-9]*', run_id) and re.fullmatch('[1-9][0-9]*', attempt),
          'HOSTED_RUN_ID_UNAVAILABLE')
    temp = Path(os.environ.get('RUNNER_TEMP', ''))
    _need(temp.is_absolute() and not temp.resolve().is_relative_to(PROJECT.resolve()),
          'UNSAFE_HOSTED_TEMP_DIRECTORY')
    fd = tx._open_directory(temp)
    name = f'owner-registration-{run_id}-{attempt}'
    try:
        os.mkdir(name, mode=0o700, dir_fd=fd)  # New only; never overwrite a prior attempt.
    finally:
        os.close(fd)
    return temp / name


def _persist(root, result):
    # These reports belong exclusively to this invocation, never authoritative data.
    result_path = root / 'result.json'
    with result_path.open('w', encoding='utf-8') as stream:
        json.dump(cli._sanitize(result), stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    inventory = {}
    for path in sorted(root.rglob('*')):
        _need(not path.is_symlink(), 'UNSAFE_HOSTED_OUTPUT')
        if path.is_file() and path.name != 'checksums.json':
            inventory[path.relative_to(root).as_posix()] = file_digest(path)
    with (root / 'checksums.json').open('w', encoding='utf-8') as stream:
        json.dump(inventory, stream, sort_keys=True, indent=2); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())
    fd = tx._open_directory(root)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def run():
    """Dedicated reviewed entry point; no user-selectable authority mode.

    Requires maintainer-controlled external pins and matching reviewed checkout,
    runtime, API identity, full evidence and repeated Owner subject verification.
    This does not offer process attestation against a malicious repository owner.
    """
    result = {'status': 'BLOCKED', 'registration': 'NOT_PERFORMED',
              'registry_committed': False, 'scope': 'ISOLATED_COPY_ONLY',
              'production_promotion': 'NOT_AUTHORIZED'}
    root, before = None, None
    authoritative = PROJECT / 'configs/ci_v2_schema2_trusted_baselines.json'
    try:
        root = _owned_output()
        before = file_digest(authoritative)
        deployment = _deployment()
        request, policy_path, policy = _inputs(deployment)
        _checkout(deployment)
        frozen_runtime(PROJECT)
        context = _context(deployment, request, policy)
        isolated = root / 'isolated'
        isolated.mkdir(mode=0o700)
        raw = authoritative.read_bytes()
        _need(tx._sha(raw) == before == request['expected_registry_sha256'], 'STALE_AUTHORITATIVE_REGISTRY')
        with (isolated / 'registry.json').open('xb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        def execution_context():
            _need(_deployment() == deployment, 'HOSTED_DEPLOYMENT_CHANGED')
            current_request, current_path, current_policy = _inputs(deployment)
            _need(current_request == request and current_path == policy_path and current_policy == policy,
                  'HOSTED_INPUTS_CHANGED')
            _checkout(deployment)
            _need(_context(deployment, request, policy) == context, 'HOSTED_EXECUTION_CHANGED')
            return context
        values = {k: request[k] for k in cli.PINS}
        values.update(registry_key=request['registry_key'], proposed_entry=request['proposed_entry'],
                      candidate_release=request['candidate_release'], approval_policy_path=policy_path)
        token = next((os.environ[k] for k in ('TRUSTED_RELEASE_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN')
                      if os.environ.get(k)), None)
        result = tx._register(PROJECT, isolated, token=token,
                              _execution_context=execution_context, **values)
    except Exception as error:
        result['reason'] = (str(error) if isinstance(error, (tx.TransactionError, cli.InputError,
                            owner.OwnerApprovalError, tx.evidence.VerificationError))
                            and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', str(error))
                            else 'HOSTED_VERIFICATION_FAILED')
    if before is not None:
        try:
            unchanged = file_digest(authoritative) == before
        except OSError:
            unchanged = False
        result.update(authoritative_registry_sha256_before=before,
                      authoritative_registry_unchanged=unchanged)
        if not unchanged:
            result.update(status='COMMITTED_WITH_ERROR' if result.get('registry_committed') else 'BLOCKED',
                          reason='AUTHORITATIVE_REGISTRY_CHANGED')
    result['hosted_validation'] = 'PENDING_INDEPENDENT_HOSTED_ACCEPTANCE'
    if root is not None:
        result['output_directory'] = str(root)
        try:
            _persist(root, result)
        except Exception:
            result.update(status='COMMITTED_WITH_ERROR' if result.get('registry_committed') else 'BLOCKED',
                          reason='HOSTED_EVIDENCE_PERSISTENCE_FAILED')
            try:
                _persist(root, result)
            except Exception:
                pass
    return result


def main(argv=None):
    # No path, actor or policy overrides on this execution entry point.
    try:
        parser = cli.Parser(description=__doc__, allow_abbrev=False)
        parser.parse_args(argv)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = run()
    except Exception:
        result = {'status': 'BLOCKED', 'reason': 'INVALID_HOSTED_ENTRY_ARGUMENTS',
                  'registry_committed': False, 'production_promotion': 'NOT_AUTHORIZED'}
    print(json.dumps(cli._sanitize(result), sort_keys=True, allow_nan=False))
    return 2 if result['status'] == 'COMMITTED_WITH_ERROR' else 0 if result['status'] == 'COMPLETED' else 1
