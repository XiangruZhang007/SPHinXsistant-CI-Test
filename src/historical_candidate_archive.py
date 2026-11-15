"""Maintainer-governed historical archival; no Baseline or production authority.

Only the reviewed Hosted entry point below is supported. API identity is not
process attestation: the maintainer controls the code and independent deployment
pins. Python helpers are not a sandbox against an equally privileged maintainer.
"""
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import stat
import subprocess
import tempfile
import time
from urllib.parse import quote
import zipfile

from . import candidate_release_archive as archive
from . import owner_manual_baseline_approval as owner
from .indexing_scope import normalize_relative_path

PROJECT = Path(__file__).resolve().parents[1]
WORKFLOW = '.github/workflows/ci_v2_historical_archive.yml'
PURPOSE = 'HISTORICAL_CANDIDATE_ARCHIVAL'
ASSETS = ('candidate.tar.gz', 'research-evidence.tar.gz', 'release-manifest.json')
LIMIT = 4 * 1024 * 1024
DEPLOYMENT_FIELDS = {'schema_version', 'repository', 'repository_id', 'default_branch',
    'workflow_path', 'implementation_revision', 'request_path', 'request_sha256',
    'policy_path', 'policy_sha256'}
ORIGINAL_FIELDS = {'workflow_path', 'branch', 'run_id', 'run_attempt', 'head_sha',
    'candidate_job_id', 'artifact_id', 'artifact_name', 'artifact_size', 'artifact_sha256'}
POLICY_FIELDS = {'schema_version', 'purpose', 'enabled', 'repository', 'repository_id',
    'default_branch', 'workflow_path', 'allow_repository_owner', 'authorized_approver_ids'}


class HistoricalArchiveError(ValueError):
    """Only fixed, credential-free error codes may leave the entry point."""


def _need(ok, reason):
    if not ok:
        raise HistoricalArchiveError(reason)


def _sha(value, length=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{%d}' % length, value) is not None


def _positive(value):
    return type(value) is int and value > 0


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(raw):
    _need(len(raw) <= LIMIT, 'JSON_TOO_LARGE')
    value = owner._strict_json(raw)
    _canonical(value)  # Reject non-finite numbers too.
    return value


def _fields(value, names, reason):
    _need(isinstance(value, dict) and set(value) == set(names), reason)


def _relative(name):
    _need(isinstance(name, str) and name and '\\' not in name
          and not name.startswith('/') and PurePosixPath(name).as_posix() == name
          and all(re.fullmatch('[A-Za-z0-9_.-]+', p) and p not in ('.', '..')
                  for p in name.split('/')), 'UNSAFE_RELATIVE_PATH')
    return name


def _directory(path):
    """Open every directory component without following symbolic links."""
    path = Path(path)
    _need(path.is_absolute(), 'UNSAFE_DIRECTORY')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            _need(part not in ('.', '..'), 'UNSAFE_DIRECTORY')
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except Exception:
        os.close(fd)
        raise


def _config(name, sha):
    _relative(name)
    _need(name.startswith('configs/') and _sha(sha), 'UNSAFE_CONFIG_OR_PIN')
    path = PROJECT / name
    fd = _directory(path.parent)
    try:
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        with os.fdopen(file_fd, 'rb') as stream:
            _need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'NONREGULAR_CONFIG')
            raw = stream.read(LIMIT + 1)
    finally:
        os.close(fd)
    _need(_hash(raw) == sha, 'INDEPENDENT_CONFIG_PIN_MISMATCH')
    return _json(raw)


def configuration():
    """Pins come from maintainer-controlled Variables, never dispatch inputs."""
    raw = os.environ.get('HISTORICAL_ARCHIVE_DEPLOYMENT_JSON', '')
    pin = os.environ.get('HISTORICAL_ARCHIVE_DEPLOYMENT_SHA256', '')
    _need(raw and _sha(pin) and _hash(raw.encode()) == pin, 'DEPLOYMENT_NOT_CONFIGURED_OR_PIN_MISMATCH')
    d = _json(raw)
    _fields(d, DEPLOYMENT_FIELDS, 'INVALID_DEPLOYMENT_FIELDS')
    _need(type(d['schema_version']) is int and d['schema_version'] == 1
          and isinstance(d['repository'], str)
          and re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', d['repository'])
          and _positive(d['repository_id']) and _sha(d['implementation_revision'], 40)
          and isinstance(d['default_branch'], str)
          and re.fullmatch('[A-Za-z0-9_./-]+', d['default_branch'])
          and '..' not in d['default_branch'] and not d['default_branch'].startswith(('-', '/'))
          and d['workflow_path'] == WORKFLOW, 'INVALID_DEPLOYMENT')
    request = _config(d['request_path'], d['request_sha256'])
    _fields(request, ('schema_version', 'purpose', 'original', 'candidate', 'assets'), 'INVALID_REQUEST_FIELDS')
    _need(type(request['schema_version']) is int and request['schema_version'] == 1
          and request['purpose'] == PURPOSE, 'INVALID_ARCHIVAL_PURPOSE')
    o = request['original']
    _fields(o, ORIGINAL_FIELDS, 'INVALID_ORIGINAL_FIELDS')
    _need(all(_positive(o[k]) for k in ('run_id', 'candidate_job_id', 'artifact_id', 'artifact_size'))
          and type(o['run_attempt']) is int and o['run_attempt'] == 1
          and o['artifact_size'] <= archive.MAX_ARTIFACT_BYTES and _sha(o['head_sha'], 40)
          and _sha(o['artifact_sha256']) and o['workflow_path'] == archive.WORKFLOW
          and o['branch'] == d['default_branch']
          and o['artifact_name'] == f"ci-v2-research-{o['run_id']}-1", 'INVALID_ORIGINAL_BINDINGS')
    c = request['candidate']
    _fields(c, ('candidate_id', 'corpus_sha256', 'upstreams'), 'INVALID_CANDIDATE_FIELDS')
    _fields(c['upstreams'], ('SPHinXsys', 'SPHinXsim'), 'INVALID_UPSTREAM_FIELDS')
    _need(isinstance(c['candidate_id'], str) and c['candidate_id'].startswith('sha256-')
          and _sha(c['candidate_id'][7:]) and _sha(c['corpus_sha256'])
          and all(_sha(v, 40) for v in c['upstreams'].values()), 'INVALID_CANDIDATE_BINDINGS')
    _fields(request['assets'], ASSETS, 'INVALID_ASSET_INVENTORY')
    for asset in request['assets'].values():
        _fields(asset, ('size_bytes', 'sha256'), 'INVALID_ASSET_FIELDS')
        _need(_positive(asset['size_bytes']) and asset['size_bytes'] <= archive.MAX_EXPANDED_BYTES
              and _sha(asset['sha256']), 'INVALID_ASSET_PIN')
    p = _config(d['policy_path'], d['policy_sha256'])
    _fields(p, POLICY_FIELDS, 'INVALID_POLICY_FIELDS')
    _need(type(p['schema_version']) is int and p['schema_version'] == 1
          and p['purpose'] == PURPOSE and p['enabled'] is True
          and all(p[k] == d[k] for k in ('repository', 'repository_id', 'default_branch', 'workflow_path'))
          and type(p['allow_repository_owner']) is bool
          and isinstance(p['authorized_approver_ids'], list)
          and all(_positive(v) for v in p['authorized_approver_ids'])
          and len(p['authorized_approver_ids']) == len(set(p['authorized_approver_ids']))
          and (p['allow_repository_owner'] or p['authorized_approver_ids']), 'INVALID_ARCHIVAL_AUTHORITY')
    return d, request, p


def _git(*args):
    return subprocess.check_output(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
        '-C', str(PROJECT), *args], stderr=subprocess.PIPE,
        env={**os.environ, 'GIT_OPTIONAL_LOCKS': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
             'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull})


def _checkout(d):
    _need(_git('rev-parse', '--show-toplevel').decode().strip() == str(PROJECT.resolve())
          and _git('rev-parse', 'HEAD').decode().strip() == d['implementation_revision'], 'UNREVIEWED_CHECKOUT')
    _git('diff', '--quiet', '--no-ext-diff', 'HEAD', '--')
    _need(not _git('ls-files', '--others', '--exclude-standard', '--', 'src', 'scripts', 'configs', '.github').strip(),
          'UNTRACKED_IMPLEMENTATION')
    for name in ('src/historical_candidate_archive.py', 'scripts/archive_historical_candidate.py',
                 d['workflow_path'], d['request_path'], d['policy_path']):
        _git('ls-files', '--error-unmatch', '--', name)
        path = PROJECT / name
        _need(path.is_file() and not path.is_symlink()
              and path.resolve().is_relative_to(PROJECT.resolve()), 'UNSAFE_REVIEWED_FILE')


class _Publisher:
    """Reuse credential-safe API/upload/hash primitives, not same-run authority."""

    _api = archive.GitHubReleasePublisher._api
    _upload = archive.GitHubReleasePublisher._upload
    _verify_asset = archive.GitHubReleasePublisher._verify_asset

    def __init__(self, token, repository):
        _need(isinstance(token, str) and token and not any(c.isspace() for c in token), 'MISSING_GITHUB_AUTHORIZATION')
        _need(isinstance(repository, str) and re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository), 'INVALID_REPOSITORY')
        self.token, self.repository = token, repository

    def json(self, endpoint):
        return self._api('GET', '/' + endpoint)


def _time(value):
    _need(isinstance(value, str), 'MISSING_GITHUB_TIMESTAMP')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    _need(result.tzinfo is not None, 'INVALID_GITHUB_TIMESTAMP')
    return result


def verify_original(client, d, request):
    """First attempt only: reject any known rerun; timestamps only corroborate."""
    base = f"repos/{d['repository']}"
    o = request['original']
    repo = client.json(base)
    _need(repo.get('full_name') == d['repository'] and repo.get('id') == d['repository_id']
          and repo.get('private') is True and repo.get('default_branch') == d['default_branch'], 'ORIGINAL_REPOSITORY_MISMATCH')
    latest = client.json(f"{base}/actions/runs/{o['run_id']}")
    attempt = client.json(f"{base}/actions/runs/{o['run_id']}/attempts/1")
    for run in (latest, attempt):
        _need(run.get('id') == o['run_id'] and type(run.get('run_attempt')) is int and run['run_attempt'] == 1
              and run.get('status') == 'completed' and run.get('conclusion') == 'success'
              and run.get('path') == o['workflow_path'] and run.get('head_branch') == o['branch']
              and run.get('head_sha') == o['head_sha'] and run.get('event') == 'workflow_dispatch', 'ORIGINAL_RUN_MISMATCH_OR_RERUN')
        for key in ('repository', 'head_repository'):
            _need(run.get(key, {}).get('id') == d['repository_id']
                  and run.get(key, {}).get('full_name') == d['repository'], 'ORIGINAL_RUN_REPOSITORY_MISMATCH')
    jobs = client.json(f"{base}/actions/runs/{o['run_id']}/attempts/1/jobs?per_page=100&page=1")
    rows = jobs.get('jobs')
    _need(type(jobs.get('total_count')) is int and 0 < jobs['total_count'] <= 100
          and isinstance(rows, list) and len(rows) == jobs['total_count']
          and all(isinstance(j, dict) for j in rows), 'INCOMPLETE_JOB_INVENTORY')
    candidates = [j for j in rows if j.get('name') == 'candidate']
    _need(len(candidates) == 1, 'AMBIGUOUS_CANDIDATE_JOB')
    job = candidates[0]
    _need(job.get('id') == o['candidate_job_id'] and job.get('run_id') == o['run_id']
          and job.get('head_sha') == o['head_sha'] and job.get('head_branch') == o['branch']
          and job.get('status') == 'completed' and job.get('conclusion') == 'success'
          and job.get('run_attempt', 1) == 1, 'ORIGINAL_CANDIDATE_JOB_MISMATCH')
    asset = client.json(f"{base}/actions/artifacts/{o['artifact_id']}")
    _need(asset.get('id') == o['artifact_id'] and asset.get('name') == o['artifact_name']
          and asset.get('size_in_bytes') == o['artifact_size'] and asset.get('expired') is False
          and asset.get('digest') == 'sha256:' + o['artifact_sha256'], 'ORIGINAL_ARTIFACT_MISMATCH_OR_EXPIRED')
    binding = asset.get('workflow_run', {})
    _need(binding.get('id') == o['run_id'] and binding.get('head_sha') == o['head_sha']
          and binding.get('repository_id') == d['repository_id']
          and binding.get('head_repository_id') == d['repository_id'], 'ORIGINAL_ARTIFACT_BINDING_MISMATCH')
    _need(_time(attempt.get('created_at')) <= _time(job.get('started_at'))
          <= _time(asset.get('created_at')) <= _time(job.get('completed_at'))
          <= _time(attempt.get('updated_at')), 'ARTIFACT_ATTEMPT_TIME_CONFLICT')
    return {'original': o, 'repository': d['repository'], 'repository_id': d['repository_id']}


def _context(d, policy, client, subject_sha, original_run_id):
    env = os.environ
    _need(env.get('GITHUB_ACTIONS') == 'true' and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
          and env.get('GITHUB_REPOSITORY') == d['repository']
          and env.get('GITHUB_REPOSITORY_ID') == str(d['repository_id'])
          and env.get('GITHUB_SHA') == d['implementation_revision']
          and env.get('GITHUB_WORKFLOW_SHA') == d['implementation_revision']
          and env.get('GITHUB_WORKFLOW_REF') == f"{d['repository']}/{d['workflow_path']}@refs/heads/{d['default_branch']}"
          and env.get('GITHUB_WORKSPACE') == str(PROJECT), 'UNTRUSTED_RUNTIME_CONTEXT')
    context = owner.context_from_environment()
    _need(context.get('dispatch_inputs') == {'archival_subject_sha256': subject_sha}, 'DISPATCH_SUBJECT_MISMATCH')
    identity = owner._github_identity(client, policy, context)
    _need(identity['commit_sha'] == d['implementation_revision']
          and identity['run_id'] != original_run_id, 'ARCHIVAL_OPERATION_NOT_SEPARATE')
    return identity


def archival_subject(d, request, manifest):
    """Pure digest preparation grants no authority; all asset pins are external."""
    _need(all(manifest.get(k) == v for k, v in request['candidate'].items()), 'CANDIDATE_EVIDENCE_MISMATCH')
    prefix = request['candidate']['candidate_id'][7:15]
    o = request['original']
    tag = f"ci-v2-historical-run-{o['run_id']}-attempt-1-artifact-{o['artifact_id']}-{prefix}"
    subject = {'schema_version': 1, 'purpose': PURPOSE, 'repository': d['repository'],
        'repository_id': d['repository_id'], 'original': o, 'candidate': request['candidate'],
        'assets': request['assets'], 'request_sha256': d['request_sha256'],
        'policy_sha256': d['policy_sha256'], 'implementation_revision': d['implementation_revision'],
        'release_target_commit': d['implementation_revision'], 'release_tag': tag}
    return subject, _hash(_canonical(subject))


def _download(client, request, destination):
    """Use the project's existing gh API download mechanism for Actions ZIPs.

    Release-only CDN allowlists do not describe Actions storage redirects.
    gh owns authenticated redirect handling; never log signed URLs or stderr.
    Bound both elapsed time and streamed bytes, and use a fresh gh config.
    """
    o = request['original']
    executable = shutil.which('gh')
    _need(executable is not None, 'GITHUB_CLI_UNAVAILABLE')
    command = [executable, 'api', '--hostname', 'github.com', '--method', 'GET',
               '-H', 'Accept: application/vnd.github+json',
               f"repos/{client.repository}/actions/artifacts/{o['artifact_id']}/zip"]
    h, size = hashlib.sha256(), 0
    with tempfile.TemporaryDirectory(prefix='gh-config-', dir=destination.parent) as config:
        env = {**os.environ, 'GH_TOKEN': client.token, 'GITHUB_TOKEN': client.token,
               'GH_HOST': 'github.com', 'GH_CONFIG_DIR': config, 'GH_PROMPT_DISABLED': '1'}
        env.pop('GH_DEBUG', None)
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env) as process:
            try:
                deadline = time.monotonic() + 300
                with selectors.DefaultSelector() as selector, destination.open('xb') as stream:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while True:
                        remaining = deadline - time.monotonic()
                        _need(remaining > 0 and selector.select(remaining), 'ARTIFACT_DOWNLOAD_TIMEOUT')
                        block = os.read(process.stdout.fileno(), 1024 * 1024)
                        if not block:
                            break
                        size += len(block)
                        _need(size <= o['artifact_size'], 'ARTIFACT_DOWNLOAD_SIZE_MISMATCH')
                        h.update(block)
                        stream.write(block)
                _need(process.wait(timeout=max(0.01, deadline - time.monotonic())) == 0, 'ARTIFACT_DOWNLOAD_FAILED')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
    _need(size == o['artifact_size'] and h.hexdigest() == o['artifact_sha256'], 'ARTIFACT_DOWNLOAD_HASH_MISMATCH')


def _extract(source, destination):
    """Fresh tool-owned destination, regular members only, bounded streamed CRC."""
    destination.mkdir(mode=0o700)
    with zipfile.ZipFile(source) as z:
        infos = z.infolist()
        _need(len(infos) <= 100000 and len({i.filename for i in infos}) == len(infos), 'UNSAFE_ZIP_INVENTORY')
        total = 0
        for item in infos:
            name = item.filename[:-1] if item.is_dir() else item.filename
            _need(normalize_relative_path(name) == name, 'NONCANONICAL_ZIP_PATH')
            kind = stat.S_IFMT(item.external_attr >> 16)
            _need(kind in (0, stat.S_IFDIR if item.is_dir() else stat.S_IFREG)
                  and not item.flag_bits & 1, 'UNSAFE_ZIP_MEMBER')
            total += item.file_size
            _need(total <= archive.MAX_EXPANDED_BYTES, 'ZIP_EXPANSION_LIMIT')
        for item in infos:
            path = destination / item.filename
            if item.is_dir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            with z.open(item) as src, path.open('xb') as dest:
                size = 0
                for block in iter(lambda: src.read(1024 * 1024), b''):
                    size += len(block)
                    _need(size <= item.file_size, 'ZIP_MEMBER_SIZE_MISMATCH')
                    dest.write(block)
            _need(size == item.file_size, 'ZIP_MEMBER_SIZE_MISMATCH')


def _check_assets(prepared, request):
    root = Path(prepared['directory'])
    _need(not root.is_symlink() and {p.name for p in root.iterdir()} == set(ASSETS), 'PREPARED_ASSET_INVENTORY_CHANGED')
    for name in ASSETS:
        path = root / name
        pin = request['assets'][name]
        _need(not path.is_symlink() and path.is_file() and path.stat().st_size == pin['size_bytes']
              and archive._digest(path) == pin['sha256'], 'PREPARED_ASSET_CHANGED')
    _need(prepared['assets'] == request['assets'], 'PREPARED_ASSET_PINS_MISMATCH')


def _tag(client, subject, *, required):
    ref = client._api('GET', f"/repos/{client.repository}/git/ref/tags/{quote(subject['release_tag'], safe='')}", allow_404=True)
    if ref is None:
        _need(not required, 'PUBLISHED_TAG_MISSING')
        return
    _need(ref.get('ref') == 'refs/tags/' + subject['release_tag']
          and ref.get('object', {}).get('type') == 'commit'
          and ref.get('object', {}).get('sha') == subject['release_target_commit'], 'UNSUPPORTED_OR_WRONG_RELEASE_TAG_TARGET')


def _release(client, value, subject, prepared, uploaded, *, published):
    _need(isinstance(value, dict) and _positive(value.get('id'))
          and value.get('tag_name') == subject['release_tag']
          and value.get('target_commitish') == subject['release_target_commit']
          and value.get('draft') is (not published), 'RELEASE_IDENTITY_MISMATCH')
    if published:
        _need(value.get('immutable') is True, 'PUBLISHED_RELEASE_NOT_IMMUTABLE')
    assets = value.get('assets')
    _need(isinstance(assets, list) and len(assets) == 3
          and {a.get('name') for a in assets} == set(ASSETS), 'RELEASE_ASSET_INVENTORY_MISMATCH')
    for asset in assets:
        _need(asset.get('id') == uploaded[asset['name']]['asset_id'], 'RELEASE_ASSET_ID_CHANGED')
        client._verify_asset(value['id'], asset, Path(prepared['directory']) / asset['name'])
    _tag(client, subject, required=published)


def _reconcile(client, result):
    """Read back only; never retry a possibly committed remote write."""
    try:
        value = client._api('GET', f"/repos/{client.repository}/releases/tags/{quote(result['tag'], safe='')}", allow_404=True)
        if value is not None and _positive(value.get('id')) and value.get('tag_name') == result['tag']:
            result['release_id'] = value['id']
            if value.get('draft') is True:
                result['publication_state'] = 'DRAFT_CREATED_NOT_PUBLISHED'
            elif value.get('draft') is False:
                result['publication_state'] = 'PUBLISHED_BUT_UNVERIFIED'
    except Exception:
        pass  # UNKNOWN stays unknown; retain any earlier proven state.


def _publish(client, subject, prepared, revalidate, result):
    """Internal orchestration, called only after reviewed identity/evidence checks."""
    base = '/repos/' + client.repository
    tag = quote(subject['release_tag'], safe='')
    revalidate()
    _need(client._api('GET', base + '/releases/tags/' + tag, allow_404=True) is None
          and client._api('GET', base + '/git/ref/tags/' + tag, allow_404=True) is None, 'RELEASE_OR_TAG_CONFLICT')
    result['publication_state'] = 'PUBLICATION_STATE_UNKNOWN'  # POST may commit even if its response is lost.
    draft = client._api('POST', base + '/releases', {
        'tag_name': subject['release_tag'], 'target_commitish': subject['release_target_commit'],
        'name': 'Historical CI V2 research Candidate ' + subject['candidate']['candidate_id'][-8:],
        'body': 'Historical research archive only. Original build identity is retained in release-manifest.json. '
                'No Baseline approval, quality acceptance, Q1 qualification, registration or production authority.',
        'draft': True, 'prerelease': True, 'generate_release_notes': False})
    _need(isinstance(draft, dict) and _positive(draft.get('id')), 'DRAFT_ID_UNAVAILABLE')
    result['release_id'] = draft['id']
    _need(draft.get('draft') is True and draft.get('tag_name') == subject['release_tag']
          and draft.get('target_commitish') == subject['release_target_commit'], 'DRAFT_IDENTITY_MISMATCH')
    result['publication_state'] = 'DRAFT_CREATED_NOT_PUBLISHED'
    uploaded = {}
    for name in ASSETS:
        path = Path(prepared['directory']) / name
        value = client._upload(draft['upload_url'], draft['id'], path)
        _need(_positive(value.get('id')), 'UPLOADED_ASSET_ID_INVALID')
        uploaded[name] = client._verify_asset(draft['id'], value, path)
        result['assets'] = list(uploaded.values())
    check = client._api('GET', f"{base}/releases/{draft['id']}")
    _need(check.get('id') == draft['id'], 'DRAFT_ID_CHANGED')
    _release(client, check, subject, prepared, uploaded, published=False)
    revalidate()  # Re-read pins, API actor/default HEAD/origin, subject and staged bytes.
    result['publication_state'] = 'PUBLICATION_STATE_UNKNOWN'  # PATCH is the publication commit point.
    reply = client._api('PATCH', f"{base}/releases/{draft['id']}", {'draft': False})
    _need(reply.get('id') == draft['id'] and reply.get('draft') is False, 'PUBLISH_RESPONSE_UNVERIFIED')
    result['publication_state'] = 'PUBLISHED_BUT_UNVERIFIED'
    final = client._api('GET', f"{base}/releases/{draft['id']}")
    _need(final.get('id') == draft['id'], 'PUBLISHED_RELEASE_ID_CHANGED')
    _release(client, final, subject, prepared, uploaded, published=True)
    result.update(publication_state='PUBLISHED_IMMUTABLE_VERIFIED', immutable=True)


def _output():
    temp = Path(os.environ.get('RUNNER_TEMP', ''))
    run_id, attempt = os.environ.get('GITHUB_RUN_ID', ''), os.environ.get('GITHUB_RUN_ATTEMPT', '')
    _need(temp.is_absolute() and not temp.resolve().is_relative_to(PROJECT.resolve())
          and re.fullmatch('[1-9][0-9]*', run_id) and attempt == '1', 'UNSAFE_AUDIT_DIRECTORY')
    fd = _directory(temp)
    try:
        name = f'historical-archive-{run_id}-{attempt}'
        os.mkdir(name, 0o700, dir_fd=fd)
    finally:
        os.close(fd)
    return temp / name


def _persist(root, result):
    with (root / 'result.json').open('xb') as stream:
        stream.write(_canonical({**result, 'audit_saved': True}))
        stream.flush(); os.fsync(stream.fileno())
    raw = _canonical({'result.json': archive._digest(root / 'result.json')})
    with (root / 'checksums.json').open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    for directory in (root, root.parent):
        fd = _directory(directory)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def run():
    result = {'schema_version': 1, 'purpose': PURPOSE, 'publication_state': 'BLOCKED_BEFORE_PUBLICATION',
              'audit_saved': False, 'research_baseline_approved': False, 'trusted_parent_registered': False,
              'fresh_replay': False, 'P8': 'BLOCKED', 'production_promotion': 'NOT_AUTHORIZED'}
    client = root = None
    try:
        d, request, policy = configuration()
        _checkout(d)
        client = _Publisher(os.environ.get('GITHUB_TOKEN'), d['repository'])
        # Establish dispatch identity BEFORE downloading any research material.
        subject, subject_sha = archival_subject(d, request, request['candidate'])
        actor = _context(d, policy, client, subject_sha, request['original']['run_id'])
        original = verify_original(client, d, request)
        result.update(repository=d['repository'], repository_id=d['repository_id'],
                      original=original, archival_operation=actor, subject=subject,
                      archival_subject_sha256=subject_sha, tag=subject['release_tag'])
        root = _output()
        with tempfile.TemporaryDirectory(prefix='historical-assets-', dir=root.parent) as temp:
            temp = Path(temp)
            _download(client, request, temp / 'original.zip')
            _extract(temp / 'original.zip', temp / 'artifact')
            o = request['original']
            prepared = archive.prepare(temp / 'artifact', temp / 'assets', run_id=o['run_id'], attempt=1,
                repository_id=d['repository_id'], head_sha=o['head_sha'], artifact_id=o['artifact_id'],
                artifact_digest=o['artifact_sha256'], repository=d['repository'])
            prepared['directory'] = str(temp / 'assets')
            verified_subject, verified_sha = archival_subject(d, request, prepared['manifest'])
            _need(verified_sha == subject_sha and verified_subject == subject, 'VERIFIED_SUBJECT_MISMATCH')
            result.update(candidate_id=prepared['manifest']['candidate_id'],
                quality_status=prepared['manifest']['quality_status'], q1_status=prepared['manifest']['q1_status'],
                research_review=prepared['manifest']['research_review'], technical_verification='PASS')
            def revalidate():
                _need(configuration() == (d, request, policy), 'DEPLOYMENT_OR_REQUEST_CHANGED')
                _checkout(d)
                _need(_context(d, policy, client, subject_sha, request['original']['run_id']) == actor, 'ARCHIVAL_AUTHORITY_CHANGED')
                _need(verify_original(client, d, request) == original, 'ORIGINAL_BINDINGS_CHANGED')
                _check_assets(prepared, request)
                fresh = _json((Path(prepared['directory']) / 'release-manifest.json').read_bytes())
                _need(archival_subject(d, request, fresh) == (subject, subject_sha), 'ARCHIVAL_SUBJECT_CHANGED')
            _publish(client, subject, prepared, revalidate, result)
    except Exception as error:
        reason = str(error)
        result['reason'] = reason if isinstance(error, (HistoricalArchiveError, owner.OwnerApprovalError)) and re.fullmatch('[A-Z][A-Z0-9_]{0,100}', reason) else 'HISTORICAL_ARCHIVAL_FAILED'
        if client is not None and result['publication_state'] != 'BLOCKED_BEFORE_PUBLICATION':
            _reconcile(client, result)
    if root is not None:
        result['output_directory'] = str(root)
        try:
            _persist(root, result)
            result['audit_saved'] = True
        except Exception:
            result['audit_error'] = 'AUDIT_PERSISTENCE_FAILED'
            # Best effort only; preserve the real publication state and never
            # retry a GitHub mutation because its audit record failed.
            try:
                with (root / 'audit-error.json').open('xb') as stream:
                    stream.write(_canonical(result)); stream.flush(); os.fsync(stream.fileno())
            except Exception:
                pass
    return result


def main(argv=None):
    import sys
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        result = {'publication_state': 'BLOCKED_BEFORE_PUBLICATION', 'audit_saved': False,
                  'reason': 'NO_ENTRY_POINT_ARGUMENTS_SUPPORTED', 'production_promotion': 'NOT_AUTHORIZED'}
    else:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result = run()
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if result['publication_state'] == 'PUBLISHED_IMMUTABLE_VERIFIED' and result['audit_saved'] else 1
