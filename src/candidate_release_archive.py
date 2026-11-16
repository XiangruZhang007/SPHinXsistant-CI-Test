"""Prepare and publish immutable, Candidate-bound research archives.

Archiving is not a research approval, Trusted Parent registration, or production
release. Publication is an explicit CLI operation and the workflow keeps it
disabled unless the manual dispatch opt-in is true.
"""
from __future__ import annotations

import gzip
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile
import urllib.parse
import urllib.request

from . import trusted_snapshot

REPOSITORY = 'XiangruZhang007/SPHinXsistant-CI-Test'
WORKFLOW = '.github/workflows/ci_v2_manual_research.yml'
WORKFLOW_BRANCH = 'ci-upstream-refresh'
MAX_ARTIFACT_BYTES = 2 * 1024**3
MAX_EXPANDED_BYTES = 4 * 1024**3
API = 'https://api.github.com'
UPLOAD_HOST = 'uploads.github.com'


class ArchiveError(ValueError):
    """Safe, bounded error text suitable for workflow logs."""


def _need(value, message):
    if not value:
        raise ArchiveError(message)


def _sha(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def _canonical_artifact_digest(value):
    """Normalize upload-artifact's raw hex output and REST's sha256: form."""
    if isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value):
        return 'sha256:' + value
    if isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value):
        return value
    raise ArchiveError('Invalid GitHub Artifact digest')


def _digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def _json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def _safe_file(path):
    path = Path(path)
    _need(not path.is_symlink() and path.is_file(), 'Required regular file is missing or unsafe')
    return path


def _read_sealed_run(run):
    run = Path(run)
    _need(run.is_dir() and not run.is_symlink(), 'Research run directory is missing or unsafe')
    for path in run.rglob('*'):
        _need(not path.is_symlink(), 'Symlinks are not allowed in research evidence')
    checks_path = _safe_file(run / 'checksums.json')
    checks = _json(checks_path)
    _need(isinstance(checks, dict) and checks, 'Research run checksum manifest is missing or invalid')
    actual = {p.relative_to(run).as_posix() for p in run.rglob('*') if p.is_file() and p != checks_path}
    _need(actual == set(checks), 'Research run contains missing or undeclared evidence')
    for name, expected in checks.items():
        rel = PurePosixPath(name)
        _need(not rel.is_absolute() and '..' not in rel.parts and '\\' not in name
              and str(rel) == name and _sha(expected), 'Unsafe or malformed research evidence manifest')
        path = _safe_file(run.joinpath(*rel.parts))
        _need(_digest(path) == expected, 'Research evidence checksum mismatch')
    return checks


def _compare_candidate_archive(run, archive):
    """Match package_candidate()'s actual contract: archive the complete run tree."""
    run, archive = Path(run), _safe_file(archive)
    _need(run.is_dir() and not run.is_symlink(), 'Research run directory is missing or unsafe')
    expected = {p.relative_to(run).as_posix() for p in run.rglob('*') if p.is_file()}
    _need(all(not p.is_symlink() for p in run.rglob('*')), 'Research run contains a symlink')
    seen = set()
    expanded = 0
    try:
        with tarfile.open(archive, 'r:gz') as tar:
            for member in tar:
                rel = PurePosixPath(member.name)
                _need(member.isfile() and not rel.is_absolute() and '..' not in rel.parts
                      and '\\' not in member.name and str(rel) == member.name
                      and member.name not in seen, 'Candidate archive has unsafe or duplicate members')
                seen.add(member.name)
                expanded += member.size
                _need(expanded <= MAX_EXPANDED_BYTES, 'Candidate archive exceeds expanded size limit')
                source = tar.extractfile(member)
                target = run.joinpath(*rel.parts)
                _need(source is not None and target.is_file(), 'Candidate archive/member mismatch')
                h = hashlib.sha256(); size = 0
                with source, target.open('rb') as expected_stream:
                    while True:
                        left = source.read(1024 * 1024)
                        right = expected_stream.read(1024 * 1024)
                        _need(left == right, 'Candidate archive bytes differ from verified Candidate files')
                        if not left:
                            break
                        h.update(left); size += len(left)
                _need(size == member.size, 'Candidate archive size mismatch')
        _need(seen == expected, 'Candidate archive inventory differs from complete run files')
    except (OSError, tarfile.TarError) as error:
        raise ArchiveError('Candidate archive is unreadable or corrupt') from error


def validate_artifact(artifact_root, *, run_id, attempt, repository_id, head_sha,
                      artifact_id, artifact_digest, repository=REPOSITORY):
    """Validate complete existing run evidence without rebuilding or replaying R2."""
    artifact_digest = _canonical_artifact_digest(artifact_digest)
    _need(isinstance(repository, str)
          and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository),
          'Invalid expected repository')
    root = Path(artifact_root)
    _need(root.is_dir() and not root.is_symlink(), 'Downloaded Actions Artifact directory is missing')
    _need(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0
          and type(repository_id) is int and repository_id > 0 and type(artifact_id) is int and artifact_id > 0,
          'Invalid GitHub run/artifact identity')
    _need(re.fullmatch(r'[0-9a-f]{40}', head_sha or '') is not None, 'Invalid workflow commit')
    expected_root = {'candidate.tar.gz', 'plan.json', 'run'}
    allowed = expected_root | {'q1-transport.json'}
    entries = {p.name for p in root.iterdir()}
    _need(expected_root <= entries and entries <= allowed, 'Incomplete or unexpected Actions Artifact contents')
    for name in entries - {'run'}:
        _safe_file(root / name)
    plan = _json(_safe_file(root / 'plan.json'))
    run = root / 'run'
    checks = _read_sealed_run(run)
    candidate_archive = _safe_file(root / 'candidate.tar.gz')
    result = _json(_safe_file(run / 'result.json'))
    parity = _json(_safe_file(run / 'parity.json'))
    verification = _json(_safe_file(run / 'execution-verification/verification.json'))
    quality = _json(_safe_file(run / 'quality/quality-report.json'))
    candidate = _json(_safe_file(run / 'candidate/candidate.json'))
    provenance = _json(_safe_file(run / 'candidate/upstream-candidate.json'))
    q1 = _json(_safe_file(run / 'q1-status.json'))
    _compare_candidate_archive(run, candidate_archive)

    identity = provenance.get('identity', {})
    candidate_identity = candidate.get('identity', {})
    bindings = result.get('bindings', {})
    corpus_sha = _digest(run / 'candidate/corpus.jsonl')
    candidate_id = candidate.get('candidate_id')
    _need(isinstance(candidate_id, str) and re.fullmatch(r'sha256-[0-9a-f]{64}', candidate_id)
          and candidate_id == provenance.get('candidate_id') == result.get('candidate_id')
          == bindings.get('candidate_id') == parity.get('candidate_id'), 'Candidate identity binding mismatch')
    _need(corpus_sha == bindings.get('target_corpus_sha256') == quality.get('corpus_sha256')
          == verification.get('candidate_corpus_sha256') == verification.get('full_corpus_sha256'),
          'Candidate Corpus checksum binding mismatch')
    _need(result.get('STRUCTURAL_PARITY') == 'PASS' and parity.get('status') == 'PARITY_PASS'
          and parity.get('full_reference_independently_built') is True
          and verification.get('status') == 'VERIFIED', 'Required technical verification did not pass')
    _need(verification.get('independent_replay_combinations') == verification.get('original_combinations')
          and type(verification.get('independent_replay_combinations')) is int
          and verification['independent_replay_combinations'] > 0,
          'Independent retrieval replay evidence is incomplete')
    _need(quality.get('status') == result.get('retrieval_quality')
          and quality.get('candidate_id') == candidate_id and quality.get('assessment') == 'FROZEN_128_EVALUATED'
          and quality.get('independent_candidate_full_rows_equal') is True,
          'Quality evidence is missing or inconsistently bound')
    _need(candidate_identity == identity,
          'Candidate and upstream-provenance identity records differ')
    _need(_sha(bindings.get('build_fingerprint'))
          and candidate_identity.get('build_fingerprint') == bindings['build_fingerprint']
          and quality.get('build_fingerprint') == bindings['build_fingerprint'],
          'Build fingerprint binding is missing or inconsistent')
    _need(_sha(bindings.get('benchmark_sha256'))
          and _digest(run / 'benchmark.json') == bindings['benchmark_sha256'],
          'Frozen benchmark checksum binding is missing or inconsistent')
    _need(_sha(bindings.get('target_rows_sha256'))
          and quality.get('raw_results_sha256') == bindings['target_rows_sha256']
          and _digest(run / 'quality/incremental-raw-results.json') == bindings['target_rows_sha256'],
          'Candidate retrieval-result checksum binding is missing or inconsistent')
    _need(_sha(bindings.get('base_rows_sha256'))
          and _digest(run / 'parent-raw-results.json') == bindings['base_rows_sha256'],
          'Parent retrieval-result checksum binding is missing or inconsistent')
    _need(q1.get('status') == result.get('Q1', {}).get('status'), 'Q1 status binding mismatch')
    _need(result.get('research_baseline_created') is False
          and result.get('RESEARCH_BASELINE_APPROVED') is False
          and result.get('automatic_research_approval') is False
          and result.get('automatic_reuse') is False
          and result.get('production_promotion') == 'NOT_AUTHORIZED'
          and verification.get('production_promotion') == 'NOT_AUTHORIZED',
          'Candidate evidence contains an unsupported approval or promotion state')
    _need(identity.get('candidate_id', candidate_id) == candidate_id
          and isinstance(identity.get('upstreams'), dict)
          and set(identity['upstreams']) == {'SPHinXsys', 'SPHinXsim'}
          and all(re.fullmatch(r'[0-9a-f]{40}', x or '') for x in identity['upstreams'].values()),
          'Candidate source revision identity is incomplete')
    _need(candidate_identity.get('parent', {}).get('node_id') == result.get('baseline_id')
          and candidate_identity.get('generation') == identity.get('generation')
          and candidate_identity.get('target_source_state') == result.get('target_source_state')
          and candidate_identity.get('upstreams') == identity.get('upstreams')
          and result.get('bindings', {}).get('target_upstreams') == identity.get('upstreams')
          and result.get('bindings', {}).get('base_upstreams') == candidate_identity.get('base_upstreams')
          and result.get('bindings', {}).get('base_source_state') == candidate_identity.get('base_source_state')
          and isinstance(candidate_identity.get('base_source_state'), str)
          and re.fullmatch(r'sha256-[0-9a-f]{64}', candidate_identity['base_source_state'])
          and isinstance(result.get('baseline_id'), str)
          and re.fullmatch(r'sha256-[0-9a-f]{64}', result['baseline_id'])
          and isinstance(result.get('target_source_state'), str)
          and re.fullmatch(r'sha256-[0-9a-f]{64}', result['target_source_state']),
          'Candidate Parent, generation, or source-state identity mismatch')
    _need(plan.get('upstreams') == identity['upstreams'], 'Plan and Candidate source revisions differ')
    _need(identity.get('parent') == {'kind': 'RESEARCH_BASELINE', 'node_id': result.get('baseline_id')}
          or (isinstance(identity.get('parent'), dict)
              and identity['parent'].get('node_id') == result.get('baseline_id')),
          'Candidate Parent identity does not match the run result')
    _need(type(identity.get('generation')) is int and identity['generation'] > 0,
          'Candidate generation is missing')
    _need(result.get('target_source_state') == bindings.get('target_source_state'),
          'Candidate source-state binding mismatch')

    return {
        'schema_version': 1,
        'archive_kind': 'CI_V2_RESEARCH_CANDIDATE_ARCHIVE',
        'archive_status': 'ARCHIVED_RESEARCH_CANDIDATE',
        'technical_verification': 'PASS',
        'repository': repository,
        'repository_id': repository_id,
        'workflow': WORKFLOW,
        'run_id': run_id,
        'run_attempt': attempt,
        'workflow_commit': head_sha,
        'actions_artifact_id': artifact_id,
        'actions_artifact_digest': artifact_digest,
        'candidate_id': candidate_id,
        'corpus_sha256': corpus_sha,
        'parent_id': result['baseline_id'],
        'generation': identity['generation'],
        'source_state': result['target_source_state'],
        'upstreams': identity['upstreams'],
        'build_fingerprint': bindings['build_fingerprint'],
        'benchmark_sha256': bindings['benchmark_sha256'],
        'quality_status': quality['status'],
        'q1_status': q1['status'],
        'research_review': result.get('hosted_validation', 'PENDING_HOSTED_REVIEW'),
        'candidate_archive': {'name': 'candidate.tar.gz', 'size_bytes': candidate_archive.stat().st_size,
                              'sha256': _digest(candidate_archive)},
        'evidence_files': len(checks) + 1,
        'approval': {
            'research_baseline_approved': False,
            'trusted_parent_registered': False,
            'automatic_research_approval': False,
            'production_promotion': 'NOT_AUTHORIZED',
        },
    }


def _write_json(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                separators=(',', ':'), allow_nan=False) + '\n')


def _tar_info(path, arcname):
    info = tarfile.TarInfo(arcname)
    st = Path(path).stat()
    info.size = st.st_size
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ''
    info.mode = 0o644
    return info


def _deterministic_evidence_tar(root, destination):
    root, destination = Path(root), Path(destination)
    files = [root / 'plan.json'] + sorted((root / 'run').rglob('*'))
    files = [p for p in files if p.is_file()]
    _need(files and all(not p.is_symlink() for p in files), 'Evidence package contains no regular files or contains symlinks')
    with destination.open('xb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0, compresslevel=6) as gz:
            with tarfile.open(fileobj=gz, mode='w|', format=tarfile.GNU_FORMAT) as tar:
                for path in files:
                    name = 'plan.json' if path.name == 'plan.json' and path.parent == root else 'run/' + path.relative_to(root / 'run').as_posix()
                    with path.open('rb') as stream:
                        tar.addfile(_tar_info(path, name), stream)
        raw.flush()
        os.fsync(raw.fileno())


def prepare(artifact_root, destination, *, run_id, attempt, repository_id, head_sha,
            artifact_id, artifact_digest, repository=REPOSITORY):
    """Create deterministic publication assets locally; does not contact GitHub."""
    root, dest = Path(artifact_root), Path(destination)
    _need(not dest.exists() and not dest.is_symlink() and dest.parent.is_dir(),
          'Archive output must be a new directory under an existing parent')
    manifest = validate_artifact(root, run_id=run_id, attempt=attempt, repository_id=repository_id,
                                 head_sha=head_sha, artifact_id=artifact_id, artifact_digest=artifact_digest,
                                 repository=repository)
    dest.mkdir()
    try:
        candidate = root / 'candidate.tar.gz'
        shutil.copyfile(candidate, dest / 'candidate.tar.gz')
        _need(_digest(dest / 'candidate.tar.gz') == manifest['candidate_archive']['sha256'],
              'Candidate asset changed while staging')
        _deterministic_evidence_tar(root, dest / 'research-evidence.tar.gz')
        manifest['assets'] = {
            'candidate.tar.gz': {'size_bytes': (dest / 'candidate.tar.gz').stat().st_size,
                                 'sha256': _digest(dest / 'candidate.tar.gz')},
            'research-evidence.tar.gz': {'size_bytes': (dest / 'research-evidence.tar.gz').stat().st_size,
                                         'sha256': _digest(dest / 'research-evidence.tar.gz')},
        }
        _write_json(dest / 'release-manifest.json', manifest)
        manifest_sha = _digest(dest / 'release-manifest.json')
        return {'manifest': manifest, 'manifest_sha256': manifest_sha,
                'assets': {p.name: {'size_bytes': p.stat().st_size, 'sha256': _digest(p)}
                           for p in sorted(dest.iterdir()) if p.is_file()}}
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise


class GitHubReleasePublisher:
    """Minimal token-scoped GitHub API client for one draft-to-immutable Release."""

    def __init__(self, token, repository=REPOSITORY):
        _need(isinstance(token, str) and token and not any(c.isspace() for c in token),
              'GitHub authorization is missing or malformed')
        _need(repository == REPOSITORY, 'Publication repository is not the pinned private repository')
        self.token = token
        self.repository = repository

    def _api(self, method, endpoint, payload=None, *, allow_404=False):
        _need(endpoint.startswith('/repos/' + self.repository + '/') or endpoint == '/repos/' + self.repository,
              'Unsupported GitHub API path')
        url = API + endpoint
        data = None if payload is None else json.dumps(payload, separators=(',', ':')).encode()
        request = urllib.request.Request(url, data=data, method=method, headers={
            'Accept': 'application/vnd.github+json', 'Authorization': 'Bearer ' + self.token,
            'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'SPHinXsistant-CI-V2-archive',
            **({'Content-Type': 'application/json'} if data is not None else {})})
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        try:
            response = urllib.request.build_opener(NoRedirect()).open(request, timeout=60)
            with response:
                raw = response.read(4 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            if status == 404 and allow_404:
                return None
            raise ArchiveError('GitHub API request failed; authorization, repository, or endpoint unavailable') from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ArchiveError('GitHub API request failed; no credential or URL details logged') from None
        _need(len(raw) <= 4 * 1024 * 1024, 'GitHub API response exceeded the size limit')
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ArchiveError('GitHub API returned invalid JSON') from None

    def _upload(self, upload_url, release_id, path):
        expected_prefix = f'/repos/{self.repository}/releases/{release_id}/assets'
        bases = (f'https://{UPLOAD_HOST}{expected_prefix}',
                 f'https://{UPLOAD_HOST}:443{expected_prefix}')
        # GitHub returns a URI template; accept only its exact known suffix.
        _need(isinstance(upload_url, str)
              and any(upload_url in (base, base + '{?name,label}') for base in bases),
              'GitHub returned an unsafe Release upload URL')
        name = Path(path).name
        target = expected_prefix + '?name=' + urllib.parse.quote(name, safe='')
        conn = http.client.HTTPSConnection(UPLOAD_HOST, timeout=300)
        try:
            conn.putrequest('POST', target)
            conn.putheader('Authorization', 'Bearer ' + self.token)
            conn.putheader('Accept', 'application/vnd.github+json')
            conn.putheader('Content-Type', 'application/gzip' if name.endswith('.gz') else 'application/json')
            conn.putheader('Content-Length', str(Path(path).stat().st_size))
            conn.endheaders()
            with Path(path).open('rb') as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    conn.send(block)
            response = conn.getresponse()
            raw = response.read(4 * 1024 * 1024 + 1)
            _need(response.status == 201 and len(raw) <= 4 * 1024 * 1024,
                  'GitHub Release asset upload failed')
            try:
                return json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise ArchiveError('GitHub upload endpoint returned invalid metadata') from None
        except ArchiveError:
            raise
        except (OSError, http.client.HTTPException, TimeoutError):
            raise ArchiveError('GitHub Release asset upload failed; token and network details suppressed') from None
        finally:
            conn.close()

    def _verify_asset(self, release_id, asset, path):
        _need(type(asset.get('id')) is int and asset.get('name') == Path(path).name
              and type(asset.get('size')) is int and asset['size'] == Path(path).stat().st_size
              and asset.get('state') == 'uploaded', 'Uploaded Release asset identity/size mismatch')
        expected = _digest(path)
        if asset.get('digest') is not None:
            _need(asset['digest'] == 'sha256:' + expected, 'Uploaded Release asset digest mismatch')
        else:
            url = API + f'/repos/{self.repository}/releases/assets/{asset["id"]}'
            try:
                with trusted_snapshot._request(url, binary=True, token=self.token) as stream:
                    h = hashlib.sha256(); size = 0
                    for block in iter(lambda: stream.read(1024 * 1024), b''):
                        size += len(block)
                        _need(size <= asset['size'], 'Downloaded Release asset exceeded its pinned size')
                        h.update(block)
            except Exception as error:
                if isinstance(error, ArchiveError):
                    raise
                raise ArchiveError('Could not independently verify uploaded Release asset') from None
            _need(size == asset['size'] and h.hexdigest() == expected,
                  'Downloaded Release asset bytes do not match the local asset')
        return {'asset_id': asset['id'], 'name': asset['name'], 'size_bytes': asset['size'], 'sha256': expected}

    def verify_origin(self, *, run_id, attempt, head_sha, artifact_id, artifact_digest):
        """Bind files to this attempt and its successfully completed candidate job.

        The workflow run itself is expected to remain in progress while its
        archive-candidate job is publishing. The upstream candidate job is the
        completed unit whose successful result authorizes archival to proceed.
        """
        artifact_digest = _canonical_artifact_digest(artifact_digest)
        repo = self._api('GET', '/repos/' + self.repository)
        _need(repo.get('full_name') == self.repository and type(repo.get('id')) is int
              and repo.get('private') is True, 'Repository identity or private visibility check failed')
        run = self._api('GET', f'/repos/{self.repository}/actions/runs/{run_id}/attempts/{attempt}')
        _need(type(run.get('id')) is int and run['id'] == run_id
              and type(run.get('run_attempt')) is int and run['run_attempt'] == attempt
              and run.get('path') == WORKFLOW and run.get('event') == 'workflow_dispatch'
              and run.get('head_branch') == WORKFLOW_BRANCH
              and run.get('status') == 'in_progress'
              and run.get('head_sha') == head_sha,
              'Workflow run is not the exact in-progress dispatch/commit')
        for key in ('repository', 'head_repository'):
            identity = run.get(key, {})
            _need(identity.get('id') == repo['id'] and identity.get('full_name') == self.repository,
                  'Workflow run repository identity mismatch')
        jobs = self._api('GET',
                         f'/repos/{self.repository}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100&page=1')
        job_rows = jobs.get('jobs')
        total_jobs = jobs.get('total_count')
        _need(type(total_jobs) is int and 0 <= total_jobs <= 100
              and isinstance(job_rows, list) and len(job_rows) == total_jobs,
              'Workflow attempt job inventory is incomplete or unsupported')
        candidate_jobs = [job for job in job_rows if job.get('name') == 'candidate']
        _need(len(candidate_jobs) == 1, 'Workflow attempt does not contain exactly one candidate job')
        candidate_job = candidate_jobs[0]
        _need(type(candidate_job.get('id')) is int and candidate_job['id'] > 0
              and candidate_job.get('run_id') == run_id
              and candidate_job.get('head_sha') == head_sha
              and candidate_job.get('head_branch') == WORKFLOW_BRANCH
              and candidate_job.get('status') == 'completed'
              and candidate_job.get('conclusion') == 'success',
              'Candidate job for this workflow attempt has not completed successfully')
        artifact = self._api('GET', f'/repos/{self.repository}/actions/artifacts/{artifact_id}')
        expected_name = f'ci-v2-research-{run_id}-{attempt}'
        _need(type(artifact.get('id')) is int and artifact['id'] == artifact_id
              and artifact.get('name') == expected_name and artifact.get('expired') is False
              and type(artifact.get('size_in_bytes')) is int and 0 < artifact['size_in_bytes'] <= MAX_ARTIFACT_BYTES
              and artifact.get('digest') == artifact_digest,
              'Actions Artifact identity, digest, or size mismatch')
        wr = artifact.get('workflow_run', {})
        _need(wr.get('id') == run_id and wr.get('repository_id') == repo['id']
              and wr.get('head_repository_id') == repo['id'] and wr.get('head_sha') == head_sha,
              'Actions Artifact is not bound to the expected workflow run')
        return {'repository_id': repo['id'], 'candidate_job_id': candidate_job['id'],
                'candidate_job_status': candidate_job['status'],
                'candidate_job_conclusion': candidate_job['conclusion'],
                'artifact_name': expected_name,
                'artifact_size_bytes': artifact['size_in_bytes'], 'artifact_digest': artifact_digest}

    def publish(self, prepared, *, run_id, attempt, head_sha, candidate_id):
        repo = self._api('GET', '/repos/' + self.repository)
        _need(repo.get('full_name') == self.repository and type(repo.get('id')) is int
              and repo.get('private') is True, 'Repository identity or private visibility check failed')
        _need(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0
              and re.fullmatch(r'[0-9a-f]{40}', head_sha or '')
              and re.fullmatch(r'sha256-[0-9a-f]{64}', candidate_id or ''), 'Invalid publication identity')
        prefix = candidate_id.removeprefix('sha256-')[:8]
        tag = f'ci-v2-research-run-{run_id}-attempt-{attempt}-{prefix}'
        encoded_tag = urllib.parse.quote(tag, safe='')
        existing_release = self._api('GET', f'/repos/{self.repository}/releases/tags/{encoded_tag}', allow_404=True)
        existing_ref = self._api('GET', f'/repos/{self.repository}/git/ref/tags/{encoded_tag}', allow_404=True)
        _need(existing_release is None and existing_ref is None,
              'Release tag already exists; refusing to overwrite or reuse it')
        manifest = prepared['manifest']
        title = f'CI V2 Research Candidate {candidate_id[-8:]} (Run {run_id}.{attempt})'
        body = ('Research Candidate archive only. Technical verification passed. '
                f'Research review: {manifest["research_review"]}. Quality: {manifest["quality_status"]}. '
                'This Release is not a Trusted Parent and grants no approval or production authorization. '
                'Automatic baseline registration is disabled.')
        release = self._api('POST', '/repos/' + self.repository + '/releases', {
            'tag_name': tag, 'target_commitish': head_sha, 'name': title, 'body': body,
            'draft': True, 'prerelease': True, 'generate_release_notes': False})
        _need(type(release.get('id')) is int and release.get('tag_name') == tag
              and release.get('draft') is True and release.get('target_commitish') == head_sha,
              'GitHub did not create the expected draft Release')
        release_id = release['id']
        uploaded = []
        # Manifest is uploaded last and binds the payload assets, avoiding a
        # self-referential checksum. Its own digest is recorded in the receipt.
        paths = [Path(prepared['directory']) / name for name in ('candidate.tar.gz', 'research-evidence.tar.gz', 'release-manifest.json')]
        try:
            for path in paths:
                asset = self._upload(release['upload_url'], release_id, path)
                uploaded.append(self._verify_asset(release_id, asset, path))
        except ArchiveError:
            raise ArchiveError(f'Draft Release {release_id} remains unpublished after partial upload/verification failure') from None
        draft_check = self._api('GET', f'/repos/{self.repository}/releases/{release_id}')
        _need(draft_check.get('draft') is True and draft_check.get('tag_name') == tag
              and len(draft_check.get('assets', [])) == len(paths),
              'Draft Release asset inventory mismatch; leaving it unpublished')
        published = self._api('PATCH', f'/repos/{self.repository}/releases/{release_id}', {'draft': False})
        final = self._api('GET', f'/repos/{self.repository}/releases/{release_id}')
        _need(final.get('draft') is False and final.get('tag_name') == tag
              and final.get('immutable') is True and published.get('id') == release_id,
              f'Release {release_id} was published but immutable status was not confirmed')
        return {'status': 'PUBLISHED_IMMUTABLE_RESEARCH_ARCHIVE', 'tag': tag,
                'release_id': release_id, 'immutable': True, 'draft': False,
                'repository_id': repo['id'], 'assets': uploaded}


def publish_from_environment(artifact_root, output_dir, *, repository, run_id, attempt,
                             head_sha, artifact_id, artifact_digest, token):
    _need(repository == REPOSITORY and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY,
          'Workflow repository does not match the pinned private repository')
    repository_id = os.environ.get('GITHUB_REPOSITORY_ID')
    _need(repository_id and repository_id.isdigit(), 'Workflow repository ID is missing')
    output = Path(output_dir)
    _need(not output.exists() and not output.is_symlink() and output.parent.is_dir(),
          'Receipt output must be a new directory under an existing parent')
    output.mkdir()
    prep_dir = Path(tempfile.mkdtemp(prefix='ci-v2-release-assets-', dir=Path(output_dir).parent))
    try:
        publisher = GitHubReleasePublisher(token, repository)
        origin = publisher.verify_origin(run_id=run_id, attempt=attempt, head_sha=head_sha,
                                         artifact_id=artifact_id, artifact_digest=artifact_digest)
        _need(origin['repository_id'] == int(repository_id), 'Workflow repository ID differs from GitHub API')
        prepared = prepare(artifact_root, prep_dir / 'assets', run_id=run_id, attempt=attempt,
                           repository_id=int(repository_id), head_sha=head_sha, artifact_id=artifact_id,
                           artifact_digest=artifact_digest)
        prepared['directory'] = str(prep_dir / 'assets')
        result = publisher.publish(prepared, run_id=run_id, attempt=attempt,
                    head_sha=head_sha, candidate_id=prepared['manifest']['candidate_id'])
        receipt = {**result, 'candidate_id': prepared['manifest']['candidate_id'],
                   'origin': origin,
                   'manifest_sha256': prepared['manifest_sha256'], 'asset_manifest': prepared['assets'],
                   'technical_verification': 'PASS', 'research_review': prepared['manifest']['research_review'],
                   'quality_status': prepared['manifest']['quality_status'], 'q1_status': prepared['manifest']['q1_status'],
                   'research_baseline_created': False, 'trusted_parent_registered': False,
                   'production_promotion': 'NOT_AUTHORIZED'}
        _write_json(output / 'release-receipt.json', receipt)
        return receipt
    finally:
        shutil.rmtree(prep_dir, ignore_errors=True)
