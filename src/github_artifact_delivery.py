"""Fetch one explicit personal-repository Actions artifact; never deploy it.

Run with --repository OWNER/REPO --run-id ID --attempt N --artifact-name NAME.
Uses existing gh authentication and the original ZIP, without extraction or
repacking. A verified download is transport evidence, not Corpus approval.
Receipts persist under doc/artifacts/; owned temporary ZIPs are always removed.
Exit 0 means the integration returned ELIGIBLE, 1 means blocked or delivery failed.
This is an on-demand command, not a background CI event receiver.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile
import zlib

from . import corpus_update_integration as integration
from . import update_eligibility_gate as gate

REPOSITORY = 'XiangruZhang007/SPHinX_AI_Assistant'
WORKFLOW = '.github/workflows/ci_v2_manual_research.yml'
RECEIPTS = Path(__file__).resolve().parents[1] / 'doc/artifacts'
MAX_ZIP_BYTES = 512 * 1024**2
MAX_EXPANDED_BYTES = 2 * 1024**3


class DeliveryError(ValueError):
    """Messages are local, bounded diagnostics, never raw gh stderr/redirects."""


def _need(condition, message):
    if not condition:
        raise DeliveryError(message)


def _positive(value):
    return type(value) is int and value > 0


def _sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def _hash(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


class GitHub:
    """Read-only gh API requests to github.com; no login or credential extraction."""

    def __init__(self):
        self.executable = shutil.which('gh')
        _need(self.executable is not None, 'GITHUB_UNAVAILABLE: gh is not installed')

    def _get(self, endpoint, output=None):
        base = 'repos/' + REPOSITORY
        _need(endpoint.startswith(base + '/actions/') or endpoint == base
              or re.fullmatch(re.escape(base) + r'/issues/(?:comments/[1-9][0-9]*|[1-9][0-9]*(?:/comments\?per_page=100&page=[1-9][0-9]*)?)', endpoint),
              'Unsupported GitHub endpoint')
        command = [self.executable, 'api', '--hostname', 'github.com', '--method', 'GET',
                   '-H', 'Accept: application/vnd.github+json', endpoint]
        try:
            # gh follows the API archive redirect using its existing authenticated
            # transport. No signed redirect URL or authentication output is logged.
            result = subprocess.run(command, stdout=output or subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=300 if output else 30)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise DeliveryError('GITHUB_UNAVAILABLE: gh request failed or timed out') from error
        _need(result.returncode == 0,
              'GITHUB_UNAVAILABLE: request denied, unavailable, missing or expired; no fallback used')
        return result.stdout

    def json(self, endpoint):
        return json.loads(self._get(endpoint), object_pairs_hook=gate._unique,
                          parse_constant=gate._reject_constant)

    def download(self, artifact_id, path):
        with path.open('xb') as output:
            self._get(f'repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip', output)


def _time(value):
    _need(isinstance(value, str), 'Missing attempt timestamp')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    _need(parsed.tzinfo is not None, 'Unqualified attempt timestamp')
    return parsed


def _resolve(client, run_id, attempt, name, expected_sha):
    prefix = f'repos/{REPOSITORY}/actions'
    run = client.json(f'{prefix}/runs/{run_id}/attempts/{attempt}')
    repo = run['repository']
    head_repo = run['head_repository']
    _need(repo['full_name'] == head_repo['full_name'] == REPOSITORY
          and _positive(repo['id']) and repo['id'] == head_repo['id'], 'Repository identity mismatch')
    _need(type(run['id']) is int and run['id'] == run_id
          and type(run['run_attempt']) is int and run['run_attempt'] == attempt,
          'Run or attempt identity mismatch')
    _need(run['path'] == WORKFLOW and run['event'] == 'workflow_dispatch'
          and run['status'] == 'completed', 'Unsupported or incomplete workflow run')
    _need(isinstance(run['head_sha'], str) and re.fullmatch('[0-9a-f]{40}', run['head_sha']),
          'Invalid workflow commit identity')
    start, end = _time(run['run_started_at']), _time(run['updated_at'])
    _need(start <= end, 'Invalid attempt time interval')
    matches = []
    total = None
    seen = 0
    for page in range(1, 101):
        listing = client.json(f'{prefix}/runs/{run_id}/artifacts?per_page=100&page={page}')
        count, artifacts = listing['total_count'], listing['artifacts']
        _need(type(count) is int and count >= 0 and isinstance(artifacts, list)
              and len(artifacts) <= 100, 'Invalid Artifact listing')
        _need(total is None or total == count, 'Artifact listing changed during pagination')
        total = count
        seen += len(artifacts)
        matches.extend(a for a in artifacts if a['name'] == name)
        if len(artifacts) < 100:
            break
    else:
        raise DeliveryError('Artifact listing exceeds supported pagination bound')
    _need(seen == total, 'Incomplete Artifact listing')
    _need(len(matches) == 1, 'Missing or ambiguous exact Artifact name')
    artifact = matches[0]
    _need(_positive(artifact['id']) and artifact['expired'] is False, 'Missing or expired Artifact')
    _need(type(artifact['size_in_bytes']) is int and 0 < artifact['size_in_bytes'] <= MAX_ZIP_BYTES,
          'Invalid or unsupported Artifact size')
    wr = artifact['workflow_run']
    _need(type(wr['id']) is int and wr['id'] == run_id
          and wr['repository_id'] == wr['head_repository_id'] == repo['id']
          and wr['head_sha'] == run['head_sha'], 'Artifact workflow identity mismatch')
    # Artifact metadata has no required attempt field. Bind the exact prescribed
    # name to the attempt-specific run and its upload time interval, conservatively.
    _need(start <= _time(artifact['created_at']) <= end, 'Artifact attempt binding not established')
    digest = artifact.get('digest')
    if digest is not None:
        _need(isinstance(digest, str) and digest.startswith('sha256:') and _sha(digest[7:]),
              'Invalid GitHub Artifact digest')
        _need(expected_sha is None or expected_sha == digest[7:], 'Independent digest pin mismatch')
        expected_sha = digest[7:]
    _need(_sha(expected_sha), 'No independently verifiable transport SHA-256')
    # Only allowlisted public identity fields survive into the permanent receipt.
    return {
        'repository': REPOSITORY, 'repository_id': repo['id'], 'run_id': run_id,
        'attempt': attempt, 'workflow': run['path'], 'workflow_head_sha': run['head_sha'],
        'run_status': run['status'], 'run_conclusion': run['conclusion'],
        'run_started_at': run['run_started_at'], 'run_updated_at': run['updated_at'],
        'artifact_id': artifact['id'], 'artifact_name': artifact['name'],
        'artifact_created_at': artifact['created_at'], 'size_bytes': artifact['size_in_bytes'],
        'expected_sha256': expected_sha,
        'digest_source': 'GITHUB_API' if digest is not None else 'INDEPENDENT_PIN',
        'attempt_binding': 'EXACT_NAME_RUN_ID_HEAD_SHA_AND_ATTEMPT_TIME_INTERVAL',
    }


def _verify_zip(path):
    # Reuse P8's canonical member/path/type checks. Never extract the archive.
    with ExitStack() as stack:
        evidence = gate._Evidence(path, stack)
        infos = evidence.archive.infolist()
        _need(0 < len(infos) <= 100000 and sum(i.file_size for i in infos) <= MAX_EXPANDED_BYTES,
              'Unsupported expanded ZIP size or member count')
        _need(all(not i.flag_bits & 1 and i.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                  for i in infos), 'Unsupported or encrypted ZIP member')
        _need(evidence.archive.testzip() is None, 'ZIP CRC integrity failure')


def _write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')


def deliver(repository, run_id, attempt, artifact_name, *, expected_sha256=None, evidence_root=RECEIPTS,
            research_review_config=None, research_review_config_sha256=None):
    """No auth/approval overrides. Tests inject gh responses, not production approvals."""
    _need(repository == REPOSITORY, 'Repository is outside the personal-repository allowlist')
    _need(_positive(run_id) and _positive(attempt), 'Run ID and attempt must be positive integers')
    _need(artifact_name == f'ci-v2-research-{run_id}-{attempt}', 'Unexpected Artifact name for attempt')
    _need(expected_sha256 is None or _sha(expected_sha256), 'Malformed expected transport SHA-256')
    _need((research_review_config is None) == (research_review_config_sha256 is None),
          'Research review configuration and its independent SHA-256 must be supplied together')
    evidence_root = Path(evidence_root)
    evidence_root.mkdir(parents=True, exist_ok=True)
    receipt = Path(tempfile.mkdtemp(prefix='github-delivery-' + datetime.now(timezone.utc)
                                    .strftime('%Y%m%dT%H%M%SZ-'), dir=evidence_root))
    summary = {'delivery': 'FAILED', 'decision': 'BLOCKED', 'repository': repository,
               'run_id': run_id, 'attempt': attempt, 'artifact_name': artifact_name,
               'candidate_id': None, 'p8_decision': 'NOT_EVALUATED', 'activation': 'DENIED',
               'gradio_reinitialization': 'NOT_ATTEMPTED', 'production_promotion': 'NOT_AUTHORIZED',
               'evidence_directory': str(receipt.resolve())}
    temporary = None
    try:
        client = GitHub()
        metadata = _resolve(client, run_id, attempt, artifact_name, expected_sha256)
        _write(receipt / 'transport-metadata.json', metadata)
        summary['transport'] = metadata
        with tempfile.TemporaryDirectory(prefix='sphinx-actions-delivery-') as directory:
            temporary = Path(directory)
            archive = temporary / 'artifact.zip'
            client.download(metadata['artifact_id'], archive)
            actual = _hash(archive)
            summary['artifact_sha256'] = actual
            _need(archive.stat().st_size == metadata['size_bytes'], 'Downloaded Artifact size mismatch')
            _need(actual == metadata['expected_sha256'], 'Downloaded Artifact SHA-256 mismatch')
            _verify_zip(archive)
            summary['delivery'] = 'VERIFIED'
            # The existing integration checks internal provenance and Corpus
            # bindings independently; transport success grants no authorization.
            with redirect_stdout(io.StringIO()):
                result = integration.run(archive)
            _write(receipt / 'integration-result.json', result)
            from .research_review import verify
            review = verify(archive, result, metadata, research_review_config,
                            research_review_config_sha256, client=client)
            _write(receipt / 'research-review.json', review)
            summary['research_review'] = review
            summary.update(decision=result['decision'], p8_decision=result['gate']['decision'],
                           candidate_id=result.get('bindings', {}).get('candidate_id'),
                           corpus_sha256=result.get('bindings', {}).get('corpus_sha256'),
                           activation=result['activation'],
                           gradio_reinitialization=result['gradio_reinitialization'],
                           internal_artifact_integrity=result['artifact_integrity'],
                           p8_reasons=result['gate']['reasons'],
                           selection_unchanged=result['selection_unchanged'])
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError,
            RuntimeError, zipfile.BadZipFile, zlib.error) as error:
        # Do not include external exception text (which may contain credentials).
        summary['error'] = str(error) if isinstance(error, DeliveryError) else type(error).__name__
    finally:
        summary['temporary_download_removed'] = temporary is None or not temporary.exists()
        summary['exit_code'] = 0 if summary['decision'] == 'ELIGIBLE' else 1
        _write(receipt / 'delivery-result.json', summary)
        files = sorted(receipt.iterdir())
        (receipt / 'SHA256SUMS').write_text(''.join(f'{_hash(p)}  {p.name}\n' for p in files), encoding='utf-8')
    return summary


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise DeliveryError(message)


def main(argv=None):
    parser = _Parser(description=__doc__)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--run-id', required=True, type=int)
    parser.add_argument('--attempt', required=True, type=int)
    parser.add_argument('--artifact-name', required=True)
    parser.add_argument('--expected-sha256', help='Independent transport pin, required if GitHub supplies no digest')
    parser.add_argument('--research-review-config', type=Path, help='Optional independent trust configuration in configs/')
    parser.add_argument('--research-review-config-sha256', help='Independent checksum of the research trust configuration')
    try:
        args = parser.parse_args(argv)
        result = deliver(args.repository, args.run_id, args.attempt, args.artifact_name,
                         expected_sha256=args.expected_sha256, research_review_config=args.research_review_config,
                         research_review_config_sha256=args.research_review_config_sha256)
    except (OSError, ValueError) as error:
        result = {'delivery': 'FAILED', 'decision': 'BLOCKED', 'activation': 'DENIED',
                  'gradio_reinitialization': 'NOT_ATTEMPTED', 'production_promotion': 'NOT_AUTHORIZED',
                  'error': str(error) if isinstance(error, DeliveryError) else type(error).__name__, 'exit_code': 1}
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
