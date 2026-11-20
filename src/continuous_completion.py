"""Private immutable completion transport; never an approval or Parent Registry.

Schema 3 requires a retained receipt pin. Schema 4 can instead delegate technical
completion trust to explicitly reviewed repository Release writers and producer
deployments. API observations are not cryptographic producer attestations.
"""
import hashlib
from pathlib import Path
import re
import shutil
import tempfile
from urllib.parse import quote

from . import ci_v2_research as c, trusted_snapshot as trust
from . import candidate_release_archive as archive
from .corpus_snapshot import digest, file_digest, read_json, write_json

STATES = ('NOT_STARTED', 'BUILDING', 'BUILD_VERIFIED', 'PUBLISHING', 'PUBLISHED_AND_VERIFIED')
ASSETS = ('candidate.tar.gz', 'release-manifest.json', 'completion.json')
TRUST_MODEL = 'MAINTAINER_GOVERNED_RELEASE_WRITERS'
AUTHORITY_FIELDS = {'schema_version', 'trust_model', 'workflow_id', 'publisher_actor_id',
                    'release_prefix', 'previous_producers'}


def validate_authority(config):
    """Closed, independently pinned deployment authority; never Candidate input."""
    value = config.get('completion_authority')
    need(isinstance(value, dict) and set(value) == AUTHORITY_FIELDS
         and type(value['schema_version']) is int and value['schema_version'] == 1
         and value['trust_model'] == TRUST_MODEL, 'INVALID_COMPLETION_AUTHORITY')
    need(all(type(value[k]) is int and value[k] > 0 for k in ('workflow_id', 'publisher_actor_id')),
         'INVALID_COMPLETION_AUTHORITY_IDENTITY')
    tag(value['release_prefix'], '0' * 64)
    previous = value['previous_producers']
    need(isinstance(previous, list) and len(previous) <= 32, 'INVALID_PREVIOUS_PRODUCERS')
    seen = {config['implementation_revision']}
    for producer in previous:
        need(isinstance(producer, dict) and set(producer) == {
            'implementation_revision', 'deployment_sha256', 'execution_contract_sha256'}
             and isinstance(producer['implementation_revision'], str)
             and re.fullmatch('[0-9a-f]{40}', producer['implementation_revision'])
             and all(isinstance(producer[k], str) and re.fullmatch('[0-9a-f]{64}', producer[k])
                     for k in ('deployment_sha256', 'execution_contract_sha256')),
             'INVALID_PREVIOUS_PRODUCER_PIN')
        need(producer['implementation_revision'] not in seen, 'DUPLICATE_PRODUCER_AUTHORITY')
        seen.add(producer['implementation_revision'])
    return value


def need(ok, reason):
    c.need(ok, reason, reason)


class Client(archive.GitHubReleasePublisher):
    """Reuse safe API/upload/download handling, with deployment-specific identity."""
    def __init__(self, repository, token):
        need(isinstance(repository, str) and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository), 'INVALID_PUBLICATION_REPOSITORY')
        need(isinstance(token, str) and token and not any(ch.isspace() for ch in token), 'PUBLICATION_AUTHORIZATION_UNAVAILABLE')
        self.repository, self.token = repository, token


def tag(prefix, execution_key):
    need(isinstance(prefix, str) and re.fullmatch('[a-z][a-z0-9-]{0,39}', prefix)
         and isinstance(execution_key, str) and re.fullmatch('[0-9a-f]{64}', execution_key), 'INVALID_COMPLETION_KEY')
    return prefix + '-' + execution_key


def origin(client, config, run_id, attempt):
    """Completed BUILD job, not the unfinished overall publishing workflow."""
    need(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt == 1, 'INVALID_BUILD_ATTEMPT')
    base = '/repos/' + config['repository']
    repo = client._api('GET', base)
    need(trust.repository_identity(repo, config['repository'], config['repository_id']),
         'COMPLETION_REPOSITORY_MISMATCH')
    run = client._api('GET', base + f'/actions/runs/{run_id}/attempts/{attempt}')
    need(run.get('id') == run_id and run.get('run_attempt') == attempt
         and run.get('event') in ('schedule', 'workflow_dispatch')
         and run.get('head_sha') == config['implementation_revision']
         and run.get('head_branch') == config['default_branch']
         and run.get('repository', {}).get('id') == config['repository_id']
         and run.get('repository', {}).get('full_name') == config['repository']
         and run.get('path') == config['workflow_path'], 'COMPLETION_RUN_MISMATCH')
    definition = client._api('GET', base + '/actions/workflows/' + str(run.get('workflow_id')))
    need(definition.get('id') == run.get('workflow_id') and definition.get('path') == config['workflow_path'], 'COMPLETION_WORKFLOW_MISMATCH')
    jobs = client._api('GET', base + f'/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100&page=1')
    rows = jobs.get('jobs'); count = jobs.get('total_count')
    need(type(count) is int and 0 <= count <= 100 and isinstance(rows, list) and len(rows) == count,
         'INCOMPLETE_BUILD_JOB_INVENTORY')
    matches = [job for job in rows if job.get('name') == 'continuous-candidate']
    need(len(matches) == 1, 'MISSING_OR_AMBIGUOUS_BUILD_JOB')
    job = matches[0]
    need(type(job.get('id')) is int and job['id'] > 0 and job.get('run_id') == run_id
         and job.get('head_sha') == config['implementation_revision']
         and job.get('status') == 'completed' and job.get('conclusion') == 'success', 'BUILD_JOB_NOT_SUCCESSFUL')
    return {'repository': config['repository'], 'repository_id': config['repository_id'],
            'workflow_path': config['workflow_path'], 'workflow_id': definition['id'],
            'implementation_revision': config['implementation_revision'], 'run_id': run_id,
            'run_attempt': attempt, 'job_id': job['id'], 'event': run['event']}


def prepare(project, delivery, destination, *, pins, transport_sha256, verified_origin, artifact_transport=None):
    """The caller must obtain pins/transport digest from verified BUILD output."""
    from . import genuine_continuous_execution as g
    delivery, destination = Path(delivery), Path(destination)
    need(set(pins) == g.PIN_FIELDS, 'INVALID_COMPLETION_PINS')
    verified = g.verify_package(project, delivery / 'run', **pins)
    c.check_archive(delivery / 'candidate.tar.gz', transport_sha256)
    with tempfile.TemporaryDirectory(prefix='completion-compare-') as temp:
        extracted = Path(temp) / 'run'
        trust.extract_regular(delivery / 'candidate.tar.gz', extracted, transport_sha256)
        need(g.v1._files(extracted) == g.v1._files(delivery / 'run')
             and all(file_digest(extracted / name) == file_digest(delivery / 'run' / name)
                     for name in g.v1._files(extracted)), 'COMPLETION_ARCHIVE_PAYLOAD_MISMATCH')
    authority = read_json(delivery / 'run/evidence/authorization-context.json')
    config = read_json(delivery / 'run/evidence/deployment.json'); actor = authority['workflow_run']
    need(all(verified_origin.get(k) == config[k] for k in ('repository', 'repository_id', 'workflow_path', 'implementation_revision'))
         and verified_origin.get('run_id') == actor['run_id'] and verified_origin.get('run_attempt') == actor['run_attempt']
         and verified_origin.get('workflow_id') == actor['workflow_id'] and verified_origin.get('event') == actor['event']
         and type(verified_origin.get('job_id')) is int and verified_origin['job_id'] > 0, 'PACKAGE_BUILD_ORIGIN_MISMATCH')
    key = authority['parent_comparison']['execution_key']
    need(not destination.exists() and not destination.is_symlink() and destination.parent.is_dir(), 'INVALID_ARCHIVE_PREPARATION_OUTPUT')
    destination.mkdir()
    shutil.copyfile(delivery / 'candidate.tar.gz', destination / 'candidate.tar.gz')
    manifest = {'schema_version': 1, 'kind': 'GENUINE_CONTINUOUS_RESEARCH_ARCHIVE',
        'format': verified['format'], 'candidate_id': verified['candidate_id'], 'corpus_sha256': verified['corpus_sha256'],
        'generation': verified['generation'], 'parent_id': verified['parent_id'], 'upstreams': verified['upstreams'],
        'source_state': verified['source_state'], 'execution_key': key, 'verification_pins': pins,
        'candidate_archive': {'sha256': transport_sha256, 'size': (destination / 'candidate.tar.gz').stat().st_size},
        'build_origin': verified_origin, 'original_artifact': artifact_transport,
        'quality': 'QUALITY_REVIEW_REQUIRED', 'Q1': 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR',
        'research_approval': 'NOT_GRANTED', 'trusted_parent_eligibility': 'NOT_GRANTED', 'production_promotion': 'NOT_AUTHORIZED'}
    write_json(destination / 'release-manifest.json', manifest)
    receipt = {'schema_version': 1, 'state': 'BUILD_VERIFIED', 'execution_key': key,
               'manifest_sha256': file_digest(destination / 'release-manifest.json'), 'build_origin': verified_origin}
    write_json(destination / 'completion.json', receipt)
    return {'directory': str(destination), 'manifest': manifest, 'receipt': receipt,
            'receipt_sha256': file_digest(destination / 'completion.json')}


def _download(client, asset, path, expected):
    need(type(asset.get('id')) is int and asset['id'] > 0 and asset.get('state') == 'uploaded'
         and type(asset.get('size')) is int and 0 < asset['size'] <= 2 * 1024**3, 'INVALID_COMPLETION_ASSET')
    if asset.get('digest') is not None:
        need(asset['digest'] == 'sha256:' + expected, 'COMPLETION_ASSET_DIGEST_MISMATCH')
    url = archive.API + f'/repos/{client.repository}/releases/assets/{asset["id"]}'
    with trust._request(url, binary=True, token=client.token) as response, path.open('xb') as target:
        size = 0
        while block := response.read(1024**2):
            size += len(block); need(size <= asset['size'], 'OVERSIZED_COMPLETION_ASSET'); target.write(block)
    need(size == asset['size'] and file_digest(path) == expected, 'COMPLETION_ASSET_HASH_MISMATCH')


def verify_completed(project, client, config, release, execution_key, *, expected_receipt_sha256,
                     producer_pins=None):
    """Authenticated expected bytes + API observations + full sealed verification.

    producer_pins is supplied only after independently configured producer trust
    has been checked. It never substitutes for a live consumer authorization.
    """
    from . import genuine_continuous_execution as g
    need(isinstance(expected_receipt_sha256, str) and re.fullmatch('[0-9a-f]{64}', expected_receipt_sha256),
         'INDEPENDENT_COMPLETION_WITNESS_REQUIRED')
    need(release.get('draft') is False and release.get('immutable') is True
         and type(release.get('id')) is int and release['id'] > 0, 'COMPLETION_RELEASE_NOT_IMMUTABLE')
    assets = release.get('assets')
    need(isinstance(assets, list) and len(assets) == len(ASSETS)
         and {a.get('name') for a in assets} == set(ASSETS)
         and len({a.get('id') for a in assets}) == len(ASSETS), 'INVALID_COMPLETION_ASSET_INVENTORY')
    by_name = {a['name']: a for a in assets}
    with tempfile.TemporaryDirectory(prefix='completion-verification-') as tmp:
        root = Path(tmp)
        _download(client, by_name['completion.json'], root / 'completion.json', expected_receipt_sha256)
        receipt = read_json(root / 'completion.json')
        need(set(receipt) == {'schema_version', 'state', 'execution_key', 'manifest_sha256', 'build_origin'}
             and receipt['schema_version'] == 1 and receipt['state'] == 'BUILD_VERIFIED'
             and receipt['execution_key'] == execution_key, 'INVALID_COMPLETION_RECEIPT')
        _download(client, by_name['release-manifest.json'], root / 'release-manifest.json', receipt['manifest_sha256'])
        manifest = read_json(root / 'release-manifest.json')
        if producer_pins is not None:
            need(manifest['verification_pins']['expected_deployment_sha256'] == producer_pins['deployment_sha256']
                 and manifest['verification_pins']['expected_execution_contract_sha256'] == producer_pins['execution_contract_sha256'],
                 'UNREVIEWED_PRODUCER_DEPLOYMENT')
            need(all(manifest['verification_pins'][pin] == config[field] for pin, field in (
                ('expected_policy_sha256', 'continuous_policy_sha256'),
                ('expected_registry_sha256', 'registry_sha256'))), 'COMPLETION_SCOPE_MISMATCH')
        recorded = receipt['build_origin']
        need(origin(client, config, recorded['run_id'], recorded['run_attempt']) == recorded == manifest['build_origin'],
             'COMPLETION_ORIGIN_MISMATCH')
        need(manifest['execution_key'] == execution_key and manifest['production_promotion'] == 'NOT_AUTHORIZED'
             and manifest['research_approval'] == manifest['trusted_parent_eligibility'] == 'NOT_GRANTED'
             and manifest['quality'] == 'QUALITY_REVIEW_REQUIRED'
             and manifest['Q1'] == 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR', 'COMPLETION_RESTRICTION_MISMATCH')
        _download(client, by_name['candidate.tar.gz'], root / 'candidate.tar.gz', manifest['candidate_archive']['sha256'])
        need(manifest['candidate_archive']['size'] == by_name['candidate.tar.gz']['size'], 'COMPLETION_PACKAGE_SIZE_MISMATCH')
        trust.extract_regular(root / 'candidate.tar.gz', root / 'run', manifest['candidate_archive']['sha256'])
        verified = g.verify_package(project, root / 'run', **manifest['verification_pins'])
        authority = read_json(root / 'run/evidence/authorization-context.json')
        actor = authority['workflow_run']
        need(all(verified[k] == manifest[k] for k in ('format', 'candidate_id', 'corpus_sha256', 'generation', 'parent_id', 'upstreams', 'source_state'))
             and authority['parent_comparison']['execution_key'] == execution_key
             and actor['run_id'] == recorded['run_id'] and actor['run_attempt'] == recorded['run_attempt']
             and actor['commit_sha'] == recorded['implementation_revision'], 'COMPLETION_CANDIDATE_BINDING_MISMATCH')
    return {'state': 'PUBLISHED_AND_VERIFIED', 'execution_key': execution_key, 'release_id': release['id'],
            'receipt_sha256': expected_receipt_sha256, 'candidate_id': manifest['candidate_id'],
            'assets': {name: {'id': by_name[name]['id'], 'size': by_name[name]['size']} for name in ASSETS},
            'research_approval': 'NOT_GRANTED', 'production_promotion': 'NOT_AUTHORIZED'}


def _publisher_job(client, config, recorded, release):
    """Historical publication must have finished, unlike same-run final checks."""
    from .continuous_build_policy import _time
    base = '/repos/' + client.repository
    endpoint = base + f'/actions/runs/{recorded["run_id"]}/attempts/{recorded["run_attempt"]}'
    run = client._api('GET', endpoint)
    need(run.get('status') == 'completed' and run.get('conclusion') == 'success',
         'HISTORICAL_PUBLICATION_NOT_SUCCESSFUL_MANUAL_RECOVERY_REQUIRED')
    jobs = client._api('GET', endpoint + '/jobs?per_page=100&page=1')
    rows, count = jobs.get('jobs'), jobs.get('total_count')
    need(type(count) is int and 0 <= count <= 100 and isinstance(rows, list) and len(rows) == count,
         'INCOMPLETE_PUBLICATION_JOB_INVENTORY')
    matches = [j for j in rows if j.get('name') == 'publish-continuous-candidate']
    need(len(matches) == 1, 'MISSING_OR_AMBIGUOUS_PUBLISHER_JOB')
    job = matches[0]
    need(type(job.get('id')) is int and job['id'] > 0 and job.get('id') != recorded['job_id']
         and job.get('run_id') == recorded['run_id'] and job.get('head_sha') == config['implementation_revision']
         and job.get('status') == 'completed' and job.get('conclusion') == 'success',
         'PUBLISHER_JOB_NOT_SUCCESSFUL_MANUAL_RECOVERY_REQUIRED')
    build = next((j for j in rows if j.get('id') == recorded['job_id']), {})
    start, end = _time(job.get('started_at')), _time(job.get('completed_at'))
    # Release.created_at may be the target commit date, NOT draft creation.
    # GitHub documents this distinction; only published_at is a publish event.
    published = _time(release.get('published_at'))
    need(_time(run.get('created_at')) <= _time(build.get('started_at'))
         <= _time(build.get('completed_at')) <= start <= published <= end,
         'COMPLETION_PUBLICATION_TIME_MISMATCH')
    for asset in release['assets']:
        need(start <= _time(asset.get('created_at')) <= _time(asset.get('updated_at')) <= published,
             'COMPLETION_ASSET_TIME_MISMATCH')
    return job['id']


def _automatic_witness(project, client, config, release, prefix, execution_key):
    """Repository-governed delegation, NOT independent cryptographic attestation.

    All principals with Release write access are trusted under this explicit
    model. A shared actions bot ID does not establish exclusive workflow access.
    The consumer's deployment is independently pinned, not loaded from assets.
    """
    from . import genuine_continuous_execution as g
    current, _, deployment_pin = g.deployment()
    need(current == config and client.repository == config['repository'], 'UNTRUSTED_COMPLETION_CONSUMER')
    g._checkout(project, config); g._implementation(project, config['execution_contract_sha256'])
    authority = validate_authority(config)
    need(authority['release_prefix'] == prefix, 'COMPLETION_NAMESPACE_NOT_AUTHORIZED')
    need(release.get('draft') is False and release.get('immutable') is True
         and type(release.get('id')) is int and release['id'] > 0, 'COMPLETION_RELEASE_NOT_IMMUTABLE')
    # Re-read the immutable object by numeric ID; do not trust a caller's cache.
    expected_id = release['id']
    release = client._api('GET', f'/repos/{client.repository}/releases/{expected_id}')
    need(type(release.get('id')) is int and release['id'] == expected_id
         and release.get('tag_name') == tag(prefix, execution_key) and release.get('draft') is False
         and release.get('immutable') is True, 'COMPLETION_RELEASE_IDENTITY_MISMATCH')
    assets = release.get('assets')
    need(isinstance(assets, list) and len(assets) == len(ASSETS)
         and {a.get('name') for a in assets} == set(ASSETS)
         and len({a.get('id') for a in assets}) == len(ASSETS), 'INVALID_COMPLETION_ASSET_INVENTORY')
    def trusted_writer(user):
        return isinstance(user, dict) and type(user.get('id')) is int and user['id'] == authority['publisher_actor_id'] and user.get('type') == 'Bot'
    need(trusted_writer(release.get('author')) and all(trusted_writer(a.get('uploader')) for a in assets),
         'UNTRUSTED_COMPLETION_WRITER')
    need(all(isinstance(a.get('digest'), str) and re.fullmatch('sha256:[0-9a-f]{64}', a['digest']) for a in assets),
         'AUTHENTICATED_COMPLETION_DIGEST_UNAVAILABLE')
    receipt_asset = next(a for a in assets if a['name'] == 'completion.json')
    observed = receipt_asset.get('digest')
    need(isinstance(observed, str) and re.fullmatch('sha256:[0-9a-f]{64}', observed),
         'AUTHENTICATED_COMPLETION_DIGEST_UNAVAILABLE')
    receipt_pin = observed[7:]
    with tempfile.TemporaryDirectory(prefix='completion-authority-') as tmp:
        path = Path(tmp) / 'completion.json'
        _download(client, receipt_asset, path, receipt_pin)
        receipt = read_json(path)
    need(isinstance(receipt, dict) and set(receipt) == {
        'schema_version', 'state', 'execution_key', 'manifest_sha256', 'build_origin'}
         and type(receipt['schema_version']) is int and receipt['schema_version'] == 1
         and receipt['state'] == 'BUILD_VERIFIED' and receipt['execution_key'] == execution_key,
         'INVALID_COMPLETION_RECEIPT')
    recorded = receipt['build_origin']; revision = recorded.get('implementation_revision')
    if revision == config['implementation_revision']:
        producer = {'implementation_revision': revision, 'deployment_sha256': deployment_pin,
                    'execution_contract_sha256': config['execution_contract_sha256']}
    else:
        matches = [p for p in authority['previous_producers'] if p['implementation_revision'] == revision]
        need(len(matches) == 1, 'HISTORICAL_PRODUCER_NOT_REVIEWED')
        producer = matches[0]
    need(producer['execution_contract_sha256'] == digest(g.contract(project)),
         'HISTORICAL_PRODUCER_ORIGINAL_VERIFIER_REQUIRED')
    producer_config = {**config, 'implementation_revision': revision}
    need(recorded.get('workflow_id') == authority['workflow_id'] and recorded.get('event') == 'schedule'
         and origin(client, producer_config, recorded['run_id'], recorded['run_attempt']) == recorded,
         'UNTRUSTED_COMPLETION_PRODUCER')
    need(release.get('target_commitish') == revision, 'COMPLETION_RELEASE_TARGET_MISMATCH')
    ref = client._api('GET', f'/repos/{client.repository}/git/ref/tags/' + quote(release['tag_name'], safe=''))
    obj = ref.get('object', {})
    if obj.get('type') == 'tag':
        need(isinstance(obj.get('sha'), str) and re.fullmatch('[0-9a-f]{40}', obj['sha']), 'INVALID_COMPLETION_TAG_OBJECT')
        obj = client._api('GET', f'/repos/{client.repository}/git/tags/' + obj['sha']).get('object', {})
    need(obj.get('type') == 'commit' and obj.get('sha') == revision, 'COMPLETION_TAG_COMMIT_MISMATCH')
    publisher_id = _publisher_job(client, producer_config, recorded, release)
    result = verify_completed(project, client, producer_config, release, execution_key,
                              expected_receipt_sha256=receipt_pin, producer_pins=producer)
    return {**result, 'completion_trust': TRUST_MODEL, 'cryptographic_producer_attestation': False,
            'producer_commit': revision, 'producer_run_id': recorded['run_id'], 'publisher_job_id': publisher_id,
            'consumer_commit': config['implementation_revision'], 'consumer_deployment_sha256': deployment_pin,
            'replay': 'SEALED_REPLAY_INSPECTED'}


def lookup(project, client, config, prefix, execution_key, *, expected_receipt_sha256=None):
    release = client._api('GET', '/repos/' + client.repository + '/releases/tags/' + quote(tag(prefix, execution_key), safe=''), allow_404=True)
    if release is None:
        return {'state': 'NOT_STARTED', 'execution_key': execution_key}
    need(release.get('tag_name') == tag(prefix, execution_key), 'COMPLETION_TAG_MISMATCH')
    if release.get('draft') is True:
        # Not a duplicate. Retry may build; existing draft is preserved. Publishing
        # requires explicit reviewed recovery instead of overwriting its assets.
        return {'state': 'PUBLISHING', 'execution_key': execution_key, 'release_id': release['id']}
    if expected_receipt_sha256 is None and config['schema_version'] == 4:
        return _automatic_witness(project, client, config, release, prefix, execution_key)
    return verify_completed(project, client, config, release, execution_key, expected_receipt_sha256=expected_receipt_sha256)


def publish(project, client, config, prepared, *, prefix):
    """Only callable by the reviewed, explicitly enabled publishing entry."""
    manifest = prepared['manifest']; recorded = manifest['build_origin']; key = manifest['execution_key']
    need(origin(client, config, recorded['run_id'], recorded['run_attempt']) == recorded, 'STALE_PUBLICATION_ORIGIN')
    # Revalidate local bytes AND their package before any remote mutation.
    directory = Path(prepared['directory'])
    need(read_json(directory / 'release-manifest.json') == manifest
         and file_digest(directory / 'completion.json') == prepared['receipt_sha256'], 'PREPARED_PUBLICATION_CHANGED')
    with tempfile.TemporaryDirectory(prefix='publication-recheck-') as tmp:
        trust.extract_regular(directory / 'candidate.tar.gz', Path(tmp) / 'run', manifest['candidate_archive']['sha256'])
        from . import genuine_continuous_execution as g
        g.verify_package(project, Path(tmp) / 'run', **manifest['verification_pins'])
    existing = lookup(project, client, config, prefix, key)
    need(existing['state'] == 'NOT_STARTED', 'EXISTING_COMPLETION_REQUIRES_INDEPENDENT_REVIEW')
    base = '/repos/' + client.repository; release_tag = tag(prefix, key)
    need(client._api('GET', base + '/git/ref/tags/' + quote(release_tag, safe=''), allow_404=True) is None, 'CONFLICTING_COMPLETION_TAG')
    draft = client._api('POST', base + '/releases', {'tag_name': release_tag, 'target_commitish': config['implementation_revision'],
        'name': 'Continuous research Candidate ' + key[:12], 'draft': True, 'prerelease': True,
        'body': 'Research archive only. QUALITY_REVIEW_REQUIRED. No approval, registration or production authorization.'})
    need(type(draft.get('id')) is int and draft['id'] > 0 and draft.get('draft') is True
         and draft.get('tag_name') == release_tag and draft.get('target_commitish') == config['implementation_revision'], 'INVALID_NEW_COMPLETION_DRAFT')
    for name in ASSETS:
        asset = client._upload(draft['upload_url'], draft['id'], directory / name)
        client._verify_asset(draft['id'], asset, directory / name)
    checked = client._api('GET', base + '/releases/' + str(draft['id']))
    need(checked.get('draft') is True and len(checked.get('assets', [])) == len(ASSETS)
         and {a.get('name') for a in checked['assets']} == set(ASSETS), 'INCOMPLETE_PUBLICATION')
    need(origin(client, config, recorded['run_id'], recorded['run_attempt']) == recorded, 'STALE_PUBLICATION_ORIGIN')
    if config['schema_version'] >= 3:
        current, _, current_pin = g.deployment()
        need(current == config and current_pin == manifest['verification_pins']['expected_deployment_sha256'],
             'STALE_PUBLICATION_DEPLOYMENT')
        with tempfile.TemporaryDirectory(prefix='publication-authority-') as tmp:
            trust.extract_regular(directory / 'candidate.tar.gz', Path(tmp) / 'run', manifest['candidate_archive']['sha256'])
            authority = g._authority(project, Path(tmp) / 'run/evidence/detection.json', config, current_pin)
            g.scheduled.mutex(project, config, authority)
    # Publication is not one atomic transaction with local evidence. If PATCH
    # succeeds and the response is lost, stop; use read-only verification later.
    client._api('PATCH', base + '/releases/' + str(draft['id']), {'draft': False})
    final = client._api('GET', base + '/releases/' + str(draft['id']))
    need(final.get('tag_name') == release_tag, 'PUBLISHED_COMPLETION_TAG_MISMATCH')
    return verify_completed(project, client, config, final, key, expected_receipt_sha256=prepared['receipt_sha256'])


def retrieve_build(client, config, run_id, attempt, destination):
    """Authenticate original Actions ZIP before deriving any package pins from it."""
    from . import historical_candidate_archive as historical
    verified = origin(client, config, run_id, attempt)
    listing = client._api('GET', f'/repos/{client.repository}/actions/runs/{run_id}/artifacts?per_page=100&page=1')
    rows, count = listing.get('artifacts'), listing.get('total_count')
    need(type(count) is int and 0 <= count <= 100 and isinstance(rows, list) and len(rows) == count,
         'INCOMPLETE_BUILD_ARTIFACT_INVENTORY')
    matches = [row for row in rows if row.get('name') == f'ci-v2-continuous-{run_id}-{attempt}']
    need(len(matches) == 1, 'MISSING_OR_AMBIGUOUS_BUILD_ARTIFACT')
    asset = matches[0]; binding = asset.get('workflow_run', {})
    need(type(asset.get('id')) is int and asset['id'] > 0 and asset.get('expired') is False
         and type(asset.get('size_in_bytes')) is int and 0 < asset['size_in_bytes'] <= 2 * 1024**3
         and isinstance(asset.get('digest'), str) and re.fullmatch('sha256:[0-9a-f]{64}', asset['digest'])
         and binding.get('id') == run_id and binding.get('repository_id') == config['repository_id']
         and binding.get('head_sha') == config['implementation_revision'], 'BUILD_ARTIFACT_BINDING_MISMATCH')
    destination = Path(destination)
    need(not destination.exists() and destination.parent.is_dir(), 'INVALID_BUILD_DOWNLOAD_OUTPUT')
    with tempfile.TemporaryDirectory(prefix='original-build-zip-', dir=destination.parent) as tmp:
        path = Path(tmp) / 'build.zip'
        historical._download(client, {'original': {'artifact_id': asset['id'], 'artifact_size': asset['size_in_bytes'],
            'artifact_sha256': asset['digest'][7:]}}, path)
        need(path.stat().st_size == asset['size_in_bytes'] and file_digest(path) == asset['digest'][7:], 'ORIGINAL_BUILD_ZIP_HASH_MISMATCH')
        historical._extract(path, destination)
    return verified, {'artifact_id': asset['id'], 'artifact_sha256': asset['digest'][7:], 'size': asset['size_in_bytes']}
