"""Bounded immutable report preservation. No downloaded code is executed.

Functions take an API transport for offline tests. Only propose() writes GitHub;
its caller must enforce the trusted workflow context and a separately validated
manifest pin. Mutation errors are uncertain; never retry or repair automatically.
"""
import base64
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import zipfile
from urllib.parse import quote

REPO = 'XiangruZhang007/SPHinXsistant-CI-Test'
RID = 1455203884
OWNER = 239840087
BRANCH = 'ci-upstream-refresh'
WORKFLOW = '.github/workflows/ci_v2_candidate_gradio_loading.yml'
HISTORICAL_WORKFLOW_SHA = '9c10a6ebdb87ace81f6285fb26835b659ad431006f17dd1d5fd6b652736be722'
RESTRICTIONS = ['QUALITY_REVIEW_REQUIRED', 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR',
                'P8_BLOCKED', 'REGISTRATION_ONLY', 'PRODUCTION_NOT_AUTHORIZED']
ROOT = 'repos/' + REPO


def need(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode()


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('NONFINITE_JSON')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def content(api, path, revision):
    obj = api('GET', ROOT + '/contents/' + path + '?ref=' + quote(revision, safe=''))
    need(obj['type'] == 'file' and obj['encoding'] == 'base64' and obj['size'] <= 256*1024,
         'UNSAFE_REMOTE_SOURCE')
    raw = base64.b64decode(obj['content'], validate=False)
    need(len(raw) == obj['size'], 'SOURCE_SIZE_MISMATCH')
    return raw


def report_from_zip(raw, expected_digest):
    need(len(raw) <= 2*1024**2 and expected_digest == 'sha256:' + sha(raw), 'ARTIFACT_DIGEST_MISMATCH')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        need(len(members) == 1, 'UNEXPECTED_ZIP_MEMBERS')
        item = members[0]
        need(item.filename == item.orig_filename == 'verification.json' and not item.is_dir()
             and not item.flag_bits & 1 and item.file_size <= 1024**2
             and stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG), 'UNSAFE_ZIP_MEMBER')
        report = archive.read(item)  # bounded member, CRC validation, no extraction
    return report, decode(report)


def validate_report(report, run, config):
    need(isinstance(report, dict), 'INVALID_REPORT')
    if run['conclusion'] == 'failure':
        need(report == {'status': 'BLOCKED', 'reason': 'CANDIDATE_RESEARCH_CONSUMPTION_FAILED',
                        'production_promotion': 'NOT_AUTHORIZED'}, 'INVALID_FAILURE_REPORT')
        return
    need(report['status'] == 'RESEARCH_CANDIDATE_GRADIO_VERIFIED'
         and report['scope'] == 'RESEARCH_LOADING_ONLY' and report['subject'] == config['subject']
         and report['restrictions'] == RESTRICTIONS
         and report['original_execution'] == 'LOCAL_RESEARCH_EXECUTION / HOSTED_NOT_RUN'
         and report['scientific_verification'] == 'NO_FRESH_REPLAY'
         and report['production_promotion'] == 'NOT_AUTHORIZED'
         and report['LLM_calls'] == 0 and report['HTTP_server_started'] is False
         and report['temporary_run_and_application_cleaned'] is True, 'REPORT_SCOPE_MISMATCH')
    app = report['application']; isolation = app['isolation']; evidence = report['evidence']
    need(app['sha256'] == config['subject']['corpus_sha256']
         and app['records'] == config['subject']['records']
         and app['complete_records_equal'] is True and app['callbacks_share_assistant'] is True
         and app['application_closed'] is True and app['retriever_class'] == 'src.retrieval_v1.RetrievalV1'
         and evidence['candidate_id'] == config['subject']['candidate_id']
         and evidence['records'] == app['records'] and evidence['parity'] == 'PARITY_PASS'
         and evidence['P8'] == 'BLOCKED' and evidence['sealed_R2'] == 'VERIFIED / NO_FRESH_REPLAY'
         and report['notices'] == 'VERIFIED_SOURCE_AND_LICENSE_BINDINGS', 'REPORT_EVIDENCE_MISMATCH')
    need(type(isolation['uid']) is int and isolation['uid'] > 0 and type(isolation['gid']) is int
         and isolation['gid'] > 0 and isolation['capabilities'] == 'ALL_ZERO'
         and isolation['no_new_privs'] is True and isolation['separate_network_namespace'] is True
         and isolation['interfaces'] == ['lo'] and isolation['external_route_probe'] == 'ENETUNREACH',
         'REPORT_ISOLATION_MISMATCH')
    need(len(app['retrieval']) == 1 and app['retrieval'][0]['top_k'] == 5, 'REPORT_RETRIEVAL_MISMATCH')
    query = app['retrieval'][0]
    need(query['query'] == 'How does SPHinXsim migrate_legacy_configuration preserve the saved document?'
         and 0 < len(query['results']) <= 5
         and [h['rank'] for h in query['results']] == list(range(1, len(query['results'])+1))
         and any(h['chunk_id'] == 'd5e0de43d804b1790811c5d1295b13ac3c957afb'
                 and h['source_path'] == 'repos/SPHinXsim/sphinxsim/config/migrations.py'
                 for h in query['results']), 'REPORT_RETRIEVAL_MISMATCH')


def archive_files(run, artifact, raw, config_raw):
    report_raw, report = report_from_zip(raw, artifact['digest'])
    return files_from_report(run, artifact, report_raw, config_raw, sha(raw))


def files_from_report(run, artifact, report_raw, config_raw, zip_sha256):
    report = decode(report_raw)
    config = decode(config_raw)
    validate_report(report, run, config)
    if run['conclusion'] == 'success':
        need(report['review_sha256'] == sha(config_raw), 'REPORT_REVIEW_PIN_MISMATCH')
    manifest = {'schema_version': 1, 'kind': 'HOSTED_RESEARCH_VERIFICATION_ARCHIVE',
        'repository': REPO, 'repository_id': RID, 'run_id': run['id'], 'run_attempt': run['run_attempt'],
        'workflow_path': run['path'], 'implementation_revision': run['head_sha'],
        'actor_id': run['actor']['id'], 'triggering_actor_id': run['triggering_actor']['id'],
        'run_conclusion': run['conclusion'], 'verification_status': report['status'],
        'artifact_id': artifact['id'], 'artifact_name': artifact['name'],
        'artifact_zip_sha256': zip_sha256, 'verification_sha256': sha(report_raw),
        'loading_configuration_sha256': sha(config_raw), 'subject': config['subject'],
        'scope': 'RESEARCH_LOADING_ONLY', 'restrictions': RESTRICTIONS,
        'scientific_approval': False, 'production_promotion': 'NOT_AUTHORIZED'}
    readme = ('# Hosted research verification evidence\n\nRun: ' + str(run['id'])
        + '; attempt: ' + str(run['run_attempt']) + '; conclusion: ' + run['conclusion']
        + '.\nImplementation: ' + run['head_sha'] + '.\nOriginal verification.json bytes preserved; '
        'manifest binds the original Run and artifact ZIP digest. This archives the actual result, '
        'not a new scientific evaluation or approval.\n'
        'A successful result verifies pinned transport, sealed evidence, isolated Gradio loading and '
        'a bounded real BM25 query. A BLOCKED result does not establish those successes.\n'
        'No R2/Q1 replay, LLM answer-quality acceptance, Candidate promotion or production deployment '
        'is conferred. Original HOSTED_NOT_RUN describes scientific construction, not this Hosted '
        'consumption test.\n\n' + '; '.join(RESTRICTIONS) + '.\n').encode()
    return {'verification.json': report_raw, 'manifest.json': encode(manifest), 'README.md': readme}


def fetch(api, project, run_id):
    need(type(run_id) is int and run_id > 0, 'INVALID_RUN_ID')
    project = Path(project)
    repo = api('GET', ROOT)
    need(repo['id'] == RID and repo['full_name'] == REPO and repo['default_branch'] == BRANCH
         and repo['owner']['id'] == OWNER, 'REPOSITORY_MISMATCH')
    run = api('GET', ROOT + '/actions/runs/' + str(run_id))
    need(run['id'] == run_id and run['repository']['id'] == RID
         and run['head_repository']['id'] == RID and run['event'] == 'workflow_dispatch'
         and run['head_branch'] == BRANCH and run['path'] == WORKFLOW
         and run['status'] == 'completed' and run['conclusion'] in ('success', 'failure')
         and run['run_attempt'] == 1 and run['actor']['id'] == run['triggering_actor']['id'] == OWNER
         and re.fullmatch('[0-9a-f]{40}', run['head_sha']) is not None, 'UNTRUSTED_SOURCE_RUN')
    comparison = api('GET', ROOT + '/compare/' + run['head_sha'] + '...' + repo['default_branch'])
    need(comparison['status'] in ('identical', 'ahead') and comparison['behind_by'] == 0
         and comparison['merge_base_commit']['sha'] == run['head_sha'], 'SOURCE_NOT_TRUSTED_ANCESTOR')
    for path in ('src/research_candidate_consumer.py', 'scripts/check_hosted_candidate_gradio.py',
                 'scripts/check_hosted_gradio_loading.py', 'src/corpus_update_integration.py',
                 'apps/gradio_app_v1.py', 'src/retrieval_v1.py'):
        need(content(api, path, run['head_sha']) == (project/path).read_bytes(), 'UNREVIEWED_SOURCE_IMPLEMENTATION')
    workflow = content(api, WORKFLOW, run['head_sha'])
    need(sha(workflow) in (HISTORICAL_WORKFLOW_SHA, sha((project/WORKFLOW).read_bytes())),
         'UNREVIEWED_SOURCE_WORKFLOW')
    config = content(api, 'configs/ci_v2_research_candidate_loading.json', run['head_sha'])
    need(config == (project/'configs/ci_v2_research_candidate_loading.json').read_bytes(), 'UNREVIEWED_SUBJECT')
    workflow_meta = api('GET', ROOT + '/actions/workflows/ci_v2_candidate_gradio_loading.yml')
    need(run['workflow_id'] == workflow_meta['id'] and workflow_meta['path'] == WORKFLOW, 'WORKFLOW_ID_MISMATCH')
    jobs = api('GET', ROOT + '/actions/runs/' + str(run_id) + '/jobs?per_page=100')
    need(jobs['total_count'] == 1 and len(jobs['jobs']) == 1
         and jobs['jobs'][0]['run_id'] == run_id and jobs['jobs'][0]['conclusion'] == run['conclusion'],
         'SOURCE_JOB_MISMATCH')
    if run['conclusion'] == 'success':
        steps = {s['name']: s['conclusion'] for s in jobs['jobs'][0]['steps']}
        need(all(steps.get(name) == 'success' for name in (
            'Check out exact trusted dispatch revision', 'Select frozen ARM64 Python',
            'Prepare frozen package verifier', 'Prepare separate application interpreter',
            'Verify immutable Candidate evidence and run isolated real Gradio BM25',
            'Retain sanitized verification report only')), 'INCOMPLETE_SUCCESS_STEPS')
    assets = api('GET', ROOT + '/actions/runs/' + str(run_id) + '/artifacts?per_page=100')
    need(assets['total_count'] == len(assets['artifacts']) == 1, 'ARTIFACT_SET_MISMATCH')
    asset = assets['artifacts'][0]
    need(asset['workflow_run']['id'] == run_id and asset['workflow_run']['repository_id'] == RID
         and asset['workflow_run']['head_repository_id'] == RID
         and asset['workflow_run']['head_sha'] == run['head_sha']
         and asset['name'] == 'candidate-gradio-loading-' + str(run_id) + '-1'
         and 0 < asset['size_in_bytes'] <= 2*1024**2, 'ARTIFACT_ATTRIBUTION_MISMATCH')
    need(re.fullmatch('sha256:[0-9a-f]{64}', asset.get('digest', '')) is not None, 'MISSING_ARTIFACT_PIN')
    if asset['expired']:
        # The CLI verifies these existing archive files against its trusted Git
        # checkout. Never fabricate or regenerate the original ZIP after expiry.
        directory = project / relative_directory(run_id)
        need(directory.is_dir() and not any(n.is_symlink() for n in (directory, *directory.parents)),
             'EXPIRED_ARTIFACT_WITHOUT_TRUSTED_ARCHIVE')
        existing = {}
        for name in ('verification.json', 'manifest.json', 'README.md'):
            path = directory/name
            need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024**2, 'INVALID_EXISTING_ARCHIVE')
            existing[name] = path.read_bytes()
        expected = files_from_report(run, asset, existing['verification.json'], config, asset['digest'][7:])
        need(existing == expected and {n.name for n in directory.iterdir()} == set(expected), 'ARCHIVE_CONFLICT')
        return existing
    raw = api('GET', ROOT + '/actions/artifacts/' + str(asset['id']) + '/zip', binary=True)
    need(len(raw) == asset['size_in_bytes'], 'ARTIFACT_SIZE_MISMATCH')
    return archive_files(run, asset, raw, config)


def relative_directory(run_id, attempt=1):
    need(type(run_id) is int and run_id > 0 and attempt == 1, 'INVALID_RUN_ID')
    leaf = ('d3-9-e-45144294526-attempt-1' if run_id == 45144294526
            else 'run-' + str(run_id) + '-attempt-1')
    return 'docs/evidence/hosted/' + leaf


def retain(directory, files):
    directory = Path(directory)
    need(set(files) == {'verification.json', 'manifest.json', 'README.md'}, 'INVALID_ARCHIVE_FILES')
    need(not directory.is_symlink() and not any(p.is_symlink() for p in directory.parents), 'UNSAFE_ARCHIVE_PATH')
    if directory.exists():
        need(directory.is_dir() and {p.name for p in directory.iterdir()} == set(files)
             and all((directory/n).is_file() and not (directory/n).is_symlink()
                     and (directory/n).read_bytes() == raw for n, raw in files.items()), 'ARCHIVE_CONFLICT')
        return 'ALREADY_ARCHIVED_IDENTICAL'
    directory.mkdir(parents=True)
    for name, raw in files.items():
        with (directory/name).open('xb') as stream:
            stream.write(raw)
    return 'ARCHIVE_PREPARED'


def propose(api, project, files, run_id, expected_manifest_sha256, expected_base):
    need(set(files) == {'verification.json', 'manifest.json', 'README.md'}, 'INVALID_ARCHIVE_FILES')
    need(re.fullmatch('[0-9a-f]{40}', expected_base or '') is not None, 'INVALID_BASE_REVISION')
    need(sha(files['manifest.json']) == expected_manifest_sha256, 'VALIDATION_JOB_PIN_MISMATCH')
    manifest = decode(files['manifest.json'])
    need(manifest['run_id'] == run_id and manifest['run_attempt'] == 1
         and manifest['verification_sha256'] == sha(files['verification.json']), 'ARCHIVE_SUBJECT_MISMATCH')
    relative = relative_directory(run_id)
    # A separately reviewed write job refetches and revalidates bytes before here.
    base_commit = api('GET', ROOT + '/git/commits/' + expected_base)
    need(base_commit['sha'] == expected_base, 'BASE_COMMIT_MISMATCH')
    tree = api('GET', ROOT + '/git/trees/' + base_commit['tree']['sha'] + '?recursive=1')
    need(not tree['truncated'] and tree['sha'] == base_commit['tree']['sha'], 'INCOMPLETE_BASE_TREE')
    present = {v['path']: v for v in tree['tree'] if v['path'].startswith(relative + '/')}
    if present:
        need(set(present) == {relative+'/'+n for n in files}
             and all(present[relative+'/'+n]['type'] == 'blob'
                     and present[relative+'/'+n]['mode'] == '100644'
                     and content(api, relative+'/'+n, expected_base) == raw for n,raw in files.items()),
             'ARCHIVE_CONFLICT')
        return {'status': 'ALREADY_ARCHIVED_IDENTICAL'}
    need(api('GET', ROOT + '/git/ref/heads/' + BRANCH)['object']['sha'] == expected_base, 'DEFAULT_BRANCH_MOVED')
    branch = 'ci-v2-proposals/hosted-evidence-' + str(run_id) + '-attempt-1'
    refs = api('GET', ROOT + '/git/matching-refs/heads/' + branch)
    prs = api('GET', ROOT + '/pulls?state=all&head=' + quote(REPO.split('/')[0]+':'+branch, safe=''))
    if refs or prs:
        need(len(refs) == len(prs) == 1 and refs[0]['ref'] == 'refs/heads/'+branch
             and prs[0]['state'] == 'open'
             and prs[0]['user']['login'] == 'github-actions[bot]' and prs[0]['user']['type'] == 'Bot'
             and prs[0]['head']['sha'] == refs[0]['object']['sha']
             and prs[0]['base']['ref'] == BRANCH and prs[0]['head']['ref'] == branch,
             'PARTIAL_OR_CONFLICTING_ARCHIVE_REVIEW_REQUIRED')
        comparison = api('GET', ROOT + '/compare/' + expected_base + '...' + refs[0]['object']['sha'])
        need(comparison['behind_by'] == 0 and comparison['ahead_by'] == 1
             and len(comparison['files']) == 3
             and {v['filename'] for v in comparison['files']} == {relative+'/'+n for n in files}
             and all(v['status'] == 'added' for v in comparison['files'])
             and all(content(api, relative+'/'+n, refs[0]['object']['sha']) == raw for n,raw in files.items()),
             'ARCHIVE_CONFLICT')
        return {'status': 'EXISTING_IDENTICAL_ARCHIVE_PR', 'number': prs[0]['number']}
    # Every write occurs once. A raised error stops the job; no retry, delete or repair.
    entries = []
    for name, raw in sorted(files.items()):
        blob = api('POST', ROOT + '/git/blobs', {'content': base64.b64encode(raw).decode(), 'encoding': 'base64'})
        need(blob['sha'] == hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(), 'WRITTEN_BLOB_MISMATCH')
        entries.append({'path': relative+'/'+name, 'mode': '100644', 'type': 'blob', 'sha': blob['sha']})
    # Check again after object preparation and before exposing a branch.
    need(api('GET', ROOT + '/git/ref/heads/' + BRANCH)['object']['sha'] == expected_base, 'DEFAULT_BRANCH_MOVED')
    created_tree = api('POST', ROOT + '/git/trees', {'base_tree': tree['sha'], 'tree': entries})
    commit = api('POST', ROOT + '/git/commits', {'message': 'Archive Hosted verification '+str(run_id),
        'tree': created_tree['sha'], 'parents': [expected_base]})
    need(commit['tree']['sha'] == created_tree['sha']
         and [v['sha'] for v in commit['parents']] == [expected_base], 'WRITTEN_COMMIT_MISMATCH')
    ref = api('POST', ROOT + '/git/refs', {'ref': 'refs/heads/'+branch, 'sha': commit['sha']})
    need(ref['object']['sha'] == commit['sha'], 'WRITTEN_REF_MISMATCH')
    need(api('GET', ROOT + '/git/ref/heads/'+branch)['object']['sha'] == commit['sha'], 'REF_READBACK_MISMATCH')
    need(all(content(api, relative+'/'+n, commit['sha']) == raw for n,raw in files.items()), 'ARCHIVE_READBACK_MISMATCH')
    pr = api('POST', ROOT + '/pulls', {'title': 'Archive Hosted verification '+str(run_id),
        'head': branch, 'base': BRANCH, 'maintainer_can_modify': False,
        'body': 'Preserve the exact verified Run report. Human approval and merge required. '
                'No scientific approval, Parent authority or production activation.'})
    need(pr['user']['login'] == 'github-actions[bot]' and pr['user']['type'] == 'Bot'
         and pr['head']['sha'] == commit['sha'] and pr['head']['ref'] == branch
         and pr['base']['ref'] == BRANCH and pr['state'] == 'open', 'PR_UNCERTAIN_STOP_WITHOUT_RETRY')
    return {'status': 'ARCHIVE_PR_CREATED_REVIEW_REQUIRED', 'number': pr['number']}
