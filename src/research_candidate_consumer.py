"""Exact D3.9 research Candidate consumption, never Baseline or build approval.

Reviewed transport inputs and an independently retained loading-authorization pin
are caller trust, not signatures. Downloaded JSON cannot confer authorization.
The original scientific run remains LOCAL_RESEARCH_EXECUTION / HOSTED_NOT_RUN.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile

from . import approval_evidence as evaluation, ci_v2_research as research
from . import corpus_snapshot as snapshot, trusted_snapshot as trust
from . import upstream_provenance as provenance, update_eligibility_gate as gate
from .candidate_release_archive import _read_sealed_run
from .local_candidate_transport import LICENSES
from .parent_r2_anchor import qualify_parent_anchor

REPOSITORY = 'XiangruZhang007/SPHinXsistant-CI-Test'
REPOSITORY_ID = 1455203884
PURPOSE = 'RESEARCH_LOADING_ONLY'
SUBJECT = {
    'candidate_id': 'sha256-76105a0d7e33375966aa09ab0bcf00f035055c0c0ffb96f5f18d6fbca63813b8',
    'corpus_sha256': '8d989e543a2a25d779ad21fe9893848b65169c8502c0119c324d42536d4ca7e2',
    'records': 12123, 'corpus_size': 27057586,
    'parent_id': 'sha256-798d0d1284c7dbba06d5788a062973bf7290cbbfdef28150037371fa78b7188a',
    'base_source_state': 'sha256-96d84d8f4a25c8a49e77aadca9d6a8accc247153bb7e0645dbf443ce71c6c151',
    'target_source_state': 'sha256-f6b3c85e6500d1edb6978f493ec462ac51a36fe506dac614bcc83c9e876e4394',
    'base_upstreams': {'SPHinXsys': '4e686ee357de1cb798ac47eb760dd79e2fb407ff',
                       'SPHinXsim': '9cdae783e3ef3f8926c2174a0db89e96846befad'},
    'target_upstreams': {'SPHinXsys': '64d6069f7469c4171f7807e7e3118a6d7dee06a5',
                         'SPHinXsim': '601343617a339a731d7484f6f43b5aaffb19f61b'},
    'build_fingerprint': '7f66fe80e92d7263d5147d4fea551855184af75829f5b62993eb162acceb0cd8',
    'orchestration_fingerprint': 'b0b43411aef4d716a15a2f0a794071523fbb3c260dc4cb3fc9b2736eed9e1ac1',
    'build_policy_sha256': '299aa0fd6925d9224432ddc474ec2f0e66edad89fbb1d031350a7b413bd68727',
    'run_manifest_sha256': '4dcd368beb47ea141d607bf9ca15afaadc528eb7b6b39cd337b7f189cb21e995',
}
QUERY = 'How does SPHinXsim migrate_legacy_configuration preserve the saved document?'
EXPECTED_CHUNK = 'd5e0de43d804b1790811c5d1295b13ac3c957afb'
EXPECTED_SOURCE = 'repos/SPHinXsim/sphinxsim/config/migrations.py'
LIMIT, FILE_LIMIT, COUNT_LIMIT = 2 * 1024**3, 256 * 1024**2, 20000
METADATA_LIMIT, METADATA_TOTAL_LIMIT = 64 * 1024, 8 * 1024**2
METADATA_COUNT_LIMIT = 20000
VENDOR_NOTICES = {
    'SPHinXsys/src/for_2D_build/geometries/earcut.hpp': 'ISC-Mapbox-earcut-matching-revision.txt',
    'SPHinXsys/src/for_3D_build/geometries/TriangleMeshDistance.h': 'TriangleMeshDistance-MIT-source-notice.txt',
    'SPHinXsys/src/for_3D_build/geometries/stl_reader.h': 'stl-reader-BSD-source-notice.txt',
    **{'SPHinXsys/src/for_3D_build/particle_dynamics/solid_dynamics/polar_decomposition_3x3' + suffix:
       'Polar-decomposition-MIT-source-notice.txt' for suffix in ('.h', '_impl.h', '_matrix.h')},
    **{'SPHinXsys/src/shared/tools/tinyxml2.' + suffix: 'TinyXML-2-source-notice.txt'
       for suffix in ('cpp', 'h')},
}
RESTRICTIONS = ['QUALITY_REVIEW_REQUIRED', 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR',
                'P8_BLOCKED', 'REGISTRATION_ONLY', 'PRODUCTION_NOT_AUTHORIZED']


class ConsumptionError(ValueError):
    """Sanitized failure code; never transport headers, secrets or package content."""


def need(value, code):
    if not value:
        raise ConsumptionError(code)


def application_interpreter(path):
    """Check before downloads; venv Python symlinks remain supported.

    Do not run/import the interpreter here: application execution belongs only
    inside the existing namespace/privilege/credential boundary.
    """
    path = Path(path)
    need(path.is_absolute() and path.is_file() and os.access(path, os.X_OK),
         'APPLICATION_INTERPRETER_REQUIRED')
    return path


class _BoundedTarInfo(tarfile.TarInfo):
    """Frozen Python TarInfo hooks bound extensions BEFORE their payload read.

    Ordinary member checks occur too late: tarfile consumes PAX/GNU extension
    payloads before yielding a member. Keep native PAX packaging unchanged.
    """

    def _metadata(self, archive):
        total = getattr(archive, '_research_metadata_bytes', 0) + self.size
        count = getattr(archive, '_research_metadata_count', 0) + 1
        need(0 <= self.size <= METADATA_LIMIT and total <= METADATA_TOTAL_LIMIT
             and count <= METADATA_COUNT_LIMIT, 'ARCHIVE_METADATA_LIMIT_EXCEEDED')
        archive._research_metadata_bytes = total
        archive._research_metadata_count = count

    def _proc_pax(self, archive):
        self._metadata(archive)
        return super()._proc_pax(archive)

    def _proc_gnulong(self, archive):
        self._metadata(archive)
        return super()._proc_gnulong(archive)

    def _reject_sparse(self, *args, **kwargs):
        # Sparse formats can read additional allocation-driving metadata from
        # the data stream and are outside the regular-file research contract.
        raise ConsumptionError('UNSAFE_ARCHIVE_MEMBER')

    _proc_sparse = _reject_sparse
    _proc_gnusparse_00 = _reject_sparse
    _proc_gnusparse_01 = _reject_sparse
    _proc_gnusparse_10 = _reject_sparse


def safe(path, *, directory=False):
    path = Path(path).absolute()
    need('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), 'UNSAFE_PATH')
    info = path.stat()
    need(stat.S_ISDIR(info.st_mode) if directory else
         stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'UNSAFE_PATH')
    return path


def json_bytes(raw):
    def reject(_):
        raise ConsumptionError('INVALID_JSON')
    return json.loads(raw, object_pairs_hook=snapshot._unique, parse_constant=reject)


def hash_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def hash_value(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def review_inputs(path, expected_sha256, *, authorized_review_sha256=None, purpose=None):
    # The separate pin must come from a real human decision retained by the
    # trusted caller. This function cannot authenticate the human who provided it.
    need(purpose == PURPOSE, 'RESEARCH_PURPOSE_REQUIRED')
    need(hash_value(authorized_review_sha256) and authorized_review_sha256 == expected_sha256,
         'LOADING_AUTHORIZATION_REQUIRED')
    path = safe(path)
    need(path.stat().st_size <= 64 * 1024, 'REVIEW_TOO_LARGE')
    raw = path.read_bytes()
    need(hash_value(expected_sha256) and hash_bytes(raw) == expected_sha256, 'REVIEW_PIN_MISMATCH')
    review = json_bytes(raw)
    need(isinstance(review, dict) and set(review) == {
        'schema_version', 'kind', 'purpose', 'subject', 'archive', 'notices'}, 'INVALID_REVIEW_FIELDS')
    need(type(review['schema_version']) is int and review['schema_version'] == 1
         and review['kind'] == 'RESEARCH_CANDIDATE_LOADING_INPUTS' and review['purpose'] == PURPOSE,
         'INVALID_REVIEW_CONTRACT')
    need(snapshot.canonical(review['subject']) == snapshot.canonical(SUBJECT), 'CANDIDATE_SUBJECT_MISMATCH')
    for name in ('archive', 'notices'):
        binding = review[name]
        need(isinstance(binding, dict) and set(binding) == {'sha256', 'storage'}
             and hash_value(binding['sha256']), 'INVALID_ASSET_BINDING')
        loc = binding['storage']
        need(isinstance(loc, dict) and set(loc) == {'kind', 'repository', 'repository_id',
             'release_id', 'asset_id', 'tag', 'asset_name', 'asset_size', 'immutable_required'},
             'INVALID_ASSET_LOCATOR')
        need(loc['kind'] == trust.PRIVATE_RELEASE_KIND and loc['repository'] == REPOSITORY
             and type(loc['repository_id']) is int and loc['repository_id'] == REPOSITORY_ID,
             'REPOSITORY_SCOPE_MISMATCH')
        trust.release_locator(loc)  # same-repository context, numeric identities, bounds
    a, n = review['archive']['storage'], review['notices']['storage']
    need(all(a[k] == n[k] for k in ('repository', 'repository_id', 'release_id', 'tag'))
         and a['asset_id'] != n['asset_id'] and a['asset_name'] != n['asset_name'], 'ASSET_SET_MISMATCH')
    need(n['asset_size'] <= trust.MAX_NOTICES_BYTES, 'NOTICES_TOO_LARGE')
    return review


def member_path(name):
    p = PurePosixPath(name)
    need(bool(p.parts) and not p.is_absolute() and str(p) == name
         and all(part not in ('', '.', '..') for part in name.split('/'))
         and '\\' not in name and ':' not in name and '\x00' not in name,
         'UNSAFE_ARCHIVE_MEMBER')
    return p


def notices_readme(review):
    return ('# Research Candidate notices\n\nCandidate: ' + SUBJECT['candidate_id']
        + '\nCorpus SHA-256: ' + SUBJECT['corpus_sha256']
        + '\nTransport SHA-256: ' + review['archive']['sha256']
        + '\n\nLOCAL_RESEARCH_EXECUTION / HOSTED_NOT_RUN / NO_FRESH_REPLAY.\n'
        'RESEARCH_LOADING_ONLY. These notices accompany the complete original run,\n'
        'including Parent, Candidate, Full and extracted corpus source material.\n'
        'Keep applicable license texts and source mappings with onward transfers.\n'
        'This is not relicensing, Baseline approval or production authorization.\n'
        + '; '.join(RESTRICTIONS) + '.\n').encode()


def verify_notices(path, review):
    path = safe(path); binding = review['notices']
    need(path.stat().st_size == binding['storage']['asset_size'] <= trust.MAX_NOTICES_BYTES
         and snapshot.file_digest(path) == binding['sha256'], 'NOTICES_PIN_MISMATCH')
    names = {'README.md', 'source-and-license-mapping.json'} | {'licenses/' + n for n in LICENSES}
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        need(len(infos) == len(names) and {i.filename for i in infos} == names
             and sum(i.file_size for i in infos) <= trust.MAX_NOTICES_BYTES, 'INVALID_NOTICES_MEMBERS')
        files = {}
        for i in infos:
            member_path(i.filename)
            need(i.filename == i.orig_filename and not i.is_dir() and not i.flag_bits & 1
                 and stat.S_IFMT(i.external_attr >> 16) in (0, stat.S_IFREG), 'UNSAFE_NOTICES_MEMBER')
            files[i.filename] = z.read(i)  # zipfile also verifies CRC
        need(files['README.md'] == notices_readme(review), 'NOTICES_SCOPE_MISMATCH')
        mapping = json_bytes(files['source-and-license-mapping.json'])
        need(isinstance(mapping, dict) and set(mapping) == {'schema_version', 'kind', 'subject',
             'archive_sha256', 'license_texts', 'source_license_bindings', 'project_license_bindings',
             'license_tree_proofs'},
             'INVALID_NOTICES_MAPPING')
        need(type(mapping['schema_version']) is int and mapping['schema_version'] == 1
             and mapping['kind'] == 'RESEARCH_CANDIDATE_NOTICES'
             and snapshot.canonical(mapping['subject']) == snapshot.canonical(SUBJECT)
             and mapping['archive_sha256'] == review['archive']['sha256'], 'NOTICES_SUBJECT_MISMATCH')
        expected = {n: {'sha256': h, 'size': len(files['licenses/' + n])} for n, h in LICENSES.items()}
        need(mapping['license_texts'] == expected and all(
            hash_bytes(files['licenses/' + n]) == h for n, h in LICENSES.items()), 'LICENSE_TEXT_MISMATCH')
    return mapping


@contextmanager
def extracted_run(archive, work, review):
    """Bounded regular-member extraction; no tar.extract/extractall or commands."""
    archive = safe(archive)
    need(archive.stat().st_size == review['archive']['storage']['asset_size']
         and snapshot.file_digest(archive) == review['archive']['sha256'], 'ARCHIVE_PIN_MISMATCH')
    with tarfile.open(archive, 'r:gz', tarinfo=_BoundedTarInfo) as tar:
        infos = []; names = set(); size = 0
        for item in tar:
            member_path(item.name)
            need(item.isfile() and not item.issym() and not item.islnk()
                 and item.name not in names and item.mode & ~0o777 == 0
                 and 0 <= item.size <= FILE_LIMIT, 'UNSAFE_ARCHIVE_MEMBER')
            names.add(item.name); infos.append(item); size += item.size
            need(len(infos) <= COUNT_LIMIT and size <= LIMIT, 'ARCHIVE_LIMIT_EXCEEDED')
        need(all(not any(str(p) in names for p in PurePosixPath(n).parents if str(p) != '.')
                 for n in names), 'ARCHIVE_PATH_COLLISION')
        research.check_archive(archive, review['archive']['sha256'])
        with tempfile.TemporaryDirectory(prefix='candidate-run-', dir=work) as tmp:
            root = Path(tmp)
            for item in infos:
                path = root / item.name; path.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(item) as source, path.open('xb') as target:
                    shutil.copyfileobj(source, target, length=1024**2)
                path.chmod(0o755 if item.mode & 0o111 else 0o644)
                need(path.stat().st_size == item.size, 'EXTRACTION_SIZE_MISMATCH')
            yield root


def verify_source_notices(root, mapping):
    """Check reviewed mappings against actual source members and Git license blobs."""
    bindings = mapping['source_license_bindings']
    need(isinstance(bindings, dict) and set(bindings) == set(VENDOR_NOTICES), 'INCOMPLETE_SOURCE_NOTICES')
    for path, license_name in VENDOR_NOTICES.items():
        expected_members = ['parent/sources/' + path, 'candidate/input/repos/' + path, 'full/sources/' + path]
        need(bindings[path] == {'license': license_name, 'members': {
             n: snapshot.file_digest(snapshot.checked_file(root, n)) for n in expected_members}},
             'SOURCE_LICENSE_BINDING_MISMATCH')
    expected = {(phase, repo, path) for phase in ('base', 'target')
                for repo, paths in [('SPHinXsys', ['LICENSE']),
                                    ('SPHinXsim', ['LICENSE', 'sphinxsim/sphinxsys/LICENSE'])] for path in paths}
    entries = mapping['project_license_bindings']
    need(isinstance(entries, list) and len(entries) == len(expected), 'INCOMPLETE_PROJECT_NOTICES')
    proofs = snapshot.read_json(root / 'candidate/git-proofs.json')
    seen = set()
    extra = mapping['license_tree_proofs']
    need(isinstance(extra, dict) and set(extra) == {'base', 'target'} and all(
         isinstance(extra[phase], dict) and set(extra[phase]) == {'SPHinXsys', 'SPHinXsim'}
         for phase in extra), 'INVALID_LICENSE_TREE_PROOFS')
    used = {(phase, repo): set() for phase in extra for repo in extra[phase]}
    for phase in extra:
        for repo, trees in extra[phase].items():
            need(isinstance(trees, dict) and len(trees) <= 128
                 and not set(trees).intersection(proofs[phase][repo]['trees']), 'INVALID_LICENSE_TREE_PROOFS')
    for entry in entries:
        need(isinstance(entry, dict) and set(entry) == {'phase', 'repository', 'path', 'revision', 'license'},
             'INVALID_PROJECT_LICENSE_BINDING')
        phase, repo, path = entry['phase'], entry['repository'], entry['path']
        key = (phase, repo, path)
        need(key in expected and key not in seen, 'INVALID_PROJECT_LICENSE_BINDING'); seen.add(key)
        license_name = 'MIT-SPHinXsim.txt' if repo == 'SPHinXsim' and path == 'LICENSE' else 'Apache-2.0-SPHinXsys.txt'
        need(entry['revision'] == SUBJECT[phase + '_upstreams'][repo] and entry['license'] == license_name,
             'PROJECT_LICENSE_SUBJECT_MISMATCH')
        proof = proofs[phase][repo]
        tree, _ = provenance._commit(provenance._decoded(proof['commit_raw'], 'commit', proof['commit']))
        for name in path.split('/'):
            trees = {**proof['trees'], **extra[phase][repo]}
            need(tree in trees, 'LICENSE_GIT_PROOF_MISSING')
            if tree in extra[phase][repo]: used[phase, repo].add(tree)
            nodes = provenance._tree(provenance._decoded(trees[tree], 'tree', tree))
            need(name in nodes, 'LICENSE_GIT_PROOF_MISSING')
            _, tree = nodes[name]
        # Mapping is pinned; the retained seven texts' blob identities are fixed.
        raw_pin = LICENSES[license_name]
        need(raw_pin == mapping['license_texts'][license_name]['sha256'], 'LICENSE_TEXT_MISMATCH')
        # Expected raw Git blob IDs for the two complete upstream license texts.
        expected_blob = {'MIT-SPHinXsim.txt': '55ecec75a9c0978b5b4db598764e454bd26f62ec',
                         'Apache-2.0-SPHinXsys.txt': 'fb82ba1eb1b72dcab96a2542a207d978c9d7c985'}
        need(tree == expected_blob[license_name], 'PROJECT_LICENSE_BLOB_MISMATCH')
    need(all(used[phase, repo] == set(extra[phase][repo]) for phase, repo in used),
         'UNUSED_LICENSE_TREE_PROOF')


def verify_run(project, root):
    """Inspect existing sealed science; NEVER schema2_workflow.verify_run/replay."""
    root = safe(root, directory=True)
    paths = list(root.rglob('*'))
    need(len(paths) <= COUNT_LIMIT and all(not p.is_symlink() and
         (p.is_dir() or (p.is_file() and p.stat().st_nlink == 1)) for p in paths), 'UNSAFE_RUN_TREE')
    need(snapshot.file_digest(root / 'checksums.json') == SUBJECT['run_manifest_sha256'], 'RUN_SEAL_PIN_MISMATCH')
    _read_sealed_run(root)
    need(not (root / 'candidate/upstream-baseline.json').exists(), 'BASELINE_SUBSTITUTION_DENIED')
    result = snapshot.read_json(root / 'result.json'); bindings = result['bindings']
    need(all(bindings[k] == SUBJECT[k] for k in ('candidate_id', 'base_source_state',
         'target_source_state', 'base_upstreams', 'target_upstreams', 'build_fingerprint'))
         and bindings['parent_id'] == SUBJECT['parent_id'], 'VERSION_BINDING_MISMATCH')
    need(result['hosted_validation'] == 'HOSTED_NOT_RUN' and result['RESEARCH_BASELINE_APPROVED'] is False
         and result['research_baseline_created'] is False and result['automatic_reuse'] is False
         and result['automatic_research_approval'] is False and result['production_promotion'] == 'NOT_AUTHORIZED'
         and result['retrieval_quality'] == 'QUALITY_REVIEW_REQUIRED'
         and snapshot.read_json(root / 'q1-status.json') == {'status': 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR'},
         'ORIGINAL_RESEARCH_SCOPE_MISMATCH')
    corpus = root / 'candidate/corpus.jsonl'
    need(corpus.stat().st_size == SUBJECT['corpus_size'] and snapshot.file_digest(corpus) == SUBJECT['corpus_sha256'],
         'CORPUS_PIN_MISMATCH')
    records = snapshot.read_records(corpus)
    need(len(records) == SUBJECT['records'], 'CORPUS_RECORD_COUNT_MISMATCH')
    identity = snapshot.read_json(root / 'candidate/upstream-candidate.json')['identity']
    need(identity['orchestration_fingerprint'] == SUBJECT['orchestration_fingerprint']
         and identity['policy_sha256'] == SUBJECT['build_policy_sha256']
         and snapshot.file_digest(root / 'build-policy.json') == SUBJECT['build_policy_sha256'], 'BUILD_POLICY_MISMATCH')
    fp = SUBJECT['build_fingerprint']
    parent = snapshot.verify_snapshot(root / 'parent', fp)
    candidate = provenance.verify(project, root / 'candidate', fp, expected_id=SUBJECT['candidate_id'])
    need(parent['snapshot_id'] == SUBJECT['parent_id'] and candidate['P4_1_verification'] == 'NOT_APPROVED',
         'PARENT_OR_APPROVAL_MISMATCH')
    parity = provenance.compare_full(project, root / 'candidate', root / 'full', fp)
    need(parity['status'] == 'PARITY_PASS' and parity == snapshot.read_json(root / 'parity.json')
         == bindings['four_artifact_parity'], 'FULL_PARITY_MISMATCH')
    inspected = gate.evaluate(root)
    need(inspected['decision'] == 'BLOCKED' and inspected['gate_mode'] == 'BLOCKING_ONLY'
         and inspected['evidence_consistency'] == 'VERIFIED_ARCHIVED_BINDINGS', 'SEALED_EVIDENCE_INVALID')
    lock = snapshot.read_json(project / 'configs/ci_v2_runtime_lock.json')
    spec = evaluation.frozen_implementation(project, root / 'benchmark.json', lock['quality_policy'])
    for label, folder in [('incremental', 'candidate'), ('full', 'full')]:
        rows = snapshot.read_json(root / ('quality/' + label + '-raw-results.json'))
        metrics = evaluation.rescore(rows, spec, snapshot.read_records(root / folder / 'corpus.jsonl'),
                                    snapshot.read_records(root / folder / 'components/documentation.jsonl'))
        need(metrics == result['quality_metrics'] and rows == snapshot.read_json(
             root / ('execution-verification/' + label + '-replay.json')), 'ARCHIVED_R2_MISMATCH')
    reference = snapshot.read_json(root / 'trusted-reference.json')
    anchor = qualify_parent_anchor(project, root / 'parent', reference, snapshot.digest(reference),
                                   root / 'parent-raw-results.json', fresh_replay=False)
    need(anchor['status'] == 'PINNED_ANCHOR_INSPECTED' and anchor['execution'] == 'NO_FRESH_REPLAY',
         'PARENT_ANCHOR_MISMATCH')
    return {'candidate_id': candidate['candidate_id'], 'records': len(records), 'parity': parity['status'],
            'sealed_R2': 'VERIFIED / NO_FRESH_REPLAY', 'P8': inspected['decision']}


def application_check(project, app_python, work, root):
    # Keep the already Hosted-verified namespace/privilege/environment boundary.
    from scripts.check_hosted_gradio_loading import isolated_python
    code = ("sys.path.insert(0,sys.argv[4])\n"
            "os.environ['SPHINX_CORPUS_PATH']=sys.argv[5]\n"
            "from src.corpus_update_integration import _gradio_check\n"
            "r=_gradio_check(pathlib.Path(sys.argv[5]),sys.argv[6],queries=[sys.argv[7]])\n"
            "r['isolation']=isolation\nprint(json.dumps(r))\n")
    return isolated_python(app_python, work, code, (project, root / 'candidate/corpus.jsonl', SUBJECT['corpus_sha256'], QUERY))


def consume(project, review_path, expected_review_sha256, output, app_python, *,
            authorized_review_sha256=None, purpose=None):
    project, output = Path(project).resolve(), Path(output).absolute()
    review = review_inputs(review_path, expected_review_sha256,
        authorized_review_sha256=authorized_review_sha256, purpose=purpose)
    app_python = application_interpreter(app_python)
    need(not output.exists() and not output.is_symlink() and output.is_absolute()
         and not output.is_relative_to(project) and not project.is_relative_to(output)
         and output.parent == safe(output.parent, directory=True), 'NEW_EXTERNAL_OUTPUT_REQUIRED')
    need(not output.is_relative_to(Path(review_path).absolute().parent), 'INPUT_OUTPUT_OVERLAP')
    runtime = research.frozen_runtime(project)
    with tempfile.TemporaryDirectory(prefix='candidate-consumer-', dir=output.parent) as tmp:
        work = Path(tmp)
        for name, binding in [('run.tar.gz', review['archive']), ('notices.zip', review['notices'])]:
            trust.download(binding['storage'], work / name, binding['sha256'],
                           token=os.environ.get('TRUSTED_RELEASE_TOKEN'))
        mapping = verify_notices(work / 'notices.zip', review)  # before any extraction
        with extracted_run(work / 'run.tar.gz', work, review) as root:
            evidence = verify_run(project, root)
            verify_source_notices(root, mapping)
            loaded = application_check(project, app_python, work, root)
            need(loaded['sha256'] == SUBJECT['corpus_sha256'] and loaded['records'] == SUBJECT['records']
                 and loaded['corpus_path'] == str(root / 'candidate/corpus.jsonl')
                 and loaded['complete_records_equal'] is True and loaded['callbacks_share_assistant'] is True
                 and loaded['application_closed'] is True
                 and loaded['retriever_class'] == 'src.retrieval_v1.RetrievalV1', 'APPLICATION_IDENTITY_MISMATCH')
            need(len(loaded['retrieval']) == 1 and loaded['retrieval'][0]['query'] == QUERY
                 and loaded['retrieval'][0]['top_k'] == 5, 'RETRIEVAL_QUERY_MISMATCH')
            records = {r['chunk_id']: r for r in snapshot.read_records(root / 'candidate/corpus.jsonl')}
            hits = loaded['retrieval'][0]['results']
            need(0 < len(hits) <= 5 and all(h['rank'] == rank and h['chunk_id'] in records
                 and h['source_path'] == records[h['chunk_id']]['source_path'] for rank, h in enumerate(hits, 1))
                 and any(h['chunk_id'] == EXPECTED_CHUNK and h['source_path'] == EXPECTED_SOURCE for h in hits),
                 'BOUND_BM25_EVIDENCE_REQUIRED')
            # Recheck the whole sealed run, not only the corpus, after application use.
            _read_sealed_run(root)
            need(snapshot.file_digest(root / 'checksums.json') == SUBJECT['run_manifest_sha256'], 'RUN_CHANGED')
            report = {'status': 'RESEARCH_CANDIDATE_GRADIO_VERIFIED', 'scope': PURPOSE,
                'subject': SUBJECT, 'review_sha256': expected_review_sha256, 'evidence': evidence,
                'frozen_runtime': runtime, 'notices': 'VERIFIED_SOURCE_AND_LICENSE_BINDINGS',
                'application': loaded, 'restrictions': RESTRICTIONS,
                'original_execution': 'LOCAL_RESEARCH_EXECUTION / HOSTED_NOT_RUN',
                'scientific_verification': 'NO_FRESH_REPLAY', 'LLM_calls': 0, 'HTTP_server_started': False,
                'production_promotion': 'NOT_AUTHORIZED'}
    report['temporary_run_and_application_cleaned'] = True
    output.mkdir(mode=0o700)
    snapshot.write_json(output / 'verification.json', report)
    return report
