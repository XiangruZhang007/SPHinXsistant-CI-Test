"""Versioned local research transport, never publication or registration authority.

USTAR/gzip validation is separate from historical archive implementations. Public
operations raise sanitized TransportError on failure. Temporary buffers are owned
and bounded. Inputs must remain stable, caller-controlled files during inspection;
this is not protection against a hostile process with the same filesystem access.
"""
from contextlib import contextmanager
import functools
import gzip
import hashlib
import io
from pathlib import Path, PurePosixPath
import stat
import tarfile
import tempfile
import zlib

from . import local_candidate_evidence as l1
from .corpus_snapshot import canonical, file_digest, checked_file
from .published_candidate_verification import _json

PROJECT = Path(__file__).resolve().parents[1]
LIMIT = 2 * 1024**3
FILE_LIMIT = 256 * 1024**2
JSON_LIMIT = 64 * 1024**2
MANIFEST_LIMIT = 4 * 1024**2
NOTICES_LIMIT = 16 * 1024**2
COUNT_LIMIT = 20000
CHUNK = 1024**2
MANIFEST = 'transport-manifest.json'
BINDINGS = {'evidence_origin', 'hosted_validation', 'candidate_id', 'baseline_id',
    'parent_id', 'corpus_sha256', 'reference_sha256', 'run_manifest_sha256',
    'baseline_manifest_sha256', 'approval_manifest_sha256', 'approval_policy_sha256',
    'execution_records'}
MANIFEST_FIELDS = BINDINGS | {'schema_version', 'kind', 'descriptor_sha256', 'files'}
# Exact seven full texts fixed by the reviewed L2-T contract, not repository IDs.
LICENSES = {
    'Apache-2.0-SPHinXsys.txt': 'a58a31e19f0df71ea68e78cedb67f309822717f1aa59e898ff0489c0184edd45',
    'ISC-Mapbox-earcut-matching-revision.txt': '828f2aed51b6526881a236758ec9b08cd69928fbfc70346d9d44a0b3a3444fe1',
    'MIT-SPHinXsim.txt': '69e91f0babc5a2b21fc484a3c868d7f94890cc1cb7515b3edf80e73dfbcc0e14',
    'Polar-decomposition-MIT-source-notice.txt': '6095ad6860a9f66de67c4dbdedede8baa910932274e695c273a67f6f6dc4f369',
    'TinyXML-2-source-notice.txt': '23ff2801082e675e2ecca91dfcac91b0edd972ce7613ae8a8c6a82fcf6ebe756',
    'TriangleMeshDistance-MIT-source-notice.txt': '9dda21e976a872616ff51f6abeb16fea3407534d0bf21221bfcbef6b0fae358b',
    'stl-reader-BSD-source-notice.txt': 'eabf59116857c496cd99aa7f0f6fba0d2390362fcc089ede3bc453be69c6ce23'}
NOTICE_NAMES = {'notices/README.md', 'notices/source-and-license-mapping.json'} | {
    'notices/licenses/' + n for n in LICENSES}
MAPPING_FIELDS = {'schema_version', 'kind', 'candidate_id', 'baseline_id', 'parent_id',
    'source_state', 'descriptor_sha256', 'run_manifest_sha256', 'base_upstreams',
    'target_upstreams', 'license_texts', 'source_license_bindings', 'project_license_bindings'}


class TransportError(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise TransportError(code)


def guarded(fn):
    @functools.wraps(fn)
    def call(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except TransportError:
            raise
        except (OSError, ValueError, TypeError, KeyError, IndexError, EOFError,
                zlib.error, tarfile.TarError, RecursionError):
            raise TransportError('INVALID_LOCAL_TRANSPORT') from None
    return call


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _check_l1(receipt):
    expected = {'status': 'LOCAL_EVIDENCE_VERIFIED', 'evidence_origin': 'LOCAL_RESEARCH_EXECUTION',
        'hosted_validation': 'HOSTED_NOT_RUN', 'replay': 'NO_FRESH_REPLAY',
        'quality': 'QUALITY_REVIEW_REQUIRED', 'Q1': 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR',
        'P8': 'BLOCKED', 'production_promotion': 'NOT_AUTHORIZED',
        'registration_authorization': 'NOT_GRANTED', 'baseline_anchor_status': 'QUALIFIED'}
    need(isinstance(receipt, dict) and all(receipt.get(k) == v for k, v in expected.items()),
         'L1_VERIFICATION_FAILED')


def _path(name):
    need(isinstance(name, str) and 0 < len(name.encode('ascii')) <= 255
         and all(32 <= ord(c) < 127 for c in name) and '\\' not in name and ':' not in name,
         'UNSAFE_MEMBER_PATH')
    p = PurePosixPath(name)
    need(not p.is_absolute() and str(p) == name and all(
        part not in ('', '.', '..') and not part.endswith((' ', '.')) for part in name.split('/')),
        'UNSAFE_MEMBER_PATH')


def _new_directory(path, protected=()):
    path = Path(path).absolute()
    need('..' not in path.parts and not path.exists() and not path.is_symlink(), 'OUTPUT_NOT_NEW')
    l1._safe(path.parent, directory=True)
    for source in (PROJECT, *map(Path, protected)):
        source = source.resolve()
        need(not path.is_relative_to(source) and not source.is_relative_to(path), 'UNSAFE_OUTPUT')
    path.mkdir(mode=0o700)
    return path


def _descriptor(raw, expected):
    # Bounded metadata inspection only; no destination tree or Parent restoration.
    need(len(raw) <= l1.DESCRIPTOR_LIMIT and _hash(raw) == expected, 'DESCRIPTOR_PIN_MISMATCH')
    with tempfile.TemporaryDirectory(prefix='local-descriptor-inspection-') as tmp:
        path = Path(tmp) / 'descriptor.json'
        path.write_bytes(raw)
        return l1.load_descriptor(path, expected)


def _readme(d, identity):
    return ('# Local research evidence notices\n\n'
        + '\n'.join(k + ': ' + d[k] for k in ('candidate_id', 'baseline_id', 'parent_id', 'source_state'))
        + '\nBase upstreams: ' + canonical(identity['base_upstreams']).decode()
        + '\nTarget upstreams: ' + canonical(identity['upstreams']).decode()
        + '\n\nLOCAL_RESEARCH_EXECUTION; HOSTED_NOT_RUN; NO_FRESH_REPLAY.\n'
        'Original run and selected operator records are unchanged. Corpus, snippets,\n'
        'Full and evaluation records are generated research transformations; original\n'
        'source notices are retained. Seven full license texts and their exact source\n'
        'mapping accompany this complete evidence set. Keep applicable notices with\n'
        'onward transfers and extracted subsets. This is not a relicensing statement.\n'
        'QUALITY_REVIEW_REQUIRED; Q1_NOT_QUALIFIED_FOR_VERSION_PAIR; P8_BLOCKED;\n'
        'PRODUCTION_NOT_AUTHORIZED. LOCAL_PREPUBLICATION_TEST_ARTIFACT.\n'
        'Publication/compliance review and registration authorization remain pending.\n').encode()


def _mapping_base(d, descriptor_sha, identity):
    return dict(schema_version=1, kind='LOCAL_RESEARCH_EVIDENCE_NOTICES',
        **{k: d[k] for k in ('candidate_id', 'baseline_id', 'parent_id', 'source_state',
                            'run_manifest_sha256')}, descriptor_sha256=descriptor_sha,
        base_upstreams=identity['base_upstreams'], target_upstreams=identity['upstreams'])


def _validate_notices(mapping, readme, files, read, d, descriptor_sha, identity):
    need(isinstance(mapping, dict) and set(mapping) == MAPPING_FIELDS, 'INVALID_NOTICES_MAPPING')
    expected = _mapping_base(d, descriptor_sha, identity)
    need(all(type(mapping[k]) is type(v) and mapping[k] == v for k, v in expected.items()),
         'NOTICES_SUBJECT_MISMATCH')
    need(readme == _readme(d, identity), 'NOTICES_SCOPE_MISMATCH')
    texts = mapping['license_texts']
    need(isinstance(texts, dict) and set(texts) == set(LICENSES), 'INCOMPLETE_LICENSE_TEXTS')
    blobs = {}
    for name, pin in LICENSES.items():
        raw = read('notices/licenses/' + name)
        need(_hash(raw) == pin and texts[name] == {'sha256': pin, 'size_bytes': len(raw)},
             'LICENSE_TEXT_MISMATCH')
        blobs[hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()] = pin
    project_bindings = mapping['project_license_bindings']
    expected_keys = {(phase, repo, path) for phase in ('base', 'target')
        for repo, paths in [('SPHinXsys', ['LICENSE']),
                            ('SPHinXsim', ['LICENSE', 'sphinxsim/sphinxsys/LICENSE'])] for path in paths}
    need(isinstance(project_bindings, list) and len(project_bindings) == 6, 'INVALID_PROJECT_LICENSE_BINDINGS')
    observed = set()
    for item in project_bindings:
        need(isinstance(item, dict) and set(item) == {'phase', 'repository', 'revision',
             'path', 'git_blob_sha', 'retained_text_sha256'}, 'INVALID_PROJECT_LICENSE_BINDINGS')
        key = (item['phase'], item['repository'], item['path'])
        need(key in expected_keys and key not in observed, 'INVALID_PROJECT_LICENSE_BINDINGS')
        observed.add(key)
        revisions = identity['base_upstreams'] if item['phase'] == 'base' else identity['upstreams']
        need(item['revision'] == revisions[item['repository']]
             and blobs.get(item['git_blob_sha']) == item['retained_text_sha256'],
             'PROJECT_LICENSE_SUBJECT_MISMATCH')
    bindings = mapping['source_license_bindings']
    need(isinstance(bindings, dict) and len(bindings) == 8, 'INCOMPLETE_VENDOR_MAPPING')
    for path, item in bindings.items():
        _path(path)
        need(isinstance(item, dict) and set(item) == {'sha256', 'notice', 'members'}
             and item['notice'] in {'licenses/' + n for n in LICENSES}, 'INVALID_VENDOR_MAPPING')
        members = sorted(n for n in files if n.startswith('run/') and '/input/' in n
                         and n.split('/input/', 1)[1] == path)
        need(members and item['members'] == members and
             all(files[n]['sha256'] == item['sha256'] for n in members), 'VENDOR_SOURCE_MISMATCH')


def _manifest(d, descriptor_sha, files):
    return {**{k: d[k] for k in BINDINGS}, 'schema_version': 1,
            'kind': 'LOCAL_RESEARCH_EVIDENCE_CONTENT_MANIFEST',
            'descriptor_sha256': descriptor_sha, 'files': files}


def _validate_contents(manifest, descriptor_raw, files, read, *, expected_manifest_sha256,
                       manifest_raw, expected_descriptor_sha256):
    need(_hash(manifest_raw) == expected_manifest_sha256, 'MANIFEST_PIN_MISMATCH')
    need(isinstance(manifest, dict) and set(manifest) == MANIFEST_FIELDS, 'INVALID_MANIFEST_FIELDS')
    need(canonical(manifest) == manifest_raw, 'NONCANONICAL_MANIFEST')
    d = _descriptor(descriptor_raw, expected_descriptor_sha256)
    need(canonical(manifest) == canonical(_manifest(d, expected_descriptor_sha256, files)),
         'MANIFEST_CONTENT_MISMATCH')
    need(set(n for n in files if n.startswith('notices/')) == NOTICE_NAMES,
         'INCOMPLETE_NOTICES')
    need(set(n for n in files if n.startswith('execution-record/')) == {
        'execution-record/' + n for n in l1.RECORD_FILES}, 'EXECUTION_RECORD_SET_MISMATCH')
    need(all(n == 'descriptor.json' or n.startswith(('run/', 'execution-record/', 'notices/'))
             for n in files), 'UNEXPECTED_MEMBER')
    need(all(not item['executable'] for n, item in files.items()
             if not n.startswith(('run/', 'execution-record/'))),
         'INVALID_MEMBER_MODE')
    seal_raw = read('run/checksums.json')
    need(_hash(seal_raw) == d['run_manifest_sha256'], 'RUN_SEAL_PIN_MISMATCH')
    checks = _json(seal_raw)
    need(isinstance(checks, dict) and checks, 'INVALID_RUN_SEAL')
    need(set(n[4:] for n in files if n.startswith('run/')) == set(checks) | {'checksums.json'},
         'RUN_MEMBER_SET_MISMATCH')
    for name, pin in checks.items():
        _path(name)
        need(l1._sha(pin) and files['run/' + name]['sha256'] == pin, 'RUN_MEMBER_HASH_MISMATCH')
    for name, pin in d['execution_records'].items():
        need(files['execution-record/' + name]['sha256'] == pin, 'EXECUTION_RECORD_PIN_MISMATCH')
    identity = _json(read('run/candidate/upstream-candidate.json'))['identity']
    mapping = _json(read('notices/source-and-license-mapping.json'))
    _validate_notices(mapping, read('notices/README.md'), files, read, d,
                      expected_descriptor_sha256, identity)
    return d


def _header(name, size, mode):
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = mode
    info.uid = info.gid = info.mtime = 0
    info.uname = info.gname = ''
    return info


@contextmanager
def _validated(archive, *, expected_archive_sha256, expected_archive_size,
               expected_manifest_sha256, expected_descriptor_sha256):
    archive = l1._safe(archive)
    need(all(l1._sha(v) for v in (expected_archive_sha256, expected_manifest_sha256,
         expected_descriptor_sha256)), 'INVALID_INDEPENDENT_PIN')
    need(type(expected_archive_size) is int and 0 < expected_archive_size <= LIMIT
         and archive.stat().st_size == expected_archive_size, 'ARCHIVE_SIZE_MISMATCH')
    need(file_digest(archive) == expected_archive_sha256, 'ARCHIVE_PIN_MISMATCH')
    with archive.open('rb') as source, tempfile.TemporaryFile() as expanded:
        need(source.read(10) == b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff', 'UNSUPPORTED_GZIP_HEADER')
        source.seek(0)
        decoder = zlib.decompressobj(31)
        total = compressed = 0
        while not decoder.eof:
            data = source.read(CHUNK)
            need(data, 'TRUNCATED_GZIP')
            compressed += len(data)
            need(compressed <= expected_archive_size, 'ARCHIVE_CHANGED')
            while data:
                block = decoder.decompress(data, CHUNK)
                total += len(block)
                need(total <= LIMIT, 'EXPANDED_LIMIT_EXCEEDED')
                expanded.write(block)
                data = decoder.unconsumed_tail
                if decoder.eof:
                    need(not decoder.unused_data and not data and not source.read(1),
                         'TRAILING_OR_CONCATENATED_GZIP')
                    break
        need(total % tarfile.RECORDSIZE == 0, 'UNSUPPORTED_TAR_PADDING')
        expanded.seek(0)
        files, offsets = {}, {}
        previous, folded = '', set()
        notices_size = 0
        while True:
            raw = expanded.read(512)
            need(len(raw) == 512, 'TRUNCATED_USTAR')
            if raw == b'\0' * 512:
                need(expanded.read(512) == b'\0' * 512, 'INVALID_TAR_END')
                end = expanded.tell()
                need(total == ((end + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE)
                     * tarfile.RECORDSIZE, 'UNSUPPORTED_TAR_PADDING')
                while True:
                    tail = expanded.read(CHUNK)
                    if not tail:
                        break
                    need(not any(tail), 'HIDDEN_TAR_PAYLOAD')
                break
            need(raw[257:265] == b'ustar\x0000', 'UNSUPPORTED_TAR_FORMAT')
            item = tarfile.TarInfo.frombuf(raw, 'ascii', 'strict')
            name = item.name
            _path(name)
            need(item.type == tarfile.REGTYPE and item.mode in (0o644, 0o755)
                 and raw == _header(name, item.size, item.mode).tobuf(tarfile.USTAR_FORMAT,
                                                                        'ascii', 'strict'),
                 'UNSUPPORTED_MEMBER_METADATA')
            need(name > previous and name.casefold() not in folded, 'DUPLICATE_OR_UNSORTED_MEMBER')
            need(not any('/'.join(name.casefold().split('/')[:i]) in folded
                         for i in range(1, len(name.split('/')))), 'MEMBER_PREFIX_COLLISION')
            need(not any(n.startswith(name.casefold() + '/') for n in folded), 'MEMBER_PREFIX_COLLISION')
            previous = name
            folded.add(name.casefold())
            need(len(folded) <= COUNT_LIMIT and 0 <= item.size <= FILE_LIMIT, 'MEMBER_LIMIT_EXCEEDED')
            limit = (MANIFEST_LIMIT if name == MANIFEST else l1.DESCRIPTOR_LIMIT
                     if name == 'descriptor.json' else JSON_LIMIT if name.endswith('.json') else FILE_LIMIT)
            need(item.size <= limit, 'OVERSIZED_MEMBER')
            if name.startswith('notices/'):
                notices_size += item.size
                need(notices_size <= NOTICES_LIMIT, 'OVERSIZED_NOTICES')
            offsets[name] = (expanded.tell(), item.size)
            h = hashlib.sha256()
            remaining = item.size
            while remaining:
                block = expanded.read(min(CHUNK, remaining))
                need(block, 'TRUNCATED_MEMBER')
                h.update(block)
                remaining -= len(block)
            pad = expanded.read((-item.size) % 512)
            need(len(pad) == (-item.size) % 512 and not any(pad), 'INVALID_MEMBER_PADDING')
            files[name] = {'size_bytes': item.size, 'sha256': h.hexdigest(), 'executable': item.mode == 0o755}
        need(MANIFEST in files and 'descriptor.json' in files, 'MISSING_TRANSPORT_METADATA')
        need(not files[MANIFEST]['executable'], 'INVALID_MEMBER_MODE')
        def read(name):
            offset, size = offsets[name]
            expanded.seek(offset)
            raw = expanded.read(size)
            need(len(raw) == size, 'TRUNCATED_MEMBER')
            return raw
        manifest_raw = read(MANIFEST)
        manifest = _json(manifest_raw)
        payload = {n: v for n, v in files.items() if n != MANIFEST}
        d = _validate_contents(manifest, read('descriptor.json'), payload, read,
            manifest_raw=manifest_raw, expected_manifest_sha256=expected_manifest_sha256,
            expected_descriptor_sha256=expected_descriptor_sha256)
        need(file_digest(archive) == expected_archive_sha256
             and archive.stat().st_size == expected_archive_size, 'ARCHIVE_CHANGED')
        yield expanded, offsets, files, d


@guarded
def inspect_archive(archive, **pins):
    """No destination extraction or L1/scientific execution."""
    with _validated(archive, **pins) as (_, offsets, files, d):
        return {'status': 'LOCAL_TRANSPORT_VERIFIED', 'evidence_origin': d['evidence_origin'],
                'hosted_validation': d['hosted_validation'], 'members': len(files),
                'manifest_sha256': pins['expected_manifest_sha256'],
                'descriptor_sha256': pins['expected_descriptor_sha256'],
                'archive_sha256': pins['expected_archive_sha256'],
                'publication': 'NOT_PERFORMED', 'registration_authorization': 'NOT_GRANTED'}


@guarded
def extract(archive, destination, **pins):
    """Validate ALL bytes before creating a new external destination."""
    with _validated(archive, **pins) as (expanded, offsets, files, d):
        destination = _new_directory(destination, (archive,))
        for name, (offset, size) in offsets.items():
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            expanded.seek(offset)
            remaining = size
            with path.open('xb') as stream:
                while remaining:
                    data = expanded.read(min(CHUNK, remaining))
                    need(data, 'TRUNCATED_EXTRACTION')
                    stream.write(data)
                    remaining -= len(data)
            path.chmod(0o755 if files[name]['executable'] else 0o644)
        _extracted(destination, pins['expected_manifest_sha256'], pins['expected_descriptor_sha256'])
        return {'status': 'LOCAL_TRANSPORT_EXTRACTED', 'destination': str(destination),
                'publication': 'NOT_PERFORMED', 'registration_authorization': 'NOT_GRANTED'}


def _extracted(root, manifest_pin, descriptor_pin):
    root = l1._tree(root)
    actual = {}
    for path in root.rglob('*'):
        if path.is_file():
            name = path.relative_to(root).as_posix()
            _path(name)
            mode = stat.S_IMODE(path.stat().st_mode)
            need(mode in (0o644, 0o755), 'INVALID_EXTRACTED_MODE')
            actual[name] = {'size_bytes': path.stat().st_size, 'sha256': file_digest(path),
                            'executable': mode == 0o755}
    names = sorted(actual)
    need(len(names) <= COUNT_LIMIT, 'MEMBER_LIMIT_EXCEEDED')
    expected_dirs = {parent for name in names for parent in PurePosixPath(name).parents
                     if str(parent) != '.'}
    actual_dirs = {PurePosixPath(p.relative_to(root).as_posix()) for p in root.rglob('*') if p.is_dir()}
    need(actual_dirs == expected_dirs, 'UNEXPECTED_EXTRACTED_DIRECTORY')
    need(sum(v['size_bytes'] for n, v in actual.items() if n.startswith('notices/'))
         <= NOTICES_LIMIT, 'OVERSIZED_NOTICES')
    folded = {n.casefold() for n in names}
    need(len(folded) == len(names), 'CASEFOLD_COLLISION')
    need(MANIFEST in actual and not actual[MANIFEST]['executable'], 'MISSING_TRANSPORT_METADATA')
    def read(name):
        path = checked_file(root, name)
        limit = MANIFEST_LIMIT if name == MANIFEST else l1.DESCRIPTOR_LIMIT if name == 'descriptor.json' else JSON_LIMIT
        need(path.stat().st_size <= limit, 'OVERSIZED_METADATA')
        return path.read_bytes()
    raw = read(MANIFEST)
    need(len(raw) <= MANIFEST_LIMIT, 'OVERSIZED_MANIFEST')
    files = {n: v for n, v in actual.items() if n != MANIFEST}
    return _validate_contents(_json(raw), read('descriptor.json'), files, read, manifest_raw=raw,
        expected_manifest_sha256=manifest_pin, expected_descriptor_sha256=descriptor_pin)


@guarded
def verify_extracted(project, root, baseline, reference_path, *,
                     expected_manifest_sha256, expected_descriptor_sha256):
    """Read-only reinspection; saved extraction receipts confer no trust."""
    need(l1._sha(expected_manifest_sha256) and l1._sha(expected_descriptor_sha256),
         'INVALID_INDEPENDENT_PIN')
    d = _extracted(root, expected_manifest_sha256, expected_descriptor_sha256)
    receipt = l1.verify(project, Path(root) / 'run', Path(root) / 'execution-record', baseline,
        Path(root) / 'descriptor.json', expected_descriptor_sha256=expected_descriptor_sha256,
        reference_path=reference_path)
    _check_l1(receipt)
    return receipt


@guarded
def verify_archive(project, archive, destination, baseline, reference_path, **pins):
    extract(archive, destination, **pins)
    return verify_extracted(project, destination, baseline, reference_path,
        expected_manifest_sha256=pins['expected_manifest_sha256'],
        expected_descriptor_sha256=pins['expected_descriptor_sha256'])


@guarded
def prepare(project, run, execution_records, baseline, descriptor_path, reference_path,
            license_directory, notices_review_path, output, *,
            expected_descriptor_sha256, expected_notices_review_sha256):
    """Prepare only LOCAL_PREPUBLICATION_TEST_ARTIFACT; never publish or authorize."""
    need(l1._sha(expected_notices_review_sha256), 'INVALID_NOTICES_REVIEW_PIN')
    review_path = l1._safe(notices_review_path)
    need(file_digest(review_path) == expected_notices_review_sha256, 'NOTICES_REVIEW_PIN_MISMATCH')
    review = l1._read(review_path)[0]
    descriptor_path = l1._safe(descriptor_path)
    d = l1.load_descriptor(descriptor_path, expected_descriptor_sha256)
    receipt = l1.verify(project, run, execution_records, baseline, descriptor_path,
        expected_descriptor_sha256=expected_descriptor_sha256, reference_path=reference_path)
    _check_l1(receipt)
    run, execution_records = l1._tree(run), l1._tree(execution_records)
    sources = {'descriptor.json': descriptor_path}
    for path in run.rglob('*'):
        if path.is_file():
            sources['run/' + path.relative_to(run).as_posix()] = path
    for name in l1.RECORD_FILES:
        sources['execution-record/' + name] = checked_file(execution_records, name)
    generated = {}
    for name, pin in LICENSES.items():
        path = checked_file(l1._safe(license_directory, directory=True), name)
        need(path.stat().st_size <= NOTICES_LIMIT and file_digest(path) == pin, 'LICENSE_TEXT_MISMATCH')
        generated['notices/licenses/' + name] = path.read_bytes()
    identity = l1._read(run / 'candidate/upstream-candidate.json')[0]['identity']
    mapping = _mapping_base(d, expected_descriptor_sha256, identity)
    mapping['license_texts'] = {n: {'sha256': pin,
        'size_bytes': len(generated['notices/licenses/' + n])} for n, pin in LICENSES.items()}
    mapping['project_license_bindings'] = review['base_target_license_git_tree_bindings']
    mapping['source_license_bindings'] = {}
    for path, item in review['vendor_matches'].items():
        mapping['source_license_bindings'][path] = {'sha256': item['sha256'], 'notice': item['notice'],
            'members': sorted(n for n in sources if '/input/' in n and n.split('/input/', 1)[1] == path)}
    generated['notices/source-and-license-mapping.json'] = canonical(mapping)
    generated['notices/README.md'] = _readme(d, identity)
    files = {n: {'size_bytes': p.stat().st_size, 'sha256': file_digest(p),
                 'executable': bool(p.stat().st_mode & 0o111)} for n, p in sources.items()}
    files['descriptor.json']['executable'] = False
    files.update({n: {'size_bytes': len(raw), 'sha256': _hash(raw), 'executable': False}
                  for n, raw in generated.items()})
    raw_manifest = canonical(_manifest(d, expected_descriptor_sha256, files))
    need(len(raw_manifest) <= MANIFEST_LIMIT, 'OVERSIZED_MANIFEST')
    tar_bytes = sum(v['size_bytes'] + 512 + (-v['size_bytes']) % 512 for v in files.values())
    tar_bytes += 512 + len(raw_manifest) + (-len(raw_manifest)) % 512 + 1024
    tar_bytes = ((tar_bytes + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE
    need(len(files) + 1 <= COUNT_LIMIT and tar_bytes <= LIMIT
         and all(v['size_bytes'] <= FILE_LIMIT for v in files.values()), 'PACKAGING_LIMIT_EXCEEDED')
    generated[MANIFEST] = raw_manifest
    def read(n):
        return generated[n] if n in generated else sources[n].read_bytes()
    _validate_contents(_json(raw_manifest), read('descriptor.json'), files, read,
        manifest_raw=raw_manifest, expected_manifest_sha256=_hash(raw_manifest),
        expected_descriptor_sha256=expected_descriptor_sha256)
    output = _new_directory(output, (run, execution_records, baseline, license_directory,
                                     descriptor_path, reference_path, notices_review_path))
    target = output / 'local-research-evidence.tar.gz'
    with target.open('xb') as stream, gzip.GzipFile(fileobj=stream, mode='wb', filename='',
            mtime=0, compresslevel=9) as zipped, tarfile.open(fileobj=zipped, mode='w|',
            format=tarfile.USTAR_FORMAT, encoding='ascii', errors='strict') as tar:
        for name in sorted(set(sources) | set(generated)):
            _path(name)
            size = files[name]['size_bytes'] if name in files else len(generated[name])
            mode = 0o755 if name in files and files[name]['executable'] else 0o644
            header = _header(name, size, mode)
            if name in generated:
                tar.addfile(header, io.BytesIO(generated[name]))
            else:
                with sources[name].open('rb') as source:
                    tar.addfile(header, source)
    pins = dict(expected_archive_sha256=file_digest(target), expected_archive_size=target.stat().st_size,
        expected_manifest_sha256=_hash(raw_manifest), expected_descriptor_sha256=expected_descriptor_sha256)
    inspect_archive(target, **pins)
    for name, path in sources.items():
        need(file_digest(path) == files[name]['sha256'], 'INPUT_CHANGED_DURING_PACKAGING')
    for name, raw in generated.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw)
    receipt = {'status': 'LOCAL_PREPUBLICATION_TEST_ARTIFACT', 'archive': str(target), **pins,
        'publication_authorization': 'NOT_GRANTED', 'registration': 'NOT_PERFORMED',
        'production_promotion': 'NOT_AUTHORIZED'}
    (output / 'preparation.json').write_bytes(canonical(receipt))
    return receipt
