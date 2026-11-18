"""Explicitly authorized snapshot recovery from immutable GitHub Releases.

The expected reference digest is supplied outside the downloaded package. An
integrity check is not an authorization and a P2 anchor is not research approval.
Public P2 transport remains unauthenticated; private same-repository transport
uses a narrowly scoped workflow token for API requests only.
"""
from pathlib import Path
import os
import re
import shutil
import tarfile
import tempfile
import urllib.parse
import urllib.request

from . import ci_v2_research as c
from .corpus_snapshot import checked_file, digest, file_digest, read_json

REGISTRY = c.ROOT / 'configs/ci_v2_schema2_trusted_baselines.json'
RELEASE_REPOSITORY = 'XiangruZhang007/SPHinX_AI_Assistant'
PRIVATE_RELEASE_KIND = 'GITHUB_PRIVATE_RELEASE_ASSET'
PUBLIC_RELEASE_KIND = 'GITHUB_RELEASE_ASSET'
RELEASE_DOWNLOAD_HOSTS = frozenset(('github.com', 'release-assets.githubusercontent.com',
                                    'objects.githubusercontent.com'))
FORMATS = {'p2-snapshot-v1': (1, 'EXPLICIT_P2_BOOTSTRAP'),
           'schema2-research-baseline': (2, 'EXPLICIT_RESEARCH_BASELINE_REUSE')}
DOWNLOAD_IMPLEMENTATION = 'atomic-no-clobber-v2'
NOTICES_REFERENCE_VERSION = 3
MAX_NOTICES_BYTES = 16 * 1024**2


def validate_reference(ref, expected_sha, *, remote=False, controlled=False):
    c.need(digest(ref) == expected_sha, 'INVALID_REFERENCE', 'Independent trusted reference checksum mismatch')
    required = {'schema_version', 'package_format', 'accepted_package_schema', 'node_id', 'package_checksum',
        'manifest_sha256', 'transport_sha256', 'source_state', 'upstreams', 'build_fingerprint',
        'corpus_sha256', 'authorization', 'storage', 'parent_rows_sha256'}
    c.need(isinstance(ref, dict) and required <= ref.keys() and type(ref['schema_version']) is int
           and ref['schema_version'] in (2, NOTICES_REFERENCE_VERSION),
           'INVALID_REFERENCE', 'Incomplete versioned trust reference')
    c.need(ref['package_format'] in FORMATS, 'INVALID_REFERENCE', 'Unsupported exact package format')
    schema, authorization = FORMATS[ref['package_format']]
    c.need(type(ref['accepted_package_schema']) is int and ref['accepted_package_schema'] == schema,
           'INVALID_REFERENCE', 'Unsupported accepted package schema')
    for field in ('package_checksum', 'manifest_sha256', 'transport_sha256', 'build_fingerprint', 'corpus_sha256', 'parent_rows_sha256'):
        c.need(isinstance(ref[field], str) and re.fullmatch('[0-9a-f]{64}', ref[field]), 'INVALID_REFERENCE', 'Invalid hash: ' + field)
    for field in ('node_id', 'source_state'):
        c.need(isinstance(ref[field], str) and re.fullmatch('sha256-[0-9a-f]{64}', ref[field]), 'INVALID_REFERENCE', 'Invalid identity: ' + field)
    c.validate_request('formal', 'schema2', ref['upstreams'])
    auth = ref['authorization']
    c.need(auth.get('type') == authorization and auth.get('scope') == 'ISOLATED_RESEARCH_PARENT_REUSE'
        and auth.get('research_only') is True and auth.get('experiment_id')
        and auth.get('automatic_research_approval') is False and auth.get('production_promotion') == 'NOT_AUTHORIZED',
        'AUTHORIZATION_FAILED', 'Missing explicit scoped bootstrap/research authorization')
    kind = ref['storage'].get('kind')
    c.need(kind in (PUBLIC_RELEASE_KIND, PRIVATE_RELEASE_KIND, 'LOCAL_QUALIFICATION_ONLY'),
           'INVALID_REFERENCE', 'Unsupported trusted storage')
    if remote:
        c.need(not controlled and kind in (PUBLIC_RELEASE_KIND, PRIVATE_RELEASE_KIND), 'CONFIGURATION_REQUIRED',
               'Remote registry needs a reviewed immutable Release asset')
        primary = ref['storage']
        rows = ref.get('parent_rows_storage', {})
        release_locator(primary)
        release_locator(rows)
        if PRIVATE_RELEASE_KIND in (primary.get('kind'), rows.get('kind')):
            c.need(primary.get('kind') == rows.get('kind') == PRIVATE_RELEASE_KIND
                and all(primary.get(k) == rows.get(k) for k in ('repository', 'repository_id', 'release_id', 'tag'))
                and primary.get('asset_id') != rows.get('asset_id')
                and primary.get('asset_name') != rows.get('asset_name'),
                'INVALID_REFERENCE', 'Private baseline and Parent R2 assets must be distinct assets in the same pinned Release')
    else:
        c.need(not controlled or kind == 'LOCAL_QUALIFICATION_ONLY', 'AUTHORIZATION_FAILED', 'Fixture privileges cannot enter remote trust')
    if ref['schema_version'] == NOTICES_REFERENCE_VERSION:
        notices_binding(ref)
    else:
        c.need('notices' not in ref, 'INVALID_REFERENCE', 'Notices require reference version 3')
    return ref


def notices_binding(ref):
    """Versioned metadata only; the external reference digest pins this binding.

    Legacy references have no new duty inferred from their old approvals.
    Metadata validation is not live download authority or research approval.
    """
    if ref.get('schema_version') != NOTICES_REFERENCE_VERSION:
        return None
    binding = ref.get('notices')
    c.need(ref.get('package_format') == 'schema2-research-baseline'
        and isinstance(binding, dict) and set(binding) == {
            'schema_version', 'baseline_id', 'parent_transport_sha256', 'sha256', 'storage'}
        and type(binding['schema_version']) is int and binding['schema_version'] == 1
        and binding['baseline_id'] == ref['node_id']
        and binding['parent_transport_sha256'] == ref['transport_sha256']
        and isinstance(binding['sha256'], str) and re.fullmatch('[0-9a-f]{64}', binding['sha256']),
        'NOTICES_REQUIRED', 'Missing or mismatched mandatory notices binding')
    stores = [ref.get('storage'), ref.get('parent_rows_storage'), binding['storage']]
    fields = {'kind', 'repository', 'repository_id', 'release_id', 'tag',
              'asset_id', 'asset_name', 'asset_size', 'immutable_required'}
    for s in stores:
        # Offline shape checks do not manufacture a GitHub runtime identity.
        # download() still enforces the existing same-repository runtime gate.
        c.need(isinstance(s, dict) and fields <= s.keys() and s['kind'] == PRIVATE_RELEASE_KIND
            and isinstance(s['repository'], str)
            and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}', s['repository'])
            and all(type(s[k]) is int and s[k] > 0 for k in ('repository_id', 'release_id', 'asset_id'))
            and isinstance(s['tag'], str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}', s['tag'])
            and s['tag'].lower() not in ('latest', 'main', 'master')
            and isinstance(s['asset_name'], str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}', s['asset_name'])
            and type(s['asset_size']) is int and 0 < s['asset_size'] <= 2 * 1024**3
            and s['immutable_required'] is True,
            'INVALID_REFERENCE', 'Invalid private notices delivery locator')
    c.need(set(binding['storage']) == fields
        and binding['storage']['asset_size'] <= MAX_NOTICES_BYTES
        and binding['storage']['asset_name'].endswith('.zip')
        and all(all(s[k] == stores[0][k] for k in ('repository', 'repository_id', 'release_id', 'tag')) for s in stores)
        and len({s['asset_id'] for s in stores}) == 3
        and len({s['asset_name'] for s in stores}) == 3,
        'INVALID_REFERENCE', 'Notices must be a distinct asset in the exact Parent Release')
    return binding


def verify_notices(ref, expected_ref_sha, path):
    """Read a pinned ZIP without extracting; internal hashes are not trust pins."""
    import hashlib
    import json
    import stat
    import zipfile
    from pathlib import PurePosixPath
    binding = notices_binding(ref)
    if binding is None:
        return None
    validate_reference(ref, expected_ref_sha)
    c.need(path is not None, 'NOTICES_REQUIRED', 'Mandatory notices file is missing')
    path = Path(path)
    c.need(path.is_file() and not path.is_symlink(), 'NOTICES_REQUIRED', 'Mandatory notices file is missing or unsafe')
    c.need(path.stat().st_size == binding['storage']['asset_size']
        and path.stat().st_size <= MAX_NOTICES_BYTES,
        'NOTICES_INVALID', 'Notices file size mismatch')
    with path.open('rb') as stream:
        raw = stream.read(MAX_NOTICES_BYTES + 1)
    c.need(len(raw) == binding['storage']['asset_size'] and len(raw) <= MAX_NOTICES_BYTES
        and hashlib.sha256(raw).hexdigest() == binding['sha256'], 'NOTICES_INVALID', 'Notices SHA-256 mismatch')
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            c.need(key not in obj, 'NOTICES_INVALID', 'Duplicate notices JSON field')
            obj[key] = value
        return obj
    try:
        import io
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            c.need(0 < len(members) <= 256 and sum(m.file_size for m in members) <= MAX_NOTICES_BYTES,
                   'NOTICES_INVALID', 'Notices ZIP exceeds size or member limit')
            files = {}
            for m in members:
                name = m.filename; relative = PurePosixPath(name)
                c.need(name == m.orig_filename and relative.parts and not relative.is_absolute()
                    and str(relative) == name and not any(p in ('', '.', '..') for p in relative.parts)
                    and '\\' not in name and ':' not in name and not m.is_dir()
                    and stat.S_IFMT(m.external_attr >> 16) in (0, stat.S_IFREG)
                    and m.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    and not m.flag_bits & 1 and name not in files,
                    'NOTICES_INVALID', 'Unsafe or duplicate notices ZIP member')
                files[name] = archive.read(m)
            required = {'README.txt', 'DELIVERY.md', 'SHA256SUMS', 'source-and-license-mapping.json'}
            c.need(required <= files.keys() and any(n.startswith('licenses/') and files[n] for n in files),
                   'NOTICES_INVALID', 'Required notices documents are missing')
            expected = {}
            for line in files['SHA256SUMS'].decode('utf-8').splitlines():
                match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
                c.need(match is not None and match[2] not in expected, 'NOTICES_INVALID', 'Invalid notices internal checksum manifest')
                expected[match[2]] = match[1]
            c.need(set(expected) == set(files) - {'SHA256SUMS'}
                and all(hashlib.sha256(files[n]).hexdigest() == checksum for n, checksum in expected.items()),
                'NOTICES_INVALID', 'Notices internal checksum mismatch')
            subject = json.loads(files['source-and-license-mapping.json'], object_pairs_hook=unique)
            c.need(isinstance(subject, dict) and subject.get('baseline_id') == ref['node_id']
                and subject.get('transport_sha256') == ref['transport_sha256'],
                'NOTICES_INVALID', 'Notices content belongs to a different Parent or transport')
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
        raise c.GateError('NOTICES_INVALID', 'Notices ZIP or internal bindings failed validation') from None
    c.need(file_digest(path) == binding['sha256'], 'NOTICES_INVALID', 'Notices changed during validation')
    return {'schema_version': 1, 'status': 'NOTICES_VERIFIED', 'baseline_id': ref['node_id'],
        'parent_transport_sha256': ref['transport_sha256'], 'reference_sha256': expected_ref_sha,
        'notices_sha256': binding['sha256'], 'storage': binding['storage'],
        'internal_manifest_sha256': hashlib.sha256(files['SHA256SUMS']).hexdigest(),
        'production_promotion': 'NOT_AUTHORIZED'}


def fetch_notices(ref, expected_ref_sha, destination):
    """No new downloader or credentials: use the existing private asset gate."""
    binding = notices_binding(ref)
    if binding is None:
        return None
    validate_reference(ref, expected_ref_sha, remote=True)
    download(binding['storage'], destination, binding['sha256'], token=os.environ.get('TRUSTED_RELEASE_TOKEN'))
    verify_notices(ref, expected_ref_sha, destination)
    return Path(destination)


def retain_notices(ref, expected_ref_sha, path, root):
    """New delivery attachment, never a member injected into the sealed Parent."""
    receipt = verify_notices(ref, expected_ref_sha, path)
    if receipt is None:
        return None
    attachment = Path(root) / 'notices'
    c.need(not attachment.exists() and not attachment.is_symlink(), 'INVALID_OUTPUT', 'Notices output must be new')
    attachment.mkdir()
    shutil.copyfile(path, attachment / 'companion.zip')
    c.need(verify_notices(ref, expected_ref_sha, attachment / 'companion.zip') == receipt,
           'NOTICES_INVALID', 'Retained notices differ from verified input')
    from .corpus_snapshot import write_json
    write_json(attachment / 'verification.json', receipt)
    return receipt


def verify_retained_notices(ref, expected_ref_sha, root):
    if notices_binding(ref) is None:
        return None
    attachment = Path(root) / 'notices'
    c.need(attachment.is_dir() and not attachment.is_symlink()
        and {p.name for p in attachment.iterdir()} == {'companion.zip', 'verification.json'},
        'NOTICES_REQUIRED', 'Retained notices attachment is incomplete')
    receipt = verify_notices(ref, expected_ref_sha, checked_file(attachment, 'companion.zip'))
    c.need(read_json(checked_file(attachment, 'verification.json')) == receipt,
           'NOTICES_INVALID', 'Retained notices receipt mismatch')
    return receipt


def registry_reference(registry, key):
    c.need(registry.get('schema_version') == 2 and isinstance(registry.get('baselines'), dict), 'INVALID_REFERENCE', 'Wrong registry schema')
    c.validate_request('formal', key, c.read(c.LOCK)['upstreams'])
    entry = registry['baselines'].get(key)
    c.need(isinstance(entry, dict), 'BOOTSTRAP_REQUIRED', 'No reviewed schema-2 trusted baseline: ' + key)
    validate_reference(entry['reference'], entry['expected_reference_sha256'], remote=True)
    return entry


def verify_package(project, root, ref, *, controlled=False):
    from . import upstream_provenance as u
    from .research_baseline import read_parent
    root = Path(root); fp = ref['build_fingerprint']
    c.need(file_digest(checked_file(root, 'checksums.json')) == ref['manifest_sha256'], 'INVALID_BASELINE', 'Sealed manifest mismatch')
    if ref['package_format'] == 'p2-snapshot-v1':
        info = read_parent(project, root, fp, baseline_format='p2')
        node, package = info['baseline_id'], info['package_checksum']
        upstreams = info['upstreams']; approval = 'NOT_APPLICABLE_P2_ANCHOR'
        c.need(not (root / 'upstream-baseline.json').exists(), 'INVALID_BASELINE', 'Mixed baseline formats')
    else:
        info = u.verify(project, root, fp, expected_id=ref['node_id'])
        c.need(info['receipt']['kind'] == 'RESEARCH_BASELINE' and info['P4_1_verification'] == 'P4_1_VERIFIED',
               'INVALID_BASELINE', 'Unapproved candidate is not a trusted research baseline')
        c.need(info['provenance_type'] == ('CONTROLLED_GIT_FIXTURE' if controlled else 'GENUINE_UPSTREAM'),
               'INVALID_BASELINE', 'Controlled provenance cannot become a genuine trusted baseline')
        node, package = info['node_id'], info['receipt']['package_checksum']
        upstreams = info['upstreams']; approval = info['P4_1_verification']
    selected = read_json(root / 'selection.json')
    checks = {'node_id': node, 'package_checksum': package, 'upstreams': upstreams,
              'source_state': u.state(selected), 'corpus_sha256': file_digest(root / 'corpus.jsonl')}
    for name, actual in checks.items():
        c.need(actual == ref[name], 'INVALID_BASELINE', 'Trusted package binding mismatch: ' + name)
    return {**checks, 'approval': approval, 'package_format': ref['package_format'],
            'parent_reuse': 'P2_BOOTSTRAP_ONLY' if ref['package_format'] == 'p2-snapshot-v1' else 'P4_1_VERIFIED',
            'controlled_fixture': controlled, 'production_promotion': 'NOT_AUTHORIZED'}


def extract_regular(archive, destination, expected_sha):
    """Bounded new-directory extraction; reject links, aliases and path traversal."""
    archive, destination = Path(archive), Path(destination)
    c.check_archive(archive, expected_sha)
    c.need(not destination.exists() and not destination.is_symlink() and destination.parent.is_dir(),
           'INVALID_OUTPUT', 'Restore destination must be new')
    c.need(not archive.resolve().is_relative_to(destination.resolve()), 'INVALID_OUTPUT', 'Archive overlaps destination')
    destination.mkdir()
    with tarfile.open(archive, 'r:*') as tar:
        for member in tar:
            c.need(member.isfile(), 'UNSAFE_ARCHIVE', 'Archive changed to a nonregular member during extraction')
            target = destination / member.name
            c.need(target.resolve().is_relative_to(destination.resolve()), 'UNSAFE_ARCHIVE', 'Extraction escaped destination')
            target.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as source, target.open('xb') as stream:
                shutil.copyfileobj(source, stream)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
    c.need(file_digest(archive) == expected_sha, 'CORRUPT_DOWNLOAD', 'Archive changed during extraction')


def restore(project, archive, destination, ref, expected_sha, *, controlled=False, notices_path=None):
    """Restore only after validating mandatory versioned delivery inputs.

    Version 2 keeps its historical behavior. Version 3 requires the actual ZIP,
    never a saved receipt or caller assertion, even for direct library calls.
    """
    from . import upstream_provenance as u
    validate_reference(ref, expected_sha, controlled=controlled)
    verify_notices(ref, expected_sha, notices_path)
    destination = Path(destination)
    u._new_output(destination, (project, archive))
    with tempfile.TemporaryDirectory(prefix='.trusted-restore-', dir=destination.parent) as tmp:
        staged = Path(tmp) / 'payload'
        extract_regular(archive, staged, ref['transport_sha256'])
        info = verify_package(project, staged, ref, controlled=controlled)
        os.replace(staged, destination)
    return info


def release_locator(storage):
    kind = storage.get('kind')
    repository = storage.get('repository')
    c.need(kind in (PUBLIC_RELEASE_KIND, PRIVATE_RELEASE_KIND)
        and isinstance(repository, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}', repository)
        and all(type(storage.get(k)) is int and storage[k] > 0 for k in ('release_id', 'asset_id'))
        and isinstance(storage.get('tag'), str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}', storage['tag'])
        and storage['tag'].lower() not in ('latest', 'main', 'master')
        and isinstance(storage.get('asset_name'), str) and re.fullmatch('[A-Za-z0-9][A-Za-z0-9._-]{0,127}', storage['asset_name'])
        and storage.get('immutable_required') is True, 'UNSAFE_INPUT', 'Unpinned or incomplete immutable Release locator')
    if kind == PUBLIC_RELEASE_KIND:
        c.need(repository == RELEASE_REPOSITORY, 'UNSAFE_INPUT', 'Public Release repository differs from the pinned P2 host')
    else:
        c.need(type(storage.get('repository_id')) is int and storage['repository_id'] > 0
            and type(storage.get('asset_size')) is int and 0 < storage['asset_size'] <= 2 * 1024**3,
            'UNSAFE_INPUT', 'Private Release needs pinned repository ID and asset size')
        # A private reference is valid only when this workflow itself runs from
        # the same repository. This prevents GITHUB_TOKEN from becoming a
        # cross-repository credential.
        c.need(os.environ.get('GITHUB_REPOSITORY') == repository
            and os.environ.get('GITHUB_REPOSITORY_ID') == str(storage['repository_id']),
            'UNSAFE_INPUT', 'Private Release must belong to this exact workflow repository')
    return 'https://api.github.com/repos/' + repository


def _request(url, *, binary=False, token=None):
    """Request GitHub API metadata and follow only safe asset redirects.

    Authentication is attached only to api.github.com. Redirects are handled
    manually so a token can never be forwarded to a CDN or other host.
    """
    def check_url(target, *, redirect=False):
        parsed = urllib.parse.urlsplit(target)
        try:
            port = parsed.port
        except ValueError:
            raise c.GateError('UNSAFE_INPUT', 'Unsafe GitHub Release URL') from None
        allowed_hosts = RELEASE_DOWNLOAD_HOSTS if redirect else frozenset(('api.github.com',))
        c.need(parsed.scheme == 'https' and parsed.hostname in allowed_hosts
            and not parsed.username and not parsed.password and port in (None, 443)
            and not parsed.fragment, 'UNSAFE_INPUT', 'Unsafe GitHub Release URL')
        return parsed

    check_url(url)
    c.need(token is None or (isinstance(token, str) and token and not any(ch.isspace() for ch in token)),
           'AUTHENTICATION_FAILED', 'Invalid GitHub token input')

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirect())
    current, current_token = url, token
    for redirect_count in range(4):
        parsed = check_url(current, redirect=redirect_count > 0)
        headers = {'Accept': 'application/octet-stream' if binary else 'application/vnd.github+json',
                   'User-Agent': 'SPHinXsistant-research-recovery'}
        if current_token is not None:
            c.need(parsed.hostname == 'api.github.com', 'AUTHENTICATION_FAILED',
                   'GitHub token cannot be sent to this host')
            headers['Authorization'] = 'Bearer ' + current_token
        request = urllib.request.Request(current, headers=headers)
        try:
            return opener.open(request, timeout=60)
        except urllib.error.HTTPError as error:
            if binary and error.code in (301, 302, 303, 307, 308):
                location = error.headers.get('Location')
                error.close()
                c.need(isinstance(location, str) and location, 'RELEASE_DOWNLOAD_FAILED',
                       'GitHub asset redirect did not include a location')
                destination = urllib.parse.urljoin(current, location)
                check_url(destination, redirect=True)
                current, current_token = destination, None
                continue
            if error.code in (401, 403):
                error.close()
                raise c.GateError('AUTHENTICATION_FAILED', 'GitHub Release authentication or repository access failed') from None
            error.close()
            raise c.GateError('RELEASE_DOWNLOAD_FAILED', 'GitHub Release request failed') from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise c.GateError('RELEASE_DOWNLOAD_FAILED', 'GitHub Release request failed') from None
    raise c.GateError('RELEASE_DOWNLOAD_FAILED', 'Too many GitHub asset redirects')


def download(storage, destination, expected_sha, *, token=None):
    """Numeric immutable asset identity + externally pinned bytes, never latest."""
    import json
    destination = Path(destination)
    c.need(not destination.exists() and not destination.is_symlink(), 'INVALID_OUTPUT', 'Download destination must be new')
    base = release_locator(storage)
    private = storage['kind'] == PRIVATE_RELEASE_KIND
    if private:
        c.need(isinstance(token, str) and token and not any(ch.isspace() for ch in token),
               'AUTHENTICATION_FAILED', 'Private Release download requires workflow token')
        c.need(re.fullmatch(r'[0-9a-f]{64}', expected_sha or '') is not None,
               'INVALID_REFERENCE', 'Private Release requires an independent SHA-256 pin')
    def request(url, *, binary=False):
        if private:
            return _request(url, binary=binary, token=token)
        return _request(url, binary=binary)
    def metadata(url):
        with request(url) as stream:
            raw = stream.read(4 * 1024**2 + 1)
        c.need(len(raw) <= 4 * 1024**2, 'CORRUPT_DOWNLOAD', 'Oversized Release metadata')
        return json.loads(raw)
    if private:
        repository = metadata(base)
        c.need(type(repository.get('id')) is int and repository['id'] == storage['repository_id']
            and repository.get('full_name') == storage['repository'] and repository.get('private') is True,
            'INVALID_REFERENCE', 'Private repository identity/visibility mismatch')
    release = metadata(base + '/releases/' + str(storage['release_id']))
    c.need(type(release.get('id')) is int and release['id'] == storage['release_id']
        and release.get('immutable') is True and release.get('draft') is False
        and release.get('tag_name') == storage['tag'],
        'INVALID_REFERENCE', 'Release is not the pinned published immutable release')
    asset_url = base + '/releases/assets/' + str(storage['asset_id'])
    asset = metadata(asset_url)
    c.need(type(asset.get('id')) is int and asset['id'] == storage['asset_id']
        and asset.get('name') == storage['asset_name']
        and asset.get('state') == 'uploaded' and type(asset.get('size')) is int
        and 0 < asset['size'] <= 2 * 1024**3
        and (not private or asset['size'] == storage['asset_size'])
        and isinstance(release.get('assets'), list)
        and any(isinstance(x, dict) and type(x.get('id')) is int and x['id'] == storage['asset_id']
            and x.get('name') == storage['asset_name'] and x.get('state', 'uploaded') == 'uploaded'
            and (not private or x.get('size') == storage['asset_size']) for x in release['assets']),
        'INVALID_REFERENCE', 'Asset does not belong to pinned release/name')
    if asset.get('digest') is not None:
        c.need(asset['digest'] == 'sha256:' + expected_sha, 'CORRUPT_DOWNLOAD', 'Release digest mismatch')
    # Only a completely verified private file may become the final destination.
    # A same-filesystem exclusive link publishes it atomically without replacing
    # a file another process/operator created while the download was in flight.
    with tempfile.TemporaryDirectory(prefix='.release-download-', dir=destination.parent) as tmp:
        staged = Path(tmp) / 'payload'
        with request(asset_url, binary=True) as source, staged.open('xb') as target:
            size = 0
            while data := source.read(1024**2):
                size += len(data)
                c.need(size <= asset['size'], 'CORRUPT_DOWNLOAD', 'Oversized asset stream')
                target.write(data)
            target.flush()
            os.fsync(target.fileno())
        c.need(size == asset['size'] and file_digest(staged) == expected_sha, 'CORRUPT_DOWNLOAD', 'Asset length/checksum mismatch')
        os.link(staged, destination)
    return {'release_id': release['id'], 'asset_id': asset['id'], 'sha256': expected_sha, 'immutable': True}
