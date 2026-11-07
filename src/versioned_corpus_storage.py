"""P9.1 local byte storage only: no activation, release approval or P8 bypass.

Use an existing, explicitly supplied storage root. Each version contains only
corpus.jsonl and metadata.json. Linux renameat2(RENAME_NOREPLACE) is required;
unsupported systems/filesystems fail closed without a rename fallback. Directory
descriptors and O_NOFOLLOW prevent symlink traversal. Immutability is enforced by
this API, not by an operating-system access-control scheme. Inspection verifies
internal consistency, not authenticity against coordinated metadata tampering.
Corpus bytes are not semantically evaluated. Abrupt process/OS termination may
leave hidden staging directories; inspection never treats them as versions.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import sys

from .corpus_snapshot import _unique, canonical

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
MEMBERS = {'corpus.jsonl', 'metadata.json'}


class StorageError(ValueError):
    """Invalid storage inputs, corruption, conflicts or unsupported publication."""


def _need(condition, message):
    if not condition:
        raise StorageError(message)


def _version(value):
    _need(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', value),
          'Version must be a safe single-component name of at most 128 characters')


def _checksum(value):
    _need(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value),
          'Expected SHA-256 must be 64 lowercase hexadecimal characters')


@contextmanager
def _directory(path):
    """Open each existing component without following symlinks; never mkdir parents."""
    path = Path(path).expanduser()
    _need('..' not in path.parts, 'Parent traversal is forbidden')
    if not path.is_absolute():
        path = Path.cwd() / path
    fd = os.open(path.anchor, DIR_FLAGS)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        yield fd
    finally:
        os.close(fd)


@contextmanager
def _regular(directory_fd, name):
    fd = os.open(name, READ_FLAGS, dir_fd=directory_fd)
    try:
        _need(stat.S_ISREG(os.fstat(fd).st_mode), 'Expected a regular file: ' + name)
        stream = os.fdopen(fd, 'rb', closefd=False)
        try:
            yield stream
        finally:
            stream.close()
    finally:
        os.close(fd)


def _inspect_directory(fd, version):
    _need(set(os.listdir(fd)) == MEMBERS, 'Incomplete or unexpected version contents')
    with _regular(fd, 'metadata.json') as stream:
        _need(os.fstat(stream.fileno()).st_size <= 4096, 'Oversized metadata')
        metadata = json.loads(stream.read().decode('utf-8'), object_pairs_hook=_unique)
    _need(isinstance(metadata, dict) and set(metadata) == {'schema_version', 'version', 'sha256', 'size_bytes'},
          'Incomplete or unsupported metadata')
    _need(type(metadata['schema_version']) is int and metadata['schema_version'] == 1,
          'Unsupported metadata schema')
    _need(metadata['version'] == version, 'Metadata version mismatch')
    _checksum(metadata['sha256'])
    _need(type(metadata['size_bytes']) is int and metadata['size_bytes'] >= 0, 'Invalid stored size')
    with _regular(fd, 'corpus.jsonl') as stream:
        _need(os.fstat(stream.fileno()).st_size == metadata['size_bytes'], 'Stored size mismatch')
        _need(hashlib.file_digest(stream, 'sha256').hexdigest() == metadata['sha256'],
              'Stored checksum mismatch')
    return metadata


def _existing(root_fd, version):
    try:
        fd = os.open(version, DIR_FLAGS, dir_fd=root_fd)
    except FileNotFoundError:
        return None
    try:
        return _inspect_directory(fd, version)
    finally:
        os.close(fd)


def _publish(root_fd, stage, version):
    """One kernel operation; never emulate no-overwrite with exists()+rename()."""
    _need(sys.platform == 'linux', 'Atomic no-overwrite publication requires Linux renameat2')
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    _need(rename is not None, 'Atomic no-overwrite renameat2 is unavailable')
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(root_fd, os.fsencode(stage), root_fd, os.fsencode(version), 1) != 0:
        number = ctypes.get_errno()
        if number == errno.EEXIST:
            raise FileExistsError(number, 'Version already exists', version)
        if number in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
            raise StorageError('Filesystem does not support atomic no-overwrite publication')
        raise OSError(number, os.strerror(number), version)


def _copy(source, destination):
    shutil.copyfileobj(source, destination, length=1024 * 1024)


def _register(root_fd, version, source, metadata):
    existing = _existing(root_fd, version)
    if existing is not None:
        _need(existing == metadata, 'Version conflicts with requested content')
        return 'ALREADY_STORED', existing
    stage = '.staging-' + secrets.token_hex(16)
    os.mkdir(stage, mode=0o700, dir_fd=root_fd)
    fd = None
    published = False
    try:
        fd = os.open(stage, DIR_FLAGS, dir_fd=root_fd)
        for name in ('corpus.jsonl', 'metadata.json'):
            output_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                mode=0o600, dir_fd=fd)
            with os.fdopen(output_fd, 'wb') as destination:
                if name == 'corpus.jsonl':
                    _copy(source, destination)
                else:
                    destination.write(canonical(metadata) + b'\n')
                destination.flush()
                os.fsync(destination.fileno())
        _need(_inspect_directory(fd, version) == metadata, 'Staged version verification failed')
        os.fsync(fd)
        try:
            _publish(root_fd, stage, version)
        except FileExistsError:
            winner = _existing(root_fd, version)
            _need(winner == metadata, 'Concurrent version conflicts with requested content')
            return 'ALREADY_STORED', winner
        published = True
        os.fsync(root_fd)
        return 'STORED', metadata
    finally:
        if fd is not None:
            try:
                if not published:
                    for name in MEMBERS:
                        try:
                            os.unlink(name, dir_fd=fd)
                        except FileNotFoundError:
                            pass
            finally:
                os.close(fd)
        if not published:
            os.rmdir(stage, dir_fd=root_fd)


def register(root, version, source, expected_sha256):
    """Read an external source; write only inside an existing explicit root."""
    _version(version)
    _checksum(expected_sha256)
    source = Path(source).expanduser()
    _need('..' not in source.parts, 'Parent traversal is forbidden')
    with _directory(source.parent) as parent_fd, _regular(parent_fd, source.name) as stream:
        _need(hashlib.file_digest(stream, 'sha256').hexdigest() == expected_sha256,
              'Source checksum differs from independently supplied expected SHA-256')
        metadata = {'schema_version': 1, 'version': version, 'sha256': expected_sha256,
                    'size_bytes': os.fstat(stream.fileno()).st_size}
        stream.seek(0)
        with _directory(root) as root_fd:
            status, stored = _register(root_fd, version, stream, metadata)
    return {'status': status, 'metadata': stored, 'storage_only': True}


def inspect(root, version):
    """Check an existing version without repairing or changing anything."""
    _version(version)
    with _directory(root) as root_fd:
        metadata = _existing(root_fd, version)
        _need(metadata is not None, 'Version does not exist')
    return {'status': 'VERIFIED', 'metadata': metadata, 'storage_only': True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    for name in ('register', 'inspect'):
        command = sub.add_parser(name)
        command.add_argument('--root', type=Path, required=True, help='Existing storage root')
        command.add_argument('--version', required=True)
        if name == 'register':
            command.add_argument('--source', type=Path, required=True)
            command.add_argument('--expected-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == 'register':
            result = register(args.root, args.version, args.source, args.expected_sha256)
        else:
            result = inspect(args.root, args.version)
        code = 0
    except (OSError, ValueError, TypeError) as error:
        result = {'status': 'ERROR', 'error': str(error), 'storage_only': True}
        code = 1
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
