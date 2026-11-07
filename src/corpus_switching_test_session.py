"""P9.2 process-owned temporary testing only; no production or Gradio activation.

Run python3 -B -m src.corpus_switching_test_session and send JSON lines on stdin:
register (version, source, expected_sha256), switch (version), current, or quit.
There is no external-root, attach or authorization option. Normal exit cleans the
workspace; abrupt termination can leave temporary files. Changing current affects
future filesystem opens, not an initialized assistant or in-memory Retriever.
This API is not an OS sandbox: an operator can manually configure another program
to read the temporary files. Directory fsync does not promise power-loss safety.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import tempfile
import threading

from .corpus_snapshot import _unique
from . import versioned_corpus_storage as storage


class TestWorkspace:
    """Own one fresh temporary store and serialize all access in its creator PID."""

    def __init__(self):
        self._temporary = tempfile.TemporaryDirectory(prefix='sphinx-p92-', dir='/tmp')
        self._root = Path(self._temporary.name)
        try:
            self._fd = os.open(self._root, storage.DIR_FLAGS)
        except OSError:
            self._temporary.cleanup()
            raise
        self._pid = os.getpid()
        self._lock = threading.RLock()
        self._closed = False

    @property
    def root(self):
        return self._root

    @contextmanager
    def _guard(self):
        storage._need(os.getpid() == self._pid, 'Workspace belongs to a different process')
        with self._lock:
            storage._need(not self._closed, 'Test workspace is closed')
            actual = self._root.lstat()
            opened = os.fstat(self._fd)
            storage._need(self._root == Path(self._temporary.name) and stat.S_ISDIR(actual.st_mode)
                          and (actual.st_dev, actual.st_ino) == (opened.st_dev, opened.st_ino),
                          'Test workspace identity changed')
            yield

    def register(self, version, source, expected_sha256):
        with self._guard():
            return {**storage.register(self._root, version, source, expected_sha256), 'test_only': True}

    def _current(self):
        try:
            info = os.stat('current', dir_fd=self._fd, follow_symlinks=False)
        except FileNotFoundError:
            return {'status': 'UNSELECTED', 'version': None, 'test_only': True}
        storage._need(stat.S_ISLNK(info.st_mode), 'Existing current must be a relative symbolic link')
        target = os.readlink('current', dir_fd=self._fd)
        parts = target.split('/')
        storage._need(len(parts) == 2 and parts[1] == 'corpus.jsonl', 'Unsafe current target')
        storage._version(parts[0])
        verified = storage.inspect(self._root, parts[0])
        return {'status': 'CURRENT', 'version': parts[0], 'target': target,
                'metadata': verified['metadata'], 'test_only': True}

    def current(self):
        with self._guard():
            return self._current()

    def _actual_after_error(self):
        try:
            return self._current()
        except (OSError, ValueError) as error:
            try:
                target = os.readlink('current', dir_fd=self._fd)
            except OSError:
                target = None
            return {'status': 'UNVERIFIED', 'target': target, 'error': str(error), 'test_only': True}

    def switch(self, version):
        with self._guard():
            self._current()  # Reject unsafe existing selections; never silently repair.
            storage.inspect(self._root, version)
            temporary = '.current-' + secrets.token_hex(16)
            created = False
            committed = False
            durability = 'NOT_CONFIRMED'
            try:
                os.symlink(version + '/corpus.jsonl', temporary, dir_fd=self._fd)
                created = True
                os.replace(temporary, 'current', src_dir_fd=self._fd, dst_dir_fd=self._fd)
                committed = True
                created = False
                os.fsync(self._fd)
                durability = 'DIRECTORY_FSYNC_COMPLETED'
                selected = self._current()
                return {'status': 'SWITCHED', 'committed': True, 'current': selected,
                        'durability': durability, 'test_only': True}
            except (OSError, ValueError) as error:
                if not committed:
                    raise
                return {'status': 'COMMITTED_WITH_ERROR', 'committed': True,
                        'current': self._actual_after_error(), 'error': str(error),
                        'durability': durability, 'test_only': True}
            finally:
                if created:
                    os.unlink(temporary, dir_fd=self._fd)

    def close(self):
        storage._need(os.getpid() == self._pid, 'Workspace belongs to a different process')
        with self._lock:
            if not self._closed:
                self._closed = True
                os.close(self._fd)
                self._temporary.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *error):
        self.close()


def _command(workspace, request):
    fields = {'register': {'command', 'version', 'source', 'expected_sha256'},
              'switch': {'command', 'version'}, 'current': {'command'}, 'quit': {'command'}}
    storage._need(isinstance(request, dict) and isinstance(request.get('command'), str),
                  'Expected a JSON command object')
    command = request['command']
    storage._need(command in fields and set(request) == fields[command],
                  'Unsupported command or fields; external storage roots are not accepted')
    if command == 'register':
        return workspace.register(request['version'], request['source'], request['expected_sha256'])
    if command == 'switch':
        return workspace.switch(request['version'])
    if command == 'current':
        return workspace.current()
    return {'status': 'QUIT', 'test_only': True}


def _print(value):
    print(json.dumps(value, sort_keys=True, allow_nan=False), flush=True)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ['--help']:
        _print({'usage': 'python3 -B -m src.corpus_switching_test_session',
                'commands': ['register', 'switch', 'current', 'quit'],
                'input': 'JSON lines on stdin; one temporary store per process', 'test_only': True})
        return 0
    if argv:
        _print({'status': 'ERROR', 'error': 'No external root or workspace arguments are accepted', 'test_only': True})
        return 2
    code = 0
    try:
        with TestWorkspace() as workspace:
            _print({'status': 'TEST_WORKSPACE_CREATED', 'root': str(workspace.root), 'test_only': True})
            for line in sys.stdin:
                try:
                    request = json.loads(line, object_pairs_hook=_unique)
                    result = _command(workspace, request)
                    if result['status'] == 'COMMITTED_WITH_ERROR':
                        code = 1
                except (OSError, ValueError, TypeError) as error:
                    result = {'status': 'ERROR', 'committed': False, 'error': str(error), 'test_only': True}
                    code = 1
                _print(result)
                if result['status'] == 'QUIT':
                    break
        _print({'status': 'TEST_WORKSPACE_CLOSED', 'test_only': True})
    except KeyboardInterrupt:
        _print({'status': 'INTERRUPTED', 'test_only': True})
        return 130
    except (OSError, ValueError) as error:
        _print({'status': 'ERROR', 'error': str(error), 'test_only': True})
        return 1
    return code


if __name__ == '__main__':
    raise SystemExit(main())
