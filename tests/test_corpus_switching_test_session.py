"""P9.2 tests use synthetic corpora in fresh process-owned temporary workspaces."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from src import corpus_switching_test_session as switching


def inventory(root):
    return {p.relative_to(root).as_posix(): (hashlib.sha256(p.read_bytes()).hexdigest(),
            p.stat().st_ino, p.stat().st_mtime_ns, p.stat().st_ctime_ns)
            for p in root.rglob('*') if p.is_file() and not p.is_symlink()}


class SwitchingTests(unittest.TestCase):
    def setUp(self):
        self.inputs = tempfile.TemporaryDirectory()
        self.addCleanup(self.inputs.cleanup)
        self.sources = {}
        for version in ('v1', 'v2'):
            path = Path(self.inputs.name) / (version + '.jsonl')
            path.write_bytes(json.dumps({'chunk_id': version}).encode() + b'\n')
            self.sources[version] = (path, hashlib.sha256(path.read_bytes()).hexdigest())
        self.workspace = switching.TestWorkspace()
        self.addCleanup(self.workspace.close)
        for version, (source, expected) in self.sources.items():
            self.workspace.register(version, source, expected)
        self.root = self.workspace.root

    def assert_no_temporary_links(self):
        self.assertEqual([p.name for p in self.root.iterdir() if p.name.startswith('.current-')], [])

    def test_initial_selection_and_current_inspection(self):
        self.assertEqual(self.workspace.current()['status'], 'UNSELECTED')
        result = self.workspace.switch('v1')
        self.assertEqual(result['status'], 'SWITCHED')
        self.assertIs(result['committed'], True)
        self.assertEqual(os.readlink(self.root / 'current'), 'v1/corpus.jsonl')
        self.assertEqual(self.workspace.current()['metadata']['sha256'], self.sources['v1'][1])
        self.assert_no_temporary_links()

    def test_forward_and_reverse_switches_preserve_stored_versions(self):
        before = inventory(self.root)
        sources = inventory(Path(self.inputs.name))
        environment = dict(os.environ)
        for version in ('v1', 'v2', 'v1'):
            self.assertEqual(self.workspace.switch(version)['current']['version'], version)
            self.assertEqual((self.root / 'current').read_bytes(), self.sources[version][0].read_bytes())
        self.assertEqual(inventory(self.root), before)
        self.assertEqual(inventory(Path(self.inputs.name)), sources)
        self.assertEqual(dict(os.environ), environment)

    def test_missing_target_preserves_selection(self):
        self.workspace.switch('v1')
        with self.assertRaises(ValueError):
            self.workspace.switch('missing')
        self.assertEqual(self.workspace.current()['version'], 'v1')
        self.assert_no_temporary_links()

    def test_corrupted_target_preserves_selection(self):
        self.workspace.switch('v1')
        corpus = self.root / 'v2/corpus.jsonl'
        corpus.write_bytes(b'x' * corpus.stat().st_size)
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            self.workspace.switch('v2')
        self.assertEqual(self.workspace.current()['version'], 'v1')
        self.assert_no_temporary_links()

    def test_missing_target_metadata_is_rejected(self):
        (self.root / 'v2/metadata.json').unlink()
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            self.workspace.switch('v2')
        self.assertEqual(self.workspace.current()['status'], 'UNSELECTED')

    def test_current_regular_file_and_directory_are_never_replaced(self):
        current = self.root / 'current'
        current.write_bytes(b'preserve')
        with self.assertRaisesRegex(ValueError, 'symbolic link'):
            self.workspace.switch('v1')
        self.assertEqual(current.read_bytes(), b'preserve')
        current.unlink()
        current.mkdir()
        with self.assertRaisesRegex(ValueError, 'symbolic link'):
            self.workspace.switch('v1')
        self.assertTrue(current.is_dir())

    def test_unsafe_broken_and_escaping_current_links(self):
        current = self.root / 'current'
        for target in ('/tmp/outside/corpus.jsonl', '../corpus.jsonl', '../v1/corpus.jsonl',
                       'v1/../corpus.jsonl', './v1/corpus.jsonl', 'v1//corpus.jsonl',
                       'v1/metadata.json', 'missing/corpus.jsonl', 'v1\\corpus.jsonl'):
            with self.subTest(target=target):
                current.symlink_to(target)
                for action in (self.workspace.current, lambda: self.workspace.switch('v2')):
                    with self.assertRaises((ValueError, OSError)):
                        action()
                self.assertEqual(os.readlink(current), target)
                current.unlink()
        self.assert_no_temporary_links()

    def test_version_directory_symlink_is_rejected(self):
        external = Path(self.inputs.name) / 'external'
        external.mkdir()
        (external / 'marker').write_bytes(b'preserve')
        (self.root / 'external-version').symlink_to(external, target_is_directory=True)
        before = inventory(external)
        with self.assertRaises(OSError):
            self.workspace.switch('external-version')
        self.assertEqual(inventory(external), before)

    def test_corrupted_existing_selection_is_not_silently_repaired(self):
        self.workspace.switch('v1')
        (self.root / 'v1/corpus.jsonl').write_bytes(b'corrupted')
        with self.assertRaises(ValueError):
            self.workspace.switch('v2')
        self.assertEqual(os.readlink(self.root / 'current'), 'v1/corpus.jsonl')

    def test_nonisolated_roots_cannot_be_attached(self):
        external = Path(self.inputs.name)
        before = inventory(external)
        with self.assertRaises(TypeError):
            switching.TestWorkspace(root=external)
        with self.assertRaises(TypeError):
            self.workspace.switch('v1', root=external)
        with self.assertRaises(AttributeError):
            self.workspace.root = external
        with self.assertRaisesRegex(ValueError, 'external storage roots'):
            switching._command(self.workspace, {'command': 'switch', 'version': 'v1', 'root': str(external)})
        self.assertEqual(inventory(external), before)

    def test_workspace_identity_change_is_rejected(self):
        original = self.workspace._root
        try:
            self.workspace._root = Path(self.inputs.name)
            with self.assertRaisesRegex(ValueError, 'identity changed'):
                self.workspace.switch('v1')
        finally:
            self.workspace._root = original

    def test_other_process_is_rejected(self):
        pid = os.getpid()
        with patch.object(switching.os, 'getpid', return_value=pid + 1), \
                self.assertRaisesRegex(ValueError, 'different process'):
            self.workspace.switch('v1')

    def test_failure_before_commit_preserves_current_and_cleans_temporary_link(self):
        self.workspace.switch('v1')
        before = inventory(self.root)
        with patch.object(switching.os, 'replace', side_effect=OSError('Before commit')), \
                self.assertRaisesRegex(OSError, 'Before commit'):
            self.workspace.switch('v2')
        self.assertEqual(self.workspace.current()['version'], 'v1')
        self.assertEqual(inventory(self.root), before)
        self.assert_no_temporary_links()

    def test_symlink_creation_failure_leaves_previous_selection(self):
        self.workspace.switch('v1')
        with patch.object(switching.os, 'symlink', side_effect=OSError('Cannot create link')), \
                self.assertRaises(OSError):
            self.workspace.switch('v2')
        self.assertEqual(self.workspace.current()['version'], 'v1')
        self.assert_no_temporary_links()

    def test_atomic_replace_uses_relative_link_and_directory_descriptors(self):
        self.workspace.switch('v1')
        replace = os.replace

        def observed(source, destination, *, src_dir_fd, dst_dir_fd):
            self.assertEqual(src_dir_fd, dst_dir_fd)
            self.assertEqual(destination, 'current')
            self.assertEqual(os.readlink(source, dir_fd=src_dir_fd), 'v2/corpus.jsonl')
            self.assertEqual(os.readlink('current', dir_fd=src_dir_fd), 'v1/corpus.jsonl')
            replace(source, destination, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)
            self.assertEqual(os.readlink('current', dir_fd=src_dir_fd), 'v2/corpus.jsonl')

        with patch.object(switching.os, 'replace', side_effect=observed):
            self.workspace.switch('v2')
        self.assert_no_temporary_links()

    def test_readers_observe_only_complete_versions(self):
        self.workspace.switch('v1')
        stop = threading.Event()
        ready = threading.Event()
        observed = []
        errors = []

        def reader():
            try:
                while not stop.is_set():
                    observed.append((self.root / 'current').read_bytes())
                    ready.set()
            except OSError as error:
                errors.append(error)
                ready.set()

        thread = threading.Thread(target=reader)
        thread.start()
        try:
            self.assertTrue(ready.wait(timeout=5))
            for version in ['v2', 'v1'] * 10:
                self.workspace.switch(version)
        finally:
            stop.set()
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(observed)
        self.assertLessEqual(set(observed), {p.read_bytes() for p, _ in self.sources.values()})

    def test_concurrent_switching_is_serialized(self):
        self.workspace.switch('v1')
        replace = os.replace
        entered = threading.Event()
        second_started = threading.Event()
        release = threading.Event()
        counter_lock = threading.Lock()
        active = 0
        maximum = 0

        def held(*args, **kwargs):
            nonlocal active, maximum
            with counter_lock:
                active += 1
                maximum = max(maximum, active)
            entered.set()
            try:
                if not release.wait(timeout=5):
                    raise OSError('Concurrent test timed out')
                return replace(*args, **kwargs)
            finally:
                with counter_lock:
                    active -= 1

        def second():
            second_started.set()
            return self.workspace.switch('v1')

        with patch.object(switching.os, 'replace', side_effect=held), ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.workspace.switch, 'v2')
            try:
                self.assertTrue(entered.wait(timeout=5))
                later = pool.submit(second)
                self.assertTrue(second_started.wait(timeout=5))
            finally:
                release.set()
            self.assertEqual(first.result(timeout=5)['status'], 'SWITCHED')
            self.assertEqual(later.result(timeout=5)['status'], 'SWITCHED')
        self.assertEqual(maximum, 1)
        self.assertEqual(self.workspace.current()['version'], 'v1')

    def test_postcommit_fsync_error_reports_actual_new_selection(self):
        self.workspace.switch('v1')
        before = inventory(self.root)
        with patch.object(switching.os, 'fsync', side_effect=OSError('Directory sync failed')):
            result = self.workspace.switch('v2')
        self.assertEqual(result['status'], 'COMMITTED_WITH_ERROR')
        self.assertIs(result['committed'], True)
        self.assertEqual(result['current']['version'], 'v2')
        self.assertEqual(result['durability'], 'NOT_CONFIRMED')
        self.assertEqual(inventory(self.root), before)
        self.assert_no_temporary_links()

    def test_postcommit_read_error_is_not_reported_as_uncommitted(self):
        self.workspace.switch('v1')
        read_current = self.workspace._current
        calls = 0

        def interrupted_read():
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('Post-commit read interrupted')
            return read_current()

        with patch.object(self.workspace, '_current', side_effect=interrupted_read):
            result = self.workspace.switch('v2')
        self.assertEqual(result['status'], 'COMMITTED_WITH_ERROR')
        self.assertIs(result['committed'], True)
        self.assertEqual(result['current']['version'], 'v2')
        self.assertEqual(result['durability'], 'DIRECTORY_FSYNC_COMPLETED')

    def test_postcommit_corruption_reports_actual_link_as_unverified(self):
        self.workspace.switch('v1')
        fsync = os.fsync

        def external_corruption(fd):
            fsync(fd)
            (self.root / 'v2/corpus.jsonl').write_bytes(b'externally-corrupted')

        with patch.object(switching.os, 'fsync', side_effect=external_corruption):
            result = self.workspace.switch('v2')
        self.assertEqual(result['status'], 'COMMITTED_WITH_ERROR')
        self.assertIs(result['committed'], True)
        self.assertEqual(result['current']['status'], 'UNVERIFIED')
        self.assertEqual(result['current']['target'], 'v2/corpus.jsonl')
        self.assertEqual(os.readlink(self.root / 'current'), 'v2/corpus.jsonl')

    def test_cli_postcommit_error_has_nonzero_exit_and_actual_state(self):
        source, expected = self.sources['v1']
        requests = [{'command': 'register', 'version': 'v1', 'source': str(source),
                     'expected_sha256': expected}, {'command': 'switch', 'version': 'v1'},
                    {'command': 'current'}]
        stdin = io.StringIO(''.join(json.dumps(r) + '\n' for r in requests))
        stdout = io.StringIO()
        original = switching.TestWorkspace.switch

        def fail_after_commit(workspace, version):
            with patch.object(switching.os, 'fsync', side_effect=OSError('Sync failed')):
                return original(workspace, version)

        with patch.object(switching.TestWorkspace, 'switch', new=fail_after_commit), \
                patch.object(switching.sys, 'stdin', stdin), redirect_stdout(stdout):
            code = switching.main([])
        rows = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(code, 1)
        self.assertEqual(rows[2]['status'], 'COMMITTED_WITH_ERROR')
        self.assertIs(rows[2]['committed'], True)
        self.assertEqual(rows[3]['version'], 'v1')
        self.assertEqual(rows[-1]['status'], 'TEST_WORKSPACE_CLOSED')
        self.assertFalse(Path(rows[0]['root']).exists())

    def test_open_file_handle_keeps_previous_bytes_after_switch(self):
        self.workspace.switch('v1')
        with (self.root / 'current').open('rb') as previous:
            self.workspace.switch('v2')
            self.assertEqual(previous.read(), self.sources['v1'][0].read_bytes())
        self.assertEqual((self.root / 'current').read_bytes(), self.sources['v2'][0].read_bytes())

    def test_workspace_cleanup_and_closed_session(self):
        self.workspace.switch('v1')
        self.workspace.close()
        self.assertFalse(self.root.exists())
        with self.assertRaisesRegex(ValueError, 'closed'):
            self.workspace.current()

    def cli(self, requests, *args):
        project = Path(__file__).resolve().parents[1]
        return subprocess.run([sys.executable, '-B', '-m', 'src.corpus_switching_test_session', *args],
            input=''.join(json.dumps(r) + '\n' for r in requests),
            cwd=self.inputs.name, env={**os.environ, 'PYTHONPATH': str(project)},
            capture_output=True, text=True, timeout=10)

    def test_cli_session_and_automatic_cleanup(self):
        requests = [{'command': 'register', 'version': v, 'source': str(p), 'expected_sha256': h}
                    for v, (p, h) in self.sources.items()]
        requests += [{'command': 'switch', 'version': 'v1'}, {'command': 'current'},
                     {'command': 'switch', 'version': 'v2'}, {'command': 'switch', 'version': 'v1'},
                     {'command': 'quit'}]
        result = self.cli(requests)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(rows[0]['status'], 'TEST_WORKSPACE_CREATED')
        self.assertFalse(Path(rows[0]['root']).exists())
        self.assertEqual(rows[-1]['status'], 'TEST_WORKSPACE_CLOSED')
        self.assertTrue(all(r['test_only'] for r in rows))
        self.assertEqual([r['current']['version'] for r in rows if r['status'] == 'SWITCHED'],
                         ['v1', 'v2', 'v1'])

    def test_cli_rejects_external_roots_and_returns_failure(self):
        before = inventory(Path(self.inputs.name))
        result = self.cli([], '--root', self.inputs.name)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)['status'], 'ERROR')
        result = self.cli([{'command': 'switch', 'version': 'v1', 'root': self.inputs.name},
                           {'command': 'current'}])
        self.assertEqual(result.returncode, 1)
        rows = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(rows[1]['status'], 'ERROR')
        self.assertEqual(rows[2]['status'], 'UNSELECTED')
        self.assertFalse(Path(rows[0]['root']).exists())
        self.assertEqual(inventory(Path(self.inputs.name)), before)


if __name__ == '__main__':
    unittest.main()
