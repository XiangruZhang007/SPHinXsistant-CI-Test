"""P9.1 storage tests use only isolated files; no real corpus or Git operations."""
from concurrent.futures import ThreadPoolExecutor
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from src import versioned_corpus_storage as storage


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root):
    return {p.relative_to(root).as_posix(): (sha(p), p.stat().st_ino,
            p.stat().st_mtime_ns, p.stat().st_ctime_ns)
            for p in root.rglob('*') if p.is_file()}


class VersionedStorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'store'
        self.root.mkdir()
        self.source = self.base / 'source.jsonl'
        self.source.write_bytes(b'{"chunk_id":"fixture-one"}\n')
        self.expected = sha(self.source)

    def register(self, **kwargs):
        args = {'root': self.root, 'version': 'v1', 'source': self.source,
                'expected_sha256': self.expected}
        args.update(kwargs)
        return storage.register(**args)

    def test_successful_registration_and_inspection(self):
        before = inventory(self.base)
        result = self.register()
        self.assertEqual(result['status'], 'STORED')
        self.assertIs(result['storage_only'], True)
        self.assertEqual(result['metadata'], {'schema_version': 1, 'version': 'v1',
                         'sha256': self.expected, 'size_bytes': self.source.stat().st_size})
        self.assertEqual({p.name for p in (self.root / 'v1').iterdir()},
                         {'metadata.json', 'corpus.jsonl'})
        self.assertEqual(storage.inspect(self.root, 'v1')['metadata'], result['metadata'])
        self.assertEqual(sha(self.root / 'v1/corpus.jsonl'), self.expected)
        self.assertEqual(inventory(self.base)['source.jsonl'], before['source.jsonl'])

    def test_incorrect_expected_hash_does_not_write(self):
        with self.assertRaisesRegex(storage.StorageError, 'Source checksum differs'):
            self.register(expected_sha256='0' * 64)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_missing_and_malformed_expected_hashes(self):
        for value in (None, '', 'bad', 'a' * 63, 'g' * 64, 'A' * 64):
            with self.subTest(value=value), self.assertRaises(storage.StorageError):
                self.register(expected_sha256=value)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_duplicate_registration_does_not_modify_any_file_or_directory(self):
        first = self.register()
        before = inventory(self.base)
        directories = {p: p.stat().st_mtime_ns for p in (self.root, self.root / 'v1')}
        with patch.object(storage, '_copy', side_effect=AssertionError('Duplicate must not copy')):
            second = self.register()
        self.assertEqual(second['status'], 'ALREADY_STORED')
        self.assertEqual(second['metadata'], first['metadata'])
        self.assertEqual(inventory(self.base), before)
        self.assertEqual({p: p.stat().st_mtime_ns for p in directories}, directories)

    def test_version_conflict_preserves_existing_bytes(self):
        self.register()
        before = inventory(self.root)
        self.source.write_bytes(b'{"chunk_id":"different"}\n')
        with self.assertRaisesRegex(storage.StorageError, 'conflicts'):
            self.register(expected_sha256=sha(self.source))
        self.assertEqual(inventory(self.root), before)

    def test_corrupted_same_size_content_is_rejected_without_repair(self):
        self.register()
        corpus = self.root / 'v1/corpus.jsonl'
        corpus.write_bytes(b'x' * corpus.stat().st_size)
        before = inventory(self.root)
        for action in (lambda: storage.inspect(self.root, 'v1'), self.register):
            with self.assertRaisesRegex(storage.StorageError, 'checksum mismatch'):
                action()
        self.assertEqual(inventory(self.root), before)

    def test_corrupted_size_is_rejected(self):
        self.register()
        (self.root / 'v1/corpus.jsonl').write_bytes(b'corrupted')
        with self.assertRaisesRegex(storage.StorageError, 'size mismatch'):
            storage.inspect(self.root, 'v1')

    def test_missing_metadata_is_not_repaired(self):
        self.register()
        (self.root / 'v1/metadata.json').unlink()
        before = inventory(self.root)
        with self.assertRaisesRegex(storage.StorageError, 'Incomplete'):
            self.register()
        self.assertEqual(inventory(self.root), before)
        self.assertFalse((self.root / 'v1/metadata.json').exists())

    def test_invalid_metadata(self):
        self.register()
        path = self.root / 'v1/metadata.json'
        original = path.read_text()
        for invalid in ('{', '{"version":"v1"}', original.replace('"v1"', '"v2"'),
                        original.replace('"schema_version":1', '"schema_version":true'),
                        original[:-2] + ',"schema_version":1}\n'):
            with self.subTest(invalid=invalid):
                path.write_text(invalid)
                before = inventory(self.root)
                with self.assertRaises(ValueError):
                    self.register()
                self.assertEqual(inventory(self.root), before)

    def test_unexpected_version_members_are_rejected(self):
        self.register()
        (self.root / 'v1/extra').write_bytes(b'unknown')
        with self.assertRaisesRegex(storage.StorageError, 'unexpected'):
            storage.inspect(self.root, 'v1')

    def test_missing_version_and_root_do_not_create_directories(self):
        with self.assertRaisesRegex(storage.StorageError, 'does not exist'):
            storage.inspect(self.root, 'absent')
        missing = self.base / 'missing'
        with self.assertRaises(OSError):
            self.register(root=missing)
        self.assertFalse(missing.exists())

    def test_unsafe_version_identifiers(self):
        for value in ('', '.', '..', '../escape', '/absolute', 'a/b', 'a\\b', '-v1', 'v' * 129, 'v\n1'):
            with self.subTest(value=value), self.assertRaises(storage.StorageError):
                self.register(version=value)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_symlink_root_and_parent_component(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'store').mkdir()
        link = self.base / 'link'
        link.symlink_to(outside, target_is_directory=True)
        for root in (link, link / 'store'):
            with self.subTest(root=root), self.assertRaises(OSError):
                self.register(root=root)
        self.assertEqual(list((outside / 'store').iterdir()), [])
        self.assertEqual({p.name for p in outside.iterdir()}, {'store'})

    def test_symlink_version_cannot_escape_root(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'marker').write_bytes(b'preserve')
        (self.root / 'v1').symlink_to(outside, target_is_directory=True)
        before = inventory(outside)
        with self.assertRaises(OSError):
            self.register()
        self.assertEqual(inventory(outside), before)
        self.assertTrue((self.root / 'v1').is_symlink())

    def test_symlink_corpus_or_metadata_is_rejected(self):
        self.register()
        for member in ('corpus.jsonl', 'metadata.json'):
            path = self.root / 'v1' / member
            saved = path.read_bytes()
            outside = self.base / ('outside-' + member)
            outside.write_bytes(saved)
            path.unlink()
            path.symlink_to(outside)
            with self.subTest(member=member), self.assertRaises(OSError):
                storage.inspect(self.root, 'v1')
            self.assertEqual(outside.read_bytes(), saved)
            path.unlink()
            path.write_bytes(saved)

    def test_source_symlink_and_nonregular_source_are_rejected(self):
        link = self.base / 'source-link'
        link.symlink_to(self.source)
        with self.assertRaises(OSError):
            self.register(source=link)
        fifo = self.base / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(storage.StorageError, 'regular file'):
            self.register(source=fifo)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_failed_copy_cleans_only_own_staging_directory(self):
        self.register(version='existing')
        before = inventory(self.root)

        def fail(source, destination):
            destination.write(b'partial')
            raise OSError('Simulated interrupted copy')

        with patch.object(storage, '_copy', side_effect=fail), self.assertRaisesRegex(OSError, 'interrupted'):
            self.register()
        self.assertEqual(inventory(self.root), before)
        self.assertEqual({p.name for p in self.root.iterdir()}, {'existing'})

    def test_stored_copy_hash_is_checked_before_publication(self):
        def corrupt(source, destination):
            destination.write(b'x' * self.source.stat().st_size)

        with patch.object(storage, '_copy', side_effect=corrupt), \
                self.assertRaisesRegex(storage.StorageError, 'checksum mismatch'):
            self.register()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_failed_metadata_write_cleans_staging(self):
        with patch.object(storage, 'canonical', side_effect=OSError('Disk full')), self.assertRaises(OSError):
            self.register()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_final_directory_appears_only_after_staged_verification(self):
        publish = storage._publish

        def observe(root_fd, stage, version):
            self.assertFalse((self.root / version).exists())
            staged = self.root / stage
            self.assertEqual({p.name for p in staged.iterdir()}, {'corpus.jsonl', 'metadata.json'})
            self.assertEqual(sha(staged / 'corpus.jsonl'), self.expected)
            self.assertEqual(json.loads((staged / 'metadata.json').read_text())['sha256'], self.expected)
            publish(root_fd, stage, version)

        with patch.object(storage, '_publish', side_effect=observe):
            self.register()
        self.assertEqual({p.name for p in self.root.iterdir()}, {'v1'})

    def test_atomic_publication_never_replaces_even_an_empty_racing_directory(self):
        publish = storage._publish

        def competing_empty_directory(root_fd, stage, version):
            (self.root / version).mkdir()
            publish(root_fd, stage, version)

        with patch.object(storage, '_publish', side_effect=competing_empty_directory), \
                self.assertRaisesRegex(storage.StorageError, 'Incomplete'):
            self.register()
        self.assertEqual(list((self.root / 'v1').iterdir()), [])
        self.assertEqual({p.name for p in self.root.iterdir()}, {'v1'})

    def test_unsupported_atomic_publication_fails_closed(self):
        with patch.object(storage.ctypes, 'CDLL', return_value=object()), \
                self.assertRaisesRegex(storage.StorageError, 'unavailable'):
            self.register()
        self.assertEqual(list(self.root.iterdir()), [])
        with patch.object(storage.ctypes, 'CDLL') as libc:
            libc.return_value.renameat2.return_value = -1
            ctypes.set_errno(errno.ENOSYS)
            with self.assertRaisesRegex(storage.StorageError, 'does not support'):
                self.register()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_existing_regular_file_is_never_overwritten(self):
        (self.root / 'v1').write_bytes(b'preserve-existing-file')
        before = inventory(self.root)
        with self.assertRaises(OSError):
            self.register()
        self.assertEqual(inventory(self.root), before)

    def concurrent(self, sources):
        publish = storage._publish
        barrier = threading.Barrier(2, timeout=10)

        def together(root_fd, stage, version):
            barrier.wait()
            publish(root_fd, stage, version)

        def worker(source):
            try:
                return storage.register(self.root, 'v1', source, sha(source))
            except storage.StorageError as error:
                return error

        with patch.object(storage, '_publish', side_effect=together), ThreadPoolExecutor(max_workers=2) as pool:
            return list(pool.map(worker, sources))

    def test_identical_concurrent_registration_is_idempotent(self):
        results = self.concurrent([self.source, self.source])
        self.assertEqual({r['status'] for r in results}, {'STORED', 'ALREADY_STORED'})
        self.assertEqual({p.name for p in self.root.iterdir()}, {'v1'})
        self.assertEqual(storage.inspect(self.root, 'v1')['metadata']['sha256'], self.expected)

    def test_conflicting_concurrent_registration_has_exactly_one_winner(self):
        other = self.base / 'other.jsonl'
        other.write_bytes(b'{"chunk_id":"fixture-two"}\n')
        results = self.concurrent([self.source, other])
        winners = [r for r in results if isinstance(r, dict)]
        losers = [r for r in results if isinstance(r, storage.StorageError)]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(losers), 1)
        self.assertIn('conflicts', str(losers[0]))
        self.assertEqual(storage.inspect(self.root, 'v1')['metadata'], winners[0]['metadata'])
        self.assertEqual({p.name for p in self.root.iterdir()}, {'v1'})

    def test_cli_register_inspect_and_mandatory_expected_checksum(self):
        project = Path(__file__).resolve().parents[1]
        command = [sys.executable, '-B', '-m', 'src.versioned_corpus_storage']
        common = ['--root', str(self.root), '--version', 'cli-v1']
        env = {**os.environ, 'PYTHONPATH': str(project)}
        registration = ['register', *common, '--source', str(self.source)]
        missing = subprocess.run(command + registration, cwd=self.base, env=env, capture_output=True, text=True)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn('--expected-sha256', missing.stderr)
        self.assertEqual(list(self.root.iterdir()), [])
        registered = subprocess.run(command + registration + ['--expected-sha256', self.expected],
                                    cwd=self.base, env=env, capture_output=True, text=True)
        self.assertEqual(registered.returncode, 0, registered.stderr)
        self.assertEqual(json.loads(registered.stdout)['status'], 'STORED')
        before = inventory(self.root)
        checked = subprocess.run(command + ['inspect', *common], cwd=self.base, env=env,
                                 capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(json.loads(checked.stdout)['status'], 'VERIFIED')
        self.assertEqual(inventory(self.root), before)
        failed = subprocess.run(command + ['inspect', '--root', str(self.root), '--version', '../escape'],
                                cwd=self.base, env=env, capture_output=True, text=True)
        self.assertEqual(failed.returncode, 1)
        self.assertEqual(json.loads(failed.stdout)['status'], 'ERROR')


if __name__ == '__main__':
    unittest.main()
