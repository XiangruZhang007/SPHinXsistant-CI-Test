"""Synthetic destructive transport tests; no scientific construction or replay."""
from copy import deepcopy
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

import test_local_candidate_evidence as fixture
from src import local_candidate_transport as t
from src.corpus_snapshot import canonical, file_digest


def gz(raw):
    stream = io.BytesIO()
    with gzip.GzipFile(fileobj=stream, mode='wb', filename='', mtime=0, compresslevel=9) as out:
        out.write(raw)
    return stream.getvalue()


class LocalTransportTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.LocalEvidenceTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.root = self.f.root
        self.licenses = self.root / 'licenses'
        self.licenses.mkdir()
        pins = {}
        for name in t.LICENSES:
            raw = ('Synthetic license fixture: ' + name).encode()
            (self.licenses / name).write_bytes(raw)
            pins[name] = hashlib.sha256(raw).hexdigest()
        p = patch.object(t, 'LICENSES', pins)
        p.start(); self.addCleanup(p.stop)
        identity = self.f.identity
        identity['base_upstreams'] = {k: 'c' * 40 for k in self.f.d['upstreams']}
        identity['upstreams'] = self.f.d['upstreams']
        self.f.write(self.f.run, 'candidate/upstream-candidate.json', {'identity': identity})
        self.f.write(self.f.baseline, 'upstream-candidate.json', {'identity': identity})
        bindings = []
        for phase in ('base', 'target'):
            for repo, paths in [('SPHinXsys', ['LICENSE']),
                                ('SPHinXsim', ['LICENSE', 'sphinxsim/sphinxsys/LICENSE'])]:
                for path in paths:
                    name = 'MIT-SPHinXsim.txt' if repo == 'SPHinXsim' and path == 'LICENSE' else 'Apache-2.0-SPHinXsys.txt'
                    raw = (self.licenses / name).read_bytes()
                    bindings.append(dict(phase=phase, repository=repo,
                        revision=identity['base_upstreams' if phase == 'base' else 'upstreams'][repo],
                        path=path, git_blob_sha=hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
                        retained_text_sha256=pins[name]))
        vendors = {}
        for i in range(8):
            path = 'repos/SPHinXsys/vendor' + str(i) + '.h'
            member = 'candidate/input/' + path
            self.f.write(self.f.run, member, {'synthetic source': i})
            vendors[path] = {'sha256': file_digest(self.f.run / member),
                            'notice': 'licenses/' + sorted(pins)[i % 7]}
        self.f.reseal()
        self.f.path.write_bytes(canonical(self.f.d))
        self.descriptor_pin = file_digest(self.f.path)
        self.review = self.root / 'review.json'
        self.review.write_bytes(canonical(dict(base_target_license_git_tree_bindings=bindings, vendor_matches=vendors)))
        self.kwargs = dict(expected_descriptor_sha256=self.descriptor_pin,
                           expected_notices_review_sha256=file_digest(self.review))
        self.out = self.root / 'prepared'
        self.receipt = self.prepare(self.out)
        self.archive = Path(self.receipt['archive'])
        self.pins = {k: v for k, v in self.receipt.items() if k.startswith('expected_')}
        self.bad = self.root / 'bad.tar.gz'

    def prepare(self, out):
        return t.prepare(self.root, self.f.run, self.f.records, self.f.baseline,
            self.f.path, self.f.refpath, self.licenses, self.review, out, **self.kwargs)

    def entries(self):
        with tarfile.open(self.archive, 'r:gz') as tar:
            return [(x, tar.extractfile(x).read()) for x in tar]

    def repack(self, entries, repin_manifest=False, **kwargs):
        if repin_manifest:
            files = {x.name: {'size_bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                             'executable': x.mode == 0o755} for x, raw in entries if x.name != t.MANIFEST}
            entries = [(x, canonical(dict(json.loads(raw), files=files)) if x.name == t.MANIFEST else raw)
                       for x, raw in entries]
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w', format=tarfile.USTAR_FORMAT) as tar:
            for x, raw in entries:
                x = deepcopy(x)
                x.size = len(raw)
                tar.addfile(x, io.BytesIO(raw))
        return self.raw_bad(gz(data.getvalue()), entries if repin_manifest else None, **kwargs)

    def raw_bad(self, raw, entries=None, **changes):
        self.bad.write_bytes(raw)
        pins = dict(self.pins, expected_archive_sha256=file_digest(self.bad), expected_archive_size=len(raw))
        if entries:
            manifest = next(raw for x, raw in entries if x.name == t.MANIFEST)
            pins['expected_manifest_sha256'] = hashlib.sha256(manifest).hexdigest()
        pins.update(changes)
        return pins

    def rejects(self, pins, path=None):
        dest = self.root / 'rejected-destination'
        with patch.object(t.l1, 'verify') as l1, self.assertRaises(t.TransportError):
            t.verify_archive(self.root, path or self.bad, dest, self.f.baseline, self.f.refpath, **pins)
        l1.assert_not_called()
        self.assertFalse(dest.exists())

    def test_deterministic_archive_and_unmodified_original_files(self):
        snapshot = {p: file_digest(p) for root in (self.f.run, self.f.records, self.f.baseline)
                    for p in root.rglob('*') if p.is_file()}
        two = self.prepare(self.root / 'prepared-again')
        self.assertEqual(self.archive.read_bytes(), Path(two['archive']).read_bytes())
        self.assertEqual(self.receipt['status'], 'LOCAL_PREPUBLICATION_TEST_ARTIFACT')
        self.assertEqual(self.receipt['publication_authorization'], 'NOT_GRANTED')
        self.assertTrue(all(file_digest(p) == pin for p, pin in snapshot.items()))
        entries = self.entries()
        names = [x.name for x, raw in entries]
        self.assertEqual(names, sorted(names))
        self.assertEqual({n[4:] for n in names if n.startswith('run/')},
                         {p.relative_to(self.f.run).as_posix() for p in self.f.run.rglob('*') if p.is_file()})
        self.assertEqual({n for n in names if n.startswith('execution-record/')},
                         {'execution-record/' + n for n in t.l1.RECORD_FILES})

    def test_valid_inspection_extraction_and_read_only_l1(self):
        self.assertEqual(t.inspect_archive(self.archive, **self.pins)['status'], 'LOCAL_TRANSPORT_VERIFIED')
        dest = self.root / 'verified'
        result = t.verify_archive(self.root, self.archive, dest, self.f.baseline, self.f.refpath, **self.pins)
        self.assertEqual(result['status'], 'LOCAL_EVIDENCE_VERIFIED')
        self.assertEqual(result['hosted_validation'], 'HOSTED_NOT_RUN')
        self.assertEqual(result['replay'], 'NO_FRESH_REPLAY')
        self.assertEqual(result['production_promotion'], 'NOT_AUTHORIZED')
        self.assertEqual(result['registration_authorization'], 'NOT_GRANTED')
        self.assertEqual(t.verify_extracted(self.root, dest, self.f.baseline, self.f.refpath,
            expected_manifest_sha256=self.pins['expected_manifest_sha256'],
            expected_descriptor_sha256=self.descriptor_pin), result)

    def test_each_independent_pin_and_size(self):
        for key in self.pins:
            pins = dict(self.pins, **{key: 1 if key == 'expected_archive_size' else '0' * 64})
            with self.subTest(key=key):
                self.rejects(pins, self.archive)

    def test_corrupt_missing_extra_and_changed_records(self):
        for name in ('run/full/manifest.json', 'execution-record/report.md', 'descriptor.json',
                     'notices/README.md', 'notices/licenses/TinyXML-2-source-notice.txt'):
            entries = self.entries()
            for missing in (True, False):
                changed = [(x, raw if x.name != name else b'changed')
                           for x, raw in entries if not (missing and x.name == name)]
                with self.subTest(name=name, missing=missing):
                    self.rejects(self.repack(changed))
        entries = self.entries() + [(t._header('unexpected.txt', 0, 0o644), b'')]
        self.rejects(self.repack(sorted(entries, key=lambda x: x[0].name)))

    def test_resealed_transport_cannot_change_original_run_or_records(self):
        for name in ('run/full/manifest.json', 'execution-record/report.md'):
            entries = [(x, b'changed' if x.name == name else raw) for x, raw in self.entries()]
            with self.subTest(name=name):
                self.rejects(self.repack(entries, repin_manifest=True))

    def test_self_consistent_failed_identity_or_manifest_version(self):
        for key, value in [('candidate_id', 'sha256-' + '0' * 64), ('schema_version', True), ('approved', True)]:
            changed = []
            for x, raw in self.entries():
                if x.name == t.MANIFEST:
                    raw = canonical(dict(json.loads(raw), **{key: value}))
                changed.append((x, raw))
            pins = self.repack(changed)
            pins['expected_manifest_sha256'] = hashlib.sha256(next(raw for x, raw in changed if x.name == t.MANIFEST)).hexdigest()
            with self.subTest(key=key):
                self.rejects(pins)

    def test_duplicate_casefold_and_prefix_collision(self):
        entries = self.entries()
        for extra in [(deepcopy(entries[0][0]), entries[0][1]),
                      (t._header('Descriptor.json', 0, 0o644), b''),
                      (t._header('run', 0, 0o644), b'')]:
            self.rejects(self.repack(sorted(entries + [extra], key=lambda x: x[0].name)))

    def test_unsafe_names_and_archive_types(self):
        for name in ('../escape', '/escape', 'run/../escape', 'run\\escape', 'C:/escape', 'run/./escape'):
            entries = self.entries() + [(t._header(name, 0, 0o644), b'')]
            with self.subTest(name=name):
                self.rejects(self.repack(sorted(entries, key=lambda x: x[0].name)))
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE,
                     tarfile.CHRTYPE, tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME):
            entries = self.entries()
            item = t._header('aaa-unsafe', 0, 0o644)
            item.type = kind
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                item.linkname = 'descriptor.json'
            with self.subTest(kind=kind):
                self.rejects(self.repack([(item, b'')] + entries))

    def test_unsupported_metadata_permissions_and_padding(self):
        for key, value in [('uid', 1), ('mtime', 1), ('uname', 'user'), ('mode', 0o600), ('mode', 0o777)]:
            entries = self.entries()
            setattr(entries[0][0], key, value)
            with self.subTest(key=key, value=value):
                self.rejects(self.repack(entries))
        entries = self.entries()
        entries[0][0].mode = 0o755  # Permitted tar mode, forbidden descriptor mode.
        self.rejects(self.repack(entries, repin_manifest=True))
        raw = bytearray(gzip.decompress(self.archive.read_bytes()))
        raw[-1] = 1
        self.rejects(self.raw_bad(gz(raw)))

    def test_invalid_gzip_ustar_crc_truncation_and_hidden_payload(self):
        raw = self.archive.read_bytes()
        bad_crc = raw[:-1] + bytes([raw[-1] ^ 1])
        bad_header = raw[:9] + b'\x03' + raw[10:]
        for bad in (raw + raw, raw + b'trailing', raw[:-12], bad_crc, bad_header, b'notgzip'):
            with self.subTest(length=len(bad)):
                self.rejects(self.raw_bad(bad))
        tar = bytearray(gzip.decompress(raw))
        tar[257] = ord('X')
        self.rejects(self.raw_bad(gz(tar)))
        tar = bytearray(gzip.decompress(raw))
        tar[0] ^= 1  # header checksum mismatch
        self.rejects(self.raw_bad(gz(tar)))
        self.rejects(self.raw_bad(gz(gzip.decompress(raw) + b'\0' * tarfile.RECORDSIZE)))

    def test_bounded_inspection(self):
        for key, value in [('LIMIT', 100), ('FILE_LIMIT', 5), ('JSON_LIMIT', 5),
                           ('COUNT_LIMIT', 2), ('NOTICES_LIMIT', 10), ('MANIFEST_LIMIT', 5)]:
            with self.subTest(key=key), patch.object(t, key, value):
                self.rejects(self.pins, self.archive)

    def test_reinspected_extracted_tree_rejects_tampering_and_links(self):
        dest = self.root / 'extract'
        t.extract(self.archive, dest, **self.pins)
        args = dict(expected_manifest_sha256=self.pins['expected_manifest_sha256'],
                    expected_descriptor_sha256=self.descriptor_pin)
        path = dest / 'run/full/manifest.json'
        raw = path.read_bytes()
        for alteration in ('bytes', 'symlink', 'mode', 'extra-dir'):
            if alteration == 'bytes':
                path.write_bytes(b'changed')
            elif alteration == 'symlink':
                path.unlink(); path.symlink_to(self.f.run / 'full/manifest.json')
            elif alteration == 'mode':
                path.chmod(0o600)
            else:
                (dest / 'extra-empty').mkdir()
            with self.subTest(alteration=alteration), patch.object(t.l1, 'verify') as l1, self.assertRaises(t.TransportError):
                t.verify_extracted(self.root, dest, self.f.baseline, self.f.refpath, **args)
            l1.assert_not_called()
            if path.is_symlink():
                path.unlink()
            path.write_bytes(raw);path.chmod(0o644)

    def test_existing_and_source_outputs_rejected(self):
        with self.assertRaises(t.TransportError):
            self.prepare(self.out)
        with self.assertRaises(t.TransportError):
            t.extract(self.archive, self.f.run, **self.pins)
        with self.assertRaises(t.TransportError):
            t.extract(self.archive, t.PROJECT / 'uncreated-transport-test-output', **self.pins)
        self.assertFalse((t.PROJECT / 'uncreated-transport-test-output').exists())

    def test_bad_review_or_license_fails_before_output(self):
        dest = self.root / 'bad-preparation'
        self.kwargs['expected_notices_review_sha256'] = '0' * 64
        with self.assertRaises(t.TransportError):
            self.prepare(dest)
        self.assertFalse(dest.exists())
        self.kwargs['expected_notices_review_sha256'] = file_digest(self.review)
        next(self.licenses.iterdir()).write_bytes(b'wrong license')
        with self.assertRaises(t.TransportError):
            self.prepare(dest)
        self.assertFalse(dest.exists())

    def test_failed_l1_or_upgraded_restrictions_cannot_prepare(self):
        for receipt in ({'status': 'BLOCKED'}, {'status': 'LOCAL_EVIDENCE_VERIFIED',
                         'hosted_validation': 'SUCCESS', 'production_promotion': 'AUTHORIZED'}):
            output = self.root / 'blocked-preparation'
            with patch.object(t.l1, 'verify', return_value=receipt), self.assertRaisesRegex(
                    t.TransportError, '^L1_VERIFICATION_FAILED$'):
                self.prepare(output)
            self.assertFalse(output.exists())

    def test_original_executable_semantics_preserved(self):
        source = self.f.run / 'candidate/input/repos/SPHinXsys/vendor0.h'
        source.chmod(0o755)
        record = self.f.records / 'executed-command.txt'
        record.chmod(0o755)
        self.f.path.chmod(0o755)  # New descriptor metadata is normalized to 0644.
        receipt = self.prepare(self.root / 'executable')
        pins = {k: v for k, v in receipt.items() if k.startswith('expected_')}
        dest = self.root / 'executable-extracted'
        t.extract(receipt['archive'], dest, **pins)
        actual = dest / 'run/candidate/input/repos/SPHinXsys/vendor0.h'
        self.assertEqual(actual.stat().st_mode & 0o777, 0o755)
        self.assertEqual(actual.read_bytes(), source.read_bytes())
        self.assertEqual((dest / 'execution-record/executed-command.txt').stat().st_mode & 0o777, 0o755)
        self.assertEqual((dest / 'descriptor.json').stat().st_mode & 0o777, 0o644)

    def test_unknown_local_descriptor_and_fabricated_hosted_fields(self):
        for key, value in [('schema_version', 2), ('run_id', 123), ('approved', True)]:
            changed = []
            for item, raw in self.entries():
                if item.name == 'descriptor.json':
                    raw = canonical(dict(json.loads(raw), **{key: value}))
                changed.append((item, raw))
            descriptor_pin = hashlib.sha256(next(raw for item, raw in changed
                                                if item.name == 'descriptor.json')).hexdigest()
            pins = self.repack(changed, repin_manifest=True,
                               expected_descriptor_sha256=descriptor_pin)
            with self.subTest(key=key):
                self.rejects(pins)


if __name__ == '__main__':
    unittest.main()
