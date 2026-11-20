"""Synthetic selection tests; no application or scientific experiment."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from src import research_corpus_selection as s
from src.corpus_snapshot import digest


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.corpus = self.root/'corpus.jsonl'
        row = dict(chunk_id='fixture', repository='SPHinXsim', source_role='documentation',
                   source_path='docs/test.md', content='test evidence', start_line=1, end_line=1)
        self.corpus.write_text(json.dumps(row)+'\n')
        ch = hashlib.sha256(self.corpus.read_bytes()).hexdigest()
        cid, bid = 'sha256-'+'1'*64, 'sha256-'+'2'*64
        upstreams = {'SPHinXsys': '3'*40, 'SPHinXsim': '4'*40}
        ci = {'artifacts': {'corpus.jsonl': ch}}
        bi = {'candidate_id': cid, 'candidate_identity': ci, 'upstreams': upstreams,
              'target_source_state': 'sha256-'+'5'*64, 'build_fingerprint': '6'*64,
              'automatic_research_approval': False, 'production_promotion': 'NOT_AUTHORIZED'}
        for name, obj in [('upstream-candidate.json', {'candidate_id': cid, 'identity': ci}),
                          ('upstream-baseline.json', {'baseline_id': bid, 'identity': bi})]:
            (self.root/name).write_text(json.dumps(obj))
        manifest = {n: hashlib.sha256((self.root/n).read_bytes()).hexdigest()
                    for n in ['corpus.jsonl', 'upstream-candidate.json', 'upstream-baseline.json']}
        (self.root/'checksums.json').write_text(json.dumps(manifest))
        ref = {'schema_version': 2, 'package_format': 'schema2-research-baseline', 'accepted_package_schema': 2,
               'node_id': bid, 'package_checksum': '7'*64, 'manifest_sha256': hashlib.sha256((self.root/'checksums.json').read_bytes()).hexdigest(),
               'transport_sha256': '8'*64, 'source_state': bi['target_source_state'], 'upstreams': upstreams,
               'build_fingerprint': '6'*64, 'corpus_sha256': ch, 'parent_rows_sha256': '9'*64,
               'storage': {'kind': 'LOCAL_QUALIFICATION_ONLY'},
               'authorization': {'type': 'EXPLICIT_RESEARCH_BASELINE_REUSE', 'scope': 'ISOLATED_RESEARCH_PARENT_REUSE',
                                 'research_only': True, 'experiment_id': 'synthetic', 'automatic_research_approval': False,
                                 'production_promotion': 'NOT_AUTHORIZED'}}
        registry = self.root/'registry.json'
        registry.write_text(json.dumps({'schema_version': 2, 'baselines': {'fixture': {
            'entry_kind': 'REGISTRATION_ONLY', 'reference': ref, 'expected_reference_sha256': digest(ref)}}}))
        self.review = s.ReviewedCorpus(registry, hashlib.sha256(registry.read_bytes()).hexdigest(),
                                      'fixture', cid, bid, ch, self.corpus.stat().st_size, 1)

    def reject(self, code, callback):
        with self.assertRaises(s.SelectionError) as caught:
            callback()
        self.assertEqual(caught.exception.code, code)

    def test_exact_identity(self):
        self.assertEqual(s.verify(self.review, self.corpus, self.root)['status'], 'RESEARCH_CORPUS_IDENTITY_VERIFIED')

    def test_bad_digest(self):
        copy = self.root/'bad.jsonl'
        copy.write_bytes(self.corpus.read_bytes().replace(b'test evidence', b'best evidence'))
        self.reject('CORPUS_IDENTITY_MISMATCH', lambda: s.verify(self.review, copy, self.root))

    def test_wrong_candidate(self):
        self.reject('VERSION_IDENTITY_MISMATCH', lambda: s.verify(replace(self.review, candidate_id='sha256-'+'a'*64), self.corpus, self.root))

    def test_wrong_baseline(self):
        self.reject('VERSION_IDENTITY_MISMATCH', lambda: s.verify(replace(self.review, baseline_id='sha256-'+'a'*64), self.corpus, self.root))

    def test_stale_registry(self):
        self.reject('REGISTRY_IDENTITY_MISMATCH', lambda: s.verify(replace(self.review, registry_sha256='a'*64), self.corpus, self.root))

    def test_changed_manifest(self):
        (self.root/'checksums.json').write_text('{}')
        self.reject('VERSION_IDENTITY_MISMATCH', lambda: s.verify(self.review, self.corpus, self.root))

    def test_record_count(self):
        self.reject('CORPUS_IDENTITY_MISMATCH', lambda: s.verify(replace(self.review, records=2), self.corpus, self.root))

    def test_production_request(self):
        with patch.object(s, 'TestWorkspace', side_effect=AssertionError('must not create')):
            with self.assertRaisesRegex(s.SelectionError, 'PRODUCTION_ACTIVATION_DENIED'):
                with s.select(self.review, self.corpus, self.root, purpose='PRODUCTION_ACTIVATION'):
                    self.fail()

    def test_build_request(self):
        with self.assertRaisesRegex(s.SelectionError, 'BUILD_AUTHORIZATION_DENIED'):
            with s.select(self.review, self.corpus, self.root, purpose='BUILD_CANDIDATE'):
                self.fail()

    def test_p9_selection_and_cleanup(self):
        with s.select(self.review, self.corpus, self.root) as selected:
            path = selected.corpus_path
            self.assertEqual(path.read_bytes(), self.corpus.read_bytes())
            self.assertEqual(selected.environment()['SPHINX_CORPUS_PATH'], str(path))
            self.assertEqual(selected.receipt['scope'], 'RESEARCH_LOADING_ONLY')
        self.assertFalse(path.exists())

    def test_no_hot_reload(self):
        with s.select(self.review, self.corpus, self.root) as selected:
            with patch.dict(sys.modules, {'apps.gradio_app_v1': object()}):
                self.reject('FRESH_APPLICATION_PROCESS_REQUIRED', selected.environment)

    def test_source_symlink(self):
        link = self.root/'linked.jsonl'
        link.symlink_to(self.corpus)
        with self.assertRaises(OSError):
            s.verify(self.review, link, self.root)

    def test_selected_bytes_rechecked_before_import_environment(self):
        with s.select(self.review, self.corpus, self.root) as selected:
            selected.corpus_path.write_bytes(b'changed')
            self.reject('CORPUS_IDENTITY_MISMATCH', selected.environment)

    def test_invalid_research_scope(self):
        with self.assertRaisesRegex(s.SelectionError, 'RESEARCH_SCOPE_REQUIRED'):
            with s.select(self.review, self.corpus, self.root, purpose='PUBLISH'):
                self.fail()

    def test_wrong_required_runtime_field(self):
        row = json.loads(self.corpus.read_bytes())
        row['start_line'] = True
        self.corpus.write_text(json.dumps(row)+'\n')
        # Matching reviewed hashes alone must not hide an invalid runtime record.
        ch = hashlib.sha256(self.corpus.read_bytes()).hexdigest()
        registry = json.loads(self.review.registry_path.read_bytes())
        entry = registry['baselines']['fixture']
        entry['reference']['corpus_sha256'] = ch
        candidate = json.loads((self.root/'upstream-candidate.json').read_bytes())
        candidate['identity']['artifacts']['corpus.jsonl'] = ch
        (self.root/'upstream-candidate.json').write_text(json.dumps(candidate))
        baseline = json.loads((self.root/'upstream-baseline.json').read_bytes())
        baseline['identity']['candidate_identity'] = candidate['identity']
        (self.root/'upstream-baseline.json').write_text(json.dumps(baseline))
        manifest = {n: hashlib.sha256((self.root/n).read_bytes()).hexdigest()
                    for n in ['corpus.jsonl', 'upstream-candidate.json', 'upstream-baseline.json']}
        (self.root/'checksums.json').write_text(json.dumps(manifest))
        entry['reference']['manifest_sha256'] = hashlib.sha256((self.root/'checksums.json').read_bytes()).hexdigest()
        entry['expected_reference_sha256'] = digest(entry['reference'])
        self.review.registry_path.write_text(json.dumps(registry))
        reviewed = replace(self.review, registry_sha256=hashlib.sha256(self.review.registry_path.read_bytes()).hexdigest(),
                           corpus_sha256=ch, size_bytes=self.corpus.stat().st_size)
        self.reject('CORPUS_IDENTITY_MISMATCH', lambda: s.verify(reviewed, self.corpus, self.root))


if __name__ == '__main__':
    unittest.main()
