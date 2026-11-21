"""Pinned local research loading only; reuse P9, never promotion or build authority.

The caller supplies reviewed Registry bytes' digest independently of the artifact.
This verifies a previously qualified Baseline's local identity bindings, not its
scientific qualification again and not Owner authorization. The caller must have
separate permission for an isolated research session and enforce runtime isolation.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import json
from pathlib import Path
import re
import shutil
import sys

from . import trusted_snapshot as trust, versioned_corpus_storage as storage
from .corpus_snapshot import _unique, digest, file_digest
from .corpus_switching_test_session import TestWorkspace


class SelectionError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _need(ok, code):
    if not ok:
        raise SelectionError(code)


@dataclass(frozen=True)
class ReviewedCorpus:
    registry_path: Path
    registry_sha256: str
    key: str
    candidate_id: str
    baseline_id: str
    corpus_sha256: str
    size_bytes: int
    records: int


def _read(path, limit):
    path = Path(path)
    _need(path.is_absolute() and '..' not in path.parts, 'UNSAFE_RESEARCH_PATH')
    with storage._directory(path.parent) as fd, storage._regular(fd, path.name) as stream:
        raw = stream.read(limit + 1)
    _need(len(raw) <= limit, 'EVIDENCE_TOO_LARGE')
    return raw


def _json(raw):
    def reject(_):
        raise SelectionError('INVALID_EVIDENCE_JSON')
    return json.loads(raw, object_pairs_hook=_unique, parse_constant=reject)


def verify(review, corpus_path, baseline_root, *, notices_path=None):
    """Read only. Reuse independently pinned Registry/manifest and v3 notices.

    Returns identity evidence, never a reusable approval token. select() verifies
    again and P9 verifies the copied bytes. No remote download or scientific replay.
    """
    _need(isinstance(review, ReviewedCorpus), 'REVIEWED_IDENTITY_REQUIRED')
    for value in (review.registry_sha256, review.corpus_sha256):
        _need(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'INVALID_REVIEWED_PIN')
    for value in (review.candidate_id, review.baseline_id):
        _need(isinstance(value, str) and re.fullmatch('sha256-[0-9a-f]{64}', value), 'INVALID_REVIEWED_PIN')
    _need(type(review.size_bytes) is int and 0 < review.size_bytes <= 1024**3
          and type(review.records) is int and review.records > 0, 'INVALID_REVIEWED_PIN')
    registry_raw = _read(review.registry_path, 8 * 1024**2)
    from hashlib import sha256
    _need(sha256(registry_raw).hexdigest() == review.registry_sha256, 'REGISTRY_IDENTITY_MISMATCH')
    registry = _json(registry_raw)
    _need(isinstance(registry, dict) and registry.get('schema_version') == 2, 'VERSION_IDENTITY_MISMATCH')
    entry = registry.get('baselines', {}).get(review.key)
    _need(isinstance(entry, dict) and entry.get('entry_kind') == 'REGISTRATION_ONLY', 'RESEARCH_SCOPE_REQUIRED')
    ref = entry.get('reference', {})
    _need(digest(ref) == entry.get('expected_reference_sha256')
          and ref.get('node_id') == review.baseline_id
          and ref.get('corpus_sha256') == review.corpus_sha256
          and ref.get('package_format') == 'schema2-research-baseline', 'VERSION_IDENTITY_MISMATCH')
    # No downloaded Parent is restored. Retained local v3 notices remain mandatory.
    trust.validate_reference(ref, entry['expected_reference_sha256'])
    notices = None
    if ref['schema_version'] == 3:
        _need(notices_path is not None, 'MANDATORY_NOTICES_REQUIRED')
        notices = trust.verify_notices(ref, entry['expected_reference_sha256'], notices_path)
    baseline_root = Path(baseline_root)
    manifest_raw = _read(baseline_root / 'checksums.json', 8 * 1024**2)
    _need(sha256(manifest_raw).hexdigest() == ref['manifest_sha256'], 'VERSION_IDENTITY_MISMATCH')
    manifest = _json(manifest_raw)
    metadata = {}
    for name in ('upstream-baseline.json', 'upstream-candidate.json'):
        raw = _read(baseline_root / name, 32 * 1024**2)
        _need(sha256(raw).hexdigest() == manifest.get(name), 'VERSION_IDENTITY_MISMATCH')
        metadata[name] = _json(raw)
    baseline, candidate = metadata['upstream-baseline.json'], metadata['upstream-candidate.json']
    identity = baseline.get('identity', {})
    _need(baseline.get('baseline_id') == review.baseline_id
          and candidate.get('candidate_id') == review.candidate_id
          and identity.get('candidate_id') == review.candidate_id
          and identity.get('candidate_identity') == candidate.get('identity')
          and identity.get('production_promotion') == 'NOT_AUTHORIZED'
          and identity.get('automatic_research_approval') is False
          and identity.get('upstreams') == ref['upstreams']
          and identity.get('target_source_state') == ref['source_state']
          and identity.get('build_fingerprint') == ref['build_fingerprint']
          and candidate['identity'].get('artifacts', {}).get('corpus.jsonl') == review.corpus_sha256
          and manifest.get('corpus.jsonl') == review.corpus_sha256, 'VERSION_IDENTITY_MISMATCH')
    raw = _read(corpus_path, review.size_bytes)
    _need(len(raw) == review.size_bytes and sha256(raw).hexdigest() == review.corpus_sha256,
          'CORPUS_IDENTITY_MISMATCH')
    records = [_json(line) for line in raw.splitlines() if line]
    required = {'chunk_id', 'repository', 'source_role', 'source_path', 'content', 'start_line', 'end_line'}
    _need(len(records) == review.records and all(isinstance(r, dict) and required <= r.keys()
          and all(isinstance(r[k], str) for k in ('chunk_id', 'content', 'source_path', 'repository', 'source_role'))
          and type(r['start_line']) is int and type(r['end_line']) is int for r in records),
          'CORPUS_IDENTITY_MISMATCH')
    return {'status': 'RESEARCH_CORPUS_IDENTITY_VERIFIED', 'scope': 'RESEARCH_LOADING_ONLY',
            'candidate_id': review.candidate_id, 'baseline_id': review.baseline_id,
            'corpus_sha256': review.corpus_sha256, 'records': review.records,
            'registry_sha256': review.registry_sha256, 'notices': notices,
            'scientific_verification': 'RETAINED_EVIDENCE_BINDINGS_ONLY / NO_FRESH_REPLAY',
            'restrictions': ['QUALITY_REVIEW_REQUIRED', 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR',
                             'P8_BLOCKED', 'PRODUCTION_NOT_AUTHORIZED']}


@dataclass(frozen=True)
class ResearchSelection:
    corpus_path: Path
    receipt: dict

    def environment(self):
        """For a fresh isolated child only; does not import/start the application."""
        _need('apps.gradio_app_v1' not in sys.modules, 'FRESH_APPLICATION_PROCESS_REQUIRED')
        _need(file_digest(self.corpus_path) == self.receipt['corpus_sha256'], 'CORPUS_IDENTITY_MISMATCH')
        return {'SPHINX_CORPUS_PATH': str(self.corpus_path)}


@contextmanager
def select(review, corpus_path, baseline_root, *, notices_path=None, purpose='RESEARCH_LOADING_ONLY'):
    """Own a P9 temporary selection; no persistent pointer or authority change.

    Lifetime is this context. Caller starts a fresh process with environment(),
    verifies actual Retriever state, and shuts it down before context exit.
    """
    _need(purpose != 'BUILD_CANDIDATE', 'BUILD_AUTHORIZATION_DENIED')
    _need(purpose != 'PRODUCTION_ACTIVATION', 'PRODUCTION_ACTIVATION_DENIED')
    _need(purpose == 'RESEARCH_LOADING_ONLY', 'RESEARCH_SCOPE_REQUIRED')
    receipt = verify(review, corpus_path, baseline_root, notices_path=notices_path)
    with TestWorkspace() as workspace:
        version = 'research-' + review.baseline_id.removeprefix('sha256-')
        workspace.register(version, corpus_path, review.corpus_sha256)
        switched = workspace.switch(version)
        _need(switched['status'] == 'SWITCHED', 'SELECTION_COMMIT_NOT_VERIFIED')
        path = workspace.root / version / 'corpus.jsonl'
        retained_notices = None
        if notices_path is not None:
            retained_notices = workspace.root / 'research-notices.zip'
            shutil.copyfile(notices_path, retained_notices)
            _need(file_digest(retained_notices) == file_digest(notices_path), 'NOTICES_IDENTITY_MISMATCH')
            # Reverify the copy using the original independently pinned reference.
            registry = _json(_read(review.registry_path, 8 * 1024**2))
            _need(file_digest(review.registry_path) == review.registry_sha256, 'REGISTRY_IDENTITY_MISMATCH')
            entry = registry['baselines'][review.key]
            trust.verify_notices(entry['reference'], entry['expected_reference_sha256'], retained_notices)
        _need(file_digest(review.registry_path) == review.registry_sha256, 'REGISTRY_IDENTITY_MISMATCH')
        yield ResearchSelection(path, {**receipt, 'selection': switched,
                                      'notices_path': str(retained_notices) if retained_notices else None})


def verify_gradio_loading(review, corpus_path, baseline_root, *, notices_path=None,
                          queries=(), purpose='RESEARCH_LOADING_ONLY'):
    """Qualified local artifact -> P9 selection -> fresh real app/BM25 -> close.

    No download, publication, approval, production pointer or persistent server.
    Run with an already installed application-compatible Python environment.
    The independent review/Registry/notices gates remain authoritative. The
    caller must separately authorize this bounded isolated research execution.
    """
    _need(isinstance(queries, (tuple, list)) and 1 <= len(queries) <= 3
          and all(isinstance(q, str) and 0 < len(q.strip()) <= 2048 for q in queries),
          'BOUNDED_RESEARCH_QUERIES_REQUIRED')
    from .corpus_update_integration import _load_gradio
    with select(review, corpus_path, baseline_root, notices_path=notices_path,
                purpose=purpose) as selected:
        path = Path(selected.environment()['SPHINX_CORPUS_PATH'])
        loaded = _load_gradio(path, review.corpus_sha256, queries=queries)
        _need(loaded.get('sha256') == review.corpus_sha256
              and loaded.get('corpus_path') == str(path) and loaded.get('records') == review.records
              and loaded.get('retriever_class') == 'src.retrieval_v1.RetrievalV1'
              and loaded.get('complete_records_equal') is True
              and loaded.get('callbacks_share_assistant') is True
              and loaded.get('application_closed') is True
              and [x.get('query') for x in loaded.get('retrieval', [])] == list(queries),
              'RESEARCH_RUNTIME_BINDING_MISMATCH')
        _need(file_digest(path) == review.corpus_sha256, 'CORPUS_IDENTITY_MISMATCH')
        return {'status': 'RESEARCH_GRADIO_LOADING_VERIFIED', 'scope': 'RESEARCH_LOADING_ONLY',
                'identity': selected.receipt, 'application': loaded,
                'application_running': False, 'hot_reload': False,
                'production_promotion': 'NOT_AUTHORIZED'}
