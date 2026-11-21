"""Temporary CI artifact -> P8 -> P9 -> Gradio integration, never deployment.

Run: python -B -m src.corpus_update_integration --artifact RUN_ZIP_OR_DIRECTORY
Only a complete sealed run is supported. The current P8 always blocks. There
is no approval file, override, external store, or server option. Registration
is temporary and is not activation. Successful reinitialization mechanics are
exercised separately with synthetic data, without manufacturing authorization.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, redirect_stdout
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from . import update_eligibility_gate as gate
from . import candidate_promotion_policy as promotion
from . import versioned_corpus_storage as storage
from .corpus_snapshot import _unique, digest, read_json
from .corpus_switching_test_session import TestWorkspace

PROJECT = Path(__file__).resolve().parents[1]


def _records(raw):
    rows = [json.loads(line, object_pairs_hook=_unique,
                       parse_constant=gate._reject_constant)
            for line in raw.decode('utf-8').splitlines() if line]
    storage._need(rows and all(isinstance(r, dict) for r in rows), 'Invalid Corpus records')
    return rows


def _register(workspace, version, raw, expected):
    storage._need(hashlib.sha256(raw).hexdigest() == expected, 'Imported Corpus checksum mismatch')
    count = len(_records(raw))
    with tempfile.NamedTemporaryFile(dir=workspace.root, prefix='.import-') as source:
        source.write(raw)
        source.flush()
        registered = workspace.register(version, Path(source.name), expected)
    return {**registered, 'version': version, 'records': count}


def _gradio_check(path, expected, queries=()):
    """Executed in a fresh child process; construct, verify, close. No HTTP/LLM."""
    path = Path(path)
    raw = path.read_bytes()
    storage._need(hashlib.sha256(raw).hexdigest() == expected, 'Gradio input checksum mismatch')
    records = _records(raw)
    app = None
    with redirect_stdout(io.StringIO()):
        try:
            from apps import gradio_app_v1 as module
            from . import grounded_answer_v1, retrieval_v1
            for loaded, relative in ((module, 'apps/gradio_app_v1.py'),
                                     (grounded_answer_v1, 'src/grounded_answer_v1.py'),
                                     (retrieval_v1, 'src/retrieval_v1.py')):
                storage._need(Path(loaded.__file__).resolve() == PROJECT / relative,
                              'Application module outside CI project')
            storage._need(module.CORPUS_PATH == path, 'Application Corpus path mismatch')
            app = module.build_app()
            asks = [inspect.unwrap(item.fn) for item in app.fns.values()
                    if item.fn is not None and getattr(inspect.unwrap(item.fn), '__name__', '') == 'ask']
            assistants = [inspect.getclosurevars(fn).nonlocals['assistant'] for fn in asks]
            storage._need(assistants and all(a is assistants[0] for a in assistants),
                          'Gradio callbacks do not share an assistant')
            retriever = assistants[0].retriever
            storage._need(type(retriever) is retrieval_v1.RetrievalV1
                          and retriever.corpus_path == path and retriever.records == records,
                          'Actual callback Retriever Corpus mismatch')
            result = {'corpus_path': str(path), 'sha256': expected, 'records': len(records),
                      'complete_records_equal': True, 'callbacks_share_assistant': True,
                      'retriever_class': 'src.retrieval_v1.RetrievalV1', 'pid': os.getpid(),
                      'application_closed': True}
            if queries:
                retrieval = []
                for query in queries:
                    hits = retriever.search(query, top_k=5)
                    storage._need(hits and all(hit.record in records for hit in hits),
                                  'Research query returned no bound Corpus evidence')
                    retrieval.append({'query': query, 'top_k': 5, 'results': [
                        {'rank': rank, 'chunk_id': hit.record['chunk_id'],
                         'source_path': hit.record['source_path'], 'score': hit.score,
                         'excerpt': hit.record['content'][:700]}
                        for rank, hit in enumerate(hits, 1)]})
                storage._need(hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                              'Corpus changed during research retrieval')
                result['retrieval'] = retrieval
        finally:
            if app is not None:
                app.close()
    return result


def _load_gradio(path, expected, *, queries=()):
    """Isolate import-time configuration and dependencies in a short-lived process."""
    storage._need(isinstance(queries, (list, tuple)) and len(queries) <= 3
                  and all(isinstance(q, str) and 0 < len(q.strip()) <= 2048 for q in queries),
                  'Invalid bounded research queries')
    # Do not forward CI/App credentials, provider credentials, proxy configuration
    # or arbitrary Python startup settings to application code.
    env = {k: os.environ[k] for k in ('PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ') if k in os.environ}
    with tempfile.TemporaryDirectory(prefix='sphinx-gradio-check-') as temporary:
        env.update({'SPHINX_CORPUS_PATH': str(path), 'PYTHONDONTWRITEBYTECODE': '1',
                    'GRADIO_ANALYTICS_ENABLED': 'False', 'HF_HUB_DISABLE_TELEMETRY': '1',
                    'HF_HUB_OFFLINE': '1', 'GRADIO_TEMP_DIR': temporary,
                    'XDG_CACHE_HOME': temporary, 'XDG_CONFIG_HOME': temporary,
                    'HOME': temporary, 'TMPDIR': temporary, 'PYTHONNOUSERSITE': '1',
                    'PYTHONHASHSEED': '0'})
        code = ("import sys,json\n"
                "def guard(event,args):\n"
                " if event in ('socket.connect','socket.bind','socket.sendto','socket.getaddrinfo',"
                "'socket.gethostbyname','socket.gethostbyaddr'):\n"
                "  raise OSError('Networking disabled in isolated Gradio validation')\n"
                " if event=='subprocess.Popen':\n"
                "  from pathlib import Path\n"
                "  a=args[1]\n"
                "  if not isinstance(a,(list,tuple)) or Path(str(a[0])).name!='git' "
                "or not any(x in a for x in ('rev-parse','remote')):\n"
                "   raise OSError('Only local Git inspection allowed in Gradio validation')\n"
                "sys.addaudithook(guard)\n"
                "from src.corpus_update_integration import _gradio_check\n"
                "print(json.dumps(_gradio_check(sys.argv[1],sys.argv[2],json.loads(sys.argv[3]))))\n")
        child = subprocess.run([sys.executable, '-B', '-c', code, str(path), expected, json.dumps(queries)],
                               cwd=PROJECT, env=env, capture_output=True, text=True, timeout=60)
        storage._need(child.returncode == 0, 'Isolated Gradio initialization/verification failed')
        return json.loads(child.stdout)


def _verify_loaded(workspace, version, initialize):
    metadata = storage.inspect(workspace.root, version)['metadata']
    path = workspace.root / version / 'corpus.jsonl'
    loaded = initialize(path, metadata['sha256'])
    storage._need(loaded['corpus_path'] == str(path) and loaded['sha256'] == metadata['sha256']
                  and loaded['records'] == len(_records(path.read_bytes()))
                  and loaded['complete_records_equal'] is True
                  and loaded['callbacks_share_assistant'] is True
                  and loaded['retriever_class'] == 'src.retrieval_v1.RetrievalV1'
                  and loaded['application_closed'] is True, 'Loaded application verification mismatch')
    storage._need(storage.inspect(workspace.root, version)['metadata'] == metadata,
                  'Stored version changed during initialization')
    storage._need(workspace.current()['version'] == version, 'Selection changed during initialization')
    return loaded


def _reinitialize(workspace, target, initialize=None):
    """Post-gate test-only mechanics. No authorization is granted by this helper.

    A verified previous selection must already exist. Each new Gradio instance
    closes before its child exits. A returned loaded version is a verified past
    initialization, not a running service. Selection and rollback are serialized.
    """
    initialize = initialize or _load_gradio
    with workspace._guard():
        previous = workspace.current()['version']
        storage._need(previous is not None, 'A previous selection is required for rollback')
        result = {'status': 'REINITIALIZATION_FAILED', 'verified_loaded_version': None,
                  'rollback': {'status': 'NOT_ATTEMPTED'}, 'application_running': False}
        try:
            switched = workspace.switch(target)
            storage._need(switched['status'] == 'SWITCHED', json.dumps(switched))
            result['initialization'] = _verify_loaded(workspace, target, initialize)
            result.update(status='TEST_REINITIALIZED', verified_loaded_version=target)
        except Exception as error:
            result['error'] = str(error)
            try:
                restored = workspace.switch(previous)
                storage._need(restored['status'] == 'SWITCHED', json.dumps(restored))
                check = _verify_loaded(workspace, previous, initialize)
                result['rollback'] = {'status': 'RESTORED', 'initialization': check}
                result['verified_loaded_version'] = previous
            except Exception as rollback_error:
                result['rollback'] = {'status': 'FAILED', 'error': str(rollback_error)}
        result['selection'] = workspace._actual_after_error()
        return result


def _integrate(artifact, workspace):
    with workspace._guard():
        before = workspace.current()
        policy = promotion.evaluate(artifact)  # Reuses the unchanged P8; never replay.
        decision = policy['p8']
        result = {'decision': 'BLOCKED', 'artifact_integrity': 'FAIL', 'gate': decision,
                  'registration': {'status': 'NOT_ATTEMPTED'}, 'activation': 'DENIED',
                  'gradio_reinitialization': 'NOT_ATTEMPTED', 'test_only': True,
                  'application_running': False, 'production_promotion': 'NOT_AUTHORIZED'}
        result['promotion_policy'] = policy
        try:
            if decision['evidence_consistency'] != 'VERIFIED_ARCHIVED_BINDINGS':
                return result
            with ExitStack() as stack:
                evidence = gate._Evidence(artifact, stack)
                candidate = evidence.json('candidate/candidate.json')
                identity = candidate['identity']
                storage._need(candidate['schema_version'] == 2
                              and candidate['kind'] == 'upstream-research-candidate', 'Unsupported Candidate schema')
                storage._need(candidate['candidate_id'] == decision['candidate_id']
                              == 'sha256-' + digest(identity), 'Artifact identity changed after P8 validation')
                storage._need(identity['artifacts']['corpus.jsonl'] == decision['corpus_sha256'],
                              'Artifact Corpus binding changed after P8 validation')
                benchmark_sha = evidence.sha('benchmark.json')
                storage._need(benchmark_sha == read_json(PROJECT / 'configs/ci_v2_runtime_lock.json')
                              ['quality_policy']['benchmark_sha256'], 'Benchmark changed after P8 validation')
                result['bindings'] = {'candidate_id': candidate['candidate_id'],
                                      'corpus_sha256': decision['corpus_sha256'],
                                      'upstreams': identity['upstreams'],
                                      'build_fingerprint': identity['build_fingerprint'],
                                      'benchmark_sha256': benchmark_sha}
                raw = evidence.raw('candidate/corpus.jsonl')
                storage._need(hashlib.sha256(raw).hexdigest() == decision['corpus_sha256'],
                              'Imported Corpus checksum mismatch')
                _records(raw)
                result['artifact_integrity'] = 'PASS'
                try:
                    result['registration'] = _register(workspace, candidate['candidate_id'], raw,
                                                       decision['corpus_sha256'])
                except Exception as error:
                    result['registration'] = {'status': 'FAILED', 'error': str(error)}
                    raise
                # No current authorization can reach the branch below. A future
                # trusted P8 implementation, not an input flag/JSON, must decide.
                if (decision['decision'] != 'ELIGIBLE' or decision.get('gate_mode') == 'BLOCKING_ONLY'
                        or decision['reasons'] or policy['final_eligibility'] != 'ELIGIBLE'):
                    return result
                if before['version'] is None:
                    parent = evidence.json('parent/manifest.json')
                    storage._need(parent['snapshot_id'] == identity['base_snapshot_id']
                                  == 'sha256-' + digest(parent['identity']), 'Parent binding mismatch')
                    version = parent['snapshot_id']
                    _register(workspace, version, evidence.raw('parent/corpus.jsonl'),
                              parent['identity']['corpus']['sha256'])
                    switched = workspace.switch(version)
                    storage._need(switched['status'] == 'SWITCHED', json.dumps(switched))
                    _verify_loaded(workspace, version, _load_gradio)
                result['gradio_reinitialization'] = _reinitialize(workspace, candidate['candidate_id'])
                if result['gradio_reinitialization']['status'] == 'TEST_REINITIALIZED':
                    result.update(decision='ELIGIBLE', activation='VERIFIED_IN_TEMPORARY_TEST_WORKSPACE')
        except Exception as error:
            result['error'] = str(error)
        finally:
            result['selection_before'] = before
            result['selection_after'] = workspace._actual_after_error()
            result['selection_unchanged'] = result['selection_before'] == result['selection_after']
        return result


def run(artifact):
    with TestWorkspace() as workspace:
        root = workspace.root
        result = _integrate(artifact, workspace)
    result['temporary_store_removed'] = not root.exists()
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', type=Path, required=True,
                        help='Complete sealed schema-2 run directory or original hosted ZIP; inspection/ is insufficient')
    args = parser.parse_args(argv)
    try:
        result = run(args.artifact)
    except Exception as error:
        result = {'decision': 'BLOCKED', 'error': str(error), 'activation': 'DENIED',
                  'production_promotion': 'NOT_AUTHORIZED'}
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if result['decision'] == 'ELIGIBLE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
