"""Owned synthetic Gradio HTTP lifecycle demo, never Candidate promotion.

Run with an existing Gradio-compatible interpreter, optionally --port N. Only
built-in v1/v2 templates are accepted, inside a process-owned P9 workspace.
No external Corpus/root, process attachment, approval or deployment options exist.
The CI app and original callbacks are used unchanged. Missing LLM configuration
is expected; no answer is fabricated. HTTP evidence validates retrieval only.
"""
from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

from .corpus_snapshot import canonical, read_records
from .corpus_switching_test_session import TestWorkspace
from . import versioned_corpus_storage as storage
from .synthetic_retriever_reload import TOKENS, _records

PROJECT = Path(__file__).resolve().parents[1]


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def _serve(version, path, proof_path, nonce, port):
    """Private child bootstrap; not an external-input CLI or a second app."""
    network = {'blocked': 0}
    def local(host):
        if host not in ('127.0.0.1', '::1', 'localhost', None):
            network['blocked'] += 1
            raise OSError('Non-loopback networking disabled')
    def guard(event, args):
        if event in ('socket.connect', 'socket.bind', 'socket.sendto'):
            address = args[-1]
            if isinstance(address, tuple):
                local(address[0])
        if event in ('socket.getaddrinfo', 'socket.gethostbyname', 'socket.gethostbyaddr'):
            local(args[0])
    sys.addaudithook(guard)
    path, proof_path = Path(path), Path(proof_path)
    from apps import gradio_app_v1 as module
    from . import grounded_answer_v1, retrieval_v1
    _need(Path(module.__file__).resolve() == PROJECT / 'apps/gradio_app_v1.py', 'Wrong application module')
    _need(Path(retrieval_v1.__file__).resolve() == PROJECT / 'src/retrieval_v1.py', 'Wrong Retriever module')
    _need(not os.environ.get('LLM_API_KEY') and module.CORPUS_PATH == path, 'Unsafe application configuration')
    app = module.build_app()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        callbacks = {name: [item for item in app.fns.values() if item.fn is not None
                           and getattr(inspect.unwrap(item.fn), '__name__', '') == name]
                     for name in ('ask', 'request_received')}
        assistants = [inspect.getclosurevars(inspect.unwrap(item.fn)).nonlocals['assistant']
                      for item in callbacks['ask']]
        _need(assistants and all(a is assistants[0] for a in assistants), 'Unverified callback assistant')
        retriever = assistants[0].retriever
        _need(type(retriever) is retrieval_v1.RetrievalV1 and retriever.corpus_path == path
              and retriever.records == read_records(path) == _records(version), 'Loaded Corpus identity mismatch')
        counts = {'ask': 0, 'llm_client': 0}
        def profile(frame, event, arg):
            if event == 'call':
                if frame.f_code.co_name == 'ask' and frame.f_code.co_filename == module.__file__:
                    counts['ask'] += 1
                if frame.f_code.co_name == '__init__' and frame.f_locals.get('self').__class__.__name__ == 'OpenAI':
                    counts['llm_client'] += 1
                    raise RuntimeError('LLM clients are disabled')
            if event == 'return' and frame.f_code.co_name == 'ask' and frame.f_code.co_filename == module.__file__:
                temporary = proof_path.with_suffix('.runtime.tmp')
                temporary.write_text(json.dumps({'nonce': nonce, 'pid': os.getpid(), **counts,
                                                 'blocked_external_connections': network['blocked']}))
                os.replace(temporary, proof_path.with_suffix('.runtime.json'))
        threading.setprofile(profile)
        sys.setprofile(profile)
        app.launch(server_name='127.0.0.1', server_port=port, share=False, inbrowser=False,
                   prevent_thread_lock=True, quiet=True, ssr_mode=False)
        proof = {'nonce': nonce, 'pid': os.getpid(), 'port': port, 'version': version,
                 'app_id': app.app_id, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                 'records': len(retriever.records), 'corpus_path': str(retriever.corpus_path),
                 'retriever_class': 'src.retrieval_v1.RetrievalV1', 'complete_records_equal': True,
                 'blocked_external_connections': network['blocked'],
                 'ask_index': callbacks['ask'][0]._id,
                 'request_api': callbacks['request_received'][0].api_name}
        temporary = proof_path.with_suffix('.ready.tmp')
        temporary.write_text(json.dumps(proof))
        os.replace(temporary, proof_path)
        stop.wait(timeout=180)  # Hard research-session lifetime, including parent loss.
    finally:
        sys.setprofile(None)
        threading.setprofile(None)
        app.close()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise ValueError('Unexpected HTTP redirect')


class Lifecycle:
    """Own exactly two synthetic versions, one port and child at a time."""

    def __init__(self, port=None):
        _need(port is None or type(port) is int and 1024 <= port <= 65535, 'Invalid test port')
        self._workspace = TestWorkspace()
        self._child = None
        self._running = self._last_good = None
        self._proof = None
        self._closed = False
        self._owner = os.getpid()
        self.events = []
        self._expected = {}
        self.startup_timeout, self.request_timeout, self.shutdown_timeout = 40.0, 15.0, 5.0
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        try:
            self.port = self._free_port(port)
            for version in TOKENS:
                raw = b''.join(canonical(row) + b'\n' for row in _records(version))
                self._expected[version] = hashlib.sha256(raw).hexdigest()
                source = self.root / ('.source-' + version)
                source.write_bytes(raw)
                try:
                    read_records(source)
                    self._workspace.register(version, source, self._expected[version])
                finally:
                    source.unlink()
        except BaseException:
            self._workspace.close()
            raise

    @property
    def root(self):
        return self._workspace.root

    @staticmethod
    def _free_port(port):
        with socket.socket() as check:
            check.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            check.bind(('127.0.0.1', port or 0))
            return check.getsockname()[1]

    def _state(self):
        selection = self._workspace._actual_after_error()
        alive = self._child is not None and self._child.poll() is None
        return {'selected_version': selection.get('version'),
                'running_version': self._running if alive else None,
                'last_verified_version': self._last_good, 'child_alive': alive,
                'child_pid': self._child.pid if self._child else None,
                'service_verified': alive and self._running is not None,
                'selection': selection, 'port': self.port, 'test_only': True}

    def state(self):
        with self._workspace._guard():
            return self._state()

    def _preflight(self, version):
        _need(version in TOKENS, 'Only internally generated v1/v2 are supported')
        metadata = storage.inspect(self.root, version)['metadata']
        path = self.root / version / 'corpus.jsonl'
        _need(metadata['sha256'] == self._expected[version]
              and hashlib.sha256(path.read_bytes()).hexdigest() == self._expected[version]
              and read_records(path) == _records(version), 'Invalid synthetic Corpus checksum/format/count')
        return path

    def _launch(self, version):
        self._free_port(self.port)  # Fail safely if another service acquired it.
        self._nonce = secrets.token_hex(16)
        self._proof = self.root / ('.service-' + self._nonce + '.json')
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(('LLM_', 'OPENAI_', 'AZURE_OPENAI_'))
               and k not in ('PYTHONPATH', 'PYTHONHOME', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
                            'http_proxy', 'https_proxy', 'all_proxy')}
        env.update(SPHINX_CORPUS_PATH=str(self.root / version / 'corpus.jsonl'),
                   PYTHONDONTWRITEBYTECODE='1', GRADIO_ANALYTICS_ENABLED='False',
                   HF_HUB_DISABLE_TELEMETRY='1', HF_HUB_OFFLINE='1',
                   GRADIO_TEMP_DIR=str(self.root / '.gradio'), XDG_CACHE_HOME=str(self.root / '.cache'))
        code = ('import sys; from src.gradio_service_lifecycle import _serve; '
                '_serve(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4],int(sys.argv[5]))')
        child_log = self.root / ('.server-' + self._nonce + '.log')
        with child_log.open('x') as log:
            self._child = subprocess.Popen([sys.executable, '-B', '-c', code, version,
                str(self.root / version / 'corpus.jsonl'), str(self._proof), self._nonce, str(self.port)],
                cwd=PROJECT, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                start_new_session=True)
        self.events.append({'event': 'SPAWNED', 'pid': self._child.pid, 'version': version, 'nonce': self._nonce})
        deadline = time.monotonic() + self.startup_timeout
        while not self._proof.exists():
            if self._child.poll() is not None:
                raise RuntimeError('Gradio child exited before readiness: ' + child_log.read_text(errors='replace')[-2000:])
            _need(time.monotonic() < deadline, 'Gradio startup timed out')
            time.sleep(0.05)

    def _http(self, route, data=None, timeout=None):
        _need(route.startswith('/') and not route.startswith('//'), 'Invalid local endpoint')
        request = urllib.request.Request(f'http://127.0.0.1:{self.port}' + route,
                    data=None if data is None else json.dumps(data).encode(),
                    headers={'Content-Type': 'application/json'})
        return self._opener.open(request, timeout=timeout or self.request_timeout)

    def _verify(self, version):
        deadline = time.monotonic() + self.request_timeout
        def request(route, data=None):
            remaining = deadline - time.monotonic()
            _need(remaining > 0, 'HTTP verification deadline exceeded')
            return self._http(route, data, timeout=remaining)
        _need(self._child is not None and self._child.poll() is None, 'Owned child is not alive')
        proof = json.loads(self._proof.read_text())
        _need(proof['pid'] == self._child.pid and proof['nonce'] == self._nonce
              and proof['port'] == self.port and proof['version'] == version
              and proof['sha256'] == self._expected[version] and proof['records'] == len(_records(version))
              and proof['corpus_path'] == str(self.root / version / 'corpus.jsonl')
              and proof['blocked_external_connections'] == 0
              and proof['complete_records_equal'] is True, 'Wrong child or loaded Corpus identity')
        with request('/') as response:
            _need(response.status == 200 and b'SPHinX' in response.read(2 * 1024**2), 'Unexpected Gradio page')
        with request('/config') as response:
            config = json.load(response)
        _need(config['app_id'] == proof['app_id'] and config['api_prefix'] == '/gradio_api',
              'Wrong HTTP application identity')
        session = secrets.token_hex(16)
        query = TOKENS[version]
        with request('/gradio_api/run/' + proof['request_api'], {'data': [query], 'session_hash': session}) as response:
            _need(len(json.load(response)['data']) == 4, 'Wrong question interface')
        with request('/gradio_api/queue/join', {'data': [query, '', '', 2, None, 'lifecycle_test', None, None, None],
                                                'fn_index': proof['ask_index'], 'session_hash': session}) as response:
            event_id = json.load(response)['event_id']
        output = None
        with request('/gradio_api/queue/data?session_hash=' + session) as response:
            for _ in range(500):
                _need(time.monotonic() < deadline, 'Retrieval callback timed out')
                line = response.readline(2 * 1024**2)
                _need(bool(line), 'Incomplete callback event stream')
                if line.startswith(b'data: '):
                    event = json.loads(line[6:])
                    if event.get('event_id') == event_id and event['msg'] == 'process_completed':
                        _need(event['success'] is True, 'Real question callback failed')
                        output = event['output']['data']
                        break
        _need(isinstance(output, list) and len(output) == 13, 'Missing callback outputs')
        _need(query in output[3] and all(token not in output[3] for token in TOKENS.values() if token != query)
              and 'repos/SPHinXsim/docs/p93_primary.md' in output[2]
              and 'Lines 1-1' in output[3] and 'LLM_API_KEY is required' in output[4],
              'Wrong version-specific retrieval evidence')
        runtime = json.loads(self._proof.with_suffix('.runtime.json').read_text())
        _need(runtime['nonce'] == self._nonce and runtime['pid'] == self._child.pid
              and runtime['ask'] >= 1 and runtime['llm_client'] == 0 and self._child.poll() is None,
              'Callback execution not verified')
        _need(runtime['blocked_external_connections'] == 0, 'Unexpected external network attempt')
        self._preflight(version)
        return {**proof, 'http': 'PASS', 'retrieval': 'PASS_RETRIEVAL_ONLY', 'query': query,
                'sources': output[2], 'evidence': output[3], 'llm_client_calls': 0,
                'actual_callback_calls': runtime['ask']}

    def _stop(self):
        self._running = None
        if self._child is None:
            return
        child = self._child
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=self.shutdown_timeout)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=self.shutdown_timeout)
        else:
            child.wait(timeout=self.shutdown_timeout)
        self.events.append({'event': 'REAPED', 'pid': child.pid, 'returncode': child.returncode})
        self._child = None

    def _boot(self, version):
        selected = self._workspace.switch(version)
        _need(selected['status'] == 'SWITCHED', 'Selection COMMITTED_WITH_ERROR: inspect actual selection')
        self._launch(version)
        verified = self._verify(version)
        self._running = self._last_good = version
        return verified

    def start(self, version='v1'):
        with self._workspace._guard():
            _need(self._child is None, 'Controller already owns a child; use update')
            self._preflight(version)
            try:
                proof = self._boot(version)
                return {'status': 'STARTED', 'verification': proof, **self._state()}
            except Exception:
                self._stop()
                raise

    def update(self, version):
        with self._workspace._guard():
            _need(self._child is not None and self._child.poll() is None and self._running is not None,
                  'No verified running service to replace')
            previous = self._last_good
            try:
                self._preflight(version)  # Reject invalid B before touching A.
            except Exception as error:
                return {'status': 'UPDATE_REJECTED', 'error': type(error).__name__,
                        'rollback': {'status': 'NOT_NEEDED'}, **self._state()}
            try:
                self._stop()
            except Exception as error:
                return {'status': 'STOP_FAILED', 'error': type(error).__name__, **self._state()}
            try:
                proof = self._boot(version)
                return {'status': 'UPDATED', 'verification': proof, 'rollback': {'status': 'NOT_NEEDED'}, **self._state()}
            except Exception as error:
                result = {'status': 'UPDATE_FAILED', 'error': str(error), 'rollback': {'status': 'FAILED'}}
                try:
                    self._stop()
                    restored = self._boot(previous)
                    result['rollback'] = {'status': 'ROLLBACK_SUCCESS', 'verification': restored}
                except Exception as rollback_error:
                    result['rollback']['error'] = str(rollback_error)
                    try:
                        self._stop()
                    except Exception as cleanup_error:
                        result['cleanup_error'] = str(cleanup_error)
                return {**result, **self._state()}

    def close(self):
        _need(os.getpid() == self._owner, 'Controller belongs to another process')
        if not self._closed:
            with self._workspace._guard():
                self._stop()
                self._workspace.close()
                self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *error):
        self.close()


def run_demo(port=None):
    with Lifecycle(port) as controller:
        root = controller.root
        first = controller.start()
        second = controller.update('v2')
        restored = controller.update('v1')
        events = controller.events
    passed = first['status'] == 'STARTED' and second['status'] == restored['status'] == 'UPDATED'
    return {'status': 'PASS_RETRIEVAL_ONLY' if passed else 'FAILED',
            'test_only': True, 'production_authorization': 'NOT_AUTHORIZED',
            'cases': [first, second, restored], 'events': events, 'temporary_store_removed': not root.exists()}


def main(argv=None):
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--port', type=int)
        result = run_demo(parser.parse_args(argv).port)
    except (OSError, ValueError, RuntimeError) as error:
        result = {'status': 'FAILED', 'error': str(error), 'test_only': True}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get('status') == 'PASS_RETRIEVAL_ONLY' and result.get('temporary_store_removed') else 1


if __name__ == '__main__':
    raise SystemExit(main())
