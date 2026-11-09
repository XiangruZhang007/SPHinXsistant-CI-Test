"""Owned loopback HTTP services plus isolated failure injection; no real Corpus."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import Mock, patch

from src import gradio_service_lifecycle as lifecycle
from src import candidate_promotion_policy as promotion


class LifecycleTests(unittest.TestCase):
    def test_real_http_updates_failures_rollback_and_cleanup(self):
        cases = []
        with lifecycle.Lifecycle() as controller:
            root, port = controller.root, controller.port
            files = {p: p.read_bytes() for v in lifecycle.TOKENS
                     for p in (root / v).iterdir()}
            first = controller.start()
            cases.append({'case': 'start_a', 'result': first})
            self.assertEqual(first['status'], 'STARTED')
            self.assertIn('amberanchor', first['verification']['evidence'])
            pid = first['child_pid']
            expected = controller._expected['v2']
            controller._expected['v2'] = '0'*64
            rejected = controller.update('v2')
            cases.append({'case': 'bad_checksum_preserves_a', 'result': rejected})
            self.assertEqual(rejected['status'], 'UPDATE_REJECTED')
            self.assertEqual(rejected['child_pid'], pid)
            self.assertEqual(rejected['running_version'], 'v1')
            controller._expected['v2'] = expected
            reader = lifecycle.read_records
            def bad_format(path):
                if path.parent.name == 'v2':
                    raise ValueError('Injected malformed input validation')
                return reader(path)
            with patch.object(lifecycle, 'read_records', side_effect=bad_format):
                rejected = controller.update('v2')
            self.assertEqual(rejected['status'], 'UPDATE_REJECTED')
            self.assertEqual(rejected['child_pid'], pid)
            cases.append({'case': 'format_rejection_preserves_a', 'result': rejected})

            second = controller.update('v2')
            cases.append({'case': 'a_to_b', 'result': second})
            self.assertEqual(second['status'], 'UPDATED')
            self.assertIn('cobaltanchor', second['verification']['evidence'])
            self.assertNotIn('amberanchor', second['verification']['evidence'])
            self.assertNotEqual(second['child_pid'], pid)
            self.assertNotEqual(second['verification']['app_id'], first['verification']['app_id'])
            cases.append({'case': 'b_to_a', 'result': controller.update('v1')})
            self.assertEqual(controller.state()['running_version'], 'v1')

            http = controller._http
            def wrong_endpoint(route, *args, **kwargs):
                if route == '/config':
                    return io.BytesIO(b'{"app_id":0,"api_prefix":"/gradio_api"}')
                return http(route, *args, **kwargs)
            with patch.object(controller, '_http', side_effect=wrong_endpoint):
                with self.assertRaisesRegex(ValueError, 'HTTP application identity'):
                    controller._verify('v1')
            with self.assertRaisesRegex(ValueError, 'loaded Corpus identity'):
                controller._verify('v2')
            self.assertEqual(controller._verify('v1')['llm_client_calls'], 0)

            verify = controller._verify
            def fail_b(version):
                if version == 'v2':
                    raise RuntimeError('Injected B readiness failure after real HTTP startup')
                return verify(version)
            # The filesystem selection is deliberately not the last good service.
            controller._workspace.switch('v2')
            with patch.object(controller, '_verify', side_effect=fail_b):
                failed = controller.update('v2')
            cases.append({'case': 'b_readiness_failure_rolls_back_last_good_a', 'result': failed})
            self.assertEqual(failed['status'], 'UPDATE_FAILED')
            self.assertEqual(failed['rollback']['status'], 'ROLLBACK_SUCCESS')
            self.assertEqual((failed['selected_version'], failed['running_version']), ('v1', 'v1'))
            self.assertEqual(failed['rollback']['verification']['http'], 'PASS')

            switch = controller._workspace.switch
            def committed_with_error(version):
                result = switch(version)
                if version == 'v2':
                    result.update(status='COMMITTED_WITH_ERROR')
                return result
            with patch.object(controller._workspace, 'switch', side_effect=committed_with_error):
                committed = controller.update('v2')
            cases.append({'case': 'committed_selection_error_restores_a', 'result': committed})
            self.assertIn('COMMITTED_WITH_ERROR', committed['error'])
            self.assertEqual(committed['rollback']['status'], 'ROLLBACK_SUCCESS')
            self.assertEqual(committed['selected_version'], 'v1')

            with patch.object(controller, '_verify', side_effect=RuntimeError('Injected B and rollback verification failure')):
                failed = controller.update('v2')
            cases.append({'case': 'rollback_failure_is_not_service_availability', 'result': failed})
            self.assertEqual(failed['rollback']['status'], 'FAILED')
            self.assertIsNone(failed['running_version'])
            self.assertFalse(failed['child_alive'])
            self.assertFalse(failed['service_verified'])
            self.assertEqual(failed['last_verified_version'], 'v1')
            self.assertEqual(files, {p: p.read_bytes() for p in files})
            events = deepcopy(controller.events)
            self.assertEqual({e['pid'] for e in events if e['event'] == 'SPAWNED'},
                             {e['pid'] for e in events if e['event'] == 'REAPED'})
        self.assertFalse(root.exists())
        self.assertEqual(lifecycle.Lifecycle._free_port(port), port)
        # Optional permanent evidence is written only into the existing CI archive.
        evidence = os.environ.get('SPHINX_LIFECYCLE_EVIDENCE')
        if evidence:
            target = Path(evidence).resolve()
            self.assertTrue(target.is_relative_to(lifecycle.PROJECT / 'doc/artifacts'))
            with (target / 'real-http-test-cases.json').open('x') as stream:
                json.dump({'cases': cases, 'events': events, 'temporary_store_removed': True,
                           'port_released': True, 'all_owned_children_reaped': True,
                           'production_authorization': 'NOT_AUTHORIZED'}, stream, indent=2)

    def test_only_internal_corpora_and_valid_ports_are_accepted(self):
        for port in (0, 80, 65536, True):
            with self.assertRaises(ValueError):
                lifecycle.Lifecycle(port)
        with lifecycle.Lifecycle() as controller:
            for value in ('candidate', '../v1', '/tmp/corpus.jsonl'):
                with self.assertRaises(ValueError):
                    controller.start(value)
        for option in ('--corpus', '--root', '--attach', '--force-promote', '--ignore-p8'):
            with patch('sys.stderr', io.StringIO()), self.assertRaises(SystemExit):
                lifecycle.main([option, 'x'])

    def test_malformed_generated_corpus_rejected_before_service_start(self):
        with patch.object(lifecycle, '_records', return_value=[{'invalid': True}]), \
                patch.object(lifecycle.subprocess, 'Popen') as start:
            with self.assertRaises(ValueError):
                lifecycle.Lifecycle()
            start.assert_not_called()

    def test_occupied_port_is_not_touched(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            port = listener.getsockname()[1]
            with self.assertRaises(OSError):
                lifecycle.Lifecycle(port)
            self.assertEqual(listener.getsockname()[1], port)
            self.assertGreaterEqual(listener.fileno(), 0)

    def test_owned_child_premature_exit_is_detected_and_reaped(self):
        start = subprocess.Popen
        def exit_early(command, **kwargs):
            return start([sys.executable, '-B', '-c', 'raise SystemExit(7)'], **kwargs)
        with lifecycle.Lifecycle() as controller:
            with patch.object(lifecycle.subprocess, 'Popen', side_effect=exit_early):
                with self.assertRaisesRegex(RuntimeError, 'exited before readiness'):
                    controller.start()
            self.assertFalse(controller.state()['child_alive'])
            self.assertEqual(controller.events[-1]['event'], 'REAPED')

    def test_shutdown_escalates_only_the_owned_handle(self):
        with lifecycle.Lifecycle() as controller:
            child = Mock(pid=123, returncode=-9)
            child.poll.return_value = None
            child.wait.side_effect = [subprocess.TimeoutExpired('owned', 1), -9]
            controller._child = child
            controller._stop()
            child.terminate.assert_called_once()
            child.kill.assert_called_once()
            self.assertEqual(child.wait.call_count, 2)
            self.assertIsNone(controller._child)

    def test_real_owned_process_ignoring_sigterm_is_killed_and_reaped(self):
        with lifecycle.Lifecycle() as controller:
            ready = controller.root / '.ignore-term-ready'
            code = ('import signal,time,sys; from pathlib import Path; '
                    'signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                    'Path(sys.argv[1]).write_text("ready"); time.sleep(20)')
            controller._child = subprocess.Popen([sys.executable, '-B', '-c', code, str(ready)],
                                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                                  stderr=subprocess.DEVNULL, start_new_session=True)
            child = controller._child
            deadline = time.monotonic() + 3
            while not ready.exists():
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            controller.shutdown_timeout = 0.2
            controller._stop()
            self.assertEqual(child.returncode, -9)
            self.assertIsNone(controller._child)
            self.assertEqual(controller.events[-1]['event'], 'REAPED')

    def test_stop_failure_never_starts_replacement(self):
        with lifecycle.Lifecycle() as controller:
            controller._workspace.switch('v1')
            child = Mock(pid=123, returncode=None)
            child.poll.return_value = None
            child.wait.side_effect = subprocess.TimeoutExpired('owned', 1)
            controller._child, controller._running, controller._last_good = child, 'v1', 'v1'
            with patch.object(controller, '_launch') as launch:
                result = controller.update('v2')
            self.assertEqual(result['status'], 'STOP_FAILED')
            self.assertEqual(result['selected_version'], 'v1')
            launch.assert_not_called()
            child.wait.side_effect = None
            child.wait.return_value = 0

    def test_transaction_serializes_selection_and_startup(self):
        with lifecycle.Lifecycle() as controller:
            controller._workspace.switch('v1')
            child = Mock(pid=123, returncode=0)
            child.poll.return_value = None
            controller._child, controller._running, controller._last_good = child, 'v1', 'v1'
            entered, release, started = threading.Event(), threading.Event(), threading.Event()
            def boot(version):
                entered.set()
                self.assertTrue(release.wait(5))
                controller._child = child
                controller._workspace.switch(version)
                controller._running = controller._last_good = version
                return {'test_only': True}
            def state():
                started.set()
                return controller.state()
            with patch.object(controller, '_boot', side_effect=boot), ThreadPoolExecutor(2) as pool:
                update = pool.submit(controller.update, 'v2')
                try:
                    self.assertTrue(entered.wait(5))
                    inspection = pool.submit(state)
                    self.assertTrue(started.wait(5))
                    self.assertFalse(inspection.done())
                finally:
                    release.set()
                self.assertEqual(update.result()['status'], 'UPDATED')
                self.assertEqual(inspection.result()['running_version'], 'v2')

    def test_historical_candidate_has_no_controller_activation_route(self):
        archive = Path('/home/zhang/Projects/SPHinX_AI_Assistant_artifacts/p5a3b_hosted_runner/'
                       'run_41617493805_attempt_1/ci-v2-research-41617493805-1.zip')
        result = promotion.evaluate(archive)
        self.assertEqual(result['final_eligibility'], 'BLOCKED')
        self.assertEqual(result['p8']['gate_mode'], 'BLOCKING_ONLY')
        self.assertIn('PRODUCTION_NOT_AUTHORIZED', str(result['blocking_reasons']))
        with lifecycle.Lifecycle() as controller:
            with self.assertRaises(ValueError):
                controller.start(str(archive))
            self.assertFalse(controller.state()['child_alive'])

    def test_cli_does_not_confuse_cleanup_with_successful_update(self):
        with patch.object(lifecycle, 'run_demo', return_value={'status': 'FAILED', 'temporary_store_removed': True}), \
                patch('sys.stdout', io.StringIO()) as output:
            self.assertEqual(lifecycle.main([]), 1)
        self.assertEqual(json.loads(output.getvalue())['status'], 'FAILED')


if __name__ == '__main__':
    unittest.main()
