"""Offline CLI contracts; no real downloads or registration authorization."""
from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_published_candidate_verification as fixtures
from scripts import register_trusted_baseline as cli
from src.corpus_snapshot import digest, file_digest


class RegistrationCLITests(unittest.TestCase):
    def setUp(self):
        f = self.f = fixtures.PublishedCandidateVerificationTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.addCleanup(f.tearDown)
        self.project = f.project
        self.registry = self.project / 'configs/ci_v2_schema2_trusted_baselines.json'
        self.registry.write_bytes(f.registry_bytes)
        policy = {'schema_version': 1, 'enabled': True,
            'repository': f.repo['full_name'], 'repository_id': f.repo['id'],
            'default_branch': 'main', 'workflow_path': '.github/workflows/approve.yml',
            'registry_path': 'configs/ci_v2_schema2_trusted_baselines.json',
            'allow_repository_owner': True, 'authorized_approver_ids': []}
        self.policy = fixtures.fixtures.put(self.project, 'configs/owner-policy.json', policy)
        self.request = {k: v for k, v in f.arguments.items() if k != 'token'}
        self.request.update(schema_version=1, registry_key='proposed-baseline', proposed_entry=f.entry,
            approval_policy_path='configs/owner-policy.json', approval_policy_sha256=file_digest(self.policy))
        self.path = f.root / 'request.json'
        self.write_request()
        self.isolation = f.root / 'isolated'
        self.isolation.mkdir()
        (self.isolation / 'registry.json').write_bytes(f.registry_bytes)
        self.env = patch.dict(os.environ, {'TRUSTED_RELEASE_TOKEN': 'offline-fixture-token',
            'GITHUB_ACTIONS': 'true', 'GITHUB_EVENT_NAME': 'workflow_dispatch'})
        self.env.start(); self.addCleanup(self.env.stop)
        p = patch.object(cli, 'PROJECT', self.project)
        p.start(); self.addCleanup(p.stop)
        self.real_registry = cli.transaction.PROJECT / 'configs/ci_v2_schema2_trusted_baselines.json'
        self.real_sha = file_digest(self.real_registry)

    def tearDown(self):
        self.assertEqual(self.registry.read_bytes(), self.f.registry_bytes)
        self.assertEqual(file_digest(self.real_registry), self.real_sha)

    def write_request(self, raw=None):
        raw = raw if raw is not None else (json.dumps(self.request, indent=2) + '\n').encode()
        self.path.write_bytes(raw)
        self.sha = hashlib.sha256(raw).hexdigest()

    def call(self, command='verify-subject', extra=None):
        args = [command]
        if command == 'recover':
            args += ['--isolation-directory', str(self.isolation), '--transaction-id', 'a' * 64]
        else:
            args += ['--request', str(self.path), '--request-sha256', self.sha]
            if command == 'register':
                args += ['--isolation-directory', str(self.isolation)]
        args += extra or []
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(args)
        self.assertEqual(err.getvalue(), '')
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        return code, json.loads(out.getvalue())

    def test_real_fixture_verification_and_deterministic_subject(self):
        code, one = self.call()
        self.assertEqual(code, 0, one)
        self.assertEqual(one['execution'], 'NO_FRESH_REPLAY')
        self.assertEqual(one['authorization'], 'NOT_VERIFIED')
        self.assertEqual(one['registration_subject_sha256'], digest(one['registration_subject']))
        self.write_request(json.dumps(self.request, sort_keys=True, separators=(',', ':')).encode())
        code, two = self.call()
        self.assertEqual(code, 0)
        self.assertEqual(one, two)
        self.assertEqual(one['production_promotion'], 'NOT_AUTHORIZED')

    def test_request_hash_is_raw_bytes_and_verified_before_backend(self):
        self.path.write_bytes(self.path.read_bytes() + b' ')
        with patch.object(cli.evidence, 'verify') as verify:
            code, result = self.call()
        self.assertEqual(code, 1)
        self.assertEqual(result['reason'], 'REQUEST_SHA256_MISMATCH')
        verify.assert_not_called()

    def test_request_is_opened_once_and_nonregular_files_are_rejected(self):
        original = cli.os.open
        calls = []
        def opened(path, *a, **kw):
            if Path(path) == self.path:
                calls.append(path)
            return original(path, *a, **kw)
        with patch.object(cli.os, 'open', side_effect=opened):
            request, _ = cli.load_request(self.path, self.sha)
        self.assertEqual(request, self.request)
        self.assertEqual(len(calls), 1)
        self.path.unlink()
        os.mkfifo(self.path)
        self.assertEqual(self.call()[0], 1)

    def test_missing_unknown_duplicate_malformed_or_wrong_types(self):
        original = deepcopy(self.request)
        cases = [b'{}', b'[]', b'not-json', b'{"schema_version":1,"schema_version":1}',
                 b'{"invalid":NaN}']
        for field in original:
            value = deepcopy(original); value.pop(field)
            cases.append(json.dumps(value).encode())
        for field in cli.PINS:
            value = deepcopy(original); value[field] = 'not-sha256'
            cases.append(json.dumps(value).encode())
        for key, val in [('schema_version', True), ('registry_key', '../unsafe'),
                         ('unexpected', True), ('proposed_entry', [])]:
            value = deepcopy(original); value[key] = val
            cases.append(json.dumps(value).encode())
        for raw in cases:
            self.write_request(raw)
            with self.subTest(raw=raw[:60]):
                code, result = self.call()
                self.assertEqual(code, 1)
                self.assertEqual(result['status'], 'BLOCKED')

    def test_nested_unknown_fields_and_unsafe_config_paths(self):
        for mutate in (
            lambda r: r['proposed_entry'].update(token='forbidden'),
            lambda r: r['proposed_entry']['reference'].update(unexpected=True),
            lambda r: r['proposed_entry']['reference']['authorization'].update(unexpected=True),
            lambda r: r['candidate_release']['assets']['candidate.tar.gz'].update(unexpected=True),
            lambda r: r.update(approval_policy_path='../outside.json'),
            lambda r: r['proposed_entry'].update(build_policy_path='/tmp/policy.json'),
            lambda r: r['proposed_entry']['reference']['storage'].update(token='forbidden'),
        ):
            value = deepcopy(self.request)
            mutate(value)
            self.write_request(json.dumps(value).encode())
            self.assertEqual(self.call()[0], 1)

    def test_ordinary_register_remains_blocked_without_patching_authorization(self):
        # Real register(), real _trusted_dispatch_context(), no simulation hook.
        before = (self.isolation / 'registry.json').read_bytes()
        code, result = self.call('register')
        self.assertEqual(code, 1)
        self.assertEqual(result['reason'], 'TRUSTED_WORKFLOW_EXECUTION_NOT_ESTABLISHED')
        self.assertFalse(result['registry_committed'])
        self.assertEqual((self.isolation / 'registry.json').read_bytes(), before)
        self.assertEqual(list(self.isolation.glob('*.prepared.json')), [])

    def test_unsafe_isolation_path_and_authoritative_alias_rejected(self):
        for path in (self.project / 'configs', self.registry):
            code, result = self.call('register', ['--isolation-directory', str(path)])
            self.assertEqual(code, 1, result)
        stored = self.isolation / 'registry.json'
        stored.unlink(); stored.symlink_to(self.registry)
        self.assertEqual(self.call('register')[0], 1)
        stored.unlink(); os.link(self.registry, stored)
        self.assertEqual(self.call('register')[0], 1)

    def test_request_symlink_policy_symlink_and_hash_errors(self):
        self.path.rename(self.path.with_suffix('.original'))
        self.path.symlink_to(self.path.with_suffix('.original'))
        self.assertEqual(self.call()[0], 1)
        self.path.unlink()
        self.write_request()
        self.policy.rename(self.policy.with_suffix('.original'))
        self.policy.symlink_to(self.policy.with_suffix('.original'))
        self.assertEqual(self.call()[0], 1)
        self.sha = 'bad'
        self.assertEqual(self.call()[0], 1)

    def test_missing_recovery_evidence_and_invalid_transaction_id(self):
        code, result = self.call('recover')
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(result['authorization'], 'NOT_GRANTED_BY_RECOVERY')
        self.assertEqual(self.call('recover', ['--transaction-id', '../escape'])[0], 1)

    def test_backend_results_map_to_exact_exit_codes(self):
        for status, expected in [('COMPLETED', 0), ('BLOCKED', 1), ('CONFLICT', 1),
                                 ('NOT_COMMITTED', 1), ('COMMITTED_WITH_ERROR', 2)]:
            with self.subTest(status=status), patch.object(cli.transaction, 'recover', return_value={
                    'status': status, 'registry_modified': False, 'production_promotion': 'NOT_AUTHORIZED'}):
                code, result = self.call('recover')
                self.assertEqual(code, expected)
                self.assertEqual(result['status'], status)

    def test_parser_failures_unknown_flags_and_help(self):
        for args in ([], ['register'], ['--project', '/tmp'], ['verify-subject', '--token', 'SECRET'],
                     ['register', '--approved'], ['register', '--simulate'], ['register', '--actor-id', '2']):
            out = io.StringIO()
            with redirect_stdout(out):
                code = cli.main(args)
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(out.getvalue())['reason'], 'INVALID_CLI_ARGUMENTS')
            self.assertNotIn('SECRET', out.getvalue())
        with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as caught:
            cli.main(['--help'])
        self.assertEqual(caught.exception.code, 0)

    def test_diagnostics_and_secret_errors_do_not_leak(self):
        def fail(*a, **kw):
            print('offline-fixture-token')
            print('https://example.test/signed?token=SECRET', file=sys.stderr)
            raise RuntimeError('offline-fixture-token')
        with patch.object(cli.transaction, 'recover', side_effect=fail):
            code, result = self.call('recover')
        self.assertEqual(code, 1)
        self.assertEqual(result['reason'], 'INVALID_INPUT_OR_OPERATION_FAILED')
        with patch.object(cli.transaction, 'recover', return_value={
                'status': 'BLOCKED', 'reason': 'https://example.test/?token=SECRET',
                'diagnostic': 'offline-fixture-token https://example.test/?token=SECRET'}):
            _, result = self.call('recover')
        self.assertEqual(result['reason'], 'OPERATION_FAILED')
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertNotIn('offline-fixture-token', json.dumps(result))

    def test_real_script_subprocess_fails_closed_with_spoofed_environment(self):
        # No dependency/authority patches cross this subprocess boundary.
        env = {**os.environ, 'GITHUB_ACTIONS': 'true', 'OWNER_APPROVED': 'true',
               'PYTHONDONTWRITEBYTECODE': '1'}
        script = Path(__file__).resolve().parents[1] / 'scripts/register_trusted_baseline.py'
        proc = subprocess.run([sys.executable, '-B', str(script), 'register',
            '--request', str(self.path), '--request-sha256', self.sha,
            '--isolation-directory', str(self.isolation)], env=env,
            capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['status'], 'BLOCKED')
        self.assertEqual(proc.stderr, '')


class RecoveryCLIIntegrationTests(unittest.TestCase):
    def setUp(self):
        import test_baseline_registration_transaction as tx_fixtures
        self.f = tx_fixtures.RegistrationTransactionTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.addCleanup(self.f.tearDown)
        self.project_patch = patch.object(cli, 'PROJECT', self.f.fixture.project)
        self.project_patch.start()
        self.addCleanup(self.project_patch.stop)

    def recover(self, transaction_id):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cli.main(['recover', '--isolation-directory', str(self.f.isolation),
                             '--transaction-id', transaction_id])
        return code, json.loads(out.getvalue())

    def test_actual_committed_audit_recovery_repeat_and_conflict(self):
        with patch.object(cli.transaction, '_complete', side_effect=OSError('test audit interruption')):
            result = self.f.run_registration()
        self.assertEqual(result['status'], 'COMMITTED_WITH_ERROR')
        tid = result['transaction_id']
        before = self.f.copy.read_bytes()
        code, one = self.recover(tid)
        self.assertEqual(code, 0, one)
        self.assertEqual(one['status'], 'COMPLETED')
        self.assertEqual(one['authorization'], 'NOT_GRANTED_BY_RECOVERY')
        self.assertEqual(self.recover(tid), (code, one))
        self.assertEqual(self.f.copy.read_bytes(), before)
        self.f.copy.write_bytes(before + b' ')
        code, result = self.recover(tid)
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'CONFLICT')
        self.assertEqual(self.f.copy.read_bytes(), before + b' ')

    def test_actual_not_committed_recovery_does_not_register(self):
        with patch.object(cli.transaction.os, 'replace', side_effect=OSError('test before commit')):
            result = self.f.run_registration()
        self.assertEqual(result['status'], 'BLOCKED')
        before = self.f.copy.read_bytes()
        code, result = self.recover(result['transaction_id'])
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'NOT_COMMITTED')
        self.assertEqual(self.f.copy.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
