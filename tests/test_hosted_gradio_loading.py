"""Hosted consumer orchestration fixtures; no claim of Hosted/scientific execution."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import errno
from contextlib import ExitStack
from unittest.mock import patch

from scripts import check_hosted_gradio_loading as consumer


class HostedGradioLoadingTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.project = self.root / 'project'
        (self.project / 'configs').mkdir(parents=True)
        self.registry = self.project / 'configs/ci_v2_schema2_trusted_baselines.json'
        self.registry.write_bytes(b'fixture')
        self.output = self.root / 'output'
        self.python = self.root / 'python'
        self.python.touch()
        self.ref = {'storage': {'asset_id': 1, 'asset_size': 4},
                    'parent_rows_storage': {'asset_id': 2, 'asset_size': 4},
                    'transport_sha256': hashlib.sha256(b'data').hexdigest(),
                    'parent_rows_sha256': hashlib.sha256(b'data').hexdigest(),
                    'notices': {'storage': {'asset_id': 3, 'asset_size': 4},
                                'sha256': hashlib.sha256(b'data').hexdigest()}}
        self.work = None
        self.patches = [patch.object(consumer, 'reference', return_value=(self.registry, self.ref)),
                        patch.object(consumer, 'REGISTRY_SHA', consumer.file_digest(self.registry)),
                        patch.object(consumer.c, 'frozen_runtime', return_value={'fixture': True}),
                        patch.object(consumer.trust, 'download', side_effect=self.download),
                        patch.object(consumer.trust, 'verify_notices', return_value={'status': 'NOTICES_VERIFIED'}),
                        patch.object(consumer.trust, 'restore', return_value={
                            'node_id': consumer.BASELINE, 'approval': 'P4_1_VERIFIED'}),
                        patch.object(consumer, 'qualify_parent_anchor', return_value={
                            'status': 'QUALIFIED', 'execution': 'NO_FRESH_REPLAY'}),
                        patch.object(consumer, 'application_check', return_value=self.loaded())]
        self.mocks = [p.start() for p in self.patches]
        for p in self.patches:
            self.addCleanup(p.stop)

    def loaded(self):
        return {'status': 'RESEARCH_GRADIO_LOADING_VERIFIED', 'scope': 'RESEARCH_LOADING_ONLY',
                'isolation': {'fixture': True},
                'application_running': False, 'identity': {'restrictions': ['P8_BLOCKED']},
                'application': {'sha256': consumer.CORPUS, 'records': 11637,
                                'complete_records_equal': True, 'callbacks_share_assistant': True,
                                'application_closed': True, 'retrieval': [{
                                    'query': consumer.QUERY, 'results': [{'chunk_id': consumer.EXPECTED_CHUNK}]}]}}

    def download(self, locator, path, pin, **kwargs):
        self.work = path.parent
        path.write_bytes(b'data')

    def consume(self):
        return consumer.consume(self.project, self.output, self.python)

    def test_valid_pinned_set_restored_with_notices_and_cleaned(self):
        result = self.consume()
        self.assertEqual(result['status'], 'IMMUTABLE_RESEARCH_ARTIFACT_GRADIO_VERIFIED')
        self.assertEqual(self.mocks[3].call_count, 3)
        self.assertIn('notices_path', self.mocks[5].call_args.kwargs)
        self.assertFalse(self.mocks[6].call_args.kwargs['fresh_replay'])
        self.assertFalse(self.work.exists())
        self.assertTrue((self.output / 'verification.json').is_file())

    def test_missing_asset_stops_before_parent_use(self):
        self.mocks[3].side_effect = FileNotFoundError('fixture')
        with self.assertRaises(FileNotFoundError):
            self.consume()
        self.mocks[5].assert_not_called()

    def test_corrupt_asset_or_digest_mismatch_stops_before_restore(self):
        self.mocks[3].side_effect = lambda loc, path, pin, **kw: path.write_bytes(b'bad!')
        with self.assertRaisesRegex(ValueError, 'DOWNLOADED_BYTES_MISMATCH'):
            self.consume()
        self.mocks[5].assert_not_called()
        self.assertFalse(self.output.exists())

    def test_wrong_size_even_with_matching_digest_rejected(self):
        self.ref['storage']['asset_size'] = 5
        with self.assertRaisesRegex(ValueError, 'DOWNLOADED_BYTES_MISMATCH'):
            self.consume()

    def test_missing_corrupt_or_wrong_subject_notices_rejected_before_restore(self):
        for reason in ('MISSING_NOTICES', 'CORRUPT_ZIP', 'WRONG_SUBJECT'):
            with self.subTest(reason=reason):
                self.mocks[4].side_effect = ValueError(reason)
                with self.assertRaisesRegex(ValueError, reason):
                    self.consume()
                self.mocks[5].assert_not_called()
                self.mocks[7].assert_not_called()
                self.assertFalse(self.work.exists())

    def test_unapproved_package_rejected(self):
        self.mocks[5].return_value['approval'] = 'PENDING'
        with self.assertRaisesRegex(ValueError, 'APPROVED_PACKAGE_REQUIRED'):
            self.consume()
        self.mocks[7].assert_not_called()

    def test_nonqualified_sealed_anchor_rejected_without_replay(self):
        self.mocks[6].return_value['status'] = 'UNQUALIFIED'
        with self.assertRaisesRegex(ValueError, 'SEALED_R2_BINDING_REQUIRED'):
            self.consume()
        self.mocks[7].assert_not_called()

    def test_wrong_corpus_identity_or_incomplete_loading_rejected(self):
        for field, value in [('sha256', '0' * 64), ('records', 1),
                             ('complete_records_equal', False), ('application_closed', False)]:
            with self.subTest(field=field):
                self.mocks[7].return_value = self.loaded()
                self.mocks[7].return_value['application'][field] = value
                with self.assertRaisesRegex(ValueError, 'APPLICATION_RESULT_MISMATCH'):
                    self.consume()
                self.assertFalse(self.work.exists())

    def test_genuine_expected_bm25_chunk_required(self):
        self.mocks[7].return_value['application']['retrieval'][0]['results'][0]['chunk_id'] = 'wrong'
        with self.assertRaisesRegex(ValueError, 'APPLICATION_RESULT_MISMATCH'):
            self.consume()

    def test_application_failure_cleans_package(self):
        self.mocks[7].side_effect = RuntimeError('fixture app failed')
        with self.assertRaises(RuntimeError):
            self.consume()
        self.assertFalse(self.work.exists())
        self.assertFalse(self.output.exists())

    def test_frozen_runtime_failure_prevents_all_downloads(self):
        self.mocks[2].side_effect = ValueError('FROZEN_RUNTIME_MISMATCH')
        with self.assertRaisesRegex(ValueError, 'FROZEN_RUNTIME_MISMATCH'):
            self.consume()
        self.mocks[3].assert_not_called()

    def test_independently_pinned_registry_cannot_be_substituted(self):
        self.patches[0].stop()
        self.registry.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'REGISTRY_PIN_MISMATCH'):
            consumer.reference(self.project)

    def test_untrusted_cli_context_emits_only_sanitized_failure(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(consumer.sys, 'argv', [
                'check', '--output', str(self.output), '--app-python', str(self.python)]):
            with patch('builtins.print'):
                self.assertEqual(consumer.main(), 1)
        result = json.loads((self.output / 'verification.json').read_text())
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(set(result), {'status', 'reason', 'production_promotion'})
        self.mocks[3].assert_not_called()

    def test_existing_or_project_local_output_denied(self):
        for output in (self.root, self.project / 'new-output'):
            with self.subTest(output=str(output)), self.assertRaisesRegex(ValueError, 'NEW_EXTERNAL_OUTPUT_REQUIRED'):
                consumer.consume(self.project, output, self.python)
        self.mocks[3].assert_not_called()

    def test_app_subprocess_has_os_isolation_and_no_credentials(self):
        self.patches[-1].stop()
        review = consumer.ReviewedCorpus(self.registry, 'a'*64, 'key', 'candidate', 'baseline', 'b'*64, 1, 1)
        with patch.dict(os.environ, {'TRUSTED_RELEASE_TOKEN': 'synthetic', 'OPENAI_API_KEY': 'synthetic',
                                    'GH_TOKEN': 'synthetic', 'HTTPS_PROXY': 'synthetic',
                                    'LD_PRELOAD': 'synthetic', 'PYTHONPATH': 'synthetic',
                                    'SUDO_COMMAND': 'synthetic'}):
            with patch.object(consumer.subprocess, 'run') as run:
                run.return_value.returncode, run.return_value.stdout = 0, '{}'
                consumer.application_check(self.project, self.python, self.root, review, self.root, self.root/'notices')
                args, kwargs = run.call_args
        command = args[0]
        self.assertEqual(command[:7], ['/usr/bin/sudo', '-n', '--', '/usr/bin/env', '-i',
                                       '/usr/bin/unshare', '--net'])
        self.assertNotIn('-E', command)
        self.assertNotIn('--user', command)
        for option in ('--clear-groups', '--inh-caps=-all', '--ambient-caps=-all',
                       '--bounding-set=-all', '--no-new-privs'):
            self.assertIn(option, command)
        self.assertLess(command.index('/usr/bin/setpriv'), command.index(str(self.python)))
        self.assertEqual(command.count('-i'), 2)
        for argument in command:
            self.assertNotIn('synthetic', argument)
        inline = command[command.index('-c') + 1]
        self.assertLess(inline.index('isolation = verify_isolation'),
                        inline.index('from src.research_corpus_selection import'))
        for key in ('TRUSTED_RELEASE_TOKEN', 'OPENAI_API_KEY', 'GH_TOKEN', 'HTTPS_PROXY', 'GITHUB_TOKEN',
                    'LD_PRELOAD', 'PYTHONPATH', 'SUDO_COMMAND'):
            self.assertNotIn(key, kwargs['env'])
        self.assertEqual(kwargs['timeout'], 120)
        self.assertEqual(kwargs['env']['GRADIO_ANALYTICS_ENABLED'], 'False')

    def test_namespace_or_setpriv_failure_blocks_application(self):
        self.patches[-1].stop()
        for failure in ('unshare denied', 'setpriv denied'):
            with self.subTest(failure=failure), patch.object(consumer.subprocess, 'run') as run:
                run.return_value.returncode = 1
                run.return_value.stdout = ''
                run.return_value.stderr = failure
                with self.assertRaisesRegex(ValueError, 'ISOLATED_APPLICATION_FAILED'):
                    consumer.isolated_python(self.python, self.root, 'raise AssertionError("not reached")')

    def test_root_caller_cannot_start_launcher(self):
        with patch.object(consumer.os, 'getuid', return_value=0), patch.object(consumer.subprocess, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'NONROOT_CALLER_REQUIRED'):
                consumer.isolated_python(self.python, self.root, 'print("not reached")')
            run.assert_not_called()

    def test_workflow_preflight_uses_same_launcher_and_cleans_workspace(self):
        env = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': consumer.REPOSITORY,
               'GITHUB_REPOSITORY_ID': '1455203884', 'GITHUB_ACTOR_ID': '239840087',
               'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/ci-upstream-refresh',
               'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'a'*40, 'GITHUB_WORKFLOW_SHA': 'a'*40}
        with patch.dict(os.environ, env), patch.object(consumer.sys, 'argv', [
                'check', '--isolation-preflight', '--output', str(self.output), '--app-python', str(self.python)]):
            with patch.object(consumer.subprocess, 'check_output', return_value='a'*40+'\n'):
                with patch.object(consumer, 'isolated_python', return_value={'fixture': True}) as launcher:
                    with patch('builtins.print'):
                        self.assertEqual(consumer.main(), 0)
        self.assertFalse(launcher.call_args.args[1].exists())
        self.assertFalse(self.output.exists())
        self.mocks[3].assert_not_called()
        self.mocks[7].assert_not_called()

    def guard(self, *, uid=(1000, 1000, 1000), gid=(1000, 1000, 1000), groups=(),
              caps='0000000000000000', nnp='1', namespace='new', interfaces=('lo',),
              connection_errno=errno.ENETUNREACH):
        scope = {}
        exec(consumer.ISOLATION_GUARD.rsplit('\nisolation = ', 1)[0], scope)
        status = '\n'.join(k + ': ' + caps for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'))
        status += '\nNoNewPrivs: ' + nnp
        with ExitStack() as stack:
            for name, value in [('getresuid', uid), ('getresgid', gid), ('getgroups', list(groups)),
                                ('readlink', namespace)]:
                stack.enter_context(patch.object(scope['os'], name, return_value=value))
            stack.enter_context(patch.object(Path, 'read_text', return_value=status))
            stack.enter_context(patch.object(scope['socket'], 'if_nameindex',
                                            return_value=list(enumerate(interfaces))))
            probe = stack.enter_context(patch.object(scope['socket'], 'socket'))
            if connection_errno is not None:
                probe.return_value.__enter__.return_value.connect.side_effect = OSError(connection_errno, 'fixture')
            return scope['verify_isolation'](1000, 1000, 'old')

    def test_successful_isolation_guard_fixture(self):
        receipt = self.guard()
        self.assertEqual(receipt['external_route_probe'], 'ENETUNREACH')
        self.assertEqual(receipt['capabilities'], 'ALL_ZERO')

    def test_root_saved_identity_or_supplementary_group_rejected(self):
        for change in ({'uid': (1000, 0, 0)}, {'gid': (1000, 1000, 0)}, {'groups': (27,)}):
            with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, 'PRIVILEGE_DROP_NOT_VERIFIED'):
                self.guard(**change)

    def test_retained_capabilities_or_privilege_regain_rejected(self):
        for change in ({'caps': '0000000000000001'}, {'nnp': '0'}):
            with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, 'CAPABILITY_DROP_NOT_VERIFIED'):
                self.guard(**change)

    def test_same_namespace_or_external_interface_rejected(self):
        for change in ({'namespace': 'old'}, {'interfaces': ('lo', 'eth0')}):
            with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, 'NETWORK_NAMESPACE_NOT_VERIFIED'):
                self.guard(**change)

    def test_external_route_or_unexpected_denial_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'EXTERNAL_ROUTE_AVAILABLE'):
            self.guard(connection_errno=None)
        with self.assertRaisesRegex(RuntimeError, 'NETWORK_DENIAL_NOT_VERIFIED'):
            self.guard(connection_errno=errno.EPERM)

    def test_workflow_is_manual_read_only_and_never_launches_http(self):
        workflow = (consumer.PROJECT / '.github/workflows/ci_v2_gradio_loading.yml').read_text()
        self.assertIn('workflow_dispatch:', workflow)
        self.assertIn('contents: read', workflow)
        self.assertIn('ref: ${{ github.sha }}', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('--only-binary=:all:', workflow)
        self.assertIn('scripts/check_hosted_gradio_loading.py --isolation-preflight', workflow)
        self.assertNotIn('--map-root-user', workflow)
        for forbidden in ('pull_request_target:', 'schedule:', 'contents: write', 'secrets.',
                          'environment:', 'PARENT_AUTHORITY_AUDIT_TOKEN', 'build_app().launch'):
            self.assertNotIn(forbidden, workflow)


if __name__ == '__main__':
    unittest.main()
