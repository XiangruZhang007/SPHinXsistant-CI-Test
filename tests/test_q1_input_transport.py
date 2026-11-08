"""Isolated Q1 transport and workflow wiring; no remote or corpus execution."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import prepare_q1_inputs as prep
from src import trusted_snapshot as trust, ci_v2_research as c
from src.corpus_snapshot import file_digest, read_json, write_json

P = Path(__file__).resolve().parents[1]


class Q1TransportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='q1 transport ')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.project = self.root / 'project'
        self.runner = self.root / 'runner-temp'
        (self.project / 'configs').mkdir(parents=True)
        (self.runner / 'p5a').mkdir(parents=True)
        self.relative = 'configs/q1.json'
        self.config_path = self.project / self.relative
        self.manifest = b'{"kind":"CONTROLLED_TRANSPORT_FIXTURE"}\n'
        self.archive = self.root / 'fixture.tar.gz'
        self.make_archive([('inputs/inputs.json', self.manifest, 0o644),
                           ('inputs/target/example.py', b'# fixture\n', 0o755)])
        self.config = {'storage': {'kind': 'GITHUB_RELEASE_ASSET', 'repository': trust.RELEASE_REPOSITORY,
            'release_id': 123, 'asset_id': 456, 'tag': 'controlled-q1-transport',
            'asset_name': 'q1-inputs.tar.gz', 'immutable_required': True},
            'transport_sha256': file_digest(self.archive),
            'inputs_sha256': c.hashlib.sha256(self.manifest).hexdigest()}
        self.config_path.write_text(json.dumps(self.config))
        self.git = self.enterContext(patch.object(prep.subprocess, 'check_output',
            side_effect=lambda *args, **kwargs: self.config_path.read_bytes()))
        # Exercise the real existing downloader, replacing only its network boundary.
        self.requests = self.enterContext(patch.object(trust, '_request', side_effect=self.request))
        self.release_immutable = True
        self.asset_digest = True

    def make_archive(self, members, kind=tarfile.REGTYPE):
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, raw, mode in members:
                info = tarfile.TarInfo(name)
                info.mode = mode
                info.type = kind
                info.size = len(raw)
                if kind == tarfile.SYMTYPE:
                    info.linkname = '../outside'
                archive.addfile(info, io.BytesIO(raw))

    def request(self, url, *, binary=False):
        if binary:
            return io.BytesIO(self.archive.read_bytes())
        if url.endswith('/releases/123'):
            value = {'id': 123, 'immutable': self.release_immutable, 'draft': False,
                     'tag_name': 'controlled-q1-transport',
                     'assets': [{'id': 456, 'name': 'q1-inputs.tar.gz'}]}
        else:
            self.assertTrue(url.endswith('/releases/assets/456'))
            value = {'id': 456, 'name': 'q1-inputs.tar.gz', 'state': 'uploaded',
                     'size': self.archive.stat().st_size}
            if self.asset_digest:
                value['digest'] = 'sha256:' + file_digest(self.archive)
        return io.BytesIO(json.dumps(value).encode())

    def prepare(self):
        self.config_path.write_text(json.dumps(self.config))
        return prep.prepare(self.project, self.relative, self.runner)

    def assert_no_staging(self):
        self.assertEqual(list(self.runner.glob('ci-v2-q1-*')), [])

    def test_valid_transport_uses_existing_utilities_and_preserves_executable_bit(self):
        result = self.prepare()
        self.assertEqual(result['status'], 'Q1_INPUTS_RESTORED')
        manifest = Path(result['inputs_path'])
        self.assertEqual(manifest.read_bytes(), self.manifest)
        self.assertTrue(manifest.is_relative_to(self.runner))
        self.assertEqual((manifest.parent / 'target/example.py').stat().st_mode & 0o111, 0o111)
        self.assertTrue(result['diagnostic_only'])
        self.assertFalse(result['automatic_research_approval'])
        self.assertEqual(result['production_promotion'], 'NOT_AUTHORIZED')
        self.assertNotIn('authorization', result)
        self.git.assert_called_once_with(['git', '--no-optional-locks', 'show', 'HEAD:' + self.relative],
                                         cwd=self.project)

    def test_each_missing_configuration_field_rejected_before_download(self):
        complete = dict(self.config)
        for field in complete:
            with self.subTest(field=field):
                self.config = {k: v for k, v in complete.items() if k != field}
                with self.assertRaises(ValueError):
                    self.prepare()
                self.requests.assert_not_called()
                self.assert_no_staging()

    def test_malformed_checksum_rejected_before_download(self):
        for field in ('transport_sha256', 'inputs_sha256'):
            correct = self.config[field]
            for value in ('', 'a' * 63, 'A' * 64, None):
                with self.subTest(field=field, value=value):
                    self.config[field] = value
                    with self.assertRaises(ValueError):
                        self.prepare()
                    self.requests.assert_not_called()
                    self.assert_no_staging()
            self.config[field] = correct

    def test_missing_locator_fields_and_foreign_repository_rejected_before_download(self):
        complete = dict(self.config['storage'])
        cases = [{k: v for k, v in complete.items() if k != field} for field in complete]
        cases += [{**complete, 'repository': 'untrusted/repository'}, {**complete, 'immutable_required': False}]
        for storage in cases:
            with self.subTest(storage=storage):
                self.config['storage'] = storage
                with self.assertRaises(ValueError):
                    self.prepare()
                self.requests.assert_not_called()
                self.assert_no_staging()

    def test_uncommitted_or_changed_config_cannot_supply_trusted_pins(self):
        for outcome in (b'{}', subprocess.CalledProcessError(128, 'git show')):
            with self.subTest(outcome=type(outcome).__name__), \
                    patch.object(prep.subprocess, 'check_output', side_effect=outcome if isinstance(outcome, Exception) else None,
                                 return_value=outcome), self.assertRaises((ValueError, subprocess.CalledProcessError)):
                self.prepare()
            self.requests.assert_not_called()
            self.assert_no_staging()

    def test_unsafe_config_path_rejected_before_git_or_download(self):
        for relative in ('/tmp/q1.json', '../configs/q1.json', 'configs/../configs/q1.json'):
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                prep.prepare(self.project, relative, self.runner)
        self.git.assert_not_called()
        self.requests.assert_not_called()

    def test_wrong_transport_checksum_rejected_and_owned_staging_removed(self):
        self.config['transport_sha256'] = '0' * 64
        self.asset_digest = False  # Exercise downloaded-byte verification, not only metadata.
        with self.assertRaises(c.GateError) as caught:
            self.prepare()
        self.assertEqual(caught.exception.status, 'CORRUPT_DOWNLOAD')
        self.assertTrue(any(call.kwargs.get('binary') for call in self.requests.call_args_list))
        self.assert_no_staging()

    def test_wrong_manifest_checksum_rejected_and_owned_staging_removed(self):
        self.config['inputs_sha256'] = '0' * 64
        with self.assertRaises(c.GateError) as caught:
            self.prepare()
        self.assertEqual(caught.exception.status, 'Q1_MANIFEST_MISMATCH')
        self.assert_no_staging()

    def test_mutable_release_rejected_by_existing_downloader(self):
        self.release_immutable = False
        with self.assertRaises(c.GateError) as caught:
            self.prepare()
        self.assertEqual(caught.exception.status, 'INVALID_REFERENCE')
        self.assert_no_staging()

    def test_unsafe_archive_members_rejected_without_writing_outside_stage(self):
        for name, kind in [('../outside', tarfile.REGTYPE), ('/outside', tarfile.REGTYPE),
                           ('inputs/link', tarfile.SYMTYPE)]:
            with self.subTest(name=name):
                self.make_archive([(name, b'', 0o644)], kind)
                self.config['transport_sha256'] = file_digest(self.archive)
                with self.assertRaises(c.GateError) as caught:
                    self.prepare()
                self.assertEqual(caught.exception.status, 'UNSAFE_ARCHIVE')
                self.assert_no_staging()
                self.assertFalse((self.runner / 'outside').exists())

    def test_project_directory_cannot_be_used_as_runner_temp(self):
        with self.assertRaises(c.GateError):
            prep.prepare(self.project, self.relative, self.project)
        self.requests.assert_not_called()

    def test_cli_records_failure_without_granting_authorization(self):
        self.config.pop('inputs_sha256')
        self.config_path.write_text(json.dumps(self.config))
        output = self.runner / 'p5a/q1-transport.json'
        with patch.object(prep, 'P', self.project), redirect_stdout(io.StringIO()) as stdout:
            code = prep.main(['--config', self.relative, '--runner-temp', str(self.runner), '--output', str(output)])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stdout.getvalue()), read_json(output))
        self.assertEqual(read_json(output)['status'], 'INVALID_Q1_CONFIGURATION')
        self.assertEqual(read_json(output)['production_promotion'], 'NOT_AUTHORIZED')
        self.requests.assert_not_called()

    def test_cli_success_writes_the_receipt_consumed_by_the_workflow(self):
        output = self.runner / 'p5a/q1-transport.json'
        with patch.object(prep, 'P', self.project), redirect_stdout(io.StringIO()) as stdout:
            code = prep.main(['--config', self.relative, '--runner-temp', str(self.runner), '--output', str(output)])
        self.assertEqual(code, 0)
        result = read_json(output)
        self.assertEqual(result, json.loads(stdout.getvalue()))
        self.assertEqual(Path(result['inputs_path']).read_bytes(), self.manifest)
        self.assertEqual(result['inputs_sha256'], self.config['inputs_sha256'])
        self.assertEqual(result['status'], 'Q1_INPUTS_RESTORED')

    def test_cli_preserves_existing_or_external_receipt_paths(self):
        for output in (self.runner / 'existing.json', self.project / 'protected.json'):
            output.write_text('preserve')
            with self.subTest(output=output), patch.object(prep, 'P', self.project), redirect_stdout(io.StringIO()):
                self.assertEqual(prep.main(['--config', self.relative, '--runner-temp', str(self.runner),
                                           '--output', str(output)]), 2)
            self.assertEqual(output.read_text(), 'preserve')
        self.requests.assert_not_called()


class Q1WorkflowWiringTests(unittest.TestCase):
    def setUp(self):
        import yaml
        self.workflow = yaml.safe_load((P / '.github/workflows/ci_v2_manual_research.yml').read_text())
        self.steps = self.workflow['jobs']['candidate']['steps']
        self.execute = next(s['run'] for s in self.steps if s['name'] == 'Restore, build and evaluate research candidate')
        temporary = tempfile.TemporaryDirectory(prefix='q1 workflow ')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.runner = self.root / 'runner'
        (self.runner / 'p5a').mkdir(parents=True)
        (self.root / 'scripts').mkdir()
        (self.root / 'scripts/ci_v2_schema2_research.py').write_text(
            'import json,os,sys\nfrom pathlib import Path\n'
            'Path(os.environ["CAPTURE_ARGS"]).write_text(json.dumps(sys.argv[1:]))\n'
            'sys.exit(int(os.environ["STUB_EXIT"]))\n')
        for relative in ('bin/python', 'tools/treesitter-chunker/.venv/bin/python'):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(sys.executable)

    def run_step(self, configured=False, exit_code=0):
        # Limited environment: no inherited remote credentials or production settings.
        environment = {'PATH': str(self.root / 'bin') + os.pathsep + os.defpath,
            'RUNNER_TEMP': str(self.runner), 'Q1_TRANSPORT_CONFIG': 'configs/q1.json' if configured else '',
            'CAPTURE_ARGS': str(self.root / 'argv.json'), 'STUB_EXIT': str(exit_code),
            'PYTHONDONTWRITEBYTECODE': '1'}
        process = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', self.execute], cwd=self.root,
                                 env=environment, capture_output=True, text=True)
        return process, read_json(self.root / 'argv.json')

    def test_unconfigured_workflow_skips_transport_and_passes_no_q1_arguments(self):
        on = self.workflow.get('on', self.workflow.get(True))
        self.assertFalse(on['workflow_dispatch']['inputs']['q1_transport_config']['required'])
        self.assertEqual(on['workflow_dispatch']['inputs']['q1_transport_config']['default'], '')
        restore = next(s for s in self.steps if s['name'] == 'Restore optional pinned Q1 diagnostic inputs')
        self.assertEqual(restore['if'], "env.Q1_TRANSPORT_CONFIG != ''")
        self.assertNotIn('continue-on-error', restore)
        process, arguments = self.run_step()
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(arguments, ['execute-plan', '--plan', str(self.runner / 'p5a/plan.json'),
                                    '--work', str(self.runner / 'p5a-work'), '--output', str(self.runner / 'p5a/run')])
        self.assertFalse((self.runner / 'p5a/q1-transport.json').exists())

    def test_configured_workflow_passes_both_pins_with_quoted_paths(self):
        manifest = self.runner / 'isolated payload/inputs/inputs.json'
        sha = 'a' * 64
        write_json(self.runner / 'p5a/q1-transport.json', {'inputs_path': str(manifest), 'inputs_sha256': sha})
        process, arguments = self.run_step(configured=True)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(arguments[-4:], ['--q1-inputs', str(manifest), '--q1-inputs-sha256', sha])

    def test_mandatory_execute_plan_failures_remain_failures_with_or_without_q1(self):
        write_json(self.runner / 'p5a/q1-transport.json', {'inputs_path': str(self.runner / 'inputs.json'),
                                                        'inputs_sha256': 'a' * 64})
        for configured in (False, True):
            with self.subTest(configured=configured):
                process, _ = self.run_step(configured=configured, exit_code=2)
                self.assertEqual(process.returncode, 2)


if __name__ == '__main__':
    unittest.main()
