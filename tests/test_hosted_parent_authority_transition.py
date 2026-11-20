"""SYNTHETIC_TRUSTED_INVOCATION_TEST; never genuine Hosted Owner evidence."""
from contextlib import ExitStack
from copy import deepcopy
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import Mock, patch

import test_parent_authority_transition as fixtures
from src import hosted_parent_authority_transition as hosted
from src import owner_manual_baseline_approval as owner
from src import parent_authority_transition as transition
from src.corpus_snapshot import digest

P = Path(__file__).resolve().parents[1]


class InvocationTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.TransitionTests(); self.f.setUp(); self.addCleanup(self.f.doCleanups)
        f = self.f; self.root = f.root
        f.owner['workflow_path'] = hosted.WORKFLOW
        f.save('configs/owner.json', f.owner)
        f.request.update(workflow_path=hosted.WORKFLOW, owner_policy_sha256=f.pin('configs/owner.json'))
        self.proposal = f.prepare()
        self.config = {'schema_version': 1, 'operation': transition.OPERATION,
            'request': deepcopy(f.request), 'proposal_sha256': digest(self.proposal),
            'subject_sha256': digest(hosted.subject(f.request, digest(self.proposal), 103)),
            'workflow_id': 103, 'transaction_backend': 'UNCONFIGURED',
            'implementation_contract_sha256': '0' * 64}
        self.inputs = {'operation': transition.OPERATION,
            'decision': 'APPROVE_RESTRICTED_BUILD_AUTHORITY_TRANSITION',
            'request_sha256': digest(f.request), 'proposal_sha256': digest(self.proposal),
            'transition_subject_sha256': self.config['subject_sha256'],
            'transaction_id': f.request['transaction_id']}
        self.event = self.root / 'event.json'; self.event.write_text(json.dumps({'inputs': self.inputs}))
        r = f.request; self.prefix = 'repos/' + r['repository']
        self.repo = {'id': 42, 'full_name': r['repository'], 'private': True,
            'default_branch': r['default_branch'], 'owner': {'id': 101, 'type': 'User'}}
        self.run = {'id': 102, 'event': 'workflow_dispatch', 'status': 'in_progress',
            'run_attempt': 1, 'head_branch': r['default_branch'], 'head_sha': r['implementation_revision'],
            'repository': {'id': 42, 'full_name': r['repository']},
            'actor': {'id': 101, 'type': 'User', 'login': 'FixtureOwner'},
            'triggering_actor': {'id': 101, 'type': 'User', 'login': 'FixtureOwner'},
            'workflow_id': 103, 'created_at': '2026-11-20T00:00:00Z'}
        self.workflow = {'id': 103, 'path': hosted.WORKFLOW}
        raw = (self.root / r['registry_path']).read_bytes()
        self.remote = {'path': r['registry_path'], 'type': 'file', 'encoding': 'base64',
                       'content': base64.b64encode(raw).decode()}
        self.branch = {'ref': 'refs/heads/' + r['default_branch'],
                       'object': {'sha': r['implementation_revision']}}
        self.responses = {self.prefix: self.repo, self.prefix + '/actions/runs/102': self.run,
            self.prefix + '/actions/workflows/103': self.workflow,
            self.prefix + '/git/ref/heads/' + r['default_branch']: self.branch,
            self.prefix + '/contents/' + r['registry_path'] + '?ref=' + r['implementation_revision']: self.remote}
        self.env = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_ARCH': 'ARM64',
            'GITHUB_WORKSPACE': str(self.root), 'GITHUB_REPOSITORY': r['repository'],
            'GITHUB_REPOSITORY_ID': '42', 'GITHUB_SHA': r['implementation_revision'],
            'GITHUB_REF': 'refs/heads/' + r['default_branch'],
            'GITHUB_WORKFLOW_SHA': r['implementation_revision'],
            'GITHUB_WORKFLOW_REF': r['repository'] + '/' + hosted.WORKFLOW + '@refs/heads/' + r['default_branch'],
            'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_EVENT_PATH': str(self.event),
            'GITHUB_RUN_ID': '102', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_ACTOR_ID': '101'}

    def boundaries(self):
        s = ExitStack(); s.enter_context(patch.dict(os.environ, self.env))
        s.enter_context(patch.object(hosted, '_checkout'))
        s.enter_context(patch.object(hosted, 'frozen_runtime'))
        s.enter_context(patch.object(hosted, '_notice_path', return_value=self.f.fixture.path))
        client = Mock(); client.json.side_effect = lambda ep: deepcopy(self.responses[ep])
        s.enter_context(patch.object(owner, 'GitHubCLI', return_value=client))
        return s

    def observe(self):
        with self.boundaries(): return hosted._observe(self.root, self.config)

    def deploy_env(self):
        raw = json.dumps(self.config)
        return {'PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_JSON': raw,
                'PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_SHA256': hashlib.sha256(raw.encode()).hexdigest()}

    def test_synthetic_owner_observation_binds_operation_without_granting_permission(self):
        result = self.observe()
        self.assertEqual(result['status'], 'API_OWNER_TRANSITION_SUBJECT_VERIFIED')
        self.assertEqual(result['proposal'], self.proposal)
        self.assertEqual(result['authorization'], 'NOT_GRANTED')
        self.assertFalse(result['durable_transaction_reserved'])

    def test_public_run_absent_deployment_remains_blocked(self):
        with patch.dict(os.environ, {'PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_JSON': ''}):
            self.assertEqual(hosted.run()['reason'], 'TRANSITION_DEPLOYMENT_NOT_CONFIGURED')

    def test_even_valid_owner_is_blocked_without_durable_backend(self):
        with self.boundaries(), patch.dict(os.environ, self.deploy_env()):
            result = hosted._run(self.root)
        self.assertEqual(result['reason'], 'DURABLE_CROSS_RUN_TRANSACTION_BACKEND_NOT_CONFIGURED')
        self.assertFalse(result['registry_committed'])
        self.assertEqual(result['authorization'], 'NOT_GRANTED')

    def test_unreviewed_backend_or_wrong_deployment_subject_cannot_enable_live_apply(self):
        for field, value in [('transaction_backend', 'LOCAL_FILE_IS_DURABLE'),
                             ('subject_sha256', '0' * 64), ('operation', 'TRUSTED_RESEARCH_PARENT_REGISTRATION')]:
            saved = deepcopy(self.config); self.config[field] = value
            with self.subTest(field=field), patch.dict(os.environ, self.deploy_env()), self.assertRaises(ValueError):
                hosted._deployment()
            self.config = saved

    def test_wrong_repository_or_actor_cannot_be_asserted_through_environment(self):
        for row, field, value in [(self.repo, 'id', 999), (self.repo, 'private', False),
            (self.run['actor'], 'id', 999), (self.run['triggering_actor'], 'id', 999),
            (self.repo, 'default_branch', 'wrong')]:
            saved = row[field]; row[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError): self.observe()
            row[field] = saved

    def test_wrong_run_workflow_branch_commit_attempt_or_event_rejected(self):
        for field, value in [('id', 999), ('event', 'schedule'), ('run_attempt', 2),
                              ('head_branch', 'wrong'), ('head_sha', '9' * 40), ('workflow_id', 999)]:
            old = self.run[field]; self.run[field] = value
            with self.subTest(field=field), self.assertRaises((ValueError, KeyError)): self.observe()
            self.run[field] = old
        self.workflow['path'] = '.github/workflows/ci_v2_owner_registration.yml'
        with self.assertRaises(ValueError): self.observe()

    def test_unverified_local_environment_or_wrong_runtime_is_rejected(self):
        for field, value in [('GITHUB_ACTIONS', 'false'), ('GITHUB_ACTOR_ID', '999'),
            ('GITHUB_RUN_ID', '999'), ('GITHUB_RUN_ATTEMPT', '2'), ('RUNNER_ARCH', 'X64'),
            ('GITHUB_WORKFLOW_SHA', '9' * 40), ('GITHUB_REF', 'refs/heads/wrong')]:
            old = self.env[field]; self.env[field] = value
            with self.subTest(field=field), self.assertRaises((ValueError, KeyError)): self.observe()
            self.env[field] = old

    def test_missing_registration_or_forged_dispatch_subject_is_rejected(self):
        for inputs in ({'registry_key': 'fixture-parent'}, {'approved': True},
                       {**self.inputs, 'transition_subject_sha256': '0' * 64},
                       {**self.inputs, 'transaction_id': '9' * 32},
                       {**self.inputs, 'decision': 'APPROVED_FOR_TRUSTED_RESEARCH_PARENT_REGISTRATION_ONLY'}):
            self.event.write_text(json.dumps({'inputs': inputs}))
            with self.subTest(inputs=inputs), self.assertRaises(ValueError): self.observe()

    def test_private_registry_bytes_and_current_default_head_rechecked(self):
        self.remote['content'] = base64.b64encode(b'changed').decode()
        with self.assertRaises(ValueError): self.observe()
        self.remote['content'] = base64.b64encode((self.root / self.f.registry_path).read_bytes()).decode()
        self.branch['object']['sha'] = '9' * 40
        with self.assertRaises(ValueError): self.observe()

    def test_corrupt_notices_fails_actual_preparation(self):
        self.f.fixture.path.write_bytes(b'corrupt attachment')
        with self.assertRaises(ValueError): self.observe()

    def refresh_dispatch(self):
        r = self.config['request']
        self.config['subject_sha256'] = digest(hosted.subject(r, self.config['proposal_sha256'], 103))
        self.inputs.update(request_sha256=digest(r),
                           transition_subject_sha256=self.config['subject_sha256'])
        self.event.write_text(json.dumps({'inputs': self.inputs}))

    def test_owner_identity_does_not_bypass_proposal_source_policy_or_result_checks(self):
        original = deepcopy(self.config)
        for field, value in [('reference_sha256', '0' * 64), ('build_policy_sha256', '0' * 64),
            ('continuous_policy_sha256', '0' * 64), ('target_source_state', 'sha256-' + '0' * 64),
            ('result_registry_sha256', '0' * 64), ('baseline_id', 'sha256-' + '0' * 64)]:
            self.config = deepcopy(original); self.config['request'][field] = value
            self.refresh_dispatch()
            with self.subTest(field=field), self.assertRaises(ValueError): self.observe()

    def test_expired_scope_rejected_even_after_valid_owner_api_observation(self):
        changed = deepcopy(self.f.scope); changed['expires_at'] = '2000-01-01T00:00:00Z'
        self.f.save('configs/continuous.json', changed)
        self.config['request']['continuous_policy_sha256'] = self.f.pin('configs/continuous.json')
        self.refresh_dispatch()
        with self.assertRaisesRegex(ValueError, 'CONTINUOUS_POLICY_NOT_CURRENT'): self.observe()

    def test_generic_approver_policy_is_not_owner_only(self):
        self.f.owner['authorized_approver_ids'] = [101]
        self.f.save('configs/owner.json', self.f.owner)
        self.config['request']['owner_policy_sha256'] = self.f.pin('configs/owner.json')
        with self.assertRaises(ValueError): self.observe()

    def test_actual_checkout_checks_tracked_code_and_reviewed_bytes(self):
        for name in hosted.CODE:
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(P / name, path)
        def git(*args):
            return subprocess.check_output(['git', '--no-optional-locks', '-c', 'user.name=Synthetic Fixture',
                '-c', 'user.email=fixture@example.invalid', '-C', str(self.root), *args], stderr=subprocess.PIPE)
        git('init', '-q'); git('add', '--all'); git('commit', '-qm', 'synthetic trusted checkout')
        c = deepcopy(self.config); c['request']['implementation_revision'] = git('rev-parse', 'HEAD').decode().strip()
        c['implementation_contract_sha256'] = digest(hosted.contract(self.root))
        hosted._checkout(self.root, c)
        wrong = deepcopy(c); wrong['request']['implementation_revision'] = '0' * 40
        with self.assertRaises(ValueError): hosted._checkout(self.root, wrong)
        (self.root / 'src/untracked.py').write_text('raise RuntimeError()\n')
        with self.assertRaises(ValueError): hosted._checkout(self.root, c)
        (self.root / 'src/untracked.py').unlink()
        (self.root / hosted.CODE[0]).write_text('changed\n')
        with self.assertRaises(subprocess.CalledProcessError): hosted._checkout(self.root, c)


class WorkflowTests(unittest.TestCase):
    def test_manual_only_pinned_read_only_workflow_and_shell_syntax(self):
        import yaml
        data = yaml.load((P / hosted.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(set(data['on']), {'workflow_dispatch'})
        self.assertEqual(set(data['on']['workflow_dispatch']['inputs']), hosted.DISPATCH_FIELDS)
        self.assertEqual(data['permissions'], {'contents': 'read', 'actions': 'read'})
        for step in data['jobs']['inspect-transition']['steps']:
            if 'uses' in step:
                import re
                self.assertRegex(step['uses'], r'@[0-9a-f]{40}$')
            if 'run' in step:
                result = subprocess.run(['bash', '-n'], input=step['run'], text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_actual_preflight_shell_fails_without_deployment_before_dependency_setup(self):
        import tempfile
        import sys
        import yaml
        data = yaml.load((P / hosted.WORKFLOW).read_text(), Loader=yaml.BaseLoader)
        step = next(s for s in data['jobs']['inspect-transition']['steps']
                    if s['name'] == 'Require independently pinned deployment')
        with tempfile.TemporaryDirectory() as directory:
            env = {**os.environ, 'RUNNER_TEMP': directory, 'GITHUB_RUN_ID': '991',
                   'GITHUB_RUN_ATTEMPT': '1', 'PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_JSON': '',
                   'PATH': str(Path(sys.executable).parent) + os.pathsep + os.defpath}
            result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', step['run']],
                                    env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            receipt = json.loads((Path(directory) / 'parent-authority-transition-991-1/result.json').read_text())
            self.assertEqual(receipt['reason'], 'TRANSITION_DEPLOYMENT_NOT_CONFIGURED')
            self.assertFalse(receipt['registry_committed'])

    def test_actual_cli_missing_deployment_creates_only_blocked_diagnostic(self):
        import tempfile
        import sys
        with tempfile.TemporaryDirectory() as directory:
            env = {**os.environ, 'RUNNER_TEMP': directory, 'GITHUB_RUN_ID': '992',
                'GITHUB_RUN_ATTEMPT': '1', 'PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_JSON': ''}
            result = subprocess.run([sys.executable, '-B', str(P / 'scripts/parent_authority_transition_hosted.py')],
                                    env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            receipt = json.loads(result.stdout)
            self.assertEqual(receipt['reason'], 'TRANSITION_DEPLOYMENT_NOT_CONFIGURED')
            self.assertFalse(receipt['registry_committed'])
            self.assertEqual(len(list(Path(directory).rglob('*registry*'))), 0)

    def test_build_bound_research_loading_stays_denied_without_transition_provenance(self):
        from dataclasses import replace
        import test_research_corpus_selection as selection_fixtures
        f = selection_fixtures.SelectionTests(); f.setUp()
        try:
            path = f.review.registry_path; registry = json.loads(path.read_text())
            entry = registry['baselines']['fixture']; entry.pop('entry_kind')
            entry.update(build_policy_path='configs/not-approved.json', build_policy_sha256='0' * 64)
            path.write_text(json.dumps(registry))
            review = replace(f.review, registry_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            with self.assertRaisesRegex(selection_fixtures.s.SelectionError, 'RESEARCH_SCOPE_REQUIRED'):
                selection_fixtures.s.verify(review, f.corpus, f.root)
        finally:
            f.doCleanups()


if __name__ == '__main__':
    unittest.main()
