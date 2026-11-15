"""Synthetic Hosted composition only; these tests do not establish real approval."""
import base64
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_register_trusted_baseline_cli as cli_fixtures
from src import hosted_registration as hosted
from src.corpus_snapshot import digest, file_digest


class HostedRegistrationTests(unittest.TestCase):
    def setUp(self):
        f = self.fixture = cli_fixtures.RegistrationCLITests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.addCleanup(f.tearDown)
        self.project = f.project
        self.sha = 'c' * 40
        self.workflow = '.github/workflows/ci_v2_owner_registration.yml'
        policy = json.loads(f.policy.read_bytes())
        policy['workflow_path'] = self.workflow
        f.policy.write_bytes(hosted.tx._serialize(policy))
        f.request['approval_policy_sha256'] = file_digest(f.policy)
        f.write_request()
        self.request_path = self.project / 'configs/registration-request.json'
        self.request_path.write_bytes(f.path.read_bytes())
        self.deployment = {'schema_version': 1, 'repository': f.f.repo['full_name'],
            'repository_id': f.f.repo['id'], 'default_branch': 'main',
            'workflow_path': self.workflow, 'implementation_revision': self.sha,
            'request_path': 'configs/registration-request.json', 'request_sha256': f.sha,
            'approval_policy_path': 'configs/owner-policy.json',
            'approval_policy_sha256': file_digest(f.policy)}
        _, verified = f.call()
        self.inputs = {'registry_key': f.request['registry_key'],
            'baseline_id': f.f.ref['node_id'], 'candidate_id': f.f.fixture.cid,
            'corpus_sha256': f.f.ref['corpus_sha256'],
            'registry_entry_sha256': digest(f.f.entry),
            'registration_subject_sha256': verified['registration_subject_sha256']}
        self.event = f.f.root / 'dispatch.json'
        self.event.write_bytes(hosted.tx._serialize({'inputs': self.inputs}))
        self.env = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
            'GITHUB_REPOSITORY': self.deployment['repository'],
            'GITHUB_REPOSITORY_ID': str(self.deployment['repository_id']),
            'GITHUB_SHA': self.sha, 'GITHUB_WORKFLOW_SHA': self.sha,
            'GITHUB_WORKFLOW_REF': self.deployment['repository'] + '/' + self.workflow + '@refs/heads/main',
            'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
            'GITHUB_EVENT_PATH': str(self.event), 'GITHUB_RUN_ID': '9001',
            'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_ACTOR_ID': '2',
            'GITHUB_WORKSPACE': str(self.project)}
        p = patch.dict(os.environ, self.env)
        p.start(); self.addCleanup(p.stop)
        self.repository = {'id': self.deployment['repository_id'],
            'full_name': self.deployment['repository'], 'default_branch': 'main',
            'owner': {'id': 2, 'type': 'User', 'login': 'fixture-owner'}}
        self.run_metadata = {'id': 9001, 'event': 'workflow_dispatch', 'status': 'in_progress',
            'run_attempt': 1, 'head_branch': 'main', 'head_sha': self.sha,
            'repository': {'id': self.repository['id'], 'full_name': self.repository['full_name']},
            'actor': {'id': 2, 'type': 'User', 'login': 'fixture-owner'},
            'triggering_actor': {'id': 2, 'type': 'User', 'login': 'fixture-owner'},
            'workflow_id': 88, 'created_at': '2026-11-15T10:00:00Z'}
        self.workflow_metadata = {'id': 88, 'path': self.workflow}
        self.head = self.sha
        self.client = type('Client', (), {'json': lambda _, endpoint: self.api(endpoint)})()
        self.checkout = patch.object(hosted, '_checkout')
        for p in (patch.object(hosted, 'PROJECT', self.project), self.checkout,
                  patch.object(hosted, 'frozen_runtime'),
                  patch.object(hosted.owner, 'GitHubCLI', return_value=self.client)):
            p.start(); self.addCleanup(p.stop)
        self.api_calls = []

    def api(self, endpoint):
        self.api_calls.append(endpoint)
        base = 'repos/' + self.deployment['repository']
        if endpoint == base:
            return self.repository
        if endpoint == base + '/actions/runs/9001':
            return self.run_metadata
        if endpoint == base + '/actions/workflows/88':
            return self.workflow_metadata
        if endpoint == base + '/git/ref/heads/main':
            return {'ref': 'refs/heads/main', 'object': {'sha': self.head}}
        if endpoint == base + '/contents/configs/ci_v2_schema2_trusted_baselines.json?ref=' + self.sha:
            return {'path': 'configs/ci_v2_schema2_trusted_baselines.json', 'type': 'file',
                'encoding': 'base64', 'content': base64.b64encode(self.fixture.f.registry_bytes).decode()}
        raise AssertionError('Unexpected synthetic API call')

    def invoke(self, changes=None, deployment=None):
        raw = json.dumps(self.deployment if deployment is None else deployment, sort_keys=True)
        runner = tempfile.mkdtemp(prefix='hosted-runner-', dir=self.fixture.f.root)
        env = {'OWNER_REGISTRATION_DEPLOYMENT_JSON': raw,
            'OWNER_REGISTRATION_DEPLOYMENT_SHA256': hosted.tx._sha(raw.encode()), 'RUNNER_TEMP': runner}
        env.update(changes or {})
        with patch.dict(os.environ, env):
            result = hosted.run()
        self.assertEqual(file_digest(self.fixture.registry), hosted.tx._sha(self.fixture.f.registry_bytes))
        return result

    def test_actual_composition_with_synthetic_trust_preserves_authority(self):
        result = self.invoke()
        self.assertEqual(result['status'], 'COMPLETED', result)
        self.assertTrue(result['registry_committed'])
        self.assertTrue(result['authoritative_registry_unchanged'])
        self.assertEqual(result['execution'], 'NO_FRESH_REPLAY')
        self.assertEqual(result['production_promotion'], 'NOT_AUTHORIZED')
        root = Path(result['output_directory'])
        saved = json.loads((root / 'result.json').read_bytes())
        self.assertEqual(saved, result)
        for name, sha in json.loads((root / 'checksums.json').read_bytes()).items():
            self.assertEqual(file_digest(root / name), sha)
        audit = json.loads(next((root / 'isolated').glob('*.prepared.json')).read_bytes())
        self.assertEqual(audit['registration_subject']['candidate']['quality_status'], 'QUALITY_REVIEW_REQUIRED')
        self.assertEqual(audit['registration_subject']['candidate']['q1_status'], 'Q1_NOT_QUALIFIED_FOR_VERSION_PAIR')
        self.assertFalse(audit['registration_subject']['registry_entry']['reference']['authorization']['automatic_research_approval'])
        self.assertEqual(audit['owner_approval']['workflow_run']['actor_id'], 2)
        self.assertEqual(len(list((root / 'isolated').glob('*.completed.json'))), 1)
        # The public ordinary entry point stays closed under the same environment.
        self.assertEqual(self.fixture.call('register')[1]['reason'],
                         'TRUSTED_WORKFLOW_EXECUTION_NOT_ESTABLISHED')

    def test_missing_unpinned_template_or_unknown_deployment_rejected(self):
        for env in ({'OWNER_REGISTRATION_DEPLOYMENT_JSON': ''},
                    {'OWNER_REGISTRATION_DEPLOYMENT_SHA256': ''},
                    {'OWNER_REGISTRATION_DEPLOYMENT_SHA256': '0' * 64}):
            with self.subTest(env=list(env)):
                self.assertEqual(self.invoke(env)['status'], 'BLOCKED')
        template = json.loads((hosted.tx.PROJECT /
            'configs/ci_v2_owner_registration_deployment.template.json').read_bytes())
        self.assertEqual(self.invoke(deployment=template)['status'], 'BLOCKED')
        self.assertEqual(self.invoke(deployment={**self.deployment, 'approved': True})['status'], 'BLOCKED')

    def test_runtime_bindings_and_nonhosted_invocation_rejected(self):
        for key, val in [('GITHUB_ACTIONS', 'false'), ('RUNNER_ENVIRONMENT', 'self-hosted'),
                         ('GITHUB_REPOSITORY', 'wrong/repo'), ('GITHUB_REPOSITORY_ID', '999'),
                         ('GITHUB_SHA', 'd' * 40), ('GITHUB_WORKFLOW_SHA', 'd' * 40),
                         ('GITHUB_WORKFLOW_REF', 'wrong/workflow'), ('GITHUB_WORKSPACE', ''),
                         ('GITHUB_EVENT_NAME', 'push'), ('GITHUB_REF', 'refs/heads/other'),
                         ('GITHUB_RUN_ATTEMPT', '2')]:
            with self.subTest(key=key):
                result = self.invoke({key: val})
                self.assertEqual(result['status'], 'BLOCKED', result)
                self.assertFalse(result['registry_committed'])

    def test_actual_api_repository_workflow_run_actor_and_head_mismatches(self):
        cases = [(self.repository, 'id', 999), (self.workflow_metadata, 'path', 'wrong'),
                 (self.run_metadata, 'id', 999), (self.run_metadata, 'status', 'completed'),
                 (self.run_metadata, 'run_attempt', 2), (self.run_metadata, 'head_sha', 'd' * 40),
                 (self.run_metadata['actor'], 'id', 99)]
        for obj, key, value in cases:
            old = obj[key]; obj[key] = value
            with self.subTest(key=key):
                self.assertEqual(self.invoke()['status'], 'BLOCKED')
            obj[key] = old
        self.head = 'd' * 40
        self.assertEqual(self.invoke()['reason'], 'STALE_WORKFLOW_COMMIT')

    def test_unauthorized_actor_and_exact_subject_required(self):
        self.repository['owner']['id'] = 99
        self.assertEqual(self.invoke()['reason'], 'UNAUTHORIZED_WORKFLOW_ACTOR')
        self.repository['owner']['id'] = 2
        self.inputs['registration_subject_sha256'] = '0' * 64
        self.event.write_bytes(hosted.tx._serialize({'inputs': self.inputs}))
        result = self.invoke()
        self.assertEqual(result['reason'], 'OWNER_APPROVAL_NOT_VERIFIED', result)
        root = Path(result['output_directory'])
        self.assertEqual((root / 'isolated/registry.json').read_bytes(), self.fixture.f.registry_bytes)
        self.inputs['unexpected'] = 'value'
        self.event.write_bytes(hosted.tx._serialize({'inputs': self.inputs}))
        self.assertEqual(self.invoke()['reason'], 'HOSTED_DISPATCH_INPUTS_MISMATCH')

    def test_request_policy_hash_domain_and_stale_registry(self):
        for key, value in [('request_sha256', '0' * 64), ('approval_policy_sha256', '0' * 64),
                           ('approval_policy_path', '../escape'), ('request_path', '/tmp/escape'),
                           ('default_branch', 'wrong')]:
            d = {**self.deployment, key: value}
            with self.subTest(key=key):
                self.assertEqual(self.invoke(deployment=d)['status'], 'BLOCKED')
        request = deepcopy(self.fixture.request)
        request['expected_registry_sha256'] = '0' * 64
        raw = hosted.tx._serialize(request)
        self.request_path.write_bytes(raw)
        d = {**self.deployment, 'request_sha256': hosted.tx._sha(raw)}
        self.assertEqual(self.invoke(deployment=d)['reason'], 'STALE_AUTHORITATIVE_REGISTRY')

    def test_unreviewed_or_modified_checkout_and_bad_runtime_stop(self):
        with patch.object(hosted, '_checkout', side_effect=hosted.tx.TransactionError('UNREVIEWED_HOSTED_FILE')):
            self.assertEqual(self.invoke()['reason'], 'UNREVIEWED_HOSTED_FILE')
        with patch.object(hosted, 'frozen_runtime', side_effect=ValueError('bad runtime')):
            self.assertEqual(self.invoke()['status'], 'BLOCKED')

    def test_prepared_and_postcommit_failures_and_real_recovery(self):
        original = os.replace
        def before_commit(source, *a, **kw):
            if isinstance(source, str) and source.startswith('.registry-'):
                raise OSError('before Registry commit')
            return original(source, *a, **kw)
        with patch.object(hosted.tx.os, 'replace', side_effect=before_commit):
            before = self.invoke()
        self.assertEqual(before['status'], 'BLOCKED')
        self.assertIn('transaction_id', before)
        isolated = Path(before['output_directory']) / 'isolated'
        self.assertEqual(hosted.tx.recover(self.project, isolated,
            transaction_id=before['transaction_id'])['status'], 'NOT_COMMITTED')
        with patch.object(hosted.tx, '_complete', side_effect=OSError('after commit')):
            after = self.invoke()
        self.assertEqual(after['status'], 'COMMITTED_WITH_ERROR')
        isolated = Path(after['output_directory']) / 'isolated'
        recovered = hosted.tx.recover(self.project, isolated, transaction_id=after['transaction_id'])
        self.assertEqual(recovered['status'], 'COMPLETED')
        self.assertEqual(recovered['authorization'], 'NOT_GRANTED_BY_RECOVERY')
        self.assertEqual(hosted.tx.recover(self.project, isolated,
            transaction_id=after['transaction_id']), recovered)

    def test_changed_deployment_before_commit_rejected_without_monkeypatch_authority(self):
        original = hosted._deployment
        count = 0
        def changing():
            nonlocal count
            count += 1
            deployment = original()
            if count >= 3:
                deployment['request_sha256'] = '0' * 64
            return deployment
        with patch.object(hosted, '_deployment', side_effect=changing):
            result = self.invoke()
        self.assertEqual(result['reason'], 'HOSTED_DEPLOYMENT_CHANGED', result)
        self.assertFalse(result['registry_committed'])

    def test_output_failure_does_not_erase_committed_state(self):
        original = hosted._persist
        count = 0
        def interrupted(root, result):
            nonlocal count
            original(root, result)
            count += 1
            if count == 1:
                raise OSError('evidence upload preparation failed')
        with patch.object(hosted, '_persist', side_effect=interrupted):
            result = self.invoke()
        self.assertEqual(result['status'], 'COMMITTED_WITH_ERROR')
        self.assertTrue(result['registry_committed'])
        saved = json.loads((Path(result['output_directory']) / 'result.json').read_bytes())
        self.assertEqual(saved['status'], 'COMMITTED_WITH_ERROR')

    def test_failed_authoritative_postcheck_preserves_actual_commit(self):
        original = hosted.file_digest
        calls = 0
        def unreadable(path):
            nonlocal calls
            if Path(path) == self.fixture.registry:
                calls += 1
                if calls > 1:
                    raise OSError('simulated lost read access')
            return original(path)
        with patch.object(hosted, 'file_digest', side_effect=unreadable):
            result = self.invoke()
        self.assertEqual(result['status'], 'COMMITTED_WITH_ERROR')
        self.assertTrue(result['registry_committed'])
        self.assertFalse(result['authoritative_registry_unchanged'])
        self.assertEqual(result['reason'], 'AUTHORITATIVE_REGISTRY_CHANGED')

    def test_missing_corrupt_evidence_and_protected_isolation_alias_fail_closed(self):
        with patch.object(hosted.tx.transport, 'restore', side_effect=ValueError('corrupt evidence')):
            result = self.invoke()
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertFalse(result['registry_committed'])
        original = hosted.tx._locked
        from contextlib import contextmanager
        @contextmanager
        def aliased(project, isolation, authoritative):
            path = Path(isolation) / 'registry.json'
            path.unlink()
            os.link(authoritative, path)
            try:
                with original(project, isolation, authoritative) as value:
                    yield value
            finally:
                path.unlink()  # Only the synthetic isolated alias is removed.
        with patch.object(hosted.tx, '_locked', side_effect=aliased):
            result = self.invoke()
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertFalse(result['registry_committed'])

    def test_candidate_cannot_supply_its_own_policy_or_request_pin(self):
        # Even with a newly pinned deployment descriptor, the separately fixed
        # policy checksum must agree with the reviewed request and actual file.
        changed = deepcopy(self.fixture.request)
        changed['approval_policy_sha256'] = '0' * 64
        raw = hosted.tx._serialize(changed)
        self.request_path.write_bytes(raw)
        deployment = {**self.deployment, 'request_sha256': hosted.tx._sha(raw)}
        self.assertEqual(self.invoke(deployment=deployment)['status'], 'BLOCKED')

    def test_alias_or_project_temp_rejected_and_owned_output_never_overwritten(self):
        root = self.fixture.f.root
        link = root / 'runner-link'; link.symlink_to(root, target_is_directory=True)
        self.assertEqual(self.invoke({'RUNNER_TEMP': str(link)})['status'], 'BLOCKED')
        self.assertEqual(self.invoke({'RUNNER_TEMP': str(self.project)})['status'], 'BLOCKED')
        result = self.invoke()
        output = Path(result['output_directory'])
        before = (output / 'result.json').read_bytes()
        second = self.invoke({'RUNNER_TEMP': str(output.parent)})
        self.assertEqual(second['status'], 'BLOCKED')
        self.assertEqual((output / 'result.json').read_bytes(), before)

    def test_hosted_script_rejects_overrides_and_missing_deployment(self):
        with patch('sys.stdout', new_callable=io.StringIO) as out:
            code = hosted.main(['--approved'])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out.getvalue())['reason'], 'INVALID_HOSTED_ENTRY_ARGUMENTS')
        script = hosted.tx.PROJECT / 'scripts/register_trusted_baseline_hosted.py'
        env = {**os.environ, 'OWNER_REGISTRATION_DEPLOYMENT_JSON': '',
               'OWNER_REGISTRATION_DEPLOYMENT_SHA256': '',
               'RUNNER_TEMP': tempfile.mkdtemp(dir=self.fixture.f.root)}
        proc = subprocess.run([sys.executable, '-B', str(script)], env=env,
                              capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(json.loads(proc.stdout)['status'], 'BLOCKED')
        self.assertEqual(proc.stderr, '')


class CheckoutProvenanceTests(unittest.TestCase):
    def test_real_synthetic_git_commit_and_tracked_byte_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflow = '.github/workflows/ci_v2_owner_registration.yml'
            paths = (*hosted.REQUIRED_CODE, workflow, 'configs/request.json', 'configs/policy.json')
            for name in paths:
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('synthetic reviewed fixture\n')
            env = {**os.environ, 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}
            def git(*args):
                return subprocess.check_output(['git', '-C', str(root), *args], env=env,
                                               stderr=subprocess.PIPE)
            git('init', '-b', 'main')
            git('add', '.')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '-m', 'isolated fixture')
            d = {'implementation_revision': git('rev-parse', 'HEAD').decode().strip(),
                 'workflow_path': workflow, 'request_path': 'configs/request.json',
                 'approval_policy_path': 'configs/policy.json'}
            with patch.object(hosted, 'PROJECT', root):
                hosted._checkout(d)
                extra = root / 'src/unreviewed.py'
                extra.write_text('unreviewed\n')
                with self.assertRaisesRegex(hosted.tx.TransactionError, 'UNTRACKED_HOSTED_IMPLEMENTATION'):
                    hosted._checkout(d)
                extra.unlink()
                (root / paths[0]).write_text('changed\n')
                with self.assertRaises(subprocess.CalledProcessError):
                    hosted._checkout(d)
                with self.assertRaises(hosted.tx.TransactionError):
                    hosted._checkout({**d, 'implementation_revision': '0' * 40})
            self.assertEqual(git('remote').strip(), b'')


if __name__ == '__main__':
    unittest.main()
