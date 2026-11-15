"""Static offline contracts for the dedicated manual registration workflow."""
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/ci_v2_owner_registration.yml'


class HostedWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.raw = WORKFLOW.read_text()

    def test_manual_only_six_inputs_and_read_only_permissions(self):
        triggers = self.raw.split('\non:\n', 1)[1].split('\npermissions:', 1)[0]
        self.assertEqual(re.findall(r'^  ([a-z_]+):', triggers, re.M), ['workflow_dispatch'])
        self.assertEqual(set(re.findall(r'^      ([a-z0-9_]+):', triggers, re.M)),
            {'registry_key', 'baseline_id', 'candidate_id', 'corpus_sha256',
             'registry_entry_sha256', 'registration_subject_sha256'})
        permissions = self.raw.split('\npermissions:\n')[1].split('\n\n')[0]
        self.assertEqual(permissions, '  contents: read\n  actions: read')
        self.assertNotIn('contents: write', self.raw)
        self.assertNotIn('${{ inputs.', self.raw)

    def test_fixed_runtime_pinned_actions_failure_preservation_and_no_build(self):
        actions = re.findall(r'uses: ([^\s]+)', self.raw)
        self.assertEqual(len(actions), 3)
        for action in actions:
            self.assertRegex(action, r'^actions/[a-z-]+@[0-9a-f]{40}$')
        for required in ('ubuntu-24.04-arm', "python-version: '3.12.3'", 'architecture: arm64',
                         "PYTHONHASHSEED: '0'", 'persist-credentials: false',
                         'cancel-in-progress: false', 'if: always()', 'include-hidden-files: true',
                         'OWNER_REGISTRATION_DEPLOYMENT_JSON: ${{ vars.',
                         'OWNER_REGISTRATION_DEPLOYMENT_SHA256: ${{ vars.',
                         'scripts/register_trusted_baseline_hosted.py'):
            self.assertIn(required, self.raw)
        for forbidden in ('execute-plan', 'run_local(', '--publish', 'git push', 'register.py --approved'):
            self.assertNotIn(forbidden, self.raw)

    def test_embedded_shell_and_python_syntax(self):
        for block in re.findall(r'^        run: \|\n((?:          .*\n|\n)+)', self.raw, re.M):
            code = '\n'.join(line[10:] if line.startswith('          ') else line
                             for line in block.splitlines()) + '\n'
            proc = subprocess.run(['bash', '-n'], input=code, text=True, capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            if "<<'PY'" in code:
                python = code.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
                compile(python, str(WORKFLOW), 'exec')


if __name__ == '__main__':
    unittest.main()
