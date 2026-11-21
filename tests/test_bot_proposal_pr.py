import copy
import importlib.util
import pathlib
import unittest

PROJECT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bot_proposal', PROJECT / 'scripts/create_bot_proposal_pr.py')
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)


class BotProposalTests(unittest.TestCase):
    def setUp(self):
        self.base, self.head = 'a' * 40, 'b' * 40
        self.root = 'repos/' + bot.REPO
        self.env = dict(GITHUB_REPOSITORY=bot.REPO, GITHUB_REPOSITORY_ID='1455203884',
                        GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REF='refs/heads/' + bot.BASE,
                        GITHUB_RUN_ATTEMPT='1', GITHUB_ACTOR_ID=str(bot.OWNER), GITHUB_RUN_ID='123',
                        GITHUB_SHA=self.base, GITHUB_WORKFLOW_SHA=self.base,
                        PROPOSAL_BRANCH='ci-v2-proposals/reviewed', PROPOSAL_SHA=self.head,
                        EXPECTED_BASE_SHA=self.base)
        self.responses = {
            self.root: dict(id=1455203884, full_name=bot.REPO, default_branch=bot.BASE,
                            owner=dict(id=bot.OWNER)),
            self.root + '/actions/runs/123': dict(repository=dict(id=1455203884),
                actor=dict(id=bot.OWNER), triggering_actor=dict(id=bot.OWNER), event='workflow_dispatch',
                run_attempt=1, head_sha=self.base, head_branch=bot.BASE, path=bot.WORKFLOW),
            self.root + '/actions/permissions/workflow': dict(can_approve_pull_request_reviews=True),
            'users/github-actions%5Bbot%5D': dict(id=41898282, type='Bot', login='github-actions[bot]'),
            self.root + '/git/ref/heads/' + bot.BASE: dict(object=dict(sha=self.base)),
            self.root + '/git/ref/heads/ci-v2-proposals/reviewed': dict(object=dict(sha=self.head)),
            self.root + '/compare/' + self.base + '...' + self.head: dict(status='ahead', behind_by=0,
                ahead_by=1, total_commits=1,
                merge_base_commit=dict(sha=self.base)),
            self.root + '/pulls': dict(number=42, state='open',
                user=dict(id=41898282, type='Bot', login='github-actions[bot]'),
                base=dict(ref=bot.BASE, sha=self.base, repo=dict(id=1455203884)),
                head=dict(ref='ci-v2-proposals/reviewed', sha=self.head, repo=dict(id=1455203884)))
        }
        self.calls = []

    def api(self, method, path, data=None):
        self.calls.append((method, path, data))
        return copy.deepcopy(self.responses[path])

    def reject(self):
        with self.assertRaises((ValueError, KeyError)):
            bot.propose(self.env, self.api)
        self.assertFalse(any(m != 'GET' for m, _, _ in self.calls))

    def test_bot_pr_only_one_mutation_no_approve_merge_or_branch_write(self):
        result = bot.propose(self.env, self.api)
        self.assertEqual(result['author'], 'github-actions[bot]')
        writes = [x for x in self.calls if x[0] != 'GET']
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][1], self.root + '/pulls')
        self.assertEqual(writes[0][2]['base'], bot.BASE)
        self.assertFalse(writes[0][2]['maintainer_can_modify'])

    def test_disabled_actions_pr_setting(self):
        def forbidden(method, path, data=None):
            if method == 'POST':
                self.calls.append((method, path, data))
                raise ValueError('GitHub forbids Actions PR creation')
            return self.api(method, path, data)
        with self.assertRaises(ValueError):
            bot.propose(self.env, forbidden)
        self.assertEqual(sum(m == 'POST' for m, _, _ in self.calls), 1)
        self.assertFalse(any('/actions/permissions/' in path for _, path, _ in self.calls))

    def test_unreadable_repository_stops(self):
        del self.responses[self.root]
        self.reject()

    def test_untrusted_owner_contexts(self):
        for key, value in [('GITHUB_EVENT_NAME', 'pull_request_target'), ('GITHUB_ACTOR_ID', '1'),
                           ('GITHUB_RUN_ATTEMPT', '2'), ('GITHUB_REF', 'refs/heads/evil')]:
            with self.subTest(key=key):
                previous = self.env[key]
                self.env[key] = value
                self.reject()
                self.env[key] = previous

    def test_triggering_actor_must_be_owner(self):
        self.responses[self.root + '/actions/runs/123']['triggering_actor']['id'] = 1
        self.reject()

    def test_branch_and_sha_input_injection(self):
        for branch in ['ci-upstream-refresh', 'ci-v2-proposals/a;evil', '../evil']:
            self.env['PROPOSAL_BRANCH'] = branch
            self.reject()

    def test_base_moved(self):
        self.responses[self.root + '/git/ref/heads/' + bot.BASE]['object']['sha'] = self.head
        # This must be rejected before mutation, regardless of proposal compatibility.
        self.reject()

    def test_source_moved(self):
        self.responses[self.root + '/git/ref/heads/ci-v2-proposals/reviewed']['object']['sha'] = self.base
        self.reject()

    def test_non_fast_forward(self):
        self.responses[self.root + '/compare/' + self.base + '...' + self.head]['behind_by'] = 1
        self.reject()

    def test_human_pr_author_is_not_accepted(self):
        self.responses[self.root + '/pulls']['user'] = dict(id=bot.OWNER, type='User', login='XiangruZhang007')
        with self.assertRaises(ValueError):
            bot.propose(self.env, self.api)
        self.assertEqual(sum(m == 'POST' for m, _, _ in self.calls), 1)

    def test_uncertain_write_never_retried(self):
        def uncertain(method, path, data=None):
            if method == 'POST':
                self.calls.append((method, path, data))
                raise TimeoutError()
            return self.api(method, path, data)
        with self.assertRaises(TimeoutError):
            bot.propose(self.env, uncertain)
        self.assertEqual(sum(m == 'POST' for m, _, _ in self.calls), 1)

    def test_workflow_credential_isolation_and_codeowners(self):
        workflow = (PROJECT / bot.WORKFLOW).read_text()
        self.assertIn('pull-requests: write', workflow)
        self.assertIn('contents: read', workflow)
        self.assertIn('actions: read', workflow)
        self.assertNotIn('contents: write', workflow)
        for forbidden in ['secrets.', 'environment:', 'pull_request_target:', 'create-github-app-token',
                          'inputs.proposal_sha }}\n          persist', 'git push', 'gh pr merge', 'gh pr review']:
            self.assertNotIn(forbidden, workflow)
        owners = (PROJECT / '.github/CODEOWNERS').read_text()
        for path in ['/.github/CODEOWNERS', '/.github/workflows/', '/scripts/', '/src/', '/configs/']:
            self.assertIn(path + ' @XiangruZhang007', owners)
        self.assertIn('workflow_dispatch:', workflow)
        self.assertNotIn('pull_request:', workflow)
        self.assertIn('ref: ${{ github.sha }}', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('ref: ${{ github.sha }}', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('python3 -I -S -B', workflow)
        owners = (PROJECT / '.github/CODEOWNERS').read_text()
        for path in ['/.github/CODEOWNERS', '/.github/workflows/', '/scripts/', '/src/', '/configs/']:
            self.assertIn(path + ' @XiangruZhang007', owners)


if __name__ == '__main__':
    unittest.main()
