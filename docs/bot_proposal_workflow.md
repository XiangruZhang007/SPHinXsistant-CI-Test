# Owner-reviewed Bot proposal PRs

Initial implementation deployed at
`9974510d681d5a15be0c194e0c18cb208c33dd7f` on `ci-upstream-refresh`.
Deployment does not establish genuine Bot PR creation or Owner approval;
those remain pending a separately authorized Hosted test.
This supplements `trusted_writer_workflow.md` without changing its seven files
or its fail-closed Writer gate. The previous document's single-owner PR blocker
is addressed by a distinct PR author, not by permitting self-approval.

## Exact interface

`ci_v2_bot_proposal.yml` is manual-only and runs trusted default-branch code.
Owner ID 239840087 must dispatch it from `ci-upstream-refresh`, first attempt,
in repository 1455203884. Inputs are `proposal_branch`, `proposal_sha`, and
`expected_base_sha`. Branch names are restricted to `ci-v2-proposals/<name>`.
The reviewed source commit must already exist on that repository branch,
strictly ahead of the exact default-branch base with no divergent history.
Uploading that source branch is a separate authorized operation; this workflow
cannot upload local files or access uncommitted changes.

The workflow checks out its own exact trusted dispatch SHA with persisted
credentials disabled. It never checks out or executes proposal code. Its stdlib
script verifies live repository, Owner, run, attempt, workflow path, base/source
refs and ancestry, then performs one POST to create a PR targeting exactly
`ci-upstream-refresh`. The response must bind the expected head/base and actual
`github-actions[bot]` identity (resolved through GET). A failure or timeout is
uncertain until read-only inspection; no automatic retries or cleanup occur.
There is no approval, merge, ref update, credential installation or dispatch API.

Only `pull-requests: write`, `contents: read`, and `actions: read` are needed:
the source branch already exists. No Contents write, App token, Environment,
private key, dependency installation or proposal script execution is needed.
Owner approval is enforced by the subsequently configured GitHub PR Ruleset;
the PR body is not an enforcement mechanism. Initial unprotected testing must
not be described as protection-enforced approval.

## Verified bootstrap deployment and remaining Hosted test

Authenticated GET after the initial deployment verified the public repository
ID 1455203884, default HEAD
`9974510d681d5a15be0c194e0c18cb208c33dd7f`, and the active Bot Workflow.
The branch remains unprotected, with audit Ruleset A 27770139 preserved.
The Owner has enabled **Allow GitHub Actions to create and approve pull requests**;
GET confirmed `can_approve_pull_request_reviews=true` while default token
permissions remain read. This documentation proposal changes no setting.
That shared setting permits creation and approval generally; this workflow
implements creation only. Never expand the Audit Writer App for this task.
The setting inspection uses the authenticated Owner/admin CLI, not the workflow
token: that settings API needs Administration read, which this job intentionally
does not have. If the setting remains disabled, GitHub rejects the sole PR POST;
the job stops without requesting broader credentials or retrying.

GitHub API confirmed `github-actions[bot]` is Bot ID 41898282, distinct from
Owner 239840087. Authenticated creation with a real workflow token and actual
Owner approval remain untested until a separately authorized Hosted run.

## Bootstrap without circular protection

The initial code deployment and Actions PR-setting prerequisites below are now
complete. Proposal upload, a real Bot dispatch, Owner approval and target-branch
protection still require their separate authorizations and verification.

1. Separately review and authorize a local checkpoint and exact one-time normal
   synchronization of the seven existing Writer files plus this Bot path to the
   currently unprotected default branch. Recheck remote HEAD before any future
   push. No Writer keys or preparation-enable variable during bootstrap. Verify
   deployed bytes and CODEOWNERS on the default branch. This task does not commit
   or authorize that synchronization.
2. Separately authorize the Actions PR-creation setting above. Verify its GET
   readback. Separately authorize uploading a genuine reviewed maintenance change
   to `ci-v2-proposals/<name>`; then authorize one Bot workflow dispatch using
   exact source/base SHAs. Do not fabricate a change solely to force a passing test.
3. Inspect the real PR author, base/head, actual diff and Owner CODEOWNERS request.
   Owner reviews and approves through their human account. Verify the approval's
   actor and commit. This establishes the maintenance path before protection.
   Any merge is a separate Owner action; no Bot auto-merge.
4. Only after that proof, separately authorize the previously proposed active
   `ci-v2-trusted-workflow-integrity-v1` Ruleset: exact default branch, no exclusions
   or bypass; deletion + non_fast_forward + pull_request; one approval, Code Owner
   approval, stale approval dismissal, resolved review threads. Keep
   `require_last_push_approval=false`: requiring a different last pusher reviewer
   could recreate a second-human requirement when Owner uploads the source.
   Preserve audit Ruleset A and Environment exactly.
5. Verify effective Ruleset/API and actual CODEOWNERS coverage. Using a separately
   authorized real Bot PR, confirm GitHub blocks unapproved merging and accepts
   Owner approval; merge only with explicit authority and exact final diff review.
   If this fails, stop, without bypasses or automatic protection changes.
6. Reassess the resulting merged deployment revision and implementation pins.
   Only afterward consider separately authorized Writer credential installation,
   including scope/fallback checks. No AUTHORIZE/APPLY or Parent authority change
   follows automatically. Repository admin can still change governance; this is
   not protection against a malicious admin.

CODEOWNERS covers itself, workflows, scripts, source and configs. GitHub's
required review applies to all PRs; required Code Owner review additionally
applies to covered files. An Owner-authored PR still cannot self-approve.

## Workflow trigger behavior

Current GitHub documentation says `GITHUB_TOKEN` PR `opened`, `synchronize` and
`reopened` events create approval-required workflow runs. A writer must explicitly
approve those runs; that is separate from approving the PR. Other token-triggered
events generally do not start workflows except workflow_dispatch/repository_dispatch.
No downstream run is promised. The existing Owner transition workflow is manual
and must retain its exact Owner/deployment checks. This workflow never dispatches
it. Check actual run state and required checks before any merge; do not invent
required status checks for workflows that cannot run.

Sources reviewed:

- https://docs.github.com/en/actions/concepts/security/github_token
- https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository
- https://docs.github.com/en/pull-requests/how-tos/review-pull-requests/reviewing-proposed-changes-in-a-pull-request
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets

## Offline validation scope

API fixture tests cover Bot/human author distinction, exact target, denied settings,
unreadable API, Owner/trigger/run restrictions, invalid branches, moved refs,
divergence, uncertain writes without retry, read-only Contents, CODEOWNERS coverage,
and trusted-checkout credential isolation. Existing Writer regressions remain
required. Fixtures are not genuine Hosted proof of approval or token capability.
