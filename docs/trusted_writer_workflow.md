# Trusted Writer Workflow integration (local, nonoperative)

The existing `ci_v2_parent_authority_transition.yml` retains manual dispatch,
its six exact inputs, read-only GITHUB_TOKEN permissions, ARM64/Python 3.12.3,
pinned Actions, operation-specific Owner verification and live APPLY blocker.
No new audit protocol is introduced.

## Two jobs, separate trust and credential lifetimes

`inspect-transition` retains the existing read-only behavior by default. Only a
separately authorized `PARENT_AUTHORITY_WRITER_PREPARATION_ENABLED=true` variable
selects `parent_authority_writer_prepare.py`. That entry reuses actual `_deployment`,
`_observe`, frozen scientific contracts, notices and exact tracked-code checks.
It exports only a NOT_GRANTED preparation receipt and implementation file hashes.
Success means Owner-verified preparation, not transaction approval or APPLY.

`trusted-audit-writer` depends on successful preparation and is bound to Environment
`ci-v2-audit-writer`. It runs on a fresh Hosted runner, checks out exact dispatch SHA
without persisted credentials, selects the pinned Python, and runs only stdlib
verification (`python -I -S -B`, excluding PYTHONPATH, script-directory module
shadowing, user site and sitecustomize) plus pinned Actions. It does not install project/parser dependencies,
load project modules, restore caches/download earlier-job artifacts or execute PR
code. The first job never receives the App private key or installation token.

Before the key-bearing step, `parent_authority_writer_gate.py` independently checks
repository/Owner/actor/trigger, workflow ID/path, exact default HEAD and checkout,
run/attempt/event, six dispatch inputs, prior job/step API success, deployment raw
SHA and implementation bytes, and Environment ID/reviewer/branch/admin-bypass
settings. It requires effective default-branch deletion/non-fast-forward/PR review
rules and their exact active no-bypass Ruleset origins. A forged receipt alone,
missing protection, stale checkout or failed preflight cannot reach minting.

## Credentials prepared, not installed or used in this implementation task

Only the pinned `actions/create-github-app-token` Action receives the future Secret
`CI_V2_AUDIT_APP_PRIVATE_KEY`. Pin `f418cff399f7aef4c2f0ad47e25ca7a6abbdd6fc` was
resolved from the official v3 tag and its Action interface read, not guessed.
It uses node24; `app-id` remains supported but deprecated in favor of Client ID.
No Client ID was fabricated. Inputs pin App ID 5855475, Owner XiangruZhang007,
repository SPHinXsistant-CI-Test, API https://api.github.com and Contents:write
only (Metadata read is implicit). No Administration/Workflows permission is
requested. `skip-token-revoke=false` keeps the Action's default post-job revocation;
crashed runners cannot be assumed to finish cleanup.

The token is not a job output or artifact. Only the final stdlib validation step
receives it as `PARENT_AUTHORITY_AUDIT_TOKEN`; GH_TOKEN remains the read-only Owner
observer credential. This step reruns the context gate, verifies returned installation
ID 184185108, and makes a read-only token-authenticated installation/repositories
request requiring exactly repository ID 1455203884. It never logs the token or
executes reserve/consume/append/APPLY. The existing transport accepts the dedicated
credential separately but its Hosted scope remains read-only and still blocked.
Real App identity/scope is not claimed verified by these offline fixtures.

GitHub's `secrets.NAME` syntax is not an Environment-only namespace: a same-named
repository/organization secret could be a fallback if the Environment key is absent.
Before authorized key installation, independently verify that this name exists
only in the intended Environment, with no broader-scope fallback. No secret or
private key was read/created/uploaded here. The code/Environment association does
not itself establish credential provenance or a workflow-path allowlist.

## Minimum default-branch protection proposal (not configured)

A separate active branch Ruleset should target only
`refs/heads/ci-upstream-refresh`, no exclusions or bypass, with:

- deletion and non_fast_forward;
- pull_request: required_approving_review_count >= 1,
  dismiss_stale_reviews_on_push=true, require_code_owner_review=true;
  explicit API-required fields require_last_push_approval=false and
  required_review_thread_resolution=true are included in the external proposal.

The added `.github/CODEOWNERS` covers itself, Workflows, scripts, source and configs
with the actual Owner. It is included in the implementation-byte contract.
This Ruleset is distinct from audit history Ruleset A (27770139) and writer seal B.
A must remain unchanged; B is not created. No audit ref is initialized.

Single-owner limitation: GitHub does not let an author approve their own PR.
Environment self-review remains deliberately allowed, but that does not bypass
PR Code Owner rules. Owner-authored changes under the proposed no-bypass rule
need another qualified Code Owner or an explicitly reviewed maintenance decision;
no extra reviewer or bypass is automatically invented/installed here.

## Actual deployment/readiness boundary

Read-only preflight found remote default HEAD e98fa6122d89edd3bd080e814f0dfa48040096a1,
branch protected=false, effective default-branch rules=[], and only Ruleset A.
The Environment's exact Owner reviewer, prevent_self_review=false and can_admins_bypass=false
were verified. The updated Workflow and CODEOWNERS are local uncommitted changes,
not deployed. No new revision or contract digest is automatically authorized.

Credential installation is NOT READY. First review this exact code/contract and
single-owner protection requirements; separately authorize deployment and branch
protection, verify actual remote bytes/rules, and only then authorize Environment
key installation with scope-fallback checks. Preparation remains default-disabled.
An App token is repository-scoped, not intrinsically audit-ref-scoped; audit B,
genesis/transaction pins and independent governance still precede any separately
authorized real append. Existing Registry/Parent authority and scientific evidence
are unchanged. No Push, Dispatch, real mint, real audit write/APPLY or Commit.
