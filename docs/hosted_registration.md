# Hosted manual approval integration (Step 2C.3-B)

This adds a dedicated `workflow_dispatch` entry for Owner-approved research
registration **on an isolated Registry copy only**. It does not enable real
deployment, automatic approval, authoritative registration, or next-Parent
selection. Local offline tests do not establish genuine Hosted acceptance.

## Execution and trust model

The new `.github/workflows/ci_v2_owner_registration.yml` workflow has six exact
dispatch inputs: `registry_key`, `baseline_id`, `candidate_id`, `corpus_sha256`,
`registry_entry_sha256`, and `registration_subject_sha256`. They confirm an exact
subject, not an approver identity or arbitrary input paths.

The maintainer must independently review the workflow, implementation commit,
request and Owner policy. Two repository-managed Actions variables provide the
deployment configuration:

- `OWNER_REGISTRATION_DEPLOYMENT_JSON`: exact UTF-8 deployment JSON;
- `OWNER_REGISTRATION_DEPLOYMENT_SHA256`: SHA-256 of those exact JSON bytes.

The versioned shape is shown in
`configs/ci_v2_owner_registration_deployment.template.json`. Its null values are
deliberately invalid and grant no authority. No real deployment values, policy,
repository IDs, approval identities, Release IDs or request pins were invented.

The fields are `schema_version: 1`, `repository`, numeric `repository_id`,
`default_branch`, `workflow_path`, exact `implementation_revision`, relative
`request_path`, raw `request_sha256`, relative `approval_policy_path`, and raw
`approval_policy_sha256`. Unknown fields are rejected. The request uses the
existing CLI schema and its own independent reference/build/Registry pins. The
Owner policy uses the existing schema. Both files must be reviewed, committed
under `configs/`, with policy directly in that directory. Expected policy values
are not accepted from the Candidate or dispatch inputs.

The expected implementation revision is configured **after** the reviewed code
and input files have a real commit SHA. It lives outside that commit in the
maintainer's deployment configuration, avoiding a self-referential commit hash.
The run must use that exact current default-branch commit. A later branch update
therefore blocks old runs until reviewed and explicitly repinned. After policy
changes, regenerate/review the subject because it includes the policy digest.

The adapter checks:

1. Independent deployment hash and exact request/policy hashes/domain.
2. Checkout root and HEAD against the expected implementation commit; no tracked
   byte changes, and no untracked code/config/workflow files. Required entry,
   request, policy and workflow files must be tracked regular files.
3. Existing frozen runtime/build/retrieval fingerprints, Python 3.12.3, arm64,
   and effective `PYTHONHASHSEED=0`.
4. Consistent GitHub repository, workflow ref/SHA, workspace, hosted-runner and
   dispatch context. These strings alone never authorize registration.
5. Actual GitHub API repository/default HEAD/workflow/run/attempt/actor evidence
   through the existing Owner identity checker. Only authorized numeric user IDs
   count; reruns and a moved default branch fail closed.
6. Full Candidate/Baseline/R2 evidence reconstruction and exact subject approval
   through the unchanged existing verification algorithms.

Deployment/configuration, checkout and API context are rechecked within the lock
and again immediately before the Registry commit. The Owner verifier still
checks exact subject and remote authoritative Registry bytes at that commit.
Actions variables are a job-start snapshot; rereading the environment cannot
detect a repository-variable change made remotely during that job. Urgent
revocation requires cancelling affected runs; a changed default-branch policy
commit is detected by the existing live HEAD check. New dispatches must use the
new reviewed pins. No live repository-variable API/revocation service is claimed.

The reviewed workflow plus maintainer-controlled code/configuration form the
trust root. GitHub environment/event/API data alone cannot prove an arbitrary
local process is a trusted Runner. There is no process-attestation claim, signed
local approval credential, environment `approved` switch, or new cryptographic
framework. The design cannot resist a malicious maintainer or equal-privilege
code that changes/calls private Python internals. Under GitHub Free private-repo
constraints, Owner self-attestation is accepted explicitly; protected PR review
remains an optional stronger mode, not a requirement or guarantee of this mode.

## Shared transaction and local compatibility

`baseline_registration_transaction.register()` keeps its original public
signature and deny-by-default `_trusted_dispatch_context()` implementation.
The ordinary CLI still returns `TRUSTED_WORKFLOW_EXECUTION_NOT_ESTABLISHED` for
otherwise valid local registration attempts, including with spoofed GitHub env.

The original algorithm is shared through private `_register()`. The dedicated
`src.hosted_registration.run()` supplies its reviewed context checker only at
this internal boundary; the public local function does not accept a context,
callback or mode selector. This is normal code organization, not an unforgeable
Python capability. No runtime monkeypatch is used in implementation code.

The Hosted script accepts no arguments selecting request paths, actor, policy,
production target, or authorization mode. Its root comes from its installation.
It copies the current authoritative Registry into a newly created, owned
`RUNNER_TEMP/owner-registration-<run-id>-<attempt>/isolated/registry.json`.
Output roots cannot overwrite previous attempts or traverse symlink directories.
Existing transaction safeguards reject Registry aliases and linked files.

The same stable lock, expected-old bytes/hash checks, historical Baseline
identity verification, duplicate checks, PREPARED/atomic-replace/COMPLETED
algorithm and recovery rules apply. Recovery remains available through the
ordinary CLI for an independently preserved isolated workspace and transaction
ID; it cannot create authorization or rewrite Registry contents. Restored audit
artifacts require their own identity/hash verification before recovery; download
success or an unsigned audit alone is not authorization.

Each Hosted run starts an isolated copy. The lock is local to that copy;
Workflow concurrency avoids overlapping cooperating runs but is not a global
exactly-once registration service. Repeated separate approvals can update
separate copies. Nothing here makes the next build use the new entry.

## Permissions, environment and evidence

The job uses only `contents: read` and `actions: read`, for same-repository private
Release reads, source/config reads and run identity checks. Actions are pinned
to the same reviewed full SHAs as existing CI; checkout persists no credentials.
No `contents: write`, PAT, GitHub App, OIDC provider, second account, paid branch
protection, workflow trigger beyond manual dispatch, or real Registry writer is
introduced. Repository policy may further restrict Actions; Hosted access is not
claimed until actually tested.

The workflow prepares the existing pinned chunker/parser dependencies solely
because the existing verifiers import them. It invokes no corpus build, real R2,
or P4.1 approval command. Sealed qualification explicitly uses `NO_FRESH_REPLAY`.

`GH_TOKEN` and `TRUSTED_RELEASE_TOKEN` receive the existing `GITHUB_TOKEN` only in
the execution step. Request/policy pins are not secret credentials. Raw error
bodies and token-bearing URLs are not returned. The script emits one JSON result
and exits 0 for completed isolated transaction, 1 for refusal, or 2 for
`COMMITTED_WITH_ERROR`.

The owned output root contains `result.json`, `checksums.json`, and the isolated
Registry/journals. No Corpus or Baseline downloads are copied to that root; the
existing verifiers clean their temporary evidence sessions. The authoritative
Registry hash is captured and checked after execution. A failed postcheck or
report persistence **after** commit retains `registry_committed: true` and
`COMMITTED_WITH_ERROR`; it does not falsely report an uncommitted rejection.

An `always()` upload step preserves result and audit files, including hidden lock
or staging files if present. The default retention is 30 days; this is not a
permanent backup. Missing deployment pins produce a refusal report before
dependency preparation. Early infrastructure failures may have no result file;
the summary says `NO_TRANSACTION_RESULT`, not successful registration. Forced
cancellation/Runner loss can prevent uploads despite `always()`. Failed uploads
do not undo an already committed isolated transaction; inspect job logs and
preserved result state rather than treating Workflow failure as rollback.

Research quality and Q1 statuses are preserved. `NO_FRESH_REPLAY`,
`automatic_research_approval: false`, `automatic_reuse: false`, P8 `BLOCKED`, and
production `NOT_AUTHORIZED` remain in force. Owner approval grants only the
specified research registration scope, not quality acceptance or deployment.

## Offline and genuine Hosted acceptance

Run the relevant offline suite with the existing environment:

```bash
PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=tests \
tools/treesitter-chunker/.venv/bin/python -m unittest \
  test_hosted_registration test_hosted_registration_workflow \
  test_register_trusted_baseline_cli test_baseline_registration_transaction \
  test_published_candidate_verification test_owner_manual_baseline_approval \
  test_trusted_baseline_registration test_github_baseline_approval \
  test_candidate_release_archive test_private_release_transport test_parent_r2_anchor
```

Synthetic tests compose real HTTP download/extraction, subject verification,
Owner checks and isolated transactions, while mocking GitHub responses and
qualification internals. A separate synthetic Git repository tests actual
checkout identity and tracked-byte validation. These are not real Hosted Owner
approval. Workflow validation includes YAML parsing, static trigger/permissions/
action contracts, `bash -n`, and compilation of embedded Python. They do not
replace GitHub server validation; actionlint availability is reported separately.

Before Step 2C.3-C, obtain explicit authorization to deploy this reviewed code,
configure its actual independent pins, and dispatch the dedicated workflow.
Real Candidate archives must contain the expected three assets. The separate
P4.1 Baseline and Parent R2 assets must exist with independently reviewed pins;
do not substitute the old C1 Baseline Release for a Candidate archive. Any
additional publication/licensing/storage authorization remains separate.

First test refusal cases, then a genuine authorized isolated transaction if all
assets exist. Verify the resulting Actor/API/run evidence, exact subject and
checksums, unchanged authoritative Registry, preserved limitations and recovery.
Cross-account rejection without an available legitimate test account remains
not Hosted-verified; never forge an actor and label it genuine acceptance.

Future automatic authorization is deferred. It requires separately approved
versioned policy, revocation/audit rules, its own reviewed execution entry and
acceptance milestone. Existing P4.1 approval remains mandatory; automatic
registration does not authorize automatic P4.1 approval. No policy engine or
automatic acceptance path was implemented here.

GitHub reference contracts:
- https://docs.github.com/en/actions/reference/workflows-and-actions/variables
- https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches
