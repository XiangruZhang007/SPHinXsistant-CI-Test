# Trusted Owner observation and isolated audit Writer

The operation is `PARENT_BUILD_AUTHORITY_TRANSITION_V1`. Registration approval,
research loading and Parent build eligibility remain separate decisions. The
public B3 `authorize`/`apply` gates and the read-only Hosted `run()` stay closed.
No local JSON receipt, dispatch flag or directory grants build authority.

## Runtime and trust boundaries

The dedicated manual-only Workflow has two fresh ARM64/Python 3.12.3 jobs:

1. `inspect-transition` uses the existing pinned scientific environment to check
   the frozen runtime, clean exact tracked checkout, deployment contract, Owner,
   actor/triggering actor, first Run attempt, Workflow/default-branch revision,
   Registry bytes, policies, immutable notices and exact operation Subject. It
   produces only `OWNER_VERIFIED_WRITER_PREPARATION_ONLY` outputs. With preparation
   disabled it retains the existing read-only blocked diagnostic behavior.
2. `trusted-audit-writer` requires that successful reader job, explicit preparation
   opt-in and the `ci-v2-audit-writer` Environment approval. Before passing a key
   to the pinned App-token action it independently checks actual GitHub Run/job,
   repository, Owner, protected default branch, Environment, exact checkout and
   reader receipt/file inventory. Only the token action receives the private key;
   only the verification/execution steps receive the installation token. It is
   repository-scoped Contents write, not a ref-specific credential. The action
   revokes the installation token after the job.

`parent_authority_writer_execute.py` runs under `python -I -S -B`, accepts no
arguments and verifies the standard-library gate and token scope before loading
project modules. The Writer installs no project dependencies, executes no
scientific build and consumes no downloaded executable artifact. Metadata-only
policy and filesystem helpers load scientific dependencies lazily; the reader's
original frozen-runtime verification remains mandatory. Both jobs use the exact
reviewed implementation and Workflow identity. Writer Owner/Subject, mutable
Registry/policy/default-branch state and governance are checked again before
transaction phases. Each notices verification uses a fresh external temporary
path and the original immutable-download verifier.

## Durable transaction connection

The existing schema-2 deployment backend `GITHUB_GIT_AUDIT_V1` binds the dedicated
transaction ref, genesis, constant tree and governance digest. The existing
[Git audit protocol](parent_authority_git_audit.md) and
[GitHub transport](parent_authority_hosted_audit_transport.md) are reused.
The new entry point adds no alternate audit format, approval provider or service.

After genuinely satisfied Writer and governance gates, the private composition:

1. Rechecks exact Request/Proposal/Subject/Owner-Run and old Registry bindings.
2. Reserves once, then independently rereads the complete audit chain.
3. Consumes once, then independently rereads the consumed claim.
4. Calls the existing isolated `_local_apply` core with repeated trusted checks.
5. Verifies isolated Registry bytes and the write-once completion receipt through
   the existing no-follow locking/read helpers.
6. Appends durable completion and independently verifies the entire chain and
   receipt digest, then confirms the authoritative Registry still has old bytes.

Result artifacts contain sanitized status, isolated Registry and original
PREPARED/COMPLETED/evidence records. They are retained even after failure where
possible. A timeout may have persisted a reservation/consumption; unknown progress
is reported as `null`/`STATE_UNCERTAIN`, never a fresh grant. `COMMITTED_WITH_ERROR`
remains unsuccessful and potentially committed. No automatic retry, replay,
rollback, lease takeover, claim restoration or second transaction is performed.
A crash can permanently consume a transaction without completing it.

A verified isolated result still reports `authorization: NOT_GRANTED`,
`build_candidate_authority: NOT_GRANTED`, `scope: ISOLATED_COPY_ONLY` and
`authoritative_registry_applied: false`. Authoritative application requires the
existing separate exact human review and protected integration process. This job
cannot directly promote a Parent, build a Candidate or deploy production.

## External prerequisites remain blocking

The real transport's current governance observer reports credential isolation and
independent governance as `NOT_VERIFIED`. Current matching Rulesets alone cannot
prove those properties or detect an administrator's rollback between observations.
The new Writer rejects that result **before creating an APPEND-capable transport**.
No environment value, configured ID or synthetic test success changes this.
Therefore this wiring is not a live authorization-ready implementation.

Before live use the independently governed control arrangement and its verifiable
evidence must satisfy the accepted anti-rollback model. The Owner explicitly
reported that no independent governance arrangement currently exists. An Owner-only
Environment approval is not independent governance. Merely installing a Secret,
Ruleset B or genesis ref cannot clear this gate. No replacement evidence-verifier
or relaxation of the threat model is introduced in this change.

Further prerequisites include the reviewed App installation/credential scope,
working protected Writer path, exact Rulesets A/B, fixed transaction ref/genesis,
tracked approved Owner/build/Continuous policies, the exact proposed old/new
Registry state and post-review deployment revision/contract pins. The transition
Variables are `PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_JSON` and its raw UTF-8
`PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_SHA256`; preparation additionally requires
`PARENT_AUTHORITY_WRITER_PREPARATION_ENABLED`. These are not enabled by this change.
A merged revision must be rebound and reviewed; historical pins are not repinned.
Do not activate a sealed Ruleset B without a verified legitimate Writer path.

## Verification scope

Offline tests exercise the real existing protocol and isolated APPLY against an
explicit synthetic Git/Owner fixture, including independent chain readbacks,
races, stale Registry, replay, rollback, interrupted reservation/consumption/APPLY,
completion tampering and uncertain writes. Separate tests run the actual stdlib
import closure and unauthorized entry point, and use the real governance observer
against synthetic REST responses. They do not establish Hosted execution, real
Owner approval, applied governance or official build eligibility.

Retain `REGISTRATION_ONLY`, `QUALITY_REVIEW_REQUIRED`,
`Q1_NOT_QUALIFIED_FOR_VERSION_PAIR`, `P8_BLOCKED` and
`PRODUCTION_NOT_AUTHORIZED`. Existing research-only construction/loading contracts
remain separate and require their own exact inputs and explicit authorization.
