# B4 trusted Owner observation and isolated transaction core

B3 checkpoint remains a distinct accepted commit. The B4 files are local and
uncommitted. Existing registration workflows/Request/Subject/approval semantics
and B3 public `authorize`/`apply` remain unchanged.

## Dedicated trust interface

`src/hosted_parent_authority_transition.py` implements the separate
`PARENT_BUILD_AUTHORITY_TRANSITION_V1` observation. The public `run()` accepts no
client, actor, decision, path, approval provider or simulation override. Its
dedicated script also accepts no arguments. Tests mock the existing GitHubCLI
transport at the same boundary as D2; this is not an enabled production mode.

A maintainer-pinned deployment is supplied through process environment populated
from future repository Variables:

- `PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_JSON`
- `PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_SHA256` (raw JSON UTF-8 SHA-256)

The closed deployment includes schema version, operation, the complete B3
`request`, proposal/Subject/code-contract digests, numeric Workflow ID and
`transaction_backend: UNCONFIGURED`. No other backend value is supported.
This task neither creates nor modifies these Variables or real policies.

The Request is nested in external deployment configuration rather than tracked
as a file containing its own commit SHA. This avoids a self-referential commit
pin: the actual reviewed implementation commit can be bound after creation.
Owner/build/Continuous policies and Registry must still be tracked, present and
raw-byte pinned in that exact clean checkout. The code contract, actual commit,
clean tracked files and frozen interpreter collectively bind implementation.
No B4 deployment revision exists merely because a local B3 checkpoint exists.

The operation Subject contains the original Request once, its canonical digest,
proposal digest and reviewed Workflow ID. All repository/key/Baseline/Reference/
notices/policy/scope/source-state/old-result Registry/transaction/authority values
are thereby bound without duplicating mutable fields. Six dispatch inputs are
operation, explicit transition decision, canonical Request digest, proposal digest,
Subject digest and transaction ID. Old registration dispatch data cannot match.

The observer checks GitHub-hosted ARM64 runtime, exact workspace/Workflow/revision,
clean reviewed checkout, tracked implementation/configs, frozen runtime and actual
API repository/private visibility/Owner/actor/triggering actor/Run/first attempt/
event/default-branch HEAD/Workflow identity. It reuses D2's `_github_identity`
and remote Registry-byte verification, requires an Owner-only policy, downloads
only independently pinned mandatory notices, re-PREPAREs original pinned inputs,
and repeats API/checkout checks. No Parent restoration, construction or scientific
replay is performed. Identity observations alone never reserve a transaction.

The trust model is the existing maintainer-governed reviewed-Workflow model,
not universal process attestation against a malicious same-privilege maintainer.
Tests that substitute API/checkout/frozen-runtime boundaries are explicitly
`SYNTHETIC_TRUSTED_INVOCATION_TEST`, never genuine Hosted evidence.

## Unresolved global durability: live path stays blocked

After successful Owner/Subject observation, `run()` **always** returns BLOCKED:
`DURABLE_CROSS_RUN_TRANSACTION_BACKEND_NOT_CONFIGURED`. It never calls the
isolated writer. B3's ordinary local approval/application gates remain closed.
No saved JSON, process environment, local directory, fake backend name, artifact
or concurrency setting can enable a production APPLY path.

D2 file locking/fsync/audits provide useful persistence in the same directory;
independent GitHub-hosted runners have different directories. Workflow concurrency
serializes only that workflow and does not provide a durable single-use ledger.
Restoring an Actions artifact is not an atomic compare-and-consume transaction.

The exact missing capability is independently governed storage retaining atomic
reservation/compare-and-set and completed transaction state across Hosted runs,
binding operation/transaction/Request/Proposal/Owner Run and result identity, with
idempotent failure resolution and a complete immutable audit/recovery boundary.
A remote mutation backend and its trust/permission model have not been approved.
No remote-write backend, credentials or extra permissions are introduced here.
If a GitHub write-backed design is later chosen, its exact resource, atomicity,
governance and least-privilege write scope require separate review/authorization.
The present Workflow has only `contents: read` and `actions: read`.

## Isolated local transaction core

`src/parent_authority_transaction.py` is private, not publicly wired. It reuses
D2 `_locked`, no-follow dirfd traversal, hardlink/authoritative-file alias refusal,
stable flock, fsync staging and write-once audit primitives. Only a future reviewed
trusted adapter with a verified global reservation may call it in production.
Direct private calls with synthetic revalidation callbacks are test boundaries,
not a supported authorization API or a sandbox against arbitrary Python code.

In a dedicated isolated directory initialized with exact old Registry bytes, the
core binds the unchanged key/Baseline/Reference, exact proposed result and repeated
operation-specific observation. It durably retains original Registry bytes,
proposal and observation in evidence plus PREPARED, then stages/verifies/replaces
only `registry.json` in that directory and records COMPLETED. Original registration
audit values and unrelated entries remain unchanged. The authoritative Registry
is read only. Same-directory duplicate reservation survives a process restart;
there is deliberately no cross-directory/global single-use claim.

Failures before replacement retain PREPARED/reservation and old bytes; failures
after or ambiguously around replacement use readback and report
COMMITTED_WITH_ERROR or STATE_UNCERTAIN. No automatic retry/replay/rollback occurs.
Read-only crash inspection classifies old/new/unknown bytes, checks audit bindings
and always requires fresh trust/backend review. It never authenticates arbitrary
audit JSON, upgrades authority or repairs state automatically.

## Workflow and research compatibility

`.github/workflows/ci_v2_parent_authority_transition.yml` is a dedicated
manual-only, pinned-action, frozen ARM64/Python3.12.3 interface with read-only
permissions and diagnostic artifacts. Missing deployment blocks before dependency
setup. A valid future deployment can observe the Owner subject but still blocks
APPLY until global durability is reviewed and implemented. It has no push/schedule
trigger, Candidate builder, publisher or production activation. No local packages
were installed while preparing this future Workflow.

D3.3 loading remains unchanged: registration-only research loading works, and a
build-bound entry with only a locally repinned Registry or synthetic transition
receipt is rejected. A future compatibility extension requires independently
verified genuine transition provenance **and preserved original research-use
permission**, with exact Corpus/Candidate/Baseline/Reference/notices verification.
BUILD_CANDIDATE alone cannot establish research/production activation permission.

Retain QUALITY_REVIEW_REQUIRED, Q1_NOT_QUALIFIED_FOR_VERSION_PAIR, P8_BLOCKED,
PRODUCTION_NOT_AUTHORIZED. New Candidates still need all existing qualification,
fresh Parent R2, independent Full/Parity and frozen target R2/replay gates.

## Offline verification

Use the existing frozen environment, `PYTHONDONTWRITEBYTECODE=1`,
`PYTHONHASHSEED=0`, `PYTHONPATH=tests`, `TMPDIR=/tmp`, the retained private-Release
repository metadata scope, and local Git file transport for synthetic fixtures.
Deny network transports. No real GitHub API/Owner, Release, Corpus or R2 run is
needed. Run the new tests and the affected registration/Owner/transaction/
Continuous/notices/research-selection suites. The Workflow tests parse YAML,
check shell syntax, execute the real missing-deployment preflight and CLI, and
verify absence of any Registry output. Local transaction tests cover restart,
concurrency, interruption, partial failure, duplicate rejection and audit damage.

Offline success is intentionally a **partial B4 implementation** while the
global transaction backend is unavailable. Do not label it a live-ready or
cross-Hosted-run replay-safe authority transition.
