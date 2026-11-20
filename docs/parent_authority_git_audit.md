# B4.1 isolated Git audit protocol

This is an offline protocol adapter and feasibility result, not a deployed durable
backend. Existing B3/B4 code, Workflow, public APPLY and policies are unchanged.
`backend_status()` is unconditionally blocked. The private
`_IsolatedGitProtocol` has an injected isolated test transport; it has no real
HTTP/GitHubCLI transport, credential access or production caller. It cannot grant
Owner/build authority. All its results say `authorization: NOT_GRANTED` and
`scope: OFFLINE_PROTOCOL_TEST`.

## Documented semantics and conditional feasibility

The [Contents API](https://docs.github.com/en/rest/repos/contents) requires the
existing blob SHA when updating a file and documents concurrency conflicts. That
is not an expected-branch-HEAD precondition, a durable approval ledger or a way to
detect delete/recreate rollback. We do not use it for transaction consumption.

The [References API](https://docs.github.com/en/rest/git/refs) accepts a new SHA
and `force`; false requires a fast-forward. It does not accept an expected old
HEAD. The [Commit API](https://docs.github.com/en/rest/git/commits) lets a writer
specify exactly one parent. Combining these permits a narrower **inferred**
protocol: from observed head H, prepare only an immediate child C with a fresh
256-bit claim nonce. Two concurrent writers choosing H produce distinct sibling
commits C1/C2. Once H advances to C1, H→C2 is not a fast-forward. The losing writer
must not retry automatically. This is a property of that restricted commit graph,
not a claim that arbitrary `force=false` updates are compare-and-swap.

This argument assumes the server enforces its documented fast-forward check
against the current ref at mutation, the ref cannot roll back or be deleted and
recreated, and all accepted writers preserve the reviewed protocol. Offline API
fixtures model these assumptions; they do not empirically establish real Hosted
atomicity, visibility, repository rules or independent governance.

## Minimal dedicated transaction protocol

A separately initialized, independently pinned ref is dedicated to ONE exact
transaction: `refs/heads/ci-v2-authority-audit/<32-hex transaction ID>`. Its fixed
genesis commit, constant tree SHA and external governance-document digest bind
repository name/ID, ref, operation, transaction, Request/Proposal and old/result
Registry digests. They cannot be chosen anew on each competing run. No branch,
genesis, tree or governance document is created by this implementation.

Git commit messages contain bounded canonical audit records. The adapter reads
the authenticated repository/ref/commit metadata, follows every single-parent
link to pinned genesis and checks the complete state sequence. Messages, parents,
tree, previous-event SHA-256, nonce and exact binding must agree. Arbitrary merge,
reset, truncated/unknown history, extra event or invalid completion fails closed.
There are at most three events; every transition is a fresh direct child:

1. RESERVED binds the exact B3/B4 Request, Proposal, Subject and full Owner
   decision, including Owner Run/attempt/workflow and expected Registry result.
   Existing B3 decision consistency and B4 Subject generation are reused. This
   validation is **not** authentication of a saved JSON decision.
2. CONSUMED burns the claim before any prospective isolated APPLY. Only the same
   in-memory adapter instance that successfully reserved may attempt consumption.
   Another run/process may inspect but cannot restore a claim from JSON or issue
   another consumption. Interrupted claims sacrifice liveness instead of replaying.
3. COMPLETED requires the existing private B4 isolated core's successful receipt
   and exact isolated Registry bytes matching the approved result SHA-256. The
   receipt digest is appended. Partial/committed-with-error local results remain
   consumed and require review; they are never silently reset or retried.

The adapter never invokes that core itself. A focused synthetic integration test
consumes first, calls the existing isolated core, verifies its bytes, then appends
completion. The authoritative Registry remains read-only. Audit completion never
grants scientific approval or production permission.

Each commit creation is read back before reference update, and the entire chain
is read again after update. A conflict, timeout or failed read never creates a
permit, even if readback shows that the write actually succeeded. Reconciliation
is read-only and explicitly review-required. No retry, second approval, rollback,
lease expiry or takeover is implemented. A crash after durable consumption and
before local completion can therefore leave a permanently consumed transaction;
the protocol favors safety over automatic recovery.

## Why actual governance remains unresolved

Git objects provide content-addressed history while reachable; they do not make a
mutable ref immutable or prove that an unsigned commit was approved by the Owner.
The pinned governance digest is an external review subject, not proof of applied
rules. A real trusted observer must authenticate the Owner again, verify the exact
proposal and applicable policies, and independently inspect audit-state governance
before any mutation or consumption. No arbitrary JSON flag can establish this.

[GitHub rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
can restrict updates/deletion and block force pushes, but rule availability depends
on plan, and bypass privileges must be assessed. A single broad bypass that can
force/delete the ref is insufficient. A prospective deployment must verify separate
effective protections against rollback/deletion/recreation, restrict accepted
writers, prevent their bypass of those protections, and independently govern rule
changes and implementation pins. Required `contents: write` scope is repository
scope, not a credential intrinsically limited to one audit branch. Existing B4
read-only permissions have NOT been broadened.

No real audit branch, token/App, ruleset, credential, genesis pin or live transport
is configured or checked here. Existing infrastructure does not yet establish
those requirements. Thus the result is **backend feasible, implementation and
governance integration incomplete**, not closure of the genuine B4 live blocker.
No external database is needed to demonstrate this conditional Git-native route.

A specific negative counterexample is retained: if the synthetic server resets
the ref from CONSUMED to genesis, a new client can reserve again. Git metadata
alone cannot detect that rollback. This is why the adapter is isolated, its
results grant no authority, and independently enforced governance is mandatory.
It would be unsafe to deploy this protocol under the current unverified rules.

## Offline verification and next boundary

Tests use a shared in-memory Git REST model enforcing general ancestry-based
fast-forward (not simulated CAS), real B3/B4 synthetic fixtures and the existing
isolated writer. They cover racing sibling writers, duplicates, cross-client and
new-process visibility, consumed claims, conflicts, failed reads, timeouts before
and after write, forbidden writes, tampering, partial application and result pins.
Model object SHA-1s are synthetic IDs, not real remote byte verification. No
genuine source construction, R2, Owner approval or remote API mutation occurs.

Before live use, separately review the exact audit resource/governance, trusted
writer and least-privilege credentials, real transport/readback, reservation-to-
isolated-APPLY integration and deployment code contract. Verify protections live,
then conduct explicitly authorized failure/concurrency Hosted validation. This
task does not perform or authorize those actions. The existing B4 public gate
continues to report `DURABLE_CROSS_RUN_TRANSACTION_BACKEND_NOT_CONFIGURED`.
