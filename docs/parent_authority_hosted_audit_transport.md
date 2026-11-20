# GitHub audit transport and Hosted readiness connection

This implementation supplies real authenticated REST transport for the existing
B4.1 protocol. It does not create a second transaction protocol. Local tests use
an HTTP-boundary server fixture; they do not establish real GitHub concurrency,
Owner authorization, or deployed governance. No remote resources were provisioned.

## Transport and supported operations

`parent_authority_github_transport.GitHubAuditTransport` implements the existing
`request(method, endpoint, body)` contract. Its endpoint allowlist is confined to
the pinned repository, exact transaction ref, Git commits/trees and ruleset GETs.
Public support uses the accepted exact name/ID allowlist; private pins remain
supported. HTTP uses api.github.com, TLS defaults, a 15-second socket timeout,
128-request ceiling, bounded JSON, duplicate-key rejection, and no redirects or
automatic retry. HTTP errors expose only status, never bodies or credentials.
The socket timeout is not an absolute deadline against a trickling response;
the existing Hosted job's 30-minute timeout is the outer execution bound.

Default transport is read-only. Explicit private provisioning/append primitives
are capability scopes, not proof of Owner authorization:

- `INITIALIZE`: create an empty Git tree and reviewed root commit, separately
  create the exact ref only after repository GET, exact-ref 404 plus successful
  matching-ref empty-list corroboration, pinned root/tree verification, then
  complete protocol readback. An inaccessible matching-ref API is not absence.
- `create_genesis(reviewed_git_identity)` requires the already independently
  pinned expected genesis SHA and explicit reviewed author/committer identity.
  The ID is never selected from a test. Mismatch creates no ref and never repins.
  There is no automatic ref creation after object creation. A separate controlled
  initialization invocation must use the retained exact pins.
- `APPEND`: canonical B4.1 single-parent commits and `force=false` ref updates.
  Only a commit created by this transport can be submitted; an immediate ref
  recheck must equal its recorded parent. Objects and the resulting full audit
  chain are re-read by the existing protocol before reporting success.

There is no delete/reset/force operation, arbitrary-branch API proxy, automatic
recreation, takeover, rollback or retry. A rejected/uncertain write closes further
transport writes. Protocol claim state is burned before an attempt. A fresh
client may inspect but cannot recover a consumed in-memory claim.

## Concurrency and rollback limits

GitHub's ref update API accepts SHA and force, **not an expected-old SHA**.
The client precheck is not CAS. Distinct nonces produce sibling direct children;
under GitHub's documented current-ref fast-forward enforcement, a racing sibling
loses. Deterministic two-writer tests model this property, not real server timing
or global atomicity. All writers must preserve the same restricted protocol.

The protocol now detects rollback/replacement relative to its own observed head
within a process. A new process with only genesis/current metadata cannot detect
an administrative reset followed by settings restoration. Current settings hashes,
Git objects, workflow concurrency and a readback receipt cannot close that gap.
Consumed history must remain reachable under independently governed protections.

## Connected Hosted entry (nonoperative)

The existing CLI and Workflow call `hosted_parent_authority_transition.run()`.
Legacy deployment schema 1 remains unchanged and blocked when UNCONFIGURED.
Schema 2 has the same top-level fields; `transaction_backend` may be a strict
object with these exact fields:

- `kind`: `GITHUB_GIT_AUDIT_V1`.
- `audit`: original seven-field B4.1 config (schema_version, repository,
  repository_id, ref, genesis_sha, tree_sha, governance_sha256).
- `history_ruleset_id`, `writer_ruleset_id`, `writer_integration_id`: real,
  independently reviewed positive numeric IDs, not supplied fixture IDs.

All existing deployment raw SHA, Subject, Request/Proposal, Owner-only policy,
Run/attempt/default-branch/implementation revision, ARM64/Python 3.12.3 runtime,
Registry, notices and scientific contract checks still precede audit access.
The implementation-byte contract now includes both audit modules.

After genuine Owner observation, the entry reconstructs the operation-specific
binding and uses `GH_TOKEN` with the READ-ONLY transport. It verifies the empty
tree, complete pinned audit chain and the two actual rulesets against the external
governance pin. Only then can it report GITHUB_AUDIT_READBACK_VERIFIED. The public
result remains BLOCKED / NOT_GRANTED, with no reserve/consume/core invocation.
Ruleset GET success is not write-capability or credential-isolation evidence.

The observed rulesets must match the B4.3 layered model:

1. History layer: branch target `refs/heads/ci-v2-authority-audit/*`, active,
   no exclusions or bypass; deletion, non_fast_forward, required_linear_history.
2. Writer layer: same target, active; creation and update restrictions, with
   update_allows_fetch_and_merge=false; only the independently reviewed Integration
   ID may always bypass THIS layer. No Owner/admin role bypass; it cannot bypass
   the history layer. B4.3's sealed empty bypass list blocks all writers until a
   separately reviewed writer-only exception is authorized and configured.

Governance pin is the canonical SHA-256 of `{schema_version: 1, rulesets: [...]}`,
ordered history then writer, retaining id/target/enforcement/conditions/
bypass_actors/rules. It binds observations, not independent control-plane trust.
No actual IDs, governance digest, transaction ID or deployment JSON are invented.

## Remaining genuine configuration requirements and safe next sequence

1. Independently decide the control-plane threat boundary and exact public
   disclosure scope. Owner/admin can edit rules; no current API snapshot proves
   that consumed history was never reset between observations.
2. Review a genuine isolated Writer App/installation, selected repository and
   credentials. Minimum Git Database mutation permission is Contents:write;
   no Administration:write or Workflows:write is needed. Contents permission is
   repository-wide, not intrinsically audit-ref-specific, including for
   GITHUB_TOKEN. Assess unrelated branches and protect them separately. A generic
   Actions token or broad Owner bypass is not a verified isolated Writer.
3. Separately authorize/configure the two actual rulesets and writer identity;
   independently retain their pins and governance evidence. Nothing here creates
   an App, token, Secret, Variable or rule. No current credential is assumed valid
   for mutation. Writer installation scope/control remains unverified.
4. Independently review genuine operation Request/Proposal/Decision, transaction
   ID, public Git author/committer metadata, empty-tree and genesis pins. Authorize
   object provisioning and one-shot ref initialization separately. Never initialize
   from reserve(), reuse a consumed transaction, or silently change genesis pins.
5. Review the new implementation revision/contract and deployment schema 2 pins.
   No deployment commit or token is created in this task. Current local Parent is
   still REGISTRATION_ONLY; this implementation grants no build authority.
6. After separately authorized deployment, verify metadata/readback using GET only:
   `repos/XiangruZhang007/SPHinXsistant-CI-Test`,
   `.../git/ref/heads/ci-v2-authority-audit/<reviewed-transaction-id>`,
   `.../git/commits/<pinned-genesis-or-observed-head>`,
   `.../git/trees/<pinned-empty-tree>`, `.../rulesets/<reviewed-id>`.
   Use `gh api --method GET` explicitly. Do not use an API error as missing state.
7. Exact future Workflow invocation uses `gh workflow run
   ci_v2_parent_authority_transition.yml --repo
   XiangruZhang007/SPHinXsistant-CI-Test --ref ci-upstream-refresh` with all six
   reviewed inputs: operation=PARENT_BUILD_AUTHORITY_TRANSITION_V1,
   decision=APPROVE_RESTRICTED_BUILD_AUTHORITY_TRANSITION, request_sha256,
   proposal_sha256, transition_subject_sha256, transaction_id. This text is not
   dispatch authorization. Current connected entry remains nonoperative even with
   matching rule snapshots because Writer/control-plane guarantees are unresolved.

**Incomplete live boundary:** real transport writes are implemented/tested, but
Hosted reserve→consume→isolated APPLY→completion is NOT enabled or wired as an
operative path. Existing B4.1 tests and new HTTP-boundary tests exercise that
sequence only with synthetic Owner evidence and an isolated Registry copy. A
separately verified Writer/control-plane prerequisite is still missing, so this
is partial Hosted integration, not deployed readiness or an authorization grant.
No scientific approval, authoritative Registry write or production permission is
inferred from a transport result. COMMITTED_WITH_ERROR remains unsuccessful and
must never cause an automatic replay, second mutation or rollback.

Official API contracts:
- https://docs.github.com/en/rest/git/refs
- https://docs.github.com/en/rest/git/commits
- https://docs.github.com/en/rest/git/trees
- https://docs.github.com/en/rest/repos/rules
