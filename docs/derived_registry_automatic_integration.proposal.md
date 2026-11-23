# Restricted automatic integration of derived Parent state — review proposal

Status: **DRAFT_FOR_HUMAN_REVIEW — NOT_AUTHORIZED — NOT_IMPLEMENTED**.
This document does not configure GitHub or authorize a writer. The Owner asked
for a restricted contract to review instead of removing protected-branch review.

## Scope and protected root

The protected default branch remains the sole source of executable code,
Workflows, policies, initial approved Parent, deployment configuration and the
historical Registry. Its PR, CODEOWNERS, stale-review, force-update and deletion
protections remain unchanged, with no bypass. No workflow approves its own PR.

Automatic state cannot be written directly to that protected Registry under
current rules. Do not claim that a completed isolated APPLY has updated it.
An automatic merge using an admin/App bypass is outside this proposal.

The proposed data-only ref is
`refs/heads/ci-v2-authority-audit/derived-parent-state-v1` in the already reviewed
repository. It is distinct from the existing per-transaction audit refs; it does
not conform to or replace their constant-tree transaction protocol. Reusing the
existing audit namespace would permit the existing history-integrity and writer
seal targeting patterns to protect it, **subject to actual independent readback
of both effective Rulesets**. No ref is created by this proposal. Existing audit
code cannot write this new state format; a separately reviewed data writer is
required after approval. Do not pass this name to the transaction audit adapter.

## Closed data contract proposed for review

A state commit would contain exactly `registry.json` and `lineage.json`; no code,
symlinks, submodules, executable modes or additional files. Its single parent
must be the independently observed previous state commit. The initial commit
must bind the protected root revision and raw Registry SHA-256, with no extra
initial entries. This proposal does not invent a genesis SHA.

Each transition must bind all of:

- Schema/version and exact repository name and numeric ID.
- Protected implementation revision, implementation-contract SHA-256 and the
  exact raw once-approved construction/admission policy digests and validity.
- Initial root revision/Registry SHA-256; previous state commit, previous raw
  Registry SHA-256, previous Parent key, node identity and entry digest.
- Exact Candidate identity, complete immutable Release/Asset identities and
  full-byte SHA-256 values, notices and source-state/upstream revisions.
- Actual authenticated producer Run ID/attempt/revision and job identity.
- Full integrity, Parity, original R2, applicable Q1, strict-failure and release
  restriction decisions, plus the recomputed admission decision digest.
- Complete new Parent Reference and its independent checksum, new Registry
  raw SHA-256, unique transition ID, and corresponding consumed/completed durable
  transaction receipts with independent readbacks.

Append **one** new eligible Parent entry; preserve all existing entries exactly
as JSON values. Never edit a prior Parent's authority, Reference or evidence.
Choose the next Parent only from a completely verified lineage, never from a
mutable `latest` name or a highest timestamp. The ordered successor must derive
from the previous head. No partial or unqualified Candidate is eligible.

`QUALITY_REVIEW_REQUIRED`, unqualified original Q1, strict failures, regression,
`P8_BLOCKED`, explicit release restrictions, missing scientific qualification or
missing authority remain denials. Neither a supplied PASS JSON nor a hash by
itself establishes approval. Supplementary Q1 diagnostics cannot rewrite the
original execution. A future accepting scientific/release contract is required;
the current blocking-only P8 and Genuine research producer do not supply one.

## Writer and consumption constraints

Only a reviewed policy-bound automatic job may request this data append. It
must have no ability through its interface to select arbitrary refs, paths,
files, policy overrides or source code. It must use the existing credential
Environment boundary and exact App/installation/repository verification, after
the separate automatic job's permission contract has been reviewed. The current
manual Owner-only Writer gate must not be relabelled as automatic authority.

GitHub Contents write is repository-wide, **not ref-scoped**. Interface checks,
Rulesets and protected Workflow code restrict use; the token itself does not.
No key installation, secret access or App permission expansion is authorized.
Ruleset A must have no bypass. Ruleset B must allow only the verified Writer;
it is currently absent, so no write may start. An Owner/admin can change these
controls: Owner-managed governance acknowledges this residual risk and does not
claim independent anti-rollback protection between observations.

Before and after reserve/consume/complete and integration, re-read policy,
protection and relevant heads. Use one non-force compare-and-swap append; stale
head or conflicting concurrent update means stop. Persist and independently
read back transaction consumption before APPLY. Unknown outcomes must be
reconciled read-only, never retried, replayed, rolled back automatically or
reported successful. Consumed transactions remain consumed after failure.
A new head must be independently read back with exact tree/byte verification
before consumers use it. Duplicate identical deliveries may return the already
verified result; conflicts must fail closed.

## Consumer and revocation boundary

Future scheduled selection would read protected code/policy plus this explicitly
pinned data ref, verify its entire chain back to the protected anchor, and select
only its last validated eligible entry. No arbitrary branch or JSON input is
accepted as authority. Changes to consumer code, policy, schema, initial anchor,
allowed repository/ref, credentials or server routing still require human PR
review. Expiry/revocation or an unknown schema prevents further construction and
deployment; it does not delete existing good evidence or stop unrelated services.

This would change Registry consumption semantics and requires explicit approval
of the exact implementation and policy, followed by protected integration and
real Hosted verification. It is not enabled in this PR. The authoritative
Registry, current `REGISTRATION_ONLY` Parent and all existing consumers remain
unchanged. If this proposal is rejected, retain the existing human-reviewed
Registry integration route.

## Exact decision requested

Review and approve or reject this data-only contract, including its fixed ref,
root/lineage checks, credential limitations and acknowledged Owner rollback
risk. Approval of this document alone must not be treated as authorization to
create refs/Rulesets, install credentials, dispatch APPLY or deploy a Corpus.
Those operations need exact, reviewable configuration and separate execution
scope. No protection setting is changed while this decision is pending.
