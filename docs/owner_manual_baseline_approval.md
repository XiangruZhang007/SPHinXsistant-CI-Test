# Owner-manual research Baseline approval (read-only adapter)

This adds an owner-manual authorization mode alongside the existing
protected-PR verifier. It does not weaken or replace
`src/github_baseline_approval.py`. The adapter verifies a GitHub
`workflow_dispatch` run and the exact P4.1-qualified schema-2 Baseline
proposal, then reports an approval decision. It **never writes** the Trusted
Baseline Registry.

## Trust model and Free-plan limitation

The owner-manual mode treats the repository owner, or a configured immutable
GitHub user ID, as the authorization authority. The person deliberately
dispatching the workflow is the approver. In a personal repository this may
be the same person who prepared the Candidate; this is an owner
self-attestation, not an independent expert review or a second-person review.

GitHub Free does not offer protected branches or repository rulesets for
private repositories. The repository owner can change workflow code,
configuration, and policy, so this mode cannot technically prevent an owner
from bypassing or changing the gate. The policy checksum detects an
unintended mismatch only when its expected value comes from a separately
managed deployment setting. It is not a trust anchor against an owner who can
change that setting and the workflow. The owner is therefore the trust root
for this personal research prototype. Use the existing PR verifier when
effective protected review controls are available; do not reinterpret this
mode as equivalent to those controls.

The adapter verifies workflow run and repository identity using GitHub's
authenticated API, including numeric actor ID, repository ID, workflow path,
workflow-dispatch event, default branch, commit, run ID, and first attempt.
It rejects reruns. The dispatch inputs are confirmation/selection values,
not authorization: they must exactly match the locally verified registry
entry, Baseline ID, Candidate ID, Corpus SHA-256, and entry digest. The
Candidate or its metadata cannot supply the approver identity.

The P4.1 verifier and existing schema-2 reference checks are reused through
the read-only registration preflight. The result binds the Baseline and
Candidate IDs, Corpus hash, Release asset identities, source revisions,
source state, generation, build fingerprint, quality status, Q1 status,
Registry key/content hash, and the GitHub run identity. An existing key or
Baseline identity blocks another approval. This is a point-in-time decision;
future registration must rerun verification immediately before a compare-
and-swap update. Since this step does not mutate the Registry, atomic
single-use consumption and cross-run duplicate prevention are not claimed.

`QUALITY_REVIEW_REQUIRED` and the recorded Q1 status are copied unchanged.
Owner approval does not grant retrieval-quality acceptance, rerun Q1, alter
P8, or authorize production. The output always says
`registration: NOT_PERFORMED`, `registry_modified: false`, and
`production_promotion: NOT_AUTHORIZED`. The JSON output is not signed and is
not a bearer approval; a future writer must execute verification and
registration in the same trusted job/process or independently reverify all
GitHub evidence and Registry state.

## Deployment policy

`configs/github_owner_manual_approval_policy.schema.json` defines the
versioned deployment-specific policy. No real repository or approver policy
is checked in. For a personal repository, set `allow_repository_owner` only
when the owner is intentionally the approver. For an organization, list
explicit numeric user IDs in `authorized_approver_ids`; organization
ownership does not authorize its members. Migration to another repository
requires new repository ID, workflow path, policy pin, approver configuration,
and explicit reauthorization.

Pass the policy SHA-256 separately from the policy file. In a Hosted workflow
the expected pin must come from deployment configuration, never a dispatch
input or Candidate package. With a single owner on GitHub Free, that setting
is an accidental-change guard, not protection against the owner.

## Minimal manual workflow shape

The future dedicated workflow should be `workflow_dispatch` only, run from
the configured default branch, and use only read permissions:

```yaml
on:
  workflow_dispatch:
    inputs:
      registry_key: { required: true, type: string }
      baseline_id: { required: true, type: string }
      candidate_id: { required: true, type: string }
      corpus_sha256: { required: true, type: string }
      registry_entry_sha256: { required: true, type: string }
permissions:
  actions: read
  contents: read
```

After obtaining the exact, already P4.1-qualified Baseline package and
proposed entry from an immutable, verified input source, the job should run
`scripts/verify_baseline_owner_approval.py` with the five dispatch values
above and the pinned policy/reference/build-policy hashes. It must set
`GH_TOKEN` to the run's `GITHUB_TOKEN`, print the JSON decision, and stop.
Do not grant `contents: write` in this approval-only step.

This repository does not yet have a configured P4.1 Baseline input transport
for a dedicated manual workflow, nor a real deployment policy/pin. Therefore
this change adds the verifier and workflow contract documentation, not an
enabled Hosted workflow. Those inputs must be prepared and independently
checked before workflow integration. The existing PR workflow remains
separate and unchanged.

## Local invocation contract

The CLI is intended to run inside the dedicated workflow because it obtains
run ID, attempt, actor ID, branch, SHA, and dispatch event inputs from
GitHub-provided runtime context. It does not accept an approver ID or run
identity as command-line flags:

```bash
GH_TOKEN="$GITHUB_TOKEN" python3 -B scripts/verify_baseline_owner_approval.py \
  --policy configs/<deployment-owner-policy>.json \
  --policy-sha256 "$OWNER_APPROVAL_POLICY_SHA256" \
  --baseline "$VERIFIED_P41_BASELINE_DIR" \
  --registry configs/ci_v2_schema2_trusted_baselines.json \
  --registry-key "$REGISTRY_KEY" \
  --entry "$PROPOSED_SCHEMA2_ENTRY" \
  --expected-reference-sha256 "$REFERENCE_SHA256" \
  --expected-build-policy-sha256 "$BUILD_POLICY_SHA256" \
  --q1-status "$Q1_STATUS"
```

Exit status is `0` only for `OWNER_APPROVAL_VERIFIED`, otherwise `1` with
machine-readable `BLOCKED` JSON. Even on success, registration remains
`NOT_PERFORMED`. A later mutation step requires a separate implementation and
review, exact registry compare-and-swap, immediate revalidation, and explicit
write authorization.
