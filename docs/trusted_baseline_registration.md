# Trusted research Baseline registration preparation

This step adds a **read-only, fail-closed preflight** for a proposed entry in
the existing schema-2 registry. It does not register a Baseline. The registry
file is read only and remains unchanged.

## Existing contract and trust boundary

The registry entry reuses the existing schema in
`configs/ci_v2_schema2_trusted_baselines.json`: `build_policy_path`,
`build_policy_sha256`, `expected_reference_sha256`, and `reference`. The
preflight calls the existing reference, release-locator, build-scope, and
P4.1 Baseline validators. The proposed reference and policy hashes must also
be supplied independently on the command line.

P4.1 proves that the archived Baseline satisfies its existing research
qualification contract. Its local `authorization.json` is not an independently
authenticated registration decision. The current `research_review.py` output
is diagnostic only; `candidate_promotion_policy.py` has no configured real
approval authority. Therefore this implementation never consumes an
`approved: true` JSON as registration authority and always reports
`BLOCKED` with `INDEPENDENT_REGISTRATION_AUTHORITY_NOT_CONFIGURED` after
successful evidence checks.

The read-only Step 2B adapter in `src/github_baseline_approval.py` verifies an
approval submitted through a GitHub Pull Request. It accepts only a separately
versioned policy whose SHA-256 is supplied independently, and checks the
repository's numeric ID, current PR state, exact Registry bytes and proposed
entry, P4.1 qualification, the reviewer's immutable numeric GitHub user ID,
review state and reviewed commit, plus effective branch-protection/ruleset
evidence. It never writes the Registry. The policy schema is
`configs/github_baseline_approval_policy.schema.json`; this is only a schema,
not a configured authority. No repository-specific policy is configured in
this worktree, so actual registration remains blocked.

The `--policy-sha256` value is an integrity pin, not proof of who authorized
that policy. A future trusted caller must obtain this pin from protected
deployment configuration that is independent of the PR and candidate. This
repository currently has no such configured pin. The emitted JSON is also not
cryptographically signed; a future registration gate must execute this
verifier from trusted code/configuration and consume its result in-process (or
independently verify the GitHub evidence again), never trust a copied result
file by itself.

For a personal repository, the policy may explicitly permit the GitHub API's
repository owner user ID. For an organization repository, organization
ownership does not authorize all members or administrators: approvers must be
listed by immutable numeric user ID. The PR author is always excluded from
approving their own proposal. The PR body carries a machine-readable binding
for the exact Registry key/entry, Candidate and Baseline IDs, Corpus SHA-256,
Release/asset identities, source revisions/state, generation, build
fingerprint, benchmark, quality/Q1 status and production restriction. The PR
must change only the configured Registry file; the base Registry must match
independently pinned bytes and the head Registry must match the independently
pinned proposed bytes. An approval counts only for the exact current PR head
SHA and is excluded if dismissed or superseded. Review/protection state is
re-read before returning, but this is still a point-in-time check: any future
mutating registration command must repeat verification immediately before a
compare-and-swap Registry update.

Technical verification, retrieval-quality acceptance, research Baseline
approval, and production authorization remain separate. A recorded
`QUALITY_REVIEW_REQUIRED` remains unchanged; an unqualified Q1 result is not
upgraded; `production_promotion` must remain `NOT_AUTHORIZED`. The preflight
cannot modify the registry, approve a Baseline, or activate a Corpus.

## Command

Provide an existing P4.1 Baseline directory and a JSON file containing one
proposed schema-2 registry entry. Supply reference and build-policy hashes
through separate arguments:

```bash
python3 -B scripts/prepare_baseline_registration.py \
  --key candidate-research-parent-<candidate-suffix> \
  --baseline /path/to/verified-research-baseline \
  --entry /path/to/proposed-registry-entry.json \
  --expected-reference-sha256 <independent-reference-sha256> \
  --expected-build-policy-sha256 <independent-policy-sha256> \
  --workflow-repository <configured-owner>/<configured-repository> \
  --workflow-repository-id <independently-verified-repository-id>
```

The preparation command above remains `BLOCKED` because it does not consume
GitHub approvals. The new read-only verifier is invoked separately:

```bash
python3 -B scripts/verify_baseline_pr_approval.py \
  --policy configs/<deployment-approval-policy>.json \
  --policy-sha256 <independent-policy-sha256> \
  --pull-request <open-pr-number> \
  --baseline <verified-p4.1-baseline-directory> \
  --registry configs/ci_v2_schema2_trusted_baselines.json \
  --registry-key <new-research-baseline-key> \
  --entry <exact-proposed-schema2-entry.json> \
  --base-registry-sha256 <independent-base-registry-sha256> \
  --proposed-registry-sha256 <independent-proposed-registry-sha256> \
  --q1-status Q1_NOT_QUALIFIED_FOR_VERSION_PAIR
```

The verifier prints JSON only. `BLOCKED` exits with status 1. Even
`GITHUB_APPROVAL_VERIFIED` reports `registration: NOT_PERFORMED`, leaves
`QUALITY_REVIEW_REQUIRED` and Q1 unchanged, and keeps production
`NOT_AUTHORIZED`. The Q1 value is bound into the PR as an explicit review
declaration; this adapter does not rerun Q1 or independently qualify that
label. The source Q1 evidence must remain available to the human reviewer, and
any future registration integration must verify its binding before consuming
the declaration. The policy file is deployment-specific, not checked in as a
real approval policy; migration to another repository requires new repository
and approver pins and independent reauthorization.

## GitHub settings and API access

The target default branch must require at least the policy's approval count,
dismiss stale reviews, require approval after the last push, enforce rules for
administrators, and expose empty review-bypass allowances. Any active matching
repository or inherited organization ruleset must be readable and have no
bypass actors. These checks prevent treating an unprotected direct push as an
approval. The tool does not change repository settings.

The authenticated `gh` identity needs:

- `Pull requests: read` for PR metadata, changed files and reviews.
- `Contents: read` for base/current/head Registry bytes.
- `Administration: read` for protected-branch settings.
- `Metadata: read` to query the effective rules for the configured branch and
  retrieve details of the applying rulesets. GitHub's rules API determines
  which rules actually apply, avoiding locally reimplemented wildcard
  matching. The adapter requires `bypass_actors` to be present in every
  applicable active ruleset detail; an omitted field is not treated as an
  empty list. GitHub documents that the detailed endpoint may hide
  `bypass_actors` unless the caller has write access to that ruleset. Do not
  grant write access merely to make this check pass: if the least-privilege
  caller cannot see bypass actors, approval verification remains `BLOCKED`.

GitHub documents private-repository branch-protection API availability for
Pro, Team and Enterprise plans. If plan support, permission, or an API response
does not establish the complete required settings, the verifier returns
`BLOCKED`. This implementation has not inspected or changed the target
repository's actual settings.

## Current state and remaining work

- Existing P2 and approved C1 registry entries are not edited.
- Candidate Release archiving does not itself create a trusted Baseline entry.
- No C2 approval or C2 Release is fabricated by this tool.
- Before actual registration can be enabled, configure and independently pin
  a deployment-specific approval policy with the target repository ID, default
  branch and authorized reviewer IDs; establish the required branch protection;
  and independently verify a PR approval in that repository. The adapter does
  not change registry contents, so the later registration step must be a
  separately reviewed operation that rechecks the approval and uses a
  compare-and-swap on the pinned base Registry SHA.
- The approval gate does not resolve retrieval quality. `QUALITY_REVIEW_REQUIRED`
  and `Q1_NOT_QUALIFIED_FOR_VERSION_PAIR` remain unchanged. A separate
  authorized quality review is needed to alter those findings under the
  applicable policy. Production remains `NOT_AUTHORIZED`.
