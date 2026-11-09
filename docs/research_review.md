# Manual research-review diagnostics

This interface verifies a **research review**, never a production approval.
It cannot remove P8 blockers, return `ELIGIBLE`, select a Corpus, initialize
Gradio, or approve a research baseline. The original P8/P9 interfaces are unchanged.
No real reviewer, Issue or comment is configured by this implementation.

## Trust anchor

An operator must independently designate a local regular JSON file directly in
the CI project's `configs/` directory, and supply its independently recorded
SHA-256. Artifact-supplied trust files and symlink configurations are rejected.
The operator, not the Candidate, controls this configuration and the command line.
Someone able to replace both that trust configuration and its independent pin
is outside this trust model. A checksum alone does not establish reviewer authority.

The complete configuration contract is:

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer `1` |
| `repository` | Exactly `XiangruZhang007/SPHinX_AI_Assistant` |
| `repository_id` | Independently verified GitHub numeric repository ID |
| `issue_number`, `issue_id` | Designated Issue number and numeric Issue identity |
| `comment_id` | One designated GitHub Issue comment ID |
| `reviewer_ids` | Nonempty, independently authorized numeric GitHub User IDs |
| `comment_sha256` | Independently pinned SHA-256 of the exact UTF-8 API `body` |
| `created_at`, `updated_at` | Pinned GitHub UTC timestamps ending in `Z` |
| `valid_until` | Operator-defined UTC expiry ending in `Z` |

V1 only accepts original, unedited comments: `created_at == updated_at`.
The local pins fix the intended record; authenticated live GitHub responses
establish its current existence, actual author and repository/Issue membership.
The author's numeric ID and account type come from the API, never from body text.
There is no automatic enrollment of a repository owner or administrator as reviewer.

## Review body

The comment body must be one JSON object, without a Markdown fence or extra text,
containing exactly these fields:

| Field | Required value |
| --- | --- |
| `schema_version` | Integer `1` |
| `kind` | `sphinxsistant-research-review` |
| `scope` | `RESEARCH_DIAGNOSTIC_ONLY` |
| `bindings` | Exact evidence projection described below |
| `decision` | `APPROVE_RESEARCH_REVIEW`, `REJECT`, or `REVOKE` |
| `reviewer_id` | Numeric ID equal to the authenticated API comment author |
| `reviewed_at` | UTC timestamp ending in `Z`, no later than comment creation |

Only `APPROVE_RESEARCH_REVIEW` can produce `RESEARCH_REVIEW_VERIFIED`.
The timestamp is authored before posting; it need not predict the server's exact
comment-creation second. Creation/update times and expiry are independently pinned.
Duplicate JSON keys, non-finite numbers, unsupported fields and unknown scopes
are rejected. This structured record is not itself the source of trust.

## Evidence projection

`bindings` retains existing CI identities; it introduces no replacement Candidate,
benchmark or evaluation identity scheme:

| Review binding | Existing source |
| --- | --- |
| `candidate_id` | Sealed `candidate/candidate.json`; independently checked by P8 |
| `corpus_sha256` | `quality/quality-report.json` and existing integration bindings |
| `build_fingerprint` | Same report and Candidate build identity |
| `benchmark_sha256` | `result.json.bindings.benchmark_sha256` and P8 |
| `upstreams` | Exact `SPHinXsys`/`SPHinXsim` commits in Candidate identity |
| `quality.quality_report_sha256` | Exact report bytes, bound by run/quality checksum inventories |
| `quality.raw_results_sha256` | Existing report identity of `quality/incremental-raw-results.json` |
| `quality.policy_sha256` | Existing report's canonical policy digest, not an invented file hash |
| `transport.repository`, `transport.repository_id` | Verified GitHub delivery metadata |
| `transport.run_id`, `transport.attempt`, `transport.artifact_id` | Verified outer transport identities |
| `transport.artifact_sha256` | Original ZIP bytes compared with the delivery's expected SHA-256 |

The verifier only runs against the complete original ZIP after the existing
integration has checked internal provenance. A verified GitHub transport is not
substituted for internal Candidate verification. The diagnostic JSON includes
the expected projection even if independent reviewer configuration is missing.

## Read-only current-state verification

The existing `gh` authentication is reused for explicit GETs to the personal
repository, designated Issue, designated comment and that Issue's comment list.
The verifier never searches other Issues or repositories. It checks all pages
of the designated Issue, including comments posted after the designated record.

Another structured review for the same Candidate from an allowlisted author
causes an unverified result, regardless of whether it approves, rejects or revokes.
There is no latest-review-wins rule or supersession mechanism. Rejected/revoked
designated records, missing records, edits, conflicts, expiry, incomplete lists,
and API errors fail closed. Additional reads detect changes during verification.
An unverified cache cannot replace live responses.

This is a point-in-time diagnostic, not an immutable GitHub attestation: later
edits or deletions cannot be prevented, and already deleted revocations cannot
be reconstructed from a current Issue listing. Revocation must use the structured
record in the designated Issue. Reverification is required for any later use;
saved diagnostic JSON is never an authorization token. GitHub and the independently
configured reviewer accounts remain trust dependencies.

## Integration and evidence

Existing artifact delivery needs no new arguments when no review is configured.
It continues to download, verify, register temporarily, and return the original
P8 decision. It now also saves `research-review.json` alongside the unchanged
`integration-result.json` in its permanent receipt directory.

Optional arguments to `python3 -B -m src.github_artifact_delivery` are:

```text
--research-review-config configs/<operator-reviewed-file>.json
--research-review-config-sha256 <independently-recorded-config-sha256>
```

Both are required together. No usable trust configuration or fake approval is
created automatically. Without one, the historical Run 41617493805 remains
`RESEARCH_REVIEW_UNVERIFIED` with `TRUST_CONFIGURATION_MISSING`, while P8 is
`BLOCKED`, activation is `DENIED` and Gradio is `NOT_ATTEMPTED`.

Even a verified research review leaves all original P8 reasons intact, including
`RELEASE_AUTHORIZATION_UNAVAILABLE`, `QUALITY_NOT_ACCEPTED`,
`UNRESOLVED_REGRESSIONS`, and `PRODUCTION_NOT_AUTHORIZED` where present.
Exit code `1` still denotes the blocked update. No production authorization or
activation path is provided. Tests use synthetic API responses, not real reviews.

Receipts store only bindings, hashes, numeric identities, relevant timestamps and
reason codes. They do not store complete comment bodies, author logins, tokens,
authentication output or signed download URLs. `doc/artifacts/` is permanent on
disk but gitignored; source commits do not automatically archive it.
