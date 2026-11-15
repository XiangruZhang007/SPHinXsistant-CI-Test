# Controlled historical Candidate archival

This separate manual operation archives an already completed first-attempt
research build. It does not reuse the original build's authorization to publish.
It neither registers a Parent nor changes P4.1, retrieval-quality acceptance, Q1,
P8, future build authorization or production promotion. The existing same-run
publisher remains unchanged; only `prepare()` gains an optional repository
argument with its original default preserved.

## Trust and deployment contract

The supported entry point is `python -B scripts/archive_historical_candidate.py`
with **no arguments**. Missing deployment pins fail closed before network access.
There are no token, actor, arbitrary upload directory or approval CLI switches.
Do not run it for real publication until separately authorized.

This is a maintainer-governed GitHub Free private research model, not independent
expert review or cryptographic process attestation. Trust starts with reviewed
workflow/code, independently maintained repository Variables and configuration,
and the maintainer's explicit dispatch of the complete reviewed subject.
Environment/event strings and API responses alone do not establish execution
authority. An account able to change code and deployment pins can change this
trust root. Local mocks do not establish real Hosted authorization.

Commit reviewed policy and request JSON under `configs/`; no real configuration
is supplied by this implementation. Configuration must contain exactly the fields
below, with no duplicate fields or non-finite values. The request and policy
cannot originate in the Candidate itself.

| Document | Exact fields |
| --- | --- |
| Deployment | `schema_version` (integer 1), `repository`, `repository_id`, `default_branch`, `workflow_path`, `implementation_revision`, `request_path`, `request_sha256`, `policy_path`, `policy_sha256` |
| Policy | `schema_version` (integer 1), `purpose`, `enabled`, `repository`, `repository_id`, `default_branch`, `workflow_path`, `allow_repository_owner`, `authorized_approver_ids` |
| Request | `schema_version` (integer 1), `purpose`, `original`, `candidate`, `assets` |
| Request `original` | `workflow_path`, `branch`, `run_id`, `run_attempt`, `head_sha`, `candidate_job_id`, `artifact_id`, `artifact_name`, `artifact_size`, `artifact_sha256` |
| Request `candidate` | `candidate_id`, `corpus_sha256`, `upstreams` (exact `SPHinXsys` and `SPHinXsim` commits) |
| Request `assets` | Exactly `candidate.tar.gz`, `research-evidence.tar.gz`, `release-manifest.json`, each containing only `size_bytes` and `sha256` |

Both purposes must be `HISTORICAL_CANDIDATE_ARCHIVAL`. Policy `enabled` must be
true. All numeric identities/sizes are positive integers. Original attempt must
be integer 1. SHA-256 values are lowercase 64 hex characters without a prefix;
commits are exact lowercase 40 hex characters. Candidate IDs retain `sha256-`.
Policy and deployment repository, numeric ID, default branch and archival
workflow must match. The archival workflow path is
`.github/workflows/ci_v2_historical_archive.yml`; the original workflow is
`.github/workflows/ci_v2_manual_research.yml`. Original branch must match the
configured default branch; original Artifact name is `ci-v2-research-RUN-1`.
Requests and policies must be tracked regular files at safe relative `configs/`
paths. Symbolic-link traversal is rejected.

Configure only after independent maintainer review:

- `HISTORICAL_ARCHIVE_DEPLOYMENT_JSON`: the exact reviewed deployment JSON bytes.
- `HISTORICAL_ARCHIVE_DEPLOYMENT_SHA256`: SHA-256 of those exact UTF-8 bytes,
  including any newline. This pin is stored independently of dispatch inputs.
- Deployment request/policy pins: SHA-256 of the exact tracked file bytes.
- `implementation_revision`: reviewed archival commit at the current default
  branch HEAD. Pins live outside the commit to avoid a self-referential hash.

Use `archival_subject(deployment, request, verified_manifest)` to compute the
reviewed subject and digest **after** independently checking original evidence
and deterministic preparation. The helper is pure and grants no authority.
Canonical subject serialization is compact sorted JSON plus a trailing newline.
Dispatch has one input, `archival_subject_sha256`, which must match this digest.
The subject binds original run/attempt/job/Artifact, Candidate/corpus/upstreams,
all three expected asset sizes and hashes, repository identity, request/policy
pins, reviewed implementation revision, Release tag and target commit.

No example containing invented production-like Release or Asset IDs is supplied.
No real C2 requests/assets were created during implementation. A new independently
reviewed deployment and dispatch are required when moving to another repository;
authority does not migrate with the source code.

## Verification and publication

1. Check independent pins, reviewed tracked checkout and runtime binding. Query
   GitHub for the current dispatch actor's immutable user ID, triggering actor,
   run/attempt, workflow and current default HEAD. Require the personal owner or
   a policy-designated ID. Organization membership alone grants no authority.
2. Independently query the original run and attempt: completed/success, exact
   commit/repository/workflow/branch and no rerun history. The attempt-specific
   jobs endpoint must contain exactly one successful `candidate` job with the
   expected job ID. More than 100 jobs/incomplete inventories are unsupported.
3. Query the exact original Artifact and verify its pinned ID/name/size/digest
   and repository/run/commit bindings. Timestamps corroborate the first-attempt
   association; names/timestamps alone do not authorize it. Expired, unavailable
   or rerun-ambiguous evidence blocks, with no local substitute.
4. Download the original ZIP using the project's existing `gh api` mechanism,
   with a fresh temporary gh config, token only in the child environment,
   suppressed stderr/debug output, and bounded download time/bytes. This requires
   the runner's existing `gh` executable; it installs no dependency. The Release
   downloader's restricted CDN allowlist is deliberately not broadened for
   Actions ZIP redirects.
   Check its independently pinned hash/size, bounded CRC-checked extraction,
   canonical regular paths, no links/duplicates/traversal/encryption. Reuse
   `prepare()` for complete sealed evidence, Candidate/archive equivalence and
   recorded parity/replay bindings. This verifies archived evidence; it does
   **not** execute a new replay or claim fresh R2 verification.
5. Compare all three prepared asset bytes to independent request pins. Preserve
   original `candidate.tar.gz` bytes and original build commit in the manifest.
6. Recheck pins, checkout, actor, default HEAD, original bindings, staged bytes
   and complete subject before Draft creation and again before Publish.
7. Refuse any existing tag or Release. Create Draft, upload exactly three assets,
   verify their IDs, names, sizes and hashes, recheck Draft inventory, then publish.
   Missing GitHub asset digests require a credential-safe download/hash check
   against the independently pinned local bytes; missing evidence never passes.
8. Require final immutable Release, exact asset identities/digests and Git tag
   target. Only lightweight tags directly pointing to the reviewed archival
   commit are supported; annotated tags are rejected.

The deterministic tag is
`ci-v2-historical-run-RUN-attempt-1-artifact-ARTIFACT-CANDIDATE8`.
It points to the reviewed **archival implementation commit**, while the sealed
manifest retains the original **build commit**. No original timestamps or build
identity fields are rewritten.

The workflow needs only job-scoped `contents: write` and `actions: read`, using
its same-repository `GITHUB_TOKEN`; it neither needs a PAT nor grants workflow
write permission. GitHub requires additional workflow permissions if the Release
target changes workflow files relative to the current default branch. This path
requires target == reviewed current default HEAD and rechecks that invariant.
A concurrent branch change or permission restriction can still cause API refusal;
the tool fails closed without broadening credentials.
See [GitHub Release API](https://docs.github.com/en/rest/releases/releases),
[run/attempt API](https://docs.github.com/en/rest/actions/workflow-runs),
[job API](https://docs.github.com/en/rest/actions/workflow-jobs) and
[Artifact API](https://docs.github.com/en/rest/actions/artifacts).

## Failure states and audit retention

| State | Meaning |
| --- | --- |
| `BLOCKED_BEFORE_PUBLICATION` | No Release mutation was attempted by this invocation; a conflicting existing Release may still exist. |
| `DRAFT_CREATED_NOT_PUBLISHED` | API evidence establishes an unpublished Draft; partial assets may remain. |
| `PUBLISHED_BUT_UNVERIFIED` | Publication is established but complete immutable/tag/asset verification has not succeeded. |
| `PUBLICATION_STATE_UNKNOWN` | A remote write may have occurred; read-back could not establish its outcome. |
| `PUBLISHED_IMMUTABLE_VERIFIED` | Final Release, three assets and exact tag target were verified. |

No remote mutation is retried automatically. Before Create/Patch, set the state
to unknown; lost responses trigger read-back only. A failed HTTP response is not
proof of no write. Do not rerun a failed job blindly: inspect the exact recorded
tag/Release first. A Draft is not repaired or reused automatically. A final
verification error never deletes an existing Release.

The CLI prints only credential-free JSON. Exit 0 requires verified publication
**and** successful local audit persistence; all other outcomes exit 1. Errors
after publication preserve actual publication state. Owned download/preparation
directories are removed on normal Python unwinding; hard process termination
relies on the ephemeral Hosted runner's lifecycle.

Only the separate audit directory under
`RUNNER_TEMP/historical-archive-RUN-ATTEMPT/` is uploaded, never a fourth Release
asset. It contains original/current operation identities, actor ID, independent
pins, full subject, Release/Asset IDs/digests and quality restrictions in
`result.json`, plus `checksums.json`. Local files and directory entries are
fsynced. Treat a receipt as complete only with matching checksums and successful
step outcome. If persistence fails, stdout and best-effort `audit-error.json`
retain the real state; the job remains unsuccessful. Audit upload is a separate
step: its failure also fails the workflow and does not undo publication.

The Actions audit Artifact expires after 30 days. After any real operation, the
operator must separately download and checksum-verify the complete audit Artifact
and preserve it in an access-controlled, backed-up permanent research directory
before expiry. Record that independent copy's path/checksum outside the Release;
Actions retention alone is not permanent archival. Failure before an output
directory exists is recorded in step JSON/logs rather than a fabricated receipt.

## Remaining acceptance requirements

Offline synthetic tests are not Hosted publication acceptance. Still required:
review/commit/deploy this implementation, prepare and review actual deterministic
asset/request/policy pins, authorize historical disclosure/storage and the exact
publication operation, configure independent Variables, ensure original Artifact
availability/private Release immutability and token permissions, then separately
authorize a real manual dispatch. No genuine asset generation, publication,
registration, R2 or Corpus build is performed by the implementation task.
