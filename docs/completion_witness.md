# Automatic completion discovery under reviewed repository authority

This is an offline-tested implementation for the personal private research
repository. No deployment, GitHub setting, Variable, Release or schedule was
enabled. Successful archiving never grants research approval, Trusted Parent
eligibility, P8 approval, Q1 qualification or production authorization.

## Independent trust and its limits

Deployment schema **4** adds `completion_authority` to schema 3's exact fields.
The existing independently retained SHA-256 of
`CONTINUOUS_BUILD_DEPLOYMENT_JSON` authenticates this authority. It must be
reviewed and installed by the maintainer outside Candidate output. It is a
versioned deployment setting, not another Registry or approval framework.

The closed authority object has these fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer 1 |
| `trust_model` | `MAINTAINER_GOVERNED_RELEASE_WRITERS` |
| `workflow_id` | Actual reviewed Workflow's positive numeric API identity |
| `publisher_actor_id` | Actual GitHub Actions bot's immutable numeric API identity |
| `release_prefix` | Reviewed namespace matching the pinned scheduled policy |
| `previous_producers` | Up to 32 explicitly reviewed previous deployments |

Each previous producer is exactly `implementation_revision`,
`deployment_sha256`, `execution_contract_sha256`. No duplicate commits, boolean
IDs, arbitrary authority modes or unknown fields are accepted. The current
deployment is implicitly eligible; its actual independent deployment digest is
required when checking its package. Previous producer commits require retained
deployment and contract pins from independent review, never from a receipt.

This model explicitly trusts GitHub's API/authentication/immutability and the
maintainers, administrators and **all accounts and workflows able to write
Releases in the repository**. The maintainer must review that writer set and
ensure every lifecycle writer follows the reviewed serialization convention.
The shared GitHub Actions bot ID and `contents: write` do not technically restrict
a token to one job or Release namespace. An administrator or another trusted
writer that deliberately forges a matching receipt is outside this model.
There is no claim that the Free private repository enforces exclusive publishing
authority or cryptographically links an asset to a job.

The independent anchor is the reviewed deployment's delegation to these
repository writers and exact producer versions. API asset digests authenticate
download consistency **under that delegation**; they are not independent
cryptographic producer attestations. Merely discovering a digest on a Release
without this delegation remains insufficient. If the maintainer cannot accept
this writer trust, retain schema 3's independent receipt-pin mode and keep
unattended repeat handling BLOCKED. No token scope or remote permission was
broadened by this implementation.

Official evidence: [Release API metadata and repository permissions](https://docs.github.com/en/rest/releases/releases),
[attempt-specific Job API](https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run-attempt),
[GitHub least-privilege guidance](https://docs.github.com/en/actions/reference/security/secure-use).
Those API contracts do not constitute a producer attestation.

## What a subsequent run verifies

The consumer first executes the existing clean-checkout, pinned implementation,
live run/actor/default-branch, pinned policies, remote Registry, exact detector
and selected-Parent checks. After verifying workflow mutual exclusion it checks
the stable execution tag again. Receipt hashes are not rewritten into deployment
Variables after builds. `completion_witness` may remain null in schema 4.

For a published completion the verifier then:

1. Re-reads the numeric immutable Release, exact stable tag, asset inventory,
   publisher/uploader IDs, asset API digests and unchanged download bytes.
2. Resolves the producer commit against the independently authorized current or
   previous deployment, checks private repository ID/name, Workflow ID/path,
   original first Attempt and the successful build Job.
3. Checks that the historical publication run and unique publishing Job finished
   successfully, and that build/publish/asset timestamps have a consistent order.
   The immutable tag's Git commit must equal the approved producer commit.
   Release `created_at` is deliberately excluded from event ordering: GitHub
   documents it as the target commit's date, rather than draft/publication time.
   Publication uses `published_at`; uploads use asset timestamps.
4. Verifies the receipt -> manifest -> full package digest chain, the independent
   producer deployment/contract pins, applicable scope/Registry pins, Candidate,
   Parent, source, generation, full parity, frozen R2 rescoring and sealed replay
   evidence with the existing package verifier.

Only this returns `PUBLISHED_AND_VERIFIED` / `NO_BUILD`. Results explicitly say
`cryptographic_producer_attestation: false`, `SEALED_REPLAY_INSPECTED`,
`research_approval: NOT_GRANTED`, `production_promotion: NOT_AUTHORIZED`.
No fresh R2 replay is implied by completion inspection.

The producer and consumer may have **different commits**. The test uses a new
reviewed consumer checkout, a distinct current API Run and an explicitly retained
producer deployment pin. Automatic inspection currently requires an unchanged
execution contract; a previous different verifier contract is rejected with
`HISTORICAL_PRODUCER_ORIGINAL_VERIFIER_REQUIRED`. Such packages remain verifiable
through the corresponding original reviewed checkout and original pins. No
arbitrary historical code is downloaded or executed automatically.

The stable execution key is unchanged. It excludes Run-specific Candidate IDs,
completion pins and the current deployment's raw JSON digest, while binding the
repository ID, selected Parent/reference/package, exact detected revisions,
scope/Registry/scheduled-policy and execution-contract digests. A code or relevant
build-policy change creates a different execution identity; merely accepting a
reviewed compatible previous producer does not.

## Publication, cancellation and recovery

The existing publisher still validates a completed successful **build Job** while
the same workflow/publishing Job may be in progress. Its final local verification
uses the freshly prepared, retained receipt digest. The new historical-consumer
path waits for the publishing Job to finish; it is not used as a prerequisite for
that same Job's own publication.

There is no atomic transaction between GitHub publication and local reporting.
A lost response with a subsequently successful publisher can be rediscovered and
fully verified by a later run. If the publisher or overall historical run failed,
automatic adoption is BLOCKED with an explicit manual-recovery reason. Existing
read-only verification with an independently retained receipt digest can inspect
the immutable bytes but never manufactures a successful publishing Job.
If GitHub Run/Job metadata has become unavailable or was deleted, automatic
verification also fails closed; immutable storage alone does not replace it.

Drafts, reservations, tags alone, failed or partial uploads and expiring Actions
Artifacts do not count as completion. Draft resolution remains a separately
authorized human operation. No automatic deletion, overwrite or draft repair is
added. Original build Artifact ZIP API integrity remains mandatory when publishing.

The repository-wide reviewed workflow concurrency group spans build and publish;
the completion check is repeated after that group has been established and again
before publication. It is not a distributed lease against outside writers, FIFO
or exactly-once execution. No new lock service or signature scheme is introduced.

## Controlled Hosted acceptance: Option A

The smallest supported route deliberately retains **two distinct paths**:
manual construction, and publication from a real scheduled execution. Manual
dispatch does not archive automatically. The publisher Job and CLI remain
schedule-only. No fake `schedule` event or new manual publishing authorization is
introduced. Hosted acceptance must exercise both paths before calling the full
loop verified.

After separate deployment authorization in the personal repository:

1. Review and deploy the exact implementation commit on its default branch.
   Preserve the registered `upstream_refresh.yml`, its root concurrency and
   pinned Actions, ARM runner, Python 3.12.3 and frozen parser requirements.
   Review the old Owner build policy, Continuous scope, Registry, evaluated Parent
   and enabled scheduled build/publication policy. No format compatibility with
   future P4.1 approval is implied for Genuine V3.
2. Obtain actual repository, Workflow and bot IDs through read-only API queries.
   For example, using the already authenticated CLI and a shell variable holding
   the personal repository name:

   ```bash
   gh api "repos/$CI_REPOSITORY" --jq '{id,full_name,private,default_branch}'
   gh api "repos/$CI_REPOSITORY/actions/workflows/upstream_refresh.yml" --jq '{id,path,state}'
   gh api 'users/github-actions[bot]' --jq '{id,type}'
   ```

   An observed bot ID is an identity pin, not proof that only this workflow can
   use it. Verify Release immutability and the accepted writer/concurrency model.
3. Prepare schema-4 deployment JSON outside generated output, including the
   reviewed implementation commit, newly measured execution-contract digest,
   all original policy/Registry pins and the authority above. Independently
   review its bytes and SHA-256 before setting
   `CONTINUOUS_BUILD_DEPLOYMENT_JSON` and
   `CONTINUOUS_BUILD_DEPLOYMENT_SHA256`. The policy paths must be reviewed,
   tracked `configs/*.json`; do not copy mock fixtures or invent IDs/pins.
4. Keep `CONTINUOUS_CONSTRUCTION_ENABLED` and
   `CONTINUOUS_PUBLICATION_ENABLED` unset/false until a controlled scheduled
   acceptance is independently authorized. All nonpublishing jobs retain
   `contents: read`; API consumers additionally require `actions: read`. Only
   `publish-continuous-candidate` has `contents: write/actions: read`, and its
   step receives `GH_TOKEN` through the existing `GITHUB_TOKEN`. No cross-repo
   credential, token CLI argument, new Secret or global write permission is needed.
5. Independently authorize a **manual construction** acceptance. A future command,
   not executed here, is:

   ```bash
   gh workflow run upstream_refresh.yml --repo "$CI_REPOSITORY" --ref "$REVIEWED_BRANCH" \
     -f build_ci_v2=false -f build_continuous_ci_v2=true
   ```

   Verify its real dispatch/Owner context, exact detected source SHAs, Parent,
   package/parity/R2 and preserved restrictions. Expect no publishing Job. Manual
   construction alone does not test durable publication or automatic duplicates.
6. With distinct scheduled-operation authorization, install the two operational
   flags and allow the existing weekly cron event to run. Confirm the actual
   event is `schedule`, first Attempt, the reviewed commit and successful build
   and publisher Jobs. Verify immutable Release and all three assets through
   authenticated API reads and full package validation. Do not claim this from
   a manual Run or the green workflow conclusion alone.
   Restrict enablement to the separately authorized acceptance window; keeping
   unattended operation enabled afterwards requires its own acceptance decision.
7. On a subsequent real scheduled run **with unchanged detected target, Parent
   and relevant contracts**, expect `NO_BUILD` and verified producer/consumer
   evidence without any completion hash Variable update. If the official source
   advanced, expect a new authorized execution key; do not substitute old SHAs
   into detector output to manufacture a repeat. Test a new revision only when
   the existing scope authorizes its authentic ancestry and bounded changes.
8. Inspect sanitized preflight/build/publication receipts, original step outcomes,
   API Job identities and immutable assets for blocked/interrupted runs. Do not
   retry publication blindly. Keep full unattended activation disabled until
   these real Hosted cases, writer coverage and cancellation behavior are accepted.

No commands in this checklist were executed against GitHub by this task.

## Local validation and preservation

The pre-change implementation was committed locally as
`4665108277bb24e4cfb8b83be00b5ecb5de6350a` after **315 tests passed in 283.352s**.
It contains exactly the reviewed ten files; its parent is
`15be431d09a655bc5960f64256b1d3fd9a4e3121`.

Exact pre-change V3 tracked sources, a 280-file SHA-256/size inventory and original
contract are in ignored `doc/artifacts/genuine-v3-preserved-3rrg6e4k/`.
Source reconstruction matched
`8bc29d86ebe52638c56020bce474a0d935c3ad8610f9998edf1b861451bd2602`.
An explicitly controlled miniature V3 package, full evidence and original
verification inputs were also preserved there and reverified using original
source and pins after current code changed. This is not a new genuine C1/C2 run.
Previous V1/V2 checkouts separately passed their original miniature fresh replay
and offline verification tests (two each); no historical asset or pin was changed.

Run the documented full suite from `docs/continuous_execution.md` with
`test_continuous_lifecycle test_genuine_continuous_execution
test_owner_manual_baseline_approval test_scheduled_construction
test_completion_witness` appended, using the frozen interpreter,
`PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH=tests`.
The new suite reuses real miniature construction/parity/frozen R2 and package
verification. GitHub API/authentication/publication are mocks, never real Owner
approval or Hosted evidence. No real C1/C2 reconstruction or R2 was executed.

Remaining external requirements are `EXTERNAL_AUTHORIZATION_REQUIRED` for
reviewed deployment/policy/writer trust/enablement and `HOSTED_VALIDATION_REQUIRED`
for actual storage, publishing and concurrency acceptance. Interrupted failed
publication/draft resolution is `MANUAL_RECOVERY_REQUIRED`. A cross-contract
automatic old-verifier dispatcher is intentionally absent; those packages need
their retained original verifier. The prior per-build witness integration gap is
closed only under the explicitly accepted schema-4 repository trust model.

## Final recorded local result

| Check | Result |
| --- | --- |
| Pre-change full regression | 315 tests PASS, 283.352 seconds |
| Final new witness module | 16 tests PASS, 51.038 seconds |
| Final full regression | 331 tests PASS, 332.754 seconds |
| Original V1/V2 source tests | Two each PASS with original implementation |
| Preserved original V3 package | PASS with original code and retained pins, sealed inspection only |
| Compilation / YAML / 29 shell blocks / embedded Python / whitespace | PASS |
| C1, P2/P3/P4.1/R2, controlled V1 and lifecycle contracts | UNCHANGED |
| Other checkpoint files | 276 byte inventories unchanged |
| Registry / policies / runtime lock / benchmark / existing research assets | UNCHANGED |
| Real Hosted validation / deployment / Releases / registration / production | NOT_PERFORMED |

An intermediate focused run was invalidated when implementation bytes were
edited while tests were running; its contract mismatch is not counted as final
acceptance. The final focused and full runs above used fixed implementation
bytes. Earlier fixture-only failures in the mocked tag/Parent download adapter
were corrected before final validation, without changing production gates.

Current measured execution contract:
`12e0591896d03f198056c42c32f92a4b31ce526f4458366bb3fb9d09f81a8b79`.
This is an observation, **not an independently authorized deployment pin**.
The pre-change V3 contract and sealed fixture were not rewritten or repinned.

Post-checkpoint changes are intentionally **uncommitted**:
`src/continuous_completion.py`, `src/genuine_continuous_execution.py`,
`src/scheduled_construction.py`, `tests/test_completion_witness.py`,
`docs/completion_witness.md`, `docs/scheduled_construction.md`.
Index is empty; remotes/upstream are unchanged. No Push, Actions execution,
personal repository API mutation, Release publication or professor-repository
access occurred. Actual schedules/publication remain unconfigured here.

Local implementation status: **READY_FOR_CONTROLLED_HOSTED_ACCEPTANCE** under
the documented writer trust assumptions. Real Hosted operation remains
**BLOCKED** pending independently authorized configuration and actual acceptance.
`QUALITY_REVIEW_REQUIRED`, `Q1_NOT_QUALIFIED_FOR_VERSION_PAIR`, P8 `BLOCKED` and
production `NOT_AUTHORIZED` are preserved.
