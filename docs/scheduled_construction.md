# Scheduled construction and immutable completion evidence

This is local implementation for controlled Hosted acceptance. Real scheduled
construction and publication remain disabled: no deployment policy, Variables,
Release, dispatch, approval or Registry update was performed.

## Versioned authorization

Deployment schemas 1/2 keep their manual/V2 behavior. Deployment schema 3 adds
`scheduled_policy_path`, `scheduled_policy_sha256` and `completion_witness` to
schema 2's closed field set. Paths must be tracked `configs/<name>.json` files;
all pins come from independently reviewed deployment configuration. No real
policy is installed by this task. `completion_witness` is either null or exactly
`{execution_key, receipt_sha256}` with two SHA-256 values. It is technical trust
input, not research approval or a second Trusted Baseline Registry.

The separate scheduled policy is version 1, operation
`SCHEDULED_CONTINUOUS_CANDIDATE_BUILD`. Its exact fields are
`scheduled_construction.FIELDS`: enabled, repository/name/numeric ID, workflow,
scope-policy and Registry pins, validity interval, safe Release namespace,
publication enablement, and explicit no-approval/no-registration/no-production
restrictions. The deployment binds implementation commit and code contract;
the pinned old scope binds official repositories, branches, bounded ancestry
and eligible evaluated Parents. A schedule actor is checked against actual
GitHub run metadata but is never called an approving reviewer.

This does **not** change the frozen scope grammar or globally flip its
`scheduled_execution: false`. That old read-only assessment remains in the
package. A scheduled Candidate uses `genuine-continuous-candidate-v3`, with
its own scheduled policy evidence and `scheduled_execution: true` as the actual
operation identity. Its remaining quality/approval/production restrictions are
unchanged. Manual Candidates retain the Genuine V2 format and restrictions.

The current executor still requires a clean reviewed checkout, independently
pinned deployment, actual first-attempt API identity, matching remote Registry,
exact detector bytes, selected-Parent comparison, clean official Git proofs,
current scope revalidation, genuine P4.1 Parent, mandatory fresh Parent R2,
incremental extraction, independent full parity and frozen Candidate/full R2
and independent replays. No exact-target policy is manufactured.

## Workflow boundary

The existing detector is unchanged. `continuous-candidate` retains the explicit
manual opt-in and adds a scheduled route conditional on **both** repository
Variables `CONTINUOUS_CONSTRUCTION_ENABLED == 'true'` and
`CONTINUOUS_PUBLICATION_ENABLED == 'true'`. Unset Variables disable it. The
executor separately requires those flags and the enabled, pinned scheduled
policy; flags alone cannot authorize execution. Real enablement requires
independent maintainer review and a separately authorized Hosted acceptance.

Workflow-level `ci-v2-continuous-lifecycle-<repository_id>` concurrency spans
all jobs from detection through publication, with `cancel-in-progress: false`.
This also serializes the timing of existing V1/manual runs of this workflow;
their extraction, retrieval and exact-target execution steps are unchanged.
The executor checks that the reviewed pinned workflow contains that exact
top-level concurrency declaration before checking durable evidence. It does
not infer a distributed lease from environment variables. This guarantee is
conditional on the reviewed GitHub workflow and all relevant writers using
that group; it does not defend against administrators or unrelated writers.

GitHub concurrency is not durable deduplication, FIFO or exactly-once execution.
GitHub documents limited pending/running groups and cancellation of older
pending runs. A cancelled operation is not a completion and a later detection
may retry. [Official concurrency documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)

Only `publish-continuous-candidate` receives `contents: write`; it also needs
`actions: read`. Build and preflight jobs retain `contents: read/actions: read`.
The publisher requires the completed build job and `candidate_built == true`;
NO_UPDATE/NO_BUILD cannot start publication. Publication remains default-disabled.
No global write permission, token arguments or stored secrets are introduced.

## Candidate archiving

`continuous_completion.Client` reuses the existing safe Release API, exact upload
URI-template validation and uploaded-asset verification without changing the
frozen Schema-2 publisher. Repository identity is deployment-specific.

`publish_continuous_candidate.py` independently obtains the original build
Artifact ZIP through the existing bounded gh download and safe ZIP extraction
helpers. It checks actual private repository/run/attempt/workflow/completed
`continuous-candidate` Job identity, exact Artifact name, API digest and original
ZIP bytes before deriving package pins. The overall workflow may still be in
progress: its publisher has not finished. The completed build job is the success
boundary, not the entire same-run workflow.

`prepare()` then verifies the actual full Candidate package with external pins,
compares the transport archive byte-for-byte with the extracted package,
validates Full Parity, frozen R2/rescoring/saved replay, generation, source state,
Candidate/Parent/Corpus identities and origin bindings. This is sealed replay
inspection, not a fresh real R2 execution. The version-aware archive contains:

- `candidate.tar.gz`: unchanged complete sealed package including all evidence.
- `release-manifest.json`: format, Candidate/Parent/generation/source revisions,
  Corpus identity, stable execution key, original verification pins, payload
  digest/size, actual build identity and preserved restrictions.
- `completion.json`: BUILD_VERIFIED receipt binding the manifest digest and
  actual build origin. It does not prematurely claim immutable publication.

Assets are published through draft -> upload/verify -> recheck -> publish ->
verify immutable Release and re-download/verify the full Candidate. The final
result records real Release/asset IDs and sizes and the receipt digest. The
stable tag is namespace + full execution key. Existing tags, immutable Releases
and drafts are never overwritten or deleted. API errors or partial uploads stop
with the draft retained. No new approval, Baseline or Trusted Registry entry is
created. Source snippets/evidence remain private; no assets were uploaded here.

## Completion states, duplicates and recovery

| State | Meaning |
| --- | --- |
| NOT_STARTED | Exact completion tag lookup returned absent; not proof against arbitrary concurrent external writers. |
| BUILDING | Current live build job; no reservation is a completed record. |
| BUILD_VERIFIED | Sealed package passed verification, build job succeeded. |
| PUBLISHING | Draft/partial upload; never a duplicate to skip. |
| PUBLISHED_AND_VERIFIED | Independent receipt witness + immutable assets + real successful build identity + actual package verification all match. |

After the workflow mutex is established, the executor rechecks the exact
completion tag. Only PUBLISHED_AND_VERIFIED returns NO_BUILD. A draft does not
suppress a retry build; publication of that retry is blocked on explicit draft
resolution rather than changing someone else's partial assets. Failed,
cancelled or skipped jobs cannot qualify as completion.

The publisher rechecks the completion tag after build and before mutation, and
revalidates the build, deployment, authority, policy expiry and workflow group
before publishing. There is no claim that an API PATCH and a local receipt
write are atomic. If publication succeeds but the response/final check is lost,
the result is unconfirmed, not success. Read-only `verify_completed()` with the
independently retained receipt pin can establish the actual immutable state;
it is idempotent and never changes a Registry or rewrites an asset. Draft
recovery requires separate review; this task does not grant deletion authority.

## Deliberate unresolved trust boundary

A Release/manifest/asset ID is not independent construction authority. The
duplicate verifier requires an independently retained completion receipt hash,
then checks live repository/run/workflow/attempt/successful job identity, exact
stable key and immutable assets and revalidates the complete sealed package.
No internal checksum is promoted to independent trust by the lookup code.

For this prototype the witness may be independently pinned in the reviewed
deployment. Changing that witness does not change the stable execution key.
The publisher returns it after successful verification, but **does not update
the deployment itself**. Automatic independently trusted witness distribution
is not implemented. Finding a published archive without a witness is BLOCKED
(`INDEPENDENT_COMPLETION_WITNESS_REQUIRED`), never guessed to be a duplicate or
silently rebuilt over the immutable tag. Thus fully unattended repeat handling
is not operational yet. This is a missing trust-input integration, not a claim
that GitHub Releases cannot store the bytes durably.

Optional native artifact attestations were not introduced: GitHub documents
that private-repository attestations require Enterprise Cloud. This does not
make a paid upgrade a requirement for the existing owner-reviewed prototype;
independent pin review remains possible. No homegrown signature or new approval
framework was substituted. [Official attestation availability](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)

Before real activation, resolve the independent witness workflow, confirm the
reviewed group covers every completion writer and interrupted publication,
configure reviewed policies/pins/permissions, and perform genuine Hosted
acceptance. All real schedule/publication switches remain unset here.

## Historical compatibility and offline validation

Before editing, the exact prior V2 checkout was preserved under
`doc/artifacts/genuine-v2-preserved-haj5dewd/`: tracked-source archive, five-file
overlay, binary diff and per-file sizes/hashes. Reconstruction independently
matched original V2 contract
`6d3c6ecb8115b083e1a947e4c81ddaee90427830de738934e1d18e5809ce01e1`.
V1 source remains in checkpoint `15be431d09a655bc5960f64256b1d3fd9a4e3121`.
Old sealed packages must use their original reviewed checkout and retained
pins. Current implementation bytes are not silently used to validate an old
execution digest. No original package is rewritten, regenerated or repinned.

Run the full regression command in `docs/continuous_execution.md`, appending
`test_continuous_lifecycle test_genuine_continuous_execution
test_owner_manual_baseline_approval test_scheduled_construction`.
The added tests use real miniature Git sources, extraction, full reconstruction,
R2/replay and package verification. Only GitHub/transport observations are
explicit fixtures. They cover schedule authorization/expiry/default disablement,
completed witness validation and skip, real retry build despite a draft,
upload interruption, corrupt assets, job failure/cancellation, repeat publication
refusal, read-only idempotent recovery and least-privilege Workflow gates.
These tests do not establish actual GitHub Owner authority or Hosted durability.

## Recorded local result

The full regression passed **314 tests in 272.422 seconds**. After the final
CLI Job-output failure guard, the two affected modules passed **57 tests in
149.079 seconds**, including the additional real-build/failed-output test.
The complete command now collects 315 tests; a single 315-test full run is not
claimed. All existing modules were covered by the full run, and the final CLI
change and new test were covered by the affected-module regression.

Original reviewed V1 and preserved V2 source checkouts separately passed two
miniature package/fresh-replay and offline-inspection tests each: **4 tests**.
The first attempt to run those tests from plain source archives could not start
because the harness needs Git metadata; isolated disposable Git repositories
were then initialized and the original-source tests passed. No project commit,
old asset, source bytes or independent verification pin was changed.

Actual miniature scheduled construction passed incremental/full parity and all
128 Candidate + 128 Full frozen combinations and independent replay. It reused
46 of 48 files / 45 chunks, re-extracted two and removed one. These are disposable
fixtures with mocked GitHub observations, not the real C1/C2 experiment.

Python compilation, YAML parsing, all Workflow Bash syntax, whitespace, frozen
runtime, historical C1, Controlled V1 and lifecycle checks passed. The V2 source
backup's original file inventories, sizes and SHA-256 digests still match.
The currently observed implementation digest is
`8bc29d86ebe52638c56020bce474a0d935c3ad8610f9998edf1b861451bd2602`;
it is not an independently authorized deployment pin.

| Required result | Verified status |
| --- | --- |
| Scheduled Authorization Contract | Schema-3 deployment + separate version-1 scheduled build policy, offline verified |
| Scheduled Construction Entry | Actual miniature construction passed; real activation disabled |
| Durable Duplicate Storage | Private immutable Release adapter implemented; no real archive published |
| Completed Candidate Verification | Independent witness + live origin contract + full package verification tested |
| Concurrency / Retry Safety | Reviewed workflow group and rechecks tested offline; not a Hosted concurrency guarantee; draft resolution remains explicit |
| Automatic Workflow Routing | Conditional code wired; default-disabled |
| Manual Continuous Execution | Existing explicit mode retained and regression-tested |
| Incremental + Full Parity | Miniature PARITY_PASS |
| Frozen R2 + Replay | Miniature 128 combinations each and independent replay passed |
| Historical Compatibility | Original-code V1/V2 tests + unchanged frozen contracts; not a new audit of every historical asset |
| Real Hosted Validation | NOT_PERFORMED |
| External Authorization | New reviewed deployment/policy/witness inputs NOT_CONFIGURED |
| Scheduled Construction Enabled | NO operational activation performed |
| Git Status | Existing Part B retained; changes uncommitted, index empty |
| Git Push / Releases / Dispatch / Registry writes | NOT_PERFORMED |

Remaining blockers are classified precisely:

1. **Missing implementation/integration:** automatic independently trusted
   completion-witness distribution. A reviewed deployment witness works now;
   self-adopting the publisher output does not. Automatic draft cleanup/resume
   is intentionally absent and requires separate review.
2. **Storage/concurrency acceptance:** actual immutable publication, cancellation,
   interrupted-response recovery and all-writer group coverage are not Hosted
   validated. No claim is made that GitHub cannot store the assets or that a
   new database/approval framework is needed.
3. **External authority/configuration:** reviewed implementation commit, raw pins,
   versioned schedule policy, witness and explicit enablement remain required.
   No such remote changes were performed here.
4. **Future lifecycle compatibility:** scheduled Genuine V3 is not automatically
   accepted by old P4.1/registration/Parent-restoration entry points. That future
   compatibility is not fabricated by archival, nor is production authorized.

Files added: `src/scheduled_construction.py`, `src/continuous_completion.py`,
`scripts/publish_continuous_candidate.py`, `tests/test_scheduled_construction.py`,
`docs/scheduled_construction.md`.
Files updated in this task: `src/genuine_continuous_execution.py`,
`scripts/run_continuous_ci_v2.py`, `.github/workflows/upstream_refresh.yml`,
`docs/genuine_continuous_execution.md`.
The pre-existing Part B changes in `tests/test_genuine_continuous_execution.py`
were retained byte-for-byte. Thus Git shows ten changed/new paths in total.

HEAD remains `15be431d09a655bc5960f64256b1d3fd9a4e3121`. Registry, Policies,
benchmark, runtime lock, frozen source contracts, original C1/C2 assets,
upstream checkouts and stable Gradio were not modified. No genuine C1/C2 build
or R2 was rerun. `QUALITY_REVIEW_REQUIRED`, Q1 unqualified status, P8 `BLOCKED`
and production `NOT_AUTHORIZED` remain unchanged.
