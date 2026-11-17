# Personal Continuous CI V2 Hosted acceptance preflight

Inspection date: 2026-11-18 (Europe/Berlin). **Remote mutation is not authorized
by this document.** No Push, dispatch, Variable/Secret update, Release operation,
registration or recurring construction enablement was performed.

## Verified checkpoint and actual target

| Item | Observed result |
| --- | --- |
| Local branch | `ci-upstream-refresh` |
| Previous checkpoint | `4665108277bb24e4cfb8b83be00b5ecb5de6350a` |
| New local checkpoint | `092d4f8aa6cfec53bcbbb669b66f197327352062` |
| Commit | `feat: complete automatic continuous completion witness verification` |
| Regression | 331 tests PASS, 333.777 seconds |
| Compilation / YAML / 29 Bash blocks / whitespace | PASS |
| Historical C1 | `b0b43411aef4d716a15a2f0a794071523fbb3c260dc4cb3fc9b2736eed9e1ac1`, unchanged |
| P2/P3/P4.1/R2, controlled V1/lifecycle | Unchanged, frozen runtime verified |
| Preserved Genuine V1/V2/V3 | Original source contracts reconstructed and matched; retained V3 package inspected with original verifier/pins, no fresh replay |
| Previous checkpoint execution contract | `12e0591896d03f198056c42c32f92a4b31ce526f4458366bb3fb9d09f81a8b79` — observed, not a new deployment authorization |

The commit contains exactly `docs/completion_witness.md`,
`docs/scheduled_construction.md`, `src/continuous_completion.py`,
`src/genuine_continuous_execution.py`, `src/scheduled_construction.py`,
`tests/test_completion_witness.py`. Its sole parent is the previous checkpoint.
The worktree/index were clean immediately after committing. This checklist was originally uncommitted, outside that six-file checkpoint.
It is now included in the separately authorized local runtime correction checkpoint.

Authenticated read-only `gh` API observations:

| Item | Actual value |
| --- | --- |
| Personal private deployment repository | `XiangruZhang007/SPHinXsistant-CI-Test` |
| Repository ID / visibility | `1455203884` / private |
| Default and intended research branch | `ci-upstream-refresh` |
| Current remote HEAD, rechecked | `d030a56f4a8269de16f9cdb1201fbef2579f94ba` |
| Authenticated owner | `XiangruZhang007`, numeric user ID `239840087`, User |
| User repository permissions | admin/maintain/push/pull/triage true; these do not prove a future job token's permissions |
| Workflow | `Upstream Refresh Candidate`, ID `420254010`, active |
| Registered path | `.github/workflows/upstream_refresh.yml` |
| Actions | enabled, allowed_actions=all; default workflow permissions=read |
| Branch protection | false; no protected-branch approval guarantee is claimed |
| Observed Actions bot | `github-actions[bot]`, ID `41898282`, Bot; an identity observation, not approval authority |
| Existing repository Variables | `HISTORICAL_ARCHIVE_DEPLOYMENT_JSON`, `HISTORICAL_ARCHIVE_DEPLOYMENT_SHA256` only; values not inspected or printed |

`backup` points to the **different public** personal repository
`https://github.com/XiangruZhang007/SPHinX_AI_Assistant.git` (ID `1383173626`,
default branch `main`). The local branch tracks `backup/ci-upstream-refresh`;
that tracking status is not the private deployment status. No private deployment
remote alias is configured. `origin` points to the professor's repository and
must never be used for this deployment. Its local URL was read; the repository
was not contacted. No remote/upstream setting was changed.

## Scheduled preflight runtime correction — locally verified

The original Job selected Python 3.12.3 but invoked the entry before preparing
its pinned chunker/parser dependencies. The top-level execution import reaches
`chunk_generation_v1.py` and `from chunker import chunk_file` before the CLI
exception handler. A package-free `python3 -B -S ... --help` probe failed with
`ModuleNotFoundError`; this was a local diagnostic, not a Hosted observation.

The correction reuses the Continuous build Job's exact runtime preparation:
checkout `Consiliency/treesitter-chunker` at
`fb70922076c773d1865176329a03f67ff893fd90`, create its isolated venv, install
unchanged `configs/ci_v2_parser_requirements.txt` requirements and the constrained
editable chunker, then invoke `tools/treesitter-chunker/.venv/bin/python`.
Python 3.12.3, ARM64, read-only permissions and `--preflight-only` remain intact.
Every other Job and routing configuration is unchanged. No import refactor,
build, publication or Registry operation is added to preflight.

Four focused offline tests cover real entry import without inherited PYTHONPATH,
execution of the actual preflight shell producing a sanitized
`CONTINUOUS_DEPLOYMENT_NOT_CONFIGURED` BLOCKED receipt, setup failure stopping
before entry, and unchanged other Jobs/runtime selection. Existing tests retain
the preflight no-construction boundary and verify the shared runtime shell.
The import/receipt probes use an already prepared local frozen runtime; stubbed
setup-failure checks do not install dependencies or contact GitHub. They are not
clean Hosted Runner acceptance or real Owner authorization.

Runtime bootstrap blocker: **RESOLVED LOCALLY; HOSTED NOT VALIDATED**.
New observed execution-contract SHA-256:
`4c33fc192433b694279b9f0432a245fb493fd1e3bfa19ebe8209855fa1388a3b`.
Workflow bytes participate in this digest. It is not independently authorized;
all historical pins remain unchanged. Deployment requires separate review of the
actual correction commit and this digest. Historical Genuine V1/V2/V3 must be
verified with their preserved original implementations and retained pins.

Correction regression result: **335 tests PASS, 331.231 seconds** (331 previous
tests plus four focused runtime tests).
The full command is the regression suite referenced in `completion_witness.md`,
using `PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH=tests` and the frozen
venv interpreter. It includes the four new `PreflightRuntimeTests` through
`test_scheduled_construction`. Python compilation, YAML parsing, all 17 Workflow
Bash blocks and whitespace validation passed.

Historical compatibility checks in the correction: original V1 and V2 checkouts
each passed their two miniature pipeline/offline-inspection tests (25.225 and
24.596 seconds). Those are synthetic package tests, not retained genuine C1/C2
replays. All three preserved source contracts matched their original pins; the
retained V3 miniature package passed its original verifier and independently
retained pins with `SEALED_REPLAY_INSPECTED` (no fresh replay). No historical
package was relabelled, regenerated to fit new code, or repinned. Existing real
research assets and the authoritative Registry were not modified.

## Deployment gap

The deployed Workflow blob is `c46cd4614f263ac31763f3ad877960fd779b96c5`.
Its only dispatch input is **`build_ci_v2`**, and its only Jobs are
`candidate-refresh` and `candidate`. Continuous inputs/Jobs, lifecycle concurrency
and the publisher are **not deployed** yet. Workflow registration alone therefore
does not make Continuous dispatch ready.

The remote Registry matches local bytes exactly, SHA-256
`224c7a84fbbaa7570cb2a085824ce1e24692f88f2ab2830af9c94476074ceb2c`.
It contains only `c1-research-parent-09b91a36` and `p2-initial-bootstrap`.

Local Git objects establish normal fast-forward ancestry from the observed remote
HEAD to the new checkpoint, including **six** commits (before any runtime fix):

```text
2361eb7d1ddda76ea50ba502e713ef4d0668c0c8
a276b709acbdbbb72460696f2c298c8f0067805c
7df9e0f971d27715fb54d68189f77905d87be617
15be431d09a655bc5960f64256b1d3fd9a4e3121
4665108277bb24e4cfb8b83be00b5ecb5de6350a
092d4f8aa6cfec53bcbbb669b66f197327352062
```

The runtime correction is local only. After separate authorization, recheck the
exact remote HEAD and review the entire transfer range including the correction.
The future command structure, **not executed here**, is:

```bash
git push https://github.com/XiangruZhang007/SPHinXsistant-CI-Test.git \
  "$REVIEWED_FIXED_COMMIT:refs/heads/ci-upstream-refresh"
```

`REVIEWED_FIXED_COMMIT` must be the actual separately reviewed correction commit
reported after local checkpoint creation; no self-referential commit SHA is invented.
Use the existing authenticated Git transport; HTTPS push credentials were not
exercised by this preflight. Do not use `origin`, force flags, fetch/reset/rebase
or automatic retry. Stop if remote identity/HEAD or local source changes differ.
The local correction commit includes this checklist. After an authorized
Push, use read-only API checks to verify exact branch SHA, Workflow bytes and
the newly available `build_continuous_ci_v2` input before dispatching anything.

## Configuration prerequisites — not created or approved here

| Required input | Current state / exact contract |
| --- | --- |
| Schema-4 deployment JSON | Missing; strict fields in `genuine_continuous_execution._shape()` |
| `authority_policy_path` and independent SHA | Missing Continuous build authority policy; reuse exact `owner_manual_baseline_approval.POLICY_FIELDS`, binding this repository/default branch/Workflow/Registry and authorized owner/designated IDs |
| `continuous_policy_path` and independent SHA | Missing; exact `continuous_build_policy.POLICY_FIELDS`, `CONTINUOUS_SCOPE` / `BUILD_CANDIDATE`, authentic upstream repository IDs/branches, bounded ancestry, validity interval, explicit eligible C1 reference and unchanged requirements/restrictions |
| `scheduled_policy_path` and independent SHA | Missing; exact `scheduled_construction.FIELDS`, `SCHEDULED_CONTINUOUS_CANDIDATE_BUILD`, reviewed interval/namespace/publication permission and no approval/registration/production grants |
| `registry_path` / SHA | Existing `configs/ci_v2_schema2_trusted_baselines.json`; actual SHA above. Retain existing P2/C1 records |
| `implementation_revision` | Use the actual correction commit after separate review; `092d4f8…` is the previous checkpoint |
| `execution_contract_sha256` | Measured corrected digest `4c33fc19…` above; independent deployment authorization remains unresolved |
| `completion_authority` | Missing independent acceptance of `MAINTAINER_GOVERNED_RELEASE_WRITERS`, actual Workflow/bot IDs, chosen namespace and any expressly reviewed previous producer versions |
| Source IDs, branches, scope and expiry | Require actual source evidence and explicit scope review; not guessed or selected in this task |

Do not reuse `ci_v2_historical_c2_archive_policy.json` as a Continuous policy:
its purpose/Workflow binding is different. No operational policy path, enabled
policy JSON, approved scope or deployment digest was manufactured here.
Observed user/bot IDs are not self-executing approvals.

The only required **repository Variables** for the new path are:

- `CONTINUOUS_BUILD_DEPLOYMENT_JSON`: independently reviewed exact JSON bytes.
- `CONTINUOUS_BUILD_DEPLOYMENT_SHA256`: separately reviewed SHA-256 of those bytes.
- `CONTINUOUS_CONSTRUCTION_ENABLED`: absent/false until a scheduled acceptance
  window is explicitly authorized.
- `CONTINUOUS_PUBLICATION_ENABLED`: absent/false until that publication window
  is explicitly authorized.

All four are currently absent. Preserve the existing Historical Variables.
Policy JSONs must be reviewed tracked `configs/*.json`; do not deploy test
fixtures, derive trust pins from Candidate output or auto-fill previous producer
authority from old checkpoint IDs. Setting Variables is a later authorized write.

The local Workflow retains the actual detector Artifact handoff, validates exact
source SHAs and compares against the selected Parent. It uses
`ubuntu-24.04-arm`, Python **3.12.3**, pinned chunker commit
`fb70922076c773d1865176329a03f67ff893fd90` and
`configs/ci_v2_parser_requirements.txt` for Continuous build/publication. Actual
future runner scheduling, quota, dependency retrieval and token access remain
Hosted acceptance requirements, not facts proven by a local API login.

Only `publish-continuous-candidate` requests `contents: write` and `actions: read`.
Continuous build/preflight retain `contents: read/actions: read`. Existing
`GITHUB_TOKEN` is passed only where needed; no cross-repository credential or new
Secret is required. The old detector/V1 job's floating Action tags remain
unchanged; do not describe every Action in the whole workflow as SHA-pinned.

## Genuine Parent and durable storage

C1 Baseline: `sha256-09b91a3634aba71ce4974c8266d7f73cba6ecb0cfabe0e4291a30bf9c9229c88`.
Registry reference SHA: `f92e93ba360ca9a7d78c2b8ab285038c4068366b41b97db7ed06acb25e20f352`.

Authenticated API confirmed Release **443114216**, tag
`ci-v2-c1-research-parent-09b91a36`, draft=false, immutable=true:

| Asset | ID / size | SHA-256 |
| --- | --- | --- |
| C1 archive | 739932956 / 29714707 | `20e1927193470bd8c6b1e1cff198bef5b3a804aadc53cc57b99c08b7eb3ed2e3` |
| Parent R2 | 739934006 / 6498477 | `372569fe9ca539a0dcfb0cd19ffa863b61e7a8d6b4ff345ce4c168afdaf40f37` |
| License companion | 739934747 / 10268 | `ff841130a4e0b891f87e12f38a2869a55a87926d75ba716abbe114ceefdf304f` |

All states/digests match the existing reference/evidence. This task rehashed the
existing local archive/rows, restored C1 through `trusted_snapshot.restore()` into
owned temporary storage and successfully invoked `qualify_parent_anchor()` with
`fresh_replay=False`: **NO_FRESH_REPLAY**. Genuine sealed P4.1 and original Parent
R2 bindings passed. No Corpus was rebuilt and no real R2 replay ran. Remote asset
bytes were not downloaded again; actual future job-token downloads and mandatory
fresh Parent replay are still required during an authorized build.

The other observed immutable Release is historical C2 archive **447029634**.
It is not a registered C2 Parent or a Genuine V3 completion record. Do not use it
to skip a new-format build or infer approval. A qualified C1 Parent exists;
missing new Continuous scope/deployment authority is the current configuration
blocker, not a missing genuine Parent.

## Acceptance order and explicit authorization boundaries

1. **Default-blocked test — pending reviewed deployment and Hosted validation.** After an
   independently authorized Push and metadata recheck, leave all four Continuous
   Variables absent. A separately authorized dispatch would be:

   ```bash
   gh workflow run upstream_refresh.yml --repo XiangruZhang007/SPHinXsistant-CI-Test \
     --ref ci-upstream-refresh -f build_ci_v2=false -f build_continuous_ci_v2=true
   ```

   Expect `CONTINUOUS_DEPLOYMENT_NOT_CONFIGURED`, `execute_candidate: false` and
   `continuous-result/failure.json` in the attempt-specific Artifact. Inspect step
   outcomes and receipts; overall failure can be expected for this negative test.
   No Continuous Candidate, publisher or Registry mutation is permitted. Existing
   `candidate-refresh` still generates its legacy **V1** corpus/evaluation: this
   is not a zero-computation detector-only dispatch and is not changed here.
2. **Authorized manual construction — BLOCKED until config/scope/Owner review.**
   Independently review policy files, deployment bytes/pins and exact code; deploy
   them under separately authorized commits/Pushes/settings. Use the same explicit
   manual command only after these prerequisites. Preserve actual detected SHAs,
   successful genuine C1 restoration/fresh Parent R2, incremental/full parity,
   frozen Candidate/full R2 and replay and complete attempt-specific Artifact.
   The manual path does **not** publish, approve or register a Baseline.
3. **Scheduled construction/publication — BLOCKED pending separate window approval.**
   Review the scheduled policy, writer trust and top-level concurrency group
   `ci-v2-continuous-lifecycle-1455203884`. Then authorize only the controlled
   enablement window for both operational flags and await the real cron event
   (`0 6 * * 1`, UTC). Do not fabricate event JSON or turn a dispatch into a
   schedule. Require successful build and publisher Jobs, unchanged package,
   immutable Release and verified assets/completion. No full-workflow success is
   required as a prerequisite inside the same publishing Job.
4. **Repeat — BLOCKED until an actual scheduled completion exists.** On a later
   authorized schedule with unchanged selected Parent, detected target and build
   contracts, require independently verified historical producer/current consumer,
   full package inspection and `PUBLISHED_AND_VERIFIED -> NO_BUILD`, without any
   per-build completion-pin update or duplicate publication. If upstream advanced,
   assess it as a new target; never substitute old SHAs to manufacture a repeat.
5. **Failure recovery — offline verified, Hosted NOT_PERFORMED.** Check expected
   missing authority, stale Parent/source or naturally encountered publication
   failures from actual receipts/API identities. Deliberate cancellation or any
   new failure experiment needs separate run-specific permission. Do not corrupt
   immutable assets, publish fake completion records or delete Releases to test.
   Draft/partial/failed publication is not completion; failed publisher adoption
   requires explicit manual recovery. Missing Run/Job evidence fails closed.

The acceptance trust model explicitly trusts maintainers/administrators and all
Release-write principals/workflows. The shared bot ID/API metadata is **not a
cryptographic producer attestation** or an enforced exclusive-writer boundary.
Writer coverage and GitHub concurrency remain explicit maintainer/Hosted checks.
Older packages retain their original verifier/pins; no automatic cross-contract
old-code execution is added. See [completion_witness.md](completion_witness.md).

## Disablement and completion criteria

With separate configuration authorization, setting both operational flags to
`false` disables future scheduled construction/publication. It does not by itself
disable explicitly requested Owner-authorized manual construction, nor guarantee
termination of in-progress Jobs. Full Continuous blocking can remove its two
deployment Variables under separate authorization; cancellation of an owned run
is a distinct action. Read-only preflight/legacy V1 may still run. Do not delete
immutable Releases, reset Registry entries, force-push old code or touch Gradio.

Declare Hosted acceptance only after actual repository/commit/event/first Attempt,
actor, exact source/Parent, mandatory computations, immutable publication and
subsequent duplicate verification are independently inspected. Record the original
step outcomes, receipts and API identities, not just a green workflow. Restore
disabled unattended flags after the authorized test window until an explicit
acceptance decision allows continuing operation.

Remaining blockers: **(1)** corrected code not deployed and new independent Continuous policies/deployment
pins/Variables and writer trust not configured or authorized; **(2)** actual
runner/token/storage/concurrency/duplicate/failure Hosted acceptance not performed.
The runtime gap is corrected locally; no GitHub operation or Hosted acceptance
was performed during the correction.
Keep `QUALITY_REVIEW_REQUIRED`, Q1 unqualified status,
P8 `BLOCKED`, research approval/registration ungranted and production
`NOT_AUTHORIZED` throughout.
