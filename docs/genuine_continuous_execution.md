# Genuine-format Continuous Execution integration

Current scheduled implementation and its remaining trust/activation limits are
documented in [scheduled_construction.md](scheduled_construction.md). The Part B
sections below retain the earlier offline checkpoint record; their scheduled
construction blocker descriptions are superseded by that versioned adapter.

This connects independently configured continuous scope to the existing update
Workflow, without generating exact-target approval policies. The default is
**blocked**: no operational deployment or authority policy is installed here.
Scheduled V2, research approval, Registry writes and production remain disabled.

## Integration map and version compatibility

| Existing component | Reuse |
| --- | --- |
| `check_upstream_updates.py` | Existing single detector; no second target selection. |
| `prepare_ci_v2_update.detection()` | Strict detector bytes, branches, exact commits and update consistency. |
| `continuous_build_policy` | Existing policy grammar, unique scoped Parent selection, real Git source proofs, bounded fast-forward relationships, fresh official repository/ref/commit observations, and repeated scope validation. |
| `owner_manual_baseline_approval` | Existing policy schema, API client, actual run/actor/repository/default-branch identity checks and remote Registry byte comparison. Registration approval itself is not reused as build approval. |
| `trusted_snapshot` / `parent_r2_anchor` | Immutable transport, independent hashes, safe extraction, genuine evaluated P4.1 Parent checks and mandatory fresh Parent R2. |
| `continuous_execution._assemble()` | Unchanged changed-file extraction, validated reuse, source materialization and deletion handling. |
| `upstream_provenance.full_reference()` / V1 parity helper | Independent full reconstruction with canonical roots and four byte-for-byte artifact comparisons. |
| Frozen quality/evidence functions | Real Candidate/Full evaluation, rescoring, replay, historical/immediate-Parent transitions, source applicability and existing attribution. |
| `ci_v2_research.package_candidate()` | Complete sealed package transport, without approval or registration. |

`src/genuine_continuous_execution.py` is a separate version-aware execution and
verification adapter. Editing the old V1 constructor/verifier would invalidate
already sealed V1 package pins and the controlled lifecycle contract. A separate
thin script is necessary for a reviewed Hosted entry without exposing authority
providers or simulation flags. There is no second extractor, ranker, provenance
algorithm, approval system or Registry.

Historical schema-2, Controlled V1 and controlled lifecycle files stay unchanged.
Their fingerprints/pins are never recomputed to conceal compatibility changes.
The old V1 entry still unconditionally blocks. The new format is
`genuine-continuous-candidate-v2`, with a distinct evaluator projection. It
rejects controlled Parents and controlled Candidates; existing verifiers still
reject the new format. No format conversion or relabelling is performed.

## Build authority, distinct from Candidate approval

Authority follows the existing maintainer-governed Hosted model:

1. The repository maintainer reviews the workflow/code, a **build-specific**
   authority policy and a continuous scope policy in a committed checkout.
2. Independent repository-managed deployment Variables pin that exact commit,
   purpose, code contract and configuration bytes.
3. An authorized Owner/designated account explicitly dispatches the update
   Workflow with `build_continuous_ci_v2=true`, `build_ci_v2=false`.
4. The entry checks the exact tracked checkout and independent pins, required
   frozen runtime, Hosted workflow context and actual GitHub API run/actor/
   default-branch identity. It checks remote Registry bytes against the checkout.
5. It revalidates that authority and the scope/source evidence before
   construction, after incremental construction, and before publishing output.

The existing Owner-policy **schema and identity helper** are reused; an old
Baseline-registration policy or its approval result is not automatically build
authorization. The new deployment purpose is `CONTINUOUS_CANDIDATE_BUILD_ONLY`.
Its policy is a separately reviewed file under `configs/`, bound to this
Workflow/domain/Registry. Organizations require designated numeric user IDs;
organization membership/admin status is not inferred as authority.

The reviewed workflow and independently maintained deployment configuration
form the trust root. Matching hashes, API responses, GitHub environment/event
JSON, or a saved result cannot individually establish a trusted process.
This model does not attest an arbitrary local process or resist an equally
privileged malicious maintainer. No cryptographic process-attestation guarantee
is claimed. Deployment Variables are a run-start snapshot; urgent revocation
requires cancelling active runs, while changed default-branch commits/policy
bytes are detected by the existing live checks.

Missing real configuration remains `CONTINUOUS_DEPLOYMENT_NOT_CONFIGURED`;
ordinary local execution cannot unlock it with an approval flag. No actual
Variables, authority policy, continuous policy or reviewed deployment pin is
created by this implementation task.

## Independent deployment configuration

Repository Variables for future separately authorized setup:

- `CONTINUOUS_BUILD_DEPLOYMENT_JSON`: exact UTF-8 JSON bytes.
- `CONTINUOUS_BUILD_DEPLOYMENT_SHA256`: SHA-256 of those exact bytes.

The closed deployment object has:

```text
schema_version = 1
purpose = CONTINUOUS_CANDIDATE_BUILD_ONLY
repository, repository_id, default_branch
workflow_path = .github/workflows/upstream_refresh.yml
implementation_revision = exact reviewed/deployed Git commit
authority_policy_path, authority_policy_sha256
continuous_policy_path, continuous_policy_sha256
registry_path, registry_sha256
execution_contract_sha256
```

All three configuration paths are tracked `configs/<name>.json` regular files.
The authority policy uses existing `POLICY_FIELDS` with enabled authority,
explicit repository/domain and Owner/designated numeric identities. The
continuous policy uses the existing scope contract: authorized official numeric
repository identities/branches, eligible Parent pins, validity interval,
bounded ancestry and unchanged quality/research/production restrictions.
Registry contents remain existing Schema V2. No future target SHA is added to
either the continuous policy or deployment object.

Parent eligibility retains the existing scope evaluator's restriction to
build-bound schema-2 research Baselines. `REGISTRATION_ONLY` entries and the
controlled lifecycle's new Baseline format are not silently upgraded. A future
registration-only/new-format Parent needs separately reviewed eligibility and
approval compatibility; this task does not implement that registration work.

The execution contract hashes the adapter, thin script, detector adapter,
Workflow and unchanged V1 dependency contract. Its computed digest is not an
Owner decision or automatically approved deployment pin. The implementation
commit is recorded externally after review/commit/deployment, avoiding a
self-referential commit hash. No proposed operational identifiers are fabricated.

## Exact detection, execution and evidence

The existing detector output is downloaded from this run/attempt's existing
preflight Artifact using the pinned download Action with digest mismatch set
to error. Its original exact SHAs are preserved; fresh branch observations
validate or reject them. A moved branch blocks instead of silently retargeting.
The detector's branches must match the continuous policy.

Only new isolated source checkouts are created. Full Git history supports
ancestry; official remotes, exact commits, actual selected bytes/modes and
source state are independently checked by existing provenance functions.
Parent transport/qualification, current policy expiry, Registry, source and
authority are mandatory gates. New-format construction does not call the old
exact-target builder with a generated policy. The read-only scope assessment's
historical execution blocker is preserved as evidence; this new version's
separately checked workflow build context is recorded independently.

V2 determines `NO_UPDATE` by comparing the exact detected pair with the selected
trusted Parent's upstream pair. It preserves the original V1 detector bytes,
static-baseline flag and SHA-256; it does not change `upstream_baseline.json` or
V1 behavior. The authority receipt contains this separate `parent_comparison`,
including the Parent reference and Registry/scope/code pins. A false V1 update
flag cannot hide a real update relative to that Parent, and a true V1 flag cannot
rebuild an identical Parent. Equality is a metadata-only no-update decision,
not fresh source authenticity, ancestry or Parent package qualification.

The sealed output contains the new Candidate identity/projection, restored
Parent, full snapshot, original detector/policy/Registry/reference/deployment
bytes, source proof/branch observations, workflow identity receipt, raw R2 and
independent replay receipts, parity, attribution and pending review reports.
Candidate identity binds exact source revisions/state, evaluated Parent and
generation, independent pins, code contract and operation identity. Run identity
is deliberately bound; different authorized runs may have different Candidate
IDs even with identical Corpus bytes.

Transport packaging/checksums and a final authority/source revalidation complete
inside the owned work directory before the complete delivery directory becomes
the output. A normal packaging failure therefore exposes only a sanitized
blocked receipt to Artifact upload; diagnostic work is retained separately.
`NO_UPDATE` writes `no-update.json` for successful evidence upload and performs
no Parent download, checkout, Corpus build or replay.

`verify_package()` requires externally retained expected code, policy, Registry,
reference, deployment, Candidate and manifest pins. It checks the actual files,
projections, Git proofs, Parent, raw rows/replays and review evidence offline.
Its default is sealed-receipt inspection; `fresh_replay=True` explicitly runs R2.
Offline verification never treats saved GitHub observations as fresh source or
Owner authorization. `verification-inputs.json` describes needed values, but
pins copied from the package itself do not become an independent trust source.

Hosted invocation (no authorization switches or token arguments):

```bash
tools/treesitter-chunker/.venv/bin/python -B scripts/run_continuous_ci_v2.py \
 --detection "$RUNNER_TEMP/continuous-detection/sphinxsistant_candidate/upstream_status.json" \
 --work "$RUNNER_TEMP/continuous-work" --output "$RUNNER_TEMP/continuous-result"
```

This is a future configured Hosted command, not permission for a local real
build. Errors are sanitized JSON; a new failure receipt is preserved where
possible, without overwriting existing evidence or claiming technical success.
Owned work is retained for diagnostics. The script never logs tokens or API
response bodies.

## Workflow and approval handoff

The original exact-target job remains available through `build_ci_v2=true`.
Selecting both modes prevents both jobs. The new job requires manual dispatch,
explicit continuous opt-in and independent authority configuration. It uses
the existing ARM Runner, Python 3.12.3 and pinned parser/dependencies. Job-only
permissions are `contents: read`, `actions: read`; credentials are supplied
only through existing environment mechanisms during execution.

Artifacts are named `ci-v2-continuous-RUN-ATTEMPT`, retained for 30 days. They
contain `run/`, `candidate.tar.gz`, verification inputs and transport checksum,
or an explicit failure receipt. This is evidence handoff, not permanent Release
publication or web approval. Existing schema-2 Release archivers and genuine
P4.1/registration workflows are **not claimed compatible** with this new format.

Scheduled **construction** remains disabled in both job routing and restrictions.
The separate `continuous-schedule-preflight` job can inspect the exact detector
artifact on schedules, but invokes only `--preflight-only`. It has no builder,
Release publisher or Registry writer. Its missing-configuration or eligible-update
`BLOCKED` receipt fails the job explicitly; a green workflow is not acceptance.
Concurrency serializes manual continuous jobs but does not deduplicate across
runs. There is no exactly-once guarantee; an explicitly authorized new manual
run may repeat a pair. Repeat attempts are rejected.

## Offline tests and remaining real validation

Focused command:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH=tests \
 tools/treesitter-chunker/.venv/bin/python -B -m unittest test_genuine_continuous_execution
```

The test reuses existing miniature fixtures and creates a fresh schema-2 Parent
with **mocked official-publication observations and a fixture P4.1 decision**.
It does not relabel an existing controlled package. Git history, source checks,
Parent evidence/replay, incremental extraction, independent full parity and
frozen R2/replay really execute. Only GitHub metadata/HTTP and Git transport are
redirected to isolated data; successful construction/evaluation is not mocked.
These are genuine-format integration fixtures, not independently authorized
execution against official repositories. They are deleted after tests and are
never registered, published or used as real research evidence.

Run the existing 242-test command plus the new module for regression. Genuine
Hosted validation remains `BLOCKED_BY_EXTERNAL_AUTHORITY` until the reviewed
configuration and separately authorized deployment/dispatch exist. Future real
new-format approval/registration compatibility and unattended deduplication are
also unresolved. No genuine C1/C2 rebuild/replay, GitHub mutation, commit, push,
Release, Gradio or production action is performed here.

Recorded final regression: **280 tests passed in 175.792 seconds**: 242 existing,
22 genuine-format integration tests and 16 existing Owner-policy/API tests.
The actual miniature Candidate reused 46 of 48 files / 45 chunks, extracted two
changed/added files, removed one file, passed independent four-artifact parity,
and completed 128 Candidate plus 128 Full frozen combinations and independent
replays. An additional successor-commit test built without editing the
continuous policy or the preexisting exact-target policy. None of these
temporary commits, mock Releases or fixture decisions establishes official
source publication or real Owner approval.

The observed new implementation digest is
`dedde1d81aa47c8f6c53f4f081fbd3e7b4a60d6c4f1d18e339d458ff3f8d616e`
at the Part A checkpoint `15be431d09a655bc5960f64256b1d3fd9a4e3121`.
That checkpoint independently reran 280 tests successfully. This is the V1
implementation pin, not the current V2 pin or an authorized deployment pin. Controlled V1 remains
`2d9c41cc55d5f6c7dd8022280e38b7d1ec8ad5d991d7e452396dfa02e19220e3`;
controlled lifecycle remains
`cf1e270eb655805934dace62e3934041db57202bdfb05d6d5d5a2dd2574ec7a3`.
The historical C1 orchestration still exactly matches its archived contract:
`b0b43411aef4d716a15a2f0a794071523fbb3c260dc4cb3fc9b2736eed9e1ac1`.
Frozen P2/P3/P4.1/R2 runtime/implementation checks and Registry-byte checks pass
unchanged. No genuine C1/C2 reconstruction or replay was executed.


## Automatic detection integration (Part B)

Deployment schema 1 remains manual-only. Schema 2 extends that same closed
object with exactly one field, `build_events`. Supported values are
`["workflow_dispatch"]` and `["workflow_dispatch", "schedule"]`. This is an
independently reviewed deployment event allowlist, not Candidate self-approval.
No real configuration/pin/Variable is created or changed by this implementation.

Schedule preflight requires schema 2 explicitly allowing `schedule`, exact
reviewed code/checkout and policy pins, a currently valid continuous scope,
live matching repository/run/actor/first-attempt/workflow/default-branch evidence,
and matching remote Registry bytes. It does not call the Owner registration
identity verifier with a forged dispatch. The schedule actor is an observed
initiator, not an approver; no reviewer is invented or required for that receipt.
Existing manual Owner/designated-actor checks remain unchanged.

The read-only preflight checks implementation bytes and ARM Hosted context,
but does not require the extraction parser installation or claim its runtime was
validated. Actual manual construction still calls the frozen runtime validator.
`--preflight-only` only restricts operations; it cannot enable a build. It writes
an exclusive external receipt through the CLI; the verification function itself
has no filesystem writes. `--work` remains a required argument for CLI
compatibility but is never created during preflight.

The existing scope grammar, sealed V1 policy/assessment and Candidate restrictions
still require `scheduled_execution: false`. Allowing a schedule in deployment
therefore establishes only a context observation, not construction authority.
An eligible scheduled update returns `BLOCKED`, `execute_candidate: false`, with:

- `SCHEDULED_SCOPE_AUTHORIZATION_NOT_IMPLEMENTED`.
- `DURABLE_REPEAT_EXECUTION_PROTECTION_NOT_ESTABLISHED`.

An identical target/Parent pair returns `NO_UPDATE`; missing/stale/expired or
mismatched evidence fails closed. The ordinary executor also independently
rejects scheduled construction, even with a valid schedule preflight context.
The manual job remains dispatch-only. No unconditional scheduled build switch,
new exact-target policy, Owner approval bypass or live Registry change exists.

### Stable execution key and deliberate scheduling limit

`parent_comparison.execution_key` binds repository ID, selected Parent ID and
package/reference, exact target SHAs, Registry/scope policy and execution contract.
It excludes operation run IDs and detector baseline/formatting. Thus repeating
the same proposed execution has the same key even when Candidate IDs differ.
This is a deterministic comparison key, **not implemented durable deduplication**.

Current Actions Artifacts expire, and the existing schema-2 Release publisher
and approval/registration interfaces do not accept this new Candidate format.
There is no verified durable completed-execution record for it. Pending or failed
runs and deleted/expired Artifacts cannot prove successful completion or absence
of duplicates. Accordingly this task chooses the explicitly allowed fallback:
only scheduled preflight is wired; unattended construction stays disabled.
Future enabling requires a separately reviewed versioned schedule-capable scope
contract, durable verified completion/race handling, new-format delivery and
P4.1 compatibility, independently reviewed deployment pins, then real Hosted
acceptance. Existing `REGISTRATION_ONLY` entries stay ineligible.

### Version boundary

Part A's `genuine-continuous-candidate-v1` verifier/constructor is retained in
checkpoint `15be431d09a655bc5960f64256b1d3fd9a4e3121`. Part B explicitly uses
`genuine-continuous-candidate-v2` because its sealed authority evidence now binds
the Parent-relative comparison. Historical schema-2, Controlled V1 and controlled
lifecycle verifiers stay byte-for-byte unchanged. No previous genuine-format
package is relabelled, silently repinned or claimed verifiable with different
implementation bytes: inspect a V1 package with its reviewed V1 checkout and
independent pins. No real V1 deployment or sealed genuine research experiment
was generated during Part A's offline tests.

### Regression command

Use the full command under `docs/continuous_execution.md` (219 tests), appending:

```text
test_continuous_lifecycle test_genuine_continuous_execution test_owner_manual_baseline_approval
```

This exercises the real miniature extraction/full parity/frozen R2 and replay,
manual authorization, scheduled context mismatch and missing authorization,
Parent-relative static-baseline contradictions, stable execution keys, schedule
build refusal, CLI receipts and actual Workflow shells. All GitHub/source
publication observations are explicit mocks; they do not establish Hosted
Owner authority or official-source execution. Part B remains uncommitted.

### Part B recorded result

Full offline regression: **290 tests passed in 181.180 seconds**, including
32 genuine-format tests and the existing Owner, controlled lifecycle and legacy
regressions. Compilation, YAML parsing, actual Workflow shell tests/Bash syntax,
whitespace and frozen runtime/contract checks passed. The miniature execution
reused 46/48 files and 45 chunks, extracted two files, removed one, passed full
parity and evaluated/replayed all 128 Candidate and 128 Full combinations.
These remain disposable fixtures with mocked GitHub observations.

The observed current V2 implementation contract digest is
`6d3c6ecb8115b083e1a947e4c81ddaee90427830de738934e1d18e5809ce01e1`.
It is not an independently approved deployment pin; no deployment was repinned.

| Acceptance field | Result |
| --- | --- |
| Genuine Executor checkpoint | `15be431d09a655bc5960f64256b1d3fd9a4e3121`, five files; Part A 280 tests passed |
| Scheduled detection routing | Read-only preflight wired and offline tested |
| Scheduled authorization | Explicit event/context verification only; construction BLOCKED |
| Detector-to-Parent consistency | Parent-relative comparison verified; original detector preserved |
| Repeat-execution protection | Stable key verified; durable completion/race protection NOT IMPLEMENTED |
| Manual continuous build | Preserved; actual miniature build offline verified |
| Scheduled continuous build | DISABLED; both executor and job routing reject construction |
| Incremental/full parity | Actual miniature `PARITY_PASS` |
| Frozen R2/replay | Actual miniature 128 combinations each and replay passed |
| Candidate Artifact delivery | Packaging and Workflow shell contracts offline verified; not Hosted verified |
| Offline tests | 290 PASS |
| Historical C1 / Controlled V1 | Unchanged contracts verified |
| Genuine Hosted validation | NOT_PERFORMED |
| GitHub Owner approval | NOT_ESTABLISHED by offline tests |
| Trusted registration | NOT_PERFORMED |
| Production deployment | NOT_AUTHORIZED |
| Working tree | Five Part B files modified, index empty; no Part B commit |
| Git Push / other GitHub operations | NOT_PERFORMED |

Authoritative Registry/Policies, runtime lock, benchmark, Owner approval verifier,
legacy scope/execution/lifecycle modules, original C1/C2 evidence and stable
Gradio were not modified. `QUALITY_REVIEW_REQUIRED`,
`Q1_NOT_QUALIFIED_FOR_VERSION_PAIR`, P8 `BLOCKED` and production
`NOT_AUTHORIZED` remain in force. Only the Part A checkpoint was committed.
