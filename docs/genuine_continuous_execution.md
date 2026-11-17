# Genuine-format Continuous Execution integration

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
`genuine-continuous-candidate-v1`, with a distinct evaluator projection. It
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

Scheduled V2 remains disabled in both job routing and restrictions. Concurrency
serializes continuous jobs but does not deduplicate across runs. There is no
exactly-once guarantee; a new explicit authorized manual dispatch may repeat a
pair. Repeat attempts are rejected, and schedules cannot start the job.

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
`dedde1d81aa47c8f6c53f4f081fbd3e7b4a60d6c4f1d18e339d458ff3f8d616e`.
It is not an authorized deployment pin. Controlled V1 remains
`2d9c41cc55d5f6c7dd8022280e38b7d1ec8ad5d991d7e452396dfa02e19220e3`;
controlled lifecycle remains
`cf1e270eb655805934dace62e3934041db57202bdfb05d6d5d5a2dd2574ec7a3`.
The historical C1 orchestration still exactly matches its archived contract:
`b0b43411aef4d716a15a2f0a794071523fbb3c260dc4cb3fc9b2736eed9e1ac1`.
Frozen P2/P3/P4.1/R2 runtime/implementation checks and Registry-byte checks pass
unchanged. No genuine C1/C2 reconstruction or replay was executed.
