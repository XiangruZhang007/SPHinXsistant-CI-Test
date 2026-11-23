# Current-run Q1 and Hosted report preservation (D3.9-F)

This local proposal is not deployed. No build, remote PR, archive write or workflow
execution is authorized by its presence. Existing manual Owner Bot gates remain
unchanged. No App credentials or new service is needed.

## Q1 integration

Schema-2 `schema2_workflow.run_local()` calls diagnostics with `automatic=True`
after authorized Candidate/Full construction and evaluation/replay have completed.
With no explicit Q1 transport inputs, `q1_current_inputs.prepare()` writes a new
`q1-auto-inputs.json` bound to that run's Parent, upstream Candidate, source states,
Corpus/documentation hashes, benchmark, build fingerprint and original row bytes.
It cross-checks mandatory caller bindings and calls the unchanged Q1 deep loader.
Derived digests are reproducibility records, not independent human approval.
The existing diagnostics regenerates and writes a relocatable `q1-inputs.json`,
Q1 report, status and attribution before the outer run is sealed.

Explicit reviewed Q1 transport remains supported. `prepare_q1_inputs.py` remains a
transport restorer, not the current-run builder. A malformed explicit input is
not silently replaced by automatic inputs. Missing/invalid current-run material
produces explicit Q1_NOT_QUALIFIED_FOR_VERSION_PAIR with reason and uncertain
attribution, never QUALIFIED. This diagnostic failure does not override mandatory
build/evaluation gates or grant approval. UNRESOLVED/AMBIGUOUS/MODIFIED results are
valid diagnostic outcomes; they are not successful evidence equivalence.

Automatic preparation currently supports the existing genuine upstream Candidate
format accepted by Q1 load_inputs. The separate genuine-continuous-candidate-v2/v3
format uses different metadata and deliberately remains on its historical
unqualified path. No new projection or authorization bypass was added. The existing loader also requires the supported P2 snapshot Parent contract; unsupported
Parent formats remain explicitly unqualified. Supporting other format pairs requires a reviewed provenance adapter; this proposal does not
claim all Continuous entry points now run automatic Q1.

Frozen benchmarks, R2 scores, Q1 mapper, historical pins, policy/Registry/Parent
identities and original scientific status remain unchanged. Schema-2 execution
contract identities change and need separate review; no deployment pin is updated.

## Existing D3.9-E evidence

The original downloaded ZIP/report already exists outside Git. The proposed
`docs/evidence/hosted/d3-9-e-45144294526-attempt-1/` retains the exact report bytes
and deterministic manifest/README, verified from the original Run/Artifact receipt.
Original ZIP SHA e0896080cbb5af377f4b4b7738cf0c64c90c8c8584501aa22edf564290e39795.
Original report SHA 93bb8bd495fea3d30abc29eccd5b43e43151efd48f592d484717f86acaefbb6c.
No new Gradio run or asset publication is needed to prepare this historical archive.

## Automatic evidence PR

`ci_v2_hosted_evidence_archive.yml` uses workflow_run(completed) for the exact
manual Candidate workflow on the default branch. Validation has only contents:read
and actions:read. It authenticates source repository/Owner/workflow/attempt,
trusted ancestor revision, reviewed source bytes/config, actual jobs and artifact
attribution/digest, bounded ZIP and report identity/isolation/scope. Failure receipts
are preserved as BLOCKED, never PASS. No code in a downloaded artifact executes.
Only reviewed same-repository source implementations are eligible; a future change
of consumer implementations must be reviewed together with archive compatibility.

The separate write job refetches/revalidates and requires the read job's exact
manifest SHA. Its contents:write/actions:read/pull-requests:write token creates only
three evidence blobs, one commit and proposal branch, then a Bot PR. It cannot
merge or approve. It does not use Audit Writer credentials. The existing
ci_v2_bot_proposal.yml remains Owner-manual-only; no gate is weakened to automate
this distinct archive task. Trusted code is checked out at github.sha and matched
to its tracked checkout before privileged operations. No untrusted PR code runs.

Each mutation is attempted once. Ambiguity stops without retry/delete/overwrite;
partially created refs or PRs require read-only reconciliation and separate recovery
review. Existing identical committed evidence or an identical open Bot PR is
recognized; conflicts fail. After artifact expiry, only an identical archive already
present in the trusted Git checkout may be reused, with Run/API digest revalidation;
no original ZIP is fabricated. Unmerged or missing expired evidence fails closed. A PR only preserves evidence after human review and
merge. There is no claim of guaranteed durable remote preservation before merge.
The default-branch ruleset requires a human approving review. docs/evidence is not
currently CODEOWNERS-covered; no new CODEOWNERS policy is introduced. The Owner
reviews as required by the branch rule and single-owner maintenance practice.

Git archival PRs use existing protected review and suit small reports. Release
archival would introduce a second publication authorization/asset lifecycle for
reports; it is unnecessary here. No redundant Release archival is implemented.
The Candidate Release continues to preserve Candidate bytes, not these reports.

Temporary Candidate verification Artifact retention changes from 14 to 30 days
for future artifacts only. The actual repository GET reports days=90 and maximum
allowed=90. Original Artifact 14803332944 still expires 2026-12-07T09:09:57Z.
Reference: https://docs.github.com/en/rest/actions/permissions#get-artifact-and-log-retention-settings-for-a-repository

## Separate Hosted validation plan

1. Review local patch and exact new contract digests. Separately authorize a
   protected Bot PR; require human approval/merge and verify the actual deployed SHA.
2. Review activation of the new workflow_run automation: deployment enables future
   automatic archive branches/PRs for eligible source runs. This is distinct from
   today's local-only authority. No remote branch or PR has been created in D3.9-F.
3. Validate Q1 on the existing exact retained pair through offline reproduction
   first. A future separately authorized genuine Schema-2 research build will test
   automatic generation on Hosted; current REGISTRATION_ONLY and build gates remain
   effective. Do not dispatch that build until its actual build authority exists.
4. If a genuine test of the new automatic archiver is separately authorized, one new
   Candidate loading dispatch at the newly reviewed deployment revision and exact
   current loading config pin triggers the archival workflow. It is a necessary
   new-feature test, not a rerun merely to save D3.9-E. Inspect source and downstream
   Run/attempt, archive Artifact bytes, Bot author, exactly three added files and
   pre-approval blocking. No automatic approval or merge.
5. Q1 build diagnostics and Gradio report archival are separate acceptance claims.
   Do not rewrite old scientific runs or verification.json to combine them. A genuine
   Hosted Q1 build/archival validation has not been performed by local fixture tests.

Preserve QUALITY_REVIEW_REQUIRED, original Q1_NOT_QUALIFIED_FOR_VERSION_PAIR,
P8_BLOCKED, REGISTRATION_ONLY and PRODUCTION_NOT_AUTHORIZED.

## D4.1 R1: explicit read-only evidence-format compatibility

R1 adds an independent input adapter; it does not wire automatic execution,
change any genuine Continuous authority gate, or qualify a Candidate for
acceptance, registration, future construction, or production use.

| Parent | Candidate | Input contract | Verification |
|---|---|---|---|
| Existing verified P2 snapshot | Existing upstream research Candidate | Existing `q1-verified-inputs`, `schema_version: 1` | Original historical loader, unchanged interpretation |
| Genuine P4.1-verified `schema2-research-baseline` | Upstream research Candidate with the exact immediate Parent edge | `q1-verified-inputs`, `schema_version: 2` | Existing `upstream_provenance.verify` on both packages, independent seal/package pins, lineage and source proofs |
| Genuine P4.1-verified `schema2-research-baseline` | `genuine-continuous-candidate-v2` | Input schema 2 | Unchanged complete-run `genuine_continuous_execution.verify_package(..., fresh_replay=False)` plus independent Q1 source/rows verification |
| Genuine P4.1-verified `schema2-research-baseline` | `genuine-continuous-candidate-v3` | Input schema 2 | Same complete-run verifier, including the existing scheduled evidence contract |
| P2, controlled lifecycle Baseline, unapproved Candidate, or an incompatible package | Genuine Continuous v2/v3 | Unsupported | Fail closed; never synthesize a P2 manifest or relabel a package |

Here `schema2-research-baseline` means the package supported by the existing
Trusted Snapshot verifier: a genuine upstream Baseline with
`upstream-baseline.json`, a `RESEARCH_BASELINE` receipt, and `P4_1_VERIFIED` evidence.
An arbitrary legacy `baseline.json` or saved approval JSON is insufficient.

`q1_current_inputs.prepare(project, root, bindings, *, package_pins=None,
execution_pins=None, output=None)` retains the historical call. New-format calls
require independent `base_manifest_sha256`, `target_manifest_sha256`, and
`base_package_checksum` pins. Continuous inputs additionally require the complete
existing seven-field `PIN_FIELDS` mapping, supplied independently by the caller.
For Continuous, `target_manifest_sha256` is the complete run's `checksums.json`
digest, not a nonexistent Candidate-only seal. These pins identify expected
bytes; they are not Owner approval or permission to run a build.

For a sealed Continuous run at `workspace/run`, select the existing enclosing
`workspace` as `output`. The new descriptor is `workspace/q1-auto-inputs.json`,
never a new member of `run`. Any already-sealed new-format input root also
requires a separate enclosing descriptor directory. Conflicting format markers
are rejected rather than interpreted as historical evidence. Paths must stay within this descriptor workspace;
symlink directories and traversal are rejected. Parent/Candidate rows must be the
original `run/evidence/parent-rows.json` and
`run/quality/incremental-raw-results.json`. Input schema 2 uses the project's
existing frozen benchmark, verified against its existing constant and fingerprint.
The reader checks package seals, formats, source states, upstream revisions,
lineage/generation, materialized bytes/modes, documentation subsets, benchmark,
and archived rows. Complete-run verification also retains Full/Parity, archived
policy/implementation bindings, original quality evidence, and notices checks.
No fresh retrieval, R2 replay, construction, or live GitHub authority is performed
by the adapter. Historical policy consistency is not fresh authorization.

The existing mapper and scoring semantics are unchanged. Historical reports and
IDs remain immutable. A diagnostic generated under modified Q1 implementation
bytes has a new implementation fingerprint and may therefore have a new report
ID; this must be recorded separately rather than rewriting a historical ID.
`diagnostic_only: true`, `automatic_research_approval: false`,
`official_score_adjustment: false`, and `production_promotion: NOT_AUTHORIZED`
remain in force. The original run's `Q1_NOT_QUALIFIED_FOR_VERSION_PAIR` is not
rewritten by a separately verified supplementary diagnosis.

The new v2/v3 compatibility tests use miniature local Git objects and explicit
mock publication, Owner, API, and transport observations. They exercise actual
independent package verifiers, but are not genuine upstream or Hosted evidence.
Genuine retained P2 evidence is verified separately for backward compatibility.
No genuine Continuous package is claimed to have been verified merely because a
fixture carries the genuine-format identifier.

R2 needs separate review and authorization to connect the post-seal diagnostic
interface to the existing executor and archive consumers. The current executor,
its Q1 status restrictions, and its permissions remain unchanged in R1. New
execution-contract digests are implementation identities only: historical and
deployment pins must not be silently updated, and a stale implementation/package
combination must continue to fail closed.

## R2: post-seal genuine Continuous supplementary diagnosis

The genuine Continuous executor now calls `supplementary_q1(project, delivery,
pins)` only after its existing build, independent Full/Parity, R2/replays, seal,
mandatory package verification, archive construction, authority revalidation,
and final delivery-directory relocation. It does not run a second Candidate
builder. The caller supplies the same seven independent verification pins used
for mandatory package verification. Identity metadata is read only after that
verification, rather than serving as its own authorization.

Supported genuine v2 and scheduled-format v3 runs use the R1 research-Baseline
adapter unchanged. The original `run/` directory, `checksums.json`,
`q1-status.json`, `regression-attribution.json`, result, and `candidate.tar.gz`
remain unchanged by the supplementary diagnostic. The historical original Q1
status remains `Q1_NOT_QUALIFIED_FOR_VERSION_PAIR`.

The final delivery adds only these external diagnostic files:

- `q1-auto-inputs.json`: R1 schema-2 descriptor with relative `run/...` paths;
- `q1-report/`: the existing mapper's JSON report, Markdown, and checksums;
- `q1-supplement.json`: version-1 supplementary receipt, not an approval record.

The receipt binds the exact Parent edge and generation, Candidate generation
and identity, source states/upstreams, Corpus and archived-row hashes, package
and execution pins, original archive digest, descriptor digest, Q1 implementation
digest, report ID, report raw digest and report-checksums digest. Relative paths
remain valid when the **whole delivery directory** is relocated. Moving only
`run/` does not carry or establish a diagnostic.

`verify_supplement(project, delivery, pins, expected_receipt_sha256)` requires
caller-trusted execution pins and a separately retained raw receipt digest.
It re-verifies the original sealed package, exact receipt/descriptor bindings,
Q1 implementation, and report through independent regeneration. A receipt or
self-declared metadata alone cannot qualify an input. A new code revision needs
new reviewed execution pins; historical packages are not repinned. A receipt
hash records integrity, not human approval or a new trust root.

Mandatory original construction and sealed-package verification errors retain
the original fail-closed behavior. They do not produce a qualified supplement.
Optional diagnosis distinguishes `Q1_UNSUPPORTED_FORMAT`,
`Q1_INPUT_QUALIFICATION_FAILED`, `Q1_REPORT_GENERATION_FAILED`, and
`Q1_REPORT_VERIFICATION_FAILED`, retaining the actual stage and exception type
without exception bodies or credentials. Partial diagnostic files may remain
for examination. A failed/unqualified receipt cannot pass `verify_supplement`.
The helper never overwrites existing supplementary evidence. It checks the
original package and archive again even after a diagnostic error. Such an
original preservation failure propagates, rather than becoming a diagnostic
success. No automatic retry is performed.

Supplementary `QUALIFIED` means verified diagnostic inputs and independently
verified report generation. `UNCHANGED`, `MOVED`, `UNRESOLVED`,
`AMBIGUOUS_MAPPING`, `SPLIT`, `MODIFIED`, `REMOVED`, and any other mapper
classifications remain observations requiring the existing scientific review.
No frozen R2 score is adjusted, and no scientific approval, registration,
construction authority, P8 permission, or production activation is granted.
The original run/result remains authoritative for its original execution.

### Existing transport and completion boundary

Both manual and scheduled genuine Continuous jobs already upload the complete
`continuous-result/` directory. That existing Actions Artifact therefore carries
the external supplement without a new Workflow. Its existing retention and
Artifact authenticity requirements still apply. `continuous_completion.retrieve_build`
authenticates and extracts the complete original Actions ZIP, so the supplement
can remain available there for an explicit supplementary verifier.

The existing completion Release has exactly `candidate.tar.gz`,
`release-manifest.json`, and `completion.json`. `continuous_completion.prepare`
verifies the original run/archive and copies only that historical three-asset
set. It neither includes nor verifies the external supplement, and its original
Q1 field remains unqualified. A later lookup of that completion Release does
not preserve or establish R2 diagnostic qualification. R2 does not extend this
publication format, wire supplementary evidence into any approval decision,
or change completion reuse/deduplication semantics. Durable supplementary
Release transport/consumption, if required later, needs separately scoped
review rather than a silent historical format change.

All local v2/v3 integration fixtures use miniature source repositories and
explicit mocked publication/Owner/API/transport observations. They establish
local behavior, not genuine Hosted execution or actual upstream/Owner authority.
Historical pins, deployed Variables, authority gates, Registry, frozen evidence,
and the primary source worktree remain outside the R2 modification scope.
