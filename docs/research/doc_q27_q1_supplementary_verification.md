# DOC-Q27: supplementary Q1 verification

Date: 2026-11-07. Development checkpoint:
`973170b81f995f9702ff18aa1aca6a8f1013cf6b`, branch `ci-upstream-refresh`,
initial working tree clean. This is a separate diagnostic record. It does not
replace the [manual investigation](doc_q27_evidence_location_drift.md), the
frozen evaluation, or any existing attribution or authorization record.

## Finding

**The existing Q1 implementation supports this case without semantic changes.**
Its existing qualified input archive describes the same parent, candidate,
upstream revisions, source states, corpora and archived retrieval rows as the
saved hosted run. Reverification of that report succeeded, and regeneration
using an isolated copy of the hosted package produced the same logical report.
DOC-Q27 meets the existing Q1 correspondence checks in both corpus modes.
The original hosted run remains recorded as `Q1_NOT_QUALIFIED_FOR_VERSION_PAIR`;
no historical status was rewritten. Evidence and exact verification procedures
are listed below. [Q1 archive][inputs] [Qualified report][report] [Runner ZIP][runner]

## Existing mechanism and qualification boundary

[State validation](../../src/version_aware_evidence.py#L60) verifies source-state
identity, selected source bytes and Git blob IDs, corpus association, record
source spans, roles and unique chunk identities. Genuine inputs also require
portable commit/tree proofs for both repositories. Controlled fixtures cannot
claim genuine upstream provenance.

[The genuine-input loader](../../src/version_aware_evidence.py#L419) additionally
requires an independently pinned `q1-verified-inputs` manifest, safe input paths,
compatible current builder, a verified P2 snapshot, a verified genuine upstream
candidate, correct parent/target relationship, exact source-state and upstream
bindings, documentation subsets and corpus hashes, the frozen benchmark and
evaluator/runtime identity, and matching archived result hashes. It rescores
saved rows against the unchanged matcher to check their consistency; it does
not execute retrieval or regenerate chunks.

[The existing mapper](../../src/version_aware_evidence.py#L254) extracts the
original frozen line range and looks for its exact raw bytes. In a changed file,
the target match must be unique. It separately checks location, content,
eligible corpus byte coverage and frozen locator applicability. Thus unchanged
documentation moving within a modified file is already supported. The existing
[historical DOC-Q27 test](../../tests/test_version_aware_evidence.py#L274) expects
`MOVED`, lines 101-104 to 103-106, identical passage hashes, unique mapping and
single-chunk coverage while preserving the target frozen FAIL.

[Schema-2 diagnostic qualification](../../src/schema2_workflow.py#L56) further
checks six run bindings: base/target source states, parent/candidate IDs and
base/target corpus hashes. Both archived-row digests must match this execution.
Finally, a relocated descriptor using the execution package must regenerate the
same report. None of these checks grants research or production approval.

## Why the hosted run did not qualify Q1

The saved ZIP contains `run/q1-status.json` with only
`{"status": "Q1_NOT_QUALIFIED_FOR_VERSION_PAIR"}` and has no Q1 input descriptor
or Q1 report directory. The status has no error reason. [Runner ZIP][runner]

This agrees with the existing execution path: the
[workflow](../../.github/workflows/ci_v2_manual_research.yml#L59) invokes
`execute-plan`, whose [call to run_local](../../src/schema2_workflow.py#L231)
does not pass the optional `q1_inputs` or `q1_sha` arguments.
[Diagnostics](../../src/schema2_workflow.py#L60) only attempts qualification when
`q1_inputs` is supplied; otherwise it keeps the default unqualified state.
The observed status therefore does not demonstrate a failed DOC-Q27 mapping or
an unsupported version pair. This explanation combines the archived status with
code inspection; a new hosted execution was not performed.

## Verified version and evidence bindings

These revisions are from the independently pinned Q1 manifest and the saved
Runner result bindings; both agree. [Input manifest][inputs] [Runner result][result]

| Repository | Historical / P2 parent | Candidate |
| --- | --- | --- |
| SPHinXsim | `9cdae783e3ef3f8926c2174a0db89e96846befad` | `dceacd4e509a8592b802cf44bb2885bea7ddfdb3` |
| SPHinXsys | `4e686ee357de1cb798ac47eb760dd79e2fb407ff` | `351368e108f47f8d15f89baac96683ecadaee32c` |

Parent ID:
`sha256-798d0d1284c7dbba06d5788a062973bf7290cbbfdef28150037371fa78b7188a`.
Candidate ID:
`sha256-d7c95bbf42703d209a5a20f60540cf04b7134736ead650d8c95d66adaee724b8`.
Both corpora, both archived raw-result files, the benchmark and both DOC-Q27
source files were also compared byte-for-byte between the Q1 inputs and Runner
ZIP and matched. [Input manifest][inputs] [Runner ZIP][runner]

## Supplementary verification performed

1. Recomputed the existing input-manifest SHA-256 and matched the separately
   saved [expected checksum][pin]:
   `8aacbd1450a2cdcee46d51c1023613bdad6231b4d565996c32e304327f04451e`.
   Checked that all implementation dependencies recorded in the qualified Q1
   report match the current files.
2. Ran the existing CLI `verify` command below. It returned exit code 0,
   `status: VERIFIED`, and the original report ID
   `sha256-ba54d9946a0adfe604c912b7e35aeced5fdf6724bbe50e9aebb3620d7a3fe484`.
   The [verifier](../../src/version_aware_evidence.py#L485) regenerates the full
   existing diagnostic report and checks complete logical JSON and Markdown;
   its input validation includes archived-row rescoring, not retrieval replay.
3. Verified the saved Runner ZIP checksum against the value in the
   [manual investigation](doc_q27_evidence_location_drift.md), then copied 2,091
   required parent/candidate and benchmark/result members into a process-owned
   temporary directory. Each copied file matched `run/checksums.json`.
   A first copy omitted executable permissions and correctly failed candidate
   discovery validation. Restoring the original ZIP file modes in a new copy
   resolved that copy error; no validator or original artifact was changed.
4. Reused the existing manifest pins with exactly the relocated `paths` mapping
   used by [schema2_workflow.diagnostics](../../src/schema2_workflow.py#L74).
   Ran existing `q.generate` on that isolated Runner copy. The regenerated report
   matched the existing qualified report by the repository's canonical digest;
   all six execution bindings and both archived-row digests matched.
5. Checked the two DOC-Q27 requirement rows described below. Removed the
   temporary input copy after verification. No corpus generation, retrieval
   benchmark execution, independent retrieval replay, LLM request or automated
   test suite was run.

Existing CLI invocation, from the development repository:

```bash
PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 \
  tools/treesitter-chunker/.venv/bin/python -s -B \
  scripts/version_aware_evidence.py verify \
  --inputs ../SPHinX_AI_Assistant_artifacts/evidence_applicability/q1_v1_20261029T215617Z/inputs/inputs.json \
  --expected-inputs-sha256 8aacbd1450a2cdcee46d51c1023613bdad6231b4d565996c32e304327f04451e \
  --report ../SPHinX_AI_Assistant_artifacts/evidence_applicability/q1_v1_20261029T215617Z/validated/analysis-final
```

## DOC-Q27 correspondence result

The following values apply independently to `combined` and
`documentation_only`. They were reproduced using the existing implementation,
and match the [qualified report][report].

| Check | Result |
| --- | --- |
| Source path | `repos/SPHinXsim/docs/installation-windows.md` |
| Primary classification | `MOVED` |
| Whole-file state / passage state | `MODIFIED` / `UNCHANGED` |
| Correspondence | `UNIQUE`, exact raw passage |
| Historical / candidate lines | 101-104 / 103-106 |
| Historical / candidate Q1 raw byte intervals | `[2265, 2437)` / `[2479, 2651)` |
| Identical Q1 passage SHA-256 | `82fe3f883ba2e7c77456c3591ec2fc603b547e433a92b9a91258efbda0bc4e23` |
| Base / target eligible corpus coverage | `SINGLE_CHUNK` / `SINGLE_CHUNK` |
| Frozen locator / applicability | `STALE` / `STALE_LOCATOR` |
| Mapped target evidence rank | 1 |
| Frozen target Hit@5 / Hit@10 | FAIL / FAIL |

Q1 deliberately omits the final line terminator from a frozen range, as specified
by [_range](../../src/version_aware_evidence.py#L143). Its 172-byte passage is
therefore one byte shorter than the complete 173-byte Notes chunk documented
in the manual investigation. The byte endpoints and passage hash above do not
conflict with that report's complete chunk endpoints and hash.

## Status, limits and smallest next action

This supplementary verification meets the existing Q1 source-correspondence,
report-reproduction and execution-binding checks for this exact version pair.
It supports the manual `EVIDENCE_LOCATION_DRIFT` finding without modifying Q1
semantics. It is distinct from the original hosted run's persisted qualification
and attribution records. Those retain `Q1_NOT_QUALIFIED_FOR_VERSION_PAIR` and
`ATTRIBUTION_UNCERTAIN`. [Runner result][result] [Runner ZIP][runner]

The [existing attribution formatter](../../src/regression_attribution.py#L57)
can use qualified unique, unchanged evidence with a stale locator to diagnose
`BENCHMARK_LOCATOR_INVALIDATED`. With verified mapped evidence in Top K, it can
explain an applicability change. That formatter was inspected but not rerun here;
this report creates no replacement attribution record or approval mechanism.

No overall quality acceptance follows from this case. P8 remains `BLOCKED`,
production promotion remains `NOT_AUTHORIZED`, and there is no deployment or
automatic-switch authority. Remote upstream publication was not freshly
authenticated; the existing offline Git/publication proofs were validated by
the supported loaders. [Runner result][result]
[P8 implementation](../../src/update_eligibility_gate.py#L220)

The smallest next action is a separately scoped diagnostic integration change
that supplies the already verified, pinned Q1 inputs to the hosted diagnostic
path, with focused tests for missing or mismatched inputs. Preserve frozen
scores and historical attribution records, and assess overall candidate quality
and release authorization separately. No integration change is made here.

[inputs]: ../../../SPHinX_AI_Assistant_artifacts/evidence_applicability/q1_v1_20261029T215617Z/inputs/inputs.json
[pin]: ../../../SPHinX_AI_Assistant_artifacts/evidence_applicability/q1_v1_20261029T215617Z/expected-inputs-sha256.txt
[report]: ../../../SPHinX_AI_Assistant_artifacts/evidence_applicability/q1_v1_20261029T215617Z/validated/analysis-final/version_aware_evidence_report.json
[runner]: ../../../SPHinX_AI_Assistant_artifacts/p5a3b_hosted_runner/run_41617493805_attempt_1/ci-v2-research-41617493805-1.zip
[result]: ../../../SPHinX_AI_Assistant_artifacts/p5a3b_hosted_runner/run_41617493805_attempt_1/inspection/result.json
