# DOC-Q27 investigation and manual adjudication

Recorded on 2026-11-07 against development checkpoint
`688e17b527f2d09e2fb4a69ca21edb6aeecc6498` on `ci-upstream-refresh`.
This report records a manual finding of **EVIDENCE_LOCATION_DRIFT**. It leaves
the frozen evaluation FAIL and formal attribution **ATTRIBUTION_UNCERTAIN**
unchanged. It grants no quality acceptance, baseline approval, or release
authorization. The evidence and the separate status decisions are detailed below.

## Evidence references and verification

Repository references are versioned with this report. References to the saved
Runner evidence use the existing sibling artifacts directory; that directory is
not included in this documentation commit. Archive member names below are exact
paths inside the linked ZIP, not additional files created by this investigation.

| Reference | Existing evidence |
| --- | --- |
| E1 | [Frozen benchmark](../../tests/retrieval_benchmarks/step_1_6_combined_frozen_v2.json#L1267), DOC-Q27 definition and historical availability annotation. |
| E2 | [Historical reference results](../../tests/retrieval_benchmarks/step_1_6_frozen_v2_support/reference-results.json), rows selected by `id = DOC-Q27` and `mode = documentation_only` or `combined`. |
| E3 | [Saved Runner ZIP](../../../SPHinX_AI_Assistant_artifacts/p5a3b_hosted_runner/run_41617493805_attempt_1/ci-v2-research-41617493805-1.zip) and [saved outer checksums](../../../SPHinX_AI_Assistant_artifacts/p5a3b_hosted_runner/run_41617493805_attempt_1/SHA256SUMS.txt). The ZIP contains the source snapshots, corpora, raw result rows, diagnostics, and `run/checksums.json`. |
| E4 | [Saved result](../../../SPHinX_AI_Assistant_artifacts/p5a3b_hosted_runner/run_41617493805_attempt_1/inspection/result.json), byte-identical to E3 member `run/result.json`; includes candidate/parent identities, upstream bindings, quality and authorization status. |
| E5 | [Saved quality report](../../../SPHinX_AI_Assistant_artifacts/p5a3b_hosted_runner/run_41617493805_attempt_1/inspection/quality-report.json), byte-identical to E3 member `run/quality/quality-report.json`. |
| E6 | [Saved oracle applicability report](../../../SPHinX_AI_Assistant_artifacts/p5a3b_hosted_runner/run_41617493805_attempt_1/inspection/oracle-applicability.json), byte-identical to E3 member `run/quality/oracle-applicability.json`. |
| E7 | [Frozen criterion matcher](../../src/retrieval_evaluation_criteria.py#L2), [availability and scoring](../../src/remediation_evaluation.py#L18), and [documentation chunk identity](../../src/documentation_chunking.py#L282). |
| E8 | [Existing P8 gate](../../src/update_eligibility_gate.py#L220), including quality, unresolved-regression and production-authorization checks immediately above `evaluate`. |

The ZIP SHA-256 was recomputed as
`c7b68d90feb620d020f58d6ac52ce2becf14ab03943e5bd8b5f3fcbf08613cfc`.
The source snapshots, benchmark, parent/candidate/full corpora, raw result files,
quality report, oracle applicability report, verified target ranks, formal
attribution and final result cited below were rehashed and matched against
`run/checksums.json`. The repository benchmark was also compared byte-for-byte
with `run/benchmark.json`; both SHA-256 values are
`bac0b31b74410eaff00246e628187ee07c4aaefb8747ad076f090393b71d1ab7`.
These are local consistency checks of existing evidence, not a new pipeline run
or independent authentication of the remote publisher. [E1][e1] [E3][e3]

## A. Case identity

The benchmark is `step_1_6_frozen_evaluation_v2` (`schema_version: 1`), question
`DOC-Q27`: "What should I do if cl is not found when building SPHinXsim on
Windows?" Its frozen requirement is a documentation record from
`repos/SPHinXsim/docs/installation-windows.md` fully covering lines **101-104**.
The specification uses `ALL_OF` and `single_evidence`; its historical
`CURRENT_SOURCE_VERIFIED` annotation does not verify applicability to later
upstream revisions. [E1][e1]

The saved run binds the following revisions. The parent is the archived P2
baseline used for the immediate comparison; historical Step 1.6 reference
rankings are independently listed in E2. The source bytes and complete chunk
record in the parent reproduce the historical Notes evidence. [E2][e2] [E3][e3]
[E4][e4]

| Repository | Historical / P2 parent revision | CI V2 candidate revision |
| --- | --- | --- |
| SPHinXsim | `9cdae783e3ef3f8926c2174a0db89e96846befad` | `dceacd4e509a8592b802cf44bb2885bea7ddfdb3` |
| SPHinXsys | `4e686ee357de1cb798ac47eb760dd79e2fb407ff` | `351368e108f47f8d15f89baac96683ecadaee32c` |

The parent Snapshot ID is
`sha256-798d0d1284c7dbba06d5788a062973bf7290cbbfdef28150037371fa78b7188a`.
The candidate ID is
`sha256-d7c95bbf42703d209a5a20f60540cf04b7134736ead650d8c95d66adaee724b8`;
its corpus SHA-256 is
`224fd0723fd0d77a3f8ad7cd300ecd31856fd689b0fc5e6c942b8d691ef63f8d`.
These identities are from `run/result.json` bindings; the corpus hash was also
recomputed from the archived bytes. [E3][e3] [E4][e4]

## B. Historical and parent evidence

The historical reference rows identify the Notes record below at rank 1 in both
corpus modes. The P2 parent corpus and its independently saved evaluation rows
contain the same record and ranks. Evidence locations in E3 are
`run/parent/sources/SPHinXsim/docs/installation-windows.md`,
`run/parent/corpus.jsonl`, and `run/parent-raw-results.json`. [E2][e2] [E3][e3]

| Field | Verified historical / parent evidence |
| --- | --- |
| Source path | `repos/SPHinXsim/docs/installation-windows.md` |
| Source file SHA-256 | `4ed25c9b0fe539eeb70feda3bed2dca81e3c0628281590e21df73ae349435f93` |
| Complete chunk ID | `doc-ad1a6343fd27e571706d28436769e8b73b30d62c8ca6f021774fd26036506f60` |
| Inclusive line range | 101-104 |
| Byte range, start inclusive / end exclusive | `[2265, 2438)` |
| Documentation-only rank | 1 in historical reference and P2 parent results |
| Combined rank | 1 in historical reference and P2 parent results |
| Strict Hit@5 / Hit@10 | PASS / PASS in both modes |

The source SHA-256 above was verified against the saved parent source bytes and
archive manifest, rather than inferred from a chunk ID. Historical reference
rankings and immediate-parent rankings are distinct observations; equal ranks
do not imply equal retrieval scores. [E2][e2] [E3][e3]

## C. CI V2 candidate evidence

Candidate evidence locations in E3 are
`run/candidate/input/repos/SPHinXsim/docs/installation-windows.md`,
`run/candidate/corpus.jsonl`, and
`run/quality/incremental-raw-results.json`. The saved independent full-build
corpus and rows are `run/full/corpus.jsonl` and
`run/quality/full-raw-results.json`; both are byte-identical to their candidate
counterparts. No corpus generation or retrieval evaluation was rerun for this
report. [E3][e3]

| Field | Verified candidate evidence |
| --- | --- |
| Source path | `repos/SPHinXsim/docs/installation-windows.md` |
| Source file SHA-256 | `1ead94b2c0513ab7bd7c676afff972e0c374f9e44338c5c71f2f694b722a969c` |
| Complete chunk ID | `doc-d7d126a693b55ff9a03349edca81d2ce2e226a0fb9e4b4a70c4a3420157811be` |
| Inclusive line range | 103-106 |
| Byte range, start inclusive / end exclusive | `[2479, 2652)` |
| Documentation-only rank of the Notes content | 1 |
| Combined rank of the Notes content | 1 |
| Strict frozen criterion rank | `null` (`evidence_ranks: [null]`) in both modes |
| Strict Hit@5 / Hit@10 | FAIL / FAIL in both modes |

The Notes content's observed rank 1 must not be confused with the unavailable
strict criterion rank. `run/quality/verified-target-ranks.json` reports frozen
requirement availability, not a new rank for manually matched equivalent text.
The raw rows mark `evidence_available: false` and `failure_type: COVERAGE_GAP`.
The evaluation code assigns that label when exact frozen evidence is unavailable;
it does not establish that the answer text disappeared. [E3][e3] [E7][e7]

## D. Observations and technical interpretation

Comparing the two archived source files shows exactly two inserted lines at
candidate lines 53-54, immediately after the pip installation code block in
Configure and Build. They add a Windows long-path warning and a Microsoft
documentation URL. The document grows from 104 to 106 lines and from 2,438 to
2,652 bytes. No other source-file changes appear in that comparison. [E3][e3]

The Notes section shifts by **two lines and 214 bytes**. Its entire content,
including its heading, blank line, two list items and final newline, is
byte-identical in both source slices and corpus records. Both content hashes are
`a0de5539fc1ab8ef4fd5aea05970e58d26792508a78a3e1f779e6c2f40a0b24e`.
The unchanged content is: [E3][e3]

```markdown
## Notes

- If `cl` is not found, reopen a Visual Studio developer shell and rerun configure.
- If CMake cache gets inconsistent, remove `build-integrated` and reconfigure.
```

The chunk's heading hierarchy, section identity, content and grouping remain
unchanged; only `start_line`, `end_line`, `byte_start`, `byte_end` and `chunk_id`
differ in the complete Notes records. The chunk identity incorporates the whole
source-file digest and byte positions, so its new ID is expected even though
this paragraph is unchanged. The strict matcher checks source path, role and
line containment; the historical chunk ID annotation is not the direct cause
of the failure. [E3][e3] [E7][e7]

The preceding Run Tests chunk now covers lines 71-102, and Notes covers 103-106.
The frozen 101-104 requirement spans these two chunks. Scanning the saved
candidate corpus finds no single record from the required path fully containing
that range, whereas the parent has one. In particular, the Notes record cannot
satisfy `start_line <= 101 <= 104 <= end_line` because its start is 103.
This explains the strict FAIL without a loss of the target content or a changed
Notes section boundary relative to that content. [E1][e1] [E3][e3] [E7][e7]

**Manual technical finding: EVIDENCE_LOCATION_DRIFT.** There is no observed
DOC-Q27 ranking regression for the unchanged Notes content: it remains rank 1 in
both modes. This is a case-specific finding about saved retrieval evidence; it
does not claim identical scores, overall retrieval stability, or answer quality.
[E2][e2] [E3][e3]

## E. Adjudication, formal status and authorization limits

| Layer | Finding or status retained | Evidence / authority |
| --- | --- | --- |
| Observed evidence | Unchanged Notes content moved from 101-104 to 103-106; rank 1 in both modes. | E2; E3 source snapshots, corpora and raw rows. |
| Manual interpretation | `EVIDENCE_LOCATION_DRIFT`; explanatory narrative only. | Source and record comparisons in section D; no automated adjudication or approval format introduced. |
| Frozen evaluation | Candidate DOC-Q27 remains FAIL at Hit@5 and Hit@10 in both modes; no criteria or result edits. | E1; E3 `run/quality/incremental-raw-results.json`. |
| Existing applicability diagnostic | `RANGE_CHANGED_OR_ORACLE_STALE_REVIEW`; frozen criterion not modified. | E6. |
| Formal attribution | `ATTRIBUTION_UNCERTAIN`; final human decision remains `PENDING`. | E3 `run/regression-attribution.json`, both DOC-Q27 rows. |
| Q1 qualification | `Q1_NOT_QUALIFIED_FOR_VERSION_PAIR`; qualified correspondence unavailable. | E4; E3 `run/regression-attribution.json`. |
| Overall quality | `QUALITY_REVIEW_REQUIRED`; `RETRIEVAL_QUALITY_ACCEPTED: false`. | E4; E5. |
| Research baseline approval | `RESEARCH_BASELINE_APPROVED: false`. | E4. |
| P8 eligibility | Must remain `BLOCKED`; this report supplies no trusted release authorization and changes no recorded losses. | E8, code inspection, together with E4/E5. P8 was not rerun for this report. |
| Production promotion | `NOT_AUTHORIZED`; no deployment or automatic corpus switching authority. | E4; E8. |

The formal attribution states "Qualified Q1 correspondence is unavailable" and
`ranking_regression_demonstrated: false`. Manual source comparison does not
retroactively qualify Q1, change formal labels, resolve the saved pending human
decision, or waive quality/release restrictions. The smallest justified action
here is to preserve this explanatory report alongside the unchanged evaluation
evidence. Any future version-aware evaluation change would require separate
scope and validation; changing the frozen line range to force PASS is not part
of this work. [E3][e3] [E4][e4] [E8][e8]

Verification limits: upstream commit identities were checked in the archived
bindings, not freshly authenticated against remote repositories. The stored
hashes establish agreement with the saved manifests, not independent remote
provenance. No new retrieval replay, LLM answer evaluation, or production test
was performed. The full underlying evidence remains in the external archive;
the repository report alone cannot replace it. [E3][e3] [E4][e4]

[e1]: ../../tests/retrieval_benchmarks/step_1_6_combined_frozen_v2.json#L1267
[e2]: ../../tests/retrieval_benchmarks/step_1_6_frozen_v2_support/reference-results.json
[e3]: ../../../SPHinX_AI_Assistant_artifacts/p5a3b_hosted_runner/run_41617493805_attempt_1/ci-v2-research-41617493805-1.zip
[e4]: ../../../SPHinX_AI_Assistant_artifacts/p5a3b_hosted_runner/run_41617493805_attempt_1/inspection/result.json
[e5]: ../../../SPHinX_AI_Assistant_artifacts/p5a3b_hosted_runner/run_41617493805_attempt_1/inspection/quality-report.json
[e6]: ../../../SPHinX_AI_Assistant_artifacts/p5a3b_hosted_runner/run_41617493805_attempt_1/inspection/oracle-applicability.json
[e7]: ../../src/retrieval_evaluation_criteria.py#L2
[e8]: ../../src/update_eligibility_gate.py#L220
