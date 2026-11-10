# Research Parent R2 result anchors

`src/parent_r2_anchor.py:qualify_parent_anchor` is the single core used by
`schema2_workflow.run_local()` and `verify_run()`. The caller supplies a restored
full Parent, its existing trusted reference and independent reference digest,
and the exact original retrieval rows. No new approval format, ranking logic,
result identity, registry or transport is introduced.

The current registry contains only the historical P2 bootstrap. No real later
Parent is qualified or registered by this change. The existing non-P2 guards
in `plan()` and `run_local()` remain. Planning precedes package download, so it
must never claim full Snapshot/result qualification from metadata alone. Hosted
workflow configuration is unchanged and no runner has executed this change.

## Checks and evidence

The core reuses `trusted_snapshot.validate_reference/verify_package`, existing
schema-2 lineage verification and P4.1 `verify_bundle`. It verifies:

- Independently pinned reference and package manifest; node, package, Corpus,
  source-state and exact upstream commit bindings, compatible frozen build.
- Frozen benchmark, R2 runtime/implementation/configuration and quality policy.
- Exact 128 question/mode combinations, canonical retrieved records, scores,
  evidence availability, frozen criteria and aggregate metrics via `rescore`.
- For research Parents, `RESEARCH_BASELINE` plus `P4_1_VERIFIED` with
  `RETRIEVAL_EVALUATED` and `INDEPENDENT_R2_REPLAY_VERIFIED` evidence.
- Result SHA-256 equals both the external Parent reference pin and the original
  Candidate rows in the sealed approval bundle. The evaluated Corpus and docs
  component equal the approved Parent, and metrics and policy agree.

P4.1 STRUCTURAL_ONLY approval alone is insufficient. An original Candidate ID
and its approved baseline ID are distinct: existing baseline metadata and
evaluation evidence prove their correspondence without rewriting old results.

The fixed historical rows come from the approved bundle's separately pinned
historical reference, not the immediate Parent's own evaluation. The returned
binding record reports both result digests. `run_local()` passes these separate
row sets to the unchanged evaluator. For the initial P2 path they coincide.
This preserves the recorded historical reference; it does not invent a new
historical reference or automatically review a changed one.

Stored P4.1 inspection uses existing sealed replay receipts. It does not attest
to a new execution or cryptographic authenticity. With `fresh_replay=True`
(the default), the core also re-executes unchanged R2 on the selected Parent.
Both existing live and archive paths retain that mandatory fresh replay.
This implementation task executes fresh retrieval only on miniature fixtures.

Without an independent pin, the legacy P2 archive path is explicitly
`ARCHIVE_INTEGRITY_VERIFIED` / `ARCHIVE_INTEGRITY_ONLY`. This is backward-compatible
reinspection, not independent authorization. A research Parent without a pin is
rejected. Pinned P2 metadata/rows inspection without replay is only
`PINNED_ANCHOR_INSPECTED`, not proof of retrieval execution.

## Entry points and compatibility

Existing P2 `local` and `execute-plan` behavior and mandatory failures remain.
Both live and archive consumers use the same core and binding record. New live
results include `parent_r2_anchor`; reinspection verifies it when present, while
old P2 archives remain readable without rewriting historical records.

An optional explicit pin is available for independently anchored reinspection:

```bash
PYTHONHASHSEED=0 python -B scripts/ci_v2_schema2_research.py verify-run \
  --root "$RUN_DIRECTORY" --expected-reference-sha256 "$REFERENCE_SHA256"
```

This command still performs existing mandatory replays: it was not run against
real research corpora in this task. Library inspection can set
`fresh_replay=False` to reuse existing results without retrieval execution.
Controlled fixture qualification is library-test-only, never a CLI override.

## Limits and remaining prerequisites

Synthetic tests use actual R2 and the full frozen 128-row inventory on miniature
Corpora, existing evaluated P4.1 approval, and actual incremental reuse. They
do not authorize the historical Candidate, demonstrate genuine upstream
research-baseline approval or prove hosted readiness. Historical FAILs and
QUALITY_REVIEW_REQUIRED persist; P8 and Promotion Policy are unchanged.

Before opening non-P2 hosted execution, obtain and independently review an
already approved genuine research Parent with evaluated P4.1 evidence and exact
R2 anchor; retain the fixed historical reference; configure pinned immutable
Snapshot/results storage and transition policy; connect qualification after
restore and during archive verification; then separately authorize and test a
real runner execution. This iteration adds no accepting hosted configuration.
No Gradio activation, production approval, automatic baseline registration,
workflow execution, publication or deployment occurs.
