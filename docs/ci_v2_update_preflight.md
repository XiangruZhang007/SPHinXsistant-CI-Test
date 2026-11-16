# Upstream detection to CI V2 preflight

`scripts/prepare_ci_v2_update.py` consumes the existing output of
`scripts/check_upstream_updates.py`. It performs no network requests, builds,
retrieval, replay, approval, registration or application activation. It does not
change either Workflow. This is an offline adapter, not a continuous build loop.

```bash
python3 -B scripts/prepare_ci_v2_update.py \
  --detection "$RUNNER_TEMP/upstream_status.json" \
  --output "$RUNNER_TEMP/new-update-preflight"
```

The input must be a regular JSON file containing exactly `SPHinXsys` and
`SPHinXsim`. Each record must have exactly `branch`, `baseline_commit`,
`latest_commit` and `update_available`. Both commits must satisfy the existing
lowercase 40-character SHA contract; the boolean must equal the commit inequality.
Duplicate/unknown fields, malformed records and contradictory flags are rejected
before even returning `NO_UPDATE`. The report byte hash is diagnostic identity,
not proof of upstream authenticity, freshness, ancestry or authorization.

| Status | Exit | Output |
| --- | --- | --- |
| `NO_UPDATE` | 0 | `result.json`; no Plan and no planner invocation |
| `PLAN_READY` | 0 | `result.json` plus unchanged planner output in `plan.json` |
| `BLOCKED` | 1 | Diagnostic `result.json` when the new output can be written; no Plan |

Argument syntax errors retain argparse's exit 2. An unsafe output destination or
I/O failure returns sanitized JSON on stdout and exit 1; existing files are never
overwritten. The output must be a new directory outside the source repository,
under an existing parent. Failed receipt writes remove only newly owned files,
including the Plan. Never use protected historical evidence as an output parent.

`NO_UPDATE` means only that the detector's reported baseline commits equal its
reported latest commits. The CI V1 baseline config and CI V2 Trusted Registry
are independent. This status does not establish synchronization with the newest
Trusted Parent, validate the Registry or poll current upstream branches.

For updates, the adapter calls the existing `schema2_workflow.plan_auto()` with
the exact detected pair, current project and authoritative Registry path. It
neither ranks Parents nor creates Policies. `NO_ELIGIBLE_PARENT` and
`AMBIGUOUS_PARENT` retain their existing reasons; corrupt Registry/Policy evidence
remains fatal and is not treated as a harmless nonmatch. Other malformed planner
evidence is reported as `INVALID_PLANNING_EVIDENCE`. Invalid detector evidence
is separately reported as `INVALID_DETECTION`.

`plan.json` is the existing `SCHEMA2_AUTO_PLAN` document, not an envelope. A later
explicitly authorized invocation of the existing `execute-plan --plan` can read
it directly. `result.json` contains its selected key and canonical JSON SHA-256,
the detected and baseline pairs, raw detection hash, update flag and unchanged
research restrictions. The canonical Plan hash is not a hash of its pretty-printed
file bytes and is not an approval credential. A future caller must require both
exit 0 and `status == PLAN_READY`, not exit 0 alone.

Private Parent metadata retains the existing same-repository GitHub identity
checks. The adapter does not set `GITHUB_REPOSITORY`, `GITHUB_REPOSITORY_ID` or
other runtime identity variables. Without the required context it remains
`BLOCKED`; simulated context is used only by isolated offline tests. A metadata
Plan is never proof of trusted Hosted execution or Owner approval.

The executor still revalidates selection, downloads and qualifies the Parent,
verifies exact Git source/ancestry/source-state and build authorization, and
runs the mandatory R2, incremental/full construction and evaluation gates.
`REGISTRATION_ONLY` remains ineligible. All existing quality/Q1 limitations,
P8 blocking, `automatic_research_approval: false`, `automatic_reuse: false` and
production `NOT_AUTHORIZED` remain unchanged.

## Offline verification

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH=tests \
  tools/treesitter-chunker/.venv/bin/python -B -m unittest \
  test_prepare_ci_v2_update test_check_upstream_updates \
  test_trusted_parent_selection test_schema2_research_parent \
  test_schema2_workflow.WorkflowContractTests \
  test_schema2_workflow.WorkflowParentModeTests \
  test_schema2_workflow.ExecutePlanQ1Tests \
  test_registration_build_separation.EntryContractsTests \
  test_registration_build_separation.BuildBoundaryTests \
  test_trusted_baseline_registration test_private_release_transport \
  test_hosted_registration_workflow test_continuous_corpus.CliTests
```

Tests reuse existing isolated metadata fixtures and the real planner; they do
not create genuine Corpus versions or perform R2. No GitHub access is needed.
The command above passed 136 tests, including 20 adapter tests. Both new Python
files compile in memory. Frozen runtime verification passed with unchanged
P2/P3/P4.1/R2 fingerprints. No existing tracked file was changed.
The next integration should consume the existing detector receipt rather than
poll upstream twice, pass only `PLAN_READY` into a separately authorized build,
and retain exact SHA checkout and the existing frozen Runner. No Workflow
dispatch, archival opt-in, authoritative registration or automatic approval is
enabled by this adapter.
