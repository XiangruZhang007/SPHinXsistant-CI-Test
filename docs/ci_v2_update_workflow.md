# Detection and authorized CI V2 execution

Step 4B connects the existing weekly detector to Step 4A preflight in
`.github/workflows/upstream_refresh.yml`. It does not enable unattended Candidate
builds. The existing `ci_v2_manual_research.yml` remains byte-for-byte unchanged.

The existing CI V1 detector writes `upstream_status.json` once. A new step passes
that exact file to `prepare_ci_v2_update.py`, captures its exit code and uses
`route_ci_v2_update.py export` to check the result. No second branch poll occurs.
The legacy CI V1 cloning, source generation, R1 retrieval and artifact steps
remain unchanged, including their existing behavior of running after detection
even when no update is found. V2 skip conditions do not change legacy V1 behavior.

| Detection/preflight | CI V2 result |
| --- | --- |
| Valid `NO_UPDATE`, exit 0 | No V2 build or Plan transfer |
| `BLOCKED`, exit 1 | Preserve blocker; no V2 build |
| Failed/malformed receipt or missing/mismatched Plan | Routing step fails; no V2 build |
| `PLAN_READY`, exit 0, scheduled/automatic event | V2 execution blocked |
| `PLAN_READY`, manual dispatch, default input | Plan evidence only; no V2 build |
| `PLAN_READY`, first manual dispatch attempt, `build_ci_v2=true` | Revalidate and enter existing V2 executor |

The new optional `workflow_dispatch` boolean `build_ci_v2` defaults to false.
It requests a build, not approval. The exact independent `BUILD_CANDIDATE`
Policy must already authorize the detector's pair. No target-SHA input, Policy
generator, credential or approval flag is introduced.

## Scheduled execution and repeated runs

The existing research restrictions explicitly retain `scheduled_execution:
false`. There is also no reliable durable cross-run execution ledger in the
current integration. The safe implementation therefore wires scheduled
**detection and preflight only**; an eligible scheduled Plan reports
`UNATTENDED_EXECUTION_NOT_AUTHORIZED`, with `SCHEDULED_EXECUTION_DISABLED` and
`DEDUPLICATION_NOT_ESTABLISHED`. These are remaining boundaries, not checks that
can be bypassed by a cache miss or a green preflight.

An execution key binds exact target commits, canonical Parent entry/reference,
Policy checksum, and build/orchestration fingerprints. It identifies equivalent
requests but does not prove prior execution or create authorization. The new
Candidate job uses it for concurrency serialization, not cross-run deduplication
or exactly-once claims. Repeated schedules never start V2 builds. A repeated
attempt of the new manual path is also blocked; a new explicit manual dispatch
can request the same authorized pair again. The old V2 manual Workflow is not
subject to this new routing rule.

## Transfer and execution boundary

The original detector, receipt and Plan bytes are transferred through bounded
base64 job outputs. No Runner-local path is passed between machines. The helper
checks adapter exit/status consistency, strict receipt fields, detector identity,
exact target revisions, unchanged restrictions and the canonical Plan hash. It
also compares the original Plan with the existing metadata planner using the
same revisions and current Registry. It never substitutes a different Plan.

The receiving job checks out the exact Workflow commit, decodes into a new
temporary directory, repeats validation and routing, then writes only the
original verified `plan.json` bytes to a new `$RUNNER_TEMP/p5a`. Missing/truncated
job outputs, Registry/Policy changes and hash or revision mismatches fail closed.
Job outputs are same-run transport, not independent Owner authorization.

CI V1 retains its original Runner. Actual V2 execution uses the existing frozen
`ubuntu-24.04-arm`, CPython 3.12.3, pinned parser checkout/dependencies and
`PYTHONHASHSEED=0`. It invokes the existing
`scripts/ci_v2_schema2_research.py execute-plan` with the restored Plan, retaining
Parent verification, P4.1, mandatory fresh Parent R2 replay, incremental/full
builds, parity, evaluation, Q1 diagnostics and repeated selection validation.
This new path supplies no Q1 package; the old manual Q1 interface is unchanged.

The helper's event/input/attempt checks are routing controls, not process
attestation or Owner identity verification. Real execution relies on the reviewed
Workflow, GitHub event/input job gate and existing independently pinned Policy.
Local tests simulate those contexts and must not be called Hosted acceptance.

## Evidence and permissions

The new preflight step can continue on error solely to preserve legacy V1
behavior. The V2 job requires its raw `outcome == success`, explicit true output,
manual event and explicit build input. A failed step cannot enable construction
even if it partially wrote job outputs. Transfer restore and Candidate execution
never use `continue-on-error`.

`ci-v2-update-preflight-RUN-ATTEMPT` preserves detector/preflight/routing evidence
with an always-run upload. V2 Candidate evidence retains the existing
`ci-v2-research-RUN-ATTEMPT` name and three-root layout: `plan.json`, `run/`,
`candidate.tar.gz`. Uploads retain evidence for 30 days; they are not permanent
archival approval. No Release publication job is added. Existing Release
publication origin checks remain unchanged; compatibility with this different
Workflow origin has not been established and is not claimed.

Permissions remain `contents: read`. The private Release token is scoped only
to the execution step. There is no Actions dispatch, cross-repository credential,
Registry write, automatic approval, Gradio activation or production permission.
All frozen quality/Q1 limitations, P8 blocking and production `NOT_AUTHORIZED`
remain unchanged.

## Offline verification and next validation

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH=tests \
  tools/treesitter-chunker/.venv/bin/python -B -m unittest \
  test_ci_v2_update_workflow test_prepare_ci_v2_update test_check_upstream_updates \
  test_trusted_parent_selection test_schema2_research_parent \
  test_schema2_workflow.WorkflowContractTests \
  test_schema2_workflow.WorkflowParentModeTests \
  test_schema2_workflow.ExecutePlanQ1Tests \
  test_registration_build_separation.EntryContractsTests \
  test_registration_build_separation.BuildBoundaryTests \
  test_trusted_baseline_registration test_private_release_transport \
  test_hosted_registration_workflow test_continuous_corpus.CliTests
```

Tests execute actual export/restore/execution Shell blocks, the real detector
receipt adapter and planner, with isolated synthetic metadata. The real
`execute-plan` CLI is tested with only its expensive method replaced by an
explicit offline stub. No genuine builds, retrieval, Replay or GitHub calls run.
The command above passed 155 tests, including 19 new Workflow integration tests.
YAML parsing, Bash syntax, in-memory Python compilation and whitespace checks
passed. Frozen P2/P3/P4.1/R2 fingerprints remain unchanged.

A future authorized Hosted test should verify the default/no-build and blocked
routes, same-run job output transport and artifact evidence. A genuine build
requires a separately authorized manual dispatch with an existing exact Policy;
current branch heads discovered later may not have one. Do not change detector
history or broaden Policy just to obtain a positive test. Unattended construction
needs a separate resolution of schedule authority and reliable deduplication;
this local integration does not resolve or enable either.
