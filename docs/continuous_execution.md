# Versioned continuous execution experiment

**PARTIAL: synthetic execution and portable verification implemented; genuine
live execution disabled.** No operational Continuous Policy, Owner authority,
new Trusted Parent, Workflow or production change is introduced.

## Entry points and trust boundaries

`src/continuous_execution.py` introduces:

- `contract(project)`: canonical identity of the actual new implementation,
  scope/source/transport/Parent validators, frozen dependencies and runtime.
- `execute(...)`: independently checks implementation/Policy/Registry pins,
  then fails with `TRUSTED_CONTINUOUS_EXECUTION_NOT_ESTABLISHED`. There is no
  genuine constructor attached, simulated authorization argument, approval flag,
  environment switch or CLI to unlock it.
- `verify_package(...)`: offline integrity, source, Parent, parity and frozen
  result verification with independently supplied expected pins. No GitHub GETs,
  current branch lookup or current policy-expiry decision occurs here.
- `_build_synthetic_fixture(...)`: private test-only assembly path. It requires
  a local, genuinely evaluated **controlled fixture** Parent, a synthetic policy
  identifier and external test pins. Its output is always
  `CONTROLLED_GIT_FIXTURE`; it cannot produce genuine authorization or an
  approved/reusable Baseline. No public `controlled`/`simulate` bypass is added.

The existing scope assessment remains `execution_authorization=BLOCKED`.
Its evidence is not converted to an approved schema-2 Plan or exact-target policy.
An independently pinned hash proves expected bytes, not an Owner decision or a
trusted process. Genuine execution still needs a reviewed independent execution
authority and live context; that boundary is intentionally not invented here.

## Independently pinned implementation

The caller must supply `expected_execution_contract_sha256` from reviewed
configuration outside the generated output. `contract()` includes exact file
hashes of this module, scope policy, CI orchestration/transport, Parent anchor,
Owner API client and registration/selection validators, plus the unchanged
historical provenance, P2/P3/P4.1/R2 and quality-policy contracts.

The runtime checks the computed contract against that expected digest, compares
the supplied implementation tree with the actual loaded source location, and
runs the existing frozen runtime checks. A different copied source tree cannot
impersonate executing code. Construction checks the contract again before
publishing its owned output directory.

Tests supply expected pins from their isolated harness before construction.
Those pins are external to the output but **are not maintainer-approved deployment
pins**. No genuine expected deployment digest or authority has been installed.
Matching expected/actual synthetic values is not a new build approval.

## New package and deterministic identity

The format is `continuous-research-candidate-v1`, schema version 1. It is separate
from the historical `upstream-research-candidate` schema-2 format.

```text
candidate/continuous-candidate.json  # new identity and Candidate ID
candidate/candidate.json             # distinct evaluator projection
candidate/{corpus,selection,inventory,extraction-graph,...}
candidate/components/               # frozen component format
candidate/input/repos/               # actual frozen selected source bytes
parent/                             # restored controlled P4.1 fixture
full/                               # independently reconstructed snapshot
evidence/                           # exact pins, source proofs and observations
quality/                            # original Candidate/Full R2 outputs
parent-anchor.json                  # actual fresh miniature Parent replay receipt
parity.json                         # all four byte comparisons and both hashes
incremental-replay.json
full-replay.json
extraction-observations/             # retained generator intermediates/summaries
observations.json                   # timing, local paths, explicit test context
checksums.json                      # complete sealed file inventory
```

Candidate ID is `sha256-` plus the canonical identity digest. The closed identity
binds exact commits, actual target source-state, verified Parent ID/package/
corpus/source/generation, new generation, independent Policy/Registry/reference
pins, scope subject, actual execution implementation, historical orchestration,
deterministic source/Corpus artifacts and all research/production restrictions.

Timing, temporary paths, generator summaries and full-build execution metadata
are preserved and sealed but excluded from Candidate ID. Two independent builds
from the same exact source/policy/Parent/code inputs must have the same ID even
when their observation files differ. No important audit evidence is discarded to
obtain identity equality. Private fixture output is published only after checks.

Seals cover all included files. The verifier requires an independent raw
`expected_manifest_sha256` as well as the expected Candidate ID, preventing
post-identity quality/observation files from silently replacing an archive's
external integrity pin. Symlinks, hard links, special files, undeclared files,
empty unrecorded directories, unknown identity fields and inconsistent
projections are rejected.

## Actual reused computations

The test path performs actual safe Parent extraction using `restore()`, sealed
Parent validation and `qualify_parent_anchor(..., fresh_replay=True)`.
The test Parent comes from the existing miniature evaluated-P4.1 factory, not
the genuine archived C1. Failed or structural-only qualification cannot count
as a successful Parent replay.

Source scope/branch/commit checks reuse `assess_scope()` and `revalidate_scope()`.
The synthetic harness explicitly mocks official GitHub API observations and the
remote Registry transport boundary for local fixture references. It does not
mock successful Parent package validation, extraction, rankers, scoring, parity
or R2 execution. No source cloning or real GitHub requests occur in these tests.

A small assembly adapter calls frozen `classify_files()`, `_copy_source()`,
`_extract_changed()`, `_records()`, `_write_lines()` and `_verify_materialized()`.
Only changed/added selected files are extracted. Reused record digests and graph
evidence are checked; deleted files are omitted. Complete selected-file metadata
is passed to extraction at its required `work/candidate/input` layout. Original
generator intermediate files remain sealed as observation-only evidence.

`full_reference()` creates a truly independent full snapshot from canonical
absolute source roots. Format-aware parity validates the new Candidate and full
snapshot, exact target revisions and all four unchanged parity artifacts
byte-for-byte. The old `compare_full()` is not used for a new-format Candidate.

The distinct `continuous-evaluator-projection-v1` exposes only Candidate ID and
the exact Parent/source-state aliases required by frozen evaluation. It is
strictly compared with the verified new identity. This allows unchanged
`evaluate_quality()` and frozen scoring/replay implementations to operate;
it is not a historical schema-2 manifest or approval projection.

The miniature Candidate and full corpus each run all 128 frozen R2 combinations,
then each receives a separate actual replay. Raw rows, aggregate rescoring,
historical/immediate-Parent transitions and oracle applicability are checked.
Frozen FAIL labels, quality thresholds and benchmark bytes are not modified.
Actual miniature computation does not validate the retrieval quality of real
C1/C2 or establish Q1 qualification for any genuine version pair.

## Offline verification versus live authorization

```python
verify_package(project, package, *,
               expected_execution_contract_sha256,
               expected_policy_sha256, expected_registry_sha256,
               expected_reference_sha256, expected_candidate_id,
               expected_manifest_sha256, fresh_replay=False)
```

Offline verification checks archived exact bytes, actual implementation identity,
strict new format/projection, Git trees/blobs/relationships, observed official
ref/publication bindings, actual source/Corpus integrity, evaluated Parent,
generation, independent full parity, frozen rows and saved replay receipts.
It does not call a moving branch or apply today's policy expiry to an old run.
`fresh_replay=True` separately runs actual miniature Parent/Candidate/full R2;
the default reports `SEALED_REPLAY_INSPECTED`, not a new replay.

Saved observations remain historical evidence, not authenticated live API
authority. Self-reported start times do not prove historical policy validity.
Both live and historical Owner authorization remain `NOT_ESTABLISHED` and
`policy_validity_at_execution` remains `NOT_INDEPENDENTLY_ESTABLISHED`.
Archive verification never creates new approval or Trusted Parent eligibility.

## Historical and future compatibility

No historical file, registry, policy, lock, benchmark, workflow or approved
package is changed. C1's orchestration digest remains
`b0b43411aef4d716a15a2f0a794071523fbb3c260dc4cb3fc9b2736eed9e1ac1`.
Old schema-2 verification rejects the new format; the new verifier rejects old
Candidates and rejects relabelling controlled evidence as genuine provenance.

Future P4.1 approval, new-format trusted restoration, Parent R2 qualification
dispatch and Registry compatibility are **not implemented**. Sufficient original
corpora, raw rows, replay receipts, benchmark/quality bindings, Parent anchor,
source evidence and parity are preserved for a separately reviewed adapter.
No call to old `approve()` is used to claim approval of this new format.

Scheduled construction remains disabled. No operational Policy is granted;
automatic research approval/registration, Gradio activation and production
promotion remain unavailable. No exactly-once execution is claimed.

## Offline regression command

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH=tests \
 tools/treesitter-chunker/.venv/bin/python -B -m unittest \
 test_continuous_execution test_continuous_build_policy \
 test_ci_v2_update_workflow test_prepare_ci_v2_update test_check_upstream_updates \
 test_trusted_parent_selection test_schema2_research_parent \
 test_schema2_workflow.WorkflowContractTests \
 test_schema2_workflow.WorkflowParentModeTests \
 test_schema2_workflow.ExecutePlanQ1Tests \
 test_registration_build_separation.EntryContractsTests \
 test_registration_build_separation.BuildBoundaryTests \
 test_trusted_baseline_registration test_private_release_transport \
 test_hosted_registration_workflow test_continuous_corpus.CliTests \
 test_parent_r2_anchor.AnchorTests.test_evaluated_synthetic_qualification_and_distinct_candidate_baseline_ids \
 test_parent_r2_anchor.AnchorTests.test_fresh_miniature_replay_matches_sealed_inspection \
 test_parent_r2_anchor.AnchorTests.test_fresh_replay_mismatch_remains_mandatory_failure \
 test_parent_r2_anchor.AnchorTests.test_structural_only_approval_cannot_qualify \
 test_approval_evidence.ApprovalEvidenceTests.test_valid_evaluated_approval_and_distinct_statuses
```

The suite prints `SYNTHETIC_EXECUTION_EVIDENCE` with actual reuse, generation,
Candidate ID and matching harness-expected/actual implementation digests. Those
values describe disposable fixtures, not independent human authorization.
No real research build, C1/C2 replay, Hosted test or publication is performed.

## Recorded local result

The documented command passed **219 tests**: the existing 188-test suite, 26
new execution tests and five additional historical Parent/P4.1 compatibility
tests. The actual synthetic generation-2 run selected 48 files, reused 46 files
and 45 chunks, extracted two changed/added files and removed one deleted file.
Independent four-artifact parity was `PARITY_PASS`; Candidate and full each
completed 128 frozen evaluation rows and matching independent replay.

Harness-expected and actual execution contract digests both were
`2d9c41cc55d5f6c7dd8022280e38b7d1ec8ad5d991d7e452396dfa02e19220e3`.
This is an observed code/test-fixture digest, **not an Owner-approved deployment
pin**. Genuine deployment's independently reviewed expected digest is absent.

The synthetic Candidate ID was
`sha256-9ce7e49a93d55a65c32c7f502de1ffa9c27370f04d3e5c444ceb5e531cf3dee9`.
It is not the genuine C2, a Research Baseline or a registered Parent. Disposable
fixtures are cleaned by the test harness; no new permanent research package is
published or installed. Live authorization remains blocked, and future P4.1,
Registry and genuine continuous execution integrations remain unimplemented.
