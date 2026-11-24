# Automatic quality V3: implementation and migration review

Status: implemented locally. The Owner accepted the critical labels and aggregate
engineering thresholds in principle. Final reference/policy approval and concrete migration execution approval remain
pending. The proposed tracked V3 files are finalized with enabled=true for Owner
review; remote activation still uses the old policy and has not been changed.
Production deployment remains disabled.

## Acceptance semantics

Native v5 uses AUTOMATIC_QUALITY_V3 only under lifecycle policy schema 3. Native
v4 and its AUTOMATIC_QUALITY_V2 decision remain readable without reinterpretation.
Original frozen benchmark bytes, 128 original R2 rows, official scores, Q1
report, Full parity, lineage, license proofs and old rejection evidence persist.
The V3 report contains its frozen V2 decision and separate admission observations.
There is no retry with weaker criteria after rejection.

References are new, reviewable relevance judgments, not corrections to official
scores. Every original question and requirement remains in the domain. Exact
symbol/heading and literal predicates are evaluated against verified records.
ALL_OF evidence can occupy multiple Top5/Top10 chunks, with no larger retrieval
budget. Ambiguous or missing scope/literals are unresolved. Unknown primary
questions remain in the denominator and count as failures. Noncritical diagnostic
questions remain reported outside the original primary denominator; critical
questions are checked even when diagnostic.

Critical proposals are C-11 (dimensional bounds), C-12 (exposed simulation types),
C-14 (scientific solver defaults), C-28/C-29/C-30 (capability boundaries), and D-02
(backend defaults). Missing, ambiguous/conflicting or unverifiable critical corpus predicates block
admission unconditionally. The same is true when the immediate Parent or fixed
initial Parent cannot establish verifiable critical evidence for comparison.

For resolved critical requirements, every required evidence unit is compared at
Top5 and Top10 against BOTH Parents. Any previously covered unit becoming
uncovered blocks admission, even if the question was already incomplete and even
if other units improve. Requirement/unit positions bind to the same reviewed
predicates; changing chunk IDs is allowed. Malformed, inconsistent, nonmonotone or
incomparable observations fail closed. Critical diagnostic questions are included.

Remaining ranking gaps inherited from both verified baselines are reported as
VERIFIED_INHERITED_RANKING_LIMITATION baseline debt. They do not independently
block a research knowledge-base update. Absolute critical Top10 completeness is
reported separately as an application-quality limitation, not production readiness.
The critical_failures=0 field means zero corpus verification failures or coverage
regressions, not zero inherited ranking debt. No critical label is removed.

Predicates are mechanical, scoped evidence probes, not an oracle for arbitrary
semantic contradictions or runtime solver capability. Ambiguous definitions are
unresolved. Relevance judgments require review; literal presence alone does not
prove a complete answer or that an exposed simulation succeeds.

## Proposed engineering thresholds

| Stratum | Hit@5 minimum | Hit@10 minimum | New losses per cutoff | Fixed-root losses per cutoff | Unknown primary questions |
|---|---:|---:|---:|---:|---:|
| Combined primary (84) | 60% | 65% | 1 | 1 | 1 |
| Documentation only (40) | 90% | 90% | 1 | 1 | 1 |

Critical failures: zero. Losses are gross, not offset by gains. The same initial
Parent is checked at every generation; tolerances cannot accumulate per Parent.
Percent floors use integer arithmetic. Repeated question modes are not treated
as independent statistical samples and no statistical significance is claimed.

These are ENGINEERING ACCEPTANCE thresholds accepted in principle, not validated
scientific performance thresholds or an application service-level requirement. Intended-use
assumption: human-reviewed research evidence discovery with source inspection,
not autonomous scientific conclusions. Final tracked-policy/reference approval
is required before enabling the runtime policy.

The initial Parent's existing raw primary counts are combined 52/84 at 5 and
58/84 at 10; documentation 37/40 at both cutoffs. The fixed historical counts
are 59/84, 63/84 and 38/40, 38/40 respectively. Coarse floors are below the initial
raw engineering baseline; one-question budgets express a small explicit loss
allowance for 40/84-sized strata. Existing accepted/authorized Parent evidence
alone does not prove application adequacy. No current-target results were used
to select the floors. Corrected-reference scores are new metrics and must not be
reported as improvements in the frozen official benchmark.

See configs/ci_v2_quality_admission_v3.calibration.json and the final proposed
tracked review inputs. Technical inspection checked the seven critical questions against
retained Parent/Candidate chunks and the frozen question intent. C-28/C-29/C-30
are scoped static boundary probes; they do not prove runtime support or global API
absence. The three inherited deficits have identical per-unit coverage in both
Parents and the Candidate. Other critical predicates are resolved and complete.

Reference review also tightened C-12 to the SimulationType symbol so incidental
words elsewhere cannot satisfy the enum question. DOC-Q08/DOC-Q28 now require the
actual installation command instead of adjacent memory advice. These refinements
change no retained question score. All 88 questions / 102 requirements received technical relevance review.
Matching scoped evidence is available for 87 questions; D-01 is unindexed. Technical
review does not silently promote relevance probes to validated complete-answer
labels. The complete proposed reference file remains an explicit Owner review input. D-01 remains unresolved, noncritical and outside
the original primary denominator. Corpus selection is unchanged.

The retained-data reassessment accepts the Candidate for V3 knowledge-base update
quality: combined 58/84 at 5 and 63/84 at 10; documentation 39/40 at both. There are
zero critical corpus failures or coverage regressions; C-28/C-29/C-30 remain
application-quality debt. This is local retained-data evaluation, not scheduled Hosted acceptance or
authorization to publish/advance a Parent.

## Fingerprint boundary

Existing P2 construction identity, R2 retrieval identity, frozen benchmark SHA,
Q1 identity and historical verifiers are reused. Schema 3 adds separately checked
construction/retrieval/benchmark/evaluation/admission/lifecycle fingerprints.
NATIVE_RUNTIME_V3 pins actual trust/transport/construction adapter files without
recursively embedding the legacy contract constructors. It excludes Gradio,
grounded answering, prompts, Skills and retriever/evaluator implementation files;
those relevant executable files are independently pinned in their component.
Shared files that implement actual native trust decisions stay in the runtime pin.

The schedule preflight and build both use the same native authority adapter.
Repository/revision/producer/actor/environment/App/installation checks and frozen
runtime checks remain. The existing v2 Owner-observation profile is reused
explicitly, including the hidden-bypass limitation. No manual R4 module is edited.

This is bounded decoupling, not a generic plugin platform. Frozen R2 modules
cannot be edited in place while expecting old Parent proofs to verify. A future
retriever/evaluator uses a new version and explicit relevant evidence migration.
A construction change still requires Full validation and compatible Parent
migration. Application-only changes no longer change the native runtime digest;
reviewed HEAD/deployment bindings still require rebinding as appropriate.

## One protected integration and one migration packet

The proposed tracked files are:

- configs/ci_v2_quality_admission_v3.json
- configs/ci_v2_admission_references_v1.json
- configs/ci_v2_automatic_lifecycle_policy_v3.json
- configs/ci_v2_quality_admission_v3.calibration.json

They have final paths, exact file/component pins and a computed deterministic
new genesis binding. The runtime policy starts at 2026-11-24T18:32:18Z and expires
at 2026-12-09T00:00:00Z, bounded to two generations and 256 upstream commits.
The start is packet preparation time; it does not claim Owner execution approval.

### Remaining reference-scope decisions

The Owner must explicitly accept these as engineering relevance proxies rather
than independently validated complete-answer labels:

| Questions | Bounded limitation |
|---|---|
| C-02 | p0_ also occurs in the constructor and inverse equation; it does not uniquely identify the getPressure formula. |
| DOC-Q03 | A match to a multi-part heading need not include every KGC equation. |
| DOC-Q04 | The dual-criteria phrase locates the discussion; the nested loop may occupy an adjacent chunk. |
| DOC-Q38 | Atomic-operations explanation is co-located in the retained chunk, but is not a required literal. |
| B-08 / B-09 | Two schema fields are discriminative anchors, not an exhaustive inventory. |
| D-02 | Acoustic CFL anchors the complete retained struct; other defaults are not individually pinned. Critical corpus and regression gates still apply. |
| D-04 | ConstructArgs uniquely selects the retained constructor chunk; every signature token is not individually pinned. |

D-01 remains explicitly unresolved and noncritical, outside the original primary
denominator; its source presence is not represented as indexed evidence. C-28/29/30
remain static scoped boundary probes, not proof of runtime support or universal
API absence. No relevance label receives automatic Owner approval.

### Runtime fingerprint preparation

The R2 fingerprint includes interpreter, architecture and PYTHONHASHSEED, in
addition to implementation files and retrieval parameters. The first seeded draft
matched frozen R2 (1b21c01ef077549c60ba17109cc9381d1172b6e483c707c146cb7d80bcaa3f6d).
An intermediate draft was prepared without PYTHONHASHSEED and recorded
85aaaf94fc9bb1fdc9ac351e0f782ed7fd075a0fc4aede288e7d66d73b7bc5c2.
The only fingerprint input difference was runtime.hash_seed: "0" versus null.
Final preparation uses the actual CPython 3.12.3 / aarch64 / seed 0 runtime and
restores exact frozen fingerprint equality. No ranking or retrieval code changed.

### Integration order

1. Owner reviews this one diff, final reference bytes and the limitations above.
   No remote configuration or publication authority is inferred from local PASS.
2. BEFORE PR merge, retain the finalized tracked policy/reference paths, validity,
   component/file pins and computed genesis SHA. Genesis binds the complete policy
   scope excluding only its own SHA; it has no future merge-SHA dependency.
3. The current read-only old-lineage observation confirms generation zero at
   9b9811b7e691b7c8c9aebdcc1297800fd9af2332. The v2 target ref is absent.
   Reconcile again before execution; if any generation advances, stop rather than
   reset budgets or silently rebase lineage.
4. Only with explicit push/PR authorization, create ONE protected PR with this
   implementation and all finalized tracked configuration. Owner merge is required.
   Any reviewed code/config amendment requires recomputing its affected pins and
   genesis before merge. Preserve old ref/genesis and authoritative Registry bytes.
5. AFTER merge, bind the actual protected merge SHA in the external build
   deployment and execution packet only. No second tracked-policy PR is needed.
   The external deployment is distinct from the unchanged disabled Gradio driver.
6. Present exact genesis requests and four Variable updates together for separate
   concrete execution approval: CONTINUOUS_BUILD_DEPLOYMENT_JSON,
   CONTINUOUS_BUILD_DEPLOYMENT_SHA256, AUTOMATIC_LIFECYCLE_POLICY_PATH and
   AUTOMATIC_LIFECYCLE_POLICY_SHA256. Preserve the three approved final activation
   flag values; any temporary suspension/cutover requires approval. Activate
   construction last. Old pins fail closed during the cutover.
7. Use existing App/installation, Rulesets, Environments, Secrets and one-shot
   initialization/readback primitives. Preserve reserve/consume/complete, token
   revocation and fail-closed uncertainty handling; no credential test is needed.
8. Genuine scheduled Hosted acceptance is outstanding. Retained-data package
   compatibility and existing synthetic publication/two-generation integration
   results do not publish a Release or authorize/advance a Parent.

Functional development is frozen. No BM25, chunking, selection, original Parent,
authoritative Registry, historical score/evidence or production configuration is
changed by this integration preparation.
