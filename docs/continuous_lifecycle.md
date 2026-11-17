# Controlled Continuous Candidate lifecycle compatibility

Step 4C.3 implements an **offline controlled-fixture lifecycle**, not genuine
continuous execution, real Owner approval, or operational Registry integration.
Only `src/continuous_lifecycle.py`, its tests and this document are added.
Historical source files, workflows, locks, policies and approved assets remain
unchanged. There is no CLI, Registry writer or deployment change.

## Compatibility map

| Boundary | Reuse and limitation |
| --- | --- |
| Candidate | `continuous_execution.verify_package()` checks external pins, identity, strict projection, complete seals, original source/Parent evidence, parity and recorded R2. It still accepts controlled provenance only. |
| Approval decision | Existing `research_baseline._check_decisions()` and `approval_evidence.external_policy()` retain decision, unresolved-quality acknowledgement and exact policy scope checks. A separately pinned **test** decision binds the reconstructed complete approval subject. This is fixture evidence, not GitHub identity or Owner authority. |
| Evaluation | Unchanged `input_manifest()`, `create_evidence()` and `verify_bundle()` check original Candidate/Full rows, distinct historical/immediate-Parent anchors and source applicability. Creation executes independent frozen R2 replay for Candidate and Full (128 combinations each). |
| Baseline | A separate `continuous-controlled-baseline-v1` wrapper preserves the complete original package and adds evaluated evidence plus pinned test decision/policy. It does not claim old schema-2 approval compatibility. |
| Parent | `qualify_controlled_parent()` independently verifies the wrapper and pins, checks the original Candidate's R2 as the new Parent anchor, and executes actual frozen replay by default. This is not acceptance by `parent_r2_anchor.qualify_parent_anchor()` or automatic Parent selection. |
| Registry | Read-only `registration_preflight()` checks the wrapper and reports both unsupported new format and missing independent registration authority. It creates no old-format entry or future `BUILD_CANDIDATE` policy. |

Calling an evidence function or observing its internal `P4_1_VERIFIED` receipt
does not establish the complete genuine P4.1 approval workflow. The adapter
verifies applicable existing decision/evidence contracts and labels its result
`FROZEN_EVIDENCE_COMPATIBILITY_VERIFIED`, `CONTROLLED_FIXTURE_ONLY` and
`owner_authorization: NOT_ESTABLISHED`. Genuine P4.1 integration is unfinished.

## Interfaces and independent inputs

- `contract(project)`: hashes the adapter and unchanged execution contract.
  Its expected digest is supplied independently; computing it is not approval.
- `approval_subject(project, package, *, candidate_pins,
  expected_lifecycle_contract_sha256, expected_approval_policy_sha256)`:
  read-only deterministic reconstruction. It binds the original Candidate ID,
  identity, Parent, generation, Corpus, source-state/upstreams, every existing
  Candidate verification pin, adapter identity and approval-policy pin.
- `_approve_controlled_fixture(...)`: private test constructor. The policy uses
  the existing evaluated P4.1 policy shape; an externally pinned test decision
  envelope binds the subject and existing research decision fields. Only
  explicitly synthetic experiments and controlled Candidates are accepted.
  There is no public simulated-authority argument or exposed fixture CLI.
- `approve(...)`: reserved genuine entry, unconditionally
  `TRUSTED_CONTINUOUS_LIFECYCLE_NOT_ESTABLISHED`. A local decision JSON, matching
  hashes or environment variables cannot unlock it.
- `verify_baseline(...)`: requires external Candidate pins, adapter/policy/test
  decision digests and exact Baseline ID/root manifest digest. Reconstructs all
  bindings and checks the complete original and evidence packages.
- `parent_reference(report)`: produces a controlled local reference proposal;
  its digest must be retained independently by the test harness. It is not the
  existing remote trusted-reference format and has no Release locator.
- `qualify_controlled_parent(..., fresh_replay=True)`: controlled package plus
  external reference, Baseline and original-row pins. `fresh_replay=False`
  reports `CONTROLLED_PARENT_INSPECTED` / `NO_FRESH_REPLAY`.
- `registration_preflight(...)`: returns `BLOCKED`, with
  `NEW_FORMAT_REGISTRY_NOT_SUPPORTED` and
  `INDEPENDENT_REGISTRATION_AUTHORITY_NOT_ESTABLISHED`.

`verify_baseline(fresh_replay=False)` inspects recorded replay evidence only and
reports `SEALED_REPLAY_INSPECTED`. `fresh_replay=True` actually replays Candidate
and Full; neither mode independently authenticates a historical human decision.

## Controlled Baseline format

```text
original/                 # unchanged complete controlled execution package
approval-evidence/        # actual frozen evaluated evidence and fresh receipts
approval-policy.json      # exact externally pinned fixture policy bytes
controlled-decision.json  # pinned synthetic decision; never genuine authority
baseline.json             # separate format, identity and Baseline ID
checksums.json            # complete outer file seal
```

The closed Baseline identity binds the original Candidate identity and pins,
Parent/package/generation, source state, upstream commits, Corpus hash, approval
subject, policy/test-decision digests, evidence seal, complete payload hashes
and restrictions. Baseline ID is a separate canonical SHA-256 identity. The
existing logical `package_checksum()` helper is reused; it is not a tarball
transport hash. Root manifest and expected Baseline ID are external pins.

The original Candidate is copied without rewriting it. No old manifest is
fabricated. Controlled packages remain unacceptable to historical genuine
approval/Parent/reference validators. No genuine Baseline schema is finalized.

## Tests, actual computations and mock boundaries

Tests reuse `ContinuousExecutionTests.setUpClass()` as the existing temporary
fixture factory without inheriting or duplicating its test cases. That factory
performs actual miniature Git/source validation, incremental extraction,
independent full reconstruction, parity and frozen R2 evaluation/replays. Only
the inherited GitHub API observations and local fixture transport boundary are
mocked. The lifecycle positive path does not mock verification, decisions,
scoring, evidence creation or replay success.

The new path performs actual independent Candidate/Full replay during evidence
creation, fresh bundle replay on request, and a fresh replay of the approved
controlled Candidate as a new Parent anchor. Its historical and previous-Parent
rows remain separate. Tests for replay failure first run the actual ranker and
then deliberately corrupt its output. A no-replay inspection test replaces the
replay function only to prove it is not called.

Focused command (frozen Python/architecture and hash seed are required):

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH=tests \
 tools/treesitter-chunker/.venv/bin/python -B -m unittest test_continuous_lifecycle
```

Regression: append `test_continuous_lifecycle` to the documented 219-test
command in `docs/continuous_execution.md`. No genuine C1/C2 execution or replay,
real GitHub access, LLM call, commit or publication is part of these tests.

Recorded verification: **23 focused tests passed**; the combined regression
passed **242 tests in 121.570 seconds** (219 existing plus 23 new). The actual
generation-2 controlled lifecycle produced distinct Candidate/Baseline IDs,
independent Candidate/Full replay of 128 rows each, a fresh controlled Parent
replay, and a blocked registration preflight. These are disposable fixtures;
their IDs are not genuine research identities or approved Registry entries.

The observed lifecycle adapter contract digest is
`cf1e270eb655805934dace62e3934041db57202bdfb05d6d5d5a2dd2574ec7a3`.
It is **not an independently authorized deployment pin**. The original execution
contract remains
`2d9c41cc55d5f6c7dd8022280e38b7d1ec8ad5d991d7e452396dfa02e19220e3`;
the historical C1 orchestration contract still matches the archived original:
`b0b43411aef4d716a15a2f0a794071523fbb3c260dc4cb3fc9b2736eed9e1ac1`.
Frozen P2/P3/P4.1/R2 runtime checks also pass unchanged.

## Remaining operational gaps

The controlled offline lifecycle is distinct from an operational continuous
pipeline. Genuine execution authority and its runtime boundary remain absent;
genuine new-format P4.1 approval and trusted transport/Parent/Registry dispatch
remain unsupported. A future Parent still needs a separate authorized build
policy. Registration and build authority are not inferred from this wrapper.

Quality remains `QUALITY_REVIEW_REQUIRED`; this adapter grants no Q1
qualification or quality acceptance. P8 remains `BLOCKED`, automatic reuse and
registration remain false, scheduled V2 stays disabled, and production remains
`NOT_AUTHORIZED`. Existing real C1/C2 and their historical review states are
untouched.
