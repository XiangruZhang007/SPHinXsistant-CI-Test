# Mandatory Parent notices delivery

This is a narrow transport/delivery extension. It does not approve, register or
authorize a Parent or Candidate. No real Release identity is configured here.

## Version and trust boundary

The Registry container stays Schema V2 and the approved package format stays
`schema2-research-baseline` / package schema 2. **Reference version 3** requires
the existing archive/R2 locators plus this closed `notices` binding:

| Field | Value |
|---|---|
| `schema_version` | integer 1 |
| `baseline_id` | exactly the reference `node_id` |
| `parent_transport_sha256` | exactly the reference `transport_sha256` |
| `sha256` | independently reviewed notices ZIP SHA-256 |
| `storage` | existing private Release locator fields |

All three locators must identify the same repository name/numeric ID, immutable
Release ID and tag, with three distinct Asset IDs/names and exact sizes. Notices
must be a ZIP no larger than 16 MiB. No owner/repository/user identity is hard
coded in the extension. For another repository, independently authorize its
real locators and new reference digest; authority is not transferred.

The entire canonical reference is independently pinned through existing Registry,
Policy and deployment bindings. A companion manifest or checksum within the ZIP
is not independent authorization. Runtime downloads still require the existing
same-repository GitHub token and immutable metadata/byte checks. No token input,
environment approval switch or approval bypass is introduced.

Historical reference version 2 keeps its two-asset behavior. It does **not** gain
a notices guarantee retroactively. A `notices` field in version 2 is rejected
instead of being silently advertised as an enforced attachment. Do not downgrade
a newly reviewed version-3 reference to evade notices: that changes its external
digest and requires a different independent trust/authorization decision.

## ZIP verification

`trusted_snapshot.verify_notices()` reads the independently pinned ZIP without
extracting or executing any member. It bounds compressed/expanded size and member
count, rejects duplicate/unsafe names, links, directories, encrypted entries and
unsupported compression. It verifies every declared internal SHA256SUMS member,
requires README.txt, DELIVERY.md, source-and-license-mapping.json and license text,
and binds the mapping to the exact Baseline ID and original transport hash.
Duplicate JSON fields and incomplete/altered checksums are rejected. This checks
the approved notice bytes, not the legal sufficiency of arbitrary new content.

## Execution and retention

- `schema2_workflow.execute_plan()` downloads/verifies the mandatory third asset
  before source cloning or calling `run_local()`.
- `run_local()` requires `notices_path` for version 3, verifies it before restore,
  and copies it into the new run's `notices/` attachment. Missing input fails
  closed. The old local CLI has no new bypass or simulated approval flag; direct
  CLI local execution without a supplied attachment remains blocked for v3.
- The public `trusted_snapshot.restore(..., *, controlled=False,
  notices_path=None)` independently validates the reference and actual notices
  ZIP before output validation, temporary staging, extraction or package
  verification. A saved verification receipt cannot substitute for the ZIP.
  Both execution callers pass the already downloaded attachment; v2 callers
  keep their original call shape. Other legacy CLI/registration callers that do
  not provide notices fail closed for v3; this change does not enable those
  routes or add registration functionality.
- `genuine_continuous_execution.execute()` also fetches/verifies before source
  cloning, restore, Parent qualification or construction.
- Both preserve `notices/companion.zip` and deterministic `verification.json` in
  the new delivered run. The receipt binds reference digest, Parent, transport,
  notices digest, immutable locator and internal manifest; it grants no authority.
- Portable reinspection revalidates that attachment against the pinned reference.
  Genuine runs declare both attachment files in their artifact hashes and allow
  the root attachment only for the new reference version. Existing closed
  `evidence/` membership and the sealed Parent are unchanged.
- Existing whole-run Candidate packaging and Workflow output upload naturally
  retain the attachment, including it in candidate.tar.gz. No Workflow edits or
  permissions changes are required. Actions Artifact retention is still 30 days;
  this feature neither publishes a Release nor establishes permanent storage.

Frozen source ancestry, fresh Parent replay during actual construction, Full
Parity, frozen R2, P4.1, Owner approval and production gates remain unchanged.
Failures never fall back to two-asset use for a version-3 Parent.

## Existing real subject (not installed or published)

Baseline: `sha256-9519233d556d62ae8660d340a8f9792d3058c44ec6d975864f3b1a1619e23767`.
Original transport:
`eccea7dbf5d51f4eff97c45e8fbe781a54ae7c4b6e582999e1a81c4c3a6e9b5c`.
Original Candidate R2 / future immediate-Parent anchor:
`eecd520a498e95299ce9a8287bbfc83afa1a2829331ec690eccd559ebfcea6c3`.
Proposed companion:
`d05bb4049c5baa7aab766478b4efd9c967319eeb599397ff5e45defbcf73cfdd`.

There are no real Release/Asset IDs for this subject yet. None are invented in
configuration. Test locators are explicitly synthetic and are not deployment
inputs. Publication, final version-3 reference pins, research registration,
future BUILD_CANDIDATE authority and Hosted acceptance require separate review.
QUALITY_REVIEW_REQUIRED, Q1_NOT_QUALIFIED_FOR_VERSION_PAIR, P8 BLOCKED and
production NOT_AUTHORIZED persist.

## Offline checks and historical contracts

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH=tests \
 tools/treesitter-chunker/.venv/bin/python -B -m unittest \
 test_notices_delivery test_private_release_transport test_schema2_research_parent \
 test_schema2_workflow.ExecutePlanQ1Tests
```

The new tests include synthetic ZIP/API failures, both call sites failing before
restore/build, direct local missing-notice rejection, manual-path argument and
retention wiring, historical reference compatibility, and an actual miniature
Genuine-format construction/packaging/reinspection using mocked upstream/Owner
observations. The latter checks full tar retention and rejection of a resealed
copy missing its notice receipt. None of these is real research R2 or Hosted
authorization. No research asset is rebuilt, modified or replayed.

For broader regression, run the full command documented in continuous_execution.md
with continuous_lifecycle, genuine_continuous_execution, owner_manual_baseline_approval,
scheduled_construction, completion_witness and this module appended (all module
names prefixed `test_`).

The three changed implementation files participate in versioned execution
contracts. Their new digests must be independently reviewed before deployment;
they are not approved by passing tests. P2/P3/P4.1/R2 frozen builder contracts and
historical C1 orchestration remain unchanged. Old sealed Continuous packages
retain original pins and must use their original reviewed implementation checkout;
do not silently repin or relabel them to pass with today's implementation bytes.

Observed local digests (pending independent review, **not deployment pins**):

| Contract | New digest |
|---|---|
| Controlled execution | `80902e24375041a9204ab0a160c59b0b7177b0669edfaf46f8fb783287252cbc` |
| Controlled lifecycle (transitive execution dependency) | `6194bac15e885cdc2ade3cb8470acb766f6305bc7a21c03b98c4bd3e1db14556` |
| Genuine execution | `d469cee70c45598f792dc6b42433053768e38b31bd622dcdf3a4b332ed2f9ca9` |

The existing historical-contract regression now reconstructs the original
Controlled execution/lifecycle contract using retained original source hashes
for the two changed dependencies. It still checks original historical digests
`2d9c41cc55d5f6c7dd8022280e38b7d1ec8ad5d991d7e452396dfa02e19220e3`
and `cf1e270eb655805934dace62e3934041db57202bdfb05d6d5d5a2dd2574ec7a3`,
and separately requires current implementation and isolated test checkout
contracts to match. It does not pretend today's implementation bytes have the
old digest or execute/rewrite a historical research package.

Retained verification before the direct-restore boundary correction:

- Focused notices/private transport/planning/argument suite: **61 PASS**.
- Full documented Continuous regression including the new tests: **358 PASS**
  (358.877 seconds).
- Archive publishing/historical archiving/snapshot restoration/Parent anchor
  compatibility suite: **129 PASS**. These suites overlap; counts are not added
  together as unique test coverage.
- In-memory Python compilation and tracked/new-file whitespace checks: PASS.
- Frozen runtime P2/P3/P4.1/R2 check: VERIFIED. Historical C1 orchestration remains
  `b0b43411aef4d716a15a2f0a794071523fbb3c260dc4cb3fc9b2736eed9e1ac1`.
- Original Baseline (1,213 files), P2 (1,069), C1 (1,173) and original build
  output (3,214) match their retained full path/size/SHA-256/executable inventories.
  Archive/R2/companion hashes, authoritative Registry/runtime lock and all three
  pre-existing uncommitted files are unchanged.
- No genuine research build/replay, live GitHub API operation, publication,
  registration, commit, push, workflow dispatch or production authorization.

Direct-restore boundary correction verification:

- 30 notices unit tests PASS, including direct v3 restore rejection before
  temporary staging/extraction for missing, corrupt or mismatched notices;
  valid pinned ZIP reaches the mocked normal restore path. Direct v2 restore
  remains compatible and rejects unsupported v2 notices bindings.
- Both automated routes reject missing v3 bindings before Parent use. Existing
  valid miniature delivery/portable verification tests remain passing.
- Focused notices/transport/planning suite: 70 PASS.
- Full documented Continuous regression: 367 PASS (360.024 seconds).
- Archive/historical/restore/Parent anchor compatibility: 129 PASS.
- Suites overlap and must not be summed. All construction/replay exercised by
  these offline suites uses disposable test fixtures, not genuine research
  packages. No genuine Baseline was restored by the new direct-restore tests.
- In-memory compilation, whitespace checks and frozen runtime check PASS;
  original research inventories, Registry, Runtime Lock and the three unrelated
  worktree changes remain unchanged. New implementation digests above are
  proposed only; historical pins and deployment settings were not changed.

Status: `DIRECT_V3_RESTORE_FIX_IMPLEMENTED_PENDING_REVIEW`. Real Hosted acceptance and
independent authorization of the new reference/implementation pins remain pending.
