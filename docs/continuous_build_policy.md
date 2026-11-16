# Continuous research build scope prototype (Step 4C)

**PARTIAL.** The separate read-only evaluator and source/policy revalidation are
implemented. They cannot execute a Candidate. Existing exact-target planning,
execution, Registry, Workflows and historical policies are unchanged. No real
Continuous Policy has been created, approved or deployed.

## Compatibility boundary

`upstream_provenance.contract()` hashes `src/upstream_provenance.py` and its
versioned implementation/test/documentation files. `verify()` compares an old
package's orchestration fingerprint with the current contract. `_parent()` uses
that verifier for an approved research Parent. Editing the frozen implementation
could therefore invalidate C1 even if P2/P3/P4.1/R2 remain unchanged.

The existing `build()` also demands an exact target pair, exact source-state,
matching orchestration identity and pinned publication receipts. Its output is
subsequently verified against the sealed original exact policy. Replacing that
policy with an automatically generated document would not establish independent
human authority. This prototype does not do so, patch globals, monkeypatch the
builder, add bypass arguments or ignore fingerprints.

Executable integration is disabled pending an explicit compatibility decision
covering the historical verifier, future execution evidence and its offline
verification. That decision must preserve C1 validation and must not migrate or
rewrite C1 implicitly. This implementation is not a completed continuous builder.

## Policy contract

`src/continuous_build_policy.py` validates a closed, versioned JSON object.
Missing/unknown/duplicate fields, invalid types, unsafe paths, NaN/infinity and
incorrect raw-file pins are rejected. No policy is read from a generated Plan.

| Fields | Required values or bounds |
| --- | --- |
| `schema_version`, `mode`, `operation` | `1`, `CONTINUOUS_SCOPE`, `BUILD_CANDIDATE` |
| `policy_id` | Short lowercase portable identifier |
| `enabled`, `research_only` | Both true for assessment; samples remain disabled |
| `valid_from`, `expires_at` | Explicit UTC seconds; current time inside interval |
| `upstreams` | Exactly SPHinXsys and SPHinXsim |
| Each upstream | Existing official GitHub URL, independently reviewed numeric repository ID, one explicit permitted branch |
| `eligible_parents` | 1–16 explicit key/node ID/package checksum/reference-digest bindings; no duplicates |
| `build_fingerprint` | Current frozen P2 contract digest |
| `orchestration_fingerprint` | Exact unchanged schema-2 provenance contract digest |
| `max_advance_commits` | Integer 1–4096, bounds the existing ancestry proof |
| `requirements` | Exact `REQUIREMENTS` mapping from this module |
| Existing `c.RESTRICTIONS` fields | Unchanged quality/reuse/schedule/research/production limits |
| `automatic_registration` | false |

The mandatory checks are P4.1 plus fresh Parent R2 qualification, clean Git
tree/blob/source-state verification, same/fast-forward proofs, independent full
parity, frozen R2 plus independent replay, preservation of Q1 qualification and
P8 blocking. The evaluator records these obligations; it does not perform
extraction, package qualification, parity or retrieval.

The only enabled samples are synthetic temporary test fixtures with mocked
GitHub observations. They are not operational policies or real approvals. No
sample is installed in `configs/` or in the authoritative Registry.

## Independent trust inputs and Parent selection

The reviewed caller must supply the policy's project-relative location and
expected **raw-byte SHA-256**, plus an independently trusted current Registry
raw SHA-256. The policy also has a separate canonical digest for deterministic
evidence. Reformatting changes the raw pin. Pins supplied by Candidate output,
saved observations or a generated assessment cannot establish authority.

Supplying matching pins is a verification input, not proof of a human decision
or trusted execution context. A future reviewed deployment must establish that
trust separately; no runtime context or approval flag is added here.

Every Registry entry/reference and its existing exact build policy is validated
using the current validators. Each exact policy is checked against its own
historically authorized targets. It is never relabelled as future authorization.
Continuous selection additionally requires an explicit matching Parent binding
in the independently pinned continuous policy. Only existing build-bound
research Baselines are eligible in this first prototype. P2 bootstrap stays on
its existing exact path; REGISTRATION_ONLY records are always excluded.

No latest-generation ranking, arbitrary fallback or automatic conversion occurs.
Zero or multiple eligible Parents block. Corrupt unselected entries/policies
also block. Metadata selection does not establish P4.1 qualification, loaded
package integrity or generation: those remain mandatory execution obligations.

## Source/ref evidence

`assess_scope()` reuses `verify_sources()`, `relationship()`,
`verify_relationship()` and `state()` against existing canonical source roots.
This checks actual clean standalone Git checkouts, official remote identity,
exact commits, selected file bytes/modes, Git tree/blob proofs and the actual
source selection state. No corpus is generated. Same or bounded fast-forward
relations are accepted; rollback, divergence and unknown relationships block.

Commit ancestry alone is insufficient for branch authorization. The reused
read-only `owner_manual_baseline_approval.GitHubCLI` queries only official
GitHub repository, exact branch-ref and commit endpoints. It uses existing gh
authentication; no new credentials or downloader are introduced. Checks bind:

- Numeric upstream repository ID and exact official owner/name.
- Exact `refs/heads/<permitted branch>`, commit object type and detected target SHA.
- Parent and target publication receipts to the actual Git commit/tree/parent objects.

The target must equal the observed branch tip, not merely an ancestor of it.
If the branch has moved since detection, or access/identity cannot be verified,
assessment blocks. No saved caller-supplied API JSON is accepted as a fresh
observation. Tests replace the API client explicitly with mocks; synthetic Git
objects are not evidence of real upstream publication.

Actual source inventories/proofs are checked again after API observations. Raw
policy and Registry pins are checked again before returning. The returned
evidence includes source selections, Git proofs, ancestry and sanitized source
ref/publication observations. Its digest is bound to the deterministic subject.
Saved observations support future audit under an independently trusted subject
pin; they are not signed or independently self-authenticating authorization.

## Interfaces and exact execution evidence

```python
assess_scope(project, registry_path, policy_path, *,
             expected_policy_sha256, expected_registry_sha256,
             revisions, base_source, target_source)

revalidate_scope(planned, project, registry_path, policy_path, *,
                 expected_plan_sha256, expected_policy_sha256,
                 expected_registry_sha256, revisions,
                 base_source, target_source)
```

The subject binds the exact pair, selected Parent entry/reference/package/corpus,
Parent and actual target source-state, independent policy location/raw digest,
canonical policy digest, Registry digest, actual build/orchestration fingerprints
and source-evidence digest. There is no guessed target state derived from SHAs.
Parent generation is explicitly pending verification of the real Parent package.

The assessment is Schema 1, status
`CONTINUOUS_SCOPE_ASSESSED_EXECUTION_BLOCKED`, not a schema-2 executable Plan.
It is derived scope evidence, never a generated approved exact-target policy.
`execution_authorization` is always `BLOCKED`. `revalidate_scope()` rereads the
independent inputs and actual source bytes, makes fresh API observations and
compares the complete assessment. A changed policy, Registry, Plan, source or ref
blocks. Success still returns `SCOPE_REVALIDATED_EXECUTION_BLOCKED`.

No ordinary CLI, Workflow or routing integration is introduced. Actual historical
builder execution, Parent restoration, fresh Parent R2, parity, R2 evaluation and
independent replay remain available only through their unchanged exact-target
path. They are not claimed as tested by scope assessment.

## Scheduling, deduplication and deployment

`scheduled_execution:false`, `build_ci_v2=false` default and Step 4B's fail-closed
routing remain unchanged. No operational Owner authority is granted. The
assessment's deterministic execution identity identifies equivalent requests;
it is not a persistent execution ledger. `deduplication` remains
`NOT_ESTABLISHED`; neither concurrency nor missing artifacts authorize execution.
No GitHub history polling or new storage framework is added. No exactly-once or
unattended construction is claimed. Future activation requires separate reviewed
policy/configuration, executable compatibility and scheduling/deduplication work.

## Offline verification

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH=tests \
  tools/treesitter-chunker/.venv/bin/python -B -m unittest \
  test_continuous_build_policy \
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

Tests use only small temporary synthetic Git repositories, source inventories and
mocked GitHub GETs. They do not clone upstream repositories, create Candidates,
build corpora, replay R2 or approve anything. Checks include C1's existing
orchestration digest compatibility, exact-policy regressions, source/ref identity,
scope bounds, raw pins, stale evidence, ambiguous Parents and blocked execution.
These tests are not genuine Hosted validation or real Owner authorization.

Local result: 188 relevant offline tests passed, including 33 new scope tests.
In-memory Python compilation and whitespace checks passed. The current schema-2
orchestration contract exactly matches the archived approved C1 contract
(`b0b43411aef4d716a15a2f0a794071523fbb3c260dc4cb3fc9b2736eed9e1ac1`).
Frozen P2/P3/P4.1/R2 runtime checks also passed. This is static compatibility
verification, not a fresh C1 qualification replay or a new Hosted execution.
