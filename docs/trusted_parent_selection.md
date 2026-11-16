# Explicit automatic Trusted Parent selection

`plan --auto-parent` selects the unique registered, build-compatible Parent
whose independently pinned existing `BUILD_CANDIDATE` policy authorizes the
exact requested SPHinXsys/SPHinXsim commits. It does not select the newest
Baseline, generate authorization, register Candidates, or enable automatic reuse.
The existing explicit `plan --key KEY` mode and manual Plan format are unchanged.
Neither mode is an implicit default; the options are mutually exclusive.

```bash
python3 -B scripts/ci_v2_schema2_research.py plan --auto-parent \
  --sys-revision "$SYS_REVISION" \
  --sim-revision "$SIM_REVISION" \
  --output /tmp/new-research-plan
```

Set both revision variables to exact 40-character lowercase commit hashes first.

The authoritative Registry path remains the existing Schema V2 configuration.
Its reviewed checkout and independently recorded reference/policy pins remain
the trust source; the Plan and its hashes do not create a new approval authority.
Private reference validation retains its existing same-repository runtime
identity requirements. No credentials are accepted by the selection CLI.

Planning reads metadata only, using the standard library. It validates supported
entry shapes, reference pins and remote locators, duplicate Baseline/content
bindings, frozen P2 build compatibility, scoped Parent/base/build bindings,
policy byte integrity and exact policy targets. It repeats the existing manual
`plan()` checks rather than replacing them with selector approval. Corrupted,
missing or contradictory evidence is fatal, including on a nonmatching entry;
validation errors are never caught and skipped.

A valid policy for other commits is a nonmatch. A valid incompatible build is
ineligible. A valid `REGISTRATION_ONLY` entry has no build authorization and is
reported as such; automatic selection does not upgrade that entry. Zero matches
raise `NO_ELIGIBLE_PARENT`; multiple matches raise `AMBIGUOUS_PARENT`. There is no
fallback to P2 or another Parent after a selected package fails verification.
Assessments are sorted only to serialize the result deterministically, never to
choose by key order. Generation and timestamps do not establish priority.

The auto Plan retains the existing key, target commits and canonical entry
digest and adds a versioned `selection` object. This records raw Registry byte
SHA-256, reference digest, raw Policy file SHA-256/path, build/orchestration
identities, policy-declared expected target source state, reason and assessments.
The expected source state is not a claim that actual target source bytes were
verified during planning. Existing execution must verify those bytes, publication
proofs, ancestry and the full build authorization.

`execute-plan` recomputes the complete automatic Plan and requires exact equality
before downloads, immediately before `run_local()` and after it returns, before
packaging. Registry formatting changes count as byte changes. It never silently
changes the Parent. These checks detect changes at the stated boundaries; they
are not continuous filesystem locking or protection against equally privileged
code editing the trusted implementation. Manual execution is unchanged.

The existing execution path still downloads and restores the exact Parent and
result assets, validates package/Corpus/P4.1 evidence, performs mandatory fresh
Parent R2 replay, incremental construction, independent full reconstruction,
parity and retrieval/replay checks. Successful selection alone claims none of
those results. Registration-only build support needs a separately reviewed
transition-policy integration and remains blocked.

Step 3B changes no Workflow, Registry entry, Policy, frozen fingerprint, benchmark
or Runtime Lock. The existing Workflow still requires `baseline_key`; Step 3C
must separately wire an explicit opt-in to this mode and perform authorized
Hosted validation. Historical C2 archival does not make C2 eligible. Owner
registration to an isolated Registry copy is not authoritative registration.
`QUALITY_REVIEW_REQUIRED`, applicable Q1 restrictions, P8 blocking and production
`NOT_AUTHORIZED` remain unchanged. Local offline tests are not Hosted acceptance.

## Local Step 3B verification

The following focused offline command passed 100 tests (33 new selection tests).
Execution tests mock transport, Git, runtime provisioning and `run_local()`; no
Corpus construction or R2 execution occurs. The existing parser virtualenv is
used for imports required by older regression modules; no dependencies were
installed. The selector also passes a separate `python -B -S` stdlib-only test.

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH=tests \
  tools/treesitter-chunker/.venv/bin/python -B -m unittest \
  test_trusted_parent_selection test_schema2_research_parent \
  test_schema2_workflow.WorkflowContractTests \
  test_schema2_workflow.ExecutePlanQ1Tests \
  test_registration_build_separation.EntryContractsTests \
  test_registration_build_separation.BuildBoundaryTests \
  test_trusted_baseline_registration test_private_release_transport \
  test_hosted_registration_workflow test_continuous_corpus.CliTests
```

All four changed/new Python files compile in memory. Frozen runtime verification
confirms unchanged P2, P3, P4.1 and R2 fingerprints. Whitespace checks cover both
tracked changes and new files. This verification does not qualify a downloaded
Parent, grant Owner approval, or establish Hosted auto-selection acceptance.
