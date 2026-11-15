# Registration and build authorization separation

Step 2C.3-C1-T1 adds an explicit registration-only entry contract. Registering
a P4.1-qualified Research Baseline does not authorize a subsequent Candidate
build. This is a local implementation; offline success is not Hosted Owner
approval. The authoritative Registry and existing research assets are unchanged.

## Closed Registry entry contracts

The outer Registry remains Schema V2. Existing entries retain exactly these
four fields, with their existing build-policy validation:

```text
reference
expected_reference_sha256
build_policy_path
build_policy_sha256
```

The new form has exactly these three fields:

```text
entry_kind: REGISTRATION_ONLY
reference
expected_reference_sha256
```

`reference` is the unchanged, independently pinned schema-2 research-Baseline
reference, with `package_format: schema2-research-baseline`. P2 anchors cannot
use this form. Missing or unknown discriminators, extra fields and mixtures
are rejected. No legacy entry is converted. This is an explicit extension of
the accepted entry contract, not a claim that older software supports it.

`trusted_baseline_registration.entry_kind()` is the shared shape discriminator.
Historical entries are validated by their own supported form, rather than
requiring the same field set as the new proposal. Their references and packages
are still verified to recover actual historical Candidate identities. Duplicate
keys, Baseline IDs, Candidate IDs and conflicting bindings remain rejected.

## Request and interface compatibility

Request schema version 1 remains unchanged and accepts only the legacy entry.
It still requires `expected_build_policy_sha256` and validates the independently
pinned future build policy. Request schema version 2 accepts only the new form,
with exactly these fields:

```text
schema_version: 2
registry_key
proposed_entry
candidate_release
expected_candidate_release_sha256
expected_reference_sha256
expected_registry_sha256
approval_policy_path
approval_policy_sha256
```

The build-policy pin is absent, not null, empty, zero-filled or inferred from a
historical policy. Cross-version entry/request combinations are rejected. Raw
request bytes still need an independent SHA-256; the Request never establishes
its own approval authority. Existing locator, reference, path, unknown-field,
duplicate-field and credential-sanitization checks remain in force.

The existing registration, published-evidence and Owner APIs allow omission of
the keyword-only `expected_build_policy_sha256` for registration-only entries.
Internally its default is `None`; an actual supplied value is rejected for the
new form. Legacy entries still require a valid independent pin and an exact
policy file. The preflight CLI similarly requires the option for legacy entries
and rejects supplying it for new entries.

The main `register_trusted_baseline.py` CLI and reviewed Hosted adapter propagate
version 2 requests to the shared transaction. The Hosted six-input dispatch,
deployment shape and independent policy pins do not change. Registration-only
Owner verification requires the complete reconstructed subject; the legacy
five-input Owner script cannot authorize it and reports
`REGISTRATION_SUBJECT_REQUIRED`. The optional protected-PR verifier remains
available for legacy entries; it explicitly refuses the new form with
`REGISTRATION_ONLY_UNSUPPORTED_BY_PR_APPROVAL`. No PR protection checks change.

## Qualification and authorization retained

For the new form, only the future build-policy requirement is removed from
registration. Verification still restores the independently pinned Baseline,
checks genuine provenance and P4.1 qualification, verifies the immutable
three-asset Candidate Release and its manifest, and binds its exact Candidate
metadata, Corpus, generation, source state, upstream commits and original R2
results to the approved Baseline. Frozen historical build policies inside the
approved package are still verified; they are not removed or reinterpreted.

Parent R2 qualification still uses `fresh_replay=False` and reports
`NO_FRESH_REPLAY`. Owner identity, exact subject and old Registry bytes are
reverified before the isolated commit. All entry fields, including `entry_kind`,
are hashed into the full subject and dispatch entry digest. Altering the entry
requires new reviewed request/subject/deployment pins and a new approval; an old
approval is not converted into authorization for the new form.

Atomic replacement, locking, PREPARED/COMPLETED records, post-commit error
reporting and recovery are unchanged. New records bind the exact new entry.
Existing records remain readable with their original hashes. Recovery only
finishes evidence for an already committed isolated update; it never changes
Registry bytes or grants a new authorization. Ordinary local registration still
fails at the existing trusted-execution boundary, even with spoofed GitHub env.

`QUALITY_REVIEW_REQUIRED`, original Q1 status, P8 restrictions and production
`NOT_AUTHORIZED` are preserved. P4.1 qualification, technical verification,
Owner registration approval and quality acceptance remain separate decisions.

## Building remains blocked

In this stage, schema-2 `plan()` unconditionally rejects registration-only
entries with `AUTHORIZATION_FAILED`; `execute_plan()` invokes the same planning
check before downloads or construction, so a forged saved plan does not help.
Adding build fields to a registration-only entry is an invalid contract, not an
upgrade to build authorization. The existing local `build-next` path also rejects
the explicit new entry kind. Its older local reference-only format is unchanged.

No policy override argument, automatic policy selection, inherited C1-to-C2
authorization or future target is introduced. Existing direct `run_local()`
continues to require its independently pinned exact build policy and all frozen
checks. It receives no registration-derived authorization. Supporting future
builds from the new Registry form requires a separately reviewed integration
and exact transition authorization; it is not implemented here.

## Offline verification and remaining work

`tests/test_registration_build_separation.py` covers strict entry/request forms,
no-policy evidence verification, original qualification/R2 requirements,
planning/execution refusals, local build refusal, simulated Owner/Hosted
composition, mixed entries, duplicate identities, stale state, subject changes,
concurrency, interruptions and audit-only recovery. Fixtures mock qualification
internals and GitHub authority; successful transactions remain simulations.
Existing A/B/C, archive, private transport and legacy build tests remain relevant.

Before genuine Hosted acceptance: prepare and separately authorize historical
asset publication, obtain authentic immutable asset IDs, review the version 2
request and Owner policy, commit/deploy the reviewed implementation and inputs,
independently configure deployment pins, and explicitly authorize the dispatch.
This change creates no real request, asset, approval, Registry entry or workflow
run and implements no historical-publication mechanism or automatic selection.

## Changed files and local results

| Area | Files |
| --- | --- |
| Contracts and verification | `src/trusted_baseline_registration.py`, `src/published_candidate_verification.py`, `src/owner_manual_baseline_approval.py`, `src/github_baseline_approval.py` |
| Transaction and execution | `src/baseline_registration_transaction.py`, `src/hosted_registration.py`, `src/schema2_workflow.py`, `src/continuous_corpus.py` |
| CLI | `scripts/register_trusted_baseline.py`, `scripts/prepare_baseline_registration.py`, `scripts/verify_baseline_owner_approval.py` |
| Tests | `tests/test_registration_build_separation.py`, `tests/test_schema2_workflow.py` |
| Documentation | `docs/registration_build_authorization_separation.md`, `docs/trusted_baseline_registration.md`, `docs/register_trusted_baseline_cli.md` |

Local validation ran 303 relevant offline tests: 302 passed and one skipped
because optional `SPHINX_P8_RUN_EVIDENCE` was not configured. The skipped test
would inspect a historical archive; no historical P8 evaluation was rerun.
The selected suites covered registration separation, A/B/C verification, Owner
and protected-PR adapters, Hosted composition/workflow contracts, schema-2
planning/execution, Candidate archiving, public/private transport, bootstrap
configuration, miniature continuous chains and miniature Parent R2 anchors.
There were no genuine C1/C2 builds or real R2 evaluations.

All 13 changed/new Python files compiled in memory. The actual frozen runtime
check passed on CPython 3.12.3/aarch64 with hash seed 0 and unchanged P2/P3/P4.1
and R2 fingerprints. The lock, authoritative Registry, historical C1-to-C2
policy, workflow definitions and application files were not changed.
