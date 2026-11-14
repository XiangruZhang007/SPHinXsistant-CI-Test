# Post-publication Candidate verification (Step 2C.2-A)

`src.published_candidate_verification.verify()` verifies evidence for a future
registration decision. It never writes a Registry, grants Owner authorization,
publishes assets, or registers a Parent. There is no CLI or transaction in this
stage. A successful result is `EVIDENCE_VERIFIED`, not registration eligibility.

## Inputs and trust

The library takes `project`, `registry_path`, `registry_key`, `proposed_entry`,
and these keyword arguments:

- `candidate_release` and `expected_candidate_release_sha256`;
- `expected_reference_sha256` for the independently approved Baseline reference;
- `expected_build_policy_sha256`;
- `expected_registry_sha256` (hash of the exact existing Registry bytes);
- `approval_policy_sha256` (reserved identity for future Owner verification);
- `token`, passed only to the existing private transport.

All expected hashes must come from the trusted caller's reviewed configuration,
not from downloaded manifests. A digest cannot establish its own trust origin.
The approval-policy hash is bound, but its authority is **not verified** here.
The runtime repository environment must satisfy the existing same-repository
private transport contract. It is not itself proof of Owner authorization.

The Candidate transport reference is a versioned descriptor of existing asset
locators, not a new Baseline or authorization format:

```text
{
  "schema_version": 1,
  "assets": {
    "candidate.tar.gz":        {"storage": <existing private locator>, "sha256": <pin>},
    "research-evidence.tar.gz": {"storage": <existing private locator>, "sha256": <pin>},
    "release-manifest.json":   {"storage": <existing private locator>, "sha256": <pin>}
  }
}
```

Each locator includes the existing `kind`, `repository`, `repository_id`,
`release_id`, `tag`, `asset_id`, `asset_name`, `asset_size`, and
`immutable_required` fields. All three must name distinct assets of the same
private immutable Release. The API Release must contain exactly those assets.
The whole descriptor is pinned using `corpus_snapshot.digest()`; individual
asset pins are SHA-256 of raw bytes. Manifest JSON rejects duplicate fields and
nonfinite numbers. Unexpected manifest fields also fail the exact comparison.

## Verification path

1. Check independently supplied pins and the exact current Registry hash.
2. Use `trusted_snapshot.download()` for authenticated metadata and byte checks.
   Recheck the complete Release asset inventory.
3. Use `extract_regular()` in an owned temporary directory. Reconstruct the
   original Actions evidence layout, call `validate_artifact()`, and compare the
   resulting manifest exactly with the downloaded, independently pinned one.
4. Download and restore the separately pinned P4.1 Baseline and its Parent R2
   asset. Restoration runs the existing full package verifier.
5. Invoke `trusted_baseline_registration.prepare()`. Its missing-registration-
   authority blocker remains expected; every other failure rejects the request.
6. Invoke `qualify_parent_anchor(..., fresh_replay=False)`. This validates and
   rescores sealed rows with the existing rules; it does not execute retrieval.
7. Bind Candidate IDs, complete original upstream metadata, Corpus, source state,
   generation, commits, fingerprint, benchmark and exact Candidate R2 bytes to
   the approved Baseline and its immediate-Parent R2 anchor.
8. Recheck Registry bytes and build-policy hash before returning the subject.

Temporary downloads and extraction directories are deleted on success and on
exceptions. Inputs, original research evidence and Registry remain read-only.
Failures raise `VerificationError` with bounded codes; remote bodies and
token-bearing URLs are not propagated. No fallback substitutes other assets.

## Compatibility corrections

`candidate_release_archive.validate_artifact()` accepts an optional expected
`repository`; the existing publisher uses its unchanged default and behavior.
This avoids hardcoding the test repository into reusable verification logic.

Step 2A previously called the frozen legacy P4 verifier for every package and
required `research-decision.json`. Actual schema-2 P4.1 packages instead contain
`upstream-baseline.json`. Its preflight now routes that format to the existing
`upstream_provenance.verify()`, checks genuine research-Baseline provenance, and
uses that verified result's restrictions. Legacy behavior remains unchanged.
Neither frozen verification algorithm nor qualification rules were modified.
The schema-2 authorization file may omit `production_promotion`, as allowed by
its existing contract. In that case the verified Candidate, approval policy and
independent reference supply the production restriction. An explicit conflicting
authorization value is rejected. Legacy preflight still requires its old field.

## Output and future registration

The deterministic subject contains the complete intended Schema V2 entry and
key, expected old Registry hash, approval-policy hash, all Candidate Release
asset pins, Candidate/Baseline identities, preserved quality/Q1 statuses, and
Parent R2 bindings. `registration_subject_sha256` uses existing canonical JSON.
No temporary paths, random values, token or current time enter the subject.

The result always says:

```text
execution: NO_FRESH_REPLAY
authorization: NOT_VERIFIED
registration: NOT_PERFORMED
registry_modified: false
production_promotion: NOT_AUTHORIZED
```

An absent Q1 field in the existing Baseline quality schema stays
`NOT_RECORDED_IN_EXISTING_BASELINE_QUALITY_SCHEMA`. The Candidate's actual Q1
status is separately retained; no qualification is inferred from absence.

Step 2C.2-B now adds an optional complete-subject binding to the Owner verifier;
the original five-input read-only behavior remains available. The isolated
transaction reconstructs the subject and requires its digest in the dispatch
inputs, with fresh policy, actor and Registry checks. Its real execution-trust
integration remains unconfigured, so ordinary registration calls stay BLOCKED.
Saved subject/result JSON cannot authorize anything. See
`baseline_registration_transaction.md` for the isolated transaction, duplicate
checks, path protection and recovery boundaries. Step 2C.2-A itself still performs
only evidence verification.

## Offline validation

Use the existing chunker Python environment; no dependency installation:

```bash
PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=tests \
tools/treesitter-chunker/.venv/bin/python -m unittest \
  test_published_candidate_verification test_candidate_release_archive \
  test_trusted_baseline_registration test_private_release_transport \
  test_owner_manual_baseline_approval test_github_baseline_approval \
  test_parent_r2_anchor
```

New integration tests exercise real download, extraction, reference validation,
preflight dispatch and binding code with mocked GitHub responses. Expensive
Baseline/P4.1 internals and anchor qualification are mocked in those fixtures;
this does not qualify a genuine Candidate. Existing Parent anchor tests exercise
the real verifier with miniature synthetic repositories/corpora, including
sealed inspection with replay forbidden. No genuine C1/C2 build, R2 evaluation,
Hosted execution, real Release download or Owner approval is performed.
