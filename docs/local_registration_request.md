# Local registration request preparation (L2-A)

This stage adds a **parsing-only** request Schema 3. It cannot generate an Owner
subject, verify published local evidence, register a Baseline, or write any
Registry. Existing Hosted request schemas 1/2 retain their closed input contracts
and verification path. A failed Hosted verification never falls back to L1.

Schema 3 has exactly these top-level fields:

- `schema_version`: integer `3`.
- `registry_key`, `proposed_entry`: existing key rules and the existing closed
  Schema V2 `REGISTRATION_ONLY` entry, respectively.
- `expected_reference_sha256`, `expected_registry_sha256`,
  `approval_policy_sha256`, `approval_policy_path`: existing pin and safe policy
  configuration rules. Loading the policy does not verify an Owner decision.
- `local_evidence`: exactly `evidence_origin: LOCAL_RESEARCH_EXECUTION`,
  `hosted_validation: HOSTED_NOT_RUN`, `candidate_id`, `baseline_id`,
  `corpus_sha256`, `descriptor_sha256`, `archive_sha256`.

The local identity must agree with the proposed Reference's Baseline and corpus,
and its Candidate ID when present. IDs use existing `sha256-…` syntax; all pins
are lowercase 64-digit SHA-256. The descriptor pin is the exact-byte pin required
by L1. The archive pin is separately required, but **syntax validation does not
establish that an archive exists or is verified**. Both pins must be independently
reviewed as part of the request; the request itself still requires an external
exact-byte SHA-256. No production archive pin, Release ID or Asset ID is created
by this implementation or its synthetic parser tests.

Schema 3 forbids `candidate_release`, `expected_candidate_release_sha256`, future
build policy fields, arbitrary approval flags, and Actions execution identities.
Schemas 1/2 forbid `local_evidence` and other new local-only fields. There is no
automatic origin inference or exception fallback.

The CLI uses the existing `--request` and `--request-sha256` inputs. After
successful Schema 3 parsing, both `verify-subject` and `register` return exit 1,
`BLOCKED / LOCAL_EVIDENCE_TRANSPORT_CONTRACT_NOT_FINALIZED`, before calling L1,
Hosted verification or any transaction. The Hosted composition likewise rejects
Schema 3 in `_inputs()` before Owner context and isolated Registry creation.

Reference v3 metadata is accepted only with its exact supported `notices`
binding. Existing `trusted_snapshot.validate_reference(remote=True)` checks the
subject, transport digest, same immutable Release and distinct private assets;
the CLI also applies its closed locator field validation. Historical v2 remains
unchanged and cannot contain notices. This is **shape and pinned metadata
validation**, not ZIP verification or delivery. Until L2-B implements download,
retention and notices-aware registration restoration, executing a Hosted request
with Reference v3 returns `REFERENCE_V3_REGISTRATION_INTEGRATION_PENDING` before
the backend. The existing public restore gate remains unchanged.

Remaining dependencies: reviewed bounded local archive layout and manifest,
publication provenance and genuine remote asset reference/pin contract, verified
downloads routed into L1, Owner Subject v2, and transaction notices integration.
No local filesystem paths or invented remote locators are accepted as substitutes
for that unfinished transport contract. Authoritative Registry application is
still a separate boundary; this stage does not enable it or future construction.

Focused offline tests (no real downloads, builds or R2):

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH=tests \
  tools/treesitter-chunker/.venv/bin/python -B -m unittest \
  test_local_registration_request \
  test_register_trusted_baseline_cli.RegistrationCLITests \
  test_registration_build_separation.RegistrationRequestTests \
  test_published_candidate_verification
```

Current result must remain **L2_A_PARTIAL_CONTRACT_BLOCKED** even when these tests
pass. Parsing readiness grants neither publication nor registration authority.
