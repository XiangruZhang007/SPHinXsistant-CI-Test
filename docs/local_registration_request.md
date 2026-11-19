# Local registration request preparation (L2-A)

L2-A originally added a **parsing-only** request Schema 3. L2-B2a now adds the
separate evidence-only route documented in [local_candidate_verification.md](local_candidate_verification.md).
Ordinary registration remains blocked. L2-B2b now supports a separately verified
unsigned Owner Subject v2 and trusted Hosted isolated route; see
[local_registration_subject.md](local_registration_subject.md). No actual
registration or authoritative Registry writing is authorized here. Published
local evidence is verified only by the separate evidence-only command.
Existing Hosted request schemas 1/2 retain their closed input contracts
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
  `corpus_sha256`, `descriptor_sha256`, `archive_sha256`, plus the L2-T
  `transport` and independently canonical-pinned `transport_sha256`.

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
successful Schema 3 parsing, legacy `verify-subject` remains blocked. Ordinary
`register` now reaches the still-denying trusted execution context; it cannot
authorize itself. Only separately pinned Deployment v2 can compose the new
Subject v2/isolated transaction. Deployment v1 continues rejecting Schema 3.

Reference v3 metadata is accepted only with its exact supported `notices`
binding. Existing `trusted_snapshot.validate_reference(remote=True)` checks the
subject, transport digest, same immutable Release and distinct private assets;
the CLI also applies its closed locator field validation. Historical v2 remains
unchanged and cannot contain notices. This is **shape and pinned metadata
validation**, not ZIP verification or delivery. Until L2-B implements download,
retention and notices-aware registration restoration, executing a Hosted request
with Reference v3 returns `REFERENCE_V3_REGISTRATION_INTEGRATION_PENDING` before
the backend. The existing public restore gate remains unchanged.

L2-B2a's separate `verify-local-evidence` can validate pinned published local
transport and restore Reference v3 with mandatory notices, without constructing
a registration subject. Old seven-field drafts are rejected. Remaining real
dependencies include actual publication/remote acceptance, expanded hosting
confirmation and genuine Hosted Owner/transaction acceptance.
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
