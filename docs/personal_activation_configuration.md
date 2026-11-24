# Personal CI V2 initialization review

Configuration preparation only. No Registry/genesis write, R4 dispatch or
automatic activation is authorized by this PR or by the earlier implementation
approval. Required runtime values remain separately subject to concrete Owner
approval. Existing manual Environment approval and protected integration remain.

## Actual settings and evidence

- PR #15 merged as `e2eae5f75fe47f0a04544eb766736dc1d6d27646`.
- Ruleset A: 27770139; default protection: 27793434; both unchanged with explicit
  empty bypass lists in the Owner readback.
- Ruleset B: 27974931, `ci-v2-audit-writer-seal-v1`, active only on
  `refs/heads/ci-v2-authority-audit/*`, creation/update restrictions; only
  Integration 5855475 may bypass B. A/default remain independent restrictions.
- B was created once with the previously approved payload. REST omits update
  parameters; Owner GraphQL explicitly verified the required false value.
  Runtime now requires that actual value via a fixed read-only query if omitted.
- App 5855475 / installation 184185108 credential baseline remains genuine run
  45362927586, successful in both Environments with all temporary tokens revoked.
  Credential verification was not repeated.
- Complete Owner observation: `2026-11-24T09:59:27Z`, raw SHA-256
  `928a17f1a8f127ea6669bf3a4728f2451625fa24cd76aca93ef474e4898c2334`.
  Expiry `2026-12-09T00:00:00Z` is proposed for this runtime-policy input and
  requires review. REST/GraphQL source evidence is preserved in the local
  consolidated activation checkpoint; no credential-only snapshot is reused.

## Concrete proposed tracked policies

| Policy | Proposed scope |
| --- | --- |
| `ci_v2_initial_r4_owner_policy.json` | Existing Owner only; exact R4 workflow, repository, protected branch and Registry |
| `ci_v2_initial_r4_governance_policy.json` | Explicit observation version 2; valid from actual observation today through `2026-11-25T00:00:00Z` |
| `ci_v2_initial_parent_build_policy.json` | Restricted official Parent build scope; same exact already verified source pair as the Parent |
| `ci_v2_continuous_owner_policy.json` | Existing continuous workflow Owner domain; no supplied approval flag |
| `ci_v2_continuous_source_policy.json` | Official Parent only; same or fast-forward; maximum 256 commits; ends `2026-12-09T00:00:00Z` |
| `ci_v2_scheduled_construction_policy.json` | Existing scheduled construction path bound to the prospective authorized Registry bytes; activation still disabled |
| `ci_v2_automatic_admission_policy.json` | Existing unmodified strict requirements, frozen benchmark, both modes, 176 rows; no supplied PASS |

Manual policy start is the actual Owner observation time today. It can be used
as soon as the necessary review, protected merge, exact execution authorization
and backend initialization are complete today; no wait until tomorrow is
introduced. No expired interval will be silently extended. Automatic test expiry
remains `2026-12-09T00:00:00Z`, with two generations and 256 commits proposed.

Initial Parent: `official-research-parent-9519233d`, node
`sha256-9519233d556d62ae8660d340a8f9792d3058c44ec6d975864f3b1a1619e23767`.
Initial exact source scope reuses SPHinXsys
`64d6069f7469c4171f7807e7e3118a6d7dee06a5`, SPHinXsim
`c4a98ca45496c5d617379f7c08d5053d49d6e20b`, source state
`sha256-9013cc571e08106083c47b8c68b93c22c85f0aef427c12fd1443b839c8fbea6e`.
This is a SAME-source initial authorization proposal, not a new Candidate or
scientific acceptance. Subsequent scheduled targets need actual independent
source and scientific evidence. Retained P4.1/Parent R2 qualification is reused;
no experiment is repeated or historical failure relabeled.

Prospective Registry raw digests, calculated locally only:

- Old: `27b787518c39787243caef817e24d0c7118b23bd41dcf0b6241b8b2f4c61a7ad`.
- Proposed result: `e7290b4465cc1512aea37c2accd5cdcf357e967947ca567137c165195d3cb187`.

Only the official Parent entry would change to the existing build-policy-bound
form. All references, historical rows, other entries and scientific restrictions
remain intact. The prospective result is stored outside the checkout for review,
not committed, pushed, integrated or treated as authority. Isolated APPLY alone
will not establish authoritative integration.

## Execution bindings that cannot yet be finalized

The execution Request must pin the actual protected merge of this configuration.
The proposal commit is a real revision, but must not be represented as that
future merge. Final Request/Proposal/Subject/dispatch digests will be recomputed
from the actual merge before concrete execution approval.

No audit refs existed at initialization readback. Existing R4 requires its
single-use audit genesis to bind the actual authenticated Owner run/decision.
That run ID does not exist before dispatch. The existing transport has bounded
`create_genesis` and `initialize_ref` primitives, but the manual Hosted Writer
entry only opens APPEND after validating a pre-existing genesis; it does not
expose a one-time initialization entry. Therefore a reviewed bootstrap execution
path and actual run-bound genesis approval remain prerequisites. This PR does
not invent a genesis SHA, bypass that requirement, add a new initializer or
change reserve/consume/APPLY/complete. This is an actual remaining integration
dependency, not a demand to execute a Writer before creating Ruleset B.

Derived Registry content will be the exact protected R4 result plus
`DERIVED_PARENT_LINEAGE_V1` with an empty entries list, using the existing
`derived_parent_registry.genesis`. Its `root_revision` must be the actual
protected Registry integration commit, which cannot exist before R4 receipts and
review. That revision affects lineage, policy scope and genesis identity. The
local review packet supplies all known policy fields, proposed seven source
license bindings and exact prospective Registry bytes; unavailable identities
are explicitly listed, never filled with fake hashes.

Automatic `root_revision`, derived `genesis_sha`, and deployment configuration
path/raw pin remain unbound. The existing deployment adapter has no approved
operational driver. No professor repository, production server, xiangyullm or
live Gradio access is allowed to manufacture those values. Lifecycle publication
and derived advancement remain separate from operational deployment.

## Variables: current and proposed

All following Variables are currently absent. Existing historical archive and
Owner registration Variables remain unchanged.

| Variable | Proposed value after concrete approval |
| --- | --- |
| `PARENT_AUTHORITY_WRITER_PREPARATION_ENABLED` | `true`, only with the exact reviewed R4 deployment and usable bootstrap |
| `PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_JSON` | Final Request/Proposal/Subject/audit bindings after actual merge/run identity |
| `PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_SHA256` | SHA-256 of those exact JSON bytes |
| `CONTINUOUS_BUILD_DEPLOYMENT_JSON` | Existing schema 4 deployment, actual protected authorized root and completion authority |
| `CONTINUOUS_BUILD_DEPLOYMENT_SHA256` | SHA-256 of its finalized exact bytes |
| `CONTINUOUS_CONSTRUCTION_ENABLED` | `true` after authorized root and derived initialization |
| `CONTINUOUS_PUBLICATION_ENABLED` | `true` after approved immutable publication scope; repository immutable Releases already enabled |
| `AUTOMATIC_LIFECYCLE_ENABLED` | `true` only after all prerequisites and complete policy approval |
| `AUTOMATIC_LIFECYCLE_POLICY_PATH` | `configs/ci_v2_automatic_lifecycle_policy.json` once complete and reviewed |
| `AUTOMATIC_LIFECYCLE_POLICY_SHA256` | Actual final complete runtime policy raw digest |

Keep all activation Variables unset until their exact complete contents have
been approved. Do not treat symbolic future bindings in this table as executable
values or authorization. No lifecycle Hosted acceptance is claimed by this PR.
