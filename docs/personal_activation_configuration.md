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
| `ci_v2_automatic_deployment.json` | Existing driver settings schema with `enabled=false`; operational deployment is blocked before any driver call |

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

No audit refs existed at initialization readback. This PR now implements the
approved minimal first-run integration in the existing manual Writer. The
externally pinned `GITHUB_GIT_AUDIT_V1` mode still requires its exact pre-existing
genesis. The new explicit backend below omits `genesis_sha` before dispatch:

```json
{
  "kind": "GITHUB_GIT_AUDIT_OWNER_RUN_BOOTSTRAP_V1",
  "audit": {
    "schema_version": 3,
    "repository": "XiangruZhang007/SPHinXsistant-CI-Test",
    "repository_id": 1455203884,
    "ref": "refs/heads/ci-v2-authority-audit/ed20b392594046db84a6f2306053440e",
    "tree_sha": "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
    "governance_sha256": "da7ec16e65c9cfdcde34af6ab244d35df3ba313dc011abed9a81623ae67fe344"
  },
  "history_ruleset_id": 27770139,
  "writer_ruleset_id": 27974931,
  "writer_integration_id": 5855475
}
```

Deployment remains schema 3 with the raw-pinned existing governance policy.
Subject schema 3 additionally pins the canonical backend digest. Preparation
authenticates the actual Owner workflow run, Request and Proposal, then derives
the genesis identity. The genesis payload includes the complete run/decision
binding digest, including the reviewed Subject; different runs yield different
genesis objects. The fixed author/committer (`CI V2 R4 Writer`,
`ci-v2-r4-writer@users.noreply.github.com`, `2000-01-01T00:00:00Z`) is Git object
metadata, not an authorization claim. SHA-1 uses the exact Git commit encoding.
No invented run ID, placeholder SHA or pre-existing tree/ref is required by
preparation or the pre-token gate. The gate independently repeats the identity
derivation against the authenticated run and preparation receipt.

After existing manual Environment approval, the existing installation-token
action and token-scope checks remain. Before any initialization write, the Writer
must observe live governance using the actual App token and prove ref absence
with both GET-ref 404 and an empty matching-ref inventory. When REST omits B's
update parameters, the existing fixed GraphQL query must return explicit false
using each runtime token that needs this observation. Owner CLI success is not
Hosted GITHUB_TOKEN or App-token capability evidence. The earlier credential
verification did not measure GraphQL; genuine Hosted capability is still
unmeasured. This integrated read-only prerequisite will fail closed before any
Git object/ref write if either required token cannot make the observation.

The first fresh INITIALIZE instance calls `create_genesis`, verifies the exact
predicted SHA and reads the object back. Context/governance and absence are
checked again, then a second fresh INITIALIZE instance calls `initialize_ref`.
Neither instance's one-shot restriction is reset or bypassed. Exact genesis/ref
readback and an empty protocol state precede APPEND. The existing
reserve/consume/isolated APPLY/complete path and effectful revalidation boundaries
then run unchanged. Existing token revocation remains enabled. Any ambiguous
initialization result stops without retry, adoption, reset or APPEND, preserving
evidence for Owner read-only reconciliation.

Implementation approval does not authorize this bootstrap or R4 execution. The
review packet must be rebound to the actual protected merge, then explicitly
approved together with the exact three R4 Variables and Owner dispatch inputs.
That execution scope would permit only empty-tree/root/ref initialization on the
ref above and the existing three audit APPEND events plus isolated APPLY. It
would not permit an authoritative Registry commit, derived initialization,
Release publication, lifecycle activation, ref deletion/reset or production work.
The actual run-bound genesis SHA is recorded after dispatch by preparation and
must match the Writer's independent derivation and remote readback. Protected
Registry integration remains a separately reviewed result after genuine R4
completion. No authoritative Registry integration is inferred from isolated APPLY.

Derived Registry content will be the exact protected R4 result plus
`DERIVED_PARENT_LINEAGE_V1` with an empty entries list, using the existing
`derived_parent_registry.genesis`. Its `root_revision` must be the actual
protected Registry integration commit, which cannot exist before R4 receipts and
review. That revision affects lineage, policy scope and genesis identity. The
local review packet supplies all known policy fields, proposed seven source
license bindings and exact prospective Registry bytes; unavailable identities
are explicitly listed, never filled with fake hashes.

Automatic `root_revision` and derived `genesis_sha` remain unbound. Deployment
configuration uses the existing schema with `enabled=false` and a raw-byte pin;
the existing adapter rejects operational deployment before any driver call.
No operational driver is supplied. The existing lifecycle policy permission map
is unchanged, but cannot override the disabled settings or missing driver.
Hosted construction/publication/derived advancement can be reviewed separately
from deployment. No professor repository, production server, xiangyullm or live
Gradio access is allowed to manufacture missing identities or activate a service.

## Variables: current and proposed

All following Variables are currently absent. Existing historical archive and
Owner registration Variables remain unchanged.

| Variable | Proposed value after concrete approval |
| --- | --- |
| `PARENT_AUTHORITY_WRITER_PREPARATION_ENABLED` | `true`, only with the exact reviewed R4 deployment and usable bootstrap |
| `PARENT_AUTHORITY_TRANSITION_DEPLOYMENT_JSON` | Final Request/Proposal/Subject and explicit bootstrap backend after actual protected merge; genesis is deterministically bound to the later authenticated run |
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
