# Owner-pinned runtime Ruleset observation

This is an explicitly selected observation revision within
`OWNER_MANAGED_GOVERNANCE_V1`, initially restricted to
`XiangruZhang007/SPHinXsistant-CI-Test` (1455203884), Owner 239840087,
App 5855475 and the existing installation 184185108. It adds no permission,
credential, approval tier or lifecycle. Historical contracts remain available.

Genuine credential verification run
[45362927586](https://github.com/XiangruZhang007/SPHinXsistant-CI-Test/actions/runs/45362927586)
passed in both Writer Environments at protected revision
`9a533901dbb55806bc62ec70b5f009e41b5bb057`. The read-only GITHUB_TOKEN,
full-installation read token and repository Contents-write token all received
the visible A/default projection but no `bypass_actors`. Four temporary tokens
were revoked; no repository-data write probe occurred. Reuse this capability
baseline; do not repeat credential verification to activate this contract.

## Explicit runtime policy selection

Manual transition deployment schema 3 still pins its governance policy through
`governance.policy_path` and `policy_sha256`; the policy digest remains bound by
the existing Subject v2 and audit binding. Governance policy **version 2** adds
exactly one field to version 1, `ruleset_observation`. All existing fields,
including the existing Owner rollback risk acknowledgement, remain required.

Automatic lifecycle policy **version 2** likewise adds exactly that field to
version 1. Its kind, permission map, generation bounds, root, genesis, deployment,
scientific and implementation pins are unchanged. The existing raw policy pin
and scope digest cover the new field. Version 1 continues to require complete
live bypass observation; omission does not silently select the new contract.

The closed `ruleset_observation` object has these five fields:

| Field | Required meaning |
| --- | --- |
| `mode` | `OWNER_PINNED_WITH_LIVE_PUBLIC_PROJECTION` |
| `evidence_path` | Reviewed tracked `configs/*.json` file |
| `evidence_sha256` | SHA-256 of its actual complete raw bytes |
| `risk_acceptance` | `CURRENT_BYPASS_CONFIGURATION_UNVERIFIABLE` |
| `operation` | `MANUAL_R4` or `AUTOMATIC_LIFECYCLE`, matching the consumer |

The new complete evidence schema is `OWNER_RUNTIME_RULESET_OBSERVATION_V1`,
schema version 1, purpose `RUNTIME_GOVERNANCE_POLICY_INPUT`. Its exact fields
are `schema_version`, `kind`, `purpose`, `repository`, `repository_id`,
`owner_id`, `default_branch`, `observer`, `observed_at`, `expires_at`,
`history_ruleset_id`, `writer_ruleset_id`, `default_ruleset_id`,
`writer_integration_id`, and `rulesets`. Observer is the reviewed Owner identity
(`id`, `login`, `repository_admin_observed=true`), not runtime authentication
or proof that historical observations are current.

The three ordered full rows are A, B, default protection. Each contains exactly
`id`, `target`, `enforcement`, `conditions`, `bypass_actors`, `rules`, with
explicit full bypass lists. A/default must have no bypass; B allows only the
existing App. Audit rules and exclusive scopes remain fixed; default protection
must retain PR review, CODEOWNERS and stale-review dismissal. The canonical A/B
digest must equal the existing `governance_sha256`. Policy validity must lie
inside the evidence window and start no earlier than the Owner observation.
The policy raw pin binds the evidence; evidence does not hash its containing
policy, avoiding a digest cycle. Do not use the PR #14 credential-only snapshot:
its schema/purpose cannot pass this loader.

## Shared runtime behavior

`scripts/runtime_ruleset_observation.py` is stdlib only and is included in the
manual and automatic implementation manifests. The manual isolated gate imports
it only after checking the reviewed checkout. Manual R4, Automatic Writer and
Git audit transport all use the same loader and live projection comparison.
Existing effectful revalidation callbacks reload policy/evidence validity and
repeat observation before reserve, consume, isolated APPLY, publication, derived
append and completion, at their existing boundaries. No transaction or
scientific acceptance checks are replaced by this observation.

Every observation GETs A/B/default. Missing required public fields, malformed
values, observable drift and returned mismatched bypass lists block. Omitted
bypass produces `NOT_RETURNED_LIVE_BYPASS_UNVERIFIED`; returned exact lists
produce `RETURNED_EXACT_MATCH`. Runtime reports keep Owner observation dates,
evidence digest and per-Ruleset visibility separate from the live public
projection, with `complete_current_ruleset_verification=false` and
`authorization=NOT_GRANTED`. A matching projection never creates authorization.

Hidden bypass changes after the Owner observation may remain undetected until
Owner review. This is an accepted limitation, not complete live protection
verification. Observation/revalidation also does not provide atomic protection
against control-plane changes between API reads and writes. Owner-managed trust
and the existing rollback limitation remain explicit.

Actual B bootstrap readback (27974931) exposed a separate REST serialization
case: GitHub omits `update.parameters` even though an authenticated Owner
GraphQL query explicitly returns `updateAllowsFetchAndMerge=false`. Runtime
accepts this exact omission only after a fixed read-only GraphQL query with the
same runtime token verifies the exact Ruleset database ID, complete two-rule
inventory and an explicit boolean false. Unavailable/error/partial/malformed
GraphQL results or a true value block. This never substitutes false for an
omission and does not query or fill missing bypass lists. The report labels
`LIVE_GRAPHQL_FALSE_REST_PARAMETERS_OMITTED` separately. Existing App token
GraphQL capability will be established at the actual runtime gate; the Owner
readback is not claimed as Hosted evidence. No new permission or credential is
needed or assumed. Full history is fetched in the two automatic jobs that use
the existing protected-root ancestry check.

## Bootstrap and remaining concrete approvals

1. Review and merge this implementation through protected CODEOWNERS review.
2. Use the already successful credential evidence to establish usable App
   credentials. Create the previously approved exact Ruleset B, without changing
   A/default protections or either Environment. A successful Writer transaction
   is **not** a prerequisite for creating the Ruleset it needs. No audit,
   Registry or genesis writes are required to create B.
3. Record the actual B ID; read back its complete approved payload and A/default
   using the Owner CLI. Compare A/default with preserved evidence. Capture a new
   complete runtime observation with an explicitly reviewed expiry.
4. Prepare actual policy bytes, raw/canonical digests and actual merged code
   pins. Obtain consolidated review of the evidence, policy values, exact initial
   R4 Request/Proposal/Subject and subsequent initialization/activation contents.
   Implementation approval alone authorizes none of those data writes or values.
5. Only after those approvals execute existing R4 reserve/consume/APPLY/complete,
   verify receipts and use protected review to integrate the authoritative
   Registry result. Then initialize the reviewed derived Registry and enable
   only approved activation Variables. Genuine lifecycle validation follows.

Proposed personal-test bounds for that next concrete review (not installed or
authorized by this implementation PR):

| Setting | Current state | Proposed review value |
| --- | --- | --- |
| Runtime validity | No active v2 runtime policy | `2026-11-25T00:00:00Z` through `2026-12-09T00:00:00Z` (exclusive end) |
| Owner evidence validity | No runtime evidence | Actual observation time through the same proposed expiry; must precede policy start |
| Manual operation | No initial R4 grant | One exact `PARENT_BUILD_AUTHORITY_TRANSITION_V1` Request, transaction and Registry result, reviewed separately |
| Initial Parent | `REGISTRATION_ONLY` | Restricted `BUILD_CANDIDATE` only after genuine R4 and protected Registry integration |
| Automatic generations | No active automatic policy | `max_generations=2`, covering the requested two genuine generations within the existing maximum of 8 |
| Upstream advance bound | Retained source-policy proposal | `max_advance_commits=256`, retained from the previous proposal |
| Automatic operations | Disabled | Existing construction, scientific admission, immutable publication and derived Parent/lineage path; exact policy/activation bytes still require review |

The end date and commit bound reuse the earlier source-policy proposal. The
start is moved forward so a newly collected observation can precede it; the
two-generation cap is a concrete proposal, not a claim of previous approval.
If review passes either date, do not silently extend or activate stale values:
submit replacement concrete bounds together with the remaining initialization
approval. A real scientific rejection remains BLOCKED. No production, professor
repository, xiangyullm or Gradio deployment is authorized.
