# Owner-managed lifecycle integration — implementation and limits

This change is a partial implementation, not a fully automated deployment or a
new scientific approval. No real R4, Hosted construction or server deployment
is performed. The primary development worktree and historical evidence stay
unchanged. Development and tests use an isolated checkout.

## Versioned Owner-managed governance

`src/owner_managed_governance.py` adds `OWNER_MANAGED_GOVERNANCE_V1` under Hosted
transition deployment **schema 3**, with an exact additional `governance` object:
`trust_model`, `policy_path`, `policy_sha256`. The policy must be tracked under
`configs/`, raw-byte pinned, current, and included in the actual trusted checkout.
The implementation contract includes the new module.

The closed policy fields are `schema_version` (1), `trust_model`, `repository`,
`repository_id`, `owner_id`, `workflow_path`, `default_branch`,
`implementation_contract_sha256`, `valid_from`, `expires_at`,
`history_ruleset_id`, `writer_ruleset_id`, `writer_integration_id`, and
`risk_acceptance`. The exact required acknowledgement is
`OWNER_CAN_CHANGE_RULES_AND_ROLL_BACK_BETWEEN_OBSERVATIONS`.

Policy and deployment must match by type and value. Implementation identity is
the exact code-contract digest; the deployment Request separately pins the real
reviewed commit. Policy bytes are not part of the code digest, avoiding a
self-referential hash. The policy raw digest is instead bound into Subject v2,
its independently pinned deployment digest and the existing audit binding.
No policy file with invented revisions, Ruleset IDs or approval is shipped.

Before any append-capable transport exists, the new path invokes the actual
stdlib Writer gate, authenticates installation repository scope, and uses the
existing HTTP governance observer to verify pinned Rulesets A/B and their full
effective configuration. The existing workflow mints only its reviewed
installation token permissions; repository-scope verification does not prove
ref-scoped permissions. The existing Owner identity, first-run/manual dispatch,
exact trusted checkout, Environment, approval, reservation/consumption/APPLY,
completion and readback gates remain mandatory. Revalidation repeats governance
checks during the transaction. Environment approval remains required for this
manual transition; it is not an unattended update authorization.

Success of these observations uses `OWNER_MANAGED_CONTROLS_OBSERVED`, never
`INDEPENDENT_GOVERNANCE_VERIFIED`. Administrator rollback prevention is explicitly
`NOT_GUARANTEED`; independent governance is `NOT_REQUIRED_BY_THIS_CONTRACT`.
Owner control can change protections between observations. Existing deployment
schemas 1/2 and Subject v1 keep the original independent-governance gate and do
not gain permission through this revision. Historical reports/pins are not
rewritten. A new Hosted implementation contract must be reviewed and pinned.

## Automatic admission assessment

`src/automatic_quality_admission.py` adds a closed, raw-pinned, time-bounded
policy and deterministic assessment. It reuses complete P8 and promotion
readers for Schema 2, and the existing `verify_package(..., fresh_replay=False)`
for Genuine Continuous v2/v3. It does not replay scientific experiments.
The policy binds repository, frozen benchmark/build fingerprint, exact row/mode
domain, zero strict failures/new losses, original accepted quality, applicable
Q1, accepting P8, actual producer provenance and non-overridable restrictions.
No numeric threshold waiver or external PASS verdict input exists.

The pure calculation is tested with synthetic facts; its ELIGIBLE result is
`POLICY_CALCULATION_ONLY` / `NOT_GRANTED`. Public local readers preserve archived
versus authenticated producer distinctions and the original restrictions. They
cannot currently produce operational admission: P8 is blocking-only and the
Genuine producer/verifier requires research-only quality/Q1/P8 restrictions.
These historical interfaces remain blocking-only. The separately versioned
native automatic accepting path and scheduled handoff are implemented in
[the automatic lifecycle](automatic_lifecycle.md), behind independently reviewed
policy, protected-root and authenticated producer gates.
The current historical Candidates remain blocked. The separate qualified Q1
supplement remains diagnostic and cannot modify their original Q1 or R2.

## Gradio preparation and replacement adapter

`src/gradio_deployment_adapter.py::stage_and_verify` reuses immutable versioned
storage, the D3.6 `sudo unshare --net` / privilege-drop launcher, and the existing
real `_gradio_check`. It sets `SPHINX_CORPUS_PATH` before application import,
checks count, complete records, shared callbacks, SHA-256, real Retriever and
closure. No HTTP server, provider key, answer call or activation is involved.
Storage failure or denied namespace fails closed without a weaker fallback.
This operation demonstrates research loading, not approved-Corpus deployment.

The private replacement kernel preserves the prior instance until verification,
activation and readback pass. Identical delivery is idempotent; stale state is
denied; rollback is compare-and-swap and never overwrites a third concurrent
version. Uncertain rollback leaves possibly active children alive and reports
`STATE_UNCERTAIN`. Cleanup failure after verified activation is distinguished
from activation failure. Test drivers are controlled fixtures, not real proxy,
process ownership or server evidence. No runtime plugin/command from JSON is
accepted as a trusted production driver.

A real host-specific driver, reviewed routing/configuration, durable crash
reconciliation and authenticated approved-Release handoff remain unimplemented.
The user deferred SSH and actual server deployment until after code/PR review.
No synthetic controller is represented as a production service. Existing
synthetic lifecycle code and production application behavior remain unchanged.

## Restricted derived Registry integration

See [the review-only proposal](derived_registry_automatic_integration.proposal.md).
The default-branch protection conflicts with unattended authoritative Registry
writes. The user accepted the restricted data-only design for implementation and local
testing. The separate derived writer/consumer and native scientific successor
are described in [the implementation](automatic_lifecycle.md). No remote
configuration or activation is authorized by design acceptance. No default-branch
Writer bypass or automatic PR approval is introduced. The current Parent remains `REGISTRATION_ONLY`.

## Migration and genuine execution prerequisites

Before using this work operationally, independently review and bind:

- The exact merged implementation commit and new Hosted contract digest.
- Tracked Owner-only policy, transition Request, raw-pinned governance policy,
  Deployment schema 3/Subject v2; no invented digest for unavailable files.
- Actual immutable Parent/Reference/notices/source/Corpus/P4.1/R2 evidence and
  exact initial restricted build authorization.
- Existing bounded scheduled construction policy/expiry/revocation and producer
  deployment, plus the separately reviewed native automatic policy and pins.
- Rulesets A/B, fixed audit/genesis, actual App/installation permissions,
  protected Environment approval and reviewed workflow credential isolation.
- Least-privilege approved-Release transfer, server directories, existing venv,
  exact Gradio startup/routing settings, owned-process driver and rollback plan.
- Real two-cycle Hosted evidence, scientific rejection cases, true app startup,
  readback/rollback/crash evidence and final server acceptance.

No migration to `Xiangyu-Hu/SPHinXsistant` is performed. Repository identities,
policies, references, workflow credentials and the target host must be reviewed
there by its Owner before use. Personal repository settings are not evidence of
migration eligibility. No further SSH or server mutation is part of this step.
