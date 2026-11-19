# Local-origin Owner Subject v2 and isolated transactions (L2-B2b)

This implementation is offline-tested only. All Owner/API and Hosted successes
in its tests are synthetic, not genuine GitHub authorization. No evidence asset
has been published, no actual registration or deployment is performed, and
expanded private-hosting consent remains pending. Do not begin L3 automatically.

## Closed version boundaries

- Hosted request schemas 1/2 retain Subject v1 and Deployment v1. Their subject
  meaning and dispatch fields are unchanged; no Hosted failure falls back to L1.
- Local request Schema 3 requires the nine-field L2-B2a evidence contract and
  Subject v2. Deployment v2 is the existing closed deployment shape **plus**
  integer `registration_subject_version: 2`, with `schema_version: 2`. It accepts
  only request Schema 3 / Reference v3. Deployment v1 continues rejecting these.
- The same six dispatch inputs can bind the new subject's canonical SHA-256;
  its version comes from the independently pinned deployment, never a new
  caller-controlled authorization flag. No workflow definition or setting has
  been changed or activated here. A future reviewed checkout must track all
  local verification modules and configuration.

`src/local_registration_subject.py` defines the exact field sets and validation.
Subject v2 binds the reviewed raw request, old Registry bytes, key/entry digest,
Owner policy digest and repository/workflow domain; Candidate/Parent/Baseline,
generation, both upstream commits, source state, build/orchestration fingerprints;
the exact original descriptor, Full snapshot manifest/parity hashes and four-file
PARITY_PASS; quality/R2/P4.1 pins and anchor qualification; complete local transport,
publication commit and immutable evidence asset; and the complete Reference-v3
three-asset set plus verified notices. No transient path enters the subject hash.
Quality/Q1/P8 and production restrictions remain unchanged.

`prepare(project, registry_path, request_path, request_sha256, *, token=None)`
reopens the independently raw-pinned request/policy, reruns remote verification,
reinspects extracted bytes through L1, reinvokes existing registration preflight,
and requalifies the immediate Parent using **NO_FRESH_REPLAY**. It never accepts a
saved verification receipt as input. `validate(subject)` is structural validation
only, usable offline for recovery; it grants no authorization.

## CLI, Owner and trusted entry point

Existing `verify-local-evidence` remains evidence-only. The new read-only
`verify-local-subject --request ... --request-sha256 ...` reconstructs an unsigned
Subject v2 for independent review and returns its canonical digest. It grants no
Owner authority and retains its new external verification workspace.

`register` now routes Schema 3 to `register_local()` but ordinary invocation is
still denied by the unchanged `_trusted_dispatch_context()`. There is no trusted,
mock, actor, approval or bypass flag. Legacy `verify-subject` is not repurposed.
Neither a saved Owner JSON nor local runtime environment establishes authority.

The dedicated reviewed Hosted adapter may select the local internal route only
with independently pinned Deployment v2, exact tracked implementation/request/
policy, clean checkout, frozen runtime and runtime/API identity checks. It marks
the approved subject version internally. Existing Owner verification then checks
actual API actor ID and authorization, run/attempt/default branch/workflow/commit,
remote Registry bytes and exact dispatched subject hash, twice. The new branch
also requires private repository visibility. Those Actions identities describe
the **approval operation**, never the original local scientific execution.

This preserves the existing maintainer-governed trust model, not cryptographic
local-process attestation or protection from a malicious equal-privilege owner.
Offline mocks do not establish that a real deployment satisfies this model.

## One transaction writer and mandatory notices

The existing `_register()` remains the sole writer. Local registration supplies
the raw request path/pin to its private version route, not an approval result.
Under its stable lock it checks authoritative/copy equality, expected old SHA,
duplicates and conflicts. It freshly verifies local content and Subject v2, then
verifies Owner approval. After PREPARED it repeats underlying remote/L1 checks,
requires the reconstructed subject to be identical, repeats trusted context and
Owner checks, validates durable audit bytes, and performs the existing final CAS.

All registration v3 restore paths, including historical duplicate checks and
post-publication qualification, use three-asset verified delivery and explicitly
pass `notices_path` to public `trusted_snapshot.restore()`. ZIP and receipt are
retained beside each restoration. v2 uses its original path and does not gain a
retroactive notices guarantee. The public restore gate is unchanged.

## Journal v2 and durable recovery

Journal v1 keeps its original fields and Subject v1 branch. Journal v2 requires
Subject v2, local origin, raw request pin and `local_audit` pins. Completion has
the matching version. Mixed/unknown versions fail closed; no broad extra-field
acceptance is introduced.

Before PREPARED, content-addressed `<sha>.evidence.json` and `<sha>.notices.zip`
are exclusively persisted and directory-fsynced in the controlled isolated
directory. The bounded JSON bundle retains exact UTF-8 request/policy/descriptor/
transport-manifest bytes and subject digest. Journal holds Subject v2, actual
Owner evidence, old Registry text and new/old digests. Full source archives are
not duplicated: independently pinned immutable assets and the retained manifest
provide their identities; this does not claim offline scientific reexecution.
The small notices ZIP survives temporary workspace removal and is independently
revalidated through the stable directory fd. Linux `/proc/self/fd` anchors ZIP
reads, consistent with the existing Linux/flock transaction runtime.
Historical v3 notices used for duplicate checks are also retained as pinned ZIP
files. The v2 bundle binds their references and verification receipts to the old
Registry; legacy journals retain their old schema and do not reinterpret v2
references as carrying a notices guarantee.

These are multiple durable writes, **not one atomic multi-file transaction**.
Interrupted pre-journal writes can leave unreferenced content-addressed evidence;
it grants no authority and is never treated as completed registration. Do not
silently clean or reuse journals to retry registration.

The sole commit point is existing atomic replacement of isolated `registry.json`.
Directory fsync precedes reporting success. Audit completion failure afterwards
reports COMMITTED_WITH_ERROR. Recovery requires the independently retained
transaction ID, verifies the matching version and retained evidence, and:

| Registry bytes | Result |
|---|---|
| Exact old bytes | NOT_COMMITTED; no registration or Registry rewrite |
| Exact new bytes | Complete audit only; repeated recovery is idempotent |
| Neither | CONFLICT; no Registry rewrite |

Recovery does not call Owner APIs, download evidence, construct another subject
or renew approval. Thus remote outages cannot hide a committed update. Missing,
corrupt or incompatible local journals/evidence fail closed; they do not permit
reconstruction of authority from an untrusted receipt. A journal pin is a trusted
local audit anchor, not a cryptographic signature against its own operator.
If valid journal identities prove that new Registry bytes were committed but
retained evidence is damaged, recovery reports COMMITTED_WITH_ERROR and does not
complete the audit. It does not misreport the update as uncommitted.

## Offline verification

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH=tests \
  tools/treesitter-chunker/.venv/bin/python -B -m unittest \
  test_local_registration_integration test_local_candidate_verification \
  test_local_candidate_transport test_local_candidate_evidence \
  test_local_registration_request test_register_trusted_baseline_cli.RegistrationCLITests \
  test_registration_build_separation.RegistrationRequestTests \
  test_published_candidate_verification test_candidate_release_archive \
  test_private_release_transport test_notices_delivery.NoticesDeliveryTests \
  test_baseline_registration_transaction test_owner_manual_baseline_approval \
  test_hosted_registration test_hosted_registration_workflow test_trusted_baseline_registration
```

The authentic L1 test's conditional bulk skip means no fixture index was supplied;
its actual test body was separately executed and passed during L2-B2a. This stage
does not rerun a scientific experiment or claim an authentic remote/Owner test.
Frozen artifacts, historical pins, Registry, policies and unrelated edits are
preserved. Future real acceptance requires separately reviewed deployment pins,
expanded hosting consent, genuine publication/readback and explicit Owner dispatch.
