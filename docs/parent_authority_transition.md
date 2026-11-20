# Owner authority transition V1 — offline contract

`src/parent_authority_transition.py` defines the distinct operation
`PARENT_BUILD_AUTHORITY_TRANSITION_V1`. It does not change registration Request
versions 1–3, Owner Subject versions 1–2, append-only registration, or Registry
schema 2. The current official Parent remains `REGISTRATION_ONLY`.

## Three separate boundaries

`prepare(project, request, expected_request_sha256=...,
expected_implementation_revision=..., notices_path=...)` reads pinned files and
returns `PREPARED_NONOPERATIVE`, `authorization: NOT_GRANTED`, `operative: false`.
The closed `REQUEST_FIELDS` contract is the authoritative field inventory. Request
and proposal SHA-256 values use existing canonical JSON serialization; Registry,
policy and notices SHA-256 values bind original bytes. The target Source State
retains its `sha256-` prefix. Policies must already exist at safe project config
paths, but preparation does not approve, install or create them. The existing
private Release locator validator also requires matching process-local
`GITHUB_REPOSITORY`/`GITHUB_REPOSITORY_ID` metadata scope. These values are not
evidence of Actions execution or Owner permission; fixtures set synthetic scope
only and cannot enable AUTHORIZE/APPLY.

Preparation checks the original Registry, existing key, unchanged Baseline/v3
Reference/notices, exact Schema-2 build-policy scope, bounded/current Continuous
scope and existing nine-field Owner policy domain. Only the requested Parent is
permitted in the proposed Continuous scope. It checks compatibility with existing
metadata consumers using an in-memory copy. The supported proposed entry uses
the four-field build-bound form; no new Registry permission field is invented.
The deterministic result serialization follows existing sorted, indented JSON
with a trailing newline. The independently supplied expected resulting Registry
digest must match. All unrelated entry/metadata values and the Reference remain
unchanged. Only hashes and a review envelope are returned, not a loadable Registry.
Original registration audit records stay untouched; the proposal binds the old
Registry and transaction ID for later transition audit provenance.

These are offline metadata/integrity checks. They do **not** verify a trusted
implementation checkout, actual official branch membership or raw source proofs,
Parent package/P4.1 qualification, fresh Parent R2, Full Parity or target replay.
Those checks remain mandatory in the genuine execution path. Proposed policy
validity is checked at preparation time and must be checked again later.

`inspect_owner_decision()` accepts the separate closed `DECISION_FIELDS` shape.
It checks operation/proposal/request/old-result Registry/scope/implementation and
transaction/run/actor bindings, including first attempt and triggering actor.
Its only success is `CONSISTENT_UNAUTHENTICATED_OWNER_DECISION`. A caller-provided
actor ID, run ID, JSON document or matching digest authenticates nobody. Repeating
this pure inspection does not consume a transaction or establish replay safety.

`authorize()` and `apply()` reject even a structurally consistent synthetic
decision with `TRUSTED_OWNER_TRANSITION_INVOCATION_NOT_IMPLEMENTED`. There is no
approval injection callback, simulation switch, credential issuer or output
Registry parameter. No real AUTHORIZE/APPLY implementation is claimed. This
explicit offline capability differs from claiming a live transition exists.

## Required future trusted invocation

A separately reviewed Hosted integration must pin the exact implementation
(including this module), Request and policy bytes; authenticate private repository
identity, actual Owner/actor/triggering actor, exact workflow/default branch and
reviewed commit, first Run attempt and operation-specific dispatch subject. Reuse
the existing Owner identity checks as identity evidence, not as approval of a new
operation. Never reinterpret an old registration approval or old dispatch input.

It must re-PREPARE from original independent pins, compare the exact reviewed
proposal, obtain the genuine operation-specific Owner decision, and lock/consume
the transaction once in durable audit state. After authorization, a future writer
may create **only an isolated** Registry result whose exact bytes equal the
approved result digest, retaining old/new identities and transition evidence.
Concurrent/replayed/partial transactions require fail-closed audit/recovery
semantics. Authoritative integration and Git operations remain separate approvals.
This task neither supplies that workflow nor creates an approval credential.

## Research loading and scientific limits

The D3.3 selector remains unchanged: it explicitly requires registration-only
authority and refuses build/production requests. There is no independently
authenticated transition receipt it could presently consume for a build-bound
Parent. A future narrow compatibility change must validate genuine transition
provenance against independently trusted pins, preserve existing research-use
permission and all Corpus/Candidate/Baseline/notices checks, and never make build
authority alone authorize research loading or production activation.

Retain `QUALITY_REVIEW_REQUIRED`, `Q1_NOT_QUALIFIED_FOR_VERSION_PAIR`, `P8_BLOCKED`
and `PRODUCTION_NOT_AUTHORIZED`. No automatic publication, research approval,
registration, scheduling or production permission follows from this contract.

## Offline checks

Use the existing frozen Chunker Python environment, with `PYTHONDONTWRITEBYTECODE=1`,
`PYTHONHASHSEED=0`, `PYTHONPATH=tests`, and `TMPDIR=/tmp`. The existing local evidence
verifier deliberately requires the OS `/tmp` workspace. Historical private Release
tests also require process-local `GITHUB_REPOSITORY` and `GITHUB_REPOSITORY_ID`
matching the retained Registry's research repository. These are metadata scope,
not Hosted execution or Owner authority. Allow file transport for synthetic Git
fixtures while denying network transports; no real Release bytes are downloaded.

```bash
tools/treesitter-chunker/.venv/bin/python -B -m unittest -v \
  test_parent_authority_transition \
  test_registration_build_separation \
  test_owner_manual_baseline_approval \
  test_continuous_build_policy \
  test_notices_delivery \
  test_research_corpus_selection \
  test_trusted_baseline_registration \
  test_baseline_registration_transaction
```

All new tests use synthetic notices, policies, repository identities and Owner
decision fixtures. Their positive result proves structural preparation and
consistent unauthenticated decision inspection, never real Owner approval or
an applied Registry upgrade. Existing regression suites overlap other historical
test inventories and must not be added to those as independent coverage.
