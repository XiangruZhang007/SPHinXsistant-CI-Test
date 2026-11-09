# Candidate promotion policy v1

This is a supplementary policy calculation and an additional fail-closed check,
not deployment or release authorization. Legacy P8 is unchanged and remains
authoritative. No accepting real quality-adjudication or release provider exists.

## Runtime contract

`candidate_promotion_policy.evaluate(artifact)` accepts only a complete archived
run directory or original ZIP. It calls the existing P8 validator once, reads
recorded evidence, and never generates a Corpus, evaluates retrieval or replays CI.
It has no parameters accepting supplied policy, approval JSON or trust providers.

The policy has its own version and canonical SHA-256, separate from the frozen
quality policy. The decision binds existing Candidate/Corpus identities, upstream
commits, parent, build and benchmark identities, exact quality report/result hashes,
and the existing frozen quality policy digest. No frozen field is rewritten.

The conservative v1 criteria are:

- Direct acceptance requires recorded `QUALITY_ACCEPTED`, a true recorded acceptance
  flag, and no unaccounted strict failures or new losses.
- Adjudication requires an independently verified authority and a policy explicitly
  permitting that recorded status and each exact finding kind. The runtime policy
  currently permits none. Unknown review-required states are not accepted merely
  because no individual finding could be identified.
- A finding uses existing comparison group, question ID, evaluation mode and metric
  coordinates, contextualized by the report/result hashes. Accepting one coordinate
  does not accept another threshold, mode, comparison or pre-existing failure.
- Recorded strict failures are retained, including historical limitations. They are
  not implicitly waived by an explanation for DOC-Q27. V1 is intentionally conservative;
  this does not reinterpret frozen scoring or establish a new accepted historical baseline.
- A separate release source must authorize the exact bindings plus the canonical
  quality-decision SHA-256 and promotion-policy SHA-256.
- Every explicit `NOT_AUTHORIZED` remains non-overridable, including restrictions in
  the Candidate, original run, build policy, quality policy and parent reference.
- All original P8 reasons are preserved. `BLOCKING_ONLY`, any P8 blocker, or any
  supplementary policy blocker keeps the runtime result `BLOCKED`.

The new fields are additional promotion findings and decisions, not replacement
Candidate or evaluation identities. GitHub transport remains separate in the delivery
receipt; downloading an artifact does not provide either human authority.

## Trust interfaces and tests

The private pure decision kernel accepts two independently verified-source interfaces:
quality adjudication and Corpus release. Each verified verdict must have its expected
scope/decision, authority and source identities, source digest, current verification
and expiry times, and exact bindings. The source verifier, not a supplied JSON field,
must establish actual trust. Exceptions, malformed verdicts, stale evidence and
mismatched bindings are invalid. No authenticated source verifier is invented here.

Runtime always uses missing-source providers. A research-review result remains
diagnostic and is not either of these authorities. There is no new GitHub approval
infrastructure or production authorization format to configure in this iteration.

Accepting synthetic providers are defined only in `tests/test_candidate_promotion_policy.py`.
They explicitly assume a test authority, finite validity, permission for specified
finding kinds, correct Candidate/quality bindings and separate release consent.
Only this hypothetical pure calculation can return `ELIGIBLE`; its output has
`policy_only: true` and `activation_authority: false`. There is no CLI option to
choose these providers, and no test decision is passed to real activation.

## Integration and use

The existing update integration consumes the unchanged P8 result returned alongside
the supplementary calculation. Its activation branch now additionally requires the
promotion-policy result to be eligible. Existing P9 registration remains temporary;
selection/reinitialization/rollback mechanics are reused without changes.

Artifact delivery saves the policy result with the existing integration result.
No new approval arguments are added. For a standalone read-only decision:

```bash
python3 -B -m src.candidate_promotion_policy --artifact /path/to/complete-run.zip
```

Stdout is JSON; `BLOCKED` exits 1. Missing or invalid evidence fails closed. This
command never registers, selects, reloads or deploys a Corpus.

Before real eligibility is possible, the project still needs independently established
quality-adjudication rules and authority, a separate current release authority, and
explicit resolution of release prohibitions under a separately authorized transition.
This iteration defines no override for existing prohibited candidates. Production
integration, service management and continuous event-driven delivery remain outside scope.
