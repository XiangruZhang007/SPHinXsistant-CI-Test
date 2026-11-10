# Hosted CI V2 research Parent integration

The existing manual workflow can plan a transition from an explicitly pinned
`schema2-research-baseline` as well as the historical P2 bootstrap. No workflow
permissions, triggers, production gates or approval formats change.

## Verification boundary

`schema2_workflow.plan()` remains a standard-library metadata preflight. A
research reference must pass the existing remote reference validator: immutable
personal-repository package and Parent-result locators, external reference pin,
exact package/Corpus/source/build bindings and scoped research-only reuse.
The transition policy must name the same `RESEARCH_BASELINE` receipt, base
commits, source state and build fingerprint. Controlled-Candidate exceptions,
automatic approval/reuse and production authorization are rejected. Planning
does not inspect a downloaded package or claim Parent qualification.

`execute_plan()` continues to revalidate the exact registry entry, download both
pinned assets through the existing public immutable Release reader, and clone
only isolated source repositories. This transport does not add private-asset
authentication or a new credential mechanism.

`run_local()` restores and verifies the complete Parent package, then calls the
existing `qualify_parent_anchor()` before any incremental build. The mandatory
live path still uses its default `fresh_replay=True`: evaluated P4.1 evidence,
frozen benchmark/runtime/quality policy and exact Parent R2 rows must verify.
There is no production CLI flag to skip that replay. Structural-only approval
or an unapproved Candidate cannot serve as this Parent.

After construction, the Candidate must use the selected Baseline ID and logical
package checksum as its immediate `RESEARCH_BASELINE` parent, with the correct
base commits/source state/build and Parent generation plus one. Existing source
proofs, lineage, full-build parity and independent retrieval checks remain.
Archive verification uses the same Parent qualifier and checks the same edge,
generation and explicit `parent_r2_anchor` binding. Older P2 archives keep their
existing compatibility path.

The immediate Parent's evaluated Candidate rows and the separately pinned fixed
historical rows stay distinct. The existing evaluator receives both. Original
frozen files are preserved; a future C2 records its own actual results and may
have different outcomes. Nothing forces old FAILs to become PASS or requires a
future result to repeat old FAILs artificially. QUALITY_REVIEW_REQUIRED, P8
BLOCKED and production NOT_AUTHORIZED remain unchanged.

## Current C1 configuration status

The approved real C1 Baseline has passed local sealed qualification with
`fresh_replay=False` / `NO_FRESH_REPLAY`. Its independently pinned local reference
and already verified package are retained outside the Baseline. Those are local
evidence, not Hosted asset configuration. This implementation does not rebuild,
repack, publish or alter them, and does not rerun real R2.

The active Hosted registry intentionally retains only its existing P2 entry.
There is no C1 Release/Asset locator or finalized C2 commit pair available in this
iteration. No fabricated IDs, placeholder active entries, or moving refs are
accepted. Pending configuration and exact known C1 bindings are recorded in the
local implementation dossier under `doc/artifacts/`, which is ignored by Git.

## Before the first genuine C1-to-C2 Hosted run

1. Review the existing C1 package for public disclosure and separately authorize
   publication, if public Release storage is selected. Keep the P2 assets intact.
2. Record actual immutable package and Parent-R2-result Release/Asset identities
   in the personal repository. Reuse the verified package/result bytes.
3. Build a new remote reference using the existing format. Replacing local
   storage descriptors changes the reference digest: compute and independently
   pin that new canonical SHA-256; do not reuse the local reference pin.
4. Freeze the exact C2 upstream commits, selected source state and genuine
   publication/relationship evidence. Prepare an independently pinned existing
   schema-2 `BUILD_CANDIDATE` policy bound to C1's approved Parent receipt.
5. Add a reviewed C1 registry key and policy without replacing P2. Deploy the
   reviewed implementation through a separately authorized Git operation, then
   authorize a manual Hosted run. Normal live replay requirements still apply.

## Validation scope

Focused tests cover standard-library planning, reference/transition binding,
missing/mismatched immutable configuration, generation checks, restoration and
mandatory evaluated qualification before a build. Synthetic package tests use
explicit controlled-fixture adapters confined to temporary test directories;
the production entry points do not expose such an override. The approved real
C1 is inspected only with `fresh_replay=False`. These checks do not constitute a
genuine C1-to-C2 build or a GitHub Runner execution.
