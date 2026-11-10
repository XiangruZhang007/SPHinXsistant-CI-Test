# Explicit local continuous research builds

The existing P4/P5A.1 engine already supports multigeneration incremental reuse.
`build-next` adds explicit local Parent selection to the schema-2 entry point.
It does not replace that engine, introduce another approval policy, or remove
the hosted workflow's `PARENT_RETRIEVAL_ANCHOR_NOT_QUALIFIED` restriction.

```bash
PYTHONHASHSEED=0 python -B scripts/ci_v2_schema2_research.py build-next \
  --registry reviewed-registry.json --key reviewed-parent \
  --expected-reference-sha256 "$REFERENCE_SHA256" \
  --parent restored-parent --base-source parent-checkouts \
  --target-source target-checkouts --policy reviewed-build-policy.json \
  --expected-policy-sha256 "$BUILD_POLICY_SHA256" --output "$RESEARCH_BUILD_ROOT/new-build"
```

Use the existing frozen parser interpreter/runtime. Registry and source paths
are explicit; no remote access or downloads occur. Use an output location outside
the project and all protected inputs, as required by the existing builder.
Success prints JSON and
returns 0; invalid inputs print a rejection and return 2. The command creates
only a new output directory; an existing directory is rejected. Failed builds
remove only their newly-created output. Live progress/power-loss recovery and
concurrent mutation by an external operator are not provided.

## Selection and trust

The operator supplies an independently reviewed reference digest, not a digest
read from an untrusted Candidate. The schema-2 registry entry and caller's pin
must agree. Registry duplicate JSON keys/node identities, missing keys, unsupported
schemas, unsafe package files, mismatched hashes and incompatible builders fail.
There is no latest selection or bootstrap fallback. The registry and build policy
must be outside the Parent. Keep both in an operator-controlled location; hashes
are integrity bindings, not signatures or a new human approval mechanism.

The existing `trusted_snapshot.validate_reference/verify_package` verify the
full Parent: manifest, Corpus SHA-256, node/package identity, source state and
exact upstream revisions. Research Parents require existing schema-2
`RESEARCH_BASELINE` and `P4_1_VERIFIED` evidence. Existing local or Release-backed
reference descriptors are accepted, but only the already-restored bytes are
used: this command does not verify remote availability, Release immutability,
or transport SHA against an archive it never reads.

The separately pinned build policy must bind the actual Parent edge, commits,
source state and build contract. If the registry also pins a build policy, that
pin must agree. The explicit `--policy` supplies the local file; the hosted
registry's `build_policy_path` is not reinterpreted relative to this registry.
The unchanged builder verifies clean local Git checkouts, Git object proofs,
authorized target revisions and relationship proofs. Parent and registry are
checked again after construction. No synthetic fixture override is in the CLI.

## Complete snapshots and lineage

`new-build/candidate/` is the ordinary sealed schema-2 Candidate. The existing
lineage retains immediate Parent identity/package checksum, upstream pairs,
source states, generation, build and orchestration contracts, source inventories
and extraction graphs. Existing validators reject broken, repeated/cyclic,
self-parenting or incompatible lineage. A separately approved research baseline
has its own existing baseline ID; its original Candidate ID stays unchanged.

`new-build/build-selection.json` is a deterministic supplementary receipt,
schema 1 (`research-build-selection`), with the exact Parent and Candidate IDs,
Corpus and manifest hashes, registry/reference/policy pins, upstream pairs,
source states, chunker commit, build fingerprints and actual reuse counters.
It references existing lineage rather than minting replacement snapshot IDs.
It is neither an input authority nor a baseline approval. A Release locator, if
present, is copied as a reference descriptor, not proof of current remote state.

P9.1's Corpus-plus-metadata storage is insufficient as an incremental Parent.
The full inventories, extraction graphs, Git proofs and required evidence must
be retained. No duplicate Corpus store or mutable current/latest pointer is added.

## Retention and remaining hosted work

A new Candidate is never automatically accepted or registered. Retain the
completed package, use the existing `scripts/upstream_research.py approve`
procedure with its complete full-parity, quality, independently pinned policy
and authorization evidence, then independently review a reference/registry entry
for the resulting baseline. If required evidence is unavailable, stop. Do not
downgrade an evaluated policy to structural-only, invent an approval, or approve
the historical Candidate as a side effect of this command.

Tests explicitly approve miniature synthetic fixtures under the existing
P4.1 STRUCTURAL_ONLY policy. This demonstrates C0 -> approved C1 -> C2 using
real extraction and unchanged-file reuse; it does not qualify a genuine
historical Candidate or establish quality acceptance. Build-only output is
marked `retrieval_evaluation=NOT_EXECUTED`, `research_baseline_created=false`,
`hosted_validation=NOT_EXECUTED` and production `NOT_AUTHORIZED`.

Hosted research-Parent execution still requires a separately qualified R2
result anchor bound to the approved Parent, trusted immutable package/results
storage and reviewed transition policy, followed by a real runner test. Existing
`plan/execute-plan/local/verify-run` semantics and mandatory checks stay intact.
P8, Promotion Policy, P9, Q1, Retriever, Gradio and all historical evidence are
unchanged. This is local continuous build support, not automatic delivery,
production promotion or a continuously updated deployed knowledge base.
