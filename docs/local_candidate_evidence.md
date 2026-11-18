# Local Candidate evidence (L1)

`src.local_candidate_evidence.verify(project, run, execution_records, baseline,
descriptor_path, *, expected_descriptor_sha256, reference_path)` is read-only.
It verifies an existing Schema-2 genuine local run and corresponding evaluated
P4.1 Baseline. It never constructs a corpus, extracts an archive, executes
retrieval/replay, approves anything, accesses GitHub, or writes a Registry.

Acceptance explicitly requires `PARITY_PASS`, not just agreement between stored
and recomputed Parity objects. Parent anchor receipts must preserve independent
reference trust, non-fixture provenance, no quality acceptance and production
`NOT_AUTHORIZED`. An original P2 anchor inspected without fresh replay has status
`PINNED_ANCHOR_INSPECTED`; this is not fresh qualification. Research Parent
receipts must be `QUALIFIED`. The approved Baseline's own original Candidate R2
anchor is also independently checked with `fresh_replay=False` and must return
`QUALIFIED`, bound to the exact Baseline, Candidate and original Candidate rows.

The caller must independently review and retain the **exact descriptor byte
SHA-256**. Computing a digest of untrusted downloaded metadata establishes no
authority. The descriptor has a closed v1 schema; field sets are exported as
`FIELDS`, `HASH_FIELDS`, `ID_FIELDS` and `RECORD_FILES`. Duplicate/unknown fields,
including Actions Run/Job/Artifact identifiers and `approved` flags, are rejected.

Required bindings:

- `schema_version: 1`, `evidence_origin: LOCAL_RESEARCH_EXECUTION`,
  `hosted_validation: HOSTED_NOT_RUN`.
- `candidate_id`, `parent_id`, `baseline_id`, `source_state` (each `sha256-…`),
  positive integer `generation`, and exact `SPHinXsys`/`SPHinXsim` commit SHAs in
  `upstreams`.
- `corpus_sha256`, `build_fingerprint`, `orchestration_fingerprint`,
  `benchmark_sha256`, `build_policy_sha256`, `quality_sha256`,
  `candidate_rows_sha256`, `r2_contract_sha256` (the existing quality policy's
  `R2_fingerprint` object hashed with existing canonical serialization).
- `run_manifest_sha256`, `baseline_manifest_sha256`, `approval_manifest_sha256`
  (exact `checksums.json` bytes), and `approval_policy_sha256` (exact existing
  `approval-evidence/external-policy.json` bytes).
- `reference_sha256` and `parent_reference_sha256` use the existing canonical
  Reference digest contract. The former binds the approved Baseline, the latter
  the original run's immediate Parent; their original R2 rows are distinct.
- `execution_records` maps exactly `authorization.json`, `executed-command.txt`,
  `execution-start.json`, `execution-exit.json`, `execution.stdout.log`,
  `execution.stderr.log`, `report.md` to independently pinned byte hashes.
  No command or path recorded in those files is executed or followed.

All hashes are lowercase 64-digit hexadecimal. Paths are separate caller inputs,
not descriptor fields. Inputs must be stable caller-controlled directories during
inspection; symbolic/hard links, special files, traversal and excessive sizes
are rejected. Limits are 64 KiB for descriptors, 64 MiB for JSON files, 256 MiB
per other file, 2 GiB and 20,000 entries per tree. Seals and record pins are
rechecked after inspection. This is not a sandbox against concurrent hostile
filesystem mutation. No partial result counts as verification success.

Existing provenance, full snapshot/parity, P4.1 and Parent R2 anchor verifiers are
reused. P4.1 rescoring uses stored rows; every replay option remains false. A
successful receipt explicitly says `NO_FRESH_REPLAY`, `HOSTED_NOT_RUN` and
`CALLER_PINNED_LOCAL_RECORDS`. It cannot independently attest that a local process
ran as reported. Independently trusted operator records and seals remain its trust
basis; a self-declared approval JSON is insufficient. This is not Owner
registration authorization or acceptance of retrieval quality. Preserve
`QUALITY_REVIEW_REQUIRED`, `Q1_NOT_QUALIFIED_FOR_VERSION_PAIR`, P8 `BLOCKED` and
production `NOT_AUTHORIZED`.

Reference validation here is identity validation against an existing package;
there is no Parent restoration or notices delivery. Reference v3 restore and
future transport must still enforce mandatory notices independently. L1 supplies
no download/delivery guarantee and does not route registration requests.

Future transport still needs a reviewed archive layout, bounded extraction,
independent archive/manifest hashes, genuine Release/Asset identities and
publication authorization. None is invented here. L2 registration integration,
Owner authorization and authoritative Registry application remain separate.

Run unit tests with the frozen interpreter and `PYTHONHASHSEED=0`:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH=tests \
  tools/treesitter-chunker/.venv/bin/python -B -m unittest \
  test_local_candidate_evidence test_published_candidate_verification \
  test_candidate_release_archive test_notices_delivery.NoticesDeliveryTests
```

Unit fixtures mock scientific verification rather than running experiments.
To additionally test retained genuine evidence, set `LOCAL_EVIDENCE_TEST_INDEX`
to a private external JSON file containing exactly the keyword arguments to
`verify()`. This switch is consumed only by tests; it grants no authorization and
does not weaken any verification. Without retained evidence that one test skips.
