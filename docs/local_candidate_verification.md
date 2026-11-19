# Local remote-evidence verification (L2-B2a)

This is an offline-tested, evidence-only integration. It does not implement
Owner Subject v2, Owner decision verification, transactions or Registry writes.
Real remote verification has **not** been performed: the local evidence asset
has not been published. Its expanded private-hosting scope still needs human
confirmation and publication needs a separate explicit decision.

## Closed request and independent trust

Request Schema 3 now requires nine `local_evidence` fields: the original seven
origin/identity/digest fields plus `transport` and `transport_sha256`. Old seven-
field drafts fail closed and require renewed review and a new raw request pin.
Schemas 1/2, their Hosted verification and all registration gates are unchanged.

The transport reference follows the exact L2-T contract: `schema_version: 1`,
`kind: LOCAL_RESEARCH_EVIDENCE_TRANSPORT`, `evidence_origin`, `hosted_validation`,
`candidate_id`, `baseline_id`, `parent_id`, `corpus_sha256`, `reference_sha256`,
`descriptor_sha256`, `manifest_sha256`, `archive_sha256`, `archive_size`,
`publication_commit`, and `storage`. Its pin hashes canonical JSON. Manifest and
descriptor pins hash their exact bytes; archive pin hashes compressed bytes.
Locators require the existing closed private immutable Release schema. Local
paths, unknown Actions identities, mixed origins and arbitrary approval flags
are rejected. No genuine future IDs or populated configuration are generated.

The CLI verifies the independently supplied **raw request SHA-256**, then the
existing separately pinned policy file. Its repository name/numeric ID supply
the independent expected domain; agreement among downloaded references alone
is insufficient. Policy loading does not validate an Owner decision. The public
library requires these domain values as explicit trusted-caller expectations;
callers must not learn them from an archive. Existing private-download runtime
repository environment gates remain additional transport constraints, never
execution authorization.

## Interface and side effects

`src/local_candidate_verification.py` exposes:

- `validate_transport(local, reference, reference_sha, *, expected_repository,
  expected_repository_id)`: closed metadata/pin/domain validation only.
- `verify(project, local, reference, reference_sha, *, expected_repository,
  expected_repository_id, token=None)`: authenticated read-only remote API and
  asset retrieval, bounded content validation, notices-aware restoration and L1
  reinspection. Tokens belong in existing credential environments for the CLI,
  never command arguments or JSON.

The separate CLI operation is:

```text
scripts/register_trusted_baseline.py verify-local-evidence
  --request <independently reviewed Schema-3 request>
  --request-sha256 <independently retained raw-byte SHA-256>
```

This is interface documentation, **not** an instruction to run it against real
GitHub during offline implementation. There is no bypass or simulation switch.
The legacy `verify-subject` still rejects Schema 3. L2-B2b adds the separate
unsigned `verify-local-subject` and an isolated `register` route that remains
denied by the ordinary trusted-context boundary; see
[local_registration_subject.md](local_registration_subject.md). Deployment v1
continues rejecting Schema 3. The evidence command rejects Hosted schemas and never falls
back to their verifier. It returns JSON and exit 0 only for verified evidence;
failure is sanitized `BLOCKED`, exit 1. No Owner Subject v2 digest is emitted.

Read-only here means **no mutation of existing evidence, authorization or Registry
state**, not zero filesystem writes. New downloads, extracted evidence, restored
Baseline, notices ZIP and verification receipts are retained in a new mode-0700
owned directory under `/tmp` in the frozen Linux runtime. Neither CLI arguments,
archived paths nor TMPDIR select this destination. Failure removes that owned
workspace and returns no successful receipt. No archived command is executed.
Nonstandard helper temporary roots are rejected before workspace creation, so
existing transport helpers cannot be redirected into frozen/source directories.
Successful directories should be retained or transferred with all attachments;
`/tmp` is not durable publication. The original frozen inputs are never edited.

## Verification order

1. Validate independent request/reference/transport pins and fixed repository
   domain. Require Reference v3 and existing research-only authorization shape.
2. Verify immutable published evidence Release, exact declared one-asset set,
   and resolve its lightweight/annotated tag to `publication_commit` using GET.
   That commit identifies later publication, never an original Hosted build.
3. Existing private downloader independently checks repository ID/privacy,
   Release membership, asset ID/name/size/state, API digest when supplied and
   downloaded bytes. L2-B1 checks the entire bounded gzip/USTAR envelope,
   manifests, notices and descriptor before extraction.
4. Check descriptor identities against the independently pinned transport.
5. Verify the separate Reference-v3 Release's exact three-asset set. Download
   and verify Baseline, original Candidate R2 and notices; validate/retain ZIP
   and receipt **before** passing `notices_path` through public `restore()`.
6. Match downloaded R2 hash to the descriptor and original Candidate rows.
   Reinspect extracted files and call accepted L1 with `NO_FRESH_REPLAY`.
7. Return `LOCAL_REMOTE_EVIDENCE_VERIFIED` with actual locators/receipts and
   retained workspace. It is unsigned evidence, not registration authorization.

The operation does not construct a registration subject or claim current
Registry freshness. Any later registration must independently recheck Registry
state and approval. `QUALITY_REVIEW_REQUIRED`, Q1 restrictions, P8 BLOCKED,
production NOT_AUTHORIZED, LOCAL_RESEARCH_EXECUTION and HOSTED_NOT_RUN remain.

## Offline checks

All positive and negative remote scenarios use synthetic fixtures and mocked
GitHub GET responses. Real archive validation, ZIP verification, safe restore
and L1 composition run; scientific validators are the existing synthetic L1
test doubles. No actual download, build or R2 experiment is required.

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH=tests \
  tools/treesitter-chunker/.venv/bin/python -B -m unittest \
  test_local_candidate_verification test_local_candidate_transport \
  test_local_registration_request test_local_candidate_evidence \
  test_register_trusted_baseline_cli.RegistrationCLITests \
  test_registration_build_separation.RegistrationRequestTests \
  test_published_candidate_verification test_candidate_release_archive \
  test_notices_delivery.NoticesDeliveryTests test_private_release_transport
```

The authentic L1 test is opt-in through its existing test-only fixture index;
report execution versus skip explicitly. Synthetic API success is not a real
remote acceptance. Hosted approval/registration and authoritative application
remain later, separately reviewed work. Do not start L2-B2b automatically.
