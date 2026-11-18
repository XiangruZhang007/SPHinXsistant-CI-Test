# Local research evidence transport (L2-B1)

This implements the reviewed L2-T gzip/USTAR content contract. It does not
implement remote publication, a populated Release reference, Owner Subject v2,
registration, a CLI, or deployment. L2-A blocking gates remain unchanged.

The public library API in `src/local_candidate_transport.py` is:

- `prepare(project, run, execution_records, baseline, descriptor_path,
  reference_path, license_directory, notices_review_path, output, *,
  expected_descriptor_sha256, expected_notices_review_sha256)` verifies L1 first,
  generates scope-specific notices outside sealed evidence, and packages original
  bytes into a new external output directory. The review input is the separately
  pinned L2-T `notices-review.json`; the seven full text hashes are also fixed in
  the reviewed implementation. No recorded command is executed.
- `inspect_archive(archive, **pins)` validates the complete bounded compressed
  stream, regular USTAR headers, member inventory and manifest/descriptor pins
  without creating a destination tree or invoking L1.
- `extract(archive, destination, **pins)` validates everything first, then creates
  a new owned external directory and writes regular files exclusively. It
  reinspects the resulting tree. Existing output paths and source-repository
  destinations are rejected. Failed extraction never invokes L1; a partial
  destination left by an I/O failure is not an accepted result.
- `verify_extracted(project, root, baseline, reference_path, *,
  expected_manifest_sha256, expected_descriptor_sha256)` independently reinspects
  every member, directory, mode, hash and binding, then invokes the existing L1
  verifier. A saved extraction receipt is not a credential. This operation reads
  evidence only; any temporary metadata inspection files belong to owned `/tmp`
  storage. It neither restores the Parent nor downloads anything.
- `verify_archive(project, archive, destination, baseline, reference_path,
  **pins)` combines validated extraction and the preceding L1 invocation. It
  never invokes L1 after failed archive validation or extraction.

`pins` requires **all four** explicitly supplied arguments:
`expected_archive_sha256`, `expected_archive_size`,
`expected_manifest_sha256`, `expected_descriptor_sha256`. The first and third
hash compressed asset bytes and canonical inner manifest bytes, respectively;
the last hashes the exact unchanged L1 descriptor bytes. Remote users must obtain
pins from independently reviewed configuration, not from the downloaded archive
or an untrusted sidecar. The preparation receipt records computed observations
for later review and is not an independent authorization source.

Failures raise sanitized `TransportError` codes and produce no successful
verification receipt or authorization. Callers must fail closed; no retry,
recovery, Hosted fallback or Registry operation exists in this module. Stable
caller-owned input files are required: this is not process attestation or a
sandbox against a hostile process with equal filesystem access.

The archive includes exactly `descriptor.json`, `transport-manifest.json`, the
entire unchanged `run/`, seven selected `execution-record/` members and nine
`notices/` members (new README/mapping plus seven unchanged full license texts).
The original execution directory is not represented as a complete copy. The
separately published Baseline is not duplicated. The supplied Baseline/reference
must still satisfy L1; any later actual Reference v3 restoration must download
and verify its mandatory notices ZIP and pass it through the existing restore
gate. This module grants no notices-delivery exception.

The closed inner manifest fields, constants and limits match L2-T. The manifest
hashes all other members, never itself, the compressed archive or a future
Release locator. Its independently pinned bytes bind the L1 descriptor, original
run seal, seven record hashes and P4.1 evidence. Source revisions and fingerprints
remain bound through the unchanged L1 descriptor and verified original evidence.
There is no circular hash dependency or fabricated Hosted execution identity.

Serialization uses canonical JSON only for newly generated manifests/mapping,
ASCII-sorted regular USTAR members, UID/GID/mtime zero, empty user/group/link
names, 0644 or original executable semantics as 0755. Original data bytes are
never reserialized. Gzip uses no filename, mtime zero, level 9 and OS byte 255;
byte reproducibility is tested in the frozen Python/zlib runtime. Inspection
rejects extensions, unsupported metadata, duplicate/casefold/prefix collisions,
unsafe names, malformed padding/end markers/CRC, multiple gzip members and
trailing data. It uses bounded private temporary storage before destination
creation. Limits are 2 GiB compressed and expanded, 20,000 members, 256 MiB per
file, 64 MiB JSON, 64 KiB descriptor, 4 MiB manifest, 16 MiB notices and 255-byte
paths. Existing historical archive validators are not modified.

Notices generation uses the exact separately reviewed source and license mapping
plus actual verified run member hashes and original source revisions. The old
Baseline companion README/mapping is not copied unchanged. The new mapping and
README must still receive independent publication/compliance review; this stage
does not issue a legal clearance or broaden existing private hosting authority.
All applicable notices must accompany future archive/subset delivery.

Every prepared output is labelled `LOCAL_PREPUBLICATION_TEST_ARTIFACT` with
publication authority `NOT_GRANTED`. Original execution remains
`LOCAL_RESEARCH_EXECUTION / HOSTED_NOT_RUN / NO_FRESH_REPLAY`, with quality/Q1/P8
and production restrictions retained. There is no remote Release/Asset ID field
populated during local preparation. Future exact transport reference validation,
remote identity checks, Schema 3 adoption and Owner/transaction integration
remain later work; none of the existing L2-A blocks is removed here.

Offline tests use synthetic records and mock only scientific validators. Archive
encoding, inspection, unsafe input rejection, notices construction, extraction
and L1 routing run as real code. No Corpus or R2 experiment runs:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 PYTHONPATH=tests \
  tools/treesitter-chunker/.venv/bin/python -B -m unittest \
  test_local_candidate_transport test_local_registration_request \
  test_register_trusted_baseline_cli.RegistrationCLITests \
  test_registration_build_separation.RegistrationRequestTests \
  test_published_candidate_verification test_candidate_release_archive \
  test_notices_delivery.NoticesDeliveryTests test_local_candidate_evidence
```

L1's optional authentic test skips unless `LOCAL_EVIDENCE_TEST_INDEX` is supplied;
its existing documented fixture index is test-only and grants no authority. Any
actual research package verification should record its independent input pins,
unchanged original inventories and receipt outside the source repository, and
must remain explicitly unpublished/unapproved for registration.
