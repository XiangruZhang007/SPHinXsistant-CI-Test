# Minimal isolated registration CLI (Step 2C.2-C2)

The legacy Request below remains schema version 1. Step 2C.3-C1-T1 adds a
strict version 2 Request for explicit registration-only entries, without any
`expected_build_policy_sha256` field. See
[registration/build separation](registration_build_authorization_separation.md).
The command names, independent request hash and deny-by-default local boundary
are unchanged.

`scripts/register_trusted_baseline.py` provides three library-backed commands.
It derives the project root from its own location and never accepts `--project`,
an authoritative Registry destination, actor IDs, saved approvals, tokens, or
simulation options. The existing transaction execution-trust boundary is
unchanged: ordinary local registration remains `BLOCKED`.

## Reviewed request

For `verify-subject` and `register`, supply the same reviewed JSON request and an
independent SHA-256 of its **exact raw bytes**. The request is opened once with
`O_NOFOLLOW`, checked as a bounded regular file (maximum 4 MiB), read once, hashed,
then parsed from those same bytes. JSON formatting changes require a new request
pin; they do not change the deterministic subject when content is unchanged.

The request has exactly these fields:

```text
schema_version: 1
registry_key: <safe Schema V2 key>
proposed_entry: <existing complete Schema V2 Registry entry>
candidate_release: <Step 2C.2-A three-asset transport descriptor>
expected_candidate_release_sha256: <canonical descriptor digest>
expected_reference_sha256: <canonical Baseline reference digest>
expected_build_policy_sha256: <raw build-policy file SHA-256>
expected_registry_sha256: <raw authoritative Registry file SHA-256>
approval_policy_path: configs/<reviewed-owner-policy>.json
approval_policy_sha256: <raw Owner-policy file SHA-256>
```

All fields are required. Duplicate fields, nonfinite numbers, unknown fields at
the request/entry/reference/authorization/locator/transport levels, malformed
identifiers and hashes, unsupported types, or unsafe paths fail closed. The
reference accepts only the existing schema-2 Research Baseline fields and the
optional existing `candidate_id` field. It must use private same-repository
immutable locators. The original public P2 transport is unchanged; this CLI
registers research Baselines only.

The build policy must be a regular file under `configs/`; the Owner policy must
be directly in `configs/`, as required by its existing verifier. Symlink paths
and escaping paths are rejected. This CLI fixes the authoritative Registry to
`configs/ci_v2_schema2_trusted_baselines.json`. A policy naming another file is
rejected. Actual Registry/evidence consistency remains checked by the existing
verification and transaction modules.

The request hash and embedded pins are integrity inputs, not authority. The
operator must obtain/review their trust origin separately. The policy's identity
must match the configured private repository. Runtime repository environment
bindings remain required for transport; they do not grant execution authority.

## Commands

Use the existing compatible chunker Python environment. Placeholders below must
be replaced with actual reviewed inputs; no genuine request is fabricated here.

```bash
PYTHONHASHSEED=0 tools/treesitter-chunker/.venv/bin/python -B \
  scripts/register_trusted_baseline.py verify-subject \
  --request /path/to/reviewed-request.json \
  --request-sha256 <independently-pinned-request-sha256>

PYTHONHASHSEED=0 tools/treesitter-chunker/.venv/bin/python -B \
  scripts/register_trusted_baseline.py register \
  --request /path/to/reviewed-request.json \
  --request-sha256 <independently-pinned-request-sha256> \
  --isolation-directory /path/to/dedicated-isolation-directory

tools/treesitter-chunker/.venv/bin/python -B \
  scripts/register_trusted_baseline.py recover \
  --isolation-directory /path/to/existing-isolation-directory \
  --transaction-id <independently-retained-transaction-id>
```

`verify-subject` calls Step 2C.2-A, returns its complete subject and deterministic
`registration_subject_sha256`, and preserves `NO_FRESH_REPLAY`, `NOT_VERIFIED`
authorization and `NOT_PERFORMED` registration. It may read/download/extract
independently pinned evidence in owned temporary directories; it never writes
the Registry or grants approval. No retrieval or corpus generation is executed.

`register` requires an existing dedicated isolation directory outside the project
containing `registry.json` with the authoritative Registry's initial exact bytes.
All path, inode, hardlink, lock and transaction safeguards are delegated to the
existing module. `_trusted_dispatch_context()` is unchanged and rejects ordinary
local calls even if `GITHUB_ACTIONS=true` or event JSON is provided. Rejection may
create the module's stable lock file; it does not alter Registry bytes.

`recover` requires no request, request checksum, token or Owner authorization.
Its independently retained transaction ID identifies the existing PREPARED
record. It may complete audit evidence for an already committed isolated update,
but cannot rewrite Registry contents or create approval. It reports a third
Registry state as `CONFLICT` and original bytes as `NOT_COMMITTED`.

For private transport, the CLI selects the first nonempty credential from
`TRUSTED_RELEASE_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN`. No credential is accepted in
JSON or command arguments. Existing `GITHUB_REPOSITORY` and numeric repository
ID bindings must match the locators. Credentials are never printed. Actual Owner
API access remains the existing module's responsibility and is not enabled here.

## JSON and exit codes

Except for explicit `--help`, stdout contains one JSON object. Parser failures
(including missing/unknown arguments) return sanitized JSON rather than usage
text or raw input values. Library stdout/stderr is suppressed; detailed safe
diagnostic codes are retained, and unrecognized exception text is replaced.
Known credential values and URL strings are redacted from returned diagnostics.

| Exit | Meaning |
| --- | --- |
| 0 | `EVIDENCE_VERIFIED` or `COMPLETED` for the requested operation |
| 1 | `BLOCKED`, `CONFLICT`, `NOT_COMMITTED`, invalid arguments or inputs |
| 2 | `COMMITTED_WITH_ERROR`: preserve evidence and inspect/recover actual state |

An exit code 0 for subject verification grants no approval. A recovered completed
audit grants no new authorization. Production remains `NOT_AUTHORIZED`; no P8,
quality or Q1 status is upgraded.

## Tests and remaining Hosted requirements

```bash
PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=tests \
tools/treesitter-chunker/.venv/bin/python -m unittest \
  test_register_trusted_baseline_cli test_baseline_registration_transaction \
  test_published_candidate_verification test_owner_manual_baseline_approval \
  test_trusted_baseline_registration test_github_baseline_approval \
  test_candidate_release_archive test_private_release_transport test_parent_r2_anchor
```

Tests use isolated files, mocked GitHub responses and existing synthetic evidence.
The ordinary registration test leaves the actual execution guard untouched. A
separate subprocess test confirms spoofed GitHub environment does not authorize
the CLI. Successful recovery tests use previously simulated isolated transactions;
these cannot be interpreted as real Owner approval. No real asset download,
genuine corpus build, genuine R2 evaluation or Hosted execution is performed.

The companion Step 2C.3-B implementation supplies a dedicated manual workflow
and separate execution entry; see `hosted_registration.md`. Actual independently
fixed deployment configuration, immutable Candidate/P4.1 assets and genuine
Hosted acceptance remain prerequisites. Initial acceptance targets an isolated
copy. This ordinary CLI neither enables Hosted authority nor writes the live
Registry, selects a Parent automatically, or delivers production corpora.
