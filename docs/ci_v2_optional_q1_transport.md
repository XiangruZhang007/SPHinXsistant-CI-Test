# Optional Q1 input transport for manual research runs

Leave `q1_transport_config` empty to keep the previous workflow behavior. No Q1
download runs and no Q1 arguments are added to `execute-plan`.

When configured, the input names a reviewed JSON file under the checked-out
repository's `configs/` directory. The file must be tracked at `HEAD` and match
that committed version byte-for-byte. Commit membership is an integrity anchor,
not proof of human review or release authorization; review must precede use.
No operational Q1 transport configuration or fabricated asset IDs are supplied
by this implementation.

The configuration has exactly three keys:

```json
{
  "storage": {
    "kind": "GITHUB_RELEASE_ASSET",
    "repository": "XiangruZhang007/SPHinX_AI_Assistant",
    "release_id": "REPLACE_WITH_REVIEWED_POSITIVE_INTEGER",
    "asset_id": "REPLACE_WITH_REVIEWED_POSITIVE_INTEGER",
    "tag": "REPLACE_WITH_EXACT_IMMUTABLE_RELEASE_TAG",
    "asset_name": "REPLACE_WITH_REVIEWED_Q1_ARCHIVE_NAME",
    "immutable_required": true
  },
  "transport_sha256": "REPLACE_WITH_INDEPENDENTLY_RECORDED_64_CHARACTER_SHA256",
  "inputs_sha256": "REPLACE_WITH_INDEPENDENTLY_RECORDED_64_CHARACTER_SHA256"
}
```

This is a template, not a valid configuration. The locator and both hashes must
come from a reviewed publication object. The values inside the downloaded
archive cannot supply their own expected hashes. Q1 inputs are diagnostic data,
not a new entry in the trusted Corpus baseline registry.

`scripts/prepare_q1_inputs.py` validates the complete configuration before any
download. It reuses `trusted_snapshot.release_locator`, `download` and
`extract_regular` without changing their checks. The existing API supports an
immutable Q1 asset in the personal repository independently of snapshot format.
`trusted_snapshot.restore` is not used because its baseline qualification
contract does not describe Q1 transport data.

The archive is downloaded and extracted into a new private directory under
`RUNNER_TEMP`, outside the project checkout. The required layout contains
`inputs/inputs.json`; its bytes must match `inputs_sha256`. The transport receipt
is saved as `p5a/q1-transport.json`, included by the workflow's existing artifact
upload rule. On transport failure the owned staging directory is removed and a
failure receipt is retained when the requested receipt path is safe. Successful
inputs remain available for the Runner session.

The workflow adds both `--q1-inputs` and `--q1-inputs-sha256` only after restoration
succeeds. Transport success is named `Q1_INPUTS_RESTORED`; it does not mean Q1
qualification. The existing loader and diagnostics still verify the builder,
benchmark, Git/source provenance, source/corpus/result identities, exact current
parent/candidate bindings and current-package diagnostic reproduction.

Explicitly configured but incomplete, corrupt or unsafe transport fails the run
before corpus construction. It is never silently treated as absent. Once intact
inputs reach the existing Q1 diagnostics, qualification failure retains the
existing nonblocking uncertain attribution behavior. Mandatory CI failures still
fail independently of Q1; there is no global `continue-on-error` or approval
override.

Before hosted use, review and accept the retained disclosure metadata, authorize
publication separately, establish an actual immutable asset and both independent
pins, and commit its reviewed configuration with the reviewed workflow code.
The historical package applies only to its pinned version pair. New upstream
pairs require corresponding verified inputs; no automatic rebinding occurs.
P8 remains blocking-only and production promotion remains NOT_AUTHORIZED.
