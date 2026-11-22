# Exact research Candidate Hosted consumer (D3.9-A / D3.9-D1)

This is a read-only consumer for Candidate
`sha256-76105a0d7e33375966aa09ab0bcf00f035055c0c0ffb96f5f18d6fbca63813b8`,
corpus SHA-256
`8d989e543a2a25d779ad21fe9893848b65169c8502c0119c324d42536d4ca7e2`,
12,123 records. It does not replace the existing approved-Baseline consumer,
selector, Registry, Parent authorization or P8 gate.

D3.9-C3 published the exact immutable research assets. D3.9-D1 adds a local
proposal for a manual workflow and its exact input file; neither is deployed or
authorized for execution by its presence. Protected code deployment and a real
Hosted dispatch still require separate human decisions.

## Interfaces and trust

`src.research_candidate_consumer.consume(project, review_path,
expected_review_sha256, output, app_python, *, authorized_review_sha256=None,
purpose=None)` requires `purpose=RESEARCH_LOADING_ONLY` and a separate retained
human loading decision bound to the exact review bytes. The trusted caller
supplies that decision's digest as `authorized_review_sha256`; a missing or
mismatched digest fails before downloading. A digest is caller trust, not a
signature, human-identity proof or transferable approval token. Never obtain
these independent pins from the downloaded package or an untrusted sidecar.
A transport configuration's existence or a successful hash is not permission.

The exact subject pins are fixed in `SUBJECT`, including Candidate, Corpus,
Parent, both source states/upstream pairs, build/orchestration/build-policy
fingerprints and the original run checksum manifest. This is intentionally not
a general Candidate approval mechanism. No Baseline or P4.1 identity is accepted.

The nonoperative input contract has exactly six top-level fields:

- `schema_version`: integer `1`.
- `kind`: `RESEARCH_CANDIDATE_LOADING_INPUTS`.
- `purpose`: `RESEARCH_LOADING_ONLY`.
- `subject`: exactly `SUBJECT`, including every original identifier prefix.
- `archive` and `notices`: each exactly `{sha256, storage}`.

Both storage objects use the existing `GITHUB_PRIVATE_RELEASE_ASSET` contract
(the historical enum also supports the explicitly permitted public research
repository). They contain exactly `kind`, `repository`, `repository_id`,
`release_id`, `asset_id`, `tag`, `asset_name`, `asset_size`, `immutable_required`.
Both must belong to repository ID 1455203884, the same immutable Release/tag,
with distinct Asset IDs/names. The reviewed local proposal is now
`configs/ci_v2_research_candidate_loading.json`, raw SHA-256
`c5a060a2d4e2fb3232ad0dbfa9c63b040277406190972099306616fdf8f4ed83`.
Its independent execution authorization remains pending. Metadata-only offline
tests supply a synthetic caller pin; they do not record a human decision.

Published Release `454787335`, tag `ci-v2-research-candidate-76105a0d`, targets
`25215499512571b6495e302f68e00a2bbefc7f13`. Its assets are:

| Asset | ID | Bytes | SHA-256 |
|---|---:|---:|---|
| research-candidate-76105a0d-complete-run.tar.gz | 780676875 | 54568087 | 95397523de2bd6c70813604fc828430fd9e6494da14696f4fa486af118b152c4 |
| research-candidate-76105a0d-notices.zip | 780683404 | 12757 | dbfc7fba58f65616f5e00e27804ff6943d7f85174320ba5307169ed86c5196eb |

The Release target is publication provenance, not the future implementation
revision. No new locator fields or historical source identities were invented.
The downloader still requires a same-repository authenticated token and verifies
repository, immutable published Release, membership, sizes and complete bytes.
That token never enters the application process.

The trusted CLI is `scripts/check_hosted_candidate_gradio.py`, accepting
`--review`, `--expected-review-sha256`, `--authorized-review-sha256`, `--purpose`,
`--output`, `--app-python`, `--expected-implementation-revision` and optional
`--isolation-preflight`. It requires the same exact Owner-dispatched context
as D3.6: repository/name/ID, protected default branch, attempt 1, and matching
checkout / workflow / run revision, additionally equal to the separately supplied
reviewed implementation revision. The exact Candidate workflow path/ref is
required. It also compares the proposed config's bytes
against the Git-tracked `configs/` file at that exact revision. These checks use
the trusted runner's context; setting environment variables locally does not
prove a genuine Actions execution. The proposed workflow binds these
pins and the retained authorization; it must not accept arbitrary uploaded JSON
as human authority. There is no local CLI override of the Hosted checks.

## Original evidence and existing checks

The archive is the existing `ci_v2_research.package_candidate` **complete run**
format, including original Parent, Candidate, Full, benchmark, quality/raw rows,
recorded replay, policy and seals. The bare `candidate/` directory is insufficient.
No packaging operation occurs during consumption.

Before downloading: require an absolute, existing, executable application Python
path. A standard venv Python symlink is allowed; this check does not execute the
interpreter or import application code outside isolation.

Before extracting: verify the notices ZIP's independent bytes, membership,
subject and transport binding; verify compressed archive bytes, regular members,
canonical paths, uniqueness, prefix collisions, size/count bounds and modes.
Extraction is exclusive into an owned temporary directory, without `extractall`,
links, executable hooks or overwriting an existing destination. Git executable
semantics are preserved; permissions are normalized to 644/755. Stable owned
inputs are assumed; this is not protection against a hostile same-UID process.

`_BoundedTarInfo` checks extension sizes before Python's parser reads their
payloads: at most 64 KiB per PAX/GNU long-name/long-link header, 8 MiB aggregate
metadata and 20,000 metadata headers. These are frozen Python 3.12 TarInfo hook
overrides. GNU sparse parsing is rejected before its additional metadata reader;
the contract accepts regular files only. Native PAX format is preserved; the
published bytes are unchanged (their largest PAX payload is 220 bytes). Negative
tests use oversized headers with no payload and prove that the standard metadata
parser and extraction destination are never reached. Normal PAX long paths and
the actual published transport remain supported.

`verify_run` reuses `_read_sealed_run`, `verify_snapshot`,
`upstream_provenance.verify` and `compare_full`, and requires actual
`PARITY_PASS` equal to both sealed reports. It reuses P8's archived-binding
inspection **while requiring P8 to remain BLOCKED/BLOCKING_ONLY**. Inspecting
bindings does not make the Candidate eligible for activation.

Frozen result consistency uses existing `frozen_implementation` and `rescore`
on archived rows and compares the recorded Candidate/Full replay rows. It never
calls `replay`, retrieval search, construction, Q1 generation or
`schema2_workflow.verify_run` (the latter would execute fresh replay).
The original P2 anchor is inspected with `fresh_replay=False`; the honest status
is `PINNED_ANCHOR_INSPECTED / NO_FRESH_REPLAY`, not fresh R2 qualification.

## Mandatory Candidate-specific notices

The old approved-Baseline notices ZIP is a different subject/transport and is
rejected. A separately prepared and reviewed ZIP must contain exactly:

- `README.md`: exact scope text returned by `notices_readme(review)`.
- `source-and-license-mapping.json`.
- `licenses/<name>`: the seven existing reviewed full texts with the exact
  hashes in `local_candidate_transport.LICENSES`.

No new legal permission or automatic completeness conclusion follows from those
seven texts. The future exact package/publication review must confirm their
applicability and any expanded disclosure scope.

The JSON fields are exactly `schema_version: 1`,
`kind: RESEARCH_CANDIDATE_NOTICES`, `subject: SUBJECT`, `archive_sha256`,
`license_texts`, `source_license_bindings`, `project_license_bindings`,
`license_tree_proofs`.

`license_texts` maps each filename to `{sha256, size}`.
`source_license_bindings` maps the eight exact paths in `VENDOR_NOTICES` to
`{license, members}`; `members` hashes all three corresponding original files
under `parent/sources/`, `candidate/input/repos/`, and `full/sources/`.
All entries and hashes are checked against the actual extracted run.

`project_license_bindings` contains exactly six distinct
`{phase, repository, path, revision, license}` entries: `base` and `target`,
SPHinXsys `LICENSE`, SPHinXsim `LICENSE` and
`sphinxsim/sphinxsys/LICENSE`. Revisions must equal the exact subject; filenames,
license text hashes and the two known upstream Git blob identities are checked.

Selected-source Git proofs do not necessarily include all license-directory
objects. `license_tree_proofs` is a closed `{base, target}` object, each with
`{SPHinXsys, SPHinXsim}` dictionaries of missing tree OID to base64 raw tree.
Every supplemental tree is hash-checked and traversed from the already verified
commit root. Existing trees cannot be replaced, and unused/unexpected objects
are rejected. These supplemental license proofs belong in the new notices ZIP,
not in modified historical Candidate or Git proof files. No Git fetch occurs.

## Application boundary

The consumer calls D3.6's existing `isolated_python`: privileged network namespace
creation followed by non-root execution, empty supplementary groups, all
capabilities dropped, `no_new_privs`, and a sanitized environment. The guard
verifies a distinct namespace with only `lo` and no external route **before**
application imports. Namespace or privilege-drop failures remain blocking.

The fresh process sets `SPHINX_CORPUS_PATH` before importing the unchanged
`corpus_update_integration._gradio_check`. This invokes the actual application,
checks complete Retriever record equality and shared callback assistant, executes
one retained D3.7 migration query with real RetrievalV1/BM25, and closes the app.
The outer consumer additionally verifies every returned chunk/path belongs to
the exact corpus and the expected new-content chunk is returned. No HTTP server,
answer callback, provider credential, real LLM call or production pointer exists.
Only a successful complete check writes a success receipt; failure cleans owned
work. The CLI may write a sanitized BLOCKED report to a new external output
directory, never raw errors, existing files or the checkout. The original run is
rehashed after application use.

## Manual Hosted workflow proposal

`.github/workflows/ci_v2_candidate_gradio_loading.yml` uses only
`workflow_dispatch`, read-only Contents permission and the existing Owner,
repository, default-branch and attempt-1 gate. Actions are pinned to the same
reviewed full SHAs as D3.6. It reuses ARM64 Python 3.12.3, frozen parser setup,
`configs/gradio_research_requirements.txt` and the unchanged D3.6 isolation
launcher. No Writer Environment, App credentials or provider keys are used.

The two required dispatch inputs have no defaults:

- `expected_implementation_revision`: the actual reviewed deployed commit,
  determined only after protected PR integration; no future SHA is fabricated.
- `authorized_review_sha256`: the separately human-authorized exact input digest
  above. The workflow supplies the fixed expected digest independently; knowing
  the digest or publication authorization alone is not loading authorization.

The preflight calls the same Candidate CLI with `--isolation-preflight`, before
the token-bearing consumption step. It checks the genuine tracked config and
authorization pin, then performs the existing OS isolation probe without loading
the Corpus. Full consumption downloads both assets using a step-scoped
`github.token`, validates the original scientific evidence without replay, and
uses the real Gradio/BM25 chain. The child process cannot inherit that token.
Only external `verification.json` is uploaded as a sanitized run-specific
Artifact, including actual Corpus/retrieval results on success. No package or
scientific evidence is published by this workflow.

Current configuration-file existence is not Git-tracked eligibility: the CLI's
`git show` check will reject it until these reviewed changes are committed,
approved through CODEOWNERS and merged into the protected default branch. Offline
mocked checkout tests are not a genuine Hosted tracked-path result.

## Evidence classification and remaining work

The report retains `LOCAL_RESEARCH_EXECUTION / HOSTED_NOT_RUN` for the original
build and `NO_FRESH_REPLAY` for scientific inspection. A future genuine Hosted
loading result is a separate observation. It retains `QUALITY_REVIEW_REQUIRED`,
original `Q1_NOT_QUALIFIED_FOR_VERSION_PAIR`, `P8_BLOCKED`, `REGISTRATION_ONLY`,
`PRODUCTION_NOT_AUTHORIZED`. The separately verified Q1 supplement remains
separate diagnostic evidence and is not regenerated here.

Next: review the local workflow/config/hardening delta; separately authorize a
protected Bot PR checkpoint/push/creation; obtain Owner CODEOWNERS approval and
merge. Verify the actual reviewed deployment SHA, tracked input raw bytes and
digest, and then separately authorize one Owner dispatch with both exact inputs.
Do not dispatch the old approved-Baseline workflow with this Candidate. No new
Parent/Writer governance or Candidate reapproval is required for this bounded
research-loading purpose.
