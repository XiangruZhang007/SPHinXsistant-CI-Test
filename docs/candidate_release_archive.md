# CI V2 Candidate Release Archiving

The manual workflow can optionally preserve a successfully verified research
Candidate in a private, immutable GitHub Release. This is archival only. It
does not approve retrieval quality, qualify a Trusted Parent, register a
baseline, or authorize production use.

## Workflow behavior

The `archive_candidate` `workflow_dispatch` input defaults to `false`. With the
default value, the existing Candidate build and 30-day Actions Artifact behavior
are unchanged. When explicitly enabled, a separate job runs only after the
Candidate job succeeds and only for `ci-upstream-refresh`, the configured
default branch. The Candidate job retains `contents: read`; only the
archive job receives `contents: write` and `actions: read`.

The archive job selects the current run's exact Actions Artifact ID. It checks
the authenticated GitHub API's repository, workflow attempt, commit, Artifact
identity, size, and digest bindings, then validates the sealed run inventory,
Candidate archive bytes, full-build parity, and recorded retrieval replay
verification. The pinned download action is configured to fail on an Artifact
digest mismatch. The upload action's raw 64-character digest is normalized to
the `sha256:<hex>` representation returned by the REST API before comparing
them. It does not rebuild a Corpus or rerun R2.

The Release contains three assets:

- `candidate.tar.gz`: the exact Candidate package from the Actions Artifact.
- `research-evidence.tar.gz`: deterministic archive of `plan.json` and the
  complete sealed `run/` tree, including parent binding, source revisions,
  evaluation, parity, replay, quality, Q1, and checksums.
- `release-manifest.json`: Candidate, parent, run, source, quality, and
  authorization bindings plus SHA-256 and size for the two payload assets.

The manifest cannot include its own digest without a self-reference. Its digest
and the digest of every uploaded asset are checked against GitHub Release Asset
metadata when available; if an asset digest is absent, the asset is downloaded
through the existing credential-safe Release transport and hashed. The final
workflow receipt records the manifest's own digest and all GitHub asset IDs.

The Release tag is unique to run ID, attempt, and Candidate ID. Existing tags
or Releases are rejected. The publisher creates a draft, uploads and verifies
all assets, checks the draft inventory, and only then publishes. A partial
upload leaves the newly created draft unpublished; it never deletes or alters
an existing Release. A retry uses a new attempt-specific tag. The repository
owner must keep Release immutability enabled; after publish, the script requires
GitHub's API to report `immutable: true` before returning success.

## Status boundaries

The manifest separately records:

- `technical_verification: PASS` only if the sealed existing technical evidence
  reports successful structural parity and independent retrieval replay.
- The exact recorded retrieval quality and Q1 statuses, including
  `QUALITY_REVIEW_REQUIRED` and `Q1_NOT_QUALIFIED_FOR_VERSION_PAIR` when present.
- Pending research review separately from GitHub workflow success.
- `research_baseline_approved: false`, `trusted_parent_registered: false`, and
  `production_promotion: NOT_AUTHORIZED`.

No code path writes to the Trusted Baseline Registry. The Release is not accepted
as a Parent automatically.

## Local verification

The focused tests use synthetic evidence and mocked API responses only:

```bash
python -m unittest discover -s tests -p 'test_candidate_release_archive.py'
```

They do not authenticate, publish, or contact GitHub. A real publication is not
part of local validation. Before a controlled Hosted publication test, confirm
that the private repository's Release immutability setting is enabled and that
repository Actions settings permit the archive job's `GITHUB_TOKEN` to create
Releases. The workflow opt-in remains false by default.
