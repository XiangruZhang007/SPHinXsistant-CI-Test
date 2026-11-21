# Read-only Hosted research loading

`ci_v2_gradio_loading.yml` is a manual Owner-triggered consumer of one fixed,
already approved research Baseline. It does not build, publish, promote, select a
Continuous construction Parent, start HTTP, or call an LLM. It requires the exact
default-branch dispatch checkout and run attempt 1. Runtime failure is blocking;
there is no alternative Corpus or offline fallback.

## Pinned input

Repository `XiangruZhang007/SPHinXsistant-CI-Test` (1455203884), immutable Release
450526546, tag `ci-v2-official-research-parent-9519233d`, target commit
`5edcb60a026cfaf5a4326876a49d51d22292304f`:

| Asset | ID | SHA-256 |
| --- | --- | --- |
| official-research-parent-9519233d.tar.gz | 764908384 | eccea7dbf5d51f4eff97c45e8fbe781a54ae7c4b6e582999e1a81c4c3a6e9b5c |
| official-parent-r2-results.json | 764908636 | eecd520a498e95299ce9a8287bbfc83afa1a2829331ec690eccd559ebfcea6c3 |
| official-parent-9519233d-license-notices-companion.proposed.zip | 764908713 | d05bb4049c5baa7aab766478b4efd9c967319eeb599397ff5e45defbcf73cfdd |

The authoritative Registry bytes and canonical Reference v3 are independently
pinned in `scripts/check_hosted_gradio_loading.py`. Existing `trusted_snapshot`
transport verifies repository/immutable Release/asset membership, sizes and full
downloaded bytes. Mandatory notices are verified before restoration. Existing
package and P4.1 verifiers inspect the sealed evidence. The original Candidate R2
anchor is checked with `fresh_replay=False`: **NO_FRESH_REPLAY**, no new R2 results.

The exact Corpus has 11,637 records, 25,392,117 bytes and SHA-256
`280c1577e2821584e72219324513a7e290b53b0022f913f71545a3d40d45fe83`.
D3.5 `verify_gradio_loading()` binds this identity to the actual application's
Retriever and callback assistant, executes one previously verified BM25 query,
and closes the application. All selected records must equal the reviewed Corpus;
the expected source chunk must rank first. This is runtime compatibility, not a
new retrieval quality evaluation or genuine LLM answer acceptance.

## Runtime and isolation

The package verifier preserves Python 3.12.3/ARM64, the frozen parser requirements
and chunker revision. A separate application venv uses
`configs/gradio_research_requirements.txt`, derived from the actually tested
D3.2-E environment snapshot (not an existing official project lockfile). Both
are installed from PyPI; the new application file pins the complete resolved
distribution set. Clean-runner wheel availability and compatibility still need
the first genuine Hosted run; local tests reuse installed environments.

Only `contents: read` is granted. The built-in token is passed only to the
transport step; neither Writer secrets nor Environment credentials are used.
Before application imports, a fresh credential-free child enters a user/network
namespace containing only loopback. No HTTP listener is started. If the runner
cannot establish this boundary, the job fails closed. The inherited D3.5 helper
also denies Python network calls and unauthorized subprocesses. Repository name
and numeric ID are passed as noncredential locator scope only, not Owner proof.

Temporary package files, copied notices and selection directories are cleaned.
The uploaded attempt-specific artifact contains only `verification.json`, never
the Corpus, package, raw headers, signed URLs or credentials. Consumer failures
emit a sanitized BLOCKED receipt; setup failures may have no consumer receipt
and must be diagnosed from the actual job steps.

## Deployment boundary

Submit these changes through the existing protected Bot PR/CODEOWNERS path after
separate authorization. After human review and merge, separately authorize one
manual dispatch at the reviewed deployment SHA. Verify the actual Run, runtime
setup, downloaded bytes, report and artifact attribution before claiming Hosted
acceptance. Local retained-asset simulation substitutes only transport with
verified original bytes; it is not a fresh remote download or Hosted execution.

Keep `REGISTRATION_ONLY`, `QUALITY_REVIEW_REQUIRED`,
`Q1_NOT_QUALIFIED_FOR_VERSION_PAIR`, `P8_BLOCKED` and
`PRODUCTION_NOT_AUTHORIZED`. No Writer preparation or authority transition is
part of this workflow.
