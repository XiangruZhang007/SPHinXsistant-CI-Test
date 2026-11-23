# Current-run Q1 and Hosted report preservation (D3.9-F)

This local proposal is not deployed. No build, remote PR, archive write or workflow
execution is authorized by its presence. Existing manual Owner Bot gates remain
unchanged. No App credentials or new service is needed.

## Q1 integration

Schema-2 `schema2_workflow.run_local()` calls diagnostics with `automatic=True`
after authorized Candidate/Full construction and evaluation/replay have completed.
With no explicit Q1 transport inputs, `q1_current_inputs.prepare()` writes a new
`q1-auto-inputs.json` bound to that run's Parent, upstream Candidate, source states,
Corpus/documentation hashes, benchmark, build fingerprint and original row bytes.
It cross-checks mandatory caller bindings and calls the unchanged Q1 deep loader.
Derived digests are reproducibility records, not independent human approval.
The existing diagnostics regenerates and writes a relocatable `q1-inputs.json`,
Q1 report, status and attribution before the outer run is sealed.

Explicit reviewed Q1 transport remains supported. `prepare_q1_inputs.py` remains a
transport restorer, not the current-run builder. A malformed explicit input is
not silently replaced by automatic inputs. Missing/invalid current-run material
produces explicit Q1_NOT_QUALIFIED_FOR_VERSION_PAIR with reason and uncertain
attribution, never QUALIFIED. This diagnostic failure does not override mandatory
build/evaluation gates or grant approval. UNRESOLVED/AMBIGUOUS/MODIFIED results are
valid diagnostic outcomes; they are not successful evidence equivalence.

Automatic preparation currently supports the existing genuine upstream Candidate
format accepted by Q1 load_inputs. The separate genuine-continuous-candidate-v2/v3
format uses different metadata and deliberately remains on its historical
unqualified path. No new projection or authorization bypass was added. The existing loader also requires the supported P2 snapshot Parent contract; unsupported
Parent formats remain explicitly unqualified. Supporting other format pairs requires a reviewed provenance adapter; this proposal does not
claim all Continuous entry points now run automatic Q1.

Frozen benchmarks, R2 scores, Q1 mapper, historical pins, policy/Registry/Parent
identities and original scientific status remain unchanged. Schema-2 execution
contract identities change and need separate review; no deployment pin is updated.

## Existing D3.9-E evidence

The original downloaded ZIP/report already exists outside Git. The proposed
`docs/evidence/hosted/d3-9-e-45144294526-attempt-1/` retains the exact report bytes
and deterministic manifest/README, verified from the original Run/Artifact receipt.
Original ZIP SHA e0896080cbb5af377f4b4b7738cf0c64c90c8c8584501aa22edf564290e39795.
Original report SHA 93bb8bd495fea3d30abc29eccd5b43e43151efd48f592d484717f86acaefbb6c.
No new Gradio run or asset publication is needed to prepare this historical archive.

## Automatic evidence PR

`ci_v2_hosted_evidence_archive.yml` uses workflow_run(completed) for the exact
manual Candidate workflow on the default branch. Validation has only contents:read
and actions:read. It authenticates source repository/Owner/workflow/attempt,
trusted ancestor revision, reviewed source bytes/config, actual jobs and artifact
attribution/digest, bounded ZIP and report identity/isolation/scope. Failure receipts
are preserved as BLOCKED, never PASS. No code in a downloaded artifact executes.
Only reviewed same-repository source implementations are eligible; a future change
of consumer implementations must be reviewed together with archive compatibility.

The separate write job refetches/revalidates and requires the read job's exact
manifest SHA. Its contents:write/actions:read/pull-requests:write token creates only
three evidence blobs, one commit and proposal branch, then a Bot PR. It cannot
merge or approve. It does not use Audit Writer credentials. The existing
ci_v2_bot_proposal.yml remains Owner-manual-only; no gate is weakened to automate
this distinct archive task. Trusted code is checked out at github.sha and matched
to its tracked checkout before privileged operations. No untrusted PR code runs.

Each mutation is attempted once. Ambiguity stops without retry/delete/overwrite;
partially created refs or PRs require read-only reconciliation and separate recovery
review. Existing identical committed evidence or an identical open Bot PR is
recognized; conflicts fail. After artifact expiry, only an identical archive already
present in the trusted Git checkout may be reused, with Run/API digest revalidation;
no original ZIP is fabricated. Unmerged or missing expired evidence fails closed. A PR only preserves evidence after human review and
merge. There is no claim of guaranteed durable remote preservation before merge.
The default-branch ruleset requires a human approving review. docs/evidence is not
currently CODEOWNERS-covered; no new CODEOWNERS policy is introduced. The Owner
reviews as required by the branch rule and single-owner maintenance practice.

Git archival PRs use existing protected review and suit small reports. Release
archival would introduce a second publication authorization/asset lifecycle for
reports; it is unnecessary here. No redundant Release archival is implemented.
The Candidate Release continues to preserve Candidate bytes, not these reports.

Temporary Candidate verification Artifact retention changes from 14 to 30 days
for future artifacts only. The actual repository GET reports days=90 and maximum
allowed=90. Original Artifact 14803332944 still expires 2026-12-07T09:09:57Z.
Reference: https://docs.github.com/en/rest/actions/permissions#get-artifact-and-log-retention-settings-for-a-repository

## Separate Hosted validation plan

1. Review local patch and exact new contract digests. Separately authorize a
   protected Bot PR; require human approval/merge and verify the actual deployed SHA.
2. Review activation of the new workflow_run automation: deployment enables future
   automatic archive branches/PRs for eligible source runs. This is distinct from
   today's local-only authority. No remote branch or PR has been created in D3.9-F.
3. Validate Q1 on the existing exact retained pair through offline reproduction
   first. A future separately authorized genuine Schema-2 research build will test
   automatic generation on Hosted; current REGISTRATION_ONLY and build gates remain
   effective. Do not dispatch that build until its actual build authority exists.
4. If a genuine test of the new automatic archiver is separately authorized, one new
   Candidate loading dispatch at the newly reviewed deployment revision and exact
   current loading config pin triggers the archival workflow. It is a necessary
   new-feature test, not a rerun merely to save D3.9-E. Inspect source and downstream
   Run/attempt, archive Artifact bytes, Bot author, exactly three added files and
   pre-approval blocking. No automatic approval or merge.
5. Q1 build diagnostics and Gradio report archival are separate acceptance claims.
   Do not rewrite old scientific runs or verification.json to combine them. A genuine
   Hosted Q1 build/archival validation has not been performed by local fixture tests.

Preserve QUALITY_REVIEW_REQUIRED, original Q1_NOT_QUALIFIED_FOR_VERSION_PAIR,
P8_BLOCKED, REGISTRATION_ONLY and PRODUCTION_NOT_AUTHORIZED.
