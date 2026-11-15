# Isolated Registry transaction (Step 2C.2-B)

This is a library implementation and offline test harness, not a live Registry
writer. Ordinary registration calls return `BLOCKED`; there is no environment
switch, approval JSON input, or application option enabling simulated authority.
The subsequent CLI and separately reviewed Hosted adapter are documented in
`register_trusted_baseline_cli.md` and `hosted_registration.md`. Hosted deployment
configuration remains absent. Successful tests do not establish real Owner approval.

## Library interfaces

`baseline_registration_transaction.register(project, isolation_directory, *,
registry_key, proposed_entry, candidate_release,
expected_candidate_release_sha256, expected_reference_sha256,
expected_build_policy_sha256, expected_registry_sha256,
approval_policy_path, approval_policy_sha256, token=None)` returns a result dict.

Inputs reuse Step 2C.2-A and the existing independently pinned Owner policy. The
policy locates the authoritative Registry; it is read only. A dedicated directory
outside the project must already contain one ordinary file, `registry.json`,
whose bytes match the authoritative Registry and the expected old checksum.
Other than this file and owned transaction files, contents are rejected.

`recover(project, isolation_directory, *, transaction_id)` checks a journal
against its independently retained transaction ID. It can write completion
evidence only, never Registry contents or new authorization.

`owner_manual_baseline_approval.verify(..., registration_subject=None)` preserves
the existing five-input read-only behavior when omitted. Registration mode
requires the complete Step 2C.2-A subject and a sixth dispatch input,
`registration_subject_sha256`. Missing fields, mismatched identities, altered
Registry bytes or an incorrect dispatch digest fail closed. The output binds the
subject digest. That output is still evidence, not an execution credential.

## Execution trust boundary

The existing Owner adapter verifies the policy checksum, repository, current
default-branch commit, workflow path, in-progress dispatch run, attempt, actor,
authorization and exact Registry bytes against GitHub API evidence. It repeats
the API identity checks before returning. Registration repeats this verifier
immediately before committing, while holding the transaction lock.

Those checks cannot prove that an arbitrary local Python process runs inside
the trusted workflow. `_trusted_dispatch_context()` therefore always raises
`TRUSTED_WORKFLOW_EXECUTION_NOT_ESTABLISHED` in the shipped implementation. It
does not consult an enabling environment variable or accept a context argument.
Tests replace this private function, plus the HTTP/qualification dependencies,
with explicit synthetic fixtures. No trusted execution provider is fabricated.

Step 2C.3-B adds a separate reviewed Hosted entry using the same private
transaction core, with fixed workflow/code/policy provenance and repeated API
checks. The ordinary entry keeps its denying guard unchanged. Deployment pins
remain required and have not been configured; policy checks cannot bootstrap
their own authority. No protected-branch or independent-review guarantee is
inferred from GitHub Free repository ownership.

## Evidence lifecycle and historical identities

The lock covers Step 2C.2-A verification, qualification, duplicate checks,
authorization and the commit. Step 2C.2-A cleans its temporary files normally.
The transaction then downloads and restores the same independently pinned
Baseline into a second owned temporary directory. Existing restoration and
Owner preflight verify those actual files again. They remain available through
the final Owner verification and are removed on success or exceptions.

Each historical Registry reference is independently validated, downloaded and
restored. A Research Baseline's Candidate ID is read from verified
`upstream-candidate.json`; missing or conflicting identity evidence blocks the
operation. Merely adding `candidate_id` to a reference cannot replace package
verification. Duplicate keys, Baseline IDs, Candidate IDs, and conflicting
Corpus/source/build bindings are rejected. P2 is verified as a bootstrap
snapshot and is not assigned a Candidate ID. Historical downloads can be
expensive, but do not rebuild corpora or execute R2.

Qualification remains `NO_FRESH_REPLAY`. Existing sealed P4.1/R2 evidence is
verified; quality and Q1 limitations are not upgraded. The complete subject
retains those statuses, Release identities/hashes, source commits, Corpus,
Candidate and Baseline IDs, Parent anchor and expected old Registry hash.

## Filesystem transaction

The isolation directory is opened component by component with `O_NOFOLLOW`.
Registry, lock and audit files must be ordinary single-link files. Project
directories, symbolic links, hard links and authoritative Registry inode aliases
are rejected. File operations use directory descriptors. A stable independent
`.registration.lock` uses Linux `flock(LOCK_EX | LOCK_NB)` and is never deleted.
Concurrent cooperating writers receive `TRANSACTION_BUSY`.

Under the lock:

1. Compare the Registry bytes and old SHA-256 with authoritative state.
2. Reject unresolved PREPARED journals and corrupted completed journals.
3. Reconstruct evidence and verify authorization and historical identities.
4. Construct exactly one new Schema V2 entry, retaining all prior entries and
   top-level metadata. New JSON serialization may change whitespace/key order.
5. Persist `<transaction-id>.prepared.json`, then fsync the staged Registry.
6. Reverify Owner evidence, directory/lock/Registry inode identities, old bytes
   and the authoritative Registry immediately before commit.
7. **Commit at `os.replace(staged_registry, registry.json)`**, fsync the directory,
   verify the actual committed bytes, then persist `<transaction-id>.completed.json`.

Audit publication uses an exclusive link followed by directory synchronization;
existing records are never overwritten. The PREPARED payload includes the full
registration subject, Owner evidence, original Registry text, old/new SHA-256,
`NO_FRESH_REPLAY`, isolation scope and production restriction. Its canonical
SHA-256 is the transaction ID; the stored record includes that ID outside its
hashed payload. This avoids a circular self-hash. Completion binds to this ID
and the resulting Registry checksum.

Locks protect cooperating writers, not malicious equal-privilege processes.
Atomic visibility and crash durability are distinct: file and directory fsync
are requested, but hardware/filesystem guarantees still apply. Two separate
files are not claimed to form one atomic update.

## Results and recovery

| Situation | Result |
| --- | --- |
| Validation/authentication failure before commit | `BLOCKED`, Registry unchanged by this operation |
| Isolated commit and audit completed | `COMPLETED`, `ISOLATED_COPY_UPDATED` |
| Commit occurred but later validation/fsync/audit failed | `COMMITTED_WITH_ERROR`, actual Registry hash reported when readable |
| Recovery finds original exact Registry bytes | `NOT_COMMITTED`, no automatic retry or Registry write |
| Recovery finds exact intended new bytes | Verify journal/subject/entry binding and complete audit only |
| Recovery finds a third state | `CONFLICT`, leave files untouched |
| Missing, malformed, mismatched or corrupted journal | `BLOCKED` |

Recovery validates the independent transaction ID, subject digest, old bytes,
exact single-entry transformation and existing completion record. Repeated
successful recovery leaves the completion record unchanged. Recovery confirms
observed committed bytes; it does not reissue the historical approval or prove
who wrote those bytes. Journals are protected local traceability evidence, not
signatures against a malicious local user.

A noncommitted PREPARED journal remains unresolved and blocks another
registration in that workspace. Start a new explicitly isolated attempt with
fresh authorization rather than silently retrying it. Ordinary failures clean
up owned staging and evidence files. A killed process may leave orphan temporary
files; they are never automatically treated as committed evidence.

All outcomes retain `production_promotion: NOT_AUTHORIZED`. No P8 approval,
production pointer switch, Hosted registration, or live Registry update occurs.

## Offline tests and remaining work

Run using the existing dependency environment:

```bash
PYTHONHASHSEED=0 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=tests \
tools/treesitter-chunker/.venv/bin/python -m unittest \
  test_baseline_registration_transaction test_owner_manual_baseline_approval \
  test_github_baseline_approval test_published_candidate_verification \
  test_trusted_baseline_registration test_candidate_release_archive \
  test_private_release_transport test_parent_r2_anchor
```

Tests include real Step 2C.2-A transport/extraction and Owner adapter composition
against mocked APIs, and fault injection before/after the commit point. Successful
qualification/authority fixtures remain synthetic; no genuine C1/C2 execution,
Owner approval, Release download or publication is performed. Existing miniature
Parent anchor tests exercise their original verifier independently.

Subsequent CLI and Hosted implementation exist; remaining work includes actual
independent deployment configuration/assets and genuine Hosted acceptance, then
a separately authorized live-Registry update. This library never automatically
selects the next Parent. See the later documents for current integration scope.
