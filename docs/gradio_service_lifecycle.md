# Isolated Gradio HTTP lifecycle MVP

`src/gradio_service_lifecycle.py` owns real Gradio child processes in a temporary
P9 workspace. It is a synthetic local research demonstration, not a promotion,
deployment, production restart or arbitrary-process management interface.

## Entry and isolation

Use an existing Python environment with the project's Gradio dependencies:

```bash
/home/zhang/Projects/SPHinX_AI_Assistant/tools/treesitter-chunker/.venv/bin/python \
  -B -m src.gradio_service_lifecycle
```

The only optional argument is `--port` (1024–65535). Without it the OS selects
an available loopback port, then all replacements use that same port. Occupied
ports fail safely; no unrelated process is contacted for control or terminated.
There is no external Corpus, root, PID, approval or force option.

The controller generates only the existing two P9 synthetic templates (`v1`,
`v2`), pins their bytes before writing, registers them with P9.1, and reuses
P9.2 selection. `amberanchor` and `cobaltanchor` distinguish their evidence.
It verifies metadata, checksum, full record schema/content and count before
starting a process, and again after HTTP verification. Corpus/metadata files
are never overwritten. No real CI Candidate is accepted by this interface.
This is not an OS sandbox against an operator modifying Python internals.

## Process and verification

The owned child calls the existing CI `build_app().launch(...)` with an explicit
127.0.0.1 address, port, share=False and no browser/SSR startup. The application
source and UI are unchanged. LLM environment settings are removed, telemetry
is disabled, temporary caches are isolated, and a child audit hook rejects
non-loopback network/DNS operations. LLM client construction is also rejected.

The child introspects the assistant captured by the actual `ask` callbacks.
It verifies that their real R1 Retriever uses the expected path and complete
synthetic records. A private atomic readiness record binds PID, fresh launch
nonce, Gradio app_id, SHA-256, count and callback identities. The parent checks
that the owned child is alive and the HTTP `/config` app_id matches that record.
An unrelated page returning HTTP 200 is insufficient.

Verification submits the question through the original HTTP request callback
and queued `ask` callback, reads the actual completion event, checks sources,
line references and version-specific evidence, and confirms callback execution
with no LLM client or external networking attempts. The expected missing-key
warning is recorded as retrieval-only success; no model answer is invented.
Feedback and Submission callbacks are not invoked. Browser rendering is not tested.

## Update and recovery

The entire transaction holds the existing process-owned workspace guard.
Invalid B inputs are rejected before A is stopped. Valid updates stop/reap A,
select B, start a new child, and verify HTTP plus actual Retriever identity before
publishing B as the verified running version. This is restart-based switching
with downtime, not hot reload or zero-downtime delivery.

If B selection/start/verification fails after A stops, the controller first
stops/reaps any owned B child, then selects, starts and verifies the last good A.
It reports ROLLBACK_SUCCESS only after all checks pass. That target is independent
of the symlink target at update entry. COMMITTED_WITH_ERROR is handled as a
possible changed selection, followed by explicit restoration and verification.
If restoration fails, no running/verified A is claimed; remaining owned children
are stopped and the actual selection/process state is reported.

State separates `selected_version`, `running_version`, and `last_verified_version`.
`service_verified` means an alive owned child with successful previous verification;
it is not a continuous health monitor. A subsequent unexpected exit clears reported
running availability when state is inspected.

Startup, requests and shutdown have finite deadlines. Shutdown uses only owned
Popen handles: SIGTERM/graceful close, bounded wait, then kill and bounded reap if
needed. Stop failure prevents replacement startup. Children have a 180-second hard
research-session lifetime as a safeguard after parent loss. Normal context exit
reaps children and removes the workspace. SIGKILL/power loss cannot guarantee
immediate cleanup, and failed OS termination is reported rather than hidden.

The CLI demo reports success only if A→B→A all verify and temporary cleanup succeeds.
Exit 0 denotes PASS_RETRIEVAL_ONLY; failures return nonzero. Fault injection belongs
only in isolated tests; it is not an exposed deployment or authorization feature.

## Unchanged boundaries

P8, Candidate Promotion Policy, P9, Q1, Retriever and stable Gradio files are unchanged.
No accepting real promotion path is wired to this controller. The historical
Candidate remains BLOCKED and cannot be provided as lifecycle input. A successful
synthetic service demonstration neither approves its quality nor authorizes a release.
Real authorized promotion/service integration remains separate future work.
