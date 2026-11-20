# Isolated reviewed research Corpus selection

`research_corpus_selection.verify(review, corpus, baseline_root, notices_path=...)`
checks a caller's independently reviewed Registry raw-file pin, reference,
Baseline manifest, Candidate/Baseline metadata and exact JSONL bytes/count/fields.
Reference v3 requires the existing notices verifier. This consumes previously
qualified evidence; it does not rerun P4.1, R2 or establish new approval. Pins
provided by an untrusted artifact do not establish trust. The caller separately
needs authorization for an isolated research session.

`select(...)` is a context manager reusing existing P9 `TestWorkspace` storage
and selection. It verifies again, copies bytes with the existing checksum gate,
retains and verifies notices beside the stored version, and cleans up on exit.
Its receipt is evidence, not an authorization token. The original artifacts and
application default remain unchanged. It never invokes the application itself.

Within the context, `selected.environment()` provides `SPHINX_CORPUS_PATH` for
a **fresh** isolated application subprocess. It rejects an already imported app
in the calling process and rechecks selected bytes. The subprocess must verify
its actual loaded records. The caller owns network/credential/cache isolation,
bounded process shutdown, and must wait for the process before exiting context.
This is process reinitialization, not hot reload or production activation.

Only `RESEARCH_LOADING_ONLY` is accepted. Production, construction, publication
and other purposes are denied; actual build authority continues to be enforced
by existing Registry consumers such as `schema2_workflow.plan()`. Registration
does not grant build or automatic Parent eligibility. P8 and quality/Q1 limits
remain unchanged. No Registry, Owner policy, deployment or production pointer is
written. This helper is not a replacement version controller, transport adapter,
Gradio app or approval mechanism.

Focused offline tests (synthetic evidence; no application/LLM/scientific run):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p test_research_corpus_selection.py
```

Real current-Corpus selection acceptance is separately authorized and evidenced
outside the repository; fixture tests do not establish scientific qualification.
