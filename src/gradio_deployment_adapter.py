"""Local deployment preparation; no operational production activation entry point.

Reuse immutable storage and D3.6's actual OS-isolated Gradio verifier. The small
private replacement kernel models blue/green activation/rollback with a trusted
server driver. No driver is loaded from JSON, a Workflow input, shell command or
plugin. The real server driver and reviewed routing configuration are pending;
synthetic drivers appear only in tests and cannot authorize production changes.
"""
from pathlib import Path
import tempfile

from . import versioned_corpus_storage as storage


def _need(ok, reason):
    if not ok: raise ValueError(reason)


def stage_and_verify(project, root, version, source, *, corpus_sha256, record_count,
                     app_python, queries):
    """Copy exact bytes once, then use the real app in a fresh isolated process.

    Artifact/policy authorization must be checked upstream; this explicit local
    storage/research verification never supplies it. Failed verification keeps
    the immutable stored version for diagnosis and never touches an active one.
    No HTTP listener, LLM request, source edit or production process is started.
    """
    _need(type(record_count) is int and record_count > 0, 'INVALID_EXPECTED_RECORD_COUNT')
    app_python = Path(app_python)
    _need(app_python.is_absolute() and app_python.is_file(), 'APPLICATION_INTERPRETER_REQUIRED')
    _need(isinstance(queries, (list,tuple)) and 1 <= len(queries) <= 3
          and all(isinstance(q,str) and 0 < len(q) <= 2048 for q in queries), 'INVALID_BOUNDED_QUERIES')
    project = Path(project).resolve()
    _need(not Path(root).resolve().is_relative_to(project), 'EXTERNAL_STORAGE_REQUIRED')
    stored = storage.register(root, version, source, corpus_sha256)
    selected = Path(root).resolve() / version / 'corpus.jsonl'
    # Importing the launcher does not import the application or start a service.
    # It owns the sudo/unshare/setpriv OS boundary; never replace it with an
    # audit-hook-only or socket-monkeypatch-only fallback.
    from scripts.check_hosted_gradio_loading import isolated_python
    code = ("import sys,pathlib,os\nsys.path.insert(0,sys.argv[4])\n"
        "os.environ['SPHINX_CORPUS_PATH']=sys.argv[5]\n"
        "from src.corpus_update_integration import _gradio_check\n"
        "result=_gradio_check(pathlib.Path(sys.argv[5]),sys.argv[6],json.loads(sys.argv[7]))\n"
        "print(json.dumps({'isolation':isolation,'application':result}))\n")
    import json
    with tempfile.TemporaryDirectory(prefix='gradio-staging-') as work:
        result = isolated_python(app_python, Path(work), code,
            [project, selected, corpus_sha256, json.dumps(list(queries))])
    application = result['application']
    _need(application['records'] == record_count, 'LOADED_RECORD_COUNT_MISMATCH')
    _need(application['sha256'] == corpus_sha256 and application['corpus_path'] == str(selected)
          and all(application.get(k) is True for k in
                  ('complete_records_equal','callbacks_share_assistant','application_closed'))
          and application['retriever_class'] == 'src.retrieval_v1.RetrievalV1'
          and len(application['retrieval']) == len(queries), 'APPLICATION_BINDING_MISMATCH')
    _need(result['isolation']['separate_network_namespace'] is True
          and result['isolation']['capabilities'] == 'ALL_ZERO', 'ISOLATION_NOT_VERIFIED')
    _need(storage.inspect(root,version)['metadata']['sha256'] == corpus_sha256,
          'STAGED_CORPUS_CHANGED')
    return {'status':'RESEARCH_STAGING_VERIFIED','storage':stored,'verification':result,
            'activation':'NOT_ATTEMPTED','production_authorization':'NOT_GRANTED',
            'http_listener':'NOT_STARTED','llm_calls':'NOT_PERFORMED'}


def _replace(driver, current, requested):
    """Private server-adapter kernel; a passed driver is NOT an authority source.

    current/requested are immutable identities supplied by trusted integration.
    The prior instance remains running until activation and independent readback
    succeed. An uncertain activation is reconciled, never automatically repeated.
    Old instances are retired only by the trusted driver after verified success.
    Driver routing/restore/retire operations must compare the expected active
    identity atomically and stop() must refuse any currently active handle.
    Public production integration is intentionally unavailable pending real host
    configuration and the restricted derived-state contract's human review.
    """
    _need(driver.current() == current, 'STALE_DEPLOYMENT')
    _need(driver.verify_current(current) is True, 'PREVIOUS_INSTANCE_NOT_VERIFIED')
    if current == requested:
        return {'status':'ALREADY_ACTIVE','active':current,'retry':False}
    handle = None
    try:
        handle = driver.start(requested)
        _need(driver.owns(handle), 'UNOWNED_REPLACEMENT_PROCESS')
        _need(driver.verify(handle,requested) is True, 'REPLACEMENT_VERIFICATION_FAILED')
        _need(driver.current() == current, 'STALE_DEPLOYMENT')
        driver.activate(current,requested,handle)
        _need(driver.current() == requested and driver.verify(handle,requested) is True,
              'ACTIVATION_READBACK_FAILED')
    except Exception:
        # Do not retry activation. The previous process has never been stopped.
        try:
            actual = driver.current()
            if actual == requested:
                driver.restore(requested,current)  # Driver must atomically compare before routing.
            elif actual != current:
                raise ValueError('CONCURRENT_DEPLOYMENT_REQUIRES_REVIEW')
            _need(driver.current() == current and driver.verify_current(current) is True,
                  'ROLLBACK_READBACK_OR_HEALTH_FAILED')
            status = 'REJECTED_PREVIOUS_RETAINED'
        except Exception:
            actual = None
            try: actual = driver.current()
            except Exception: pass
            return {'status':'STATE_UNCERTAIN','active':actual,'retry':False,
                    'replacement_cleanup':'NOT_ATTEMPTED_TO_PRESERVE_POSSIBLY_ACTIVE_INSTANCE'}
        cleaned = handle is None
        if handle is not None:
            try:
                _need(driver.owns(handle),'UNOWNED_REPLACEMENT_PROCESS')
                driver.stop(handle);cleaned = True
            except Exception: pass
        return {'status':status if cleaned else 'CLEANUP_REQUIRES_REVIEW',
                'active':current,'retry':False,'replacement_cleanup':cleaned}
    # The handle is now active. Never roll it back merely because retiring the
    # old owned instance fails; report successful activation with cleanup pending.
    retired = False
    try: retired = driver.retire(current, expected_active=requested) is True
    except Exception: pass
    return {'status':'ACTIVE_VERIFIED' if retired else 'ACTIVE_CLEANUP_PENDING',
            'active':requested,'retry':False,'previous_retired':retired}
