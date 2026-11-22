#!/usr/bin/env python3
"""Consume one reviewed immutable research Baseline; no build or promotion.

Run in the frozen verifier runtime, with --app-python selecting the separately
installed application venv. The app runs in a credential-free network namespace.
The only CLI output retained is a sanitized result, never downloaded package bytes.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from src import ci_v2_research as c, trusted_snapshot as trust
from src.corpus_snapshot import digest, file_digest, read_json
from src.parent_r2_anchor import qualify_parent_anchor
from src.research_corpus_selection import ReviewedCorpus

REPOSITORY = 'XiangruZhang007/SPHinXsistant-CI-Test'
REGISTRY_SHA = '27b787518c39787243caef817e24d0c7118b23bd41dcf0b6241b8b2f4c61a7ad'
REFERENCE_SHA = '83df3259b292e3e0323b19fbe1bb5b01afd4f74cfdb8b96f452b1da2468d8724'
KEY = 'official-research-parent-9519233d'
BASELINE = 'sha256-9519233d556d62ae8660d340a8f9792d3058c44ec6d975864f3b1a1619e23767'
CANDIDATE = 'sha256-4987eba3b1346fb50bf0e665196cb9c12036310bcebc0d3ce7c2830526eadc8e'
CORPUS = '280c1577e2821584e72219324513a7e290b53b0022f913f71545a3d40d45fe83'
QUERY = 'What should I do if cl is not found when building SPHinXsim on Windows?'
EXPECTED_CHUNK = 'doc-72b51ca8d4bcd58824925b529c5b38dbf9658f92072a7046f182094ab98af79a'

# Executed only AFTER setpriv, before any project/application import. Ordinary
# checks (not assert statements) keep the boundary effective under Python -O.
ISOLATION_GUARD = """
import os, sys, json, pathlib, socket, errno
def verify_isolation(uid, gid, original_net):
    if uid <= 0 or gid <= 0 or os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid) or os.getgroups():
        raise RuntimeError('PRIVILEGE_DROP_NOT_VERIFIED')
    status = dict(line.split(':', 1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if any(int(status[k].strip(), 16) != 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')) or status['NoNewPrivs'].strip() != '1':
        raise RuntimeError('CAPABILITY_DROP_NOT_VERIFIED')
    if os.readlink('/proc/self/ns/net') == original_net or [n for _, n in socket.if_nameindex()] != ['lo']:
        raise RuntimeError('NETWORK_NAMESPACE_NOT_VERIFIED')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.connect(('192.0.2.1', 9))
        except OSError as error:
            if error.errno != errno.ENETUNREACH:
                raise RuntimeError('NETWORK_DENIAL_NOT_VERIFIED') from None
        else:
            raise RuntimeError('EXTERNAL_ROUTE_AVAILABLE')
    return {'uid': uid, 'gid': gid, 'capabilities': 'ALL_ZERO', 'no_new_privs': True,
            'interfaces': ['lo'], 'separate_network_namespace': True,
            'external_route_probe': 'ENETUNREACH'}
isolation = verify_isolation(int(sys.argv[1]), int(sys.argv[2]), sys.argv[3])
"""


def need(value, reason):
    if not value:
        raise ValueError(reason)


def reference(project):
    registry_path = project / 'configs/ci_v2_schema2_trusted_baselines.json'
    need(file_digest(registry_path) == REGISTRY_SHA, 'REGISTRY_PIN_MISMATCH')
    registry = read_json(registry_path)
    entry = registry['baselines'][KEY]
    need(entry['entry_kind'] == 'REGISTRATION_ONLY' and registry['schema_version'] == 2,
         'RESEARCH_SCOPE_MISMATCH')
    ref = entry['reference']
    need(entry['expected_reference_sha256'] == REFERENCE_SHA == digest(ref), 'REFERENCE_PIN_MISMATCH')
    trust.validate_reference(ref, REFERENCE_SHA, remote=True)
    need(ref['schema_version'] == 3 and ref['node_id'] == BASELINE
         and ref['corpus_sha256'] == CORPUS, 'RESEARCH_SUBJECT_MISMATCH')
    return registry_path, ref


def isolated_python(app_python, work, code, arguments=()):
    """Root runs only fixed OS utilities; Python and all descendants are unprivileged."""
    uid, gid = os.getuid(), os.getgid()
    need(uid > 0 and gid > 0, 'NONROOT_CALLER_REQUIRED')
    app_python, work = Path(app_python), Path(work)
    need(app_python.is_absolute() and app_python.is_file(), 'APPLICATION_INTERPRETER_REQUIRED')
    for executable in ('sudo', 'env', 'unshare', 'setpriv'):
        need(Path('/usr/bin', executable).is_file(), 'ISOLATION_UTILITY_REQUIRED')
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
    env.update(PYTHONDONTWRITEBYTECODE='1', PYTHONHASHSEED='0', HOME=str(work),
               TMPDIR=str(work), XDG_CACHE_HOME=str(work / 'cache'),
               GRADIO_ANALYTICS_ENABLED='False', HF_HUB_OFFLINE='1', HF_HUB_DISABLE_TELEMETRY='1')
    # Noncredential identity scope required by the historical private locator.
    # This conveys neither Actions execution provenance nor Owner authorization.
    env.update(GITHUB_REPOSITORY=REPOSITORY, GITHUB_REPOSITORY_ID='1455203884')
    command = ['/usr/bin/sudo', '-n', '--', '/usr/bin/env', '-i',
               '/usr/bin/unshare', '--net', '--', '/usr/bin/setpriv',
               '--reuid=' + str(uid), '--regid=' + str(gid), '--clear-groups',
               '--inh-caps=-all', '--ambient-caps=-all', '--bounding-set=-all',
               '--no-new-privs', '--', '/usr/bin/env', '-i']
    # sudo may add SUDO_* / HOME / PATH. A second env -i after dropping privileges
    # removes those as well. Never use sudo -E or forward the parent environment.
    command += [k + '=' + v for k, v in sorted(env.items())]
    command += [str(app_python), '-B', '-c', ISOLATION_GUARD + code,
                str(uid), str(gid), os.readlink('/proc/self/ns/net'), *map(str, arguments)]
    result = subprocess.run(command, cwd=work, env=env, stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=120)
    need(result.returncode == 0 and len(result.stdout) <= 1024**2, 'ISOLATED_APPLICATION_FAILED')
    return json.loads(result.stdout)


def application_check(project, app_python, work, review, baseline, notices):
    """App never inherits the transport token or the verifier's CI environment."""
    config = {'review': {**review.__dict__, 'registry_path': str(review.registry_path)},
              'baseline': str(baseline), 'notices': str(notices), 'query': QUERY}
    code = (
        "sys.path.insert(0,sys.argv[4])\n"
        "from src.research_corpus_selection import ReviewedCorpus,verify_gradio_loading\n"
        "v=json.loads(sys.argv[5]);v['review']['registry_path']=pathlib.Path(v['review']['registry_path'])\n"
        "r=verify_gradio_loading(ReviewedCorpus(**v['review']),pathlib.Path(v['baseline'])/'corpus.jsonl',"
        "pathlib.Path(v['baseline']),notices_path=pathlib.Path(v['notices']),queries=[v['query']])\n"
        "r['isolation']=isolation\n"
        "print(json.dumps(r))\n")
    return isolated_python(app_python, work, code, (project, json.dumps(config)))


def consume(project, output, app_python):
    project, output, app_python = map(Path, (project, output, app_python))
    need(output.is_absolute() and not output.exists() and not output.is_symlink()
         and output.parent.is_dir() and not output.resolve().is_relative_to(project.resolve()),
         'NEW_EXTERNAL_OUTPUT_REQUIRED')
    need(app_python.is_absolute() and app_python.is_file(), 'APPLICATION_INTERPRETER_REQUIRED')
    registry_path, ref = reference(project)
    # Complete frozen runtime/implementation checks before unsealing any package.
    runtime = c.frozen_runtime(project)
    with tempfile.TemporaryDirectory(prefix='gradio-consumer-', dir=output.parent) as tmp:
        work = Path(tmp)
        bindings = [('baseline.tar.gz', ref['storage'], ref['transport_sha256']),
                    ('original-r2.json', ref['parent_rows_storage'], ref['parent_rows_sha256']),
                    ('notices.zip', ref['notices']['storage'], ref['notices']['sha256'])]
        for name, locator, pin in bindings:
            trust.download(locator, work / name, pin, token=os.environ.get('TRUSTED_RELEASE_TOKEN'))
            need(file_digest(work / name) == pin and (work / name).stat().st_size == locator['asset_size'],
                 'DOWNLOADED_BYTES_MISMATCH')
        notices = work / 'notices.zip'
        notice_receipt = trust.verify_notices(ref, REFERENCE_SHA, notices)
        baseline = work / 'baseline'
        package = trust.restore(project, work / 'baseline.tar.gz', baseline, ref,
                                REFERENCE_SHA, notices_path=notices)
        need(package['node_id'] == BASELINE and package['approval'] == 'P4_1_VERIFIED',
             'APPROVED_PACKAGE_REQUIRED')
        anchor = qualify_parent_anchor(project, baseline, ref, REFERENCE_SHA,
                                       work / 'original-r2.json', fresh_replay=False)
        need(anchor['status'] == 'QUALIFIED' and anchor['execution'] == 'NO_FRESH_REPLAY',
             'SEALED_R2_BINDING_REQUIRED')
        review = ReviewedCorpus(registry_path, REGISTRY_SHA, KEY, CANDIDATE, BASELINE,
                                CORPUS, 25392117, 11637)
        loaded = application_check(project, app_python, work, review, baseline, notices)
        app = loaded['application']
        need(loaded['status'] == 'RESEARCH_GRADIO_LOADING_VERIFIED'
             and loaded['scope'] == 'RESEARCH_LOADING_ONLY' and not loaded['application_running']
             and app['sha256'] == CORPUS and app['records'] == 11637
             and app['complete_records_equal'] is True and app['callbacks_share_assistant'] is True
             and app['application_closed'] is True and app['retrieval'][0]['query'] == QUERY
             and app['retrieval'][0]['results'][0]['chunk_id'] == EXPECTED_CHUNK,
             'APPLICATION_RESULT_MISMATCH')
        need(file_digest(registry_path) == REGISTRY_SHA, 'REGISTRY_CHANGED_DURING_CONSUMPTION')
        report = {'status': 'IMMUTABLE_RESEARCH_ARTIFACT_GRADIO_VERIFIED',
                  'scope': 'RESEARCH_LOADING_ONLY', 'reference_sha256': REFERENCE_SHA,
                  'baseline_id': BASELINE, 'candidate_id': CANDIDATE, 'package': package,
                  'frozen_runtime': runtime, 'notices': notice_receipt,
                  'R2_verification': 'SEALED_EVIDENCE_INSPECTED / NO_FRESH_REPLAY',
                  'application': app, 'restrictions': loaded['identity']['restrictions'],
                  'isolation': loaded['isolation'],
                  'assets': [{'asset_id': loc['asset_id'], 'sha256': pin} for _, loc, pin in bindings],
                  'external_network_during_application': 'DENIED_BY_NETWORK_NAMESPACE',
                  'LLM_calls': 0, 'HTTP_server_started': False,
                  'production_promotion': 'NOT_AUTHORIZED'}
    report['temporary_package_and_selection_cleaned'] = True
    output.mkdir(mode=0o700)
    (output / 'verification.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--app-python', type=Path, required=True)
    parser.add_argument('--isolation-preflight', action='store_true')
    args = parser.parse_args()
    try:
        need(os.environ.get('GITHUB_ACTIONS') == 'true'
             and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY
             and os.environ.get('GITHUB_REPOSITORY_ID') == '1455203884'
             and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
             and os.environ.get('GITHUB_REF') == 'refs/heads/ci-upstream-refresh'
             and os.environ.get('GITHUB_ACTOR_ID') == '239840087'
             and os.environ.get('GITHUB_RUN_ATTEMPT') == '1', 'TRUSTED_DISPATCH_REQUIRED')
        sha = subprocess.check_output(['git', '--no-optional-locks', 'rev-parse', 'HEAD'],
                                      cwd=PROJECT, text=True).strip()
        need(sha == os.environ.get('GITHUB_SHA') == os.environ.get('GITHUB_WORKFLOW_SHA'),
             'CHECKOUT_REVISION_MISMATCH')
        if args.isolation_preflight:
            with tempfile.TemporaryDirectory(prefix='gradio-isolation-', dir=args.output.parent) as tmp:
                probe = isolated_python(args.app_python, Path(tmp), 'print(json.dumps(isolation))\n')
            print(json.dumps({'status': 'ISOLATION_PREFLIGHT_VERIFIED', 'isolation': probe}))
            return 0
        result = consume(PROJECT, args.output, args.app_python)
        print(json.dumps({'status': result['status'], 'records': result['application']['records']}))
        return 0
    except Exception:
        # No raw download exceptions/headers/redirect URLs or application stderr.
        failure = {'status': 'BLOCKED', 'reason': 'RESEARCH_ARTIFACT_CONSUMPTION_FAILED',
                   'production_promotion': 'NOT_AUTHORIZED'}
        if (args.output.is_absolute() and not args.output.exists() and not args.output.is_symlink()
                and args.output.parent.is_dir()
                and not args.output.resolve().is_relative_to(PROJECT)):
            args.output.mkdir(mode=0o700)
            (args.output / 'verification.json').write_text(json.dumps(failure) + '\n')
        print(json.dumps(failure))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
