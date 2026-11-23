#!/usr/bin/env python3
"""Trusted archive runner; no execution of code from source-run artifacts."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from src import hosted_verification_archive as archive


def api(method, path, data=None, binary=False):
    args = ['gh', 'api', '--hostname', 'github.com', '--method', method, path]
    if data is not None:
        args += ['--input', '-']
    result = subprocess.run(args, input=None if data is None else json.dumps(data).encode(),
                            capture_output=True, timeout=90)
    archive.need(result.returncode == 0 and len(result.stdout) <= 8*1024**2,
                 'API_FAILED_OR_UNCERTAIN_NO_RETRY')
    return result.stdout if binary else archive.decode(result.stdout)


def context(run_id):
    expected = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': archive.REPO,
                'GITHUB_REPOSITORY_ID': str(archive.RID), 'GITHUB_EVENT_NAME': 'workflow_run',
                'GITHUB_REF': 'refs/heads/'+archive.BRANCH, 'GITHUB_RUN_ATTEMPT': '1',
                'GITHUB_WORKFLOW_REF': archive.REPO+'/.github/workflows/ci_v2_hosted_evidence_archive.yml@refs/heads/'+archive.BRANCH}
    archive.need(all(os.environ.get(k)==v for k,v in expected.items()), 'TRUSTED_ARCHIVER_CONTEXT_REQUIRED')
    head = subprocess.check_output(['git','--no-optional-locks','rev-parse','HEAD'],cwd=PROJECT,text=True).strip()
    archive.need(re.fullmatch('[0-9a-f]{40}',head) is not None
                 and head==os.environ.get('GITHUB_SHA')==os.environ.get('GITHUB_WORKFLOW_SHA'), 'ARCHIVER_CHECKOUT_MISMATCH')
    event=archive.decode(Path(os.environ['GITHUB_EVENT_PATH']).read_bytes())
    archive.need(event['repository']['id']==archive.RID and event['workflow_run']['id']==run_id
                 and event['workflow_run']['head_repository']['id']==archive.RID, 'ARCHIVE_EVENT_MISMATCH')
    for path in ['scripts/archive_hosted_verification.py','src/hosted_verification_archive.py',
                 '.github/workflows/ci_v2_hosted_evidence_archive.yml']:
        committed=subprocess.check_output(['git','--no-optional-locks','show',head+':'+path],cwd=PROJECT)
        archive.need(committed==(PROJECT/path).read_bytes(), 'UNTRACKED_ARCHIVER_CODE')
    directory=PROJECT/archive.relative_directory(run_id)
    if directory.exists():
        for name in ('verification.json','manifest.json','README.md'):
            path=directory/name
            archive.need(path.is_file() and not path.is_symlink(), 'INVALID_EXISTING_ARCHIVE')
            committed=subprocess.check_output(['git','--no-optional-locks','show',head+':'+path.relative_to(PROJECT).as_posix()],cwd=PROJECT)
            archive.need(committed==path.read_bytes(), 'UNTRACKED_EXISTING_ARCHIVE')
    return head


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['validate','propose'])
    parser.add_argument('--run-id',type=int,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--expected-manifest-sha256')
    args=parser.parse_args()
    try:
        head=context(args.run_id)
        archive.need(args.output.is_absolute() and not args.output.exists()
                     and not args.output.resolve().is_relative_to(PROJECT)
                     and args.output.parent.is_dir()
                     and not any(p.is_symlink() for p in (args.output,*args.output.parents)), 'NEW_EXTERNAL_OUTPUT_REQUIRED')
        if args.command=='propose':
            archive.need(re.fullmatch('[0-9a-f]{64}',args.expected_manifest_sha256 or '') is not None,
                         'INDEPENDENT_VALIDATION_PIN_REQUIRED')
        files=archive.fetch(api,PROJECT,args.run_id)
        digest=archive.sha(files['manifest.json'])
        if args.command=='propose':
            archive.need(digest==args.expected_manifest_sha256, 'VALIDATION_JOB_PIN_MISMATCH')
        archive.retain(args.output,files)
        if args.command=='validate':
            with open(os.environ['GITHUB_OUTPUT'],'a') as stream:
                stream.write('manifest_sha256='+digest+'\n')
            result={'status':'ARCHIVE_VALIDATED','manifest_sha256':digest}
        else:
            result=archive.propose(api,PROJECT,files,args.run_id,args.expected_manifest_sha256,head)
        print(json.dumps(result,sort_keys=True))
        return 0
    except Exception:
        print(json.dumps({'status':'ARCHIVE_BLOCKED_OR_WRITE_UNCERTAIN','retry':'NOT_PERMITTED'}))
        return 1


if __name__=='__main__':
    raise SystemExit(main())
