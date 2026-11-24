#!/usr/bin/env python3
"""Existing scheduled pipeline's closed build/pre-token/writer entry points."""
from pathlib import Path
import argparse,json,os,re,sys
P=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(P))
from src import automatic_lifecycle as lifecycle,automatic_lifecycle_policy as policy_api
from src import automatic_writer as writer,genuine_continuous_execution as genuine
from src import continuous_completion as completion
from src.corpus_snapshot import write_json


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('context','build','pre-token','advance'))
    parser.add_argument('--detection',type=Path)
    parser.add_argument('--work',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        if args.operation=='context':
            if args.detection is None:raise ValueError('DETECTION_REQUIRED')
            config,_,pin=genuine.deployment();policy=policy_api.load(P,config)
            if policy['schema_version']==3:
                from src.native_runtime_contract import authority
                observed=authority(P,args.detection,config,pin)
                result={'status':'BUILD_CONTEXT_VERIFIED','execute_candidate':False,
                    'authority_observation':observed,'construction':'NOT_PERFORMED'}
            else:
                result=genuine.preflight(P,args.detection)
            args.work.mkdir(parents=True,exist_ok=False)
            write_json(args.work/'result.json',result)
        elif args.operation=='build':
            if args.detection is None:raise ValueError('DETECTION_REQUIRED')
            result=lifecycle.build(P,args.detection,args.work,args.work.parent/'continuous-result')
            if os.environ.get('GITHUB_OUTPUT'):
                with open(os.environ['GITHUB_OUTPUT'],'a') as stream:
                    stream.write('candidate_built='+('true' if result['status']=='NATIVE_CANDIDATE_BUILT' else 'false')+'\n')
        elif args.operation=='pre-token':
            result=lifecycle.pre_token(P,args.work)
        else:
            result=lifecycle.publish_and_advance(P,args.work)
            write_json(args.work/'result.json',result)
        print(json.dumps(result,sort_keys=True))
        if args.operation=='pre-token' and result['status']=='QUALITY_REJECTED':return 1
        return 0 if result['status'] in ('BUILD_CONTEXT_VERIFIED','NATIVE_CANDIDATE_BUILT','NO_UPDATE','AUTOMATIC_PRETOKEN_VERIFIED','PARENT_ADVANCED','QUALITY_REJECTED') else 1
    except Exception as error:
        reason=str(error)
        if not re.fullmatch('[A-Z][A-Z0-9_]{0,99}',reason):reason='AUTOMATIC_LIFECYCLE_FAILED'
        result={'status':'BLOCKED','reason':reason,'retry':False}
        if isinstance(error,lifecycle.audit.AuditError) and getattr(error,'api_diagnostics',None):
            result['api_diagnostics']=error.api_diagnostics
        print(json.dumps(result))
        return 1

if __name__=='__main__':raise SystemExit(main())
