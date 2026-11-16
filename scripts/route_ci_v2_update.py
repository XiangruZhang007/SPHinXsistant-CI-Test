#!/usr/bin/env python3
"""Route verified preflight evidence; unattended Candidate execution stays blocked."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import sys
import tempfile

P = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P))
from scripts import prepare_ci_v2_update as adapter
from src import ci_v2_research as c, schema2_workflow as workflow, trusted_snapshot as trust
from src.corpus_snapshot import checked_file, digest, read_json, write_json


def validate(project, registry, detection_path, preflight, exit_code):
    observed = adapter.detection(detection_path)
    receipt = read_json(checked_file(preflight, 'result.json'))
    c.need(isinstance(receipt, dict), 'INVALID_PREFLIGHT', 'Invalid receipt')
    status = receipt.get('status')
    c.need(status in ('NO_UPDATE', 'PLAN_READY', 'BLOCKED')
           and type(exit_code) is int and exit_code == (1 if status == 'BLOCKED' else 0),
           'INVALID_PREFLIGHT', 'Preflight status/exit mismatch')
    base = set(c.RESTRICTIONS) | {'status'}
    metadata = set(observed)
    fields = (base | metadata | {'selected_parent', 'plan_file', 'plan_canonical_sha256'}
              if status == 'PLAN_READY' else base | metadata)
    c.need(set(receipt) == fields if status != 'BLOCKED' else
           set(receipt) in (base | {'reason'}, base | metadata | {'reason'}),
           'INVALID_PREFLIGHT', 'Unexpected receipt fields')
    c.need(all(receipt.get(k) == v and type(receipt.get(k)) is type(v)
               for k, v in c.RESTRICTIONS.items()), 'INVALID_PREFLIGHT', 'Changed restrictions')
    planned = None
    plan_present = (preflight / 'plan.json').exists() or (preflight / 'plan.json').is_symlink()
    if status == 'BLOCKED':
        c.need(not plan_present
               and isinstance(receipt.get('reason'), str)
               and re.fullmatch('[A-Z][A-Z0-9_]*', receipt['reason']),
               'INVALID_PREFLIGHT', 'Invalid blocked receipt')
    else:
        c.need(all(receipt.get(k) == v and type(receipt.get(k)) is type(v)
                   for k, v in observed.items()),
               'INVALID_PREFLIGHT', 'Detection/receipt mismatch')
        if status == 'NO_UPDATE':
            c.need(not observed['update_reported'] and not plan_present,
                   'INVALID_PREFLIGHT', 'Invalid no-update receipt')
        else:
            planned = read_json(checked_file(preflight, 'plan.json'))
            c.need(observed['update_reported'] and isinstance(planned, dict)
                   and receipt.get('plan_file') == 'plan.json'
                   and planned.get('status') == 'SCHEMA2_AUTO_PLAN'
                   and planned.get('upstreams') == observed['upstreams']
                   and planned.get('key') == receipt.get('selected_parent')
                   and digest(planned) == receipt.get('plan_canonical_sha256'),
                   'INVALID_PREFLIGHT', 'Invalid Plan binding')
            # Compare only; retain the original Plan bytes and never change targets.
            c.need(workflow.plan_auto(project, registry, observed['upstreams']) == planned,
                   'INVALID_PREFLIGHT', 'Stale Plan')
    return receipt, planned


def decision(receipt, planned):
    """Routing is not Owner approval or a new build authorization source."""
    result = {'preflight_status': receipt['status'], 'execute_candidate': False,
              'deduplication': 'NOT_ESTABLISHED', **c.RESTRICTIONS}
    if planned is None:
        result.update(status=receipt['status'], reason=receipt.get('reason', 'NO_UPDATE'))
        return result
    selection = planned['selection']
    result['execution_key'] = digest({
        'upstreams': planned['upstreams'], 'parent_entry_sha256': planned['registry_entry_sha256'],
        'reference_sha256': selection['reference_sha256'],
        'policy_sha256': selection['build_policy_sha256'],
        'build_fingerprint': selection['build_fingerprint'],
        'orchestration_fingerprint': selection['orchestration_fingerprint']})
    if os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch':
        result.update(status='BLOCKED', reason='UNATTENDED_EXECUTION_NOT_AUTHORIZED',
                      blocking_reasons=['SCHEDULED_EXECUTION_DISABLED', 'DEDUPLICATION_NOT_ESTABLISHED'])
    elif os.environ.get('CI_V2_BUILD_REQUESTED') != 'true':
        result.update(status='PLAN_READY', reason='MANUAL_EXECUTION_NOT_REQUESTED')
    elif os.environ.get('GITHUB_RUN_ATTEMPT') != '1':
        result.update(status='BLOCKED', reason='REPEAT_ATTEMPT_REQUIRES_NEW_DISPATCH')
    else:
        result.update(status='PLAN_READY', execute_candidate=True, reason='EXPLICIT_MANUAL_BUILD_REQUEST')
    return result


def payload(detection_path, preflight, exit_code):
    values = {'detection': Path(detection_path).read_bytes(),
              'receipt': checked_file(preflight, 'result.json').read_bytes()}
    if (preflight / 'plan.json').is_file():
        values['plan'] = checked_file(preflight, 'plan.json').read_bytes()
    return {**{name: base64.b64encode(raw).decode('ascii') for name, raw in values.items()},
            'exit_code': exit_code}


def restore(output):
    """Validate same-run job outputs in a temporary directory before emitting a Plan."""
    raw = os.environ.get('CI_V2_TRANSFER', '')
    c.need(0 < len(raw) <= 65536, 'INVALID_TRANSFER', 'Missing or oversized transfer')
    output = adapter.output_directory(P, output)
    with tempfile.TemporaryDirectory(prefix='ci-v2-transfer-', dir=output.parent) as tmp:
        stage = Path(tmp); transfer_path = stage / 'transfer.json'
        transfer_path.write_text(raw)
        transfer = read_json(transfer_path)
        c.need(isinstance(transfer, dict) and set(transfer) == {'detection', 'receipt', 'plan', 'exit_code'},
               'INVALID_TRANSFER', 'Invalid transfer fields')
        preflight = stage / 'preflight'; preflight.mkdir()
        for name, path in [('detection', stage / 'upstream_status.json'),
                           ('receipt', preflight / 'result.json'), ('plan', preflight / 'plan.json')]:
            c.need(isinstance(transfer[name], str), 'INVALID_TRANSFER', 'Invalid transfer value')
            path.write_bytes(base64.b64decode(transfer[name], validate=True))
        receipt, planned = validate(P, trust.REGISTRY, stage / 'upstream_status.json',
                                    preflight, transfer['exit_code'])
        result = decision(receipt, planned)
        c.need(result['execute_candidate'], 'EXECUTION_NOT_PERMITTED', 'Build routing is closed')
        output.mkdir()
        # Byte-preserve the actual Step 4A Plan, after all checks succeed.
        with (output / 'plan.json').open('xb') as stream:
            stream.write((preflight / 'plan.json').read_bytes())
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    export = commands.add_parser('export')
    for name in ('detection', 'preflight', 'output'):
        export.add_argument('--' + name, type=Path, required=True)
    export.add_argument('--adapter-exit', type=int, required=True)
    restore_cli = commands.add_parser('restore')
    restore_cli.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'restore':
            result = restore(args.output)
        else:
            receipt, planned = validate(P, trust.REGISTRY, args.detection, args.preflight, args.adapter_exit)
            result = decision(receipt, planned)
            transfer = None
            if result['execute_candidate']:
                transfer = json.dumps(payload(args.detection, args.preflight, args.adapter_exit), sort_keys=True)
                c.need(len(transfer) <= 65536, 'INVALID_TRANSFER', 'Oversized transfer')
            with Path(os.environ['GITHUB_OUTPUT']).open('a') as stream:
                stream.write('execute_candidate=' + str(result['execute_candidate']).lower() + '\n')
                if planned is not None:
                    stream.write('execution_key=' + result['execution_key'] + '\n')
                if transfer is not None:
                    stream.write('transfer=' + transfer + '\n')
            write_json(args.output, result)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        result = {'status': 'BLOCKED', 'reason': getattr(error, 'status', 'WORKFLOW_ROUTING_FAILED'),
                  'execute_candidate': False, **c.RESTRICTIONS}
        if args.command == 'export' and not args.output.exists() and not args.output.is_symlink():
            try:
                write_json(args.output, result)
            except OSError:
                pass
        print(json.dumps(result, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
