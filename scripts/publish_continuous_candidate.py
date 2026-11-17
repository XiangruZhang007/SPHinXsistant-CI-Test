#!/usr/bin/env python3
"""Default-disabled dedicated Hosted publisher. No approval or Registry mutation."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

P = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P))
from src import genuine_continuous_execution as g, scheduled_construction as scheduled
from src import continuous_completion as completion
from src.corpus_snapshot import read_json, write_json
from scripts.prepare_ci_v2_update import output_directory


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    output = None
    try:
        output = output_directory(P, args.output)
        config, _, pin = g.deployment()
        g._checkout(P, config); g._implementation(P, config['execution_contract_sha256'])
        policy = scheduled.load(P, config)
        g.need(policy['publication_enabled'] is True
               and os.environ.get('CONTINUOUS_PUBLICATION_ENABLED') == 'true', 'CONTINUOUS_PUBLICATION_DISABLED')
        # Identifiers are GitHub runtime observations, subsequently checked by API;
        # there are no actor, approval or simulation arguments.
        context = g._scheduled_context() if os.environ.get('GITHUB_EVENT_NAME') == 'schedule' else g.owner.context_from_environment()
        client = completion.Client(config['repository'], os.environ.get('GH_TOKEN'))
        with tempfile.TemporaryDirectory(prefix='continuous-publication-', dir=output.parent) as tmp:
            work = Path(tmp); delivery = work / 'delivery'
            origin, artifact = completion.retrieve_build(client, config, context['run_id'], context['run_attempt'], delivery)
            authority = g._authority(P, delivery / 'run/evidence/detection.json', config, pin)
            # Same reviewed workflow-level group still covers this publisher job.
            g.need(authority['workflow_run']['event'] == 'schedule', 'SCHEDULED_PUBLISHER_CONTEXT_REQUIRED')
            scheduled.mutex(P, config, authority)
            prepared = completion.prepare(P, delivery, work / 'prepared', pins=read_json(delivery / 'verification-inputs.json'),
                transport_sha256=read_json(delivery / 'transport.json')['transport_sha256'], verified_origin=origin, artifact_transport=artifact)
            g.need(prepared['manifest']['execution_key'] == authority['parent_comparison']['execution_key'], 'PUBLICATION_SUBJECT_CHANGED')
            g._authority(P, delivery / 'run/evidence/detection.json', config, pin)
            result = completion.publish(P, client, config, prepared, prefix=policy['release_prefix'])
            result['original_artifact'] = artifact
        output.mkdir(); write_json(output / 'publication.json', result)
        print(json.dumps(result, sort_keys=True)); return 0
    except Exception:
        # Do not log credentials, raw API bodies, redirect URLs or local paths.
        reason = getattr(sys.exception(), 'status', 'CONTINUOUS_PUBLICATION_FAILED')
        if not isinstance(reason, str) or not g.re.fullmatch('[A-Z][A-Z0-9_]{0,99}', reason):
            reason = 'CONTINUOUS_PUBLICATION_FAILED'
        result = {'status': 'BLOCKED', 'reason': reason,
                  'publication_state': 'UNCONFIRMED_REQUIRES_READ_ONLY_VERIFICATION',
                  'research_approval': 'NOT_GRANTED', 'production_promotion': 'NOT_AUTHORIZED'}
        if output is not None:
            try:
                output.mkdir(exist_ok=False); write_json(output / 'failure.json', result)
            except OSError:
                pass
        print(json.dumps(result, sort_keys=True)); return 1


if __name__ == '__main__':
    raise SystemExit(main())
