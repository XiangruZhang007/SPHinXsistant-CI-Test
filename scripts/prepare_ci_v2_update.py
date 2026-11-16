#!/usr/bin/env python3
"""Offline detection-to-plan adapter; never builds, approves or registers."""
import argparse
import json
from pathlib import Path
import sys

P = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(P))
from src import ci_v2_research as c, schema2_workflow as workflow, trusted_snapshot as trust
from src.corpus_snapshot import checked_file, digest, file_digest, read_json, write_json

DETECTION_FIELDS = {'branch', 'baseline_commit', 'latest_commit', 'update_available'}


def detection(path):
    """Validate the complete detector output before trusting even NO_UPDATE."""
    path = Path(path)
    try:
        path = checked_file(path.parent, path.name)
        before = file_digest(path)
        report = read_json(path)  # Existing duplicate-key rejection.
        c.need(isinstance(report, dict) and set(report) == set(c.SOURCES),
               'INVALID_DETECTION', 'Expected exactly both upstream repositories')
        baseline, targets = {}, {}
        for repo, row in report.items():
            c.need(isinstance(row, dict) and set(row) == DETECTION_FIELDS,
                   'INVALID_DETECTION', 'Unexpected or missing detector fields')
            branch = row['branch']
            c.need(isinstance(branch, str) and bool(branch)
                   and not any(ch.isspace() or ord(ch) < 32 for ch in branch)
                   and type(row['update_available']) is bool,
                   'INVALID_DETECTION', 'Invalid detector branch or update boolean')
            baseline[repo], targets[repo] = row['baseline_commit'], row['latest_commit']
            c.need(row['update_available'] == (targets[repo] != baseline[repo]),
                   'INVALID_DETECTION', 'Contradictory update metadata')
        # Reuse the planner's exact two-repository lowercase commit contract.
        c.validate_request('formal', 'upstream-update', baseline)
        c.validate_request('formal', 'upstream-update', targets)
        c.need(file_digest(path) == before, 'INVALID_DETECTION', 'Detection changed while reading')
        return {'detection_sha256': before, 'baseline_upstreams': baseline,
                'upstreams': targets,
                'update_reported': any(row['update_available'] for row in report.values())}
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise c.GateError('INVALID_DETECTION', 'Invalid upstream detection evidence') from error


def preflight(project, registry_path, detection_path):
    """Return diagnostics and an unchanged existing Plan, without any writes.

    The report hash identifies observed bytes; it is not source authentication.
    NO_UPDATE compares detector baselines only and does not inspect the Registry.
    """
    result = {**detection(detection_path), **c.RESTRICTIONS}
    if not result['update_reported']:
        return {**result, 'status': 'NO_UPDATE'}, None
    try:
        planned = workflow.plan_auto(project, registry_path, result['upstreams'])
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        return {**result, 'status': 'BLOCKED',
                'reason': getattr(error, 'status', 'INVALID_PLANNING_EVIDENCE')}, None
    return {**result, 'status': 'PLAN_READY', 'selected_parent': planned['key'],
            'plan_file': 'plan.json', 'plan_canonical_sha256': digest(planned)}, planned


def output_directory(project, output):
    output, project = Path(output), Path(project).resolve()
    c.need(output.parent.is_dir() and not output.parent.is_symlink()
           and not output.exists() and not output.is_symlink()
           and not output.resolve().is_relative_to(project),
           'INVALID_OUTPUT', 'Output must be a new external directory')
    return output


def persist(output, result, planned):
    """Never overwrite receipts; a failed write leaves no executable Plan."""
    output.mkdir()  # Exclusive creation; existing directories are never owned.
    owned = []
    try:
        for name, value in [('plan.json', planned), ('result.json', result)]:
            if value is not None:
                path = output / name
                try:
                    write_json(path, value)
                except FileExistsError:
                    raise  # Never delete a file another writer created.
                except OSError:
                    path.unlink(missing_ok=True)  # Our partial exclusive write.
                    raise
                owned.append(path)
    except OSError:
        for path in owned:
            path.unlink(missing_ok=True)  # Only files in our newly owned directory.
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--detection', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        output = output_directory(P, args.output)
        try:
            result, planned = preflight(P, trust.REGISTRY, args.detection)
        except c.GateError as error:
            result, planned = {'status': 'BLOCKED', 'reason': error.status, **c.RESTRICTIONS}, None
        persist(output, result, planned)
    except (OSError, ValueError, KeyError, TypeError) as error:
        result = {'status': 'BLOCKED', 'reason': getattr(error, 'status', 'OUTPUT_WRITE_FAILED'),
                  **c.RESTRICTIONS}
    # Do not print input text, exception messages, credentials or arbitrary URLs.
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False))
    return 1 if result['status'] == 'BLOCKED' else 0


if __name__ == '__main__':
    raise SystemExit(main())
