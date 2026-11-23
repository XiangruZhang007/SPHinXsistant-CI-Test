"""Supplementary promotion policy; legacy P8 remains authoritative and unchanged.

evaluate() accepts only a complete artifact, never supplied trust verdicts or
providers. No real quality-adjudication/release authority is configured. The
private pure decision kernel is exercised with providers defined only in tests.
Its mathematical ELIGIBLE result cannot authorize activation. No storage/network,
Gradio, benchmark execution or production mutation occurs in this module.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import json
from pathlib import Path
import zipfile
import zlib

from . import update_eligibility_gate as gate
from .corpus_snapshot import canonical, digest

POLICY = {
    'schema_version': 1, 'name': 'candidate-promotion-policy-v1',
    'direct_quality': 'Recorded QUALITY_ACCEPTED, accepted flag true, no strict failures or new losses',
    'adjudicable_quality_statuses': [], 'adjudicable_finding_kinds': [],
    'explicit_prohibitions': 'NON_OVERRIDABLE', 'legacy_p8': 'REQUIRED',
    'quality_authority': 'NOT_CONFIGURED', 'release_authority': 'NOT_CONFIGURED',
}


def _need(condition):
    if not condition:
        raise ValueError('Invalid promotion evidence')


def _missing(_):
    """Unavailable real trust source; a research review is never substituted."""
    return {'status': 'MISSING'}


def _time(value):
    _need(isinstance(value, str) and value.endswith('Z'))
    return datetime.fromisoformat(value[:-1] + '+00:00')


def _verified(provider, bindings, scope, at):
    """A provider must independently verify source, authority and current state.

    This interface does not authenticate JSON. No accepting provider is shipped;
    synthetic accepting providers exist only in tests and are not CLI inputs.
    """
    try:
        expected = canonical(bindings)
        verdict = provider(json.loads(expected))
        _need(isinstance(verdict, dict))
        if verdict == {'status': 'MISSING'}:
            return verdict
        _need(verdict['status'] == 'VERIFIED' and verdict['scope'] == scope
              and verdict['decision'] == {'QUALITY_ADJUDICATION': 'ACCEPT_QUALITY_FINDINGS',
                                          'CORPUS_RELEASE': 'AUTHORIZE_CORPUS_RELEASE'}[scope]
              and canonical(verdict['bindings']) == expected
              and all(isinstance(verdict[k], str) and verdict[k] for k in ('authority_id', 'source_id'))
              and isinstance(verdict['source_sha256'], str) and len(verdict['source_sha256']) == 64
              and all(c in '0123456789abcdef' for c in verdict['source_sha256'])
              and _time(verdict['checked_at']) <= _time(at) <= _time(verdict['expires_at']))
        return verdict
    except Exception:
        return {'status': 'INVALID'}


def _decide(facts, policy, adjudication_provider, release_provider):
    """Pure policy calculation. Callers of this private kernel do not gain authority."""
    bindings = {**facts['bindings'], 'promotion_policy_sha256': digest(policy)}
    result = {
        'candidate_id': bindings.get('candidate_id'), 'corpus_sha256': bindings.get('corpus_sha256'),
        'bindings': bindings, 'policy': policy, 'policy_only': True, 'activation_authority': False,
        'integrity_status': facts['integrity_status'], 'quality_status': 'NOT_EVALUATED',
        'quality_adjudication_status': 'NOT_EVALUATED', 'release_authorization_status': 'NOT_EVALUATED',
        'final_eligibility': 'BLOCKED', 'blocking_reasons': [],
    }
    reasons = result['blocking_reasons']
    if facts['integrity_status'] != 'VERIFIED':
        reasons.append({'code': 'INTEGRITY_REJECTED'})
        return result
    findings = facts['findings']
    keys = [finding['key'] for finding in findings]
    _need(len(keys) == len(set(keys)))
    adjudication = _verified(adjudication_provider, bindings, 'QUALITY_ADJUDICATION', facts['checked_at'])
    accepted = []
    if adjudication['status'] == 'VERIFIED':
        proposed = adjudication.get('accepted_findings')
        permitted = {f['key'] for f in findings if f['kind'] in policy['adjudicable_finding_kinds']}
        if (not isinstance(proposed, list) or not all(isinstance(k, str) for k in proposed)
                or len(proposed) != len(set(proposed)) or not set(proposed) <= permitted):
            adjudication = {'status': 'INVALID'}
        else:
            accepted = sorted(proposed)
    result['quality_adjudication_status'] = adjudication['status']
    remaining = [f for f in findings if f['key'] not in accepted]
    status = facts['recorded_quality_status']
    direct = status == 'QUALITY_ACCEPTED' and facts['quality_accepted_flag'] is True and not findings
    adjudicated = (adjudication['status'] == 'VERIFIED' and bool(findings) and not remaining
                   and status in policy['adjudicable_quality_statuses'])
    quality_ok = (direct or adjudicated) and adjudication['status'] != 'INVALID'
    result['quality_status'] = ('QUALITY_ACCEPTED' if quality_ok else
                                'QUALITY_REJECTED' if status in ('QUALITY_REJECTED', 'QUALITY_NOT_EVALUATED')
                                else 'QUALITY_REVIEW_REQUIRED')
    if not quality_ok:
        reasons.append({'code': result['quality_status']})
    if adjudication['status'] == 'INVALID':
        reasons.append({'code': 'QUALITY_ADJUDICATION_INVALID'})
    if remaining:
        reasons.append({'code': 'UNRESOLVED_QUALITY_FINDINGS', 'findings': [f['key'] for f in remaining]})
    quality_decision = {
        'bindings': bindings, 'recorded_quality_status': status,
        'recorded_accepted_flag': facts['quality_accepted_flag'], 'quality_status': result['quality_status'],
        'findings': findings, 'accepted_findings': accepted, 'remaining_findings': remaining,
        'adjudication_status': adjudication['status'],
        'adjudication_source': {k: adjudication[k] for k in ('authority_id', 'source_id', 'source_sha256')
                                if k in adjudication},
    }
    result['quality_decision'] = quality_decision
    result['quality_decision_sha256'] = digest(quality_decision)
    release_bindings = {**bindings, 'quality_decision_sha256': result['quality_decision_sha256']}
    release = _verified(release_provider, release_bindings, 'CORPUS_RELEASE', facts['checked_at'])
    result['release_authorization_status'] = release['status']
    if release['status'] != 'VERIFIED':
        reasons.append({'code': 'RELEASE_AUTHORIZATION_' + release['status']})
    if facts['explicit_prohibitions']:
        reasons.append({'code': 'PRODUCTION_NOT_AUTHORIZED', 'sources': facts['explicit_prohibitions']})
    if quality_ok and release['status'] == 'VERIFIED' and not facts['explicit_prohibitions']:
        result['final_eligibility'] = 'ELIGIBLE'
    return result


def _facts(e, p8):
    quality = e.json('quality/quality-report.json')
    original = e.json('result.json')
    b = original['bindings']
    bindings = {
        'candidate_id': p8['candidate_id'], 'corpus_sha256': p8['corpus_sha256'],
        'build_fingerprint': b['build_fingerprint'], 'benchmark_sha256': b['benchmark_sha256'],
        'upstreams': b['target_upstreams'], 'parent_id': b['parent_id'],
        'quality_report_sha256': e.sha('quality/quality-report.json'),
        'raw_results_sha256': quality['raw_results_sha256'], 'quality_policy_sha256': quality['policy_sha256'],
    }
    findings = []
    for row in e.json('quality/incremental-raw-results.json'):
        for metric in ('hit_at_5', 'hit_at_10'):
            value = row['strict'][metric]
            _need(type(value) is bool)
            if not value:
                findings.append({'key': f"candidate/{row['mode']}/{row['id']}/{metric}",
                                 'kind': 'FROZEN_STRICT_FAILURE', 'comparison': 'candidate',
                                 'id': row['id'], 'mode': row['mode'], 'metric': metric})
    for comparison, rows in quality['new_losses'].items():
        for row in rows:
            for column, metric in (('hit5', 'hit_at_5'), ('hit10', 'hit_at_10')):
                if row[column] == 'PASS\u2192FAIL':
                    findings.append({'key': f"{comparison}/{row['mode']}/{row['id']}/{metric}",
                                     'kind': 'REGRESSION', 'comparison': comparison,
                                     'id': row['id'], 'mode': row['mode'], 'metric': metric})
    paths = ('result.json', 'candidate/candidate.json', 'execution-verification/verification.json',
             'build-policy.json', 'quality/quality-report.json', 'trusted-reference.json')
    restrictions = [original, e.json(paths[1])['identity'], e.json(paths[2]), e.json(paths[3]),
                    quality['policy'], e.json(paths[5])['authorization']]
    return {'bindings': bindings, 'integrity_status': 'VERIFIED', 'recorded_quality_status': quality['status'],
            'quality_accepted_flag': original['RETRIEVAL_QUALITY_ACCEPTED'],
            'findings': sorted(findings, key=lambda f: f['key']),
            'explicit_prohibitions': [path for path, record in zip(paths, restrictions)
                                      if record['production_promotion'] == 'NOT_AUTHORIZED'],
            'checked_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}


def evaluate(artifact):
    """Real entry: verify complete evidence with P8; no external trust injection."""
    p8 = gate.evaluate(artifact)
    result = {
        'candidate_id': p8.get('candidate_id'), 'corpus_sha256': p8.get('corpus_sha256'),
        'integrity_status': 'REJECTED', 'quality_status': 'NOT_EVALUATED',
        'quality_adjudication_status': 'MISSING', 'release_authorization_status': 'MISSING',
        'final_eligibility': 'BLOCKED', 'blocking_reasons': [],
        'policy': POLICY, 'policy_sha256': digest(POLICY), 'activation_authority': False,
        'evaluation_context': 'ARCHIVED_EVIDENCE', 'p8': p8,
    }
    try:
        _need(p8['evidence_consistency'] == 'VERIFIED_ARCHIVED_BINDINGS')
        result['integrity_status'] = 'VERIFIED'
        with ExitStack() as stack:
            calculated = _decide(_facts(gate._Evidence(artifact, stack), p8), POLICY, _missing, _missing)
        result.update(calculated)
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError, RuntimeError,
            zipfile.BadZipFile, zlib.error):
        result['blocking_reasons'].append({'code': 'INTEGRITY_REJECTED' if result['integrity_status'] == 'REJECTED'
                                           else 'PROMOTION_EVIDENCE_INVALID'})
    # Never discard P8 reasons or interpret blocking-only mode as authorization.
    result['blocking_reasons'].extend({'source': 'P8', **reason} for reason in p8['reasons'])
    if p8['decision'] != 'ELIGIBLE' or p8['gate_mode'] == 'BLOCKING_ONLY' or result['blocking_reasons']:
        result['final_eligibility'] = 'BLOCKED'
    return result


def main(argv=None):
    try:
        parser = gate._Parser(description=__doc__)
        parser.add_argument('--artifact', type=Path, required=True)
        result = evaluate(parser.parse_args(argv).artifact)
    except (OSError, ValueError):
        result = {'final_eligibility': 'BLOCKED', 'blocking_reasons': [{'code': 'INVALID_INPUT'}],
                  'activation_authority': False}
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if result['final_eligibility'] == 'ELIGIBLE' else 1


if __name__ == '__main__':
    raise SystemExit(main())


def assess_automatic(project, artifact, policy, candidate_id, parent):
    """Versioned complete-evidence admission; existing promotion API unchanged."""
    from . import update_eligibility_gate as gate
    result=gate.evaluate_automatic(project,artifact,policy,candidate_id,parent)
    eligible=result['decision']=='ELIGIBLE'
    return {'schema_version':1,'contract':'AUTOMATIC_QUALITY_V2',
        'decision':'APPROVED_RELEASE_ELIGIBLE' if eligible else 'PUBLICATION_BLOCKED',
        'verified':result['verified'],'P8':result['decision'],
        'production_activation':'SEPARATE_APPROVED_DRIVER_REQUIRED','authorization':'NOT_GRANTED'}
