"""Deterministic automatic admission, separate from construction and activation.

Real inputs always pass the existing complete sealed P8 and promotion readers.
No supplied JSON verdict, synthetic provider, score adjustment or waiver is a
public input. The decision is not a deployment credential or Owner approval.
"""
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import re
from . import candidate_promotion_policy as promotion
from . import update_eligibility_gate as p8
from .corpus_snapshot import digest

KIND = 'AUTOMATIC_QUALITY_ADMISSION_V1'
FIELDS = {'schema_version', 'kind', 'repository', 'repository_id', 'valid_from',
          'expires_at', 'benchmark_sha256', 'build_fingerprint', 'required_modes',
          'required_rows', 'requirements'}
REQUIREMENTS = {'strict_failures': 0, 'new_losses': 0, 'parity': 'PARITY_PASS',
    'recorded_quality': 'QUALITY_ACCEPTED', 'accepted_flag': True,
    'q1': 'QUALIFIED_FOR_VERSION_PAIR', 'p8': 'ELIGIBLE',
    'explicit_restrictions': 'NON_OVERRIDABLE', 'synthetic': 'DENIED'}


def need(ok, reason):
    if not ok: raise ValueError(reason)


def policy(path, expected_sha256):
    from . import versioned_corpus_storage as storage
    from . import owner_manual_baseline_approval as owner
    path = Path(path)
    need(isinstance(expected_sha256, str) and re.fullmatch('[0-9a-f]{64}', expected_sha256),
         'INVALID_ADMISSION_POLICY_PIN')
    with storage._directory(path.parent) as fd, storage._regular(fd, path.name) as stream:
        need(stream.seek(0, 2) <= 256 * 1024, 'ADMISSION_POLICY_TOO_LARGE')
        stream.seek(0); raw = stream.read()
    need(hashlib.sha256(raw).hexdigest() == expected_sha256, 'ADMISSION_POLICY_PIN_MISMATCH')
    value = owner._strict_json(raw.decode('utf-8'))
    need(set(value) == FIELDS and type(value['schema_version']) is int
         and value['schema_version'] == 1 and value['kind'] == KIND,
         'INVALID_ADMISSION_POLICY')
    need(value['requirements'] == REQUIREMENTS and type(value['repository_id']) is int
         and value['repository_id'] > 0 and isinstance(value['repository'], str)
         and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value['repository'])
         and all(isinstance(value[k], str) and re.fullmatch('[0-9a-f]{64}', value[k])
                 for k in ('benchmark_sha256', 'build_fingerprint')), 'UNSUPPORTED_ADMISSION_REQUIREMENTS')
    need(value['required_modes'] == ['combined', 'documentation_only']
         and type(value['required_rows']) is int and value['required_rows'] > 0,
         'INVALID_ADMISSION_BENCHMARK_DOMAIN')
    def time(v):
        need(isinstance(v, str) and v.endswith('Z'), 'INVALID_ADMISSION_TIME')
        return datetime.fromisoformat(v[:-1] + '+00:00')
    need(time(value['valid_from']) <= datetime.now(timezone.utc) < time(value['expires_at']),
         'ADMISSION_POLICY_NOT_CURRENT')
    return value


def _decide(facts, value):
    """Private pure kernel; test fixtures cannot become trusted run evidence."""
    reasons = []
    def check(ok, reason):
        if not ok: reasons.append(reason)
    check(facts.get('integrity') == 'VERIFIED_ARCHIVED_BINDINGS', 'INTEGRITY_NOT_VERIFIED')
    check(facts.get('parity') == 'PARITY_PASS', 'PARITY_NOT_PASS')
    check(facts.get('quality') == 'QUALITY_ACCEPTED' and facts.get('accepted') is True,
          'QUALITY_NOT_ACCEPTED')
    check(facts.get('q1') == 'QUALIFIED_FOR_VERSION_PAIR', 'Q1_NOT_QUALIFIED')
    check(facts.get('p8') == 'ELIGIBLE' and facts.get('p8_mode') != 'BLOCKING_ONLY', 'P8_BLOCKED')
    check(not facts.get('prohibitions'), 'EXPLICIT_RELEASE_RESTRICTION')
    check(facts.get('provenance') == 'AUTHENTICATED_GITHUB_ACTIONS', 'PRODUCER_NOT_AUTHENTICATED')
    bindings = facts.get('bindings', {})
    check(bindings.get('benchmark_sha256') == value['benchmark_sha256']
          and bindings.get('build_fingerprint') == value['build_fingerprint'], 'SCIENTIFIC_DOMAIN_MISMATCH')
    rows = facts.get('rows', [])
    check(len(rows) == value['required_rows'] and
          sorted({r.get('mode') for r in rows}) == value['required_modes'] and
          len({(r.get('id'), r.get('mode')) for r in rows}) == len(rows), 'R2_ROW_DOMAIN_MISMATCH')
    check(bool(rows) and all(type(r.get('strict', {}).get(k)) is bool
          and r['strict'][k] is True for r in rows for k in ('hit_at_5','hit_at_10')),
          'FROZEN_STRICT_FAILURE')
    check(not facts.get('new_losses'), 'NEW_RETRIEVAL_REGRESSION')
    subject = {'schema_version': 1, 'kind': KIND, 'bindings': bindings,
               'policy_sha256': digest(value), 'facts_sha256': digest(facts),
               'eligibility': 'ELIGIBLE' if not reasons else 'BLOCKED',
               'reasons': sorted(reasons)}
    return {**subject, 'decision_sha256': digest(subject), 'authorization': 'NOT_GRANTED',
            'observed': {k:facts.get(k) for k in ('parity','quality','accepted','q1','p8','provenance')},
            'strict_failure_count': sum(r.get('strict', {}).get(k) is not True for r in rows
                                        for k in ('hit_at_5','hit_at_10')),
            'authority_scope': 'POLICY_CALCULATION_ONLY',
            'implementation_scope': 'BLOCKING_ADMISSION_ASSESSMENT'}


def evaluate(artifact, policy_path, expected_policy_sha256):
    """Read actual archived evidence; never extract, replay, approve or mutate it.

    Archive consistency does not authenticate an Actions producer. The existing
    immutable completion transport must establish that separately in a genuine
    trusted job. This local interface therefore never supplies that assertion.
    """
    result = {'eligibility': 'BLOCKED', 'authorization': 'NOT_GRANTED', 'reasons': []}
    try:
        value = policy(policy_path, expected_policy_sha256)
        gate = p8.evaluate(artifact)
        # Reject invalid formats before opening the existing evidence reader.
        need(gate.get('evidence_consistency') == 'VERIFIED_ARCHIVED_BINDINGS', 'INVALID_COMPLETE_RUN')
        with ExitStack() as stack:
            evidence = p8._Evidence(artifact, stack)
            old = promotion._facts(evidence, gate)
            try: q1 = evidence.json('q1-status.json')['status']
            except (KeyError, ValueError): q1 = 'NOT_AVAILABLE'
            facts = {'integrity': gate['evidence_consistency'],
                'parity': evidence.json('parity.json').get('status'),
                'quality': old['recorded_quality_status'], 'accepted': old['quality_accepted_flag'],
                'q1': q1, 'p8': gate['decision'], 'p8_mode': gate['gate_mode'],
                'prohibitions': old['explicit_prohibitions'], 'provenance': 'ARCHIVED_NOT_LIVE_AUTHENTICATED',
                'bindings': old['bindings'], 'rows': evidence.json('quality/incremental-raw-results.json'),
                'new_losses': [r for r in old['findings'] if r['kind'] == 'REGRESSION']}
            result = _decide(facts, value)
            result['legacy_p8_reasons'] = gate['reasons']
            result['raw_policy_sha256'] = expected_policy_sha256
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, IndexError, AttributeError):
        result['reasons'] = ['INVALID_POLICY_OR_COMPLETE_EVIDENCE']
    return result


def evaluate_genuine(project, delivery, pins, policy_path, expected_policy_sha256):
    """Read Genuine v2/v3 using its existing full verifier, without fresh replay.

    Current Genuine contracts deliberately require research restrictions. A
    supplementary Q1 diagnostic never replaces the original Q1 status or lifts
    P8. This adapter exposes those exact blockers; no new accepting provider or
    production authority is asserted by local package consistency verification.
    """
    result = {'eligibility':'BLOCKED','authorization':'NOT_GRANTED',
              'reasons':['INVALID_POLICY_OR_COMPLETE_EVIDENCE']}
    try:
        from . import genuine_continuous_execution as genuine
        from .corpus_snapshot import checked_file, read_json
        value = policy(policy_path, expected_policy_sha256)
        root = Path(delivery) / 'run'
        verified = genuine.verify_package(project, root, **pins, fresh_replay=False)
        config = read_json(checked_file(root, 'evidence/deployment.json'))
        need(all(type(config[k]) is type(value[k]) and config[k] == value[k]
                 for k in ('repository', 'repository_id')), 'ADMISSION_REPOSITORY_MISMATCH')
        metadata = read_json(checked_file(root, 'candidate/genuine-candidate.json'))
        identity = metadata['identity']
        quality = read_json(checked_file(root, 'quality/quality-report.json'))
        restrictions = {k:v for k,v in identity.items() if k in genuine.c.RESTRICTIONS}
        bindings = {'candidate_id':metadata['candidate_id'],
            'corpus_sha256':genuine.file_digest(checked_file(root, 'candidate/corpus.jsonl')),
            'parent_id':identity['parent']['node_id'], 'upstreams':identity['upstreams'],
            'source_state':identity['target_source_state'],
            'benchmark_sha256':quality['policy']['benchmark_sha256'],
            'build_fingerprint':identity['build_fingerprint'],
            'execution_contract_sha256':pins['expected_execution_contract_sha256'],
            'package_manifest_sha256':pins['expected_manifest_sha256']}
        facts = {'integrity':'VERIFIED_ARCHIVED_BINDINGS',
            'parity':read_json(checked_file(root,'parity.json')).get('status'),
            'quality':quality['status'], 'accepted':verified.get('RETRIEVAL_QUALITY_ACCEPTED'),
            'q1':read_json(checked_file(root,'q1-status.json'))['status'],
            'p8':'P8_BLOCKED','p8_mode':'BLOCKING_ONLY',
            'prohibitions':restrictions,'provenance':'ARCHIVED_NOT_LIVE_AUTHENTICATED',
            'bindings':bindings,
            'rows':read_json(checked_file(root,'quality/incremental-raw-results.json')),
            'new_losses':[row for rows in quality['new_losses'].values() for row in rows]}
        result = _decide(facts, value)
        result.update(raw_policy_sha256=expected_policy_sha256,
            format=metadata['format'], scientific_execution='NO_FRESH_REPLAY',
            original_q1_status=facts['q1'], live_authorization='NOT_ESTABLISHED')
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, IndexError, AttributeError):
        pass
    return result
