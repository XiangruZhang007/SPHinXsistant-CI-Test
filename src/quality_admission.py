"""AUTOMATIC_QUALITY_V3: engineering acceptance, never execution authority."""
from pathlib import Path
from . import admission_evidence as evidence
from .corpus_snapshot import digest, file_digest, read_json, read_records

CONTRACT = 'AUTOMATIC_QUALITY_V3'
MODES = ('combined', 'documentation_only')
FIELDS = {'schema_version', 'kind', 'enabled', 'threshold_basis', 'floors_percent',
          'max_new_losses', 'max_anchor_losses', 'max_unknown_questions', 'critical_failures'}


def validate(value, *, require_enabled=True):
    evidence.need(isinstance(value, dict) and set(value) == FIELDS
        and type(value['schema_version']) is int and value['schema_version'] == 1
        and value['kind'] == CONTRACT and type(value['enabled']) is bool
        and (value['enabled'] or not require_enabled)
        and value['threshold_basis'] == 'ENGINEERING_ACCEPTANCE_NOT_VALIDATED_PERFORMANCE'
        and type(value['critical_failures']) is int and value['critical_failures'] == 0,
        'INVALID_QUALITY_V3_POLICY')
    for name in ('floors_percent', 'max_new_losses', 'max_anchor_losses'):
        evidence.need(isinstance(value[name], dict) and set(value[name]) == set(MODES), 'INVALID_V3_MODES')
        for row in value[name].values():
            evidence.need(isinstance(row, dict) and set(row) == {'5', '10'}
                and all(type(x) is int and 0 <= x <= (100 if name == 'floors_percent' else 2)
                        for x in row.values()), 'INVALID_V3_THRESHOLD')
            if name == 'floors_percent':
                evidence.need(0 < row['5'] <= row['10'], 'INVALID_V3_FLOOR')
    evidence.need(isinstance(value['max_unknown_questions'], dict)
        and set(value['max_unknown_questions']) == set(MODES)
        and all(type(x) is int and 0 <= x <= 2 for x in value['max_unknown_questions'].values()),
        'INVALID_V3_UNKNOWN_BUDGET')
    return value


def critical_coverage(row):
    """Validate observations before granting any inherited-debt exception.

    Unit positions bind to the same reviewed predicates across all three
    corpora. Chunk IDs may change; requirement/unit identities may not.
    """
    requirements = row.get('requirements')
    evidence.need(isinstance(requirements, list) and bool(requirements),
                  'INVALID_CRITICAL_OBSERVATION')
    unknown = False
    for requirement in requirements:
        evidence.need(isinstance(requirement, dict) and set(requirement) ==
            {'status', 'reason', 'units', 'coverage'}, 'INVALID_CRITICAL_OBSERVATION')
        status = requirement['status']; units = requirement['units']; coverage = requirement['coverage']
        evidence.need(status in ('RESOLVED', 'UNRESOLVED') and isinstance(units, list)
            and isinstance(coverage, dict) and set(coverage) == {'5', '10'},
            'INVALID_CRITICAL_OBSERVATION')
        evidence.need(all(isinstance(v, list) and len(v) == len(units)
            and all(type(x) is bool for x in v) for v in coverage.values()),
            'INVALID_CRITICAL_OBSERVATION')
        evidence.need(all(not a or b for a, b in zip(coverage['5'], coverage['10'])),
                      'INCONSISTENT_CRITICAL_COVERAGE')
        if status == 'RESOLVED':
            evidence.need(requirement['reason'] is None and bool(units)
                and all(isinstance(unit, list) and bool(unit)
                    and all(isinstance(cid, str) and cid for cid in unit)
                    and len(set(unit)) == len(unit) for unit in units),
                'INVALID_CRITICAL_OBSERVATION')
        else:
            unknown = True
            evidence.need(requirement['reason'] in ('REFERENCE_SCOPE_NOT_INDEXED',
                'AMBIGUOUS_REFERENCE_SCOPE', 'REQUIRED_LITERAL_NOT_INDEXED')
                and units == [], 'INVALID_CRITICAL_OBSERVATION')
    evidence.need(type(row['unknown']) is bool and row['unknown'] == unknown
        and isinstance(row['hits'], dict) and set(row['hits']) == {'5', '10'}
        and all(type(row['hits'][k]) is bool and row['hits'][k] ==
            (not unknown and all(x for r in requirements for x in r['coverage'][k]))
            for k in ('5', '10')), 'INCONSISTENT_CRITICAL_OBSERVATION')
    return None if unknown else [r['coverage'] for r in requirements]


def decision(policy, base, target, anchor):
    """Gross aggregate losses plus zero critical evidence-unit regression.

    Inherited ranking debt is allowed only with resolved corpus predicates in
    all three observations. Neither unknown evidence nor partial coverage loss
    is grandfathered. Absolute completeness is reported separately.
    """
    validate(policy)
    evidence.need(set(base) == set(target) == set(anchor), 'V3_QUESTION_DOMAIN_CHANGED')
    reasons = []; metrics = {}; critical = []; debt = []; regressions = []
    corpus_failures = []; baseline_unverified = []; incomplete = []
    for key, row in target.items():
        evidence.need(all(row[k] == base[key][k] == anchor[key][k]
                          for k in ('id', 'mode', 'critical', 'primary')), 'V3_ROW_METADATA_CHANGED')
        if not row['critical']:
            continue
        observations = {'target': critical_coverage(row), 'base': critical_coverage(base[key]),
                        'anchor': critical_coverage(anchor[key])}
        if not row['hits']['10']:
            incomplete.append(key)
        if observations['target'] is None:
            corpus_failures.append(key); critical.append(key)
            reasons.append('CRITICAL_CORPUS_EVIDENCE_FAILURE')
        if any(observations[label] is None for label in ('base', 'anchor')):
            baseline_unverified.append(key); critical.append(key)
            reasons.append('CRITICAL_BASELINE_UNVERIFIED')
        if any(value is None for value in observations.values()):
            continue
        current = observations['target']
        for label in ('base', 'anchor'):
            previous = observations[label]
            evidence.need(len(previous) == len(current) and all(
                len(a['10']) == len(b['10']) for a, b in zip(previous, current)),
                'CRITICAL_EVIDENCE_DOMAIN_CHANGED')
            for index, (old, new) in enumerate(zip(previous, current)):
                for cutoff in ('5', '10'):
                    for unit, (was, now) in enumerate(zip(old[cutoff], new[cutoff])):
                        if was and not now:
                            regressions.append({'question': key, 'baseline': label,
                                'requirement': index, 'unit': unit, 'cutoff': cutoff})
                            critical.append(key)
        # Baseline debt is visible at both cutoffs, including partial failures.
        missing = [{'requirement': index, 'unit': unit, 'cutoff': cutoff}
            for index, requirement in enumerate(current) for cutoff in ('5', '10')
            for unit, covered in enumerate(requirement[cutoff]) if not covered]
        if missing and not any(r['question'] == key for r in regressions):
            debt.append({'question': key, 'classification': 'VERIFIED_INHERITED_RANKING_LIMITATION',
                'verified_against': ['base', 'anchor'], 'missing_units': missing})
    if regressions:
        reasons.append('CRITICAL_RETRIEVAL_DEGRADATION')
    for mode in MODES:
        keys = [k for k, row in target.items() if row['mode'] == mode and row['primary']]
        evidence.need(bool(keys), 'EMPTY_V3_PRIMARY_DOMAIN')
        unknown = sum(target[k]['unknown'] for k in keys)
        data = {'n': len(keys), 'unknown_questions': unknown, 'metrics': {}}
        if unknown > policy['max_unknown_questions'][mode]:
            reasons.append('MAPPING_UNCERTAINTY_BUDGET_EXCEEDED')
        for cutoff in ('5', '10'):
            passed = sum(target[k]['hits'][cutoff] for k in keys)
            losses = [k for k in keys if base[k]['hits'][cutoff] and not target[k]['hits'][cutoff]]
            anchor_losses = [k for k in keys if anchor[k]['hits'][cutoff] and not target[k]['hits'][cutoff]]
            if passed * 100 < policy['floors_percent'][mode][cutoff] * len(keys):
                reasons.append('ABSOLUTE_QUALITY_FLOOR_FAILED')
            if len(losses) > policy['max_new_losses'][mode][cutoff]:
                reasons.append('RETRIEVAL_REGRESSION_BUDGET_EXCEEDED')
            if len(anchor_losses) > policy['max_anchor_losses'][mode][cutoff]:
                reasons.append('CUMULATIVE_REGRESSION_BUDGET_EXCEEDED')
            data['metrics'][cutoff] = {'passed': passed, 'new_losses': losses, 'anchor_losses': anchor_losses}
        metrics[mode] = data
    return {'accepted': not reasons, 'reasons': sorted(set(reasons)), 'metrics': metrics,
            'critical_failures': sorted(set(critical)),
            'critical_corpus_failures': corpus_failures,
            'critical_baseline_unverified': baseline_unverified,
            'critical_retrieval_regressions': regressions, 'baseline_debt': debt,
            'application_quality': {'critical_top10_complete': not incomplete,
                'critical_top10_incomplete': incomplete,
                'scope': 'RETRIEVAL_COMPLETENESS_ONLY_NOT_PRODUCTION_READINESS'},
            'threshold_basis': policy['threshold_basis']}


def evaluate(project, root, policy, rows, frozen_report, spec):
    """Caller already verifies the entire native package, Full, R2, Q1 and licenses."""
    from . import approval_evidence as ev
    project, root = Path(project), Path(root)
    pins = policy['quality_v3']
    for key, name in [('policy', 'admission-policy.json'), ('references', 'admission-references.json')]:
        evidence.need(file_digest(root / name) == pins[key]['sha256'], 'V3_EXTERNAL_PIN_MISMATCH')
    rules = validate(read_json(root / 'admission-policy.json'))
    document = read_json(root / 'admission-references.json')
    evidence.need(document['benchmark_sha256'] == policy['benchmark_sha256'], 'V3_BENCHMARK_MISMATCH')
    refs = evidence.validate(document, spec)
    registry=Path(project)/'configs/ci_v2_schema2_trusted_baselines.json'
    evidence.need(file_digest(registry)==policy['root_registry_sha256'],'V3_ROOT_REGISTRY_MISMATCH')
    entry=read_json(registry)['baselines'][policy['initial_parent_key']]
    evidence.need(document['root_reference_sha256']==entry['expected_reference_sha256']
        and document['anchor_corpus_sha256']==entry['reference']['corpus_sha256']
        and document['anchor_rows_sha256']==entry['reference']['parent_rows_sha256'], 'V3_ROOT_REFERENCE_MISMATCH')
    anchor_corpus = root / 'admission-anchor-corpus.jsonl'; anchor_rows = root / 'admission-anchor-rows.json'
    evidence.need(file_digest(anchor_corpus) == document['anchor_corpus_sha256']
        and file_digest(anchor_rows) == document['anchor_rows_sha256'], 'V3_INITIAL_ANCHOR_MISMATCH')
    anchor_records = read_records(anchor_corpus); anchor_results = read_json(anchor_rows)
    ev.rescore(anchor_results, spec, anchor_records, [r for r in anchor_records if r['source_role'] == 'documentation'])
    expected = {(r['id'], r['mode']) for r in anchor_results}
    evidence.need(all(len(v) == len(expected) and {(r['id'], r['mode']) for r in v} == expected
        for v in (rows['base'], rows['target'])), 'V3_ROW_DOMAIN_MISMATCH')
    observations = {'anchor': evidence.outcomes(anchor_records, anchor_results, refs)}
    for label, folder in [('base', 'parent'), ('target', 'candidate')]:
        observations[label] = evidence.outcomes(read_records(root / folder / 'corpus.jsonl'), rows[label], refs)
    result = decision(rules, observations['base'], observations['target'], observations['anchor'])
    return {'schema_version': 1, 'contract': CONTRACT, 'candidate_id': frozen_report['candidate_id'],
        'policy_sha256': policy['policy_sha256'], 'corpus_sha256': frozen_report['corpus_sha256'],
        'accepted': result['accepted'], 'status': 'QUALITY_ACCEPTED' if result['accepted'] else 'QUALITY_REVIEW_REQUIRED',
        'P8': 'ELIGIBLE' if result['accepted'] else 'P8_BLOCKED',
        'q1': 'ADMISSION_EVIDENCE_V3_CHECKED', 'reasons': result['reasons'],
        'decision': result, 'observations': observations,
        'frozen_quality_v2': frozen_report, 'frozen_scores_adjusted': False,
        'admission_policy_sha256': pins['policy']['sha256'], 'references_sha256': pins['references']['sha256'],
        'execution_authority': 'NOT_GRANTED'}
