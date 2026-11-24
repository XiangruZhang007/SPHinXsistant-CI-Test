"""Admission-only, versioned evidence predicates; frozen benchmark/Q1 stay intact.

Predicates are reviewed relevance judgments, not generated semantic approvals.
Only canonical, independently verified Corpus records may enter this adapter.
"""
from pathlib import PurePosixPath
from .corpus_snapshot import digest


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def validate(document, spec):
    need(isinstance(document, dict) and set(document) == {
        'schema_version', 'kind', 'benchmark_sha256', 'root_reference_sha256',
        'anchor_corpus_sha256', 'anchor_rows_sha256', 'questions'}, 'INVALID_ADMISSION_REFERENCES')
    need(document['schema_version'] == 1 and type(document['schema_version']) is int
         and document['kind'] == 'ADMISSION_REFERENCES_V1', 'INVALID_ADMISSION_REFERENCES')
    expected = {q['id']: q for q in spec['questions']}
    need(isinstance(document['questions'], list), 'INVALID_REFERENCE_QUESTIONS')
    found = {}
    for row in document['questions']:
        need(isinstance(row, dict) and set(row) == {'id', 'critical', 'requirements', 'rationale'}
             and row['id'] in expected and row['id'] not in found
             and type(row['critical']) is bool and isinstance(row['rationale'], str)
             and row['rationale'].strip(), 'INVALID_REFERENCE_QUESTION')
        need(isinstance(row['requirements'], list) and len(row['requirements']) ==
             len(expected[row['id']]['requirements']), 'REFERENCE_REQUIREMENT_DOMAIN_CHANGED')
        for ref in row['requirements']:
            need(isinstance(ref, dict) and set(ref) == {'path', 'symbol', 'section_title', 'contains_all'}
                 and isinstance(ref['path'], str), 'INVALID_REFERENCE_PREDICATE')
            path = PurePosixPath(ref['path'])
            need(not path.is_absolute() and '..' not in path.parts and len(path.parts) >= 3
                 and path.parts[:2] in (('repos', 'SPHinXsys'), ('repos', 'SPHinXsim'))
                 and path.as_posix() == ref['path'], 'INVALID_REFERENCE_PATH')
            need(all(v is None or isinstance(v, str) and v.strip()
                     for v in (ref['symbol'], ref['section_title']))
                 and not (ref['symbol'] and ref['section_title'])
                 and isinstance(ref['contains_all'], list)
                 and all(isinstance(t, str) and t.strip() for t in ref['contains_all'])
                 and len(set(ref['contains_all'])) == len(ref['contains_all'])
                 and bool(ref['symbol'] or ref['section_title'] or ref['contains_all']),
                 'EMPTY_OR_INVALID_REFERENCE_PREDICATE')
        found[row['id']] = row
    need(set(found) == set(expected), 'REFERENCE_QUESTION_DOMAIN_CHANGED')
    return found


def resolve(records, reference):
    """Exact metadata/text predicates. No line-number correction or LLM oracle.

    All required literals can be covered by multiple returned chunks. An
    ambiguous symbol/heading scope is uncertainty, never a silent match.
    """
    candidates = [r for r in records if r['source_path'] == reference['path']]
    if reference['symbol']:
        candidates = [r for r in candidates if r.get('symbol') == reference['symbol']]
    if reference['section_title']:
        candidates = [r for r in candidates if r.get('section_title') == reference['section_title']]
    if not candidates:
        return {'status': 'UNRESOLVED', 'reason': 'REFERENCE_SCOPE_NOT_INDEXED', 'units': []}
    # Multiple equally named definitions are not treated as equivalent evidence.
    if reference['symbol'] or reference['section_title']:
        ranges = sorted((r['start_line'], r['end_line']) for r in candidates)
        if len(ranges) > 1 and any(b[0] > a[1] + 1 for a, b in zip(ranges, ranges[1:])):
            return {'status': 'UNRESOLVED', 'reason': 'AMBIGUOUS_REFERENCE_SCOPE', 'units': []}
    units = []
    for term in reference['contains_all']:
        ids = sorted({r['chunk_id'] for r in candidates if term in r['content']})
        if not ids:
            return {'status': 'UNRESOLVED', 'reason': 'REQUIRED_LITERAL_NOT_INDEXED', 'units': []}
        units.append(ids)
    if not units:
        units = [sorted({r['chunk_id'] for r in candidates})]
    return {'status': 'RESOLVED', 'reason': None, 'units': units}


def outcomes(records, rows, references):
    """Fixed question/mode domain is checked by the caller before this function."""
    by_id = {r['chunk_id']: r for r in records}
    need(len(by_id) == len(records), 'DUPLICATE_ADMISSION_CHUNK')
    result = {}
    for row in rows:
        key = row['mode'] + '/' + row['id']; ref = references[row['id']]
        domain = [r for r in records if row['mode'] == 'combined' or r['source_role'] == 'documentation']
        resolved = [resolve(domain, r) for r in ref['requirements']]
        ids = row['top_10_ids']
        need(isinstance(ids, list) and len(ids) <= 10 and len(set(ids)) == len(ids)
             and all(cid in by_id and (row['mode'] == 'combined'
                     or by_id[cid]['source_role'] == 'documentation') for cid in ids),
             'INVALID_ADMISSION_RANK_DOMAIN')
        unknown = any(r['status'] != 'RESOLVED' for r in resolved)
        for requirement in resolved:
            requirement['coverage'] = {str(k): [bool(set(ids[:k]).intersection(unit))
                for unit in requirement['units']] for k in (5, 10)}
        hits = {str(k): not unknown and all(set(ids[:k]).intersection(unit)
                    for r in resolved for unit in r['units']) for k in (5, 10)}
        result[key] = {'id': row['id'], 'mode': row['mode'], 'critical': ref['critical'],
            'primary': row['primary_score_eligible'], 'unknown': unknown,
            'hits': hits, 'requirements': resolved}
    return result
