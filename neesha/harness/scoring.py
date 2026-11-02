"""Explained weighted signals, with unknown coverage kept separate from scores.

These are transparent analyst aids, not exploitability estimates, an overall
security-posture rating, or a prediction that an organization will buy.
"""
from __future__ import annotations

import math
import re

_HEADERS = (
    'strict-transport-security', 'content-security-policy', 'x-content-type-options',
    'x-frame-options', 'referrer-policy', 'permissions-policy',
)
_ATTRIBUTE = re.compile(r'[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+')


def _observations(facts):
    rows = {}
    for fact in facts:
        if not isinstance(fact, dict) or fact.get('is_inference') is True:
            continue
        flags = fact.get('flags') or []
        if not isinstance(flags, list) or 'inference' in flags or fact.get('confidence') == 'unknown':
            continue
        if any(not isinstance(fact.get(k), str) or not fact[k].strip()
               for k in ('attribute', 'value', 'fact_id', 'source_record_id')):
            continue
        rows[fact['fact_id']] = fact
    return list(rows.values())


def _criterion(identifier, label, attribute, weight, rows, points, reason, **extra):
    return {
        'id': identifier, 'label': label, 'attribute': attribute, 'weight': weight,
        'status': 'assessed' if points is not None else 'unknown',
        'observed_values': sorted({r['value'] for r in rows}),
        'points': points, 'contribution': None,
        'evidence_ids': sorted({r['fact_id'] for r in rows}),
        'source_record_ids': sorted({r['source_record_id'] for r in rows}),
        'explanation': reason, **extra,
    }


def _summarize(criteria, explanation):
    total_weight = math.fsum(c['weight'] for c in criteria)
    assessed_weight = math.fsum(c['weight'] for c in criteria if c['points'] is not None)
    if assessed_weight:
        for criterion in criteria:
            if criterion['points'] is not None:
                criterion['contribution'] = round(criterion['weight'] * criterion['points'] / assessed_weight, 4)
        score = round(math.fsum(c['weight'] * c['points'] for c in criteria
                              if c['points'] is not None) / assessed_weight, 1)
    else:
        score = None
    return {
        'score': score,
        'coverage': round(100 * assessed_weight / total_weight, 1) if total_weight else 0.0,
        'assessed_weight': assessed_weight, 'total_weight': total_weight,
        'assessed_count': sum(c['points'] is not None for c in criteria),
        'criteria_count': len(criteria), 'criteria': criteria,
        'unknowns': [{'id': c['id'], 'reason': c['explanation']}
                     for c in criteria if c['points'] is None],
        'explanation': explanation,
    }


def _security(rows):
    criteria = []
    for identifier, label, attribute, weight, mapping, explanations in (
        ('dmarc_policy', 'Published DMARC policy', 'email.dmarc.policy', 3.0,
         {'none': 100, 'quarantine': 50, 'reject': 0},
         {'none': 'The observed policy requests monitoring, not quarantine or rejection.',
          'quarantine': 'The observed policy requests quarantine rather than rejection.',
          'reject': 'The observed policy requests rejection; no need signal is assigned on this criterion.'}),
        ('spf_qualifier', 'Published SPF all qualifier', 'email.spf.qualifier', 2.0,
         {'+all': 100, '~all': 50, '-all': 0},
         {'+all': 'The observed +all mechanism permits all senders.',
          '~all': 'The observed ~all mechanism is a soft-fail signal rather than a hard fail.',
          '-all': 'The observed -all mechanism requests a hard fail; no need signal is assigned on this criterion.'}),
    ):
        matching = [r for r in rows if r['attribute'] == attribute]
        values = {r['value'].strip().lower() for r in matching}
        if len(values) == 1 and next(iter(values)) in mapping:
            value = next(iter(values))
            points, reason = mapping[value], explanations[value]
            reason += ' This describes the published record, not actual receiver behavior or exploitability.'
        else:
            points = None
            reason = ('No observed record is available; this is unknown, not a missing control.' if not values
                      else 'Conflicting or unsupported observed values require analyst review; no score is assigned.')
        criteria.append(_criterion(identifier, label, attribute, weight, matching, points, reason))
    for header in _HEADERS:
        attribute = 'http.security_header.' + header
        matching = [r for r in rows if r['attribute'] == attribute]
        criteria.append(_criterion(
            'header_' + header.replace('-', '_'), 'Observed ' + header, attribute, 1.0,
            matching, 0 if matching else None,
            ('This header was observed. Presence alone does not establish correct configuration or effective protection.'
             if matching else 'No observation is available. An uncollected header is not assumed absent or vulnerable.'),
        ))
    result = _summarize(criteria,
        'Higher values indicate stronger observed signals of potential security needs on assessed criteria only. '
        'Weights are transparent product rules, not a scientifically calibrated risk model. '
        'Coverage is separate: a low score with sparse coverage does not establish good security. '
        'This is not an exploitability score or an overall posture rating.')
    result['configured'] = True
    result['direction'] = 'higher means stronger observed potential-need signals'
    return result


def _text(value, field, *, required=True):
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        raise ValueError(f'{field} must be a nonempty string of at most 200 characters.')
    return value.strip()


def _validate_profile(profile):
    if not isinstance(profile, dict) or set(profile) - {'name', 'services', 'criteria'}:
        raise ValueError('Commercial profile fields must be name, services, and criteria only.')
    name = _text(profile.get('name'), 'profile name', required=False)
    services = profile.get('services', [])
    if not isinstance(services, list) or len(services) > 100:
        raise ValueError('services must be a list of at most 100 names.')
    services = [_text(service, 'service') for service in services]
    criteria = profile.get('criteria', [])
    if not isinstance(criteria, list) or len(criteria) > 100:
        raise ValueError('criteria must be a list of at most 100 criteria.')
    normalized, ids = [], set()
    for criterion in criteria:
        allowed = {'id', 'label', 'service', 'attribute', 'weight', 'equals', 'contains'}
        if not isinstance(criterion, dict) or set(criterion) - allowed:
            raise ValueError('Unknown commercial criterion field.')
        identifier = _text(criterion.get('id'), 'criterion id')
        if identifier in ids:
            raise ValueError('Commercial criterion ids must be unique.')
        ids.add(identifier)
        attribute = _text(criterion.get('attribute'), 'attribute')
        if not _ATTRIBUTE.fullmatch(attribute):
            raise ValueError('Commercial attribute must be a dotted fact attribute.')
        operators = set(criterion) & {'equals', 'contains'}
        if len(operators) != 1:
            raise ValueError('Each commercial criterion must define exactly one of equals or contains.')
        operator = next(iter(operators))
        expected = _text(criterion[operator], operator)
        weight = criterion.get('weight')
        if isinstance(weight, bool) or not isinstance(weight, (int, float)):
            raise ValueError('Criterion weight must be a finite number greater than zero and at most 1000.')
        if not 0 < weight <= 1000 or not math.isfinite(weight):
            raise ValueError('Criterion weight must be a finite number greater than zero and at most 1000.')
        service = _text(criterion.get('service'), 'criterion service', required=False)
        if service is not None and services and service not in services:
            raise ValueError('Criterion service must be present in configured services.')
        normalized.append({'id': identifier, 'label': _text(criterion.get('label', identifier), 'criterion label'),
                           'attribute': attribute, 'weight': float(weight),
                           'operator': operator, 'expected': expected, 'service': service})
    return name, services, normalized


def _commercial(rows, profile):
    if profile is None:
        result = _summarize([], 'Commercial fit is not configured. No ideal customer or service preference has been assumed.')
        result.update(configured=False, profile_name=None, services=[], direction='higher means stronger configured criterion matches')
        return result
    name, services, configured = _validate_profile(profile)
    criteria = []
    for rule in configured:
        matching = [r for r in rows if r['attribute'] == rule['attribute']]
        if not matching:
            points, reason = None, 'No observation for this configured attribute; fit is unknown, not zero.'
        else:
            expected = rule['expected'].casefold()
            matched = any((r['value'].strip().casefold() == expected if rule['operator'] == 'equals'
                           else expected in r['value'].casefold()) for r in matching)
            points = 100 if matched else 0
            reason = ('An observed value matches the configured criterion.' if matched
                      else 'The observed values do not match this criterion. This does not establish a complete inventory.')
        criteria.append(_criterion(rule['id'], rule['label'], rule['attribute'], rule['weight'],
            matching, points, reason, operator=rule['operator'], expected=rule['expected'], service=rule['service']))
    result = _summarize(criteria,
        'Fit measures only the configured service criteria against observed attributes. '
        'It is normalized over assessed criteria; missing observations remain unknown and reduce coverage. '
        'It does not predict purchase intent or buying authority.')
    result.update(configured=True, profile_name=name, services=services,
                  direction='higher means stronger configured criterion matches')
    return result


def score_brief(facts: list[dict], profile=None) -> dict:
    """Score guarded observed facts without network/model calls or inferred gaps.

    Commercial profile schema: {name?, services?:[str], criteria:[
      {id, label?, service?, attribute, weight, exactly one of equals|contains:str}
    ]}. Matching is case-insensitive. Weights must be finite, 0 < weight <= 1000.
    Security weights: DMARC=3, SPF=2, each of six observed headers=1.
    """
    rows = _observations(facts)
    return {'commercial_fit': _commercial(rows, profile), 'security_needs': _security(rows)}
