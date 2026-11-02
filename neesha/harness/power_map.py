"""Conservative professional-role hypotheses from already guarded observations.

This is a title-based aid for an analyst, not an organization chart or a list
of established buyers. It performs no collection and derives no personal traits.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict

from neesha.evidence.models import Evidence
from neesha.guardrail.engine import Guardrail

# Use bounded, explicit professional-title patterns. A broad "director" or
# "chief" rule would turn virtually any senior title into a buying claim.
_RULES = (
    ('technical evaluator', re.compile(
        r'\b(?:security|cybersecurity|information security|network|infrastructure|systems?|it)\s+'
        r'(?:engineer|architect|analyst|administrator|admin)\b|\bsysadmin\b')),
    ('security owner', re.compile(
        r'\bciso\b|\bchief (?:information |cyber)?security officer\b|'
        r'\b(?:head|director|manager|vp|vice president) (?:of )?(?:information |cyber)?security\b|'
        r'\b(?:information |cyber)?security (?:head|director|manager|lead)\b|'
        r'\b(?:head|director|manager|vp|vice president) (?:of )?cybersecurity\b')),
    ('technology leadership', re.compile(
        r'\b(?:cto|cio)\b|\bchief (?:technology|information) officer\b|'
        r'\b(?:head|director|vp|vice president) (?:of )?(?:it|technology|information technology|infrastructure)\b|'
        r'\b(?:it|technology|information technology|infrastructure) director\b')),
    ('procurement', re.compile(r'\b(?:procurement|purchasing|strategic sourcing|vendor management)\b')),
    ('finance', re.compile(
        r'\bcfo\b|\bchief financial officer\b|\bfinancial controller\b|'
        r'\b(?:head|director|vp|vice president) (?:of )?finance\b|\bfinance director\b')),
)
_EXCLUDED = re.compile(
    r'\b(?:former|retired|intern|student|sales|marketing|recruiter|recruitment|talent|advisor|adviser)\b|'
    r'\bex[- ]|\b(?:assistant|executive assistant) to\b'
)
RATIONALE = (
    'Possible involvement is inferred only from published professional titles. '
    'A title does not prove buying authority, budget ownership, a reporting line, '
    'or involvement in this particular decision; an analyst must verify it.'
)


def _clean_title(value: str) -> str:
    return ' '.join(re.sub(r'[^a-z0-9]+', ' ', value.casefold()).split())


def build_power_map(facts: list[dict]) -> list[dict]:
    """Return one inference entry per person with a recognized observed role.

    Input is the brief's guarded *facts* list, not raw provider output. Required
    role fields: attribute='person.role', subject, value, fact_id, and
    source_record_id. Output keeps underlying role IDs and observed titles;
    unknown titles and unprovenanced rows produce no mapping. Confidence is
    deliberately low even when a person's title is independently corroborated:
    confirmed employment is not confirmed purchasing involvement.
    """
    people: dict[str, list[dict]] = defaultdict(list)
    for fact in facts:
        if not isinstance(fact, dict) or fact.get('attribute') != 'person.role':
            continue
        if fact.get('is_inference') is True or 'inference' in fact.get('flags', []):
            continue
        required = ('subject', 'value', 'fact_id', 'source_record_id')
        if any(not isinstance(fact.get(key), str) or not fact[key].strip() for key in required):
            continue
        if fact.get('confidence') == 'unknown':
            continue
        people[fact.get('entity_id') or fact['subject']].append(fact)

    result = []
    for identity in sorted(people, key=str.casefold):
        observations = people[identity]
        subject = observations[0]['subject']
        matches = defaultdict(list)
        for observation in observations:
            title = _clean_title(observation['value'])
            if _EXCLUDED.search(title):
                continue
            for involvement, pattern in _RULES:
                if pattern.search(title):
                    matches[involvement].append(observation)
        if not matches:
            continue
        supporting = {row['fact_id']: row for rows in matches.values() for row in rows}
        ids = sorted(supporting)
        categories = [name for name, _ in _RULES if name in matches]
        claim = hashlib.sha256(json.dumps([subject, categories], ensure_ascii=False).encode()).hexdigest()
        inference_evidence = []
        for row in supporting.values():
            # Source type denotes this derived analysis, not a claim that a
            # provider directly established decision-making responsibility.
            inference_evidence.append(Evidence(
                evidence_id=row['fact_id'], target_id=subject, entity_id=subject,
                claim=claim, source_type='osint', source_url=row.get('source_url'),
                origin_url=row.get('origin_url') or 'record:' + row['source_record_id'],
                collection_mode='passive', collector=str(row.get('source') or 'role-observation'),
                agent='role-map', scope_id='derived-from-guarded-brief',
                confidence='low', is_inference=True,
                flags=['title-based-inference', 'buying-authority-unverified'],
            ))
        verdicts = Guardrail.apply(inference_evidence, strict=True).survived()
        if not verdicts:
            continue
        kept = {v.evidence_id for v in verdicts}
        ids = [value for value in ids if value in kept]
        result.append({
            'subject': subject,
            'entity_id': observations[0].get('entity_id'),
            'observed_roles': sorted({supporting[value]['value'] for value in ids}),
            'possible_involvement': categories,
            'is_inference': True,
            'confidence': 'low',
            'admiralty': 'C3',
            'evidence_ids': ids,
            'source_record_ids': sorted({supporting[value]['source_record_id'] for value in ids}),
            'rationale': RATIONALE,
            'flags': sorted({flag for verdict in verdicts for flag in verdict.flags}),
        })
    return result
