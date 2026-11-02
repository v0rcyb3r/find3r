"""Observed titles support hypotheses, never a buying-authority assertion."""
import copy

import pytest

from neesha.harness.power_map import build_power_map


def role(name, title, fid='role-1', **extra):
    return {'subject':name,'attribute':'person.role','value':title,'fact_id':fid,
            'source_record_id':'record-'+fid,'source':'company-web','confidence':'high',
            'source_url':'https://acme.com/team','origin_url':'https://acme.com/',**extra}


@pytest.mark.parametrize('title,expected',[
    ('Security Engineer','technical evaluator'),('Infrastructure Architect','technical evaluator'),
    ('CISO','security owner'),('Chief Information Security Officer','security owner'),
    ('Director of Information Security','security owner'),('Head of Cybersecurity','security owner'),
    ('CTO','technology leadership'),('Director of IT','technology leadership'),
    ('Chief Information Officer','technology leadership'),('Procurement Director','procurement'),
    ('Strategic Sourcing Manager','procurement'),('CFO','finance'),('Head of Finance','finance'),
])
def test_explicit_title_rules_are_low_confidence_inferences(title,expected):
    mapping,=build_power_map([role('Dana Ops',title)])
    assert mapping['possible_involvement']==[expected]
    assert mapping['is_inference'] is True
    assert mapping['confidence']=='low'
    assert mapping['admiralty']=='C3'
    assert mapping['evidence_ids']==['role-1']
    assert mapping['source_record_ids']==['record-role-1']
    assert 'inference' in mapping['flags']
    assert 'does not prove buying authority' in mapping['rationale']
    assert 'reporting line' in mapping['rationale']


@pytest.mark.parametrize('title',[
    'CEO','Director','Chief of Staff','Founder','Customer Success Manager',
    'Former CISO','Retired CTO','Executive Assistant to CFO','Sales Engineer',
    'Security Intern','Talent Sourcing Director','Marketing Director','CISO Advisor',
])
def test_unknown_and_noncurrent_titles_have_no_buying_claim(title):
    assert build_power_map([role('Dana Ops',title)])==[]


def test_grouping_deduplication_and_multiple_roles_keep_only_role_evidence():
    rows=[role('Dana Ops','CISO','a'),role('Dana Ops','CISO','b'),
          role('Dana Ops','Head of Procurement','c'),role('Dana Ops','Founder','d'),
          {**role('Dana Ops','dana@acme.com','email'),'attribute':'person.business_email'}]
    mapping,=build_power_map(rows)
    assert mapping['observed_roles']==['CISO','Head of Procurement']
    assert mapping['possible_involvement']==['security owner','procurement']
    assert mapping['evidence_ids']==['a','b','c']
    assert mapping['confidence']=='low'


def test_output_is_deterministic_and_input_is_unchanged():
    rows=[role('Zoe','CFO','z'),role('Alice','CISO','a')]
    original=copy.deepcopy(rows)
    assert build_power_map(rows)==build_power_map(list(reversed(rows)))
    assert [m['subject'] for m in build_power_map(rows)]==['Alice','Zoe']
    assert rows==original


def test_unprovenanced_unknown_confidence_and_inferred_roles_are_excluded():
    inputs=[role('No Source','CISO',source_record_id=''),role('No Fact','CFO',fact_id=''),
            role('Unknown','CFO',confidence='unknown'),role('Inferred','CISO',flags=['inference']),
            role('Inferred Again','CISO',is_inference=True),None,{}]
    assert build_power_map(inputs)==[]


def test_no_reporting_lines_or_personal_traits_are_generated():
    mappings=build_power_map([role('Alice','CISO','a'),role('Bob','CFO','b')])
    assert len(mappings)==2
    forbidden={'reports_to','manager','buyer','budget_owner','personality','vulnerability'}
    assert not any(forbidden & set(m) for m in mappings)
