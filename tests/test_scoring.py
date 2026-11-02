"""Explained scores assess observations; missing data is never a vulnerability."""
import copy
import math

import pytest

from neesha.harness.scoring import score_brief


def fact(attribute,value,fid='f1',**extra):
    return {'attribute':attribute,'value':value,'fact_id':fid,'source_record_id':'s-'+fid,
            'confidence':'medium',**extra}


def profile(*criteria):
    return {'name':'Email services','services':['Email security'],'criteria':list(criteria)}


def rule(identifier='r1',attribute='company.industry',weight=1,**extra):
    return {'id':identifier,'attribute':attribute,'weight':weight,'equals':'Healthcare',**extra}


def test_unconfigured_commercial_and_no_security_data_have_null_scores():
    scores=score_brief([])
    assert scores['commercial_fit']['score'] is None
    assert scores['commercial_fit']['configured'] is False
    security=scores['security_needs']
    assert security['score'] is None
    assert security['coverage']==0
    assert len(security['unknowns'])==8
    assert security['assessed_weight']==0
    assert 'not an exploitability score' in security['explanation']


@pytest.mark.parametrize('attribute,value,expected',[
    ('email.dmarc.policy','none',100),('email.dmarc.policy','quarantine',50),
    ('email.dmarc.policy','reject',0),('email.spf.qualifier','+all',100),
    ('email.spf.qualifier','~all',50),('email.spf.qualifier','-all',0),
])
def test_known_security_signals_explain_and_link_each_contribution(attribute,value,expected):
    security=score_brief([fact(attribute,value)])['security_needs']
    assert security['score']==expected
    assert 0<security['coverage']<100
    assessed=[c for c in security['criteria'] if c['status']=='assessed']
    assert len(assessed)==1
    assert assessed[0]['evidence_ids']==['f1']
    assert assessed[0]['source_record_ids']==['s-f1']
    assert assessed[0]['contribution']==expected
    assert assessed[0]['explanation']


def test_weighted_security_score_normalizes_only_assessed_criteria():
    security=score_brief([fact('email.dmarc.policy','none','d'),
        fact('email.spf.qualifier','-all','s'),
        fact('http.security_header.x-frame-options','DENY','h')])['security_needs']
    # Weights 3 (100) + 2 (0) + 1 (0), not divided by all 11 possible weights.
    assert security['score']==50
    assert security['assessed_weight']==6
    assert security['total_weight']==11
    assert security['coverage']==54.5
    assert math.isclose(sum(c['contribution'] or 0 for c in security['criteria']),50)


@pytest.mark.parametrize('attribute,value',[
    ('email.dmarc.policy','unsupported'),('email.spf.qualifier','?all'),
    ('http.status','200'),('dns.a','203.0.113.1'),
])
def test_unsupported_or_unrelated_observations_do_not_create_need(attribute,value):
    assert score_brief([fact(attribute,value)])['security_needs']['score'] is None


def test_conflicting_policy_is_unknown_with_conflicting_evidence_links():
    security=score_brief([fact('email.dmarc.policy','none','one'),
                         fact('email.dmarc.policy','reject','two')])['security_needs']
    dmarc=security['criteria'][0]
    assert security['score'] is None
    assert dmarc['status']=='unknown'
    assert dmarc['evidence_ids']==['one','two']
    assert 'Conflicting' in dmarc['explanation']


def test_observed_header_presence_is_not_a_configuration_verdict():
    security=score_brief([fact('http.security_header.content-security-policy',"default-src *")])['security_needs']
    header=next(c for c in security['criteria'] if c['status']=='assessed')
    assert security['score']==0
    assert security['coverage']==9.1
    assert 'does not establish correct configuration' in header['explanation']
    assert len(security['unknowns'])==7


def test_inferred_unprovenanced_and_empty_values_never_contribute():
    rows=[fact('email.dmarc.policy','none',is_inference=True),
          fact('email.spf.qualifier','+all','two',flags=['inference']),
          fact('email.dmarc.policy','none','three',source_record_id=''),
          fact('email.dmarc.policy','none','four',confidence='unknown'),
          fact('http.security_header.x-frame-options','   ','five'),None]
    assert score_brief(rows)['security_needs']['score'] is None


def test_commercial_weighting_configuration_and_missing_coverage_are_explicit():
    configured=profile(rule(weight=3,service='Email security'),
        rule('r2','company.region',1,equals='Europe'),
        rule('r3','company.size',6,equals='Enterprise'))
    rows=[fact('company.industry','Healthcare','industry'),fact('company.region','US','region')]
    fit=score_brief(rows,configured)['commercial_fit']
    assert fit['score']==75
    assert fit['coverage']==40
    assert fit['assessed_weight']==4
    assert fit['total_weight']==10
    assert fit['unknowns'][0]['id']=='r3'
    assert [c['contribution'] for c in fit['criteria']]==[75,0,None]
    assert fit['criteria'][0]['evidence_ids']==['industry']
    assert fit['criteria'][1]['evidence_ids']==['region']
    assert fit['services']==['Email security']


def test_missing_commercial_attributes_are_unknown_not_zero_fit():
    fit=score_brief([],profile(rule()))['commercial_fit']
    assert fit['score'] is None
    assert fit['configured'] is True
    assert fit['coverage']==0
    assert fit['criteria'][0]['points'] is None
    assert 'unknown, not zero' in fit['unknowns'][0]['reason']


def test_commercial_contains_is_case_insensitive_and_any_observed_match_counts():
    configured=profile({'id':'security','attribute':'person.role','contains':'security','weight':2})
    rows=[fact('person.role','CFO','one'),fact('person.role','Information Security Director','two')]
    fit=score_brief(rows,configured)['commercial_fit']
    assert fit['score']==100
    assert fit['coverage']==100
    assert fit['criteria'][0]['evidence_ids']==['one','two']


@pytest.mark.parametrize('weight',[0,-1,1001,float('nan'),float('inf'),-float('inf'),True,'1',None])
def test_invalid_weights_are_rejected(weight):
    with pytest.raises(ValueError,match='weight'):
        score_brief([],profile(rule(weight=weight)))


@pytest.mark.parametrize('configured',[
    {'unknown':'field'},
    {'criteria':[{'id':'bad','attribute':'company.industry','weight':1,'execute':'anything','equals':'test'}]},
    {'criteria':[{'id':'bad','attribute':'company.industry','weight':1}]},
    {'criteria':[rule(contains='also')]},
    {'criteria':[rule(attribute='not_dotted')]},
    {'criteria':[rule(),rule()]},
    {'services':['Email security'],'criteria':[rule(service='Unconfigured service')]},
    {'criteria':'not a list'},
    {'services':'not a list'},
])
def test_invalid_profile_fields_and_operators_are_rejected(configured):
    with pytest.raises(ValueError):
        score_brief([],configured)


def test_scoring_is_deterministic_does_not_mutate_and_deduplicates_fact_ids():
    rows=[fact('email.dmarc.policy','none'),fact('email.dmarc.policy','none')]
    configured=profile(rule())
    original=(copy.deepcopy(rows),copy.deepcopy(configured))
    first=score_brief(rows,configured)
    assert first==score_brief(list(reversed(rows)),configured)
    assert (rows,configured)==original
    assert first['security_needs']['criteria'][0]['evidence_ids']==['f1']


# ---- step 3: confirmed absence is a graded need signal ------------------


@pytest.mark.parametrize('attribute', ['email.dmarc.policy', 'email.spf.qualifier'])
def test_confirmed_absence_of_email_auth_is_the_strongest_need(attribute):
    """An observed 'absent' record is the top need signal, not an unknown. A
    domain that publishes nothing must not look better-covered than one that
    publishes a weak policy."""
    security = score_brief([fact(attribute, 'absent')])['security_needs']
    criterion = next(c for c in security['criteria'] if c['status'] == 'assessed')
    assert security['score'] == 100
    assert criterion['points'] == 100
    assert criterion['evidence_ids'] == ['f1']
    assert 'No ' in criterion['explanation']


def test_absent_dmarc_outscores_enforced_dmarc():
    absent = score_brief([fact('email.dmarc.policy', 'absent')])['security_needs']['score']
    enforced = score_brief([fact('email.dmarc.policy', 'reject')])['security_needs']['score']
    assert absent > enforced


def test_missing_header_is_a_need_only_once_the_page_was_assessed():
    # No scan marker: a header we never looked for stays unknown, not a need.
    unknown = score_brief([fact('email.dmarc.policy', 'reject')])['security_needs']
    hsts = next(c for c in unknown['criteria']
                if c['attribute'] == 'http.security_header.strict-transport-security')
    assert hsts['points'] is None

    # The website was fetched: an absent header is now an observed need, while
    # a present one remains a non-verdict at zero need.
    assessed = score_brief([
        fact('http.security_assessed', 'true', 'scan'),
        fact('http.security_header.content-security-policy', "default-src 'self'", 'csp'),
    ])['security_needs']
    by_attr = {c['attribute']: c for c in assessed['criteria']}
    assert by_attr['http.security_header.content-security-policy']['points'] == 0
    assert by_attr['http.security_header.strict-transport-security']['points'] == 100
    # All six header criteria are now assessed rather than unknown.
    assert sum(c['points'] is not None for c in assessed['criteria']
               if c['attribute'].startswith('http.security_header.')) == 6
