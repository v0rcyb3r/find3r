"""Identifier classification never turns a clue into an identity assertion."""
import pytest

from neesha.resolve.intake import resolve_seed


@pytest.mark.parametrize('value,kind,normalized,domain',[
    ('Example.COM.','domain','example.com','example.com'),
    ('bücher.de','domain','xn--bcher-kva.de','xn--bcher-kva.de'),
    ('https://BÜCHER.de/team?session=secret#token','website','https://xn--bcher-kva.de/team','xn--bcher-kva.de'),
    ('https://example.com','website','https://example.com/','example.com'),
])
def test_domain_and_website_research_starting_points(value,kind,normalized,domain):
    result=resolve_seed(value)
    assert result['kind']==kind
    assert result['normalized']==normalized
    assert result['domain']==domain
    assert result['requires_resolution'] is False
    assert result['domain_is_candidate'] is False
    assert 'secret' not in result['normalized']


def test_corporate_email_domain_is_only_a_research_candidate():
    result=resolve_seed('Dana.Ops+Research@ACME.COM')
    assert result['kind']=='email'
    assert result['normalized']=='Dana.Ops+Research@acme.com'
    assert result['domain'] is None
    assert result['candidate_domains']==['acme.com']
    assert result['domain_is_candidate'] is True
    assert result['requires_resolution'] is False
    assert 'does not identify a named person' in result['reason']
    assert 'person' not in result and 'company' not in result


@pytest.mark.parametrize('provider',['gmail.com','outlook.com','proton.me','yahoo.co.uk','icloud.com','hotmail.com','mail.gmail.com'])
def test_public_mailbox_does_not_become_an_organization(provider):
    result=resolve_seed('someone@'+provider)
    assert result['kind']=='email'
    assert result['domain'] is None
    assert result['candidate_domains']==[]
    assert result['requires_resolution'] is False


@pytest.mark.parametrize('value',['Dana Ops','Acme Corporation','Acme Inc.','Jordan','Studio 54'])
def test_auto_names_remain_ambiguous(value):
    result=resolve_seed(value)
    assert result['kind']=='name'
    assert result['domain'] is None
    assert result['requires_resolution'] is True
    assert not result['candidate_domains']


@pytest.mark.parametrize('kind,expected_unresolved',[('person',False),('company',False),('name',True)])
def test_explicit_name_types_are_runnable_while_bare_name_needs_type(kind,expected_unresolved):
    result=resolve_seed('  Dana   Ops  ',kind)
    assert result['kind']==kind
    assert result['normalized']=='Dana Ops'
    assert result['requires_resolution'] is expected_unresolved


@pytest.mark.parametrize('value,normalized',[
    ('8.8.8.8','8.8.8.8'),('2001:4860:4860:0000:0000:0000:0000:8888','2001:4860:4860::8888'),
    ('127.0.0.1','127.0.0.1'),
])
def test_ips_are_recognized_without_company_ownership(value,normalized):
    result=resolve_seed(value)
    assert result['kind']=='ip'
    assert result['normalized']==normalized
    assert result['requires_resolution'] is False
    assert result['domain'] is None


@pytest.mark.parametrize('value,normalized',[('+1 (212) 555-0199','+12125550199'),('212-555-0199','2125550199')])
def test_phones_are_normalized_without_country_or_subscriber_guess(value,normalized):
    result=resolve_seed(value)
    assert result['kind']==normalized and False or result['kind']=='phone'
    assert result['normalized']==normalized
    assert result['domain'] is None
    assert result['requires_resolution'] is False


@pytest.mark.parametrize('value,kind',[
    ('','auto'),('user@@acme.com','auto'),('.user@acme.com','email'),('a..b@acme.com','email'),
    ('person@localhost','email'),('name@-acme.com','email'),('name@example.com/path','email'),
    ('123','phone'),('+1234567890123456','phone'),('+1-call-me','phone'),
    ('ftp://example.com','auto'),('https://user:secret@example.com','auto'),
    ('https://127.0.0.1/admin','auto'),('http://169.254.169.254/latest','auto'),
    ('http://[::1]','website'),('https://example.com:bad/','website'),
    ('example.com/path','domain'),('127.0.0.1','domain'),('bad\nname','auto'),
])
def test_invalid_inputs_and_unsafe_website_literals_are_rejected(value,kind):
    with pytest.raises(ValueError):
        resolve_seed(value,kind)


def test_public_ip_website_is_not_guessed_to_be_a_company_domain():
    result=resolve_seed('https://8.8.8.8/path?secret=token')
    assert result['kind']=='website'
    assert result['requires_resolution'] is True
    assert result['domain'] is None
    assert result['normalized']=='https://8.8.8.8/path'


def test_unknown_kind_and_nonstrings_reject():
    with pytest.raises(ValueError):resolve_seed('acme.com','unknown')
    with pytest.raises(ValueError):resolve_seed(None)


def test_parenthesized_phone_and_invalid_dotted_quad():
    assert resolve_seed('(212) 555-0199')['normalized']=='2125550199'
    with pytest.raises(ValueError):resolve_seed('256.256.256.256')
    with pytest.raises(ValueError):resolve_seed('(212 555-0199','phone')
