"""Runtime role boundaries and reserve-before-spend, with no live model calls."""
import json
from decimal import Decimal

import pytest
import sqlalchemy as sa

from neesha.db import schema
from neesha.ledger.ledger import Ledger
from neesha.runtime import investigation as runtime
from neesha.runtime.providers import ProviderError


@pytest.fixture
def configured(engine, monkeypatch):
    for name, key in [('openai', 'OPENAI_API_KEY'), ('anthropic', 'ANTHROPIC_API_KEY'),
                      ('google', 'GEMINI_API_KEY'), ('deepseek', 'DEEPSEEK_API_KEY')]:
        monkeypatch.setenv(key, 'fixture-secret-' + name)
        monkeypatch.setenv(f'NEESHA_{name.upper()}_MODEL', 'explicit-model')
        monkeypatch.setenv(f'NEESHA_{name.upper()}_CALL_CAP_USD', '0.10')
    Ledger(engine).set_cap('10')


def fact(identifier='infra1', attribute='dns.subdomain', value='mail.example.com'):
    return {'fact_id': identifier, 'source_record_id': 'source-' + identifier,
            'subject': 'example.com', 'attribute': attribute, 'value': value,
            'raw_payload': 'DO NOT TRANSMIT RAW DOCUMENTS', 'confidence': 'medium'}


@pytest.fixture
def brief():
    return {'run_id': 'run-fixture', 'company': 'example.com',
            'facts': [fact(), fact('person1', 'person.role', 'Security Director')],
            'raw_documents': ['NEVER SEND THESE'], 'api_key': 'NEVER SEND THIS'}


def ledger_rows(engine):
    with engine.connect() as conn:
        return conn.execute(sa.select(schema.ledger).order_by(schema.ledger.c.id)).mappings().all()


def fake_provider(monkeypatch, engine, behavior=None):
    calls = []
    class FakeProvider:
        def __init__(self, config):
            self.config = config
        def generate(self, system, payload):
            calls.append((self.config.name, system, payload))
            assert any(row['state'] == 'reserved' for row in ledger_rows(engine))
            if behavior:
                return behavior(self.config.name, system, payload)
            identifier = payload['facts'][0]['fact_id']
            return json.dumps({'claims': [{'text': 'Tentative conclusion for review.',
                                          'evidence_ids': [identifier]}]})
    monkeypatch.setattr(runtime, 'Provider', FakeProvider)
    return calls


def test_single_analysis_is_cited_labeled_and_metered(engine, monkeypatch, configured, brief):
    calls = fake_provider(monkeypatch, engine)
    result = runtime.analyze_brief(engine, brief, 'single', ['openai'])
    assert result['status'] == 'complete'
    assert Decimal(result['spend_usd']) == Decimal('0.10')
    assert len(calls) == 1
    assert calls[0][2]['role'] == 'synthesis'
    claim = result['claims'][0]
    assert claim['evidence_ids'] == ['infra1']
    assert claim['source_record_ids'] == ['source-infra1']
    assert claim['is_inference'] and claim['human_review_required']
    assert claim['confidence'] == 'low'
    assert claim['retrieved_by'] == {'provider': 'openai', 'model': 'explicit-model'}
    assert ledger_rows(engine)[0]['state'] == 'settled'
    assert ledger_rows(engine)[0]['actual_usd'] == Decimal('0.10')
    assert 'fixture-secret' not in json.dumps(result)


def test_multi_specialists_are_bounded_and_reviewer_receives_proposals(
    engine, monkeypatch, configured, brief
):
    reservation_counts = []
    def behavior(name, system, payload):
        reservation_counts.append(sum(r['state'] == 'reserved' for r in ledger_rows(engine)))
        role = payload['role']
        attributes = {f['attribute'] for f in payload['facts']}
        if role == 'infrastructure_specialist':
            assert attributes == {'dns.subdomain'}
        elif role == 'company_specialist':
            assert attributes == {'person.role'}
        else:
            assert role == 'reviewer'
            assert len(payload['specialist_proposals']) == 2
            assert attributes == {'dns.subdomain', 'person.role'}
        return json.dumps({'claims': [{'text': 'Tentative ' + role,
            'evidence_ids': [payload['facts'][0]['fact_id']]}]})
    calls = fake_provider(monkeypatch, engine, behavior)
    result = runtime.analyze_brief(engine, brief, 'multi', ['openai', 'anthropic'])
    assert result['status'] == 'complete'
    assert len(calls) == 3
    assert [c[0] for c in calls] == ['openai', 'anthropic', 'openai']
    assert reservation_counts == [3, 2, 1]
    assert len(result['reports']) == 3
    assert Decimal(result['spend_usd']) == Decimal('0.30')
    assert all(row['state'] == 'settled' for row in ledger_rows(engine))
    assert 'reviewer' in result['claims'][0]['text']


def test_three_provider_mode_assigns_third_as_reviewer(engine, monkeypatch, configured, brief):
    calls = fake_provider(monkeypatch, engine)
    runtime.analyze_brief(engine, brief, 'multi', ['openai', 'anthropic', 'google'])
    assert [c[0] for c in calls] == ['openai', 'anthropic', 'google']


@pytest.mark.parametrize('mode,names', [('single', []), ('single', ['openai', 'google']),
    ('multi', ['openai']), ('multi', ['openai', 'openai']),
    ('multi', ['openai', 'anthropic', 'google', 'deepseek']), ('bad', ['openai']),
    ('single', 'openai'), ('single', ['https://evil.example'])])
def test_invalid_plan_fails_before_reservation(engine, configured, brief, mode, names):
    with pytest.raises(runtime.RuntimeAnalysisError):
        runtime.analyze_brief(engine, brief, mode, names)
    assert ledger_rows(engine) == []


def test_total_cap_is_checked_before_any_model_call(engine, monkeypatch, configured, brief):
    calls = fake_provider(monkeypatch, engine)
    with pytest.raises(runtime.RuntimeAnalysisError, match='exceed'):
        runtime.analyze_brief(engine, brief, 'multi', ['openai', 'anthropic'], Decimal('0.29'))
    assert calls == []
    assert ledger_rows(engine) == []


def test_partial_reservations_are_released_if_monthly_budget_insufficient(
    engine, monkeypatch, configured, brief
):
    Ledger(engine).set_cap('0.15')
    calls = fake_provider(monkeypatch, engine)
    with pytest.raises(runtime.RuntimeAnalysisError, match='monthly budget'):
        runtime.analyze_brief(engine, brief, 'multi', ['openai', 'anthropic'])
    assert calls == []
    assert all(r['state'] == 'released' for r in ledger_rows(engine))
    assert Ledger(engine).summary().committed_usd == 0


@pytest.mark.parametrize('raw', [
    'not json',
    '{"claims":[{"text":"Unsupported","evidence_ids":[]}]}',
    '{"claims":[{"text":"Invented","evidence_ids":["unknown"]}]}',
    '{"claims":[{"text":"Cross-specialty","evidence_ids":["person1"]}]}',
])
def test_paid_invalid_output_settles_and_stops_later_calls(
    engine, monkeypatch, configured, brief, raw
):
    calls = fake_provider(monkeypatch, engine, lambda *args: raw)
    result = runtime.analyze_brief(engine, brief, 'multi', ['openai', 'anthropic'])
    assert result['status'] == 'failed'
    assert result['claims'] == []
    assert Decimal(result['spend_usd']) == Decimal('0.10')
    assert len(calls) == 1
    assert [row['state'] for row in ledger_rows(engine)] == ['settled', 'released', 'released']


def test_known_unbillable_failure_releases_reservation(engine, monkeypatch, configured, brief):
    def fail(*args):
        raise ProviderError('fixture-secret-openai', response_received=False)
    calls = fake_provider(monkeypatch, engine, fail)
    result = runtime.analyze_brief(engine, brief, 'single', ['openai'])
    assert result['status'] == 'failed'
    assert result['spend_usd'] == '0'
    assert len(calls) == 1
    assert ledger_rows(engine)[0]['state'] == 'released'
    assert 'fixture-secret' not in json.dumps(result)


@pytest.mark.parametrize('error', [ProviderError('sensitive error', response_received=True),
    ProviderError('sensitive error', cost_uncertain=True), RuntimeError('secret provider exception')])
def test_paid_or_uncertain_provider_failure_keeps_conservative_charge(
    engine, monkeypatch, configured, brief, error
):
    def fail(*args):
        raise error
    fake_provider(monkeypatch, engine, fail)
    result = runtime.analyze_brief(engine, brief, 'single', ['openai'])
    assert result['status'] == 'failed'
    assert Decimal(result['spend_usd']) == Decimal('0.10')
    assert ledger_rows(engine)[0]['state'] == 'settled'
    assert 'sensitive error' not in json.dumps(result)
    assert 'secret provider exception' not in json.dumps(result)


def test_only_allowlisted_business_facts_enter_prompts(engine, monkeypatch, configured, brief):
    brief['facts'] += [
        fact('restricted', 'person.role', 'Sensitive role') | {'sensitivity': 'restricted'},
        fact('personal', 'person.business_phone', 'Sensitive number') | {'sensitivity': 'personal'},
        fact('secret', 'company.api_key', 'sensitive-key'),
        fact('raw', 'dns.txt', 'verification-token'),
        fact('leaked', 'person.role', 'fixture-secret-openai'),
        fact('inferred', 'person.role', 'Unproven role') | {'is_inference': True},
        fact('url', 'company.contact_page', 'https://example.com/?token=sensitive'),
    ]
    calls = fake_provider(monkeypatch, engine)
    result = runtime.analyze_brief(engine, brief, 'single', ['openai'])
    assert result['eligible_facts'] == 2
    assert result['omitted_facts'] == 7
    payload = json.dumps(calls[0][2])
    assert 'DO NOT TRANSMIT' not in payload
    assert 'NEVER SEND' not in payload
    assert 'fixture-secret' not in payload
    assert 'verification-token' not in payload
    assert 'Sensitive' not in payload
    assert 'untrusted DATA' in calls[0][1]
    assert 'no tools' in calls[0][1]


def test_no_eligible_evidence_never_spends(engine, monkeypatch, configured):
    calls = fake_provider(monkeypatch, engine)
    result = runtime.analyze_brief(engine, {'facts': []}, 'single', ['openai'])
    assert result['status'] == 'skipped'
    assert calls == []
    assert ledger_rows(engine) == []


def test_call_cap_configuration_is_required(engine, monkeypatch, configured, brief):
    monkeypatch.delenv('NEESHA_OPENAI_CALL_CAP_USD')
    with pytest.raises(runtime.RuntimeAnalysisError, match='NEESHA_OPENAI_CALL_CAP_USD'):
        runtime.analyze_brief(engine, brief, 'single', ['openai'])
    assert ledger_rows(engine) == []


@pytest.mark.parametrize('amount', ['NaN', 'Infinity', '-1', '0', 'not-a-number'])
def test_invalid_call_cap_never_spends(engine, monkeypatch, configured, brief, amount):
    monkeypatch.setenv('NEESHA_OPENAI_CALL_CAP_USD', amount)
    with pytest.raises(runtime.RuntimeAnalysisError, match='finite positive'):
        runtime.analyze_brief(engine, brief, 'single', ['openai'])
    assert ledger_rows(engine) == []


def test_fractional_spend_limit_is_never_rounded_up(engine, monkeypatch, configured, brief):
    calls = fake_provider(monkeypatch, engine)
    with pytest.raises(runtime.RuntimeAnalysisError, match='exceed'):
        runtime.analyze_brief(engine, brief, 'multi', ['openai', 'anthropic'], Decimal('0.29999'))
    assert calls == []


def test_failed_settlement_keeps_the_paid_reservation_held(engine, monkeypatch, configured, brief):
    from neesha.ledger.ledger import LedgerError
    class BrokenSettlement(Ledger):
        def settle(self, *args):
            raise LedgerError('fixture-secret-openai')
    monkeypatch.setattr(runtime, 'Ledger', BrokenSettlement)
    fake_provider(monkeypatch, engine)
    with pytest.raises(runtime.RuntimeAnalysisError, match='reservation remains held') as caught:
        runtime.analyze_brief(engine, brief, 'multi', ['openai', 'anthropic'])
    assert 'fixture-secret' not in str(caught.value)
    assert [r['state'] for r in ledger_rows(engine)] == ['reserved', 'released', 'released']


def test_email_runtime_exact_subject_allowlist_and_specialist_boundaries(engine, monkeypatch, configured):
    email='casey@gmail.com'
    def public(identifier, attribute, subject=email, sensitivity='personal'):
        return fact(identifier,attribute,'Public metadata') | {'subject':subject,'sensitivity':sensitivity}
    brief={'run_id':'email-run','subject_kind':'email','seed':{'normalized':email},'facts':[
        public('commit','public.email.github.commit_url'),
        public('profile','public.profile.gravatar.url'),
        public('other','public.profile.gravatar.display_name','other@gmail.com'),
        public('private','person.personal_phone'),
        public('restricted','public.profile.gravatar.url',sensitivity='restricted'),
        public('inferred','public.email.emailrep.profile_hint') | {'is_inference':True},
    ]}
    calls=fake_provider(monkeypatch,engine)
    result=runtime.analyze_brief(engine,brief,'multi',['openai','anthropic'])
    assert result['status']=='complete' and result['eligible_facts']==2 and result['omitted_facts']==4
    assert [c[2]['role'] for c in calls]==['publication_specialist','profile_specialist','reviewer']
    assert {f['fact_id'] for f in calls[0][2]['facts']}=={'commit'}
    assert {f['fact_id'] for f in calls[1][2]['facts']}=={'profile'}
    assert all('registration' in c[1] for c in calls)


def test_public_personal_email_fact_not_eligible_in_company_run():
    row=fact('profile','public.profile.gravatar.url','https://gravatar.com/example')
    row['sensitivity']='personal'
    rows,omitted=runtime._safe_facts({'facts':[row]})
    assert rows==[] and omitted==1
