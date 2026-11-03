"""Paid metadata connectors: contract, gates, and absence of sensitive payloads."""
import json
from unittest.mock import Mock

import pytest

from neesha.adapters.base import AdapterError, RawResult, Request
from neesha.adapters.dehashed import DeHashedAdapter
from neesha.adapters.intelx import IntelXAdapter

SEED = Request('domain', 'acme.com')
SEARCH_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv('INTELX_API_KEY', 'server-side-key')
    monkeypatch.setenv('INTELX_ESTIMATED_USD_PER_SEARCH', '0.25')
    return IntelXAdapter()


@pytest.mark.parametrize('value', ['', 'unknown', '0', '-1', 'NaN', 'Infinity', '0.00001'])
def test_intelx_cost_fails_closed_without_valid_positive_estimate(monkeypatch, value):
    monkeypatch.setenv('INTELX_ESTIMATED_USD_PER_SEARCH', value)
    with pytest.raises(AdapterError, match='positive'):
        IntelXAdapter().estimate_cost(SEED)


def test_paid_provider_is_not_automatic_and_requires_breach_metadata(configured):
    assert configured.tier == 'C'
    assert configured.default_enabled is False
    assert configured.requires_techniques == frozenset({'breach_metadata'})
    assert configured.source_type == 'commercial_api'
    assert configured.estimate_cost(SEED).usd == 0.25
    assert configured.availability()['available']


def test_intelx_cannot_fetch_without_key_or_price(monkeypatch):
    adapter = IntelXAdapter()
    monkeypatch.delenv('INTELX_API_KEY', raising=False)
    monkeypatch.delenv('INTELX_KEY', raising=False)
    assert not adapter.availability()['available']
    with pytest.raises(AdapterError, match='key is not configured'):
        adapter.fetch(adapter.search(SEED)[0])


def test_intelx_sanitizes_before_raw_result_cache_or_provenance(configured, monkeypatch):
    responses = [
        {'id': SEARCH_ID, 'status': 0},
        {'status': 1, 'records': [
            {'bucket': 'leaks.public', 'name': 'password=NEVER-PERSIST',
             'description': 'person@acme.com', 'storageid': 'sensitive-file-id',
             'password': 'NEVER-PERSIST', 'hashed_password': 'SENSITIVE-HASH'},
            {'bucket': 'pastes', 'password': 'NEVER-PERSIST'},
            {'bucket': 'unrecognized-secret-title', 'username': 'private-user'},
        ]},
        {},
    ]
    calls = []

    def provider(path, **kwargs):
        calls.append((path, kwargs))
        return responses.pop(0)
    monkeypatch.setattr(configured, '_request_json', provider)
    result = configured.fetch(configured.search(SEED)[0])
    envelope = result.to_envelope()
    data = json.loads(result.payload)
    assert data == {'domain': 'acme.com', 'sample_count': 3, 'partial': False,
                    'category_counts': {'leaks': 1, 'pastes': 1, 'darknet': 0, 'other': 1}}
    for forbidden in [b'NEVER-PERSIST', b'person@acme.com', b'private-user',
                      b'password', b'SENSITIVE-HASH', SEARCH_ID.encode(), b'sensitive-file-id']:
        assert forbidden not in result.payload
        assert forbidden not in result.request_url.encode()
    assert b'NEVER-PERSIST' not in envelope
    assert [path for path, _ in calls] == [
        '/intelligent/search', '/intelligent/search/result', '/intelligent/search/terminate']
    assert calls[0][1]['payload']['term'] == 'acme.com'
    assert calls[1][1]['params']['id'] == SEARCH_ID
    facts = configured.parse(result, SEED)
    assert all(f.entity_kind == 'company' and f.entity_name == 'acme.com' for f in facts)
    assert {f.value for f in facts if f.attribute == 'intelx.search.sample_count'} == {'3'}


def test_intelx_polling_is_bounded_and_reports_partial_results(configured, monkeypatch):
    calls = []
    def provider(path, **kwargs):
        calls.append(path)
        if path == '/intelligent/search':
            return {'id': SEARCH_ID}
        if path == '/intelligent/search/result':
            return {'status': 3, 'records': []}
        return {}
    monkeypatch.setattr(configured, '_request_json', provider)
    result = configured.fetch(configured.search(SEED)[0])
    data = json.loads(result.payload)
    assert data['partial'] is True
    assert data['sample_count'] == 0
    assert calls.count('/intelligent/search/result') == configured.max_polls
    assert calls[-1] == '/intelligent/search/terminate'


def test_intelx_terminates_search_on_malformed_provider_result(configured, monkeypatch):
    provider = Mock(side_effect=[{'id': SEARCH_ID}, {'status': 2}, {}])
    monkeypatch.setattr(configured, '_request_json', provider)
    with pytest.raises(AdapterError, match='invalid search metadata'):
        configured.fetch(configured.search(SEED)[0])
    assert provider.call_args.args[0] == '/intelligent/search/terminate'


def test_intelx_headers_transport_and_bounded_response(configured, monkeypatch):
    monkeypatch.setattr('neesha.adapters.intelx._LAST_CALL', 0)
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.read.return_value = b'{"status":1,"records":[]}'
    opener = Mock()
    opener.open.return_value = response
    monkeypatch.setattr('urllib.request.build_opener', Mock(return_value=opener))
    configured._request_json('/intelligent/search', payload={'term': 'acme.com'})
    request = opener.open.call_args.args[0]
    assert request.get_header('X-key') == 'server-side-key'
    assert 'server-side-key' not in request.full_url
    assert request.method == 'POST'
    response.read.assert_called_once_with(configured.max_response_bytes + 1)
    assert opener.open.call_args.kwargs['timeout'] == configured.timeout


def test_intelx_transport_never_exposes_provider_errors(configured, monkeypatch):
    monkeypatch.setattr('neesha.adapters.intelx._LAST_CALL', 0)
    monkeypatch.setattr('urllib.request.build_opener', Mock(side_effect=OSError('password=TOP-SECRET')))
    with pytest.raises(AdapterError) as caught:
        configured._request_json('/intelligent/search', payload={'term': 'acme.com'})
    assert str(caught.value) == 'Intelligence X metadata request failed'
    assert caught.value.__suppress_context__ is True


@pytest.mark.parametrize('domain', ['someone@acme.com', '--evil', 'acme.com OR other.com', 'localhost'])
def test_intelx_metadata_only_accepts_domain_seeds(domain):
    with pytest.raises(AdapterError):
        IntelXAdapter().search(Request('domain', domain))


def test_dehashed_requires_api_key_and_positive_cost_estimate(monkeypatch):
    monkeypatch.delenv('DEHASHED_API_KEY', raising=False)
    monkeypatch.delenv('DEHASHED_KEY', raising=False)
    adapter = DeHashedAdapter()
    assert adapter.availability()['available'] is False
    assert adapter.default_enabled is False
    assert adapter.tier == 'C'
    assert adapter.requires_techniques == frozenset({'breach_metadata'})
    with pytest.raises(AdapterError, match='key is not configured'):
        adapter.fetch(adapter.search(SEED)[0])

    monkeypatch.setenv('DEHASHED_API_KEY', 'dh-secret-key')
    monkeypatch.setenv('DEHASHED_ESTIMATED_USD_PER_SEARCH', '0')
    with pytest.raises(AdapterError, match='positive'):
        adapter.estimate_cost(SEED)


def test_dehashed_v2_sanitizes_passwords_and_hashes_and_extracts_breach_intelligence(monkeypatch):
    monkeypatch.setenv('DEHASHED_API_KEY', 'dh-secret-key')
    monkeypatch.setenv('DEHASHED_ESTIMATED_USD_PER_SEARCH', '0.05')
    adapter = DeHashedAdapter()
    assert adapter.availability()['available'] is True

    raw_provider_response = {
        'total': 2,
        'balance': 98,
        'entries': [
            {
                'id': 'rec-1',
                'email': ['alice@acme.com', 'ignored@otherdomain.com'],
                'username': ['alice_ops'],
                'password': ['CLEARTEXT-SECRET-NEVER-STORE'],
                'hashed_password': ['HASH-SECRET-NEVER-STORE'],
                'hash_type': 'bcrypt',
                'ip_address': ['93.184.215.14'],
                'phone': ['+14155552671'],
                'name': ['Alice Ops'],
                'company': ['Acme Corp'],
                'address': ['123 Secret Home St'],
                'vin': ['1HGCM82633A004352'],
                'database_name': 'Collection1',
            },
            {
                'id': 'rec-2',
                'email': 'bob@acme.com',
                'username': 'bob_dev',
                'password': '',
                'hashed_password': 'SECOND-HASH-NEVER-STORE',
                'hash_type': 'sha256',
                'database_name': 'LinkedIn',
            },
        ],
    }
    monkeypatch.setattr(adapter, '_request_json', lambda query: raw_provider_response)
    ref = adapter.search(SEED)[0]
    raw = adapter.fetch(ref)

    # Verify zero credential, hash, address, or VIN material is stored in RawResult
    for forbidden in (
        b'CLEARTEXT-SECRET-NEVER-STORE',
        b'HASH-SECRET-NEVER-STORE',
        b'SECOND-HASH-NEVER-STORE',
        b'123 Secret Home St',
        b'1HGCM82633A004352',
        b'ignored@otherdomain.com',
    ):
        assert forbidden not in raw.payload

    facts = adapter.parse(raw, SEED)
    by_attr = {}
    for f in facts:
        by_attr.setdefault(f.attribute, set()).add(f.value)

    assert by_attr['dehashed.search.total_count'] == {'2'}
    assert by_attr['dehashed.breach.secret_exposure_count'] == {'1'}
    assert by_attr['dehashed.breach.hash_exposure_count'] == {'2'}
    assert by_attr['dehashed.breach.database'] == {'Collection1', 'LinkedIn'}
    assert by_attr['dehashed.breach.email'] == {'alice@acme.com', 'bob@acme.com'}
    assert by_attr['dehashed.breach.username'] == {'alice_ops', 'bob_dev'}
    assert by_attr['dehashed.breach.ip_address'] == {'93.184.215.14'}
    assert by_attr['dehashed.breach.phone'] == {'+14155552671'}
    assert by_attr['dehashed.breach.name'] == {'Alice Ops'}
    assert by_attr['dehashed.breach.company'] == {'Acme Corp'}


def test_dehashed_supports_email_username_ip_phone_and_person_selectors(monkeypatch):
    monkeypatch.setenv('DEHASHED_API_KEY', 'dh-secret-key')
    adapter = DeHashedAdapter()
    captured_queries = []

    def fake_request(query):
        captured_queries.append(query)
        return {
            'total': 1,
            'entries': [{
                'email': ['dana@example.com'],
                'username': ['dana_sec'],
                'password': ['DO-NOT-STORE'],
                'database_name': 'Canva',
            }],
        }

    monkeypatch.setattr(adapter, '_request_json', fake_request)
    email_req = Request('email', 'dana@example.com')
    raw = adapter.fetch(adapter.search(email_req)[0])
    facts = adapter.parse(raw, email_req)
    assert captured_queries == ['email:dana@example.com']
    assert all(f.entity_kind == 'email' and f.sensitivity == 'personal' for f in facts)
    assert any(f.attribute == 'public.dehashed.breach_database' and f.value == 'Canva' for f in facts)


def test_intelx_gate_requires_client_scope_technique_approval_and_budget(engine, configured):
    from decimal import Decimal
    from neesha.harness.executor import spec_of
    from neesha.harness.gate import EngagementView, PolicyGate, RunCaps
    from neesha.ledger.ledger import Ledger

    ledger = Ledger(engine)
    gate = PolicyGate(engine, ledger, approval_tiers=frozenset({'C'}))
    caps = RunCaps(10, Decimal('1'), 60)
    base = dict(id='client', authorized_domains=('acme.com',))
    def ask(engagement, approved=False):
        return gate.authorize(adapter=spec_of(configured), target='acme.com',
                              engagement=engagement, analyst='test', caps=caps,
                              approved=approved, estimated_usd=Decimal('0.25'))

    prospect = EngagementView(authority_basis='prospect_company', **base)
    assert ask(prospect, approved=True).outcome == 'denied'
    client = EngagementView(authority_basis='client_engagement', **base)
    assert ask(client, approved=True).outcome == 'denied'
    scoped = EngagementView(authority_basis='client_engagement',
                            permitted_techniques=frozenset({'breach_metadata'}), **base)
    assert ask(scoped).outcome == 'paused'
    assert ask(scoped, approved=True).outcome == 'denied'
    ledger.set_cap('1')
    decision = ask(scoped, approved=True)
    assert decision.outcome == 'allowed'
    assert decision.reservation is not None
