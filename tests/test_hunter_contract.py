"""Verified Hunter API contract, conservative metering, and company matching."""
import json
from unittest.mock import Mock

import pytest

from neesha.adapters.base import AdapterError, RawResult, Reference, Request
from neesha.adapters.hunter import HunterAdapter, MAX_PAYLOAD_BYTES

SEED = Request('domain', 'acme.com')


def raw(data):
    return RawResult(json.dumps({'data': data}).encode(), 'https://api.hunter.io/v2/domain-search')


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv('HUNTER_API_KEY', 'SERVER-SIDE-KEY')
    monkeypatch.setenv('HUNTER_ESTIMATED_USD_PER_SEARCH', '0.02')
    return HunterAdapter()


def test_hunter_key_is_header_only_and_fields_are_allowlisted(configured, monkeypatch):
    captured = {}
    def get(url, headers=None, timeout=0):
        captured.update(url=url, headers=headers, timeout=timeout)
        return json.dumps({'data': {'domain': 'acme.com', 'pattern': '{first}.{last}',
            'password': 'MUST-NOT-PERSIST', 'emails': [
                {'value': 'person@acme.com', 'position': 'CTO', 'password': 'MUST-NOT-PERSIST'},
                {'value': 'unrelated@another.com', 'first_name': 'Unrelated'},
            ]}})
    monkeypatch.setattr('neesha.adapters.hunter.http_get', get)
    reference = configured.search(SEED)[0]
    assert 'SERVER-SIDE-KEY' not in reference.url
    assert 'api_key=' not in reference.url
    assert 'limit=10' in reference.url
    result = configured.fetch(reference)
    assert captured['headers'] == {'X-API-KEY': 'SERVER-SIDE-KEY'}
    assert captured['timeout'] == 30
    assert 'SERVER-SIDE-KEY' not in result.request_url
    assert b'MUST-NOT-PERSIST' not in result.payload
    assert b'unrelated@another.com' not in result.payload
    assert result.collected_at.tzinfo is not None
    assert configured.estimate_cost(SEED).usd == 0.02


@pytest.mark.parametrize('value', ['', '0', '-1', 'NaN', 'Infinity', 'unknown', '0.00001'])
def test_hunter_unknown_or_invalid_cost_never_becomes_free(monkeypatch, value):
    monkeypatch.setenv('HUNTER_ESTIMATED_USD_PER_SEARCH', value)
    with pytest.raises(AdapterError, match='positive'):
        HunterAdapter().estimate_cost(SEED)


@pytest.mark.parametrize('limit', [0, -1, 11, True, 1.5, '10.5', '1000'])
def test_hunter_request_limit_cannot_exceed_configured_bound(configured, limit):
    with pytest.raises(AdapterError, match='configured result cap'):
        configured.search(Request('domain', 'acme.com', {'limit': limit}))


def test_hunter_small_request_and_explicit_larger_application_cap(configured, monkeypatch):
    assert 'limit=2' in configured.search(Request('domain', 'acme.com', {'limit': 2}))[0].url
    larger = HunterAdapter(max_people=20)
    assert 'limit=20' in larger.search(SEED)[0].url
    with pytest.raises(AdapterError):
        HunterAdapter(max_people=1000)


def test_hunter_availability_requires_key_and_uses_default_cost(monkeypatch):
    monkeypatch.delenv('HUNTER_API_KEY', raising=False)
    monkeypatch.delenv('HUNTER_ESTIMATED_USD_PER_SEARCH', raising=False)
    assert not HunterAdapter().availability()['available']
    monkeypatch.setenv('HUNTER_API_KEY', 'key')
    assert HunterAdapter().availability()['available']
    assert HunterAdapter().estimate_cost(SEED).usd == 0.05
    monkeypatch.setenv('HUNTER_ESTIMATED_USD_PER_SEARCH', '0.01')
    assert HunterAdapter().estimate_cost(SEED).usd == 0.01


def test_hunter_only_emits_company_emails_and_keeps_stable_identity(configured):
    facts = configured.parse(raw({'domain': 'acme.com', 'emails': [
        {'value': 'Dana@Acme.com', 'first_name': 'Dana', 'last_name': 'Ops',
         'position': 'CTO', 'seniority': 'executive'},
        {'value': 'someone@gmail.com', 'position': 'CEO'},
        {'value': 'other@acme.com.attacker.com'},
        {'value': 'person@subsidiary.acme.com'},
        {'value': 'bad@@acme.com'},
        {'value': 'has space@acme.com'},
        {'value': None},
    ]}), SEED)
    assert {f.value for f in facts if f.attribute == 'person.business_email'} == {'dana@acme.com'}
    assert all(f.identity_key == 'email:dana@acme.com' for f in facts)
    assert all(f.entity_name == 'Dana Ops' for f in facts)


def test_hunter_rejects_mismatched_response_company(configured):
    with pytest.raises(AdapterError, match='does not match'):
        configured.parse(raw({'domain': 'another.com', 'emails': []}), SEED)


def test_hunter_does_not_turn_webmail_or_disposable_response_into_people(configured):
    for flag in ('webmail', 'disposable'):
        assert configured.parse(raw({'domain': 'acme.com', flag: True,
            'pattern': '{first}', 'emails': [{'value': 'person@acme.com'}]}), SEED) == []


def test_hunter_rejects_arbitrary_reference_before_sending_credentials(configured, monkeypatch):
    get = Mock()
    monkeypatch.setattr('neesha.adapters.hunter.http_get', get)
    for url in ('https://evil.example/v2/domain-search?domain=acme.com&limit=10',
                'https://api.hunter.io/v2/domain-search?domain=acme.com&limit=10&api_key=secret'):
        with pytest.raises(AdapterError, match='verified domain-search endpoint'):
            configured.fetch(Reference(url))
    get.assert_not_called()


def test_hunter_error_text_does_not_include_credentials_or_provider_body(configured, monkeypatch):
    monkeypatch.setattr('neesha.adapters.hunter.http_get', Mock(side_effect=OSError('SERVER-SIDE-KEY password=SECRET')))
    with pytest.raises(AdapterError) as caught:
        configured.fetch(configured.search(SEED)[0])
    assert 'SERVER-SIDE-KEY' not in str(caught.value)
    assert 'SECRET' not in str(caught.value)
    assert caught.value.__suppress_context__ is True


def test_hunter_transport_disables_redirects_and_bounds_the_response(monkeypatch):
    from neesha.adapters.hunter import http_get, _NoRedirect
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.read.return_value = b'{}'
    opener = Mock()
    opener.open.return_value = response
    build = Mock(return_value=opener)
    monkeypatch.setattr('urllib.request.build_opener', build)
    assert http_get('https://api.hunter.io/v2/domain-search') == '{}'
    assert isinstance(build.call_args.args[0], _NoRedirect)
    response.read.assert_called_once_with(MAX_PAYLOAD_BYTES + 1)
