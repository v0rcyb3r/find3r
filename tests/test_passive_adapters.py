"""Passive-source adapters preserve scope and distinguish historical data."""
import json
from unittest.mock import Mock

import pytest

from neesha.adapters.base import AdapterError, RawResult, Request
from neesha.adapters.otx import OtxAdapter
from neesha.adapters.wayback import WaybackAdapter

SEED = Request('domain', 'acme.com')


def raw(payload):
    return RawResult(payload=json.dumps(payload).encode(), request_url='https://source.test/query')


def test_wayback_extracts_scoped_historical_urls_and_hosts():
    adapter = WaybackAdapter()
    result = adapter.parse(raw([
        ['timestamp', 'original', 'statuscode'],
        ['20240101123000', 'https://www.acme.com/contact', '200'],
        ['20240101123000', 'https://acme.com/?api_key=secret#token', '200'],
        ['20240101123000', 'https://unrelated.com/', '200'],
        ['20240101123000', 'https://acme.com.attacker.net/', '200'],
        ['20240101123000', 'https://user:secret@acme.com/', '200'],
        ['20240101123000', 'ftp://ftp.acme.com/', '200'],
        ['not-a-date', 'https://bad.acme.com/', '200'],
        ['20240101123000', 'https://www.acme.com/contact', '200'],
        None,
    ]), SEED)
    assert {(f.attribute, f.value) for f in result} == {
        ('web.archive.url', 'https://www.acme.com/contact'),
        ('web.archive.url', 'https://acme.com/?api_key=REDACTED'),
        ('dns.subdomain', 'www.acme.com'),
    }
    assert all(f.entity_name == 'acme.com' for f in result)
    assert not any('secret' in f.value for f in result)


def test_wayback_honors_column_names_and_does_not_assume_order():
    result = WaybackAdapter().parse(raw([
        ['original', 'statuscode', 'timestamp'],
        ['https://docs.acme.com/', '200', '20240202120000'],
    ]), SEED)
    assert {f.value for f in result} == {'https://docs.acme.com/', 'docs.acme.com'}


def test_wayback_does_not_call_absence_a_security_fact():
    assert WaybackAdapter().parse(raw([]), SEED) == []
    assert WaybackAdapter().parse(raw([['timestamp', 'original']]), SEED) == []


@pytest.mark.parametrize('payload', [{}, {'error': 'rate limited'}, [['wrong', 'columns']]])
def test_wayback_rejects_provider_errors_and_malformed_shapes(payload):
    with pytest.raises(AdapterError):
        WaybackAdapter().parse(raw(payload), SEED)


def test_otx_scopes_hosts_validates_addresses_and_labels_history():
    result = OtxAdapter().parse(raw({'passive_dns': [
        {'hostname': 'VPN.Acme.com.', 'address': '203.0.113.1'},
        {'hostname': 'acme.com', 'address': '2001:db8::1'},
        {'hostname': 'vpn.acme.com', 'address': '203.0.113.1'},
        {'hostname': 'unrelated.com', 'address': '203.0.113.2'},
        {'hostname': 'acme.com.attacker.net', 'address': '203.0.113.3'},
        {'hostname': 'bad.acme.com', 'address': 'not-an-ip'},
        {'hostname': 'invalid_name.acme.com', 'address': '203.0.113.4'},
        {'hostname': 'incomplete.acme.com'}, None,
    ]}), SEED)
    assert {(f.attribute, f.value, f.entity_name) for f in result} == {
        ('dns.subdomain', 'vpn.acme.com', 'acme.com'),
        ('dns.passive.ipv4', '203.0.113.1', 'vpn.acme.com'),
        ('dns.passive.ipv6', '2001:db8::1', 'acme.com'),
    }
    assert not any(f.attribute in ('dns.a', 'dns.aaaa') for f in result)


@pytest.mark.parametrize('payload', [[], {}, {'passive_dns': None}, {'error': 'unauthorized'}])
def test_otx_rejects_unexpected_provider_shapes(payload):
    with pytest.raises(AdapterError):
        OtxAdapter().parse(raw(payload), SEED)


def test_otx_empty_response_is_no_observation():
    assert OtxAdapter().parse(raw({'passive_dns': []}), SEED) == []


@pytest.mark.parametrize('adapter', [WaybackAdapter(), OtxAdapter()])
def test_parsing_is_bounded_and_bad_json_is_a_collection_gap(adapter):
    with pytest.raises(AdapterError, match='invalid JSON'):
        adapter.parse(RawResult(b'not-json', 'https://source.test/'), SEED)
    with pytest.raises(AdapterError, match='size limit'):
        adapter.parse(RawResult(b'x' * (adapter.max_payload_bytes + 1), 'https://source.test/'), SEED)


@pytest.mark.parametrize('adapter', [WaybackAdapter(), OtxAdapter()])
def test_fetch_preserves_provenance_and_limits_read_size(adapter, monkeypatch):
    reference = adapter.search(SEED)[0]
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.status = 200
    response.read.return_value = b'[]'
    open_url = Mock(return_value=response)
    monkeypatch.setattr('urllib.request.urlopen', open_url)
    result = adapter.fetch(reference)
    assert result.request_url == reference.url
    assert result.origin_url == reference.origin_url
    assert result.collected_at.tzinfo is not None
    assert result.http_status == 200
    response.read.assert_called_once_with(adapter.max_payload_bytes + 1)
    assert open_url.call_args.kwargs['timeout'] == 20
    assert adapter.collection_mode == 'third_party_passive'
    assert adapter.estimate_cost(SEED).usd == 0


@pytest.mark.parametrize('adapter', [WaybackAdapter(), OtxAdapter()])
def test_provider_failure_is_a_sanitized_gap(adapter, monkeypatch):
    monkeypatch.setattr('urllib.request.urlopen', Mock(side_effect=OSError('provider secret body')))
    with pytest.raises(AdapterError, match='request failed') as error:
        adapter.fetch(adapter.search(SEED)[0])
    assert 'secret' not in str(error.value)


def test_result_row_caps_prevent_unbounded_facts():
    wayback = WaybackAdapter()
    wayback.max_rows = 1
    result = wayback.parse(raw([
        ['timestamp', 'original'], ['20240101120000', 'https://one.acme.com/'],
        ['20240101120000', 'https://two.acme.com/'],
    ]), SEED)
    assert not any('two.acme.com' in f.value for f in result)
    otx = OtxAdapter()
    otx.max_rows = 1
    result = otx.parse(raw({'passive_dns': [
        {'hostname': 'one.acme.com', 'address': '203.0.113.1'},
        {'hostname': 'two.acme.com', 'address': '203.0.113.2'},
    ]}), SEED)
    assert not any('two.acme.com' in f.value for f in result)
