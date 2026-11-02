"""Optional Subfinder wrapper: parser and mocked execution, no live scans."""
import json
import os
import sys

import pytest

from neesha.adapters.base import AdapterError, RawResult, Request
from neesha.adapters.subfinder import SubfinderAdapter

SEED = Request('domain', 'acme.com')


def raw(*rows):
    return RawResult(b'\n'.join(json.dumps(row).encode() for row in rows), 'tool://subfinder/acme.com')


def test_subfinder_aggregate_namespace_and_upstream_attribution():
    result = SubfinderAdapter().parse(raw(
        {'host': 'MAIL.Acme.com', 'sources': ['crtsh', 'rapiddns']},
        {'host': 'mail.acme.com', 'source': 'commoncrawl'},
        {'host': 'vpn.acme.com', 'source': 'paid-service'},
        {'host': 'other.example', 'sources': ['crtsh']},
        {'host': 'acme.com', 'sources': ['crtsh']},
        {'host': 'acme.com.other.example', 'source': 'crtsh'},
        {'host': 'bad_name.acme.com', 'source': 'crtsh'},
        {'host': '--evil.acme.com', 'source': 'crtsh'},
    ), SEED)
    assert {(f.attribute, f.value, f.entity_name) for f in result} == {
        ('discovery.subdomain', 'mail.acme.com', 'acme.com'),
        ('discovery.subdomain', 'vpn.acme.com', 'acme.com'),
        ('discovery.source', 'crtsh', 'mail.acme.com'),
        ('discovery.source', 'rapiddns', 'mail.acme.com'),
        ('discovery.source', 'commoncrawl', 'mail.acme.com'),
    }
    assert not any(f.attribute == 'dns.subdomain' for f in result)


def test_subfinder_uninstalled_is_a_gap(monkeypatch):
    adapter = SubfinderAdapter()
    monkeypatch.setattr(adapter, 'binary', lambda: None)
    assert not adapter.availability()['available']
    with pytest.raises(AdapterError, match='not installed'):
        adapter.fetch(adapter.search(SEED)[0])


def test_binary_presence_does_not_grant_external_write_permission(monkeypatch):
    adapter = SubfinderAdapter()
    monkeypatch.setattr(adapter, 'binary', lambda: '/path/to/subfinder')
    monkeypatch.delenv('NEESHA_ALLOW_TOOL_HOME_WRITES', raising=False)
    assert not adapter.availability()['available']
    with pytest.raises(AdapterError, match='outside NEESHA'):
        adapter.fetch(adapter.search(SEED)[0])
    assert adapter.default_enabled is False


def test_opted_in_mock_execution_uses_only_keyless_sources_and_local_paths(monkeypatch, tmp_path):
    adapter = SubfinderAdapter()
    monkeypatch.setattr(adapter, 'binary', lambda: '/trusted/subfinder')
    monkeypatch.setenv('NEESHA_ALLOW_TOOL_HOME_WRITES', '1')
    monkeypatch.setenv('HUNTER_API_KEY', 'must-not-leak')
    monkeypatch.setenv('SHODAN_API_KEY', 'must-not-leak')
    monkeypatch.setattr('neesha.adapters.subfinder.PROJECT_ROOT', tmp_path)
    captured = {}

    def execute(args, env, output):
        captured.update(args=args, env=env)
        output.write(b'{"host":"mail.acme.com","source":"crtsh"}\n')
    monkeypatch.setattr(adapter, '_execute', execute)
    result = adapter.fetch(adapter.search(SEED)[0])
    args, env = captured['args'], captured['env']
    assert args[0] == '/trusted/subfinder'
    assert args[args.index('-d') + 1] == 'acme.com'
    assert args[args.index('-s') + 1] == 'crtsh,commoncrawl,rapiddns'
    assert not any(flag in args for flag in ('-active', '-all', '-up', '-nW'))
    assert all(flag in args for flag in ('-json', '-cs', '-silent', '-duc', '-mr', '-rsr'))
    for flag in ('-config', '-pc'):
        assert args[args.index(flag) + 1].startswith(str(tmp_path))
    assert env['SUBFINDER_CONFIG'].startswith(str(tmp_path))
    assert env['SUBFINDER_PROVIDER_CONFIG'].startswith(str(tmp_path))
    assert not any('API_KEY' in key for key in env)
    assert result.collected_at.tzinfo is not None
    assert result.payload == b'{"host":"mail.acme.com","source":"crtsh"}\n'
    assert result.origin_url == 'tool://subfinder/'


@pytest.mark.parametrize('domain', ['--config=/etc/file', 'acme.com;echo hi', 'x@y.com', 'localhost', '../x'])
def test_subfinder_rejects_non_domain_seed(domain):
    with pytest.raises(AdapterError, match='valid company domain'):
        SubfinderAdapter().search(Request('domain', domain))


def test_parser_empty_invalid_and_size_boundaries():
    adapter = SubfinderAdapter()
    assert adapter.parse(RawResult(b'', 'tool://subfinder/'), SEED) == []
    with pytest.raises(AdapterError, match='invalid JSONL'):
        adapter.parse(RawResult(b'not-json', 'tool://subfinder/'), SEED)
    adapter.max_output_bytes = 2
    with pytest.raises(AdapterError, match='size limit'):
        adapter.parse(RawResult(b'123', 'tool://subfinder/'), SEED)


def test_parser_result_count_is_bounded():
    adapter = SubfinderAdapter()
    adapter.max_results = 1
    result = adapter.parse(raw({'host': 'one.acme.com'}, {'host': 'two.acme.com'}), SEED)
    assert [f.value for f in result] == ['one.acme.com']


def test_process_output_is_bounded_without_live_subfinder(tmp_path):
    adapter = SubfinderAdapter()
    adapter.max_output_bytes = 100
    adapter.timeout = 3
    # This subprocess runs Python's standard library, never Subfinder or a scan.
    with (tmp_path / 'output').open('w+b') as output:
        with pytest.raises(AdapterError, match='size limit'):
            adapter._execute([sys.executable, '-c', "print('x' * 1000)"], os.environ.copy(), output)
        assert output.tell() <= 100


def test_process_timeout_is_enforced_without_live_subfinder(tmp_path):
    adapter = SubfinderAdapter()
    adapter.timeout = 0.05
    with (tmp_path / 'output').open('w+b') as output:
        with pytest.raises(AdapterError, match='time limit'):
            adapter._execute([sys.executable, '-c', 'import time; time.sleep(5)'], os.environ.copy(), output)


def test_nonzero_process_exit_is_sanitized(tmp_path):
    adapter = SubfinderAdapter()
    with (tmp_path / 'output').open('w+b') as output:
        with pytest.raises(AdapterError, match='collection failed'):
            adapter._execute([sys.executable, '-c', 'raise SystemExit(1)'], os.environ.copy(), output)
