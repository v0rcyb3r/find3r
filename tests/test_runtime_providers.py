"""Provider API contracts are fixture-tested without paid calls or credentials."""
import io
import json
import traceback
import urllib.error

import pytest

from neesha.runtime import providers as p


SECRET = 'fixture-secret-do-not-disclose'
RESPONSES = {
    'openai': {'status': 'completed', 'output': [
        {'type': 'reasoning', 'summary': []},
        {'type': 'message', 'role': 'assistant', 'content': [{'type': 'output_text', 'text': 'analysis'}]},
    ]},
    'anthropic': {'stop_reason': 'end_turn', 'content': [{'type': 'text', 'text': 'analysis'}]},
    'google': {'candidates': [{'finishReason': 'STOP', 'content': {'parts': [
        {'text': 'hidden reasoning', 'thought': True}, {'text': 'analysis'}]}}]},
    'deepseek': {'choices': [{'finish_reason': 'stop', 'message': {'role': 'assistant', 'content': 'analysis'}}]},
}


@pytest.mark.parametrize('name', list(p.API_CONTRACTS))
def test_request_contract_and_parse_are_provider_specific(name, monkeypatch):
    config = p.ProviderConfig(name, 'explicit-model-v1', SECRET)
    seen = []

    def post(request, timeout):
        seen.append(request)
        assert timeout == 30
        assert request.method == 'POST'
        assert SECRET not in request.full_url
        body = json.loads(request.data)
        assert SECRET not in request.data.decode()
        headers = {k.lower(): v for k, v in request.header_items()}
        assert headers['content-type'] == 'application/json'
        if name == 'openai':
            assert request.full_url == 'https://api.openai.com/v1/responses'
            assert body['instructions'] == 'Only evidence-backed analysis.'
            assert body['store'] is False
            assert body['tools'] == []
            assert body['max_output_tokens'] == 2048
            assert headers['authorization'] == 'Bearer ' + SECRET
        elif name == 'anthropic':
            assert request.full_url == 'https://api.anthropic.com/v1/messages'
            assert headers['x-api-key'] == SECRET
            assert headers['anthropic-version'] == '2023-06-01'
            assert body['system'] == 'Only evidence-backed analysis.'
            assert body['messages'][0]['role'] == 'user'
        elif name == 'google':
            assert request.full_url == 'https://generativelanguage.googleapis.com/v1beta/models/explicit-model-v1:generateContent'
            assert headers['x-goog-api-key'] == SECRET
            assert body['systemInstruction']['parts'][0]['text'] == 'Only evidence-backed analysis.'
            assert body['generationConfig']['maxOutputTokens'] == 2048
        else:
            assert request.full_url == 'https://api.deepseek.com/chat/completions'
            assert headers['authorization'] == 'Bearer ' + SECRET
            assert body['messages'][0]['role'] == 'system'
            assert body['stream'] is False
        assert body.get('model', 'explicit-model-v1') == 'explicit-model-v1'
        assert 'tools' not in body or body['tools'] == []
        return RESPONSES[name]

    monkeypatch.setattr(p, '_post_json', post)
    assert p.Provider(config).generate('Only evidence-backed analysis.', {'facts': ['f1']}) == 'analysis'
    assert len(seen) == 1  # no silent retry or fallback paid call
    assert SECRET not in repr(config)


def test_environment_configuration_has_no_model_or_key_defaults(monkeypatch):
    env = {'OPENAI_API_KEY': SECRET}
    readiness = p.provider_readiness(env)
    assert all(not row['ready'] for row in readiness)
    assert SECRET not in json.dumps(readiness)
    env['NEESHA_OPENAI_MODEL'] = 'chosen-explicitly'
    config = p.ProviderConfig.from_env('openai', env)
    assert config.model == 'chosen-explicitly'
    # Key + model alone is not "ready": analysis also needs a per-call cap, so
    # the provider must not be reported ready while a run would fail for it.
    readiness = p.provider_readiness(env)
    assert not readiness[0]['ready']
    assert 'CALL_CAP_USD' in readiness[0]['reason']
    env['NEESHA_OPENAI_CALL_CAP_USD'] = '0.02'
    readiness = p.provider_readiness(env)
    assert readiness[0]['ready']
    assert readiness[0]['model'] == 'chosen-explicitly'
    assert 'not tested' in readiness[0]['reason']
    assert SECRET not in json.dumps(readiness)
    with pytest.raises(p.ProviderError, match='Unknown runtime provider'):
        p.ProviderConfig.from_env('https://evil.example', env)


@pytest.mark.parametrize('model', ['', '../../evil', 'https://evil.example', 'model?key=x', 'model/other', 'bad\nheader'])
def test_model_cannot_change_endpoint(model):
    with pytest.raises(p.ProviderError, match='model ID'):
        p.ProviderConfig('google', model, SECRET)


@pytest.mark.parametrize('secret', ['', 'bad\nheader', 'bad\rheader', 'secret with spaces'])
def test_invalid_keys_fail_without_echo(secret):
    with pytest.raises(p.ProviderError):
        p.ProviderConfig('openai', 'model', secret)


@pytest.mark.parametrize('name,response', [
    ('openai', {'status': 'incomplete', 'output': []}),
    ('openai', {'status': 'completed', 'output': [{'type': 'function_call', 'name': 'shell'}]}),
    ('openai', {'status': 'completed', 'output': [{'type': 'message', 'role': 'assistant', 'content': [{'type': 'refusal', 'refusal': 'No'}]}]}),
    ('anthropic', {'stop_reason': 'max_tokens', 'content': [{'type': 'text', 'text': 'partial'}]}),
    ('anthropic', {'stop_reason': 'end_turn', 'content': [{'type': 'tool_use', 'name': 'shell'}]}),
    ('google', {'candidates': [{'finishReason': 'SAFETY', 'content': {'parts': []}}]}),
    ('google', {'candidates': [{'finishReason': 'STOP', 'content': {'parts': [{'functionCall': {'name': 'shell'}}]}}]}),
    ('deepseek', {'choices': [{'finish_reason': 'length', 'message': {'content': 'partial'}}]}),
    ('deepseek', {'choices': [{'finish_reason': 'stop', 'message': {'content': 'x', 'tool_calls': [{'name': 'shell'}]}}]}),
    ('deepseek', {'choices': []}),
])
def test_non_text_or_incomplete_outputs_never_become_analysis(name, response, monkeypatch):
    monkeypatch.setattr(p, '_post_json', lambda *args: response)
    with pytest.raises(p.ProviderError):
        p.Provider(p.ProviderConfig(name, 'explicit-model', SECRET)).generate('Analyze.', 'facts')


def test_request_size_limit_prevents_outbound_call(monkeypatch):
    monkeypatch.setattr(p, '_post_json', lambda *args: pytest.fail('must not call provider'))
    with pytest.raises(p.ProviderError, match='size limit'):
        p.Provider(p.ProviderConfig('openai', 'model', SECRET)).generate('Analyze.', 'x' * p.MAX_REQUEST_BYTES)


class FakeResponse:
    def __init__(self, body, content_type='application/json', status=200):
        self.body = io.BytesIO(body)
        self.headers = {'Content-Type': content_type}
        self.status = status
        self.closed = False
    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.closed = True
    def read1(self, size):
        return self.body.read(size)


def test_transport_disables_proxies_redirects_and_bounds_reads(monkeypatch):
    response = FakeResponse(b'{"ok": true}')
    captured = []
    class Opener:
        def open(self, request, timeout):
            assert timeout == 30
            return response
    def build(*handlers):
        captured.extend(handlers)
        return Opener()
    monkeypatch.setattr(p.urllib.request, 'build_opener', build)
    request = p.Provider(p.ProviderConfig('openai', 'model', SECRET))._request('Analyze.', 'facts')
    assert p._post_json(request, 30) == {'ok': True}
    assert response.closed
    proxy = next(h for h in captured if isinstance(h, p.urllib.request.ProxyHandler))
    assert proxy.proxies == {}
    redirect = next(h for h in captured if isinstance(h, p._NoRedirect))
    with pytest.raises(p.ProviderError, match='redirect refused'):
        redirect.redirect_request(request, None, 302, 'Found', {}, 'https://evil.example')


@pytest.mark.parametrize('body,content_type', [
    (b'x' * (p.MAX_RESPONSE_BYTES + 1), 'application/json'),
    (b'not-json ' + SECRET.encode(), 'application/json'),
    (b'[]', 'application/json'),
    (b'<html>error</html>', 'text/html'),
])
def test_transport_rejects_unbounded_or_malformed_body(body, content_type, monkeypatch):
    response = FakeResponse(body, content_type)
    class Opener:
        def open(self, *args, **kwargs):
            return response
    monkeypatch.setattr(p.urllib.request, 'build_opener', lambda *handlers: Opener())
    request = p.Provider(p.ProviderConfig('openai', 'model', SECRET))._request('Analyze.', 'facts')
    with pytest.raises(p.ProviderError) as caught:
        p._post_json(request, 30)
    assert SECRET not in ''.join(traceback.format_exception(caught.value))
    assert response.closed


def test_transport_http_failure_redacts_provider_body_and_exception(monkeypatch):
    class Opener:
        def open(self, *args, **kwargs):
            raise urllib.error.HTTPError('https://example.test/?key=' + SECRET, 401,
                SECRET, {}, io.BytesIO(SECRET.encode()))
    monkeypatch.setattr(p.urllib.request, 'build_opener', lambda *handlers: Opener())
    request = p.Provider(p.ProviderConfig('openai', 'model', SECRET))._request('Analyze.', 'facts')
    with pytest.raises(p.ProviderError, match='status 401') as caught:
        p._post_json(request, 30)
    assert SECRET not in ''.join(traceback.format_exception(caught.value))


def test_paid_response_parse_failures_are_marked_for_budget_settlement(monkeypatch):
    monkeypatch.setattr(p, '_post_json', lambda *args: {'status': 'incomplete', 'output': []})
    with pytest.raises(p.ProviderError) as caught:
        p.Provider(p.ProviderConfig('openai', 'model', SECRET)).generate('Analyze.', 'facts')
    assert caught.value.response_received is True


def test_uncertain_network_failure_is_marked_for_conservative_accounting(monkeypatch):
    class Opener:
        def open(self, *args, **kwargs):
            raise TimeoutError('request might have reached provider ' + SECRET)
    monkeypatch.setattr(p.urllib.request, 'build_opener', lambda *handlers: Opener())
    request = p.Provider(p.ProviderConfig('openai', 'model', SECRET))._request('Analyze.', 'facts')
    with pytest.raises(p.ProviderError) as caught:
        p._post_json(request, 30)
    assert caught.value.cost_uncertain
    assert SECRET not in ''.join(traceback.format_exception(caught.value))
