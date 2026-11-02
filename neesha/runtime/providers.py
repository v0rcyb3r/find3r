"""Small text-only provider clients; the caller owns policy and spend gating.

No client is invoked on import or by readiness checks. Call ``generate`` only
inside the runtime executor after a budget reservation. Models and credentials
come from explicit environment settings, never a coding-assistant session.
No tools, browser access, custom endpoints, redirects, or provider retries are
exposed. Returned text is untrusted analysis, not executable instructions.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Mapping

import certifi

CHECKED_DATE = '2026-11-02'
API_CONTRACTS = {
    'openai': {
        'endpoint': 'https://api.openai.com/v1/responses',
        'key_env': 'OPENAI_API_KEY', 'model_env': 'NEESHA_OPENAI_MODEL',
        'docs': 'https://developers.openai.com/api/docs/guides/text',
        'reference': 'https://developers.openai.com/api/reference/resources/responses/methods/create',
        'contract': 'Responses API; store=false; no tools; output message/output_text blocks',
    },
    'anthropic': {
        'endpoint': 'https://api.anthropic.com/v1/messages',
        'key_env': 'ANTHROPIC_API_KEY', 'model_env': 'NEESHA_ANTHROPIC_MODEL',
        'docs': 'https://platform.claude.com/docs/en/api/messages/create',
        'reference': 'https://platform.claude.com/docs/en/api/versioning',
        'authentication': 'https://platform.claude.com/docs/en/manage-claude/authentication',
        'contract': 'Messages API; x-api-key; anthropic-version=2023-06-01; text blocks',
    },
    'google': {
        'endpoint': 'https://generativelanguage.googleapis.com/v1beta/models/',
        'key_env': 'GEMINI_API_KEY', 'model_env': 'NEESHA_GOOGLE_MODEL',
        'docs': 'https://ai.google.dev/api/rest/v1beta/models/generateContent',
        'contract': 'models.generateContent; x-goog-api-key; systemInstruction; candidates/content/parts',
    },
    'deepseek': {
        'endpoint': 'https://api.deepseek.com/chat/completions',
        'key_env': 'DEEPSEEK_API_KEY', 'model_env': 'NEESHA_DEEPSEEK_MODEL',
        'docs': 'https://api-docs.deepseek.com/api/create-chat-completion/',
        'reference': 'https://api-docs.deepseek.com/',
        'contract': 'Chat completions; bearer header; no tools; choices/message/content',
    },
}
MODEL_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,159}\Z')
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_TEXT_CHARS = 100_000


class ProviderError(RuntimeError):
    """Sanitized failure with conservative accounting context, never response text."""
    def __init__(self, message: str, *, response_received: bool = False, cost_uncertain: bool = False):
        super().__init__(message)
        self.response_received = response_received
        self.cost_uncertain = cost_uncertain


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    model: str
    api_key: str = field(repr=False)
    max_output_tokens: int = 2048
    timeout_seconds: int = 30

    def __post_init__(self):
        if self.name not in API_CONTRACTS:
            raise ProviderError('Unknown runtime provider.')
        if not isinstance(self.model, str) or not MODEL_ID.fullmatch(self.model):
            raise ProviderError('Configure an explicit, valid provider model ID.')
        if not isinstance(self.api_key, str) or not self.api_key.strip() or any(
            ord(c) < 33 or ord(c) > 126 for c in self.api_key
        ):
            raise ProviderError('Configure a valid provider API key in the environment.')
        if type(self.max_output_tokens) is not int or not 16 <= self.max_output_tokens <= 8192:
            raise ProviderError('Runtime output limit must be between 16 and 8192 tokens.')
        if type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 60:
            raise ProviderError('Runtime timeout must be between 1 and 60 seconds.')

    @classmethod
    def from_env(cls, name: str, environ: Mapping[str, str] | None = None):
        if name not in API_CONTRACTS:
            raise ProviderError('Unknown runtime provider.')
        env = os.environ if environ is None else environ
        contract = API_CONTRACTS[name]
        key = env.get(contract['key_env'], '').strip()
        model = env.get(contract['model_env'], '').strip()
        if not key or not model:
            raise ProviderError(f"Configure {contract['key_env']} and {contract['model_env']} first.")
        return cls(name=name, model=model, api_key=key)


def provider_readiness(environ: Mapping[str, str] | None = None) -> list[dict]:
    """Return configuration status only. Does not verify account/model access."""
    env = os.environ if environ is None else environ
    result = []
    for name, contract in API_CONTRACTS.items():
        try:
            config = ProviderConfig.from_env(name, env)
            ready, reason, model = True, 'Configured; account and model access not tested.', config.model
        except ProviderError as exc:
            ready, reason, model = False, str(exc), None
        result.append({
            'provider': name, 'ready': ready, 'reason': reason, 'model': model,
            'key_env': contract['key_env'], 'model_env': contract['model_env'],
            'checked_date': CHECKED_DATE, 'docs': contract['docs'],
        })
    return result


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProviderError('Provider redirect refused.')


def _post_json(request: urllib.request.Request, timeout: int) -> dict:
    # Ignore ambient proxies and preserve TLS validation. Credentials never
    # follow redirects to another origin, even if a provider returns one.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=certifi.where())),
    )
    deadline = time.monotonic() + timeout
    response_received = False
    try:
        with opener.open(request, timeout=timeout) as response:
            response_received = True
            if response.status != 200:
                raise ProviderError('Provider returned an unsuccessful response.')
            content_type = response.headers.get('Content-Type', '').split(';')[0].strip().lower()
            if content_type != 'application/json':
                raise ProviderError('Provider returned an unexpected content type.')
            chunks, size = [], 0
            while True:
                if time.monotonic() >= deadline:
                    raise ProviderError('Provider request timed out.')
                # read1 performs at most one underlying buffered read, so a
                # streaming/trickling peer cannot indefinitely renew the deadline.
                chunk = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise ProviderError('Provider response exceeded the size limit.')
                chunks.append(chunk)
            data = json.loads(b''.join(chunks))
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
        raise ProviderError(f'Provider HTTP request failed (status {status}).',
                            cost_uncertain=status >= 500) from None
    except ProviderError as exc:
        exc.response_received = response_received or exc.response_received
        raise
    except Exception:
        # Never include URL, response body, request object, or exception text.
        raise ProviderError('Provider request failed or returned invalid JSON.',
                            response_received=response_received, cost_uncertain=not response_received) from None
    if not isinstance(data, dict):
        raise ProviderError('Provider returned an unexpected response shape.', response_received=True)
    return data


def _text_blocks(blocks: Any, kind: str) -> str:
    if not isinstance(blocks, list):
        raise ProviderError('Provider returned an unexpected content shape.')
    pieces = []
    for block in blocks:
        if not isinstance(block, dict) or block.get('type') != kind:
            raise ProviderError('Provider returned non-text content; no actions were taken.')
        value = block.get('text')
        if not isinstance(value, str):
            raise ProviderError('Provider returned an invalid text block.')
        pieces.append(value)
    return '\n'.join(pieces)


class Provider:
    """Text-only transport. Caller must reserve budget before ``generate``."""
    def __init__(self, config: ProviderConfig):
        self.config = config

    def _request(self, system: str, payload: Any) -> urllib.request.Request:
        if not isinstance(system, str) or not system.strip():
            raise ProviderError('A runtime system instruction is required.')
        try:
            user_text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, allow_nan=False)
        except (ValueError, TypeError):
            raise ProviderError('Runtime payload must be JSON serializable.') from None
        c = self.config
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        endpoint = API_CONTRACTS[c.name]['endpoint']
        if c.name == 'openai':
            headers['Authorization'] = f'Bearer {c.api_key}'
            body = {'model': c.model, 'instructions': system, 'input': user_text,
                    'max_output_tokens': c.max_output_tokens, 'store': False, 'tools': []}
        elif c.name == 'anthropic':
            headers.update({'x-api-key': c.api_key, 'anthropic-version': '2023-06-01'})
            body = {'model': c.model, 'system': system,
                    'messages': [{'role': 'user', 'content': user_text}],
                    'max_tokens': c.max_output_tokens}
        elif c.name == 'google':
            headers['x-goog-api-key'] = c.api_key
            endpoint += c.model + ':generateContent'
            body = {'systemInstruction': {'parts': [{'text': system}]},
                    'contents': [{'role': 'user', 'parts': [{'text': user_text}]}],
                    'generationConfig': {'maxOutputTokens': c.max_output_tokens}, 'store': False}
        else:
            headers['Authorization'] = f'Bearer {c.api_key}'
            body = {'model': c.model, 'messages': [
                {'role': 'system', 'content': system}, {'role': 'user', 'content': user_text}],
                'max_tokens': c.max_output_tokens, 'stream': False}
        try:
            encoded = json.dumps(body, ensure_ascii=False, allow_nan=False).encode('utf-8')
        except (UnicodeError, ValueError):
            raise ProviderError('Runtime request contains invalid text.') from None
        if len(encoded) > MAX_REQUEST_BYTES:
            raise ProviderError('Runtime request exceeded the size limit.')
        return urllib.request.Request(endpoint, data=encoded, headers=headers, method='POST')

    def generate(self, system: str, payload: Any) -> str:
        request = self._request(system, payload)
        response = _post_json(request, self.config.timeout_seconds)
        try:
            result = self._parse(response)
        except ProviderError as exc:
            exc.response_received = True
            raise
        except (KeyError, IndexError, TypeError, AttributeError):
            raise ProviderError('Provider returned an unexpected response shape.', response_received=True) from None
        if not result.strip() or len(result) > MAX_TEXT_CHARS:
            raise ProviderError('Provider returned empty or oversized text.', response_received=True)
        return result

    def _parse(self, data: dict) -> str:
        if data.get('error'):
            raise ProviderError('Provider returned an error response.')
        if self.config.name == 'openai':
            if data.get('status') != 'completed':
                raise ProviderError('Provider response did not complete.')
            output = data['output']
            if not isinstance(output, list):
                raise ProviderError('Provider returned an unexpected output shape.')
            pieces = []
            for item in output:
                if item.get('type') == 'reasoning':
                    continue  # Never expose internal reasoning or execute anything.
                if item.get('type') != 'message' or item.get('role') != 'assistant':
                    raise ProviderError('Provider returned non-text output; no actions were taken.')
                pieces.append(_text_blocks(item['content'], 'output_text'))
            return '\n'.join(pieces)
        if self.config.name == 'anthropic':
            if data.get('stop_reason') not in ('end_turn', 'stop_sequence'):
                raise ProviderError('Provider response did not complete normally.')
            return _text_blocks(data['content'], 'text')
        if self.config.name == 'google':
            candidate = data['candidates'][0]
            if candidate.get('finishReason') != 'STOP':
                raise ProviderError('Provider response did not complete normally.')
            parts = candidate['content']['parts']
            if not isinstance(parts, list) or any(
                not isinstance(p, dict) or set(p) - {'text', 'thought', 'thoughtSignature'} for p in parts
            ):
                raise ProviderError('Provider returned non-text output; no actions were taken.')
            texts = [p['text'] for p in parts if not p.get('thought')]
            if not all(isinstance(t, str) for t in texts):
                raise ProviderError('Provider returned invalid text.')
            return '\n'.join(texts)
        choice = data['choices'][0]
        message = choice['message']
        if choice.get('finish_reason') != 'stop' or message.get('tool_calls') or message.get('function_call'):
            raise ProviderError('Provider response did not complete as text; no actions were taken.')
        if not isinstance(message.get('content'), str):
            raise ProviderError('Provider returned invalid text.')
        return message['content']
